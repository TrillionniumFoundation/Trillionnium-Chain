"""Actual child ownership and refusal controls for the peer Unix qualifier."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from . import build, process, readback
from .original_build import TEST_COUNTS, completed_original_tests, cargo_events


def summaries():
    rows = [(count, 0) for count in [*TEST_COUNTS.values(), 0]] + [(1, 1), (1, 1)]
    return b"\n".join((f"test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; "
                       f"{filtered} filtered out; finished in 0.01s").encode()
                      for count, filtered in rows) + b"\n"


class QualificationControls(unittest.TestCase):
    def setUp(self):
        kept = os.environ.get("TRNM_PEER_UNIX_CONTROL_ROOT")
        if kept:
            self.root = Path(kept) / self._testMethodName
            self.root.mkdir(parents=True, mode=0o700)
            self.temporary = None
        else:
            self.temporary = tempfile.TemporaryDirectory(prefix="peer-unix-control-")
            self.root = Path(self.temporary.name)

    def tearDown(self):
        if self.temporary is not None:
            self.temporary.cleanup()

    def runner(self):
        return process.Processes(self.root / "processes", build.ROOT,
                                 {"PATH": os.environ["PATH"]}, lambda: None)

    def test_actual_normal_command_has_independent_owned_terminal_readback(self):
        runner = self.runner()
        self.assertEqual(runner.run("success", [sys.executable, "-c", "print('actual-success')"], timeout=10),
                         b"actual-success\n")
        rows = readback.processes(runner.output, runner.rows)
        self.assertTrue(rows["success"]["collector_readback"]["collector_wait_domain_reaped"])

    def test_actual_new_session_descendant_is_waited_after_leader_exit(self):
        runner = self.runner()
        code = ("import os,time\npid=os.fork()\n"
                "if pid: os._exit(0)\nos.setsid()\ntime.sleep(0.2)\n"
                "os.write(1,b'actual-descendant-finished\\n')\nos._exit(0)\n")
        self.assertEqual(runner.run("descendant", [sys.executable, "-c", code], timeout=10),
                         b"actual-descendant-finished\n")
        row = runner.rows[-1]["collector_readback"]["result"]
        self.assertGreaterEqual(len(row["wait4_records"]), 2)
        self.assertTrue(row["collector_wait_domain_reaped"])

    def test_actual_deadline_cancels_and_reaps_new_session_descendant(self):
        runner = self.runner()
        code = ("import os,time\npid=os.fork()\n"
                "if pid: os._exit(0)\nos.setsid()\ntime.sleep(30)\n")
        started = time.monotonic()
        with self.assertRaises(ValueError):
            runner.run("deadline", [sys.executable, "-c", code], timeout=1)
        self.assertLess(time.monotonic() - started, 4)
        row = runner.rows[-1]
        self.assertTrue(row["timed_out"])
        self.assertTrue(row["collector_readback"]["collector_wait_domain_reaped"])
        self.assertFalse(row["collector_readback"]["command_success"])
        self.assertIsNotNone(row["failure"])

    def test_malformed_terminal_diagnostic_never_erases_initial_failure_or_raw(self):
        runner = self.runner()

        def damaged(directory, *args, **kwargs):
            path = directory / "result.json"
            (directory / "original-result.json").write_bytes(path.read_bytes())
            path.write_bytes(b'{"deliberate_control":')
            raise RuntimeError("original-control-failure")

        with patch.object(process.owned, "read_result", side_effect=damaged):
            with self.assertRaisesRegex(RuntimeError, "original-control-failure"):
                runner.run("damaged", [sys.executable, "-c", "print('retained-before-failure')"], timeout=10)
        receipt = readback.document(runner.output / "damaged/receipt.json")
        self.assertIn("original-control-failure", receipt["failure"])
        self.assertTrue(receipt["cleanup_errors"])
        self.assertEqual((runner.output / "damaged/stdout.raw").read_bytes(), b"retained-before-failure\n")
        self.assertEqual(readback.document(runner.output / "stages.json"), [receipt])

    def test_actual_serial_history_capacity_is_not_the_live_pid_budget(self):
        # The child only reads the collector's already-published observations;
        # it cannot manufacture records. Each next fork follows actual waitpid.
        code = ("import json,os,pathlib,sys,time\n"
                "events=pathlib.Path(sys.argv[1])\n"
                "for index in range(273):\n"
                " pid=os.fork()\n"
                " if pid==0:\n"
                "  who=os.getpid();print('start',index,who,flush=True)\n"
                "  end=time.monotonic()+2\n"
                "  while time.monotonic()<end:\n"
                "   lines=events.read_bytes().splitlines()\n"
                "   observed=[]\n"
                "   for line in lines:\n"
                "    try: row=json.loads(line)\n"
                "    except json.JSONDecodeError: continue\n"
                "    if row['kind']=='process-observed': observed.append(row['value']['identity']['pid'])\n"
                "   if who in observed: os._exit(0)\n"
                "   time.sleep(0.002)\n"
                "  os._exit(4)\n"
                " actual,status=os.waitpid(pid,0)\n"
                " assert actual==pid and status==0\n"
                " print('end',index,pid,flush=True)\n")
        old = process.Processes(self.root / "prior-capacity", build.ROOT,
                                {"PATH": os.environ["PATH"]}, lambda: None)
        with patch.object(process, "MAX_PROCESS_OBSERVATIONS", 256):
            with self.assertRaises(ValueError):
                old.run("serial", [sys.executable, "-c", code,
                    old.output / "serial/owned/events.jsonl"], timeout=15)
        failed = readback.document(old.output / "serial/owned/result.json")
        self.assertEqual(failed["cause"], "process-observation-limit")
        self.assertTrue(failed["records_truncated"])
        self.assertFalse(failed["command_success_before_handoff"])
        self.assertIsNotNone(failed["final_echild"])
        runner = self.runner()
        raw = runner.run("serial", [sys.executable, "-c", code,
            runner.output / "serial/owned/events.jsonl"], timeout=15)
        lines = raw.decode().splitlines()
        self.assertEqual(len(lines), 273 * 2)
        for index in range(273):
            first, second = lines[2 * index].split(), lines[2 * index + 1].split()
            self.assertEqual(first[:2], ["start", str(index)])
            self.assertEqual(second, ["end", str(index), first[2]])
        result = runner.rows[-1]["collector_readback"]["result"]
        records = result["process_observations"]
        self.assertGreater(len(records), 256)
        self.assertEqual(len(records), len({(row["identity"]["pid"], row["identity"]["start_ticks"])
                                           for row in records}))
        self.assertFalse(result["records_truncated"])
        self.assertTrue(result["collector_wait_domain_reaped"])
        readback.processes(runner.output, runner.rows)
        (self.root / "serial-history-summary.json").write_text(json.dumps({
            "sequential_children": 273, "peak_unwaited_children": 1,
            "peak_command_family_processes": 2, "actual_observed_identities": len(records),
            "original_w1_pid_budget": 256, "original_service_budget_qualified": False,
            "prior_256_record_refusal_observed": True}) + "\n")

    def test_original_two_nested_children_never_inflate_outer_test_count(self):
        value = completed_original_tests(summaries())
        self.assertEqual(value["outer_tests"], 121)
        self.assertEqual(value["child_reexecutions"], 2)

    def test_original_missing_ignored_filtered_or_wrong_roster_is_rejected(self):
        raw = summaries()
        bad = (raw.replace(b"97 passed", b"96 passed"), raw.split(b"\n", 1)[1],
               raw.replace(b"0 ignored", b"1 ignored", 1),
               raw.replace(b"0 failed", b"1 failed", 1),
               raw.replace(b"1 filtered out", b"0 filtered out"), raw + raw)
        for value in bad:
            with self.subTest(value=value[:120]), self.assertRaises(ValueError):
                completed_original_tests(value)

    def test_original_cargo_failure_and_post_completion_artifacts_are_rejected(self):
        artifact = {"reason": "compiler-artifact", "actual": "reader fixture, no execution claim"}
        finish = {"reason": "build-finished", "success": True}
        for rows in ([artifact], [artifact, dict(finish, success=False)],
                     [artifact, finish, artifact], [artifact, finish, finish]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                cargo_events(b"\n".join(json.dumps(row).encode() for row in rows))

    def test_cargo_home_repo_ancestor_and_linked_config_are_rejected(self):
        root = self.root / "repo"
        root.mkdir()
        home = self.root / "cargo"
        with patch.object(build, "ROOT", root):
            build.cargo_configuration({"CARGO_HOME": str(home)})
            for directory in (home, root / ".cargo", self.root / ".cargo", root / "trillionnium/.cargo"):
                directory.mkdir(parents=True, exist_ok=True)
                for name in ("config", "config.toml"):
                    path = directory / name
                    path.write_text('[build]\nrustc-wrapper = "unadmitted-wrapper"\n')
                    with self.assertRaises(ValueError):
                        build.cargo_configuration({"CARGO_HOME": str(home)})
                    path.unlink()
                    path.symlink_to(directory / "missing")
                    with self.assertRaises(ValueError):
                        build.cargo_configuration({"CARGO_HOME": str(home)})
                    path.unlink()

    def test_duplicate_report_keys_are_refused(self):
        path = self.root / "report.json"
        path.write_bytes(b'{"status":"FAIL","status":"PASS"}')
        with self.assertRaises(ValueError):
            readback.document(path)

    def test_linked_or_modified_retained_bytes_are_refused(self):
        path = self.root / "raw"
        path.write_bytes(b"actual retained control bytes")
        wanted = readback.regular_identity(path)
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(ValueError):
            readback.check_identity(link, wanted)
        path.write_bytes(b"mutated retained control bytes")
        with self.assertRaises(ValueError):
            readback.check_identity(path, wanted)

    def test_correct_count_cannot_substitute_other_named_native_cases(self):
        value = {"status": "PASS", "total": 299, "passed": 299,
                 "cases": [{"name": "wrong-" + str(i), "status": "PASS"} for i in range(299)]}
        for changed in (value, {**value, "total": True},
                        {**value, "cases": [value["cases"][0]] * 299}):
            with self.assertRaises(ValueError):
                readback.named_group(self.root, "client", changed, {}, {})

    def test_finite_qualification_cannot_promote_whole_chain_or_service_claims(self):
        original = {"schema": "trnm.hia.peer-unix-qualification.v1", "status": "PASS",
                    "source_inputs_stable": True, **dict.fromkeys(readback.FALSE_CLAIMS, False)}
        for field in readback.FALSE_CLAIMS:
            value = copy.deepcopy(original)
            value[field] = True
            (self.root / "report.json").write_text(json.dumps(value))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "overstated"):
                readback.readback(self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
