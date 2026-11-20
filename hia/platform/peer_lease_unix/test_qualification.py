"""Actual child ownership and refusal controls for the peer Unix qualifier."""
from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
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

    @contextmanager
    def source_fixture(self):
        """Actual file/Git checks; semantic admission is a counted test double."""
        from hia.tools import toolchain

        root = self.root / "source-fixture"
        here = root / "hia/platform/peer_lease_unix"
        here.mkdir(parents=True)
        fixed = (
            "hia/tools/toolchain.py", "hia/toolchain.lock.json", "AGENTS.md", "PROJECT_ID",
            "PROJECT_BOUNDARY.json", "rust-toolchain.toml", "scripts/project-preflight.sh",
            "scripts/ci/project_boundary.py", "scripts/w1_owned_process_collector_v1.py",
            "config/portability-inventory-v1.json", "config/pon/work-profile-v1.json",
            "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md",
            "hia/platform/peer_lease_unix/image.hepta", "hia/platform/peer_lease_unix/codec.hepta",
            "hia/src/fixture/declared.hepta", "hia/src/fixture/nonkey-dependency.hepta",
            "original/lib.rs",
        )
        for name in fixed:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("source-capture control only: " + name + "\n").encode())
        manifest = {"schema": "trnm.hia.component-includes.v1",
                    "includes": {"src/fixture/declared.hepta": []}}
        (root / "hia/components.json").write_text(json.dumps(manifest))
        commands = (
            ["git", "init", "--quiet", str(root)],
            ["git", "-C", str(root), "add", "original/lib.rs"],
            ["git", "-C", str(root), "-c", "user.name=Source capture control",
             "-c", "user.email=source-control@example.invalid", "commit", "--quiet", "-m", "fixture"],
        )
        for argv in commands:
            subprocess.run(argv, check=True, capture_output=True, timeout=10)

        def compose(path):
            dependency = root / "hia/src/fixture/nonkey-dependency.hepta"
            return b"semantic admission test double", [(path, path.read_bytes()),
                                                       (dependency, dependency.read_bytes())]

        with patch.multiple(build, ROOT=root, HERE=here, INPUTS=(), IMAGES=("image",),
                            ORIGINAL_ROOTS=("original",)), \
                patch.object(toolchain, "HIA_ROOT", root / "hia"), \
                patch.object(build, "pinned_toolchain"), \
                patch.dict(os.environ, {"CARGO_HOME": str(self.root / "cargo-home")}), \
                patch.object(build, "compose_source", side_effect=compose) as admission:
            initial = build.source_capture()
            self.assertEqual(admission.call_count, 2)
            checker = build.Build.__new__(build.Build)
            checker.inputs = initial
            checker.admitted_hia_paths = tuple(sorted(name[4:] for name in initial
                                                       if name.startswith("hia/") and name.endswith(".hepta")))
            checker.pinned = type("PinnedControl", (), {"check_pin": lambda self: None})()
            yield root, here, checker, admission

    def test_source_recheck_reads_every_admitted_byte_without_recompiling(self):
        with self.source_fixture() as (root, _, checker, admission):
            with patch.object(build, "compose_source", side_effect=AssertionError("unexpected repeated admission")):
                checker.check()
                # This includes the non-manifest-key transitive dependency,
                # platform source, pin, manifest, boundary and real Git blob.
                for name, raw in checker.inputs.items():
                    with self.subTest(path=name):
                        path = root / name
                        path.write_bytes(raw + b"changed")
                        try:
                            with self.assertRaises(ValueError):
                                checker.check()
                        finally:
                            path.write_bytes(raw)
                checker.check()
            self.assertEqual(admission.call_count, 2)
            self.assertEqual(build.source_capture(), checker.inputs)
            self.assertEqual(admission.call_count, 4)

    def test_source_recheck_rejects_member_changes_links_and_omitted_dependency(self):
        with self.source_fixture() as (root, here, checker, _):
            with patch.object(build, "compose_source", side_effect=AssertionError("unexpected repeated admission")):
                extra = here / "new-unbound.py"
                extra.write_bytes(b"new actual namespace member\n")
                with self.assertRaises(ValueError):
                    checker.check()
                extra.unlink()
                dependency = root / "hia/src/fixture/nonkey-dependency.hepta"
                raw = dependency.read_bytes()
                dependency.unlink()
                try:
                    with self.assertRaises(ValueError):
                        checker.check()
                    target = self.root / "linked-target"
                    target.write_bytes(raw)
                    dependency.symlink_to(target)
                    with self.assertRaises(ValueError):
                        checker.check()
                    dependency.unlink()
                finally:
                    dependency.write_bytes(raw)
                original_paths = checker.admitted_hia_paths
                checker.admitted_hia_paths = tuple(name for name in original_paths
                    if name != "src/fixture/nonkey-dependency.hepta")
                with self.assertRaises(ValueError):
                    checker.check()
                checker.admitted_hia_paths = original_paths
                checker.check()
                extra = root / "original/new.rs"
                extra.write_bytes(b"new tracked original member\n")
                subprocess.run(["git", "-C", str(root), "add", "original/new.rs"],
                               check=True, capture_output=True, timeout=10)
                subprocess.run(["git", "-C", str(root), "-c", "user.name=Source capture control",
                                "-c", "user.email=source-control@example.invalid", "commit",
                                "--quiet", "-m", "add original member"],
                               check=True, capture_output=True, timeout=10)
                with self.assertRaises(ValueError):
                    checker.check()

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
                "def birth(pid):\n"
                " return int(pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rpartition(') ')[2].split()[19])\n"
                "for index in range(273):\n"
                " pid=os.fork()\n"
                " if pid==0:\n"
                "  who=os.getpid();ticks=birth(who);print('start',index,who,ticks,flush=True)\n"
                "  end=time.monotonic()+2\n"
                "  while time.monotonic()<end:\n"
                "   lines=events.read_bytes().splitlines()\n"
                "   observed=[]\n"
                "   for line in lines:\n"
                "    try: row=json.loads(line)\n"
                "    except json.JSONDecodeError: continue\n"
                "    if row['kind']=='process-observed':\n"
                "     ident=row['value']['identity'];observed.append((ident['pid'],ident['start_ticks']))\n"
                "   if (who,ticks) in observed: os._exit(0)\n"
                "   time.sleep(0.002)\n"
                "  os._exit(4)\n"
                " ticks=birth(pid);actual,status=os.waitpid(pid,0)\n"
                " assert actual==pid and status==0\n"
                " print('end',index,pid,ticks,flush=True)\n")
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
        births = set()
        for index in range(273):
            first, second = lines[2 * index].split(), lines[2 * index + 1].split()
            self.assertEqual(len(first), 4)
            self.assertEqual(first[:2], ["start", str(index)])
            self.assertEqual(second, ["end", str(index), *first[2:]])
            births.add((int(first[2]), int(first[3])))
        self.assertEqual(len(births), 273)
        result = runner.rows[-1]["collector_readback"]["result"]
        records = result["process_observations"]
        self.assertGreater(len(records), 256)
        identities = {(row["identity"]["pid"], row["identity"]["start_ticks"]) for row in records}
        root = result["root_identity"]
        # A ready pidfd is released before a grandchild's parent necessarily
        # waits it. Rediscovery of that same zombie is an observation, not a
        # new process birth. Require the exact complete actual birth roster.
        self.assertEqual(identities, births | {(root["pid"], root["start_ticks"])})
        self.assertFalse(result["records_truncated"])
        self.assertTrue(result["collector_wait_domain_reaped"])
        readback.processes(runner.output, runner.rows)
        (self.root / "serial-history-summary.json").write_text(json.dumps({
            "sequential_children": 273, "peak_unwaited_children": 1,
            "peak_command_family_processes": 2, "actual_observed_identities": len(identities),
            "actual_observation_rows": len(records), "repeated_birth_observations": len(records) - len(identities),
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
        # Reader-only fixture: require all 18 current control names, and keep
        # the prior 14-method transcript as a refusal rather than a PASS.
        names = [test.id() for test in unittest.defaultTestLoader.loadTestsFromTestCase(type(self))]
        self.assertEqual(len(names), 18)
        stderr = self.root / "observations/integrity-controls/stderr.raw"
        stderr.parent.mkdir(parents=True)
        lines = [name.rsplit(".", 1)[1] + " (" + name + ") ... ok" for name in names]
        raw = "\n".join(lines) + "\n\nRan 18 tests in 0.01s\n\nOK\n"
        row = {"argv": [sys.executable, "-B", "-m", "unittest", "-v",
                        "hia.platform.peer_lease_unix.test_qualification"], "wall_limit_seconds": 30}
        stderr.write_text(raw)
        self.assertEqual(readback.integrity_readback(self.root, row)["count"], 18)
        for changed in (raw.replace("Ran 18 tests", "Ran 14 tests"),
                        "\n".join(lines[:14]) + "\n\nRan 14 tests in 0.01s\n\nOK\n"):
            stderr.write_text(changed)
            with self.assertRaises(ValueError):
                readback.integrity_readback(self.root, row)

    def committed_reader_fixture(self, directory, stem):
        # Manufactured retained bytes for reader negatives, not an execution.
        journal = bytearray(236)
        journal[:10] = b"TPLR\1\1\xa2\0\0\0"
        journal[42] = 1
        journal[43:75] = b"\1" * 32
        journal[75:107] = b"\2" * 32
        journal[107] = 1
        struct.pack_into("<Q", journal, 108, 9)
        journal[116:148] = b"\3" * 32
        journal[148:180] = b"\4" * 32
        struct.pack_into("<QQQ", journal, 180, 1, 40000, 10000)
        journal[204:] = hashlib.sha256(journal[:204]).digest()
        head = b"TPLH\1\0\0\0" + struct.pack("<Q", 1) + journal[204:]
        head += hashlib.sha256(b"TPLH" + struct.pack("<Q", 48) + head).digest()
        (directory / "fs").mkdir(parents=True)
        for name, raw in ((stem + "-journal.raw", journal), (stem + "-head.raw", head),
                          ("fs/j", journal), ("fs/.j.head-v1", head)):
            (directory / name).write_bytes(raw)
        return b"TPLS" + struct.pack("<I", 187) + b"\1\0" + journal[43:196] + journal[204:236]

    def test_capacity_reader_keeps_original_histories_and_unchanged_deadlines(self):
        rows = []
        for prefix in ("capacity-", "capacity-idempotent-"):
            for count in (1, 16, 63, 64, 65, 80):
                name = prefix + str(count)
                row = {"name": name}
                for role in ("original", "native"):
                    directory = self.root / name / role
                    reply = self.committed_reader_fixture(directory, "seed")
                    daemon = directory / "daemon"
                    request = daemon / "request-0000"
                    request.mkdir(parents=True)
                    (request / "response.raw").write_bytes(reply)
                    (daemon / "stdin.raw").write_bytes(b"PLUN0001" + struct.pack("<QQQQQQ", 1, 0, 0, 0, 0, 250_000_000))
                    (daemon / "receipt.json").write_text(json.dumps({"operations": [
                        {"elapsed_ns": 100_000_000, "output": build.identity(reply)}]}))
                    (directory / "timing.json").write_text(json.dumps(
                        {"stalled_clients": count, "honest_elapsed_ns": 110_000_000}))
                    row[role] = {"clients": count, "closed": count, "honest_response": (reply[:155] + bytes(40)).hex(), "alive": True}
                    if prefix == "capacity-idempotent-":
                        seed = directory / "seed/request-0000"
                        seed.mkdir(parents=True)
                        (seed / "response.raw").write_bytes(reply)
                        row[role].update(seeded_by_actual_API=True, exact_seed_token_returned=True,
                                         journal_and_head_unchanged=True)
                rows.append(row)
        readback.daemon_capacity_observations(self.root, rows)
        with self.assertRaises(ValueError):
            readback.daemon_capacity_observations(self.root, [row for row in rows if row["name"] != "capacity-64"])
        directory = self.root / "capacity-64/native"
        targets = [
            (directory / "timing.json", json.dumps({"stalled_clients": 64, "honest_elapsed_ns": 2_000_000_000}).encode()),
            (directory / "daemon/stdin.raw", b"PLUN0001" + struct.pack("<QQQQQQ", 1, 0, 0, 0, 0, 251_000_000)),
            (directory / "daemon/request-0000/response.raw", b""),
            (self.root / "capacity-idempotent-64/native/seed/request-0000/response.raw", b"substituted token"),
        ]
        for path, bad in targets:
            raw = path.read_bytes()
            try:
                path.write_bytes(bad)
                with self.subTest(path=str(path)), self.assertRaises(ValueError):
                    readback.daemon_capacity_observations(self.root, rows)
            finally:
                path.write_bytes(raw)

    def test_deadline_reader_rejects_unbound_delay_late_success_and_changed_commit(self):
        probe_name = "deadline-journal-target-probe"
        delayed_name = "durable-commit-crosses-absolute-deadline"
        rows = [{"name": probe_name}, {"name": delayed_name}]
        for role in ("original", "native"):
            probe_directory = self.root / probe_name / role
            probe_daemon = probe_directory / "daemon"
            probe_daemon.mkdir(parents=True)
            probe_line = "123 fsync(5<" + str(probe_directory / "fs/j") + ">) = 0"
            probe = {"phase": "journal-fsync", "syscall": "fsync", "ordinal": 1, "line_index": 1, "line": probe_line}
            (probe_daemon / "syscalls.raw").write_text("123 getsockopt(8, SOL_SOCKET, SO_PEERCRED, ...) = 0\n" + probe_line + "\n")
            (probe_directory / "selector.json").write_text(json.dumps(probe))
            directory = self.root / delayed_name / role
            reply = self.committed_reader_fixture(directory, "committed")
            daemon = directory / "daemon"
            for index, response in enumerate((b"", reply)):
                request = daemon / ("request-" + str(index).zfill(4))
                request.mkdir(parents=True)
                (request / "request.raw").write_bytes(b"reader fixture only")
                (request / "response.raw").write_bytes(response)
            (daemon / "stdin.raw").write_bytes(b"PLUN0001" + struct.pack("<QQQQQQ", 1, 0, 0, 0, 0, 250_000_000))
            injection = "fsync:delay_exit=350ms:when=1"
            (daemon / "receipt.json").write_text(json.dumps({
                "argv": ["strace", "--inject=" + injection, "reader-fixture-only"],
                "operations": [{"elapsed_ns": 400_000_000, "output": build.identity(b"")},
                               {"elapsed_ns": 100_000, "output": build.identity(reply)}]}))
            (directory / "injection-selector.json").write_text(json.dumps({"probe": probe, "injection": injection,
                "connection_deadline_ns": 250_000_000, "injected_delay_exit_ns": 350_000_000}))
            line = "123 fsync(5<" + str(directory / "fs/j") + ">) = 0 (DELAYED)"
            (daemon / "syscalls.raw").write_text("123 getsockopt(8, SOL_SOCKET, SO_PEERCRED, ...) = 0\n" + line + "\n")
            (directory / "actual-delay.json").write_text(json.dumps({**probe, "line": line}))
            (directory / "timing.json").write_text(json.dumps({"commit_exchange_elapsed_ns": 401_000_000}))
            rows[1][role] = {"connection_deadline_ns": 250_000_000, "injected_delay_exit_ns": 350_000_000,
                "empty_reply_after_durable_commit": True, "committed_records": 1,
                "exact_actual_target_verified": True, "idempotent_retry": (reply[:155] + bytes(40)).hex(),
                "journal_and_head_unchanged_on_retry": True, "alive_after_commit": True}
        readback.daemon_deadline_observations(self.root, rows)
        directory = self.root / delayed_name / "native"
        receipt = json.loads((directory / "daemon/receipt.json").read_bytes())
        targets = [
            (directory / "daemon/receipt.json", json.dumps({**receipt, "argv": ["strace", "reader-fixture-only"]}).encode()),
            (directory / "daemon/stdin.raw", b"PLUN0001" + struct.pack("<QQQQQQ", 1, 0, 0, 0, 0, 350_000_000)),
            (directory / "timing.json", b'{"commit_exchange_elapsed_ns":349999999}'),
            (directory / "daemon/request-0000/response.raw", (directory / "daemon/request-0001/response.raw").read_bytes()),
            (directory / "fs/j", b"changed committed bytes"),
            (directory / "daemon/syscalls.raw", (directory / "daemon/syscalls.raw").read_bytes().replace(b"(DELAYED)", b"(INJECTED)")),
            (self.root / probe_name / "native/selector.json", b'{"phase":"journal-fsync","ordinal":2}'),
        ]
        for path, bad in targets:
            raw = path.read_bytes()
            try:
                path.write_bytes(bad)
                with self.subTest(path=str(path)), self.assertRaises(ValueError):
                    readback.daemon_deadline_observations(self.root, rows)
            finally:
                path.write_bytes(raw)
        changed = copy.deepcopy(rows)
        changed[1]["native"]["empty_reply_after_durable_commit"] = False
        with self.assertRaises(ValueError):
            readback.daemon_deadline_observations(self.root, changed)

    def test_socket_replacement_reader_requires_pinned_distinct_inodes_and_actual_replies(self):
        # Reader fixtures only: these values do not claim real socket execution.
        socket_path = os.fsencode(self.root / "fs/lease.sock")
        parent_path = os.fsencode(self.root / "fs")
        old = {"device": 7, "inode": 101, "mode": stat.S_IFSOCK | 0o600}
        new = {**old, "inode": 102}
        parent = {"device": 7, "inode": 100, "mode": stat.S_IFDIR | 0o700}
        fixture = {"schema": "trnm.hia.peer-unix.socket-replacement.v1", "status": "PASS",
                   "path_hex": socket_path.hex(), "parent_path_hex": parent_path.hex(),
                   "original_socket": old, "pinned_before_unlink": old, "pinned_after_capture": old,
                   "replacement_before_capture": new, "replacement_after_capture": new,
                   "parent_before": parent, "parent_after": parent,
                   "pin_open_flags": os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, "pin_closed": True,
                   "opened_ns": 1, "rebound_before_ns": 2, "rebound_after_ns": 3, "closed_ns": 4}
        rows = [{"name": name, "op": 7} for name in
                ("socket-binding", "zero-timeout-binding", "same-object-observes-replaced-socket")]
        for role in ("original", "native"):
            (self.root / role).mkdir()
            for index, endpoint in enumerate((old, old, new), 1):
                data = b"trnm.peer-lease.unix-authority-binding.v1\0"
                for encoded, observed in ((parent_path, parent), (socket_path, endpoint)):
                    data += struct.pack(">I", len(encoded)) + encoded
                    data += struct.pack(">QQI", observed["device"], observed["inode"], observed["mode"])
                raw = b"PLUR0001" + struct.pack("<QQQ", 0, 0, 32) + hashlib.sha256(data).digest()
                (self.root / role / f"{index:05d}.stdout.raw").write_bytes(raw)

        def write(value):
            raw = (json.dumps(value, sort_keys=True) + "\n").encode()
            (self.root / "socket-replacement.json").write_bytes(raw)
            return {"socket_replacement": build.identity(raw)}

        readback.socket_replacement(self.root, write(fixture), rows)
        alternatives = []
        for fields, replacement in ((["replacement_before_capture", "replacement_after_capture"], old),
                                    (["pinned_after_capture"], new),
                                    (["pin_closed"], False), (["pin_open_flags"], os.O_CLOEXEC),
                                    (["closed_ns"], 2), (["path_hex"], b"/substituted".hex()),
                                    (["pinned_before_unlink"], {**old, "mode": stat.S_IFLNK | 0o600})):
            changed = copy.deepcopy(fixture)
            for field in fields:
                changed[field] = replacement
            alternatives.append(changed)
        for changed in alternatives:
            with self.subTest(value=changed), self.assertRaises(ValueError):
                readback.socket_replacement(self.root, write(changed), rows)
        report = write(fixture)
        path = self.root / "native/00003.stdout.raw"
        raw = path.read_bytes()
        path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with self.assertRaises(ValueError):
            readback.socket_replacement(self.root, report, rows)

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
