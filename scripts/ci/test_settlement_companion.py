"""Exercise the exact hosted companion entry point; this never runs Settlement."""
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from hia.tools import settlement_companion as companion
from hia.platform.service_settlement.qualification.native import Progress


ROOT = Path(__file__).resolve().parents[2]
HEAD = "1" * 40
TREE = "2" * 40
SECRET = "private-fixture-bytes-and-env-secret"


# Only the three reviewed optional runner-CPU steps are exempt from the
# pre-existing mandatory-owner and image-postlude scope checks.
CPU_STEP_ALLOWLIST = {
    'Observe Settlement runner CPU before execution': (
        '      - name: Observe Settlement runner CPU before execution\n'
        "        if: matrix.component == 'settlement-engine'\n"
        '        continue-on-error: true\n'
        '        run: |\n'
        '          set -euo pipefail\n'
        '          test "$(git rev-parse HEAD)" = "$TRNM_EXPECTED_SOURCE_SHA"\n'
        '          mkdir -m 700 -- "$RUNNER_TEMP/settlement-runner-cpu"\n'
        '          timeout 2s python3 -B -m hia.tools.settlement_runner_cpu \\\n'
        '            --phase before --output-dir "$RUNNER_TEMP/settlement-runner-cpu" \\\n'
        '            --head "$TRNM_EXPECTED_SOURCE_SHA" --tree "$(git rev-parse \'HEAD^{tree}\')" \\\n'
        '            --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT"\n'
    ),
    'Observe Settlement runner CPU after execution': (
        '      - name: Observe Settlement runner CPU after execution\n'
        "        if: always() && matrix.component == 'settlement-engine'\n"
        '        continue-on-error: true\n'
        '        run: |\n'
        '          set -euo pipefail\n'
        '          test "$(git rev-parse HEAD)" = "$TRNM_EXPECTED_SOURCE_SHA"\n'
        '          test -d "$RUNNER_TEMP/settlement-runner-cpu"\n'
        '          timeout 2s python3 -B -m hia.tools.settlement_runner_cpu \\\n'
        '            --phase after --output-dir "$RUNNER_TEMP/settlement-runner-cpu" \\\n'
        '            --head "$TRNM_EXPECTED_SOURCE_SHA" --tree "$(git rev-parse \'HEAD^{tree}\')" \\\n'
        '            --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT"\n'
    ),
    'Upload separate optional Settlement runner CPU observations': (
        '      - name: Upload separate optional Settlement runner CPU observations\n'
        "        if: always() && matrix.component == 'settlement-engine'\n"
        '        continue-on-error: true\n'
        '        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n'
        '        with:\n'
        '          name: hia-settlement-runner-cpu-${{ env.TRNM_EXPECTED_SOURCE_SHA }}-${{ github.run_id }}-${{ github.run_attempt }}\n'
        '          path: |\n'
        '            ${{ runner.temp }}/settlement-runner-cpu/before.json\n'
        '            ${{ runner.temp }}/settlement-runner-cpu/after.json\n'
        '          if-no-files-found: ignore\n'
        '          retention-days: 30\n'
    ),
}
OWNER_JOB = "\n  native-additional-owners:\n"
STEP_NAME = re.compile(r"(?m)^      - name: ([^\n]+)\n")


def owner_without_cpu_workflow(workflow):
    if workflow.count(OWNER_JOB) != 1:
        raise ValueError("expected one native owner job")
    job = workflow.split(OWNER_JOB, 1)[1]
    next_job = re.search(r"(?m)^  [a-z0-9_-]+:[ \t]*$", job)
    if next_job is not None:
        job = job[:next_job.start()]
    # Ignore trailing blank separators between jobs, not step content.
    job = job.rstrip("\n") + "\n"
    steps = list(STEP_NAME.finditer(job))
    names = tuple(step[1] for step in steps)
    indices = {}
    for name, expected in CPU_STEP_ALLOWLIST.items():
        named_prefix = f"      - name: {name}\n"
        if workflow.count(named_prefix) != 1 or names.count(name) != 1:
            raise ValueError(f"missing, duplicate, or misplaced Settlement step: {name}")
        index = names.index(name)
        end = steps[index + 1].start() if index + 1 < len(steps) else len(job)
        start = steps[index].start()
        if job[start:end] != expected:
            raise ValueError(f"changed optional Settlement step: {name}")
        indices[name] = (index, start, end)
    before, after, upload = (value[0] for value in indices.values())
    if (names[before + 1:after] != ("Execute the complete component and its independent reader",)
            or names[after + 1:after + 2] != ("Recheck every committed source byte after success or failure",)
            or upload == 0
            or names[upload - 1] != "Upload the separate Settlement image identity diagnostic"
            or not before < after < upload):
        raise ValueError("optional Settlement steps are not scoped around execution and original upload")
    for _, start, end in sorted(indices.values(), reverse=True):
        job = job[:start] + job[end:]
    return job


class SettlementCompanionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temp = Path(temporary.name)
        self.source = self.temp / "source"
        self.source.mkdir()
        self.dest = self.temp / "compact"
        self.dest.mkdir()

    def write(self, path, raw):
        file = self.source / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(raw)
        return file

    def doc(self, path, row):
        return self.write(path, json.dumps(row).encode())

    def invoke(self, *, root=None, dest=None, succeeds=True, extra=()):
        result = subprocess.run([
            sys.executable, "-B", "-m", "hia.tools.settlement_companion",
            "--root", str(root or self.source), "--output-dir", str(dest or self.dest),
            "--head", HEAD, "--run-id", "12345", "--run-attempt", "2",
            "--execution-outcome", "failure", "--source-after-outcome", "success",
            "--binding-outcome", "skipped", "--job-status", "failure",
            *extra], cwd=ROOT, check=False, capture_output=True, text=True, timeout=10)
        if not succeeds:
            self.assertNotEqual(result.returncode, 0)
            return
        self.assertEqual(result.returncode, 0, result.stderr)
        output = (self.dest / "summary.json").read_bytes()
        self.assertLess(len(output), companion.MAX_OUTPUT)
        self.assertNotIn(SECRET.encode(), output)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        self.assertEqual([p.name for p in self.dest.iterdir()], ["summary.json"])
        return json.loads(output)

    def timed_receipt(self):
        return {"schema": "trnm.service-settlement.owned-process.v1", "status": "FAIL",
                "started": True, "exit_code": -15, "timed_out": True, "cleanup_complete": True,
                "execution_deadline_seconds": 240, "cleanup_deadline_seconds": 3,
                "original_deadline_monotonic_ns": 99, "elapsed_ns": 240_000_000_001,
                "environment": {"CREDENTIAL": SECRET}, "argv": [SECRET],
                "collector_readback": {"actual_stream_bytes": SECRET}, "exception": SECRET}

    def test_failed_native_with_last_complete_progress_and_missing_reader(self):
        progress_file = self.source / companion.CURSOR
        progress_file.parent.mkdir(parents=True)
        with Progress(progress_file) as progress:
            progress.record("stage_start")
            report = {"fixtures": 5, "fixture_operations": 68}
            capture = type("Capture", (), {"calls": 79, "public_dispatch_wall_ns": 400})()
            progress.record("fixture_start", report, capture, fixture_ordinal=6)
            progress.record("operation_start", report, capture, fixture_ordinal=6,
                            operation_ordinal=1, opcode=4)
        with progress_file.open("ab") as stream:
            fragment = b'{"phase":"' + SECRET.encode()
            stream.write(fragment)
        raw_cursor = progress_file.read_bytes()
        path = "qualification/stages/native/receipt.json"
        raw_receipt = self.doc(path, self.timed_receipt()).read_bytes()
        source_record = {"schema": "trnm-ci-source-v1", "kind": "head",
                         "tested_commit": HEAD, "candidate": HEAD, "tested_tree": TREE,
                         "tracked_worktree_verified": True, "tracked_entries": 42300,
                         "tracked_bytes": 4_100_000_000}
        self.doc(companion.PINS[0], source_record)
        self.doc(companion.PINS[1], source_record)
        self.write("qualification/stages/native/stdout.raw", SECRET.encode())
        self.write("qualification/stages/native/request.json", SECRET.encode())
        self.write("qualification/session.json", SECRET.encode())
        self.write("qualification/native/actual-bytes.chunked-zlib.bin", SECRET.encode())
        result = self.invoke()
        self.assertFalse(result["qualifies_execution"])
        self.assertFalse(result["substitutes_full_original_archive"])
        self.assertEqual(result["workflow"]["execution_step"], "failure")
        self.assertEqual(result["workflow"]["job_status_at_collection"], "failure")
        self.assertEqual(result["workflow"]["binding_step"], "skipped")
        observations = result["observations"]
        self.assertFalse(any(name.endswith((".raw", "/request.json", "/session.json", ".bin"))
                             for name in observations))
        self.assertEqual(observations[companion.PINS[0]]["projection"]["tree"], TREE)
        self.assertEqual(observations[path]["original"], companion.identity(raw_receipt))
        self.assertTrue(observations[path]["projection"]["timed_out"])
        self.assertEqual(observations[path]["projection"]["exit_code"], -15)
        cursor = observations[companion.CURSOR]
        self.assertEqual(cursor["original"], companion.identity(raw_cursor))
        self.assertEqual(cursor["projection"]["complete_rows"], 3)
        self.assertEqual(cursor["projection"]["trailing_fragment_bytes"], len(fragment))
        self.assertEqual(cursor["projection"]["last_complete_row"]["phase"], "operation_start")
        self.assertEqual(cursor["projection"]["last_complete_row"]["fixture_ordinal"], 6)
        self.assertEqual(cursor["projection"]["last_complete_row"]["completed_fixtures"], 5)
        self.assertEqual(observations[companion.BINDING], {"availability": "missing"})
        self.assertEqual(observations["observations/readback.receipt.json"], {"availability": "missing"})

    def checkpoint_inputs(self):
        source = {"schema": "trnm-ci-source-v1", "kind": "head",
                  "tested_commit": HEAD, "candidate": HEAD, "tested_tree": TREE,
                  "tracked_worktree_verified": True, "tracked_entries": 4, "tracked_bytes": 900}
        for path in companion.PINS:
            self.doc(path, source)
        self.doc("qualification/stages/native/receipt.json", self.timed_receipt())
        progress = [{"phase": "stage_start", "wall_ns": 1, "thread_cpu_ns": 1}]
        calls = []
        measured = 0

        def step(phase, fixture, operations, complete=False, **kw):
            progress.append({"phase": phase, "wall_ns": len(progress) * 100,
                             "thread_cpu_ns": len(progress) * 99, "fixture_ordinal": fixture,
                             "completed_fixtures": fixture if complete else fixture - 1,
                             "completed_operations": operations, "capture_records": len(calls),
                             "public_dispatch_wall_ns": measured, **kw})

        for i in range(1, 320):
            step("fixture_start", i, i - 1)
            step("operation_start", i, i - 1, operation_ordinal=1, opcode=1)
            calls.append({"ordinal": len(calls), "function": "engine_apply", "native_call": True,
                          "status": 0, "elapsed_ns": 20, "request": SECRET, "owners": [1]})
            measured += 20
            if i == 319:
                calls.extend((
                    {"ordinal": len(calls), "function": "bytes_view:view", "owner": 1, "value": SECRET},
                    {"ordinal": len(calls) + 1, "function": "owned_drop", "owner": 1,
                     "native_call": True, "status": 0, "elapsed_ns": 1234},
                    {"ordinal": len(calls) + 2, "function": "private_proportional_fee",
                     "native_call": True, "status": 0, "elapsed_ns": 2345},
                    {"ordinal": len(calls) + 3, "function": "owned_drop", "owners": [],
                     "native_call": True, "status": 0, "elapsed_ns": 7},
                ))
                measured += 7
            step("fixture_result", i, i)
            step("fixture_cleanup", i, i)
            step("fixture_done", i, i, complete=True)
        step("fixture_start", 320, 319)
        return progress, calls

    def journal(self, path, rows, tail=b""):
        return self.write(path, b"".join(json.dumps(row).encode() + b"\n" for row in rows) + tail)

    def test_dispatch_checkpoint_observes_exact_prefix_not_tail_or_success(self):
        progress, calls = self.checkpoint_inputs()
        path = "qualification/stages/native/receipt.json"
        cursor = self.journal(companion.CURSOR, progress)
        journal = self.journal(companion.CALL_INDEX, calls)
        prefix_identity = companion.identity(journal.read_bytes())
        with journal.open("ab") as file:
            file.write(b'{"truncated":')
        data = self.invoke()
        checkpoint = data["dispatch_checkpoint"]
        self.assertEqual(checkpoint["availability"], "observed")
        self.assertFalse(checkpoint["establishes_execution_success"])
        self.assertFalse(data["qualifies_execution"])
        self.assertTrue(data["observations"][path]["projection"]["timed_out"])
        self.assertEqual(checkpoint["boundary"]["fixture_ordinal"], 319)
        self.assertEqual(checkpoint["boundary"]["capture_records"], len(calls))
        self.assertEqual(checkpoint["cursor"], companion.identity(cursor.read_bytes()))
        self.assertEqual(checkpoint["call_index_prefix"], prefix_identity)
        methods = checkpoint["public_methods"]
        self.assertEqual(list(methods), sorted(companion.DISPATCH_METHODS))
        self.assertEqual(methods["engine_apply"], {"calls": 319, "wall_ns": 6380})
        self.assertEqual(methods["owned_drop"], {"calls": 1, "wall_ns": 7})
        self.assertEqual(sum(method["calls"] for method in methods.values()), 320)
        self.assertEqual(sum(method["wall_ns"] for method in methods.values()), 6387)

    def test_dispatch_checkpoint_refuses_unbound_incomplete_or_invalid_evidence(self):
        progress, calls = self.checkpoint_inputs()
        for change, expected in (
            ("missing", "missing"), ("truncated", "incomplete-call-prefix"),
            ("ordinal", "invalid-call-ordinal"), ("method", "invalid-call-record"),
            ("time", "invalid-json-or-fields"), ("sum", "dispatch-total-mismatch"),
            ("oversized", "over-byte-limit"), ("hardlink", "unsafe-path"),
            ("boundary", "invalid-dispatch-boundary"), ("early", "checkpoint-not-reached"),
            ("source", "source-unbound"),
        ):
            with self.subTest(change=change):
                case = self.temp / ("case-" + change)
                case.mkdir()
                previous = self.dest
                try:
                    self.dest = case
                    rows = [dict(row) for row in progress]
                    records = [dict(row) for row in calls]
                    if change == "ordinal": records[1]["ordinal"] = 0
                    if change == "method": records[1]["function"] = SECRET
                    if change == "time": del records[1]["elapsed_ns"]
                    if change == "sum": records[1]["elapsed_ns"] -= 1
                    if change == "oversized": records[1]["request"] = "x" * companion.MAX_CALL_ROW
                    if change == "boundary": rows[5]["completed_fixtures"] = 0
                    if change == "early": rows = rows[:-2]
                    if change == "truncated": records.pop()
                    self.journal(companion.CURSOR, rows)
                    journal = self.journal(companion.CALL_INDEX, records)
                    if change == "missing": journal.unlink()
                    if change == "hardlink":
                        alias = self.temp / "call-index-alias"
                        os.link(journal, alias)
                        self.addCleanup(alias.unlink)
                    data = self.invoke(extra=("--source-after-outcome", "failure") if change == "source" else ())
                    self.assertEqual(data["dispatch_checkpoint"], {"availability": expected})
                    self.assertEqual(data["workflow"]["execution_step"], "failure")
                    self.assertTrue(data["observations"]["qualification/stages/native/receipt.json"]["projection"]["timed_out"])
                finally:
                    self.dest = previous

    def test_linked_leaf_parent_and_hardlink_are_refused(self):
        outside = self.temp / "outside"
        outside.mkdir()
        payload = outside / "receipt.json"
        payload.write_text(SECRET)
        self.write("observations/unlisted", b"")
        (self.source / companion.PINS[0]).symlink_to(payload)
        os.link(payload, self.source / companion.PINS[1])
        (self.source / "qualification").symlink_to(outside, target_is_directory=True)
        results = self.invoke()["observations"]
        for path in (*companion.PINS, companion.CURSOR, "qualification/report.json"):
            self.assertEqual(results[path], {"availability": "unsafe-path"})

    def test_root_link_and_lexical_traversal_are_refused(self):
        link = self.temp / "link"
        link.symlink_to(self.source, target_is_directory=True)
        results = self.invoke(root=link)["observations"]
        self.assertEqual({r["availability"] for r in results.values()}, {"unsafe-path"})
        (self.dest / "summary.json").unlink()
        results = self.invoke(root=str(link) + "/../source")["observations"]
        self.assertEqual({r["availability"] for r in results.values()}, {"unsafe-path"})

    def test_destination_cannot_redirect_or_overwrite(self):
        redirected = self.temp / "redirected"
        redirected.symlink_to(self.dest, target_is_directory=True)
        self.invoke(dest=redirected, succeeds=False)
        original = self.temp / "original"
        original.write_text(SECRET)
        (self.dest / "summary.json").symlink_to(original)
        self.invoke(succeeds=False)
        self.assertEqual(original.read_text(), SECRET)

    def test_missing_root_and_oversized_files_are_not_success(self):
        self.assertEqual({r["availability"] for r in
                          self.invoke(root=self.temp / "absent")["observations"].values()}, {"missing"})
        (self.dest / "summary.json").unlink()
        for name, limit in ((companion.CURSOR, companion.MAX_CURSOR_ROWS * companion.MAX_CURSOR_ROW),
                            (companion.PINS[0], companion.MAX_RECEIPT)):
            with self.write(name, b"").open("r+b") as file:
                file.truncate(limit + 1)
        results = self.invoke()["observations"]
        self.assertEqual(results[companion.CURSOR], {"availability": "over-byte-limit"})
        self.assertEqual(results[companion.PINS[0]], {"availability": "over-byte-limit"})

    def test_fifo_duplicate_json_fields_and_wrong_budget_are_refused(self):
        bad_source = self.write(companion.PINS[0], b"")
        bad_source.unlink()
        os.mkfifo(bad_source)
        path = "qualification/stages/native/receipt.json"
        wrong = dict(self.timed_receipt(), execution_deadline_seconds=241)
        self.doc(path, wrong)
        self.write(companion.CURSOR, b'{"phase":"stage_start","phase":"stage_done"}\n')
        results = self.invoke()["observations"]
        self.assertEqual(results[companion.PINS[0]], {"availability": "unsafe-path"})
        self.assertEqual(results[path]["availability"], "invalid-deadline")
        self.assertEqual(results[companion.CURSOR]["availability"], "invalid-json")

    def test_cross_attempt_binding_cannot_appear_observed(self):
        self.doc(companion.BINDING, {"schema": "trnm.hia.additional-owner-ci-binding.v1",
                                    "component": "settlement-engine", "status": "PASS",
                                    "head": HEAD, "run_id": "12345", "run_attempt": "1",
                                    "tree": TREE, "source_set_sha256": "3" * 64})
        result = self.invoke()["observations"][companion.BINDING]
        self.assertEqual(result["availability"], "invalid-source-bind")
        self.assertNotIn("projection", result)

    def test_integrity_failure_prefix_is_not_a_failed_control_verdict(self):
        report = {"status": "FAIL", "cases": [
            {"name": companion.ROSTER[0], "result": "PASS"},
            {"name": companion.ROSTER[1], "result": "REJECTED", "exception": SECRET},
        ], "exception": SECRET}
        data = self.doc(companion.INTEGRITY, report).read_bytes()
        receipt = "qualification/stages/integrity/receipt.json"
        self.doc(receipt, self.timed_receipt())
        summary = self.invoke()
        observations = summary["observations"]
        self.assertEqual(observations[receipt]["projection"]["status"], "FAIL")
        self.assertEqual(observations[companion.INTEGRITY]["original"], companion.identity(data))
        projected = observations[companion.INTEGRITY]["projection"]
        self.assertEqual(projected["reported_status"], "FAIL")
        self.assertEqual(projected["results_in_roster_order"], ["PASS", "REJECTED"])
        self.assertEqual(projected["last_recorded_control"], companion.ROSTER[1])
        self.assertEqual(projected["first_unrecorded_control"], companion.ROSTER[2])
        self.assertEqual(projected["unrecorded_controls"], len(companion.ROSTER) - 2)
        self.assertFalse(projected["establishes_reader_success"])

    def test_integrity_complete_producer_does_not_substitute_missing_reader(self):
        roster = companion.ROSTER
        self.doc(companion.INTEGRITY, {"schema": companion.INTEGRITY_SCHEMA, "status": "PASS",
                                     "roster": roster, "passed": len(roster), "failed": 0,
                                     "not_run": 0, "cases": [
                                         {"name": name, "result": "PASS",
                                          "arbitrary_nested_diagnostic": SECRET}
                                         for name in roster]})
        result = self.invoke()["observations"]
        projected = result[companion.INTEGRITY]["projection"]
        self.assertEqual(projected["reported_status"], "PASS")
        self.assertEqual(projected["unrecorded_controls"], 0)
        self.assertIsNone(projected["first_unrecorded_control"])
        self.assertFalse(projected["establishes_reader_success"])
        self.assertEqual(result["independent-readback/report.json"], {"availability": "missing"})

    def test_integrity_rejects_fabricated_partial_pass_or_unregistered_label(self):
        roster = companion.ROSTER
        partial = {"schema": companion.INTEGRITY_SCHEMA, "status": "PASS",
                   "roster": roster, "passed": len(roster), "failed": 0, "not_run": 0,
                   "cases": [{"name": roster[0], "result": "PASS"}]}
        cases = (
            partial, {"status": "FAIL", "cases": [{"name": roster[1], "result": "PASS"}]},
            {"status": "FAIL", "cases": [{"name": SECRET, "result": "PASS"}]},
            {"status": "FAIL", "cases": [42] * (len(roster) + 1)},
        )
        for report in cases:
            self.doc(companion.INTEGRITY, report)
            observed = self.invoke()["observations"][companion.INTEGRITY]
            self.assertIn(observed["availability"], ("invalid-integrity-roster",
                                                      "invalid-integrity-report"))
            self.assertNotIn("projection", observed)
            (self.dest / "summary.json").unlink()

    def test_integrity_report_and_process_receipt_have_separate_availability(self):
        path = "qualification/stages/integrity/receipt.json"
        self.doc(path, dict(self.timed_receipt(), execution_deadline_seconds=239))
        observations = self.invoke()["observations"]
        self.assertEqual(observations[path]["availability"], "invalid-deadline")
        self.assertEqual(observations[companion.INTEGRITY], {"availability": "missing"})

    def test_wiring_keeps_full_original_upload_and_non_gating_sidecar(self):
        workflow = (ROOT / ".github/workflows/hia-native-migration.yml").read_text()
        self.assert_wiring_keeps_full_original_upload(workflow)

    def assert_wiring_keeps_full_original_upload(self, workflow):
        job = owner_without_cpu_workflow(workflow)
        run = job.split("      - name: Collect compact", 1)[0]
        compact = job.split("      - name: Collect compact", 1)[1].split("      - name: Retain and reread", 1)[0]
        full = job.split("      - name: Retain and reread", 1)[1].split(
            "      - name: Collect separate Settlement image identity", 1)[0]
        self.assertIn("timeout-minutes: 20", run)
        for needle in ("qualify_additional_owner_ci.py run", "qualify_additional_owner_ci.py bind",
                       "source-before.json", "source-after.json"):
            self.assertIn(needle, run)
        self.assertNotIn("continue-on-error:", run)
        self.assertEqual(compact.count("continue-on-error: true"), 2)
        self.assertEqual(compact.count("if: always() && matrix.component == 'settlement-engine'"), 2)
        self.assertIn("path: ${{ runner.temp }}/settlement-compact/summary.json", compact)
        self.assertIn("python3 -B -m hia.tools.settlement_companion", compact)
        self.assertNotIn("OWNER_ARTIFACT", compact)
        self.assertNotIn("continue-on-error:", full)
        self.assertEqual(full.count("if: always()"), 2)
        self.assertIn("if-no-files-found: error", full)
        self.assertIn("archive_runtime_observations.py --root \"component=$OWNER_ROOT\"", full)
        self.assertIn("${{ env.OWNER_ARTIFACT }}/", full)
        self.assertIn("${{ env.OWNER_ROOT }}/observations/", full)

    def test_image_identity_is_separate_settlement_only_postlude(self):
        workflow = (ROOT / ".github/workflows/hia-native-migration.yml").read_text()
        postlude = self.assert_image_identity_postlude(workflow)
        collect, _ = postlude.split("      - name: Upload the separate Settlement image identity diagnostic")
        # Exercise the actual shell postlude on an ordinary incomplete owner;
        # it must preserve v1 and emit a distinct non-qualifying missing result.
        shell = textwrap.dedent(collect.split("        run: |\n", 1)[1])
        self.invoke()
        legacy = self.dest / "summary.json"
        before = legacy.read_bytes()
        pin = {"schema": "trnm-ci-source-v1", "kind": "head", "tested_commit": HEAD,
               "candidate": HEAD, "tested_tree": TREE, "tracked_worktree_verified": True,
               "tracked_entries": 800, "tracked_bytes": 1200}
        for name in companion.PINS:
            self.doc(name, pin)
        result = subprocess.run(["bash", "-c", shell], cwd=ROOT, capture_output=True, text=True, timeout=10,
                                env={"PATH": os.defpath, "RUNNER_TEMP": str(self.temp),
                                     "OWNER_ROOT": str(self.source), "TRNM_EXPECTED_SOURCE_SHA": HEAD,
                                     "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2",
                                     "SETTLEMENT_SOURCE_AFTER_OUTCOME": "success"})
        self.assertEqual(result.returncode, 0, result.stderr)
        identity = self.temp / "settlement-image-identity"
        self.assertEqual([p.name for p in identity.iterdir()], ["image-identity.json"])
        actual = json.loads((identity / "image-identity.json").read_bytes())
        self.assertEqual(actual["workflow"], {"head": HEAD, "tree": TREE, "run_id": "12345",
                                              "run_attempt": "2", "original_binding": "missing"})
        self.assertEqual(actual["linked"], {"availability": "missing"})
        self.assertFalse(actual["qualifies_execution"])
        self.assertFalse(actual["substitutes_full_original_archive"])
        self.assertEqual(legacy.read_bytes(), before)

    def assert_image_identity_postlude(self, workflow):
        job = owner_without_cpu_workflow(workflow)
        mark = "      - name: Collect separate Settlement image identity"
        self.assertEqual(job.count(mark), 1)
        original, postlude = job.split(mark, 1)
        self.assertTrue(original.endswith("          retention-days: 30\n"))
        self.assertGreater(original.rfind("Upload complete current-source observations and diagnostics"), 0)
        collect, upload = postlude.split("      - name: Upload the separate Settlement image identity diagnostic")
        self.assertEqual(postlude.count("continue-on-error: true"), 2)
        self.assertEqual(postlude.count("if: always() && matrix.component == 'settlement-engine'"), 2)
        self.assertIn("id: settlement_image_identity", collect)
        self.assertIn("SETTLEMENT_SOURCE_AFTER_OUTCOME: ${{ steps.owner_source_after.outcome }}", collect)
        self.assertIn("&& steps.settlement_image_identity.outcome == 'success'", upload)
        self.assertIn("name: hia-settlement-image-identity-${{ env.TRNM_EXPECTED_SOURCE_SHA }}"
                      "-${{ github.run_id }}-${{ github.run_attempt }}", upload)
        self.assertIn("path: ${{ runner.temp }}/settlement-image-identity/image-identity.json", upload)
        self.assertIn("retention-days: 30", upload)
        self.assertNotIn("OWNER_ARTIFACT", postlude)
        self.assertNotIn("settlement-compact", postlude)
        self.assertNotIn("timeout-minutes:", postlude)
        self.assertNotIn("permissions:", postlude)
        self.assertNotIn("qualify_additional_owner_ci.py", postlude)

        return postlude

    def test_optional_cpu_allowlist_refuses_drift_misplacement_and_duplicates(self):
        workflow = (ROOT / ".github/workflows/hia-native-migration.yml").read_text()
        before, after, upload = CPU_STEP_ALLOWLIST.values()
        for name, altered in {
                "missing before": workflow.replace(before, ""),
                "duplicate after": workflow.replace(after, after + after),
                "wrong lane": workflow.replace(before, before.replace("'settlement-engine'", "'pq-auth'")),
                "archive destination": workflow.replace(upload, upload.replace("settlement-runner-cpu/before.json", "settlement-compact/summary.json")),
                "mandatory CPU": workflow.replace(after, after.replace("continue-on-error: true", "continue-on-error: false")),
                "overlong optional probe": workflow.replace(before, before.replace("timeout 2s", "timeout 240s")),
                "misplaced before": workflow.replace(before, "").replace(after, before + after),
                "misplaced upload": workflow.replace(upload, "").replace(before, upload + before),
        }.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                owner_without_cpu_workflow(altered)

    def test_optional_cpu_allowlist_does_not_exempt_mandatory_or_other_optional_steps(self):
        workflow = (ROOT / ".github/workflows/hia-native-migration.yml").read_text()
        for mark, check in (
            ("id: owner_execute", self.assert_wiring_keeps_full_original_upload),
            ("name: Upload complete current-source observations and diagnostics",
             self.assert_wiring_keeps_full_original_upload),
            ("name: Upload the separate Settlement image identity diagnostic",
             self.assert_image_identity_postlude),
        ):
            with self.subTest(mark=mark):
                self.assertEqual(workflow.count(mark), 1)
                altered = workflow.replace(mark + "\n", mark + "\n        continue-on-error: true\n", 1)
                with self.assertRaises(AssertionError):
                    check(altered)

        # A differently named optional step is not hidden by the projection.
        extra = ("      - name: Unreviewed optional step\n"
                 "        continue-on-error: true\n"
                 "        run: echo example\n")
        with self.assertRaises(AssertionError):
            self.assert_image_identity_postlude(workflow + extra)


if __name__ == "__main__":
    unittest.main()
