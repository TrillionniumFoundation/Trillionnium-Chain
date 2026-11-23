"""Exercise the exact hosted companion entry point; this never runs Settlement."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hia.tools import settlement_companion as companion
from hia.platform.service_settlement.qualification.native import Progress


ROOT = Path(__file__).resolve().parents[2]
HEAD = "1" * 40
TREE = "2" * 40
SECRET = "private-fixture-bytes-and-env-secret"


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
            sys.executable, "-B", str(ROOT / "hia/tools/settlement_companion.py"),
            "--root", str(root or self.source), "--output-dir", str(dest or self.dest),
            "--head", HEAD, "--run-id", "12345", "--run-attempt", "2",
            "--execution-outcome", "failure", "--source-after-outcome", "success",
            "--binding-outcome", "skipped", "--job-status", "failure",
            *extra], check=False, capture_output=True, text=True, timeout=10)
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

    def test_wiring_keeps_full_original_upload_and_non_gating_sidecar(self):
        workflow = (ROOT / ".github/workflows/hia-native-migration.yml").read_text()
        job = workflow.split("\n  native-additional-owners:", 1)[1]
        run = job.split("      - name: Collect compact", 1)[0]
        compact = job.split("      - name: Collect compact", 1)[1].split("      - name: Retain and reread", 1)[0]
        full = job.split("      - name: Retain and reread", 1)[1]
        self.assertIn("timeout-minutes: 20", run)
        for needle in ("qualify_additional_owner_ci.py run", "qualify_additional_owner_ci.py bind",
                       "source-before.json", "source-after.json"):
            self.assertIn(needle, run)
        self.assertNotIn("continue-on-error:", run)
        self.assertEqual(compact.count("continue-on-error: true"), 2)
        self.assertEqual(compact.count("if: always() && matrix.component == 'settlement-engine'"), 2)
        self.assertIn("path: ${{ runner.temp }}/settlement-compact/summary.json", compact)
        self.assertNotIn("OWNER_ARTIFACT", compact)
        self.assertNotIn("continue-on-error:", full)
        self.assertIn("archive_runtime_observations.py --root \"component=$OWNER_ROOT\"", full)
        self.assertIn("${{ env.OWNER_ARTIFACT }}/", full)
        self.assertIn("${{ env.OWNER_ROOT }}/observations/", full)


if __name__ == "__main__":
    unittest.main()
