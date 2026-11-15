#!/usr/bin/env python3
"""Original-deadline and dispatch controls, never synthetic proof evidence.

Executable children either exercise the process observer or fail preparation.
No control produces a checkpoint, seal, successful prover, or accepted proof.
"""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS = ROOT / "formal/pon-nakamoto-v1/experiments"
sys.path.insert(0, str(EXPERIMENTS))
import w1_stage_measure as stage
import w1_full_staged_run as coordinator

FROZEN = ROOT / "evidence/pon-w1-complete-succinct-20261028/full-proof"


class CoordinatorDeadlineControls(unittest.TestCase):
    def invocation(self, temp, code="raise SystemExit(7)", seconds=5):
        command = temp / "negative-control"
        command.write_text("#!/usr/bin/env python3\n" + code + "\n")
        command.chmod(0o755)
        return ["--runner", str(command), "--r0vm", str(command),
                "--fresh-verifier", str(command), "--native-verifier", str(command),
                "--prepare-input", str(FROZEN / "input.bin"),
                "--checkpoint", str(temp / "checkpoint"), "--out", str(temp / "result"),
                "--total-wall-seconds", str(seconds)]

    def rejected_cli(self, extra):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            temp = Path(directory)
            with patch.object(coordinator, "measure") as measured, self.assertRaises(SystemExit) as caught:
                coordinator.main(self.invocation(temp) + extra)
            self.assertEqual(caught.exception.code, 2)
            measured.assert_not_called()
            self.assertFalse((temp / "result").exists())

    def test_original_deadline_and_boot_id_are_a_required_pair(self):
        for extra in (["--deadline-monotonic", "100"],
                      ["--deadline-boot-id", coordinator.current_boot_id()]):
            with self.subTest(extra=extra):
                self.rejected_cli(extra)

    def test_nonfinite_original_deadlines_are_rejected_before_dispatch(self):
        for number in ("nan", "inf", "-inf"):
            with self.subTest(number=number):
                self.rejected_cli(["--deadline-monotonic=" + number,
                                   "--deadline-boot-id", coordinator.current_boot_id()])

    def test_a_different_boot_cannot_supply_a_monotonic_deadline(self):
        wrong = "00000000-0000-0000-0000-000000000000"
        self.assertNotEqual(wrong, coordinator.current_boot_id())
        self.rejected_cli(["--deadline-monotonic", str(time.monotonic() + 10),
                           "--deadline-boot-id", wrong])

    def test_omitted_original_deadline_retains_the_local_budget(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            temp = Path(directory)
            self.assertEqual(coordinator.main(self.invocation(temp)), 1)
            result = json.loads((temp / "result/result.json").read_text())
            self.assertIsNone(result["original_deadline_monotonic"])
            self.assertFalse(result["original_local_deadline_supplied"])
            self.assertEqual(result["deadline_boot_id"], coordinator.current_boot_id())
            self.assertEqual(result["deadline_monotonic"], result["started_monotonic"] + 5)
            self.assertFalse(result["complete_proof_claim"])
            self.assertFalse(result["end_to_end_observation_complete"])
            self.assertIsNone(result["parent_observed_receiver_ack_monotonic_ns"])
            self.assertIsNone(result["parent_observed_receiver_ack_boot_id"])
            self.assertEqual(result["stages"][0]["result"]["returncode"], 7)

    def test_expired_original_deadline_cannot_restart_a_relative_allowance(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            temp = Path(directory)
            original = time.monotonic() - 1
            with patch.object(coordinator, "measure") as measured:
                self.assertEqual(coordinator.main(self.invocation(temp) + [
                    "--deadline-monotonic", repr(original),
                    "--deadline-boot-id", coordinator.current_boot_id()]), 1)
            measured.assert_not_called()
            result = json.loads((temp / "result/result.json").read_text())
            self.assertEqual(result["deadline_monotonic"], original)
            self.assertEqual(result["stages"], [])
            self.assertTrue(result["deadline_exhausted_at_snapshot"])
            self.assertFalse(result["complete_proof_claim"])

    def test_later_original_deadline_cannot_extend_the_local_budget(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            temp = Path(directory)
            original = time.monotonic() + 60
            self.assertEqual(coordinator.main(self.invocation(temp, seconds=5) + [
                "--deadline-monotonic", repr(original),
                "--deadline-boot-id", coordinator.current_boot_id()]), 1)
            result = json.loads((temp / "result/result.json").read_text())
            self.assertEqual(result["deadline_monotonic"], result["started_monotonic"] + 5)
            self.assertLess(result["deadline_monotonic"], original)
            self.assertFalse(result["complete_proof_claim"])

    def test_initialization_work_spends_the_unchanged_original_deadline(self):
        now = [100.0]
        clock = SimpleNamespace(monotonic=lambda: now[0], time_ns=time.time_ns)
        original_hash = coordinator.sha

        def charged_hash(path):
            result = original_hash(path)
            now[0] += .25
            return result

        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            temp = Path(directory)
            with patch.object(coordinator, "time", clock), \
                    patch.object(coordinator, "sha", side_effect=charged_hash), \
                    patch.object(coordinator, "measure") as measured:
                self.assertEqual(coordinator.main(self.invocation(temp, seconds=30) + [
                    "--deadline-monotonic", "100.1",
                    "--deadline-boot-id", coordinator.current_boot_id()]), 1)
            measured.assert_not_called()
            result = json.loads((temp / "result/result.json").read_text())
            self.assertEqual(result["deadline_monotonic"], 100.1)
            self.assertTrue(result["deadline_exhausted_at_snapshot"])
            self.assertFalse(result["complete_proof_claim"])

    def test_prior_wall_cost_and_original_deadline_both_bound_resume(self):
        self.assertEqual(coordinator.effective_deadline(100, 20, 18, 110), 102)
        self.assertEqual(coordinator.effective_deadline(100, 20, 18, 101), 101)
        self.assertEqual(coordinator.effective_deadline(100, 20, 21, 110), 99)

    def test_real_cancel_preserves_the_original_deadline_and_boot(self):
        original_snapshot = stage.session_snapshot
        sent = False

        def cancel_once(session):
            nonlocal sent
            result = original_snapshot(session)
            if not sent:
                sent = True
                os.kill(os.getpid(), signal.SIGTERM)
            return result

        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            temp = Path(directory)
            deadline = time.monotonic() + 10
            with patch.object(stage, "session_snapshot", side_effect=cancel_once), \
                    self.assertRaises(stage.Canceled) as caught:
                coordinator.main(self.invocation(temp, "import time;time.sleep(60)", 20) + [
                    "--deadline-monotonic", repr(deadline),
                    "--deadline-boot-id", coordinator.current_boot_id()])
            self.assertTrue(sent)
            self.assertEqual(caught.exception.signum, signal.SIGTERM)
            result = json.loads((temp / "result/result.json").read_text())
            self.assertEqual(result["deadline_monotonic"], deadline)
            self.assertEqual(result["controller_canceled_signal"], signal.SIGTERM)
            self.assertEqual(result["deadline_boot_id"], coordinator.current_boot_id())
            self.assertEqual(result["stages"][0]["result"]["effective_deadline_monotonic"], deadline)
            self.assertFalse(result["end_to_end_observation_complete"])
            self.assertFalse(result["complete_proof_claim"])

    def test_cli_resource_oversubscription_is_rejected_before_dispatch(self):
        for extra in (["--segment-workers", "2"],
                      ["--compression-mode", "balanced", "--compression-workers", "2"],
                      ["--compression-mode", "sequential", "--compression-workers", "2", "--rayon-threads", "2"],
                      ["--segment-workers", "0"], ["--rayon-threads", "0"]):
            with self.subTest(extra=extra):
                self.rejected_cli(extra)

    def test_completion_hook_requires_complete_v2_statement(self):
        self.rejected_cli(["--completion-hook-json", "/does/not/exist.json"])


class ResourceAndHookControls(unittest.TestCase):
    def test_explicit_schedule_preserves_the_sequential_baseline_argv(self):
        base = [Path("/bin/backend"), "--r0vm", Path("/bin/r0vm")]
        checkpoint = Path("/run/checkpoint")
        self.assertEqual(coordinator.segment_command(base, checkpoint, 1),
                         [*base, "prove", checkpoint, "1"])
        self.assertEqual(coordinator.segment_command(base, checkpoint, 2),
                         [*base, "prove-parallel", checkpoint, "2", "2"])
        self.assertEqual(coordinator.compression_command(base, checkpoint, "sequential", 1),
                         [*base, "compress", checkpoint])
        self.assertEqual(coordinator.compression_command(base, checkpoint, "balanced", 2),
                         [*base, "compress-balanced", checkpoint, "2"])
        self.assertEqual(coordinator.resource_plan(2, "balanced", 2, 4)["maximum_planned_rayon_workers"], 8)

    def test_resource_plan_rejects_type_and_budget_substitution(self):
        for args in ((True, "sequential", 1, 8), (1, "sequential", True, 8),
                     (1, "sequential", 1, True), (5, "balanced", 1, 1),
                     (1, "balanced", 5, 1), (2, "balanced", 2, 5),
                     (1, "sequential", 2, 2), (1, "other", 1, 1)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                coordinator.resource_plan(*args)

    def test_actual_child_receives_declared_rayon_without_mutating_parent(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"RAYON_NUM_THREADS": "6"}):
            out = Path(directory) / "stage"
            result = stage.measure([sys.executable, "-c", "import os;print(os.environ['RAYON_NUM_THREADS'])"],
                                   out, 3, environment_overrides={"RAYON_NUM_THREADS": "2"})
            self.assertEqual((out / "stdout.log").read_text(), "2\n")
            self.assertEqual(result["environment"]["RAYON_NUM_THREADS"], "2")
            self.assertEqual(result["explicit_environment_override_names"], ["RAYON_NUM_THREADS"])
            self.assertEqual(os.environ["RAYON_NUM_THREADS"], "6")
            self.assertTrue(result["stage_process_complete"])
            self.assertFalse(result["complete_proof_claim"])

    def test_invalid_environment_override_does_not_start_a_process(self):
        for value in ({"RAYON_NUM_THREADS": 2}, {"bad=name": "x"}, {"name": "x\0y"}, ["x"]):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                out = Path(directory) / "stage"
                with patch.object(stage.subprocess, "Popen") as process, self.assertRaises(ValueError):
                    stage.measure([sys.executable, "-c", "raise SystemExit(7)"], out, 3,
                                  environment_overrides=value)
                process.assert_not_called()
                self.assertFalse(out.exists())

    def test_cli_late_snapshot_write_keeps_the_fact_but_returns_timeout(self):
        original_write = stage.write_new
        saved = {}
        deadline = time.monotonic() + 2

        def slow_after_snapshot(path, value):
            original_write(path, value)
            if path.name == "result.json":
                saved["bytes"] = path.read_bytes()
                time.sleep(max(0, deadline - time.monotonic()) + .02)

        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            out = Path(directory) / "late-write"
            with patch.object(stage, "write_new", side_effect=slow_after_snapshot):
                status = stage.main(["--wall-seconds", "5", "--deadline-monotonic", repr(deadline),
                                     "--out", str(out), "--", sys.executable, "-c", "raise SystemExit(0)"])
            self.assertEqual(status, 124)
            self.assertEqual((out / "result.json").read_bytes(), saved["bytes"])
            result = json.loads(saved["bytes"])
            self.assertTrue(result["stage_process_complete"])
            self.assertFalse(result["deadline_exhausted_at_snapshot"])
            self.assertFalse(result["complete_proof_claim"])

    def hook(self, temp):
        return {"schema": "TRNM-W1-COMPLETION-HOOK1",
                "argv": [sys.executable, "-c", "raise SystemExit(7)"],
                "ack_path": str(temp / "receiver/ack.json")}

    def test_hook_declaration_pins_configuration_and_executable_only(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            path = temp / "hook.json"
            value = self.hook(temp)
            path.write_text(json.dumps(value))
            row = coordinator.completion_hook_declaration(path)
            self.assertEqual(row["argv"], value["argv"])
            self.assertEqual(row["config_sha256"], stage.sha(path))
            self.assertEqual(row["argv0_sha256"], stage.sha(Path(sys.executable)))
            self.assertFalse(Path(row["ack_path"]).exists())
            self.assertNotIn("verified", row)

    def test_hook_rejects_relative_paths_invalid_argv_and_other_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            changes = ({"schema": "TRNM-W1-COMPLETION-HOOK0"}, {"argv": []},
                       {"argv": ["python3", "-c", "raise SystemExit(7)"]},
                       {"argv": [sys.executable, None]}, {"ack_path": "ack.json"},
                       {"extra": True})
            for index, change in enumerate(changes):
                with self.subTest(change=change):
                    path = temp / f"hook-{index}.json"
                    path.write_text(json.dumps({**self.hook(temp), **change}))
                    with self.assertRaises(ValueError):
                        coordinator.completion_hook_declaration(path)

    def test_existing_ack_and_dangling_symlink_cannot_supply_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            (temp / "receiver").mkdir()
            value = self.hook(temp)
            ack = Path(value["ack_path"])
            path = temp / "hook.json"
            path.write_text(json.dumps(value))
            ack.write_text("untrusted pre-existing data")
            with self.assertRaises(ValueError):
                coordinator.completion_hook_declaration(path)
            ack.unlink()
            ack.symlink_to(temp / "missing")
            with self.assertRaises(ValueError):
                coordinator.completion_hook_declaration(path)

    def test_receiver_ack_rejects_every_wrong_identity_and_negative_terminal_fact(self):
        # These dictionaries are rejection inputs only. No synthetic ACK passes
        # the check, invokes a receiver, or stands in for proof verification.
        identity = {"work_id": "11" * 32, "header_sha256": "22" * 32,
                    "external_artifacts_sha256": "33" * 32, "receipt_sha256": "44" * 32}
        seed = {"schema": "TRNM-W1-RECEIVER-ACK2", "receiver_operation_complete": True,
                "verified": True, "admission_authorized": False, "error": None,
                "cancellation_event": None, "deadline_exhausted_at_snapshot": False,
                "work_id": identity["work_id"], "header_sha256": identity["header_sha256"],
                "expected_artifacts_sha256": identity["external_artifacts_sha256"],
                "receipt_sha256": identity["receipt_sha256"]}
        mutations = [{field: "00" * 32} for field in (
            "work_id", "header_sha256", "expected_artifacts_sha256", "receipt_sha256")]
        mutations += [{"schema": "other"}, {"receiver_operation_complete": 1},
                      {"verified": False}, {"admission_authorized": True},
                      {"error": {"type": "OSError"}}, {"cancellation_event": {}},
                      {"canceled_signal": 15}, {"cleanup_unknown": True},
                      {"deadline_exhausted_at_snapshot": True}]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                coordinator.validate_receiver_ack({**copy.deepcopy(seed), **mutation}, identity)


if __name__ == "__main__":
    unittest.main()
