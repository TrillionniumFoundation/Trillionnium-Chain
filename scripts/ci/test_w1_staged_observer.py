#!/usr/bin/env python3
"""Lifecycle and binding controls, never successful synthetic proof evidence."""
import contextlib
import copy
import errno
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS = ROOT / "formal/pon-nakamoto-v1/experiments"
sys.path.insert(0, str(EXPERIMENTS))
import w1_stage_measure as stage
import w1_full_staged_run as coordinator
import w1_local_payload as local

FROZEN = ROOT / "evidence/pon-w1-complete-succinct-20261028/full-proof"


class ProcessLifecycleTests(unittest.TestCase):
    def run_control(self, code, seconds=3):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        out = Path(temp.name) / "observation"
        result = stage.measure([sys.executable, "-c", code], out, seconds)
        self.assertEqual(json.loads((out / "result.json").read_text()), result)
        self.assertFalse(result["complete_proof_claim"])
        self.assertFalse(result["prover_resource_completeness_established"])
        self.assertIsNone(result["aggregate_process_tree_peak_rss_bytes"])
        return out, result

    def test_actual_success_and_failure_keep_raw_logs_and_usage(self):
        for status in (0, 7):
            with self.subTest(status=status):
                out, result = self.run_control(f"print('control only');raise SystemExit({status})")
                self.assertEqual(result["returncode"], status)
                self.assertEqual((out / "stdout.log").read_text(), "control only\n")
                self.assertEqual(result["stage_process_complete"], status == 0)
                self.assertGreater(result["rusage"]["max_single_process_rss_bytes"], 0)

    def test_timeout_preserves_failed_trial_and_settles_session(self):
        _, result = self.run_control("import time;time.sleep(60)", .15)
        self.assertTrue(result["timed_out"])
        self.assertIn("TIMEOUT", result["termination_reasons"])
        self.assertFalse(result["stage_process_complete"])
        self.assertEqual(result["final_owned_session_members"], [])
        self.assertLess(result["wall_seconds"], 2)

    def test_absolute_budget_exhaustion_does_not_spawn(self):
        with tempfile.TemporaryDirectory() as temp:
            result = stage.measure([sys.executable, "-c", "raise SystemExit(0)"],
                                   Path(temp) / "expired", 100, deadline=time.monotonic() - 1)
            self.assertIsNone(result["pid"])
            self.assertIsNone(result["returncode"])
            self.assertIn("DEADLINE_EXHAUSTED_BEFORE_SPAWN", result["termination_reasons"])

    def test_absolute_deadline_wins_over_fresh_stage_allowance(self):
        with tempfile.TemporaryDirectory() as temp:
            result = stage.measure([sys.executable, "-c", "import time;time.sleep(60)"],
                                   Path(temp) / "deadline", 100, deadline=time.monotonic() + .15)
            self.assertTrue(result["timed_out"])
            self.assertLess(result["wall_seconds"], 2)

    def test_late_observed_exit_zero_cannot_pass_the_budget(self):
        real_sleep = time.sleep
        with patch.object(stage.time, "sleep", side_effect=lambda _: real_sleep(.4)):
            _, result = self.run_control("import time;time.sleep(.25)", .2)
        self.assertEqual(result["returncode"], 0)
        self.assertIn("COMPLETION_NOT_OBSERVED_BEFORE_DEADLINE", result["termination_reasons"])
        self.assertFalse(result["stage_process_complete"])

    def test_exit_zero_cannot_leave_unsettled_descendants(self):
        for group_option in ("", ",process_group=0"):
            with self.subTest(group_option=group_option):
                _, result = self.run_control("import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']" + group_option + ")")
                self.assertEqual(result["returncode"], 0)
                self.assertIn("DESCENDANTS_REMAINED_AFTER_CHILD_EXIT", result["termination_reasons"])
                self.assertFalse(result["stage_process_complete"])
                self.assertFalse(any(row["state"] != "Z" for row in result["final_owned_session_members"]))
                if group_option:
                    self.assertGreaterEqual(len(result["known_owned_groups"]), 2)
                    self.assertTrue(all(any(attempt["group"] == group and attempt["signal"] == signal.SIGTERM
                                            for attempt in result["signal_attempts"])
                                        for group in result["known_owned_groups"]))

    def test_cancellation_signal_is_recorded_by_real_supervisor(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "cancel"
            process = subprocess.Popen([sys.executable, str(EXPERIMENTS / "w1_stage_measure.py"),
                "--wall-seconds", "60", "--out", str(out), "--", sys.executable, "-c",
                "import time;time.sleep(60)"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while not (out / "process-samples.jsonl").exists() or not (out / "process-samples.jsonl").stat().st_size:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.02)
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=5)
                self.assertNotEqual(process.returncode, 0)
                result = json.loads((out / "result.json").read_text())
                self.assertIn("CANCELED_SIGNAL_15", result["termination_reasons"])
                self.assertFalse(result["stage_process_complete"])
                self.assertEqual(result["final_owned_session_members"], [])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)

    def test_ignored_sigterm_escalates_and_output_overflow_remains_failure(self):
        with patch.object(stage, "TERMINATION_GRACE_SECONDS", .15):
            _, result = self.run_control("import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)", .2)
        self.assertIn("SIGKILL_DURING_SETTLEMENT", result["termination_reasons"])
        self.assertEqual(result["returncode"], -signal.SIGKILL)
        with patch.object(stage, "MAX_LOG_BYTES", 4096):
            out, result = self.run_control("print('x'*8192)")
        self.assertIn("OUTPUT_LIMIT", result["termination_reasons"])
        self.assertFalse(result["stage_process_complete"])
        self.assertGreater((out / "stdout.log").stat().st_size, 4096)

    def test_unreadable_or_malformed_owned_proc_is_not_an_empty_session(self):
        original = stage.read_proc_member
        for failure in (PermissionError(errno.EACCES, "injected unreadable owned proc"),
                        ValueError("injected malformed owned proc")):
            def unreadable(*args):
                member = original(*args)
                if member is not None:
                    raise failure
                return member
            with self.subTest(failure=type(failure).__name__), patch.object(stage, "read_proc_member", side_effect=unreadable):
                _, result = self.run_control("import time;time.sleep(60)")
            self.assertIn("PROC_STATE_UNKNOWN", result["termination_reasons"])
            self.assertFalse(result["stage_process_complete"])
            self.assertFalse(result["owned_session_observation_complete"])
            self.assertTrue(any(row["type"] == type(failure).__name__ for row in result["proc_scan_errors"]))
            self.assertEqual({row["signal"] for row in result["signal_attempts"]},
                             {signal.SIGTERM, signal.SIGKILL})
            self.assertIsNotNone(result["returncode"])

    def test_cleanup_scan_failure_keeps_result_and_signals_known_groups(self):
        original = stage.session_snapshot
        calls = 0
        def unreadable_during_cleanup(session):
            nonlocal calls
            calls += 1
            if calls >= 2:
                raise PermissionError(errno.EACCES, "injected cleanup proc failure")
            return original(session)
        with patch.object(stage, "session_snapshot", side_effect=unreadable_during_cleanup), \
                patch.object(stage, "TERMINATION_GRACE_SECONDS", .15):
            _, result = self.run_control("import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])")
        self.assertFalse(result["stage_process_complete"])
        self.assertFalse(result["owned_session_observation_complete"])
        self.assertTrue(any(row["phase"] in ("settlement_entry", "settling", "final")
                            for row in result["proc_scan_errors"]))
        self.assertEqual({row["signal"] for row in result["signal_attempts"]},
                         {signal.SIGTERM, signal.SIGKILL})
        self.assertFalse(any(row["state"] != "Z" for row in original(result["pid"])["members"]))

    def test_enoent_exit_race_is_distinct_from_unknown_membership(self):
        original = stage.read_proc_member
        injected = False
        def disappeared_once(*args):
            nonlocal injected
            member = original(*args)
            if member is not None and not injected:
                injected = True
                raise FileNotFoundError(errno.ENOENT, "injected proc disappearance race")
            return member
        with patch.object(stage, "read_proc_member", side_effect=disappeared_once):
            _, result = self.run_control("import time;time.sleep(.1)")
        self.assertTrue(injected)
        self.assertTrue(result["stage_process_complete"])
        self.assertTrue(result["owned_session_observation_complete"])
        self.assertEqual(result["proc_scan_errors"], [])
        self.assertTrue(any(row["errno"] == errno.ENOENT for row in result["proc_disappearance_races"]))

    def test_kernel_group_probe_exposes_an_empty_proc_snapshot(self):
        original = stage.session_snapshot
        with patch.object(stage, "session_snapshot", return_value={"members": [], "errors": [], "disappearance_races": []}), \
                patch.object(stage, "TERMINATION_GRACE_SECONDS", .15):
            _, result = self.run_control("import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])")
        self.assertEqual(result["returncode"], 0)
        self.assertFalse(result["stage_process_complete"])
        self.assertFalse(result["owned_session_observation_complete"])
        self.assertIn("GROUP_PRESENT_WITHOUT_VISIBLE_MEMBER", result["termination_reasons"])
        self.assertTrue(result["process_group_remaining_after_child_exit"])
        self.assertTrue(result["signal_attempts"])
        self.assertFalse(any(row["state"] != "Z" for row in original(result["pid"])["members"]))


class BindingAndLocalCostTests(unittest.TestCase):
    def test_old_journal_cannot_be_relabelled_v2(self):
        manifest = coordinator.read_json(FROZEN / "manifest.json")
        with self.assertRaisesRegex(ValueError, "domain"):
            coordinator.saved_identity(FROZEN, None, 2, manifest)
        identity = coordinator.saved_identity(FROZEN, None, 1, manifest)
        self.assertEqual(identity["receipt_bytes"], 256886)
        self.assertEqual(identity["image_id"], manifest["image_id"])
        for image in (None, [], [0] * 7, [0] * 9, [True] * 8, [0.0] * 8,
                      [-1] * 8, [2**32] * 8):
            with self.subTest(image=image), self.assertRaisesRegex(ValueError, "image_id"):
                coordinator.saved_identity(FROZEN, None, 1, {**manifest, "image_id": image})

    def test_v2_report_requires_same_work_bytes_profile_and_real_sample_types(self):
        identity = {name: f"{index:064x}" for index, name in enumerate(
            ("work_id", "header_sha256", "journal_sha256", "input_sha256", "receipt_sha256",
             "external_artifacts_sha256"), 1)}
        identity["image_id"] = list(range(1, 9))
        # Parser control only: these rows are never saved as actual proof evidence.
        row = {**identity, "schema": "TRNM-W1-V2-FULL-VERIFY1", "iterations": 1,
               "profile_id": coordinator.V2_PROFILE_ID, "decode_and_verify_ns": [100],
               "expected_artifacts_sha256": identity["external_artifacts_sha256"],
               "parent_eligibility_checked": False, "admission_authorized": False}
        coordinator.validate_v2_report(row, identity, "transparent", 1)
        mutations = {"work_id": "0" * 64, "receipt_sha256": "0" * 64,
                     "header_sha256": "0" * 64, "journal_sha256": "0" * 64,
                     "schema": "TRNM-W1-HARDENED-FULL-VERIFY2", "iterations": True,
                     "profile_id": coordinator.V2_PROFILE_ID[:-1] + "1",
                     "admission_authorized": True, "decode_and_verify_ns": [True],
                     "expected_artifacts_sha256": "0" * 64, "parent_eligibility_checked": True}
        for field, value in mutations.items():
            damaged = copy.deepcopy(row)
            damaged[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                coordinator.validate_v2_report(damaged, identity, "transparent", 1)

    def test_fresh_and_many_same_profile_cannot_substitute_image_but_native_needs_none(self):
        # Report-parser controls only, never an actual verifier observation.
        identity = {name: "a" * 64 for name in ("work_id", "header_sha256", "journal_sha256",
                    "input_sha256", "receipt_sha256", "external_artifacts_sha256")}
        identity["image_id"] = list(range(1, 9))
        base = {**identity, "profile_id": coordinator.V2_PROFILE_ID,
                "expected_artifacts_sha256": identity["external_artifacts_sha256"],
                "parent_eligibility_checked": False, "admission_authorized": False}
        for count in (1, 100):
            row = {**base, "schema": "TRNM-W1-V2-FULL-VERIFY1", "iterations": count,
                   "decode_and_verify_ns": [100] * count}
            coordinator.validate_v2_report(row, identity, "transparent", count)
            for image in ([9, 2, 3, 4, 5, 6, 7, 8], [True, 2, 3, 4, 5, 6, 7, 8],
                          [1.0, 2, 3, 4, 5, 6, 7, 8], None):
                with self.subTest(count=count, image=image), self.assertRaisesRegex(ValueError, "image_id"):
                    coordinator.validate_v2_report({**row, "image_id": image}, identity, "transparent", count)
            del row["image_id"]
            with self.assertRaisesRegex(ValueError, "image_id"):
                coordinator.validate_v2_report(row, identity, "transparent", count)
        native = {**base, "schema": "TRNM-W1-V2-NATIVE1", "iterations": 1000,
                  "native_replay_ns": [100] * 1000}
        del native["image_id"]
        coordinator.validate_v2_report(native, identity, "native", 1000)

    def test_duplicate_nonfinite_and_overflow_json_are_not_observations(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "record.json"
            for data in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":1e309}'):
                path.write_text(data)
                with self.subTest(data=data), self.assertRaises(ValueError):
                    coordinator.read_json(path)

    def test_actual_serialization_and_loopback_keep_remote_metrics_unmeasured(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            encoded = local.serialize(FROZEN / "input.bin", FROZEN / "succinct.bin", None, 1, temp / "payloads")
            row = encoded["payloads"]["transparent"]
            transferred = local.transfer(temp / "payloads" / row["payload_file"], row["payload_sha256"],
                                         1_000_000, temp / "transfer")
            self.assertTrue(transferred["byte_roundtrip_complete"])
            self.assertEqual(transferred["receiver"]["received_bytes"], row["payload_bytes"])
            self.assertGreaterEqual(transferred["send_receive_and_durable_write_seconds"], row["payload_bytes"] / 1_000_000)
            self.assertEqual(transferred["receiver_address"], "127.0.0.1")
            self.assertEqual((temp / "transfer/received.bin").read_bytes(),
                             (temp / "payloads" / row["payload_file"]).read_bytes())
            for field in ("real_network_propagation_seconds", "node_admission_seconds", "confirmation_seconds", "stale_block_rate"):
                self.assertIsNone(transferred[field])
            self.assertEqual(encoded["proof_randomness_tickets"], 0)
            with self.assertRaisesRegex(ValueError, "digest"):
                local.transfer(temp / "payloads" / row["payload_file"], "0" * 64, 1_000_000, temp / "wrong")

    def test_v2_envelope_requires_external_64_byte_commitments(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            for length in (0, 63, 65):
                path = temp / f"artifacts-{length}.bin"
                path.write_bytes(bytes(length))
                with self.subTest(length=length), self.assertRaises(ValueError):
                    local.serialize(FROZEN / "input.bin", FROZEN / "succinct.bin", path, 2, temp / f"out-{length}")


class CoordinatorFailureTests(unittest.TestCase):
    def invocation(self, temp, code, seconds):
        # The control deliberately produces no manifest or receipt. It must fail;
        # no test supplies a successful synthetic cryptographic backend.
        executable = temp / "control-only"
        executable.write_text("#!/usr/bin/env python3\n" + code + "\n")
        executable.chmod(0o755)
        return ["--runner", str(executable), "--r0vm", str(executable),
                "--fresh-verifier", str(executable), "--native-verifier", str(executable),
                "--prepare-input", str(FROZEN / "input.bin"), "--checkpoint", str(temp / "checkpoint"),
                "--out", str(temp / "result"), "--total-wall-seconds", str(seconds)]

    def test_exit_zero_without_actual_checkpoint_cannot_claim_a_full_proof(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            temp = Path(temp)
            self.assertEqual(coordinator.main(self.invocation(temp, "print('control only')", 5)), 1)
            result = json.loads((temp / "result/result.json").read_text())
            self.assertFalse(result["complete_proof_claim"])
            self.assertFalse(result["end_to_end_observation_complete"])
            self.assertEqual(len(result["stages"]), 1)
            self.assertIn("FileNotFoundError", result["error"])

    def test_preparation_consumes_same_cumulative_budget(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            temp = Path(temp)
            self.assertEqual(coordinator.main(self.invocation(temp, "import time;time.sleep(60)", .2)), 1)
            result = json.loads((temp / "result/result.json").read_text())
            self.assertFalse(result["complete_proof_claim"])
            self.assertEqual(result["stages"][0]["stage"], "prepare-full-execution")
            self.assertTrue(result["stages"][0]["result"]["timed_out"])
            self.assertLess(result["new_controller_wall_seconds"], 2)
            self.assertEqual(result["proof_randomness_tickets"], 0)
            self.assertIsNone(result["post_find_publish_seconds"])

    def test_same_prior_observation_is_not_counted_twice(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            temp = Path(temp)
            args = self.invocation(temp, "print('control only')", 5)
            index = args.index("--prepare-input")
            del args[index:index + 2]
            prior = temp / "prior.json"
            prior.write_text(json.dumps({"wall_seconds": 1, "started_unix_ns": 10, "command": ["control only"]}))
            duplicate = temp / "copy.json"
            duplicate.write_bytes(prior.read_bytes())
            args += ["--prior-result", str(prior), "--prior-result", str(duplicate)]
            self.assertEqual(coordinator.main(args), 1)
            result = json.loads((temp / "result/result.json").read_text())
            self.assertEqual(result["phase"], "INITIALIZATION_FAILED")
            self.assertIn("twice", result["error"])
            self.assertEqual(result["stages"], [])


if __name__ == "__main__":
    unittest.main()
