"""Real lightweight subprocess cost controls; no model, ledger, or frozen trial."""
import copy
import concurrent.futures
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import dev_circuit_evaluation as evaluation
import dev_loop_identity as loop


class EvaluationAttemptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.job = Path(self.temp.name)
        evaluation.record(self.job / "ADMISSION.json", {"engineering_control": True})

    def run_child(self, code):
        return evaluation.measure(self.job, [sys.executable, "-B", "-c", code], dict(os.environ))

    def successful_cost(self):
        cpu, wall = self.run_child("import sys; print('output'); print('diagnostic', file=sys.stderr)")
        return dict(schema="trnm-isolated-plain-paired-evaluation-cost-v3", cpu_ns=cpu, wall_ns=wall,
                    **evaluation.attempt_cost_fields(self.job))

    def test_success_records_actual_logs_and_scoped_counters(self):
        cost = self.successful_cost()
        checked = evaluation.verify_attempt_cost(self.job, cost)
        self.assertTrue(checked["attempt_receipt_bound"])
        self.assertFalse(checked["cost_completeness_verified"])
        self.assertFalse(checked["execution_authenticated"])
        self.assertTrue(checked["concurrent_child_cpu_isolation_declared"])
        self.assertGreater(cost["wall_ns"], 0)
        self.assertGreaterEqual(cost["cpu_ns"], 0)

    def test_failed_child_retains_its_cost_and_original_exit(self):
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            self.run_child("import sys; print('retained failure'); sys.exit(7)")
        self.assertEqual(failure.exception.returncode, 7)
        attempt = evaluation.read(self.job / evaluation.ATTEMPT_FILE)
        self.assertEqual((attempt["child_status"], attempt["returncode"]), ("failed", 7))
        self.assertGreater(attempt["wall_ns"], 0)
        self.assertEqual((self.job / "evaluation.stdout").read_bytes(), b"retained failure\n")
        self.assertFalse((self.job / "COST.json").exists())
        self.assertFalse((self.job / "DELIVERY.json").exists())

    def test_failed_launch_is_unknown_execution_not_success_or_zero_cost(self):
        with self.assertRaises(FileNotFoundError):
            evaluation.measure(self.job, [str(self.job / "missing-executable")], {})
        attempt = evaluation.read(self.job / evaluation.ATTEMPT_FILE)
        self.assertEqual(attempt["child_status"], "unknown")
        self.assertIsNone(attempt["returncode"])
        self.assertIsNone(attempt["cpu_ns"])
        self.assertEqual(attempt["error_type"], "FileNotFoundError")
        self.assertFalse(attempt["cost_completeness_verified"])

    def test_second_attempt_cannot_overwrite_or_reexecute(self):
        self.successful_cost()
        raw = (self.job / evaluation.ATTEMPT_FILE).read_bytes()
        with patch.object(evaluation.subprocess, "Popen") as run:
            with self.assertRaisesRegex(ValueError, "already recorded"):
                self.run_child("raise SystemExit(9)")
            run.assert_not_called()
        self.assertEqual((self.job / evaluation.ATTEMPT_FILE).read_bytes(), raw)

    def test_recording_error_does_not_hide_original_child_failure(self):
        original = evaluation.record
        def fail_receipt(path, value):
            if path.name == evaluation.ATTEMPT_FILE:
                raise OSError("test-only disk failure")
            return original(path, value)
        with patch.object(evaluation, "record", side_effect=fail_receipt):
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                self.run_child("raise SystemExit(11)")
        self.assertEqual(failure.exception.returncode, 11)
        self.assertIn("could not be persisted", failure.exception.__notes__[0])

    def test_success_cannot_continue_without_recorded_cost(self):
        original = evaluation.record
        def fail_receipt(path, value):
            if path.name == evaluation.ATTEMPT_FILE:
                raise OSError("test-only disk failure")
            return original(path, value)
        with patch.object(evaluation, "record", side_effect=fail_receipt):
            with self.assertRaises(OSError):
                self.run_child("pass")

    def test_existing_logs_do_not_create_an_intent_or_terminal_receipt(self):
        existing = self.job / "evaluation.stdout"
        existing.write_bytes(b"original owner's output")
        with patch.object(evaluation.subprocess, "Popen") as run:
            with self.assertRaisesRegex(ValueError, "logs already exist"):
                self.run_child("pass")
            run.assert_not_called()
        self.assertEqual(existing.read_bytes(), b"original owner's output")
        self.assertFalse((self.job / evaluation.INTENT_FILE).exists())
        self.assertFalse((self.job / evaluation.ATTEMPT_FILE).exists())

    def test_concurrent_loser_cannot_publish_the_active_owners_terminal_receipt(self):
        entered, release = threading.Event(), threading.Event()
        original_record = evaluation.record
        def held_intent(path, value):
            result = original_record(path, value)
            if path.name == evaluation.INTENT_FILE:
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("test owner was not released")
            return result
        with patch.object(evaluation, "record", side_effect=held_intent), \
             patch.object(evaluation.subprocess, "Popen", wraps=evaluation.subprocess.Popen) as run:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                owner = pool.submit(self.run_child, "print('original owner')")
                try:
                    self.assertTrue(entered.wait(5))
                    intent = (self.job / evaluation.INTENT_FILE).read_bytes()
                    self.assertFalse((self.job / "evaluation.stdout").exists())
                    with self.assertRaises((ValueError, FileExistsError)):
                        self.run_child("print('loser')")
                    self.assertFalse((self.job / evaluation.ATTEMPT_FILE).exists())
                    self.assertEqual((self.job / evaluation.INTENT_FILE).read_bytes(), intent)
                finally:
                    release.set()
                owner.result(timeout=5)
            self.assertEqual(run.call_count, 1)
        self.assertEqual((self.job / "evaluation.stdout").read_bytes(), b"original owner\n")
        self.assertEqual(evaluation.read(self.job / evaluation.ATTEMPT_FILE)["child_status"], "succeeded")

    def test_output_collision_after_intent_does_not_write_terminal_receipt(self):
        original_open = Path.open
        stderr = self.job / "evaluation.stderr"
        def late_collision(path, mode="r", *args, **kwargs):
            if path == stderr and mode == "x+b":
                with original_open(path, "wb") as other:
                    other.write(b"other owner's existing stderr")
            return original_open(path, mode, *args, **kwargs)
        with patch.object(Path, "open", new=late_collision), patch.object(evaluation.subprocess, "Popen") as run:
            with self.assertRaises(FileExistsError):
                self.run_child("pass")
            run.assert_not_called()
        self.assertEqual(stderr.read_bytes(), b"other owner's existing stderr")
        self.assertTrue((self.job / evaluation.INTENT_FILE).exists())
        self.assertFalse((self.job / evaluation.ATTEMPT_FILE).exists())

    def test_existing_intent_blocks_launch_without_fabricating_a_terminal_state(self):
        intent = self.job / evaluation.INTENT_FILE
        intent.write_bytes(b"interrupted original launch intent")
        with patch.object(evaluation.subprocess, "Popen") as run:
            with self.assertRaises(FileExistsError):
                self.run_child("pass")
            run.assert_not_called()
        self.assertEqual(intent.read_bytes(), b"interrupted original launch intent")
        self.assertFalse((self.job / evaluation.ATTEMPT_FILE).exists())

    def test_changed_logs_request_or_counters_are_refused(self):
        cost = self.successful_cost()
        original = (self.job / "evaluation.stdout").read_bytes()
        (self.job / "evaluation.stdout").write_bytes(b"replaced")
        with self.assertRaisesRegex(ValueError, "logs differ"):
            evaluation.verify_attempt_cost(self.job, cost)
        (self.job / "evaluation.stdout").write_bytes(original)
        with self.assertRaisesRegex(ValueError, "counters differ"):
            evaluation.verify_attempt_cost(self.job, dict(cost, cpu_ns=cost["cpu_ns"] + 1))
        (self.job / "ADMISSION.json").write_bytes(b'{"different":true}\n')
        with self.assertRaisesRegex(ValueError, "scope or request"):
            evaluation.verify_attempt_cost(self.job, cost)

    def test_scope_upgrades_boolean_exit_and_failed_receipts_are_refused(self):
        cost = self.successful_cost()
        with self.assertRaisesRegex(ValueError, "cost scope"):
            evaluation.verify_attempt_cost(self.job, dict(cost, cost_completeness_verified=True))
        path = self.job / evaluation.ATTEMPT_FILE
        original = evaluation.read(path)
        for key, value in (("execution_authority", True), ("returncode", False),
                           ("child_status", "failed"), ("error_type", "CalledProcessError")):
            altered = copy.deepcopy(original)
            altered[key] = value
            path.write_bytes(evaluation.canonical(altered))
            changed = dict(cost, evaluation_attempt_sha256=evaluation.sha(path.read_bytes()))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "scope or request"):
                evaluation.verify_attempt_cost(self.job, changed)

    def test_historical_cost_remains_incomplete_without_a_new_attempt(self):
        result = evaluation.verify_attempt_cost(self.job, {"schema": "trnm-isolated-circuit-evaluation-cost-v1"})
        self.assertFalse(result["attempt_receipt_bound"])
        self.assertFalse(result["cost_completeness_verified"])
        with self.assertRaisesRegex(ValueError, "requires cost v2"):
            evaluation.verify_attempt_cost(self.job, {"schema": "trnm-isolated-circuit-evaluation-cost-v1",
                                                     "evaluation_attempt_sha256": "a" * 64})

    def test_unknown_cost_namespace_or_historical_completeness_cannot_bypass_attempt_gate(self):
        for schema in ("not-a-cost-schema", "trnm-isolated-plain-paired-evaluation-cost-v9", None):
            with self.subTest(schema=schema), self.assertRaisesRegex(ValueError, "unknown evaluation cost schema"):
                evaluation.verify_attempt_cost(self.job, {"schema": schema, "cost_completeness_verified": True})
        with self.assertRaisesRegex(ValueError, "historical cost completeness"):
            evaluation.verify_attempt_cost(self.job, {"schema": "trnm-isolated-circuit-evaluation-cost-v1",
                                                     "cost_completeness_verified": True})

    def test_cost_family_must_match_original_admission_even_with_matching_receipt_pin(self):
        cost = self.successful_cost()
        for admission in ("trnm-isolated-circuit-evaluation-request-v1",
                          "trnm-isolated-historical-evaluation-request-v1"):
            with self.subTest(admission=admission), self.assertRaisesRegex(ValueError, "cost family"):
                evaluation.verify_attempt_cost(self.job, cost, admission={"schema": admission})
        with self.assertRaisesRegex(ValueError, "unknown cost admission schema"):
            evaluation.verify_attempt_cost(self.job, cost, admission={"schema": "unknown"})

    def test_v3_cannot_downgrade_to_v1_even_after_rehashing_untrusted_cost_bytes(self):
        cost = self.successful_cost()
        cost["schema"] = "trnm-isolated-plain-paired-evaluation-cost-v1"
        del cost["evaluation_attempt_sha256"]
        encoded = evaluation.canonical(cost)
        declared_hash = evaluation.sha(encoded)
        self.assertEqual(declared_hash, evaluation.digest(cost))
        with self.assertRaisesRegex(ValueError, "artifact-bound admission requires cost v2"):
            evaluation.verify_attempt_cost(self.job, cost, admission={"schema": loop.ARTIFACT_ADMISSION})
        # Original version-only bound requests retain their historical namespace.
        self.assertFalse(evaluation.verify_attempt_cost(self.job, cost,
                         admission={"schema": loop.ADMISSION})["attempt_receipt_bound"])

    def test_distinct_concurrent_jobs_do_not_share_cpu_cost(self):
        busy = self.job / "other-job"
        busy.mkdir()
        evaluation.record(busy / "ADMISSION.json", {"engineering_control": True})
        waiting_code = ("import pathlib,time; pathlib.Path('ready').touch(); deadline=time.monotonic()+10\n"
                        "while not pathlib.Path('release').exists():\n"
                        " if time.monotonic()>deadline: raise TimeoutError('test release missing')\n"
                        " time.sleep(.01)\n")
        busy_code = "import time; end=time.process_time()+.3\nwhile time.process_time()<end: pass\n"
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            waiting = pool.submit(self.run_child, waiting_code)
            try:
                deadline = time.monotonic() + 5
                while not (self.job / "ready").exists():
                    self.assertLess(time.monotonic(), deadline, "waiting child did not start")
                    time.sleep(.01)
                busy_cpu, _ = evaluation.measure(busy, [sys.executable, "-B", "-c", busy_code], dict(os.environ))
            finally:
                (self.job / "release").touch()
            idle_cpu, _ = waiting.result(timeout=5)
        self.assertGreater(busy_cpu, 250_000_000)
        self.assertLess(idle_cpu * 2, busy_cpu)

    def test_waited_descendant_cpu_is_included_without_popen_double_reap(self):
        code = ("import subprocess,sys; subprocess.run([sys.executable,'-B','-c',"
                "'import time; end=time.process_time()+.2\\nwhile time.process_time()<end: pass'],check=True)")
        with patch.object(evaluation.subprocess.Popen, "wait", side_effect=AssertionError("second reaper")), \
             patch.object(evaluation.subprocess.Popen, "poll", side_effect=AssertionError("second reaper")):
            cpu, _ = self.run_child(code)
        self.assertGreater(cpu, 180_000_000)

    def test_large_stdout_and_stderr_are_file_backed_without_pipe_deadlock(self):
        self.run_child("import os; os.write(1,b'x'*1048576); os.write(2,b'y'*1048576)")
        self.assertEqual((self.job / "evaluation.stdout").stat().st_size, 1048576)
        self.assertEqual((self.job / "evaluation.stderr").stat().st_size, 1048576)

    def test_real_wall_timeout_stops_owned_process_group_and_retains_failure(self):
        code = ("import os,pathlib,time; child=os.fork()\n"
                "if child==0:\n pathlib.Path('descendant').write_text(str(os.getpid()))\n time.sleep(10)\n"
                "else:\n pathlib.Path('leader').write_text(str(os.getpid()))\n time.sleep(10)\n")
        with self.assertRaises(subprocess.TimeoutExpired) as failure:
            evaluation.measure(self.job, [sys.executable, "-B", "-c", code], dict(os.environ), timeout_seconds=.5)
        self.assertEqual(failure.exception.timeout, .5)
        attempt = evaluation.read(self.job / evaluation.ATTEMPT_FILE)
        self.assertEqual((attempt["child_status"], attempt["returncode"], attempt["error_type"]),
                         ("failed", -9, "TimeoutExpired"))
        self.assertIsInstance(attempt["cpu_ns"], int)
        self.assertEqual(evaluation.read(self.job / evaluation.INTENT_FILE)["wall_timeout_seconds"], .5)
        leader = int((self.job / "leader").read_text())
        with self.assertRaises(ChildProcessError):
            os.waitpid(leader, os.WNOHANG)
        descendant = int((self.job / "descendant").read_text())
        deadline = time.monotonic() + 2
        while True:
            stat = Path(f"/proc/{descendant}/stat")
            if not stat.exists() or stat.read_text().split()[2] == "Z":
                break
            self.assertLess(time.monotonic(), deadline, "owned descendant still running")
            time.sleep(.01)
        self.assertFalse((self.job / "COST.json").exists())

    def test_interrupted_wait_cleans_up_and_preserves_original_exception(self):
        original = evaluation._wait_owned
        calls = []
        def interrupted(child, deadline=None):
            calls.append(child.pid)
            if len(calls) == 1:
                raise KeyboardInterrupt("test cancellation")
            return original(child, deadline)
        with patch.object(evaluation, "_wait_owned", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.run_child("import time; time.sleep(10)")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1])
        attempt = evaluation.read(self.job / evaluation.ATTEMPT_FILE)
        self.assertEqual((attempt["returncode"], attempt["error_type"]), (-9, "KeyboardInterrupt"))
        self.assertIsInstance(attempt["cpu_ns"], int)
        with self.assertRaises(ChildProcessError):
            os.waitpid(calls[0], os.WNOHANG)

    def test_unsupported_meter_and_invalid_timeout_do_not_launch(self):
        with patch.object(evaluation.os, "wait4", None), patch.object(evaluation.subprocess, "Popen") as child:
            with self.assertRaisesRegex(ValueError, "requires wait4"):
                self.run_child("pass")
            child.assert_not_called()
        for timeout in (True, False, 0, -1, float("inf"), float("nan"), 86401, "1"):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(ValueError, "invalid evaluation wall timeout"):
                evaluation.measure(self.job, [sys.executable], dict(os.environ), timeout_seconds=timeout)
        self.assertFalse((self.job / evaluation.INTENT_FILE).exists())

    def test_original_v2_cost_reads_with_original_nonisolated_scope(self):
        # Schema compatibility fixture only, not a new measurement of old CPU semantics.
        cost = self.successful_cost()
        intent_path = self.job / evaluation.INTENT_FILE
        intent = evaluation.read(intent_path)
        intent["schema"] = evaluation.INTENT_SCHEMA_V1
        del intent["wall_timeout_seconds"]
        intent_path.write_bytes(evaluation.canonical(intent))
        attempt_path = self.job / evaluation.ATTEMPT_FILE
        attempt = evaluation.read(attempt_path)
        attempt.update(schema=evaluation.ATTEMPT_SCHEMA_V1, cpu_scope=evaluation.CPU_SCOPE_V1,
                       intent_sha256=evaluation.sha(intent_path.read_bytes()))
        attempt_path.write_bytes(evaluation.canonical(attempt))
        cost.update(schema="trnm-isolated-plain-paired-evaluation-cost-v2", cpu_scope=evaluation.CPU_SCOPE_V1,
                    evaluation_attempt_sha256=evaluation.sha(attempt_path.read_bytes()))
        checked = evaluation.verify_attempt_cost(self.job, cost, admission={"schema": loop.ARTIFACT_ADMISSION})
        self.assertFalse(checked["concurrent_child_cpu_isolation_declared"])
        self.assertEqual(checked["scope"], "historical_process_children_delta")
        cost.update(schema="trnm-isolated-plain-paired-evaluation-cost-v3", cpu_scope=evaluation.CPU_SCOPE)
        with self.assertRaisesRegex(ValueError, "scope or request"):
            evaluation.verify_attempt_cost(self.job, cost)

    def test_new_attempt_cannot_be_relabelled_as_cost_v2(self):
        cost = self.successful_cost()
        cost.update(schema="trnm-isolated-plain-paired-evaluation-cost-v2", cpu_scope=evaluation.CPU_SCOPE_V1)
        with self.assertRaisesRegex(ValueError, "scope or request"):
            evaluation.verify_attempt_cost(self.job, cost)

    def test_lost_wait_ownership_stays_unknown_and_never_signals_reusable_pid(self):
        def foreign_reaper(child, deadline=None):
            os.waitpid(child.pid, 0)
            raise ChildProcessError("another owner reaped the child")
        with patch.object(evaluation, "_wait_owned", side_effect=foreign_reaper), \
             patch.object(evaluation.os, "killpg") as kill:
            with self.assertRaises(ChildProcessError):
                self.run_child("pass")
            kill.assert_not_called()
        attempt = evaluation.read(self.job / evaluation.ATTEMPT_FILE)
        self.assertEqual(attempt["child_status"], "unknown")
        self.assertIsNone(attempt["returncode"])
        self.assertIsNone(attempt["cpu_ns"])
        self.assertEqual(attempt["error_type"], "ChildProcessError")


if __name__ == "__main__":
    unittest.main()
