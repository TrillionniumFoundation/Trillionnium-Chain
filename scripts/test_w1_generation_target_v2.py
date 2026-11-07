"""Actual short local-process controls; no test produces a W1 proof or payment."""
import copy
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import w1_generation_target_v2 as target


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.children = []
        original = target.subprocess.Popen
        def retained(*args, **kwargs):
            child = original(*args, **kwargs)
            self.children.append(child)
            return child
        self.popen_patch = patch.object(target.subprocess, "Popen", side_effect=retained)
        self.popen_patch.start()

    def tearDown(self):
        try:
            for child in self.children:
                try:
                    child.wait(timeout=2)
                except target.subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
        finally:
            self.popen_patch.stop()

    def request(self, root, *, sleep=0):
        script = root / "actual_short_child.py"
        script.write_text("from pathlib import Path\nimport time\n"
                          f"with Path({str(root / 'invocations')!r}).open('a') as f: f.write('one\\n')\n"
                          f"time.sleep({sleep!r})\n")
        python = str(Path(sys.executable).resolve())
        now = time.monotonic_ns()
        return {"schema": target.NAMESPACE, "target_instance": "actual-short-process-test",
                "operation": "01" * 32, "task_scope": "02" * 32, "statement": "03" * 32,
                "provider_namespace": "04" * 32, "execution_source_commitment": "05" * 32,
                "target_backend_sha256": target.file_sha(target.__file__),
                "clock_domain": target.clock_domain("actual-short-process-test"),
                "winner_monotonic_ns": now - 1, "deadline_monotonic_ns": now + 10_000_000_000,
                "argv": [python, str(script)], "cwd": str(root),
                "file_pins": {python: target.file_sha(python), str(script): target.file_sha(script)},
                "environment": {"PATH": "/usr/bin:/bin", "RAYON_NUM_THREADS": "1", "PYTHONDONTWRITEBYTECODE": "1"},
                "cpus": [min(os.sched_getaffinity(0))], "total_threads": 1,
                "containment": "process-group-research", "cleanup_grace_ns": 1_000_000_000}

    def wait_result(self, db, op):
        until = time.monotonic() + 15
        while time.monotonic() < until:
            row = target.read_operation(db, op)
            if row["result"] is not None:
                return row
            time.sleep(.02)
        self.fail("actual short process did not publish its retained result")

    def test_actual_process_cold_replay_and_cross_journal_fence_no_second_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r = self.request(root)
            request = root / "request.json"
            request.write_bytes(target.canonical(r))
            args = SimpleNamespace(root=str(root / "persistent-target"), target=r["target_instance"], request=str(request))
            target.dispatch(args)
            db, _ = target.open_db(args.root, args.target, False)
            first = self.wait_result(db, r["operation"])
            self.assertTrue(first["result"]["command_success"])
            self.assertIsNotNone(first["result"]["child_identity"])
            self.assertFalse(first["result"]["all_owned_processes_terminal"])
            self.assertEqual(first["state"], "termination-unknown")
            self.assertFalse(first["result"]["can_authorize_payment"])
            db.close()
            replay = target.dispatch(args)
            self.assertEqual(replay["worker"], first["worker"])
            self.assertEqual((root / "invocations").read_text(), "one\n")
            changed = copy.deepcopy(r)
            changed["operation"] = "ff" * 32
            changed["statement"] = "fe" * 32
            request.write_bytes(target.canonical(changed))
            with self.assertRaises(sqlite3.IntegrityError):
                target.dispatch(args)
            self.assertEqual((root / "invocations").read_text(), "one\n")

    def test_actual_running_cancel_is_sticky_and_not_a_resource_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r = self.request(root, sleep=5)
            request = root / "request.json"
            request.write_bytes(target.canonical(r))
            args = SimpleNamespace(root=str(root / "persistent-target"), target=r["target_instance"], request=str(request))
            target.dispatch(args)
            db, _ = target.open_db(args.root, args.target, False)
            until = time.monotonic() + 5
            while not (root / "invocations").exists() and time.monotonic() < until:
                time.sleep(.02)
            self.assertTrue((root / "invocations").exists())
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE operations SET cancel=1 WHERE operation=?", (r["operation"],))
            db.execute("COMMIT")
            finished = self.wait_result(db, r["operation"])
            self.assertTrue(finished["cancel"])
            self.assertTrue(finished["result"]["sticky_cancel"])
            self.assertFalse(finished["result"]["command_success"])
            self.assertEqual(finished["result"]["cause"], "cancelled")
            self.assertFalse(finished["result"]["all_owned_processes_terminal"])
            replay = target.dispatch(args)
            self.assertTrue(replay["sticky_cancel"])
            self.assertEqual((root / "invocations").read_text(), "one\n")

    def test_changed_proof_plan_and_argv_cannot_reuse_real_original_operation(self):
        # The child is a real bounded local fixture, not a W1 prover. What is
        # tested is the durable target's actual complete-request fence, shared
        # by real heavy commands and independent of a claimed plan label.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r = self.request(root)
            first_plan = {"segment_workers": 2, "compression_mode": "balanced", "compression_workers": 2, "rayon_threads": 4}
            second_plan = {"segment_workers": 1, "compression_mode": "sequential", "compression_workers": 1, "rayon_threads": 8}
            r["proof_plan"] = first_plan
            r["argv"].extend(["--synthetic-plan-binding", target.canonical(first_plan).decode()])
            request = root / "request.json"
            request.write_bytes(target.canonical(r))
            args = SimpleNamespace(root=str(root / "persistent-target"), target=r["target_instance"], request=str(request))
            target.dispatch(args)
            db, _ = target.open_db(args.root, args.target, False)
            retained = self.wait_result(db, r["operation"])
            db.close()
            changed = copy.deepcopy(r)
            changed["proof_plan"] = second_plan
            changed["argv"][-1] = target.canonical(second_plan).decode()
            request.write_bytes(target.canonical(changed))
            with self.assertRaisesRegex(ValueError, "operation replay mismatch"):
                target.dispatch(args)
            db, _ = target.open_db(args.root, args.target, False)
            after = target.read_operation(db, r["operation"])
            self.assertEqual(after["request_sha256"], retained["request_sha256"])
            self.assertEqual(after["worker"], retained["worker"])
            self.assertEqual((root / "invocations").read_text(), "one\n")
            self.assertEqual(len(self.children), 1)
            db.close()

    def test_expired_deadline_and_changed_clock_refuse_before_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            r = self.request(root)
            r["deadline_monotonic_ns"] = r["winner_monotonic_ns"] + 1
            with self.assertRaisesRegex(ValueError, "deadline expired"):
                target.request_check(r, r["target_instance"])
            r["deadline_monotonic_ns"] = time.monotonic_ns() + 5_000_000_000
            r["clock_domain"] = "ff" * 32
            with self.assertRaisesRegex(ValueError, "continuity UNKNOWN"):
                target.request_check(r, r["target_instance"])
            self.assertFalse((root / "invocations").exists())


if __name__ == "__main__":
    unittest.main()
