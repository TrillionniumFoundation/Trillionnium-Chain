#!/usr/bin/env python3
"""Real subprocess controls for observation retention; no proof is simulated."""
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class ProcessObservations(unittest.TestCase):
    def run_child(self, code=None, *, timeout=10, command=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = command or [sys.executable, "-u", "-c", code]
            process = subprocess.run([sys.executable, str(HERE / "measure_step.py"),
                "--out", str(root), "--name", "control", "--timeout", str(timeout),
                "--", *command], capture_output=True, timeout=timeout + 15)
            report = json.loads((root / "control.process.json").read_text())
            logs = {name: (root / f"control.{name}.log").read_bytes()
                    for name in ["stdout", "stderr"]}
            for name, raw in logs.items():
                self.assertEqual(report["raw_logs"][name]["bytes"], len(raw))
                self.assertEqual(report["raw_logs"][name]["sha256"],
                                 hashlib.sha256(raw).hexdigest())
            self.assertEqual(report["schema"], "pon-w1-actual-process-v2")
            self.assertFalse(report["consensus_authority"])
            if report["child_pid"] is not None:
                self.assertTrue(report["subreaper_enabled"])
                self.assertTrue(report["owned_process_group_empty"])
            return process, report, logs

    def test_success_and_real_nonzero_exit_keep_both_streams(self):
        for status in [0, 7]:
            process, report, logs = self.run_child(
                f"import sys; print('raw-out'); print('raw-err', file=sys.stderr); sys.exit({status})")
            self.assertEqual(process.returncode, status)
            self.assertEqual(report["child_returncode"], status)
            self.assertEqual(report["returncode"], status)
            self.assertTrue(report["child_reaped"])
            self.assertFalse(report["timed_out"])
            self.assertEqual(report["cleanup_actions"], [])
            self.assertEqual(logs, {"stdout": b"raw-out\n", "stderr": b"raw-err\n"})

    def test_timeout_retains_sigterm_tail_and_actual_child_terminal(self):
        process, report, logs = self.run_child(
            "import signal,time,sys\n"
            "def stop(*_):\n print('terminal-tail'); sys.exit(23)\n"
            "signal.signal(signal.SIGTERM,stop)\nprint('started')\ntime.sleep(90)", timeout=1)
        self.assertEqual(process.returncode, 124)
        self.assertTrue(report["timed_out"])
        self.assertEqual(report["child_returncode"], 23)
        self.assertTrue(report["child_reaped"])
        self.assertEqual(report["cleanup_actions"], ["SIGTERM"])
        self.assertEqual(logs["stdout"], b"started\nterminal-tail\n")

    def test_sigkill_preserves_partial_raw_bytes_and_genuine_negative_status(self):
        process, report, logs = self.run_child(
            "import signal,time,os\n"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "os.write(1,b'partial\\xff'); time.sleep(90)", timeout=1)
        self.assertEqual(process.returncode, 124)
        self.assertTrue(report["timed_out"])
        self.assertEqual(report["child_returncode"], -signal.SIGKILL)
        self.assertTrue(report["child_reaped"])
        self.assertEqual(report["cleanup_actions"], ["SIGTERM", "SIGKILL"])
        self.assertEqual(logs["stdout"], b"partial\xff")

    def test_spawn_failure_is_not_a_reaped_or_successful_child(self):
        process, report, _ = self.run_child(command=["/not/an/available/w1-prover"])
        self.assertEqual(process.returncode, 125)
        self.assertIsNone(report["child_pid"])
        self.assertIsNone(report["child_returncode"])
        self.assertFalse(report["child_reaped"])
        self.assertIn("runner_error", report)

    def test_exited_or_killed_leader_cannot_leave_its_prover_running(self):
        for killed in [False, True]:
            process, report, logs = self.run_child(
                "import os,signal,time,sys\n"
                "read,write=os.pipe()\n"
                "pid=os.fork()\n"
                "if pid==0:\n"
                " os.close(read)\n"
                " def stop(*_):\n  print('adopted-terminal-tail'); sys.exit(31)\n"
                " signal.signal(signal.SIGTERM,stop)\n"
                " os.write(write,b'1'); os.close(write); time.sleep(90)\n"
                "else:\n"
                " os.close(write); os.read(read,1); os.close(read)\n"
                " print('leader-terminal')\n"
                + (" os.kill(os.getpid(),signal.SIGKILL)\n" if killed else " os._exit(0)\n"))
            self.assertNotEqual(process.returncode, 0)
            self.assertFalse(report["timed_out"])
            self.assertEqual(report["child_returncode"], -signal.SIGKILL if killed else 0)
            self.assertEqual(report["returncode"], -signal.SIGKILL if killed else 125)
            self.assertTrue(report["child_reaped"])
            self.assertTrue(report["leader_exited_before_group"])
            self.assertEqual(report["cleanup_actions"], ["SIGTERM"])
            self.assertEqual(len(report["adopted_child_terminals"]), 1)
            self.assertEqual(report["adopted_child_terminals"][0]["returncode"], 31)
            self.assertEqual(logs["stdout"], b"leader-terminal\nadopted-terminal-tail\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
