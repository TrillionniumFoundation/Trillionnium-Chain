#!/usr/bin/env python3
"""Real process/resource controls; these never simulate a positive W1 proof."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import proof_resources

HERE = Path(__file__).resolve().parent
MOUNT = "1 0 0:1 / /sys/fs/cgroup ro - cgroup2 cgroup2 rw\n"


class Resources(unittest.TestCase):
    def test_actual_membership_includes_all_visible_ancestors_and_namespace_root(self):
        self.assertEqual(proof_resources.controller_paths("0::/system.slice/job\n", MOUNT),
            [Path("/sys/fs/cgroup/system.slice/job"), Path("/sys/fs/cgroup/system.slice"),
             Path("/sys/fs/cgroup")])
        self.assertEqual(proof_resources.controller_paths("0::/\n", MOUNT),
                         [Path("/sys/fs/cgroup")])
        for membership, mount in [("1:memory:/job\n", MOUNT), ("0::/../escape\n", MOUNT),
                                   ("0::/job\n", ""), ("0::/job\n", MOUNT + MOUNT)]:
            with self.assertRaises(ValueError):
                proof_resources.controller_paths(membership, mount)

    def observation(self, cpu, maximum, current, *, member="/job"):
        values = {"/proc/self/cgroup": f"0::{member}\n", "/proc/self/mountinfo": MOUNT,
            "/proc/meminfo": "MemTotal: 16777216 kB\nMemAvailable: 12582912 kB\n"}
        values.update({"/sys/fs/cgroup" + member + "/" + key: value for key, value in
            [("cpu.max", cpu), ("memory.max", maximum), ("memory.current", current)]})
        def read(path, *args, **kwargs):
            value = values.get(str(path))
            if value is None:
                raise FileNotFoundError(2, "control unavailable")
            return value
        with patch.object(Path, "read_text", read), \
                patch.object(os, "sched_getaffinity", return_value={0, 1, 2, 3}):
            return proof_resources.observe()

    def test_missing_limits_never_mean_unlimited_or_a_smaller_profile(self):
        for cpu, maximum, current in [(None, None, None),
                ("200000 100000", "max", "0"),
                ("max 100000", str(9 * proof_resources.GIB), str(2 * proof_resources.GIB)),
                ("max 100000", str(16 * proof_resources.GIB), None)]:
            result = self.observation(cpu, maximum, current)
            self.assertFalse(result["prerequisites_met"])
            self.assertFalse(result["silent_profile_fallback"])
        self.assertTrue(self.observation("400000 100000", str(16 * proof_resources.GIB),
                                        str(2 * proof_resources.GIB))["prerequisites_met"])
        hidden_ancestor = self.observation("400000 100000", str(16 * proof_resources.GIB),
                                          "0", member="/slice/job")
        self.assertFalse(hidden_ancestor["prerequisites_met"])
        self.assertTrue(any("unavailable controller limit: /sys/fs/cgroup/slice/" in error
                            for error in hidden_ancestor["errors"]))


class ActualProcesses(unittest.TestCase):
    def controller(self, source, timeout):
        with tempfile.TemporaryDirectory(prefix="pon-segment-control-") as temporary:
            root = Path(temporary)
            steps = root / "steps"
            steps.mkdir()
            script = root / "controller.py"
            script.write_text("import sys\nsys.path.insert(0, " + repr(str(HERE)) + ")\n"
                "import signal,time,json\nfrom pathlib import Path\n"
                "import prove_segments as s\n"
                "signal.signal(signal.SIGTERM,s.stopping)\n"
                "steps=Path(" + repr(str(steps)) + ")\n" + source)
            wrapper = subprocess.run([sys.executable, str(HERE / "measure_step.py"),
                "--out", str(root), "--name", "control", "--timeout", str(timeout),
                "--", sys.executable, str(script)], capture_output=True, timeout=timeout + 15)
            phase = json.loads((root / "control.process.json").read_text())
            files = {path.name: path.read_bytes() for path in steps.iterdir() if path.is_file()}
            self.assertEqual(wrapper.returncode, 0, wrapper.stderr)
            self.assertTrue(phase["child_reaped"])
            self.assertTrue(phase["owned_process_group_empty"])
            self.assertEqual(phase["cleanup_errors"], [])
            return phase, files

    def test_actual_failed_worker_cancels_other_worker_and_retains_terminal_logs(self):
        phase, files = self.controller(
            "a=s.Stage(steps,'failed',[sys.executable,'-c',\"print('worker-a'); raise SystemExit(7)\"],2)\n"
            "b=s.Stage(steps,'cancelled',[sys.executable,'-c',"
            "\"import signal,time,sys; signal.signal(signal.SIGTERM,lambda *_: (print('worker-b-tail',file=sys.stderr,flush=True),sys.exit(23))); print('ready',flush=True); time.sleep(20)\"],2)\n"
            "deadline=time.monotonic()+3\n"
            "while b\'ready\' not in (steps/(\'cancelled.stdout.log\')).read_bytes() and time.monotonic()<deadline: time.sleep(0.01)\n"
            "assert b\'ready\' in (steps/\'cancelled.stdout.log\').read_bytes()\n"
            "try:\n a.check(); raise AssertionError('actual nonzero not rejected')\n"
            "except RuntimeError: pass\n"
            "assert not s.cleanup([a,b])\n"
            "assert a.finished==7 and b.finished==23\n", 10)
        self.assertEqual(json.loads(files["failed.terminal.json"])["returncode"], 7)
        self.assertEqual(json.loads(files["cancelled.terminal.json"])["returncode"], 23)
        self.assertIn(b"worker-a", files["failed.stdout.log"])
        self.assertIn(b"worker-b-tail", files["cancelled.stderr.log"])
        self.assertFalse(json.loads(files["failed.terminal.json"])["complete_w1_proof_verified"])
        self.assertFalse(phase["timed_out"])

    def test_actual_per_worker_deadline_retains_sigkill_without_claiming_a_proof(self):
        _, files = self.controller(
            "a=s.Stage(steps,'deadline',[sys.executable,'-c',"
            "\"import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('ready',flush=True); time.sleep(20)\"],0.05)\n"
            "deadline=time.monotonic()+3\n"
            "while b\'ready\' not in (steps/\'deadline.stdout.log\').read_bytes() and time.monotonic()<deadline: time.sleep(0.01)\n"
            "assert b\'ready\' in (steps/\'deadline.stdout.log\').read_bytes()\n"
            "while time.monotonic()-a.started<=a.timeout: time.sleep(0.01)\n"
            "try:\n a.check(); raise AssertionError('deadline not enforced')\n"
            "except TimeoutError: pass\n"
            "assert not s.cleanup([a])\nassert a.finished==-9\n", 12)
        terminal = json.loads(files["deadline.terminal.json"])
        self.assertEqual(terminal["returncode"], -9)
        self.assertTrue(terminal["child_reaped"])
        self.assertFalse(terminal["complete_w1_proof_verified"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
