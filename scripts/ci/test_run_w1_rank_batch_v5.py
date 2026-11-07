#!/usr/bin/env python3
"""Actual subprocess failures/timeouts for the V5 accounting owner."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import run_w1_rank_batch_v5 as runner
capture = runner.capture


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "wait4"), "Linux wait4 owner")
class CaptureTests(unittest.TestCase):
    def run_code(self, code, timeout=2):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        observed = capture([sys.executable, "-c", code], root, "run", timeout=timeout, cwd=root)
        return root, observed

    def test_success_retains_both_streams_and_whole_process_cpu(self):
        root, observed = self.run_code("import sys; print('complete'); print('diagnostic', file=sys.stderr); sum(i*i for i in range(300000))")
        self.assertEqual(observed["exit_code"], 0)
        self.assertGreater(observed["wait4_cpu_ns"], 0)
        self.assertGreater(observed["wait4_maxrss_kib"], 0)
        self.assertEqual((root / observed["stdout"]).read_text(), "complete\n")
        self.assertEqual((root / observed["stderr"]).read_text(), "diagnostic\n")
        self.assertFalse(observed["global_cpu_complete"])
        self.assertFalse(observed["global_memory_peak_observed"])

    def test_nonzero_preserves_partial_rows_costs_and_actual_exit(self):
        root, observed = self.run_code("import sys; print('partial', flush=True); sum(i*i for i in range(200000)); sys.exit(7)")
        self.assertEqual((observed["exit_code"], observed["process_exit_code"]), (7, 7))
        self.assertEqual((root / observed["stdout"]).read_text(), "partial\n")
        self.assertGreater(observed["wait4_cpu_ns"], 0)

    def test_timeout_keeps_all_prior_work_and_signal_status(self):
        root, observed = self.run_code("print('before-timeout', flush=True)\nwhile True: pass", timeout=0.15)
        self.assertTrue(observed["timed_out"])
        self.assertEqual(observed["exit_code"], 124)
        self.assertLess(observed["process_exit_code"], 0)
        self.assertGreater(observed["wait4_cpu_ns"], 0)
        self.assertEqual((root / observed["stdout"]).read_text(), "before-timeout\n")

    def test_successful_leader_does_not_leave_a_background_log_writer(self):
        root, observed = self.run_code("import os,time\np=os.fork()\nif p==0:\n time.sleep(0.2)\n open('escaped-output','w').write('late')\n os._exit(0)\nos._exit(0)")
        self.assertEqual(observed["exit_code"], 0)
        time.sleep(0.3)
        self.assertFalse((root / "escaped-output").exists())

    def test_launch_failure_and_existing_logs_are_not_success_or_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observed = capture([str(root / "missing-executable")], root, "run", timeout=1, cwd=root)
            self.assertFalse(observed["executed"])
            self.assertIsNone(observed["exit_code"])
            self.assertIsNone(observed["wait4_cpu_ns"])
            self.assertIn("launch_error", observed)
            with self.assertRaises(FileExistsError):
                capture([sys.executable, "-c", "pass"], root, "run", timeout=1, cwd=root)

    def test_compiler_multicall_symlink_keeps_its_invocation_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / "multicall-launcher"
            launcher.write_text("#!/bin/sh\ncase \"$0\" in */rustc) printf 'compiler path preserved\\n';; *) exit 9;; esac\n")
            launcher.chmod(0o755)
            link = root / "rustc"
            link.symlink_to(launcher)
            with patch.object(runner.shutil, "which", return_value=str(link)):
                selected = runner.discover_tool("rustc")
            good = capture([str(selected), "-vV"], root, "kept-name", timeout=2, cwd=root)
            bad = capture([str(selected.resolve()), "-vV"], root, "lost-name", timeout=2, cwd=root)
            self.assertEqual(selected, link)
            self.assertEqual(good["exit_code"], 0)
            self.assertEqual(bad["exit_code"], 9)
            self.assertEqual((root / good["stdout"]).read_text(), "compiler path preserved\n")
            with patch.object(runner.shutil, "which", return_value=None):
                with self.assertRaises(ValueError):
                    runner.discover_tool("rustc")


if __name__ == "__main__":
    unittest.main()
