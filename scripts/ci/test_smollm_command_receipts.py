#!/usr/bin/env python3
"""Real command lifecycle controls; these do not execute a model or Cell node."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_smollm_cell_replica_research as runner


class CommandReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="smollm-command-receipt-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def run_code(self, code, **kwargs):
        return runner.run_logged([sys.executable, "-I", "-S", "-c", code], self.root,
                                 "attempt", timeout=kwargs.pop("timeout", 5), **kwargs)

    def receipt(self):
        row = json.loads((self.root / "attempt-command.json").read_text())
        self.assertEqual(row["schema"], "trnm-smollm-command-receipt-v2")
        self.assertEqual(row["elapsed_ns"],
                         row["finished_monotonic_ns"] - row["started_monotonic_ns"])
        self.assertGreater(row["elapsed_ns"], 0)
        self.assertIsNone(row["cpu_ns"])
        self.assertIsNone(row["peak_rss_bytes"])
        self.assertIs(row["process_family_cleanup_verified"], False)
        self.assertIs(row["native_execution_authenticated"], False)
        self.assertIs(row["throughput_qualified"], False)
        for stream in ("stdout", "stderr"):
            raw = (self.root / ("attempt." + stream + ".log")).read_bytes()
            self.assertEqual(len(raw), row[stream + "_bytes"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row[stream + "_sha256"])
        return row

    def test_success_keeps_text_api_and_exact_separate_bytes(self):
        result = self.run_code("import os; os.write(1,b'out\\r\\n'); os.write(2,b'err\\x00')")
        self.assertEqual(result.stdout, "out\r\n")
        self.assertEqual(result.stderr, "err\x00")
        self.assertEqual((self.root / "attempt.log").read_bytes(), b"out\r\nerr\x00")
        row = self.receipt()
        self.assertEqual((row["outcome"], row["returncode"]), ("exit-zero", 0))
        self.assertIs(row["output_complete"], True)

    def test_nonzero_is_retained_before_propagating_original_failure(self):
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            self.run_code("import sys; print('refused', file=sys.stderr); sys.exit(7)")
        self.assertEqual(caught.exception.returncode, 7)
        row = self.receipt()
        self.assertEqual((row["outcome"], row["returncode"]), ("exit-nonzero", 7))
        self.assertIs(row["expected_success"], True)

    def test_expected_refusal_is_not_relabelled_exit_zero(self):
        result = self.run_code("raise SystemExit(3)", expected_success=False)
        self.assertEqual(result.returncode, 3)
        row = self.receipt()
        self.assertEqual(row["outcome"], "exit-nonzero")
        self.assertIs(row["expected_success"], False)

    def test_unexpected_negative_control_success_still_refuses(self):
        with self.assertRaisesRegex(ValueError, "negative control unexpectedly succeeded"):
            self.run_code("pass", expected_success=False)
        self.assertEqual(self.receipt()["outcome"], "exit-zero")

    def test_real_timeout_is_retained_and_not_a_completed_native_observation(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_code("import time; time.sleep(30)", timeout=0.2)
        row = self.receipt()
        self.assertEqual((row["outcome"], row["error_type"]), ("timeout", "TimeoutExpired"))
        self.assertEqual(row["timeout_seconds"], 0.2)
        self.assertIsNone(row["returncode"])
        self.assertIs(row["output_complete"], False)

    def test_partial_timeout_bytes_preserved_without_extending_budget(self):
        original = subprocess.TimeoutExpired(["fixture"], 3, output=b"partial\xff", stderr=b"err\x00")
        with mock.patch.object(runner.subprocess, "run", side_effect=original) as launch:
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                runner.run_logged(["fixture"], self.root, "attempt", timeout=3)
        self.assertIs(caught.exception, original)
        self.assertEqual(launch.call_args.kwargs["timeout"], 3)
        self.assertEqual((self.root / "attempt.stdout.log").read_bytes(), b"partial\xff")
        self.assertEqual((self.root / "attempt.stderr.log").read_bytes(), b"err\x00")
        self.receipt()

    def test_launch_failure_retains_attempt(self):
        with self.assertRaises(FileNotFoundError):
            runner.run_logged([str(self.root / "missing")], self.root, "attempt", timeout=5)
        row = self.receipt()
        self.assertEqual(row["error_type"], "FileNotFoundError")
        self.assertIsNone(row["returncode"])

    def test_undecodable_output_keeps_original_bytes_and_failure(self):
        with self.assertRaises(UnicodeDecodeError):
            self.run_code("import os; os.write(1,b'\\xff')")
        self.assertEqual((self.root / "attempt.stdout.log").read_bytes(), b"\xff")
        row = self.receipt()
        self.assertEqual(row["outcome"], "command-error")
        self.assertEqual(row["returncode"], 0)


if __name__ == "__main__":
    unittest.main()
