#!/usr/bin/env python3
"""Runner boundary tests; Python children below are never labeled W1 execution."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_pon_w1_native_campaign as runner


class RunnerTests(unittest.TestCase):
    def test_source_status_and_tree_cannot_be_substituted(self):
        source = {'head': 'a' * 40, 'tree': 'b' * 40, 'status_porcelain': ''}
        runner.validate_source(source, 'a' * 40, 'b' * 40)
        for key, value in (('status_porcelain', ' M actual.rs'), ('tree', 'c' * 40)):
            bad = dict(source, **{key: value})
            with self.assertRaises(ValueError):
                runner.validate_source(bad, 'a' * 40, 'b' * 40)

    def test_actual_ancestor_limits_and_nice_are_checked(self):
        resource = {'limits': [{'cpu.max': '400000 100000', 'memory.max': '17179869184'},
                               {'cpu.max': 'max 100000', 'memory.max': 'max'}],
                    'nice': 10, 'cpu_affinity': [0, 1, 2, 3]}
        runner.validate_resources(resource, 10)
        for key, value in (('cpu.max', '200000 100000'), ('memory.max', '8589934592')):
            bad = copy.deepcopy(resource)
            bad['limits'][1][key] = value
            with self.assertRaises(ValueError):
                runner.validate_resources(bad, 10)
        with self.assertRaisesRegex(ValueError, 'NICE'):
            runner.validate_resources(resource, 5)

    def test_nonzero_exit_retains_both_streams_and_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            command = [sys.executable, '-c', 'import sys; print("stdout"); print("stderr", file=sys.stderr); sys.exit(7)']
            row = runner.run_step(output, 'boundary-test', command, None, timeout=5)
            self.assertEqual(row['returncode'], 7)
            self.assertFalse(row['complete_success'])
            self.assertEqual((output / row['stdout']).read_bytes(), b'stdout\n')
            self.assertEqual((output / row['stderr']).read_bytes(), b'stderr\n')
            with self.assertRaises(FileExistsError):
                runner.run_step(output, 'boundary-test', command, None, timeout=5)
            self.assertEqual((output / row['stdout']).read_bytes(), b'stdout\n')

    def test_zero_exit_with_output_limit_failure_never_becomes_success(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            row = runner.run_step(output, 'bounded-output-test',
                [sys.executable, '-c', 'print("x"*4096)'], None, timeout=5, stdout_limit=32)
            self.assertFalse(row['complete_success'])
            self.assertIsNotNone(row['error'])
            self.assertTrue(row['stdout_truncated'])
            self.assertLessEqual((output / row['stdout']).stat().st_size, 32)


if __name__ == '__main__':
    unittest.main()
