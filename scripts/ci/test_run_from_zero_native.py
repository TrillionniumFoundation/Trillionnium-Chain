#!/usr/bin/env python3
"""Execution-driver negative controls; compiler/test processes are simulated here.

These tests verify result handling, not Rust compilation or public service.
"""
from __future__ import annotations
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_from_zero_native as driver


def artifact(path: Path, **fields: object) -> str:
    row = {'reason': 'compiler-artifact', 'target': {'name': driver.TARGET},
           'profile': {'test': True}, 'executable': str(path)}
    row.update(fields)
    return json.dumps(row)


class BinarySelectionTests(unittest.TestCase):
    def test_exact_artifact_selected(self):
        p = Path('/tmp/exact-build-test')
        self.assertEqual(driver.select_binary(['ordinary compiler diagnostic', artifact(p)]), p)

    def test_empty_output_cannot_select_an_old_binary(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED'):
            driver.select_binary([])

    def test_duplicate_artifacts_are_not_silently_deduplicated(self):
        row = artifact(Path('/tmp/exact-build-test'))
        with self.assertRaisesRegex(ValueError, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED'):
            driver.select_binary([row, row])

    def test_non_test_binary_is_not_a_test_harness(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED'):
            driver.select_binary([artifact(Path('/tmp/other'), profile={'test': False})])

    def test_numeric_truth_is_not_boolean_test_identity(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED'):
            driver.select_binary([artifact(Path('/tmp/other'), profile={'test': 1})])

    def test_wrong_target_cannot_replace_required_test(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED'):
            driver.select_binary([artifact(Path('/tmp/other'), target={'name': 'different'})])

    def test_missing_executable_rejected(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED'):
            driver.select_binary([artifact(Path('/tmp/other'), executable=None)])

    def test_duplicate_json_identity_rejected(self):
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY'):
            driver.select_binary(['{"reason":"compiler-artifact","reason":"other"}'])


class ExecutionBoundaryTests(unittest.TestCase):
    def exercise(self, *, fail=None, zero=None, ignored=None, timeout=None,
                 format_exit=0, build_exit=0, source_drift=False, binary_drift=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'; root.mkdir()
            test_source = root / driver.SOURCE
            test_source.parent.mkdir(parents=True)
            test_source.write_text('// simulated source; not Rust execution\n')
            binary = root / 'fake-binary'; binary.write_bytes(b'not a real executable')
            identity = {'commit': 'a'*40, 'tree': 'b'*40, 'test_sha256': driver.digest(test_source.read_bytes())}
            after = copy.deepcopy(identity)
            if source_drift:
                after['tree'] = 'c'*40
            out = Path(directory) / 'observations'
            seen = []
            def child(command, folder, seconds):
                folder.mkdir()
                name = folder.name
                seen.append(name)
                code = format_exit if name == 'format-check' else build_exit if name == 'build' else 0
                text = artifact(binary) if name == 'build' else ''
                timed_out = name == timeout
                if name in driver.TESTS:
                    if name == zero:
                        text = 'running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s\n'
                    elif name == ignored:
                        text = 'running 1 test\ntest ' + name + ' ... ignored\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 2 filtered out; finished in 0.00s\n'
                    else:
                        text = 'running 1 test\ntest ' + name + ' ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s\n'
                    if name == fail:
                        code = 101
                    if binary_drift:
                        binary.write_bytes(b'changed binary')
                (folder / 'stdout').write_text(text)
                (folder / 'stderr').write_text('retained simulated stderr\n')
                # There are deliberately no invented CPU values in this fixture.
                return {'exit_code': code, 'timed_out': timed_out, 'simulated_control': True}
            previous_cwd = Path.cwd()
            try:
                with patch.object(driver, 'ROOT', root), \
                     patch.object(driver, 'source_identity', side_effect=[identity, after]), \
                     patch.object(driver, 'run_child', side_effect=child), \
                     patch.object(driver.subprocess, 'check_output', return_value='simulated compiler version\n'):
                    with redirect_stdout(io.StringIO()):
                        result = driver.run(out)
                retained = json.loads((out / 'manifest.json').read_text())
                self.assertEqual(retained, result)
                self.assertTrue((out / 'build/stderr').exists())
                return result, seen
            finally:
                os.chdir(previous_cwd)

    def test_driver_success_requires_all_three_named_results(self):
        result, _ = self.exercise()
        self.assertTrue(result['passed'])
        self.assertEqual([r['name'] for r in result['runs']], list(driver.TESTS))
        self.assertTrue(all(r['process']['simulated_control'] for r in result['runs']))

    def test_build_failure_preserved_without_test_execution(self):
        result, seen = self.exercise(build_exit=101)
        self.assertFalse(result['passed'])
        self.assertFalse(result['source_recompiled'])
        self.assertFalse(result['runs'])
        self.assertNotIn(driver.TESTS[0], seen)
        self.assertIn('NATIVE_BUILD_FAILED', result['failures'])

    def test_zero_match_exit_zero_is_still_failure(self):
        result, _ = self.exercise(zero=driver.TESTS[0])
        self.assertFalse(result['passed'])
        self.assertEqual([r['passed'] for r in result['runs']], [False, True, True])

    def test_ignored_exit_zero_is_still_failure(self):
        result, _ = self.exercise(ignored=driver.TESTS[1])
        self.assertFalse(result['passed'])
        self.assertEqual([r['passed'] for r in result['runs']], [True, False, True])

    def test_nonzero_exit_cannot_be_overridden_by_success_text(self):
        result, _ = self.exercise(fail=driver.TESTS[0])
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['runs']), 3)
        self.assertFalse(result['runs'][0]['passed'])

    def test_timeout_cannot_be_overridden_by_success_text(self):
        result, _ = self.exercise(timeout=driver.TESTS[2])
        self.assertFalse(result['passed'])
        self.assertFalse(result['runs'][2]['passed'])

    def test_format_failure_retains_native_results_but_refuses_overall_pass(self):
        result, _ = self.exercise(format_exit=1)
        self.assertFalse(result['passed'])
        self.assertTrue(result['all_named_tests_passed'])
        self.assertFalse(result['format_passed'])

    def test_source_moved_after_build_cannot_pass(self):
        result, _ = self.exercise(source_drift=True)
        self.assertFalse(result['passed'])
        self.assertNotEqual(result['source_before'], result['source_after'])

    def test_binary_mutation_refuses_source_identity_substitution(self):
        result, _ = self.exercise(binary_drift=True)
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_BINARY_CHANGED', result['failures'])

    def test_caller_environment_is_restored(self):
        name = 'TRNM_PUBLIC_V3_FROM_ZERO_DIR'
        with patch.dict(os.environ, {name: 'unchanged-parent-setting'}):
            self.exercise()
            self.assertEqual(os.environ[name], 'unchanged-parent-setting')


if __name__ == '__main__':
    unittest.main(verbosity=2)
