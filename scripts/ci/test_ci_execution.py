#!/usr/bin/env python3
"""Exercise source-parent validation, actual failure propagation, and fuzz evidence."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ci_observation import checked
from check_required_native_test import validate as validate_required_test
from run_fuzz_smoke import counters
from verify_ci_source import verify
# Include the raw-worktree negatives in both existing repository-truth lanes.
from test_ci_source_integrity import TrackedSourceTests


class SourceIdentityTests(unittest.TestCase):
    def test_head_and_merge_evidence_cannot_be_interchanged(self):
        with tempfile.TemporaryDirectory(prefix='trnm-ci-source-') as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, text=True, stderr=subprocess.DEVNULL).strip()
            git('init', '-b', 'base')
            git('config', 'user.name', 'CI boundary test')
            git('config', 'user.email', 'ci-test@example.invalid')
            (root / 'base.txt').write_text('base\n')
            git('add', '.')
            git('commit', '-m', 'base')
            base = git('rev-parse', 'HEAD')
            git('switch', '-c', 'candidate')
            (root / 'candidate.txt').write_text('candidate\n')
            git('add', '.')
            git('commit', '-m', 'candidate')
            head = git('rev-parse', 'HEAD')
            self.assertEqual(verify('head', head, root=root)['tested_commit'], head)
            with self.assertRaises(ValueError):
                verify('prospective-merge', head, base, head, root)
            git('switch', 'base')
            git('merge', '--no-ff', '-m', 'prospective merge', 'candidate')
            merge = git('rev-parse', 'HEAD')
            report = verify('prospective-merge', head, base, merge, root)
            self.assertEqual(report['base'], base)
            self.assertFalse(report['tests_executed_by_identity_check'])
            with self.assertRaises(ValueError):
                verify('head', head, root=root)
            with self.assertRaises(ValueError):
                verify('prospective-merge', base, head, merge, root)
            (root / 'untracked').write_text('changed source')
            with self.assertRaises(ValueError):
                verify('prospective-merge', head, base, merge, root)


class ObservationTests(unittest.TestCase):
    def test_real_nonzero_child_is_retained_and_fails_the_runner(self):
        with tempfile.TemporaryDirectory(prefix='trnm-ci-failure-') as directory:
            log = Path(directory) / 'failure.log'
            observations = []
            with self.assertRaises(RuntimeError):
                checked([sys.executable, '-c', 'print("retained failure"); raise SystemExit(7)'],
                        log, observations)
            self.assertEqual(observations[0]['exit_code'], 7)
            self.assertIn('retained failure', log.read_text())

    def test_fuzz_receipt_requires_instrumented_mutations(self):
        real_shape = ('INFO: Loaded 1 modules (123 inline 8-bit counters)\n'
                      '#100 DONE cov: 41 ft: 49 corp: 5/321b\n'
                      'stat::number_of_executed_units: 100\n')
        self.assertEqual(counters(real_shape, 10)['executed_units'], 100)
        for invalid in [real_shape.replace('100', '1'),
                        real_shape.replace('INFO: Loaded', 'not instrumented'),
                        real_shape.split('stat::')[0], '20 fixed cases passed']:
            with self.assertRaises(ValueError):
                counters(invalid, 10)


class RequiredNativeTestTests(unittest.TestCase):
    NAME = 'gate::required'
    # Actual Rust 1.95.0 libtest pretty-format shape; these fixtures exercise
    # the parser only. The separate shell controls exercise exit propagation.
    GOOD = ('running 1 test\n'
            'test gate::required ... native control progress\n'
            'no final newlineok\n\n'
            'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
            '2 filtered out; finished in 0.00s\n')

    def check(self, text):
        return validate_required_test(text.splitlines(keepends=True), self.NAME)

    def test_one_named_pass_with_nocapture_progress(self):
        self.assertEqual(self.check(self.GOOD)['executed_tests'], 1)
        self.assertEqual(self.check(self.GOOD.replace('\n', '\r\n'))['test'], self.NAME)
        self.assertEqual(self.check(self.GOOD.replace('native control progress\nno final newlineok',
                                                    'ok'))['result'], 'PASS')

    def test_zero_matches_is_not_a_pass(self):
        zero = ('running 0 tests\n\n'
                'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; '
                '3 filtered out; finished in 0.00s\n')
        with self.assertRaises(ValueError):
            self.check(zero)

    def test_ignored_failed_measured_or_missing_outcome_is_rejected(self):
        for text in [self.GOOD.replace('1 passed', '0 passed').replace('0 ignored', '1 ignored'),
                     self.GOOD.replace('ok. 1 passed; 0 failed', 'FAILED. 0 passed; 1 failed'),
                     self.GOOD.replace('0 measured', '1 measured'),
                     self.GOOD.split('test result:')[0], '', 'all checks passed\n']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.check(text)

    def test_wrong_test_duplicate_or_missing_identity_is_rejected(self):
        for text in [self.GOOD.replace(self.NAME, 'gate::other'),
                     self.GOOD.replace('test gate::required ...', 'unlabelled progress'),
                     self.GOOD.replace('no final newlineok', 'test gate::required ... ok'),
                     self.GOOD.replace('running 1 test', 'running 2 tests')]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.check(text)

    def test_multiple_runs_or_summary_replay_is_rejected(self):
        summary = self.GOOD[self.GOOD.index('test result:'):]
        for text in [self.GOOD * 2, self.GOOD + summary, summary + self.GOOD,
                     self.GOOD + 'running 0 tests\n',
                     self.GOOD.replace('running 1 test', 'running 1 test\nrunning 1 test')]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.check(text)

    def test_noncanonical_control_lines_fail_closed(self):
        for text in [self.GOOD.replace('running 1 test', 'running 01 test'),
                     self.GOOD.replace('running 1 test', 'running one test'),
                     self.GOOD.replace('finished in 0.00s', 'finished in NaNs'),
                     self.GOOD.replace('1 passed', '10 passed')]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.check(text)

    def test_progress_is_streamed_and_not_collected(self):
        def lines():
            yield 'running 1 test\n'
            yield f'test {self.NAME} ... first progress\n'
            for _ in range(10000):
                yield 'authenticated full capacity: progress\n'
            yield self.GOOD[self.GOOD.index('test result:'):]
        self.assertEqual(validate_required_test(lines(), self.NAME)['executed_tests'], 1)

    def test_cli_keeps_missing_and_invalid_logs_nonzero(self):
        checker = Path(__file__).with_name('check_required_native_test.py')
        with tempfile.TemporaryDirectory(prefix='trnm-native-test-log-') as directory:
            path = Path(directory) / 'log with spaces'
            for content, expected in [(None, 1), ('', 1), (self.GOOD, 0),
                                      (self.GOOD.replace(self.NAME, 'gate::other'), 1)]:
                if content is not None:
                    path.write_text(content)
                result = subprocess.run([sys.executable, str(checker), str(path), '--test', self.NAME],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_invalid_expected_name_is_not_an_interpolated_pattern(self):
        for name in ['', 'gate::.*', 'gate::required\n', 'gate::required --ignored']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_required_test(self.GOOD.splitlines(), name)


if __name__ == '__main__':
    unittest.main(verbosity=2)
