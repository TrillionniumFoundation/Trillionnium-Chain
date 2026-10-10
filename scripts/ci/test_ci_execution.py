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

    def _timeout_with_term_ignoring_descendant(self, *, use_checked):
        # Run real processes, not mocks. The descendant keeps the observer's
        # actual stdout descriptor after its parent handles TERM and exits zero.
        # A returned timeout must not leave that writer running.
        import os
        import signal
        import time
        with tempfile.TemporaryDirectory(prefix='trnm-ci-descendant-') as directory:
            root = Path(directory)
            child = root / 'child.py'
            child.write_text(
                'import os, signal, sys, time\n'
                'from pathlib import Path\n'
                'signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
                'Path(sys.argv[1]).write_text(str(os.getpid()))\n'
                'print("descendant-ready", flush=True)\n'
                'deadline = time.monotonic() + 20\n'
                'while time.monotonic() < deadline:\n'
                '    print("descendant-output", flush=True)\n'
                '    time.sleep(0.01)\n')
            parent = root / 'parent.py'
            parent.write_text(
                'import signal, subprocess, sys, time\n'
                'signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n'
                'subprocess.Popen([sys.executable, "-S", sys.argv[1], sys.argv[2]])\n'
                'while True: time.sleep(0.01)\n')
            pidfile = root / 'descendant.pid'
            log = root / 'command.log'
            # The fixture uses only stdlib; exclude unrelated site startup hooks.
            command = [sys.executable, '-S', str(parent), str(child), str(pidfile)]
            observations = []
            try:
                if use_checked:
                    with self.assertRaisesRegex(RuntimeError, 'command exited 124'):
                        checked(command, log, observations, timeout=1, cwd=root)
                    result = observations[0]
                else:
                    from ci_observation import run
                    result = run(command, log, timeout=1, cwd=root)
                self.assertTrue(pidfile.is_file(), 'fixture descendant never started')
                self.assertEqual(result['exit_code'], 124)
                self.assertIs(result['timed_out'], True)
                self.assertIn('descendant-ready', log.read_text())
                # Give an already signalled descendant a scheduling turn; a
                # surviving original writer then changes these exact log bytes.
                time.sleep(0.05)
                snapshot = log.read_bytes()
                time.sleep(0.15)
                self.assertEqual(log.read_bytes(), snapshot,
                                 'timeout returned while its descendant still wrote the log')
            finally:
                # The regression must clean up even when run against the known
                # broken baseline. SIGKILL never targets an unrelated process group.
                if pidfile.is_file():
                    try:
                        os.kill(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_timeout_kills_descendant_even_when_term_exits_parent_zero(self):
        self._timeout_with_term_ignoring_descendant(use_checked=False)

    def test_checked_timeout_retains_failure_and_stops_descendant_writer(self):
        self._timeout_with_term_ignoring_descendant(use_checked=True)

    def test_real_success_child_is_not_reclassified(self):
        with tempfile.TemporaryDirectory(prefix='trnm-ci-success-') as directory:
            log = Path(directory) / 'success.log'
            observations = []
            result = checked([sys.executable, '-c', 'print("success-observed")'],
                             log, observations)
            self.assertEqual(result['exit_code'], 0)
            self.assertIs(result['timed_out'], False)
            self.assertEqual(observations, [result])
            self.assertEqual(log.read_text(), 'success-observed\n')

    def test_existing_log_is_not_overwritten_or_reused(self):
        with tempfile.TemporaryDirectory(prefix='trnm-ci-log-owner-') as directory:
            log = Path(directory) / 'old.log'
            log.write_text('retained original failure\n')
            observations = []
            with self.assertRaises(FileExistsError):
                checked([sys.executable, '-c', 'print("substitute pass")'], log, observations)
            self.assertEqual(observations, [])
            self.assertEqual(log.read_text(), 'retained original failure\n')

    def test_cooperative_timeout_never_becomes_a_success(self):
        with tempfile.TemporaryDirectory(prefix='trnm-ci-cooperative-timeout-') as directory:
            from ci_observation import run
            log = Path(directory) / 'timeout.log'
            program = ('import signal, sys, time; '
                       'signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); '
                       'print("cooperative-ready", flush=True); time.sleep(30)')
            result = run([sys.executable, '-S', '-c', program], log, timeout=1)
            self.assertEqual(result['exit_code'], 124)
            self.assertIs(result['timed_out'], True)
            self.assertIn('cooperative-ready', log.read_text())

    def test_term_ignoring_leader_still_uses_original_hard_kill(self):
        with tempfile.TemporaryDirectory(prefix='trnm-ci-hard-timeout-') as directory:
            from ci_observation import run
            log = Path(directory) / 'timeout.log'
            program = ('import signal, time; '
                       'signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                       'print("uncooperative-ready", flush=True); time.sleep(30)')
            result = run([sys.executable, '-S', '-c', program], log, timeout=1)
            self.assertEqual(result['exit_code'], 124)
            self.assertIs(result['timed_out'], True)
            self.assertIn('uncooperative-ready', log.read_text())

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
