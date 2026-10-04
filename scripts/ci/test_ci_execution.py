#!/usr/bin/env python3
"""Exercise source-parent validation, actual failure propagation, and fuzz evidence."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ci_observation import checked
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
