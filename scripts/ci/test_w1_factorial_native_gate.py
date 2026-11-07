#!/usr/bin/env python3
"""Exercise the actual workflow gate, including false-success log mutations."""
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/pon-w1-work-security.yml'
SOURCE = ROOT / 'trillionnium/crates/trnm-crypto-primitives/src/pon_work/legal_attempt.rs'
RANK_SOURCE = SOURCE.parent / 'legal_attempt/low_rank.rs'
COUNTS = {'factorial-kernel-tests': (14, 0), 'factorial-example-tests': (6, 0),
          'header-binding-tests': (1, 0), 'history-w1-tests': (5, 0),
          'history-import-tests': (28, 1), 'cpu-completion-tests': (11, 0)}
HISTORY = [
    'deadline_controls::final_resource_completion_preserves_error_priority_and_original_deadline',
    'deadline_controls::final_resource_expiry_keeps_committed_history_and_settled_cpu',
    'history_codec_snapshot_preserves_legacy_bytes_identity_and_deferred_profile_errors',
]


class NativeGateTests(unittest.TestCase):
    def setUp(self):
        workflow = WORKFLOW.read_text()
        self.code = textwrap.dedent(workflow.split("<<'PYTEST'\n", 1)[1].split('          PYTEST', 1)[0])
        self.names = ['pon_work::legal_attempt::tests::' + n for n in
                      re.findall(r'#\[test\]\s+fn (\w+)', SOURCE.read_text())]
        self.assertEqual(len(self.names), 9)
        rank_names = ['pon_work::legal_attempt::low_rank::tests::' + n for n in
                      re.findall(r'#\[test\]\s+fn (\w+)', RANK_SOURCE.read_text())]
        self.assertEqual(len(rank_names), 5)
        self.names += rank_names
        self.logs = {name: f'test result: ok. {passed} passed; 0 failed; {ignored} ignored;\n'
                     for name, (passed, ignored) in COUNTS.items()}
        self.logs['factorial-kernel-tests'] += ''.join(f'test {n} ... ok\n' for n in self.names)
        self.logs['history-import-tests'] += ''.join(
            f'test ingress::history_import::tests::{n} ... ok\n' for n in HISTORY)

    def run_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, content in self.logs.items():
                (Path(directory) / (name + '.log')).write_text(content)
            return subprocess.run([sys.executable, '-c', self.code, directory], capture_output=True).returncode

    def test_complete_roster_passes(self):
        self.assertEqual(self.run_gate(), 0)

    def test_every_suite_rejects_wrong_count_failure_ignored_and_duplicate_summary(self):
        for name in COUNTS:
            original = self.logs[name]
            mutations = [original.replace(' passed;', '0 passed;', 1),
                         original.replace('0 failed;', '1 failed;', 1),
                         original.replace(' ignored;', '0 ignored;', 1),
                         original + original.splitlines()[0] + '\n', '']
            for mutant in mutations:
                with self.subTest(suite=name, mutant=mutant):
                    self.logs[name] = mutant
                    self.assertNotEqual(self.run_gate(), 0)
            self.logs[name] = original

    def test_kernel_rejects_missing_duplicate_or_replaced_named_control(self):
        original = self.logs['factorial-kernel-tests']
        for name in self.names:
            line = f'test {name} ... ok\n'
            for mutant in [original.replace(line, ''), original + line,
                           original.replace(name, 'pon_work::legal_attempt::tests::unexpected')]:
                with self.subTest(control=name):
                    self.logs['factorial-kernel-tests'] = mutant
                    self.assertNotEqual(self.run_gate(), 0)
        self.logs['factorial-kernel-tests'] = original

    def test_history_named_controls_remain_required_once(self):
        original = self.logs['history-import-tests']
        for name in HISTORY:
            line = f'test ingress::history_import::tests::{name} ... ok\n'
            for mutant in [original.replace(line, ''), original + line]:
                self.logs['history-import-tests'] = mutant
                self.assertNotEqual(self.run_gate(), 0)
        self.logs['history-import-tests'] = original


if __name__ == '__main__':
    unittest.main()
