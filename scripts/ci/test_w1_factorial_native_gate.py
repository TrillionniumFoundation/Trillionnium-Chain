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
EXAMPLES = ROOT / 'trillionnium/crates/trnm-pon-node/examples'
MATERIAL_SOURCE = ROOT / 'trillionnium/crates/trnm-crypto-primitives/examples/support/w1_material.rs'
COUNTS = {'factorial-kernel-tests': (14, 0), 'factorial-example-tests': (11, 0),
          'header-binding-tests': (1, 0), 'history-w1-tests': (5, 0),
          'history-import-tests': (36, 1), 'cpu-completion-tests': (11, 0)}
HISTORY = [
    'deadline_controls::final_resource_completion_preserves_error_priority_and_original_deadline',
    'deadline_controls::final_resource_expiry_keeps_committed_history_and_settled_cpu',
    'history_codec_snapshot_preserves_legacy_bytes_identity_and_deferred_profile_errors',
    'deadline_controls::history_control_keeps_original_timely_single_resource_observation',
    'deadline_controls::history_control_preexpired_does_not_invoke_resource',
    'deadline_controls::history_control_resource_expiry_refuses_late_success',
    'deadline_controls::history_control_resource_expiry_keeps_original_resource_error',
    'deadline_controls::history_owner_resource_expiry_never_invokes_exclusive_or_shared_action',
    'detached_budget_controls::shared_detached_history_continues_from_real_deficit_without_new_credit',
    'detached_budget_controls::shared_detached_history_refill_keeps_original_resource_cancellation',
    'detached_budget_controls::shared_detached_history_refill_cannot_renew_original_deadline',
]


def names(path, prefix):
    return [prefix + name for name in re.findall(r'#\[test\]\s+fn (\w+)', path.read_text())]


def example_names(version):
    return (names(EXAMPLES / f'pon_w1_legal_strategy_{version}.rs', 'tests::')
            + names(EXAMPLES / 'support/w1_cost_producers.rs',
                    'w1_cost_producers::observed_search_tests::')
            + names(MATERIAL_SOURCE, 'w1_material::tests::'))


def summary(passed, ignored=0):
    return (f'test result: ok. {passed} passed; 0 failed; {ignored} ignored; '
            '0 measured; 0 filtered out; finished in 0.01s\n')


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
        self.example_names = example_names('v3')
        self.assertEqual(len(self.example_names), 11)
        self.logs = {name: summary(passed, ignored)
                     for name, (passed, ignored) in COUNTS.items()}
        self.logs['factorial-kernel-tests'] += ''.join(f'test {n} ... ok\n' for n in self.names)
        self.logs['factorial-example-tests'] += ''.join(f'test {n} ... ok\n' for n in self.example_names)
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
                         original + original.splitlines()[0] + '\n',
                         original + original.splitlines()[0].replace('ok.', 'FAILED.') + '\n', '']
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

    def test_factorial_example_rejects_missing_duplicate_replaced_or_failed_named_control(self):
        original = self.logs['factorial-example-tests']
        for name in self.example_names:
            line = f'test {name} ... ok\n'
            for mutant in [original.replace(line, ''), original + line,
                           original.replace(name, 'tests::unexpected'),
                           original.replace(line, line.replace('... ok', '... FAILED')),
                           original.replace(line, line.replace('... ok', '... ignored'))]:
                with self.subTest(control=name):
                    self.logs['factorial-example-tests'] = mutant
                    self.assertNotEqual(self.run_gate(), 0)
        self.logs['factorial-example-tests'] = original

    def test_factorial_example_does_not_accept_filtered_or_measured_tests(self):
        original = self.logs['factorial-example-tests']
        for field in ('measured', 'filtered out'):
            self.logs['factorial-example-tests'] = original.replace(f'0 {field};', f'1 {field};')
            self.assertNotEqual(self.run_gate(), 0)
        self.logs['factorial-example-tests'] = original


class LegalGateTests(unittest.TestCase):
    def setUp(self):
        workflow = WORKFLOW.read_text()
        command = 'python3 - "$OUT/legal-native-controls.log" <<\'PY\'\n'
        self.assertEqual(workflow.count(command), 1)
        self.code = textwrap.dedent(workflow.split(command, 1)[1].split('          PY', 1)[0])
        self.names = example_names('v1')
        self.assertEqual(len(self.names), 13)
        self.log = ''.join(f'test {name} ... ok\n' for name in self.names) + summary(len(self.names))

    def run_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'legal-native-controls.log'
            path.write_text(self.log)
            return subprocess.run([sys.executable, '-c', self.code, str(path)],
                                  capture_output=True).returncode

    def test_complete_current_native_roster_passes(self):
        self.assertEqual(self.run_gate(), 0)

    def test_every_retained_versioned_material_and_observer_control_executes_once(self):
        original = self.log
        for name in self.names:
            line = f'test {name} ... ok\n'
            for mutant in [original.replace(line, ''), original + line,
                           original.replace(name, 'tests::unexpected'),
                           original.replace(line, line.replace('... ok', '... FAILED')),
                           original.replace(line, line.replace('... ok', '... ignored'))]:
                with self.subTest(control=name):
                    self.log = mutant
                    self.assertNotEqual(self.run_gate(), 0)
        self.log = original

    def test_summary_only_stale_filtered_duplicate_or_failed_summaries_are_refused(self):
        original = self.log
        mutants = [summary(13), original.replace('13 passed;', '8 passed;'),
                   original.replace('0 failed;', '1 failed;'),
                   original.replace('0 ignored;', '1 ignored;'),
                   original.replace('0 measured;', '1 measured;'),
                   original.replace('0 filtered out;', '1 filtered out;'),
                   original + summary(13),
                   original + summary(13).replace('ok.', 'FAILED.'), '']
        for mutant in mutants:
            with self.subTest(mutant=mutant):
                self.log = mutant
                self.assertNotEqual(self.run_gate(), 0)
        self.log = original


if __name__ == '__main__':
    unittest.main()
