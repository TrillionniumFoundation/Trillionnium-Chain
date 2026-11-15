#!/usr/bin/env python3
"""Negative transcript/source controls; these do not execute Rust tests."""
from pathlib import Path
import re
import unittest

from check_consensus_roster import EXPECTED, PASSED, validate

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/pon-branch-encoding-acceptance.yml'
SOURCE = ROOT / 'trillionnium/crates/trnm-pon-node/src/consensus.rs'


def transcript():
    return ['running 11 tests'] + [f'test {name} ... ok' for name in sorted(EXPECTED)] + [
        'test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 1320 filtered out; finished in 0.06s']


class ConsensusRosterTests(unittest.TestCase):
    def require_isolated_consensus_controls(self, workflow):
        loops = [match for match in re.finditer(
            r"^          for test in (?P<names>[^\n]+); do\n"
            r"(?P<body>.*?)^          done$", workflow, re.MULTILINE | re.DOTALL)
            if 'selector="consensus::tests::$test"' in match["body"]]
        self.assertEqual(len(loops), 1)
        loop = loops[0]
        self.assertEqual(loop["names"].split(), [
            'aligned_division_preserves_all_512_shift_and_limb_boundaries',
            'aligned_division_matches_original_for_wide_arbitrary_operands',
            'aligned_required_work_and_retarget_match_original_arithmetic',
            'native_arithmetic_matches_versioned_python_domain_vectors',
        ])
        command = ('cargo +1.95.0 test --release --locked --manifest-path trillionnium/Cargo.toml '
                   '-p trnm-pon-node --lib "$selector" -- --exact --show-output --test-threads=1')
        self.assertIn(command, loop["body"])
        self.assertIn('python3 scripts/ci/check_required_native_test.py '
                      '"$OUT/$test.log" --test "$selector"', loop["body"])
        return loop

    def test_workflow_retains_all_four_isolated_consensus_controls(self):
        self.require_isolated_consensus_controls(WORKFLOW.read_text(encoding='utf-8'))

    def test_missing_duplicate_or_unchecked_isolated_control_is_refused(self):
        workflow = WORKFLOW.read_text(encoding='utf-8')
        loop = self.require_isolated_consensus_controls(workflow)
        original = loop.group(0)
        changes = [(name + ' ', '') for name in loop["names"].split()[:-1]]
        last = 'native_arithmetic_matches_versioned_python_domain_vectors'
        changes += [
            (' ' + last + '; do', '; do'),
            (' ' + last + '; do', ' ' + last + ' ' + last + '; do'),
            (' -- --exact --show-output', ' -- --show-output'),
            ('python3 scripts/ci/check_required_native_test.py', 'python3 scripts/ci/other.py'),
        ]
        for old, new in changes:
            with self.subTest(replacement=new):
                self.assertIn(old, original)
                changed = workflow[:loop.start()] + original.replace(old, new, 1) + workflow[loop.end():]
                with self.assertRaises(AssertionError):
                    self.require_isolated_consensus_controls(changed)

    def test_complete_frozen_roster(self):
        self.assertEqual(validate(transcript())['passed'], list(PASSED))

    def test_reordered_crlf_and_show_output_listing(self):
        rows = transcript()
        listing = ['successes:', '', 'successes:'] + ['    ' + name for name in sorted(EXPECTED)]
        changed = rows[:1] + list(reversed(rows[1:-1])) + listing + rows[-1:]
        self.assertEqual(validate(line + '\r\n' for line in changed)['result'], 'PASS')

    def test_missing_duplicate_or_substituted_identity_is_rejected(self):
        original = transcript()
        for index in range(1, 12):
            changed = original.copy()
            changed[index] = changed[index].replace('consensus::tests::', 'unrelated::tests::')
            for variant in (original[:index] + original[index + 1:],
                            original[:index] + [original[index]] + original[index:], changed):
                with self.subTest(index=index, variant=variant), self.assertRaises(ValueError):
                    validate(variant)

    def test_each_failed_ignored_or_measured_outcome_is_rejected(self):
        for index in range(1, 12):
            for outcome in ('FAILED', 'ignored', 'ignored, diagnostic', 'bench: 10 ns/iter'):
                rows = transcript()
                rows[index] = rows[index][:-2] + outcome
                with self.subTest(index=index, outcome=outcome), self.assertRaises(ValueError):
                    validate(rows)

    def test_wrong_terminal_summary_is_rejected(self):
        for old, new in [('11 passed', '10 passed'), ('11 passed', '12 passed'),
                         ('0 failed', '1 failed'), ('0 ignored', '1 ignored'),
                         ('0 measured', '1 measured'), ('result: ok', 'result: FAILED')]:
            rows = transcript()
            rows[-1] = rows[-1].replace(old, new)
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                validate(rows)

    def test_zero_extra_partial_and_reordered_invocations_are_rejected(self):
        rows = transcript()
        for variant in ([], rows[:-1], rows[1:], rows + rows, [rows[-1]],
                        rows + [rows[1]], [rows[1]] + rows,
                        ['running 0 tests'] + rows[1:],
                        rows[:-1] + [rows[-1], rows[-1]]):
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                validate(variant)

    def test_previous_ten_test_roster_does_not_pass(self):
        rows = [row for row in transcript()
                if 'native_arithmetic_matches_versioned_python_domain_vectors' not in row]
        rows[0] = 'running 10 tests'
        rows[-1] = rows[-1].replace('11 passed', '10 passed')
        with self.assertRaises(ValueError):
            validate(rows)

    def test_frozen_names_cover_each_actual_source_test(self):
        source = SOURCE.read_text(encoding='utf-8')
        names = re.findall(r'#\[test\]\s+fn (\w+)\(', source)
        self.assertCountEqual(names, PASSED)
        self.assertEqual(len(re.findall(r'#\[test\]', source)), len(PASSED))

    def test_workflow_keeps_original_native_and_downstream_gates(self):
        workflow = WORKFLOW.read_text(encoding='utf-8')
        check = 'python3 scripts/ci/check_consensus_roster.py "$OUT/work-arithmetic.log"'
        controls = 'python3 scripts/ci/test_consensus_roster.py'
        command = ('cargo +1.95.0 test --release --locked --manifest-path trillionnium/Cargo.toml '
                   '-p trnm-pon-node --lib consensus::tests:: -- --show-output --test-threads=1')
        self.assertEqual(workflow.count(check), 1)
        self.assertEqual(workflow.count(controls), 1)
        self.assertIn(command, workflow)
        self.assertLess(workflow.index(controls), workflow.index(command))
        self.assertLess(workflow.index(command), workflow.index(check))
        for retained in ('set -euo pipefail',
                         'aligned_division_preserves_all_512_shift_and_limb_boundaries',
                         'aligned_division_matches_original_for_wide_arbitrary_operands',
                         'aligned_required_work_and_retarget_match_original_arithmetic',
                         '--lib ingress::public_v3::scalar_cpu::request_owned_reserve_tests',
                         '--test public_v3_service_campaign',
                         '--all-targets --all-features -- -D warnings'):
            self.assertIn(retained, workflow)
        self.assertNotIn('continue-on-error: true', workflow)
        self.assertNotRegex(workflow, r'grep[^\n]*\$OUT/work-arithmetic\.log')


if __name__ == '__main__':
    unittest.main(verbosity=2)
