#!/usr/bin/env python3
"""Synthetic negative controls; these do not execute Rust tests."""
from pathlib import Path
import unittest

from check_native_constants_roster import EXPECTED, validate


def transcript():
    return ['running 13 tests'] + [f'test {name} ... {outcome}'
                                for name, outcome in EXPECTED.items()] + [
        'test result: ok. 11 passed; 0 failed; 2 ignored; 0 measured; 1070 filtered out; finished in 0.08s']


class RosterTests(unittest.TestCase):
    def test_complete_roster(self):
        self.assertEqual(validate(transcript())['result'], 'PASS')

    def test_ignore_reasons_and_crlf(self):
        lines = [line + (', explicit diagnostic' if line.endswith('ignored') else '') + '\r\n'
                 for line in transcript()]
        self.assertEqual(validate(lines)['result'], 'PASS')

    def test_reordered_names(self):
        lines = transcript()
        self.assertEqual(validate(lines[:1] + list(reversed(lines[1:-1])) + lines[-1:])['result'], 'PASS')

    def test_reject_missing_or_duplicate_each_identity(self):
        original = transcript()
        for i in range(1, 14):
            for changed in (original[:i] + original[i+1:], original[:i] + [original[i]] + original[i:]):
                with self.subTest(index=i, changed=changed), self.assertRaises(ValueError):
                    validate(changed)

    def test_reject_substitution_even_with_same_total(self):
        for i in range(1, 14):
            lines = transcript()
            lines[i] = lines[i].replace('::tests::', '::unrelated::')
            with self.subTest(index=i), self.assertRaises(ValueError):
                validate(lines)

    def test_reject_changed_outcomes(self):
        for i in range(1, 14):
            for outcome in ('FAILED', 'ok', 'ignored'):
                lines = transcript()
                old = lines[i].split(' ... ')[1]
                if old == outcome:
                    continue
                lines[i] = lines[i].split(' ... ')[0] + ' ... ' + outcome
                with self.subTest(index=i, outcome=outcome), self.assertRaises(ValueError):
                    validate(lines)

    def test_reject_wrong_summary(self):
        for old, new in [('11 passed', '10 passed'), ('0 failed', '1 failed'),
                         ('2 ignored', '1 ignored'), ('0 measured', '1 measured'),
                         ('result: ok', 'result: FAILED')]:
            lines = transcript()
            lines[-1] = lines[-1].replace(old, new)
            with self.subTest(new=new), self.assertRaises(ValueError):
                validate(lines)

    def test_reject_truncated_extra_or_zero_invocations(self):
        lines = transcript()
        for changed in ([], lines[:-1], lines[1:], lines + lines,
                        ['running 0 tests'] + lines[1:], lines + [lines[1]],
                        [lines[1]] + lines, [lines[-1]]):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate(changed)

    def test_reject_previous_roster_without_page_controls(self):
        lines = [line for line in transcript() if '::native_lift_pages_' not in line]
        lines[0] = 'running 9 tests'
        lines[-1] = lines[-1].replace('11 passed', '7 passed')
        with self.assertRaises(ValueError):
            validate(lines)

    def test_workflow_keeps_original_gate_and_uses_roster(self):
        root = Path(__file__).resolve().parents[2]
        text = (root / '.github/workflows/pon-branch-encoding-acceptance.yml').read_text()
        self.assertIn('python3 scripts/ci/check_native_constants_roster.py "$OUT/native-constants.log"', text)
        self.assertIn('python3 scripts/ci/test_native_constants_roster.py', text)
        self.assertIn('--lib account_archive_prototype::native_store::tests -- --show-output --test-threads=1', text)
        for retained in ('--lib account_archive_prototype::native_store::batch_tests',
                         '--lib authenticated_migration', '--test public_v3_service_campaign',
                         '--all-targets --all-features -- -D warnings',
                         '--exact --ignored --show-output --test-threads=1'):
            self.assertIn(retained, text)
        self.assertNotIn('continue-on-error: true', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
