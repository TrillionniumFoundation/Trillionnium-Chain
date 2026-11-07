#!/usr/bin/env python3
"""Check the fixed error-boundary roster and retained CI count regression.

Transcript checks are not fresh native execution or global acceptance.
"""
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/pon-recent-batch-acceptance.yml'
EVIDENCE = ROOT / 'evidence/recent-batch-suite-count-20261106'


def guard():
    text = WORKFLOW.read_text()
    matches = re.findall(r"grep -E '([^']+)' \"\$OUT/error-boundary.log\"", text)
    if len(matches) != 1:
        raise ValueError('expected one exact suite guard')
    return matches[0]


def accepts(pattern, text):
    return subprocess.run(['grep', '-E', pattern], input=text, text=True,
                          capture_output=True, check=False).returncode == 0


class RecentBatchSuiteCount(unittest.TestCase):
    def test_guard_retains_exact_current_count_and_original_failure_limits(self):
        self.assertEqual(guard(), r'^test result: ok\. 16 passed; 0 failed; 0 ignored;')

    def test_four_actual_ci_rosters_match_current_source(self):
        source = (ROOT / 'trillionnium/crates/trnm-pon-node/src/store.rs').read_text()
        module = source.split('mod error_boundary_tests {', 1)[1].split('\n}\n', 1)[0]
        names = re.findall(r'#\[test\]\s+fn ([a-zA-Z0-9_]+)\(', module)
        self.assertEqual(len(names), 16)
        for job in (127638016541, 127638016683, 127638016786, 127638016822):
            with self.subTest(job=job):
                log = (EVIDENCE / f'{job}.txt').read_text()
                actual = re.findall(r'^test store::error_boundary_tests::(\w+) \.\.\. ok$', log, re.M)
                self.assertCountEqual(names, actual)
                self.assertEqual(log.count('test result:'), 1)
                self.assertFalse(accepts(guard().replace('16 passed', '13 passed'), log))
                self.assertTrue(accepts(guard(), log))

    def test_missing_extra_failed_ignored_and_incomplete_summaries_rejected(self):
        for text in ('', 'test result: ok. 13 passed; 0 failed; 0 ignored;',
                     'test result: ok. 15 passed; 0 failed; 0 ignored;',
                     'test result: ok. 17 passed; 0 failed; 0 ignored;',
                     'test result: ok. 16 passed; 1 failed; 0 ignored;',
                     'test result: ok. 16 passed; 0 failed; 1 ignored;',
                     'test result: FAILED. 16 passed; 0 failed; 0 ignored;',
                     'test result: ok. 16 passed; 0 failed;'):
            with self.subTest(text=text):
                self.assertFalse(accepts(guard(), text))

    def test_original_native_call_and_three_exact_replays_retained(self):
        text = WORKFLOW.read_text()
        self.assertIn('set -euo pipefail', text)
        self.assertIn('cargo +1.95.0 test --release --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::error_boundary_tests:: -- --show-output --test-threads=1', text)
        self.assertIn('for test in recent_batch_exact_window_and_complete_call_observation recent_batch_retained_corruption_and_read_boundary_match_original recent_batch_branch_reopen_and_callback_errors_preserve_context; do', text)
        self.assertIn('python3 scripts/ci/check_required_native_test.py "$OUT/$test.log" --test "$selector"', text)


if __name__ == '__main__':
    unittest.main()
