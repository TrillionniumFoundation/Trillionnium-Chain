#!/usr/bin/env python3
"""Replay the migration count regression; not a fresh native acceptance run."""
from pathlib import Path
import gzip
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/pon-branch-encoding-acceptance.yml'
EVIDENCE = ROOT / 'evidence/branch-migration-count-20261106'


def guard():
    patterns = re.findall(r"grep -E '([^']+)' \"\$OUT/migration.log\"", WORKFLOW.read_text())
    if len(patterns) != 1:
        raise ValueError('expected exactly one migration suite guard')
    return patterns[0]


def accepts(pattern, text):
    return subprocess.run(['grep', '-E', pattern], input=text, text=True,
                          capture_output=True, check=False).returncode == 0


def source_names():
    store = ROOT / 'trillionnium/crates/trnm-pon-node/src/store'
    owners = {
        'authenticated_migration_tests.rs': 'store::authenticated_migration::tests::',
        'growth_reservation_io.rs': 'store::authenticated_migration::growth_reservation_io::tests::',
        'authenticated_migration/growth_rehearsal/snapshot.rs':
            'store::authenticated_migration::growth_rehearsal::snapshot::receipt_copy_tests::',
        'reorg_cancellation/tests.rs': 'store::reorg_cancellation::tests::',
    }
    names = []
    for path, prefix in owners.items():
        for name in re.findall(r'#\[test\]\s+fn (\w+)\(', (store / path).read_text()):
            full = prefix + name
            if 'authenticated_migration' in full:
                names.append(full)
    return names


class MigrationCountTests(unittest.TestCase):
    def test_exact_current_count_and_original_failure_limits(self):
        self.assertEqual(guard(), r'^test result: ok\. 40 passed; 0 failed; 0 ignored;')

    def test_four_actual_ci_rosters_match_source(self):
        expected = source_names()
        self.assertEqual(len(expected), 40)
        for job in (127684791178, 127684791288, 127684791333, 127684791498):
            with self.subTest(job=job):
                log = gzip.decompress((EVIDENCE / f'{job}.txt.gz').read_bytes()).decode()
                # The parent --show-output success list excludes nested subprocess
                # harness announcements. Keep those nested transcripts in fixtures.
                actual = re.findall(r'^    (store::\S*authenticated_migration\S*)$', log, re.M)
                self.assertCountEqual(expected, actual)
                self.assertEqual(log.count('running 40 tests'), 1)
                self.assertEqual(log.count('test result: ok. 40 passed;'), 1)
                self.assertFalse(accepts(guard().replace('40 passed', '36 passed'), log))
                self.assertTrue(accepts(guard(), log))

    def test_missing_extra_failed_ignored_and_partial_summaries_rejected(self):
        for text in ('', 'test result: ok. 36 passed; 0 failed; 0 ignored;',
                     'test result: ok. 39 passed; 0 failed; 0 ignored;',
                     'test result: ok. 41 passed; 0 failed; 0 ignored;',
                     'test result: ok. 40 passed; 1 failed; 0 ignored;',
                     'test result: ok. 40 passed; 0 failed; 1 ignored;',
                     'test result: FAILED. 40 passed; 0 failed; 0 ignored;',
                     'test result: ok. 40 passed; 0 failed;',
                     'test result: ok. 1 passed; 0 failed; 0 ignored;'):
            with self.subTest(text=text):
                self.assertFalse(accepts(guard(), text))

    def test_original_native_call_batch_and_downstream_requirements_retained(self):
        text = WORKFLOW.read_text()
        self.assertIn('set -euo pipefail', text)
        self.assertIn('cargo +1.95.0 test --release --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib authenticated_migration -- --show-output --test-threads=1', text)
        for retained in ('--lib account_archive_prototype::native_store::batch_tests',
                         '--test public_v3_service_campaign',
                         '--all-targets --all-features -- -D warnings'):
            self.assertIn(retained, text)
        self.assertNotIn('continue-on-error: true', text)


if __name__ == '__main__':
    unittest.main()
