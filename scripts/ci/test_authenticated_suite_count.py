#!/usr/bin/env python3
"""Replay the actual workflow guards; not a new native execution."""
from pathlib import Path
import gzip
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/pon-recent-batch-acceptance.yml'
EVIDENCE = ROOT / 'evidence/authenticated-suite-count-20261106'
JOBS = (127701926958, 127701927002, 127701927160, 127701927200)
PREFIX = 'store::native_authenticated::'


def workflow_guards():
    text = WORKFLOW.read_text()
    start = text.index('if test "$suite" = store::native_authenticated::; then\n              grep')
    section = text[start:text.index('          PYLOG', start)]
    grep = re.search(r"grep -E '([^']+)'", section)[1]
    code = textwrap.dedent(section.split("<<'PYLOG'\n", 1)[1])
    return grep, code


def check(log, old=False):
    pattern, code = workflow_guards()
    if old:
        pattern = pattern.replace('97 passed', '91 passed')
        code = code.replace('97 passed', '91 passed').replace('!= 97', '!= 91').replace('!= 25', '!= 23')
    grep = subprocess.run(['grep', '-E', pattern], input=log, text=True, capture_output=True)
    with tempfile.TemporaryDirectory(prefix='auth-suite-guard-') as directory:
        path = Path(directory) / 'native.log'
        path.write_text(log)
        inline = subprocess.run([sys.executable, '-B', '-c', code, str(path)], capture_output=True)
    return grep.returncode == 0, inline.returncode == 0


def fixture(job):
    return gzip.decompress((EVIDENCE / f'{job}.txt.gz').read_bytes()).decode()


class AuthenticatedSuiteCount(unittest.TestCase):
    def test_all_four_original_logs_pass_both_corrected_guards_and_fail_old(self):
        for job in JOBS:
            with self.subTest(job=job):
                self.assertEqual(check(fixture(job)), (True, True))
                self.assertEqual(check(fixture(job), old=True), (False, False))

    def test_complete_roster_matches_source_owners_and_subgroups(self):
        store = ROOT / 'trillionnium/crates/trnm-pon-node/src/store'
        files = [store / 'native_authenticated.rs', store / 'native_fixed_blob_tests.rs']
        files += list((store / 'native_authenticated').rglob('*.rs'))
        source = [name for path in files for name in re.findall(
            r'#\[test\]\s*(?:#\[[^\]]+\]\s*)*fn (\w+)\(', path.read_text())]
        self.assertEqual(len(source), 97)
        for job in JOBS:
            names = re.findall(r'^test (store::native_authenticated::\w[\w:]*) \.\.\. ok$', fixture(job), re.M)
            self.assertEqual(len(names), 97)
            self.assertEqual(len(set(names)), 97)
            self.assertCountEqual(source, [name.rsplit('::', 1)[1] for name in names])
            self.assertEqual(sum('::post_write_readback::tests::' in name for name in names), 25)
            self.assertEqual(sum('::current_accounts_tests::' in name for name in names), 5)

    def test_missing_duplicate_wrong_group_and_current_identity_rejected(self):
        log = fixture(JOBS[0])
        names = re.findall(r'^test (store::native_authenticated::\w[\w:]*) \.\.\. ok$', log, re.M)
        first = f'test {names[0]} ... ok\n'
        for changed in (log.replace(first, '', 1), log + first,
                        log.replace('::post_write_readback::tests::', '::other::', 1),
                        log.replace('::current_accounts_tests::', '::other::', 1)):
            with self.subTest(changed=changed[:60]):
                self.assertFalse(check(changed)[1])

    def test_reduced_extra_failed_ignored_partial_and_repeated_summary_rejected(self):
        log = fixture(JOBS[0])
        for old, new in [('97 passed', '91 passed'), ('97 passed', '96 passed'),
                         ('97 passed', '98 passed'), ('0 failed', '1 failed'),
                         ('0 ignored', '1 ignored'), ('result: ok.', 'result: FAILED.')]:
            with self.subTest(new=new):
                self.assertEqual(check(log.replace(old, new)), (False, False))
        summary = next(line for line in log.splitlines() if line.startswith('test result:'))
        self.assertEqual(check(log.replace(summary, '')), (False, False))
        self.assertFalse(check(log + summary + '\n')[1])

    def test_original_execution_and_downstream_requirements_unchanged(self):
        text = WORKFLOW.read_text()
        for required in ('options+=(--include-ignored)', 'set -euo pipefail',
                         '-- "${options[@]}" --show-output --test-threads=1',
                         '--test continuity_authenticated --test authenticated_storage_cli',
                         '--all-targets --all-features -- -D warnings'):
            self.assertIn(required, text)
        self.assertNotIn('continue-on-error: true', text)


if __name__ == '__main__':
    unittest.main()
