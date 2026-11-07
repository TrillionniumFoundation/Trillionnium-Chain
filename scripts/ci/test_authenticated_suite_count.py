#!/usr/bin/env python3
"""Replay historical guards and current guards with explicit synthetic inputs.

The four retained 97-test executions and native registries stay byte-for-byte
historical. New declarations extend only in-memory reader fixtures; a passing
fixture grants neither current ELF registration nor native execution evidence.
"""
from pathlib import Path
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from test_six_workpackage_native_rosters import source_fixture_extensions

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/pon-recent-batch-acceptance.yml'
EVIDENCE = ROOT / 'evidence/authenticated-suite-count-20261106'
JOBS = (127701926958, 127701927002, 127701927160, 127701927200)
PREFIX = 'store::native_authenticated::'
WORKSPACE_WORKFLOW = ROOT / '.github/workflows/pon-original-workspace-large-state-cpu.yml'
REGISTRY_EVIDENCE = ROOT / 'evidence/workspace-semantic-registry-20261106'
REGISTRY_SHA256 = {
    'm06': '2dde5653eb7086c89fbaea7a14855faa0d8891589354fdc0d34f48c2043a238b',
    'node': '357025f7f34769299392d01f26e33047f4b81d8e25594ef5158a474f47175865',
}
POSTWRITE_PREFIX = PREFIX + 'post_write_readback::tests::'


def workflow_guards():
    text = WORKFLOW.read_text()
    start = text.index('if test "$suite" = store::native_authenticated::; then\n              grep')
    section = text[start:text.index('          PYLOG', start)]
    grep = re.search(r"grep -E '([^']+)'", section)[1]
    code = textwrap.dedent(section.split("<<'PYLOG'\n", 1)[1])
    return grep, code


def check(log, old=False, historical=False):
    pattern, code = workflow_guards()
    if historical or old:
        pattern = pattern.replace('123 passed', '97 passed')
        code = (code.replace('123 passed', '97 passed').replace('!= 123', '!= 97')
                .replace('or observed_history != history', 'or observed_history != set()'))
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


def source_fixture_history():
    return source_fixture_extensions()['postwrite-history']


def source_fixture_log(job):
    """Synthetic positive reader input, not retained output from any process."""
    historical = fixture(job)
    names = source_fixture_history()
    assert len(names) == len(set(names)) == 26
    assert all(name not in historical for name in names)
    return ('SOURCE-ONLY SYNTHETIC READER FIXTURE; NOT NATIVE EXECUTION\n'
            + historical.replace('97 passed', '123 passed').replace('running 97 tests', 'running 123 tests')
            + ''.join(f'test {name} ... ok\n' for name in names))


def registry_fixtures():
    result = {}
    for crate, expected in REGISTRY_SHA256.items():
        raw = gzip.decompress((REGISTRY_EVIDENCE / f'{crate}-registry.log.gz').read_bytes())
        assert hashlib.sha256(raw).hexdigest() == expected, crate + ' native registry fixture changed'
        result[crate] = raw.decode()
    return result


def source_registry_fixtures():
    """Keep actual registry bytes separate from synthetic current declarations."""
    result = registry_fixtures()
    for crate, count in (('node', 60), ('m06', 3)):
        names = [name for group in source_fixture_extensions(crate).values() for name in group]
        assert len(names) == len(set(names)) == count
        assert all(name + ': test\n' not in result[crate] for name in names)
        result[crate] += ''.join(name + ': test\n' for name in names)
    return result


def workspace_registry_check(registries, old=False):
    workflow = WORKSPACE_WORKFLOW.read_text()
    code = textwrap.dedent(workflow.split("<<'PYREGISTRY'\n", 1)[1].split('        PYREGISTRY\n', 1)[0])
    if old:
        corrected = f'prefix("node", "postwrite-readback", "{POSTWRITE_PREFIX}", 25)'
        assert corrected in code
        code = code.replace(corrected, corrected.replace(', 25)', ', 23)'))
    with tempfile.TemporaryDirectory(prefix='workspace-registry-guard-') as directory:
        controls = Path(directory) / 'semantic-controls'
        controls.mkdir()
        for crate, text in registries.items():
            (controls / f'{crate}-registry.log').write_text(text)
        result = subprocess.run([sys.executable, '-B', '-c', code],
                                env=dict(os.environ, TRNM_CI_RECEIPT_DIR=directory),
                                capture_output=True, text=True)
        selected = controls / 'selected-tests.tsv'
        return result, selected.read_text() if selected.exists() else None


class AuthenticatedSuiteCount(unittest.TestCase):
    def test_all_four_original_logs_pass_both_corrected_guards_and_fail_old(self):
        for job in JOBS:
            with self.subTest(job=job):
                self.assertEqual(check(fixture(job), historical=True), (True, True))
                self.assertEqual(check(fixture(job), old=True), (False, False))
                self.assertEqual(check(fixture(job)), (False, False))
                self.assertEqual(check(source_fixture_log(job)), (True, True))

    def test_complete_roster_matches_source_owners_and_subgroups(self):
        store = ROOT / 'trillionnium/crates/trnm-pon-node/src/store'
        files = [store / 'native_authenticated.rs', store / 'native_fixed_blob_tests.rs']
        files += list((store / 'native_authenticated').rglob('*.rs'))
        source = [name for path in files for name in re.findall(
            r'#\[test\]\s*(?:#\[[^\]]+\]\s*)*fn (\w+)\(', path.read_text())]
        self.assertEqual(len(source), 123)
        for job in JOBS:
            names = re.findall(r'^test (store::native_authenticated::\w[\w:]*) \.\.\. ok$', fixture(job), re.M)
            self.assertEqual(len(names), 97)
            self.assertEqual(len(set(names)), 97)
            self.assertCountEqual(source, [name.rsplit('::', 1)[1]
                                           for name in names + source_fixture_history()])
            self.assertEqual(sum('::post_write_readback::tests::' in name for name in names), 25)
            self.assertEqual(sum('::current_accounts_tests::' in name for name in names), 5)

    def test_previous_118_names_cannot_claim_current_123_executions(self):
        # This is an explicitly synthetic reader input, never rewritten evidence.
        current = source_fixture_log(JOBS[0])
        state_names = [name for name in source_fixture_history()
                       if '::record_binding::state_binding::' in name]
        self.assertEqual(len(state_names), 5)
        previous = current
        for name in state_names:
            line = f'test {name} ... ok\n'
            self.assertEqual(previous.count(line), 1)
            previous = previous.replace(line, '', 1)
        previous = previous.replace('123 passed', '118 passed').replace(
            'running 123 tests', 'running 118 tests')
        self.assertEqual(len(re.findall(
            r'^test (store::native_authenticated::\w[\w:]*) \.\.\. ok$', previous, re.M)), 118)
        self.assertEqual(check(previous), (False, False))
        # A current-looking summary cannot supply the five absent executions.
        forged = previous.replace('118 passed', '123 passed').replace(
            'running 118 tests', 'running 123 tests')
        self.assertEqual(check(forged), (True, False))
        for name in state_names:
            with self.subTest(missing=name):
                changed = current.replace(f'test {name} ... ok\n',
                                          f'test {name}_substituted ... ok\n', 1)
                self.assertEqual(check(changed), (True, False))

    def test_missing_duplicate_wrong_group_and_current_identity_rejected(self):
        log = source_fixture_log(JOBS[0])
        names = re.findall(r'^test (store::native_authenticated::\w[\w:]*) \.\.\. ok$', log, re.M)
        first = f'test {names[0]} ... ok\n'
        for changed in (log.replace(first, '', 1), log + first,
                        log.replace('::post_write_readback::tests::', '::other::', 1),
                        log.replace('::current_accounts_tests::', '::other::', 1),
                        log.replace('::history_tests::', '::other::', 1)):
            with self.subTest(changed=changed[:60]):
                self.assertFalse(check(changed)[1])

    def test_reduced_extra_failed_ignored_partial_and_repeated_summary_rejected(self):
        log = fixture(JOBS[0])
        for old, new in [('97 passed', '91 passed'), ('97 passed', '96 passed'),
                         ('97 passed', '98 passed'), ('0 failed', '1 failed'),
                         ('0 ignored', '1 ignored'), ('result: ok.', 'result: FAILED.')]:
            with self.subTest(new=new):
                self.assertEqual(check(log.replace(old, new), historical=True), (False, False))
        summary = next(line for line in log.splitlines() if line.startswith('test result:'))
        self.assertEqual(check(log.replace(summary, ''), historical=True), (False, False))
        self.assertFalse(check(log + summary + '\n', historical=True)[1])
        log = source_fixture_log(JOBS[0])
        for old, new in [('123 passed', '97 passed'), ('123 passed', '122 passed'),
                         ('123 passed', '124 passed'), ('0 failed', '1 failed'),
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


class WorkspaceSemanticRegistry(unittest.TestCase):
    def test_actual_native_registry_passes_current_guard_and_rejects_stale_count(self):
        registries = registry_fixtures()
        result, selected = workspace_registry_check(registries)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('postwrite-history: expected 26 actual registered controls, got 0', result.stderr)
        self.assertIsNone(selected)
        registries = source_registry_fixtures()
        result, selected = workspace_registry_check(registries)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['selected_count'], 123)
        self.assertEqual(len(selected.splitlines()), 123)
        self.assertEqual(len(set(selected.splitlines())), 123)
        extensions = {**source_fixture_extensions(), **source_fixture_extensions('m06')}
        self.assertEqual({group['group']: group['expected_count'] for group in report['groups']
                          if group['group'] not in extensions}, {
            'full-root-arithmetic': 5, 'unchanged-canonical-map': 6, 'account-root-digest': 3,
            'growth-return-observations': 2, 'canonical-ascii': 7, 'reorg-tail': 6,
            'direct-append-readback': 2, 'current-sql-root': 1,
            'prepared-current-history': 3, 'postwrite-readback': 25,
        })
        for group in report['groups']:
            if group['group'] in extensions:
                self.assertCountEqual(group['tests'], extensions[group['group']])
                self.assertEqual(group['expected_count'], len(extensions[group['group']]))
        old, omitted = workspace_registry_check(registries, old=True)
        self.assertNotEqual(old.returncode, 0)
        self.assertIn('postwrite-readback: expected 23 actual registered controls, got 25', old.stderr)
        self.assertIsNone(omitted)

    def test_selected_postwrite_roster_matches_source_and_four_executed_native_logs(self):
        result, selected = workspace_registry_check(source_registry_fixtures())
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = [line.split('\t')[2] for line in selected.splitlines()
                    if line.split('\t')[1] == 'postwrite-readback']
        source = ROOT / 'trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback/tests.rs'
        expected = [POSTWRITE_PREFIX + name for name in re.findall(r'#\[test\]\s*fn (\w+)\(', source.read_text())]
        for path, module in re.findall(r'#\[path = "([^"]+)"\]\s*mod (\w+);', source.read_text()):
            expected += [POSTWRITE_PREFIX + module + '::' + name for name in
                         re.findall(r'#\[test\]\s*fn (\w+)\(', (source.parent / path).read_text())]
        self.assertEqual(len(expected), 25)
        self.assertCountEqual(observed, expected)
        for job in JOBS:
            executed = re.findall(r'^test (' + re.escape(POSTWRITE_PREFIX) + r'[\w:]+) \.\.\. ok$', fixture(job), re.M)
            self.assertCountEqual(observed, executed)

    def test_empty_missing_duplicate_extra_and_wrong_group_registries_rejected(self):
        registries = source_registry_fixtures()
        line = next(line + '\n' for line in registries['node'].splitlines()
                    if line.startswith(POSTWRITE_PREFIX))
        for label, node in (
                ('empty', ''), ('missing', registries['node'].replace(line, '', 1)),
                ('duplicate', registries['node'] + line),
                ('extra', registries['node'] + POSTWRITE_PREFIX + 'unexpected_control: test\n'),
                ('wrong-group', registries['node'].replace(line, line.replace(POSTWRITE_PREFIX, 'other::'), 1))):
            with self.subTest(label=label):
                result, selected = workspace_registry_check(dict(registries, node=node))
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(selected)

    def test_missing_exact_control_in_each_crate_rejected(self):
        registries = source_registry_fixtures()
        for crate, name in (
                ('m06', 'pon_commitment::unchanged_snapshot_tests::unchanged_snapshot_shares_only_after_full_actual_bytes_match'),
                ('node', 'store::append_readback_tests::direct_append_keeps_complete_rows_events_state_and_cold_reopen')):
            with self.subTest(crate=crate):
                changed = dict(registries)
                changed[crate] = changed[crate].replace(name + ': test\n', '', 1)
                result, selected = workspace_registry_check(changed)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('missing exact control:', result.stderr)
                self.assertIsNone(selected)

    def test_every_source_fixture_group_is_required_without_promoting_historical_execution(self):
        registries = source_registry_fixtures()
        for crate in ('node', 'm06'):
            for group, names in source_fixture_extensions(crate).items():
                with self.subTest(crate=crate, group=group):
                    changed = dict(registries)
                    changed[crate] = changed[crate].replace(names[0] + ': test\n', '', 1)
                    result, selected = workspace_registry_check(changed)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIsNone(selected)

    def test_original_build_and_execution_contract_remains_required(self):
        text = WORKSPACE_WORKFLOW.read_text()
        for required in ('python3 scripts/ci/test_authenticated_suite_count.py',
                         '--workspace", "--all-targets", "--all-features",',
                         '--no-run", "--message-format=json"',
                         '"$binary" --list --format terse',
                         '"$binary" "$selector" --exact --nocapture --test-threads=1',
                         'check_required_native_test.py" "$log" --test "$selector"',
                         'if [ "$index" -eq 0 ] || [ "$index" -ne "$expected_count" ]; then status=1; fi',
                         'timeout-minutes: 180', "CARGO_BUILD_JOBS: '2'"):
            self.assertIn(required, text)
        self.assertNotIn('continue-on-error: true', text)


if __name__ == '__main__':
    unittest.main()
