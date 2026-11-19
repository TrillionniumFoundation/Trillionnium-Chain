#!/usr/bin/env python3
"""Replay the actual workflow guards; not a new native execution."""
import ast
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
CURRENT_EVIDENCE = ROOT / 'evidence/chain-native-owned-append-20261119-2e9b/controls'
CURRENT_ROSTER = ROOT / 'config/pon/authenticated-current-roster-v1.json'
CURRENT_ROSTER_SHA256 = '1e98393ca0a366d99714bd3e4c813b078afa4be6f450888ca47a4882234950fa'
CURRENT_NATIVE_SHA256 = '83ca708525ff68f8bfa67db329b769507f109f78ca5db832e8580e9c692dc371'
CURRENT_REGISTRY_SHA256 = '53145dd409aa99a75cab15fa96e66a102ccc19f731f2b016ae62e29cdeab3559'
HISTORICAL_REGISTRY_GUARD_SHA256 = '2e6f389f8c25f8b3298979a58ce3eda54980439a2dda4342427f7a6b51f8859e'


def current_roster():
    raw = CURRENT_ROSTER.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CURRENT_ROSTER_SHA256
    value = json.loads(raw)
    assert set(value) == {'schema', 'tests'}
    assert value['schema'] == 'trnm-authenticated-current-roster-v1'
    names = value['tests']
    assert names == sorted(set(names)) and len(names) == 133
    assert sum(name.startswith(POSTWRITE_PREFIX) for name in names) == 55
    return names


def current_native_fixture():
    raw = gzip.decompress((CURRENT_EVIDENCE / 'native-authenticated.log.gz').read_bytes())
    assert hashlib.sha256(raw).hexdigest() == CURRENT_NATIVE_SHA256
    return raw.decode()

LEGACY_TAIL_PREFIX = PREFIX + 'history_arithmetic::legacy_activation_tail::tests::'
LEGACY_TAIL_CONTROLS = {
    LEGACY_TAIL_PREFIX + 'disabled_paths_do_not_read_diagnostic_clocks',
    LEGACY_TAIL_PREFIX + 'known_boundaries_and_completed_prefix_are_fixed_and_relative',
    LEGACY_TAIL_PREFIX + 'missing_reversed_overflow_and_cross_thread_clocks_remain_unknown',
    LEGACY_TAIL_PREFIX + 'unwinding_retains_prefix_without_error_or_panic_payload',
    LEGACY_TAIL_PREFIX + 'completion_counts_do_not_reset_and_overflow_is_null',
    LEGACY_TAIL_PREFIX + 'unavailable_accounting_does_not_replace_native_results',
}

# Frozen verbatim from the c3e53d2 workflow. These four observations established
# the historical 97-control roster; they cannot establish the current 133.
HISTORICAL_LOG_SHA256 = {
    127701926958: '244f253489f52e62e8985323ca2041de293039981b1c2bd86f1ddab6a5f0e692',
    127701927002: 'e51a5d58671626c3d6e48b4e908a18724da393de0bcedd7c1d1ffeece2a4dc62',
    127701927160: '466c1fa743cf135ef9f1b92d4a0dd1dde971f2e9e5d34976e52345aaaaa1586f',
    127701927200: '5b8bc65500824b156b70359a53879864f1023fe52570612bbb9f89878569a5c9',
}
HISTORICAL_GREP = r'^test result: ok\. 97 passed; 0 failed; 0 ignored;'
HISTORICAL_INLINE = r"""import re, sys
from pathlib import Path
lines = Path(sys.argv[1]).read_text().splitlines()
names = [m[1] for line in lines if (m := re.fullmatch(r'test (store::native_authenticated::[A-Za-z0-9_:]+) \.\.\. ok', line))]
summaries = [line for line in lines if line.startswith('test result:')]
post_write = [name for name in names if name.startswith('store::native_authenticated::post_write_readback::tests::')]
current_accounts = {
    'store::native_authenticated::current_accounts_tests::cold_complete_reuses_actual_account_parse_and_keeps_all_graph_checkpoints',
    'store::native_authenticated::current_accounts_tests::current_projection_is_bound_to_exact_state_and_never_hides_account_changes',
    'store::native_authenticated::current_accounts_tests::current_projection_preserves_complete_root_and_late_error_priority',
    'store::native_authenticated::current_accounts_tests::current_projection_rereads_corrupt_sql_and_preserves_every_cancellation',
    'store::native_authenticated::current_accounts_tests::cold_full_validation_projection_abba_observation_without_timing_gate',
}
observed_current = {name for name in names if name.startswith('store::native_authenticated::current_accounts_tests::')}
if (len(names) != 97 or len(set(names)) != 97 or len(post_write) != 25
        or observed_current != current_accounts
        or len(summaries) != 1 or not summaries[0].startswith('test result: ok. 97 passed; 0 failed; 0 ignored;')):
    raise SystemExit('current authenticated module requires 72 non-post-write and 25 post-write executions, including all five current-account controls, in one log')
"""
HISTORICAL_GUARD_SHA256 = '5a904c2a6eb22c9b38f1853b599a83ea6194488173ca90a423b67a2883d2b007'


def workflow_guards(historical=False):
    if historical:
        return HISTORICAL_GREP, HISTORICAL_INLINE
    text = WORKFLOW.read_text()
    start = text.index('if test "$suite" = store::native_authenticated::; then\n              grep')
    section = text[start:text.index('          PYLOG', start)]
    grep = re.search(r"grep -E '([^']+)'", section)[1]
    code = textwrap.dedent(section.split("<<'PYLOG'\n", 1)[1])
    return grep, code


def check(log, old=False, historical=False):
    pattern, code = workflow_guards(historical=historical)
    if old:
        assert historical, 'the 91-control comparison is historical only'
        pattern = pattern.replace('97 passed', '91 passed')
        code = code.replace('97 passed', '91 passed').replace('!= 97', '!= 91').replace('!= 25', '!= 23')
    grep = subprocess.run(['grep', '-E', pattern], input=log, text=True, capture_output=True)
    with tempfile.TemporaryDirectory(prefix='auth-suite-guard-') as directory:
        path = Path(directory) / 'native.log'
        path.write_text(log)
        inline = subprocess.run([sys.executable, '-B', '-c', code, str(path)], cwd=ROOT, capture_output=True)
    return grep.returncode == 0, inline.returncode == 0


def fixture(job):
    raw = gzip.decompress((EVIDENCE / f'{job}.txt.gz').read_bytes())
    assert hashlib.sha256(raw).hexdigest() == HISTORICAL_LOG_SHA256[job], \
        'original 97-control native log changed'
    return raw.decode()


def synthetic_current_parser_control():
    """Parser input only: it is not a native observation or execution receipt."""
    return ('SYNTHETIC READER CONTROL ONLY; no native execution\n'
            + ''.join(f'test {name} ... ok\n' for name in current_roster())
            + 'test result: ok. 133 passed; 0 failed; 0 ignored; 0 measured; '
              '0 filtered out; finished in 0.00s\n')


def registry_fixtures(historical=False):
    result = {}
    for crate, expected in REGISTRY_SHA256.items():
        raw = gzip.decompress((REGISTRY_EVIDENCE / f'{crate}-registry.log.gz').read_bytes())
        assert hashlib.sha256(raw).hexdigest() == expected, crate + ' native registry fixture changed'
        result[crate] = raw.decode()
    if not historical:
        # Current node registry is an actual default-feature release libtest
        # observation; the unchanged m06 fixture remains explicitly historical.
        # Neither is a complete current workspace execution qualification.
        raw = gzip.decompress((CURRENT_EVIDENCE / 'node-registry.log.gz').read_bytes())
        assert hashlib.sha256(raw).hexdigest() == CURRENT_REGISTRY_SHA256
        result['node'] = raw.decode()
    return result


def workspace_registry_check(registries, old=False, historical=False):
    workflow = WORKSPACE_WORKFLOW.read_text()
    code = textwrap.dedent(workflow.split("<<'PYREGISTRY'\n", 1)[1].split('        PYREGISTRY\n', 1)[0])
    current = f'prefix("node", "postwrite-readback", "{POSTWRITE_PREFIX}", 55)'
    assert current in code
    if historical:
        code = code.replace(current, current.replace(', 55)', ', 25)'))
        assert hashlib.sha256(code.encode()).hexdigest() == HISTORICAL_REGISTRY_GUARD_SHA256
    if old:
        count = 25 if historical else 55
        wanted = 23 if historical else 25
        corrected = f'prefix("node", "postwrite-readback", "{POSTWRITE_PREFIX}", {count})'
        assert corrected in code
        code = code.replace(corrected, corrected.replace(f', {count})', f', {wanted})'))
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
                self.assertEqual(check(fixture(job), old=True, historical=True), (False, False))

    def test_complete_roster_matches_source_owners_and_subgroups(self):
        store = ROOT / 'trillionnium/crates/trnm-pon-node/src/store'
        files = [store / 'native_authenticated.rs', store / 'native_fixed_blob_tests.rs']
        files += list((store / 'native_authenticated').rglob('*.rs'))
        owned = {path: re.findall(r'#\[test\]\s*(?:#\[[^\]]+\]\s*)*fn (\w+)\(',
                                 path.read_text()) for path in files}
        source = [name for names in owned.values() for name in names]
        current = current_roster()
        self.assertEqual(len(source), 133)
        self.assertCountEqual(source, [name.rsplit('::', 1)[1] for name in current])
        tail = store / 'native_authenticated/history_arithmetic/legacy_activation_tail/tests.rs'
        self.assertCountEqual([LEGACY_TAIL_PREFIX + name for name in owned[tail]],
                              LEGACY_TAIL_CONTROLS)
        executed = re.findall(r'^test (store::native_authenticated::\w[\w:]*) \.\.\. ok$',
                              current_native_fixture(), re.M)
        self.assertCountEqual(current, executed)
        self.assertEqual(check(current_native_fixture()), (True, True))
        for job in JOBS:
            names = re.findall(r'^test (store::native_authenticated::\w[\w:]*) \.\.\. ok$', fixture(job), re.M)
            self.assertEqual(len(names), 97)
            self.assertEqual(len(set(names)), 97)
            self.assertTrue(set(names) < set(current))
            self.assertEqual(len(set(current) - set(names)), 36)
            self.assertEqual(sum('::post_write_readback::tests::' in name for name in names), 25)
            self.assertEqual(sum('::current_accounts_tests::' in name for name in names), 5)

    def test_missing_duplicate_wrong_group_and_current_identity_rejected(self):
        for log, historical in ((fixture(JOBS[0]), True),
                                (synthetic_current_parser_control(), False)):
            self.assertEqual(check(log, historical=historical), (True, True))
            names = re.findall(r'^test (store::native_authenticated::\w[\w:]*) \.\.\. ok$', log, re.M)
            first = f'test {names[0]} ... ok\n'
            for changed in (log.replace(first, '', 1), log + first,
                            log.replace('::post_write_readback::tests::', '::other::', 1),
                            log.replace('::current_accounts_tests::', '::other::', 1)):
                with self.subTest(historical=historical, changed=changed[:60]):
                    self.assertNotEqual(changed, log)
                    self.assertFalse(check(changed, historical=historical)[1])

    def test_reduced_extra_failed_ignored_partial_and_repeated_summary_rejected(self):
        for log, historical, count in ((fixture(JOBS[0]), True, 97),
                                       (synthetic_current_parser_control(), False, 133)):
            changes = [(f'{count} passed', f'{value} passed')
                       for value in (count - 6, count - 1, count + 1)]
            changes += [('0 failed', '1 failed'), ('0 ignored', '1 ignored'),
                        ('result: ok.', 'result: FAILED.')]
            for old, new in changes:
                with self.subTest(historical=historical, new=new):
                    changed = log.replace(old, new)
                    self.assertNotEqual(changed, log)
                    self.assertEqual(check(changed, historical=historical), (False, False))
            summary = next(line for line in log.splitlines() if line.startswith('test result:'))
            self.assertEqual(check(log.replace(summary, ''), historical=historical), (False, False))
            self.assertFalse(check(log + summary + '\n', historical=historical)[1])

    def test_historical_guard_stays_frozen(self):
        pattern, code = workflow_guards(historical=True)
        self.assertEqual(hashlib.sha256((pattern + '\0' + code).encode()).hexdigest(),
                         HISTORICAL_GUARD_SHA256)
        self.assertEqual(set(HISTORICAL_LOG_SHA256), set(JOBS))

    def test_current_guard_requires_current_roster_and_refuses_historical_qualification(self):
        current = synthetic_current_parser_control()
        self.assertEqual(check(current), (True, True))
        self.assertEqual(check(current, historical=True), (False, False))
        for job in JOBS:
            with self.subTest(job=job):
                self.assertEqual(check(fixture(job)), (False, False))

    def test_each_new_control_must_be_unique_named_and_successful(self):
        log = synthetic_current_parser_control()
        self.assertEqual(check(log), (True, True))
        historical = set(re.findall(r'^test (store::native_authenticated::\w[\w:]*) \.\.\. ok$',
                                    fixture(JOBS[0]), re.M))
        added = set(current_roster()) - historical
        self.assertEqual(len(added), 36)
        for name in added:
            line = f'test {name} ... ok\n'
            duplicate = next(other for other in added if other != name)
            changes = {
                'missing': log.replace(line, '', 1),
                'extra-duplicate': log + line,
                'same-count-duplicate': log.replace(line, f'test {duplicate} ... ok\n', 1),
                'substitute': log.replace(line, f'test {LEGACY_TAIL_PREFIX}unexpected_control ... ok\n', 1),
                'wrong-group': log.replace(line, line.replace(PREFIX, PREFIX + 'other::'), 1),
                'failed': log.replace(line, line.replace(' ... ok', ' ... FAILED'), 1),
                'ignored': log.replace(line, line.replace(' ... ok', ' ... ignored'), 1),
            }
            for label, changed in changes.items():
                with self.subTest(control=name, change=label):
                    self.assertNotEqual(changed, log)
                    self.assertFalse(check(changed)[1])

    def test_original_execution_and_downstream_requirements_unchanged(self):
        text = WORKFLOW.read_text()
        for required in ('options+=(--include-ignored)', 'set -euo pipefail',
                         '-- "${options[@]}" --show-output --test-threads=1',
                         '--test continuity_authenticated --test authenticated_storage_cli',
                         '--all-targets --all-features -- -D warnings'):
            self.assertIn(required, text)
        self.assertNotIn('continue-on-error: true', text)


class WorkspaceSemanticRegistry(unittest.TestCase):
    def test_previous_127_control_observation_is_retained_and_not_current(self):
        old = ROOT / 'evidence/chain-native-operation-readback-20261119-2e9b/controls'
        raw = gzip.decompress((old / 'native-authenticated.log.gz').read_bytes())
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         '38ef82773e04943365b8a16fbe420fdb345fc493ed1a4e5ae20c2b2055cd77e9')
        self.assertIn('test result: ok. 127 passed; 0 failed; 0 ignored;', raw.decode())
        self.assertEqual(check(raw.decode()), (False, False))
        registry = gzip.decompress((old / 'node-registry.log.gz').read_bytes())
        self.assertEqual(hashlib.sha256(registry).hexdigest(),
                         '2e3c2c5a355fe61d1358e4c9b591d1b0cf868a63a8d45ea857fac4225540f4e4')
        registries = registry_fixtures()
        registries['node'] = registry.decode()
        result, selected = workspace_registry_check(registries)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('postwrite-readback: expected 55 actual registered controls, got 49', result.stderr)
        self.assertIsNone(selected)

    def test_actual_current_node_registry_selects_all_current_controls(self):
        registries = registry_fixtures()
        result, selected = workspace_registry_check(registries)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['selected_count'], 90)
        self.assertEqual(len(selected.splitlines()), 90)
        self.assertEqual(len(set(selected.splitlines())), 90)
        self.assertEqual({group['group']: group['expected_count'] for group in report['groups']}, {
            'full-root-arithmetic': 5, 'unchanged-canonical-map': 6, 'account-root-digest': 3,
            'growth-return-observations': 2, 'canonical-ascii': 7, 'reorg-tail': 6,
            'direct-append-readback': 2, 'current-sql-root': 1,
            'prepared-current-history': 3, 'postwrite-readback': 55,
        })
        old, omitted = workspace_registry_check(registries, old=True)
        self.assertNotEqual(old.returncode, 0)
        self.assertIn('postwrite-readback: expected 25 actual registered controls, got 55', old.stderr)
        self.assertIsNone(omitted)

    def test_historical_registry_and_four_logs_keep_their_original_25_controls(self):
        registries = registry_fixtures(historical=True)
        result, selected = workspace_registry_check(registries, historical=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['selected_count'], 60)
        observed = [line.split('\t')[2] for line in selected.splitlines()
                    if line.split('\t')[1] == 'postwrite-readback']
        self.assertEqual(len(observed), 25)
        for job in JOBS:
            executed = re.findall(r'^test (' + re.escape(POSTWRITE_PREFIX) + r'[\w:]+) \.\.\. ok$', fixture(job), re.M)
            self.assertCountEqual(observed, executed)
        old, omitted = workspace_registry_check(registries, old=True, historical=True)
        self.assertNotEqual(old.returncode, 0)
        self.assertIn('postwrite-readback: expected 23 actual registered controls, got 25', old.stderr)
        self.assertIsNone(omitted)
        current, omitted = workspace_registry_check(registries)
        self.assertNotEqual(current.returncode, 0)
        self.assertIn('postwrite-readback: expected 55 actual registered controls, got 25', current.stderr)
        self.assertIsNone(omitted)

    def test_current_postwrite_roster_matches_source_and_current_native_log(self):
        result, selected = workspace_registry_check(registry_fixtures())
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = [line.split('\t')[2] for line in selected.splitlines()
                    if line.split('\t')[1] == 'postwrite-readback']
        source = ROOT / 'trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback/tests.rs'
        visited = set()
        def declared_tests(path, prefix):
            # Follow only the real declared module edges, including nested controls.
            self.assertTrue(path.is_relative_to(source.parent))
            self.assertNotIn(path, visited)
            visited.add(path)
            text = path.read_text()
            names = [prefix + name for name in re.findall(r'#\[test\]\s*fn (\w+)\(', text)]
            for child, module in re.findall(r'#\[path = "([^"]+)"\]\s*mod (\w+);', text):
                names += declared_tests((path.parent / child).resolve(), prefix + module + '::')
            return names
        expected = declared_tests(source, POSTWRITE_PREFIX)
        self.assertEqual(len(expected), 55)
        self.assertCountEqual(observed, expected)
        self.assertCountEqual(expected, [name for name in current_roster()
                                        if name.startswith(POSTWRITE_PREFIX)])
        executed = re.findall(r'^test (' + re.escape(POSTWRITE_PREFIX) + r'[\w:]+) \.\.\. ok$',
                              current_native_fixture(), re.M)
        self.assertCountEqual(observed, executed)

    def test_empty_missing_duplicate_extra_and_wrong_group_registries_rejected(self):
        registries = registry_fixtures()
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
        registries = registry_fixtures()
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


WORKSPACE_FEATURE_WORKFLOWS = (
    (WORKSPACE_WORKFLOW, False),
    (ROOT / '.github/workflows/pon-legacy-reorg-cost-20261104.yml', True),
)
WORKSPACE_EXPECTED_FEATURES = {
    'trnm-pon-node': ['default', 'pq-native-openssl', 'pq-root-v3'],
    'trnm-mvcc-fee': ['default', 'pq-native-openssl'],
}


def workspace_artifact_code(path):
    bodies = re.findall(
        r"(?ms)<<'PYART'\n(.*?)^[ \t]*PYART[ \t]*$",
        path.read_text(),
    )
    if len(bodies) != 1:
        raise ValueError('workspace feature guard: expected exactly one PYART block')
    return textwrap.dedent(bodies[0])


def workspace_feature_contract(tree, has_ancestry):
    """Inspect the real workflow's fixed map and directly executed assertions."""
    def require(condition, message):
        if not condition:
            raise ValueError('workspace feature guard: ' + message)

    def same(left, right):
        return ast.dump(left, include_attributes=False) == ast.dump(
            right, include_attributes=False)

    assignments = [
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == 'expected_features'
    ]
    require(len(assignments) == 1, 'one top-level expected_features declaration')
    assignment = assignments[0]
    require(isinstance(assignment.value, ast.Dict)
            and len(assignment.value.keys) == len(WORKSPACE_EXPECTED_FEATURES),
            'explicit two-crate literal map without duplicate declarations')
    expected = ast.literal_eval(assignment.value)
    require(expected == WORKSPACE_EXPECTED_FEATURES,
            'reviewed exact per-crate feature lists')

    loop_target = ast.parse(
        'for crate, target, opt in (): pass').body[0].target
    loops = [
        node for node in tree.body
        if isinstance(node, ast.For) and same(node.target, loop_target)
    ]
    require(len(loops) == 1, 'one top-level complete-workspace artifact loop')
    outer = loops[0]
    require(ast.literal_eval(outer.iter) == (
        ('trnm-pon-node', 'trnm_pon_node', '3'),
        ('trnm-mvcc-fee', 'trnm_mvcc_fee', '1'),
    ), 'both original crate targets and optimization levels')
    require(tree.body.index(assignment) < tree.body.index(outer),
            'fixed map declared before artifact validation')

    artifact_loops = [
        node for node in outer.body
        if isinstance(node, ast.For)
        and isinstance(node.target, ast.Name)
        and node.target.id == 'artifact'
        and isinstance(node.iter, ast.Name)
        and node.iter.id == 'artifacts'
    ]
    require(len(artifact_loops) == 1, 'direct loop over every selected artifact')

    def direct_assert(body, expression):
        expected_test = ast.parse(expression, mode='eval').body
        matches = [
            node for node in body
            if isinstance(node, ast.Assert) and same(node.test, expected_test)
        ]
        require(len(matches) == 1,
                'direct exact feature assertion: ' + expression)
        return matches[0]

    guards = {
        'library': direct_assert(
            artifact_loops[0].body,
            'artifact["features"] == expected_features[crate]',
        ),
    }
    if has_ancestry:
        guards['ancestry'] = direct_assert(
            tree.body,
            'ancestry_artifact["features"] == expected_features["trnm-pon-node"]',
        )

    last = tree.body[-1]
    require(isinstance(last, ast.Expr)
            and isinstance(last.value, ast.Call)
            and isinstance(last.value.func, ast.Name)
            and last.value.func.id == 'print',
            'final artifact report remains printed')
    report_refs = [
        value
        for node in ast.walk(last)
        if isinstance(node, ast.Dict)
        for key, value in zip(node.keys, node.values)
        if isinstance(key, ast.Constant) and key.value == 'features_by_crate'
    ]
    require(len(report_refs) == 1
            and isinstance(report_refs[0], ast.Name)
            and report_refs[0].id == 'expected_features',
            'report exposes the same exact per-crate map')
    allowed_refs = [assignment.targets[0], report_refs[0]]
    allowed_refs += [guard.test.comparators[0].value for guard in guards.values()]
    actual_refs = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == 'expected_features'
    ]
    require({id(node) for node in actual_refs}
            == {id(node) for node in allowed_refs},
            'fixed map cannot be rebound or otherwise reused')
    return expected, guards


def run_workspace_feature_assertion(guard, expected, crate, features):
    """Execute only the extracted, structurally checked real assertion."""
    module = ast.fix_missing_locations(ast.Module(body=[guard], type_ignores=[]))
    code = compile(module, '<actual workflow feature assertion>', 'exec',
                   dont_inherit=True, optimize=0)
    exec(code, {
        '__builtins__': {},
        'expected_features': expected,
        'crate': crate,
        'artifact': {'features': list(features)},
        'ancestry_artifact': {'features': list(features)},
    })


class WorkspaceArtifactFeatures(unittest.TestCase):
    def test_exact_per_crate_features_pass_actual_workflow_assertions(self):
        for path, has_ancestry in WORKSPACE_FEATURE_WORKFLOWS:
            expected, guards = workspace_feature_contract(
                ast.parse(workspace_artifact_code(path)), has_ancestry)
            cases = [(crate, 'library') for crate in WORKSPACE_EXPECTED_FEATURES]
            if has_ancestry:
                cases.append(('trnm-pon-node', 'ancestry'))
            for crate, kind in cases:
                with self.subTest(workflow=path.name, crate=crate, kind=kind):
                    run_workspace_feature_assertion(
                        guards[kind], expected, crate, WORKSPACE_EXPECTED_FEATURES[crate])

    def test_missing_extra_cross_crate_and_duplicate_features_are_rejected(self):
        for path, has_ancestry in WORKSPACE_FEATURE_WORKFLOWS:
            expected, guards = workspace_feature_contract(
                ast.parse(workspace_artifact_code(path)), has_ancestry)
            cases = [(crate, 'library') for crate in WORKSPACE_EXPECTED_FEATURES]
            if has_ancestry:
                cases.append(('trnm-pon-node', 'ancestry'))
            for crate, kind in cases:
                features = WORKSPACE_EXPECTED_FEATURES[crate]
                other = next(name for name in WORKSPACE_EXPECTED_FEATURES if name != crate)
                changes = [
                    ('missing ' + feature, features[:index] + features[index + 1:])
                    for index, feature in enumerate(features)
                ]
                changes += [
                    ('extra', features + ['unexpected-feature']),
                    ('cross-crate', WORKSPACE_EXPECTED_FEATURES[other]),
                    ('duplicate', features + [features[0]]),
                ]
                for label, changed in changes:
                    with self.subTest(workflow=path.name, crate=crate,
                                      kind=kind, change=label):
                        with self.assertRaises(AssertionError):
                            run_workspace_feature_assertion(
                                guards[kind], expected, crate, changed)

    def test_subset_set_equality_and_disabled_guards_are_rejected(self):
        for path, has_ancestry in WORKSPACE_FEATURE_WORKFLOWS:
            source = workspace_artifact_code(path)
            _, initial = workspace_feature_contract(ast.parse(source), has_ancestry)
            for kind in initial:
                actual = ('artifact["features"]' if kind == 'library'
                          else 'ancestry_artifact["features"]')
                wanted = ('expected_features[crate]' if kind == 'library'
                          else 'expected_features["trnm-pon-node"]')
                for replacement in (f'set({actual}).issubset({wanted})',
                                    f'set({actual}) <= set({wanted})',
                                    f'set({actual}) == set({wanted})', 'True'):
                    tree = ast.parse(source)
                    _, guards = workspace_feature_contract(tree, has_ancestry)
                    guards[kind].test = ast.parse(replacement, mode='eval').body
                    with self.subTest(workflow=path.name, kind=kind,
                                      replacement=replacement):
                        with self.assertRaisesRegex(ValueError, 'direct exact feature assertion'):
                            workspace_feature_contract(tree, has_ancestry)

    def test_exact_assertions_cannot_move_under_a_skipping_condition(self):
        for path, has_ancestry in WORKSPACE_FEATURE_WORKFLOWS:
            source = workspace_artifact_code(path)
            _, initial = workspace_feature_contract(ast.parse(source), has_ancestry)
            for kind in initial:
                tree = ast.parse(source)
                _, guards = workspace_feature_contract(tree, has_ancestry)
                guard = guards[kind]
                owners = [node.body for node in ast.walk(tree)
                          if isinstance(getattr(node, 'body', None), list)
                          and guard in node.body]
                self.assertEqual(len(owners), 1)
                body = owners[0]
                body[body.index(guard)] = ast.If(
                    test=ast.Constant(value=False), body=[guard], orelse=[])
                with self.subTest(workflow=path.name, kind=kind):
                    with self.assertRaisesRegex(ValueError, 'direct exact feature assertion'):
                        workspace_feature_contract(tree, has_ancestry)

    def test_expected_map_cannot_silently_follow_changed_features(self):
        for path, has_ancestry in WORKSPACE_FEATURE_WORKFLOWS:
            source = workspace_artifact_code(path)
            for crate in WORKSPACE_EXPECTED_FEATURES:
                changed = {name: list(features)
                           for name, features in WORKSPACE_EXPECTED_FEATURES.items()}
                changed[crate].append('unexpected-feature')
                tree = ast.parse(source)
                declaration = next(node for node in tree.body
                                   if isinstance(node, ast.Assign)
                                   and len(node.targets) == 1
                                   and isinstance(node.targets[0], ast.Name)
                                   and node.targets[0].id == 'expected_features')
                declaration.value = ast.parse(repr(changed), mode='eval').body
                with self.subTest(workflow=path.name, crate=crate):
                    with self.assertRaisesRegex(ValueError, 'reviewed exact per-crate feature lists'):
                        workspace_feature_contract(tree, has_ancestry)


if __name__ == '__main__':
    unittest.main()
