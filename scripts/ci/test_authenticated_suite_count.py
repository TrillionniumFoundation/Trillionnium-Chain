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


def registry_fixtures():
    result = {}
    for crate, expected in REGISTRY_SHA256.items():
        raw = gzip.decompress((REGISTRY_EVIDENCE / f'{crate}-registry.log.gz').read_bytes())
        assert hashlib.sha256(raw).hexdigest() == expected, crate + ' native registry fixture changed'
        result[crate] = raw.decode()
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


class WorkspaceSemanticRegistry(unittest.TestCase):
    def test_actual_native_registry_passes_current_guard_and_rejects_stale_count(self):
        registries = registry_fixtures()
        result, selected = workspace_registry_check(registries)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['selected_count'], 60)
        self.assertEqual(len(selected.splitlines()), 60)
        self.assertEqual(len(set(selected.splitlines())), 60)
        self.assertEqual({group['group']: group['expected_count'] for group in report['groups']}, {
            'full-root-arithmetic': 5, 'unchanged-canonical-map': 6, 'account-root-digest': 3,
            'growth-return-observations': 2, 'canonical-ascii': 7, 'reorg-tail': 6,
            'direct-append-readback': 2, 'current-sql-root': 1,
            'prepared-current-history': 3, 'postwrite-readback': 25,
        })
        old, omitted = workspace_registry_check(registries, old=True)
        self.assertNotEqual(old.returncode, 0)
        self.assertIn('postwrite-readback: expected 23 actual registered controls, got 25', old.stderr)
        self.assertIsNone(omitted)

    def test_selected_postwrite_roster_matches_source_and_four_executed_native_logs(self):
        result, selected = workspace_registry_check(registry_fixtures())
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
