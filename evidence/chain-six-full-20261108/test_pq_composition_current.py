"""Small, actual-log mutation controls for the current composition parser."""
from __future__ import annotations

import ast
import gzip
import hashlib
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location(
    'current_pq_composition', HERE / 'run_pq_composition_current.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
ADDED_IDS = {
    '__main__.TestClaimGuard.test_explicit_false_null_and_nested_hold_claims_stay_unqualified',
    '__main__.TestClaimGuard.test_reserved_boolean_alias_requires_exact_false',
    '__main__.TestClaimGuard.test_reserved_numeric_alias_requires_null_even_for_zero',
    '__main__.TestClaimGuard.test_reserved_numeric_claims_refused_in_every_claim_document',
    '__main__.TestClaimGuard.test_reserved_promotions_cannot_hide_in_nested_mappings_or_lists',
    '__main__.TestClaimGuard.test_reserved_true_claims_refused_in_every_claim_document',
}


class CurrentCompositionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        actual = (HERE / 'claim-tests-f2.stderr.txt').read_bytes()
        assert hashlib.sha256(actual).hexdigest() == '30d70900e35d735a2ece7be26771d3e8be928b3ed26cf751e111905d0302d2eb'
        old_dir = ROOT / 'evidence/pq-seven-layer-composition-20261108'
        old = gzip.decompress((old_dir / 'committed-source-1d29818/claim-tests.stderr.txt.gz').read_bytes())
        assert hashlib.sha256(old).hexdigest() == 'ea166eb3bd7c75fe30e13076ed29cd1de620730d5ba80a28818197fddbbffd31'
        cls.actual, cls.old = actual.decode(), old.decode()
        cls.source = ROOT / 'scripts/ci/test_pq_chain_claim_guard.py'
        cls.source_bytes = cls.source.read_bytes()
        assert len(cls.source_bytes) == 28476
        assert hashlib.sha256(cls.source_bytes).hexdigest() == '5a3c2e0d15dbfed68cb7afcc0c7f88a6b5c8620823ea7257e0dc5ef2be570a6f'
        cls.pin = RUNNER.digest(cls.source)
        cls.first, cls.second = cls.actual.splitlines(keepends=True)[:2]
        cls.historical_runner = (old_dir / 'run_validation.py').read_bytes()
        assert hashlib.sha256(cls.historical_runner).hexdigest() == '080dc1c54fb7f9a9990fcdcbdb83baf74e7065ab78c32534f65e8717990ce638'

    def validate(self, text=None, *, stdout='', code=0, before=None, after=None):
        return RUNNER.validate_current_claim_run(
            stdout, self.actual if text is None else text, code,
            self.pin if before is None else before,
            self.pin if after is None else after,
        )

    def refused(self, text=None, **kwargs):
        self.assertTrue(self.validate()['passed'], 'untouched actual log must first pass')
        result = self.validate(text, **kwargs)
        self.assertFalse(result['passed'], result)
        self.assertTrue(result['errors'])
        return result

    def test_actual_f2_log_is_a_parser_fixture_with_all_55_names(self):
        result = self.validate()
        self.assertTrue(result['passed'], result)
        self.assertEqual(result['reported_count'], 55)
        self.assertEqual(result['distinct_count'], 55)
        self.assertEqual(len(result['records']), 55)
        self.assertTrue(all(item['status'] == 'ok' for item in result['records']))

    def test_original_49_are_retained_and_only_six_reviewed_source_controls_are_added(self):
        pattern = r'^test_\w+ \((__main__\.\w+\.test_\w+)\) \.\.\. ok$'
        old_ids = re.findall(pattern, self.old, re.M)
        actual_ids = re.findall(pattern, self.actual, re.M)
        self.assertEqual(len(old_ids), len(set(old_ids)))
        self.assertEqual(len(old_ids), 49)
        self.assertLess(set(old_ids), set(actual_ids))
        self.assertEqual(set(actual_ids) - set(old_ids), ADDED_IDS)
        self.assertEqual(tuple(actual_ids), RUNNER.CURRENT_CLAIM_TEST_IDS)
        classes = {node.name: node for node in ast.parse(self.source_bytes).body
                   if isinstance(node, ast.ClassDef)}

        def members(name):
            cls = classes[name]
            own = {node.name for node in cls.body if isinstance(node, ast.FunctionDef)
                   and node.name.startswith('test_')}
            for base in cls.bases:
                if isinstance(base, ast.Name) and base.id in classes:
                    own |= members(base.id)
            return own

        source_ids = {'__main__.' + cls + '.' + method
                      for cls in ('ClaimReaderRaceTests', 'TestClaimGuard')
                      for method in members(cls)}
        self.assertEqual(source_ids, set(actual_ids))

    def test_historical_49_only_success_is_refused(self):
        result = self.refused(self.old)
        self.assertEqual(result['reported_count'], 49)
        self.assertEqual(set(result['missing_ids']), ADDED_IDS)

    def test_missing_unknown_or_mismatched_name_is_refused(self):
        for changed in (
            self.actual.replace(self.first, '', 1),
            self.actual.replace(self.first, self.first.replace('ClaimReaderRaceTests', 'UnknownTests'), 1),
            self.actual.replace(self.first, self.first.replace('test_checkout_', 'test_unreviewed_', 1), 1),
        ):
            with self.subTest(changed_first_line=changed.splitlines()[0]):
                self.refused(changed)

    def test_duplicate_names_cannot_replace_a_missing_name_or_inflate_count(self):
        for changed in (
            self.actual.replace(self.first, self.second, 1),
            self.first + self.actual,
        ):
            with self.subTest(length=len(changed)):
                result = self.refused(changed)
                self.assertTrue(result['duplicate_ids'])

    def test_skips_failures_and_expected_failures_cannot_be_laundered_by_ok(self):
        for status in ('skipped \'disabled\'', 'expected failure', 'unexpected success',
                       'FAIL', 'ERROR', 'ok (skipped=1)', 'ok trailing text'):
            with self.subTest(status=status):
                changed = self.actual.replace(self.first, self.first.replace('... ok', '... ' + status), 1)
                self.refused(changed)

    def test_fake_or_duplicate_success_summary_cannot_replace_actual_records(self):
        for changed in (
            'Ran 55 tests in 0.001s\n\nOK\n',
            self.actual.replace('Ran 55 tests', 'Ran 49 tests'),
            self.actual.replace('Ran 55 tests', 'Ran 0 tests'),
            self.actual.replace('\nOK\n', '\nOK (skipped=1)\n'),
            self.actual + 'OK\n',
            self.actual + 'FAILED (failures=1)\n',
            'Traceback (most recent call last):\n' + self.actual,
        ):
            with self.subTest(length=len(changed)):
                self.refused(changed)
        self.refused(stdout='OK\n')
        self.refused(code=1)

    def test_actual_source_byte_drift_before_or_after_execution_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / 'scripts/ci/test_pq_chain_claim_guard.py'
            source.parent.mkdir(parents=True)
            source.write_bytes(self.source_bytes)
            before = RUNNER.claim_source_snapshot(root)
            self.assertEqual(before, self.pin)
            source.write_bytes(self.source_bytes + b'\n# real byte drift\n')
            after = RUNNER.claim_source_snapshot(root)
            self.refused(before=after)
            self.refused(before=before, after=after)
            source.unlink()
            self.refused(after=RUNNER.claim_source_snapshot(root))

    def test_all_29_original_commands_timeout_and_source_gates_are_unchanged(self):
        original = ast.parse(self.historical_runner)
        current = ast.parse((HERE / 'run_pq_composition_current.py').read_bytes())

        def contracts(tree):
            main = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'main')
            selected, count = [], 0
            for node in ast.walk(main):
                if isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id in
                    ('py', 'guard', 'commands', 'cargo', 'manifest', 'common')
                    for target in node.targets
                ):
                    selected.append(ast.dump(node))
                    if any(isinstance(target, ast.Name) and target.id == 'commands'
                           for target in node.targets):
                        count += len(node.value.elts)
                elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == 'commands':
                    selected.append(ast.dump(node))
                    count += len(node.value.elts)
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'commands' and node.func.attr == 'append':
                        selected.append(ast.dump(node))
                        count += 1
                    elif isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess' and node.func.attr == 'run':
                        selected.append(ast.dump(node))
                        self.assertIn(ast.dump(ast.keyword(arg='timeout', value=ast.Constant(value=1200))), ast.dump(node))
                elif isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and 'preflight' in ast.dump(node.test):
                    selected.append(ast.dump(node))
            return sorted(selected), count

        self.assertEqual(contracts(original), contracts(current))
        self.assertEqual(contracts(current)[1], 29)


if __name__ == '__main__':
    unittest.main()
