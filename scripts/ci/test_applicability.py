#!/usr/bin/env python3
"""Counterexamples to stale profiles and promoted navigation/CI evidence."""
import ast
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from check_applicability import (
    ROOT, REGISTRY, NATIVE_STORAGE_ENTRY, NATIVE_STORAGE_PROFILE, NATIVE_STORAGE_TESTS,
    validate, markdown, profile_table,
)
from report_module_evidence import check_test_selector


class ApplicabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pon-applicability-')
        cls.root = Path(cls.temp.name) / 'source'
        shutil.copytree(ROOT, cls.root, ignore=shutil.ignore_patterns(
            '.git', 'target', '__pycache__', '.pytest_cache', 'node_modules'))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def reject(self, change, path=REGISTRY):
        p = self.root / path
        raw = p.read_bytes()
        try:
            data = json.loads(raw)
            change(data)
            p.write_text(json.dumps(data))
            with self.assertRaises((ValueError, KeyError)):
                validate(self.root)
        finally:
            p.write_bytes(raw)

    def test_current_table_binds_all_procedures_without_execution(self):
        result = validate(self.root)
        self.assertEqual(len(result['procedures']), 39)
        self.assertEqual({r['module'] for r in result['procedures']}, {f'M{i:02}' for i in range(18)})
        self.assertFalse(result['tests_executed_by_this_checker'])
        self.assertFalse(result['acceptance_granted'])
        self.assertIn('M05.ReconsiderAfterReorg', markdown(result))

    def test_wrong_profile_revision_rejects(self):
        self.reject(lambda d: d['profiles'][3].update(consensus_revision=8))

    def test_missing_profile_rejects(self):
        self.reject(lambda d: d['profiles'].pop())

    def test_duplicate_profile_rejects(self):
        self.reject(lambda d: d['profiles'].append(d['profiles'][0]))

    def test_missing_doc_rejects(self):
        self.reject(lambda d: d['profiles'][0].update(document='docs/missing.md'))

    def test_missing_entry_rejects(self):
        self.reject(lambda d: d['profiles'][0]['entrypoint'].update(symbol='not_an_entry'))

    def test_source_binding_cannot_be_promoted_to_measurement(self):
        self.reject(lambda d: d['profiles'][0].update(evidence_class='local-execution'))

    def test_source_binding_cannot_invent_receipt(self):
        self.reject(lambda d: d['profiles'][0].update(receipt='current-head-pass'))

    def test_claimed_ci_pass_rejects(self):
        self.reject(lambda d: d['delivery'].update(hosted_head_status='PASS'))

    def test_claimed_merge_pass_rejects(self):
        self.reject(lambda d: d['delivery'].update(prospective_merge_status='PASS'))

    def test_stale_snapshot_package_count_rejects(self):
        self.reject(lambda d: d.update(workspace_packages=24), 'docs/development/CURRENT_SNAPSHOT_V1.json')

    def test_local_policy_cannot_claim_consensus_revision(self):
        self.reject(lambda d: d['profiles'][-1].update(consensus_revision=10))

    def reject_native_profile_with_current_table(self, change, message):
        """Regenerating navigation must not conceal a changed storage contract."""
        registry = self.root / REGISTRY
        authority = self.root / 'docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md'
        original_registry, original_authority = registry.read_bytes(), authority.read_bytes()
        try:
            data = json.loads(original_registry)
            profile = next(p for p in data['profiles'] if p['id'] == NATIVE_STORAGE_PROFILE)
            change(profile, data)
            registry.write_text(json.dumps(data))
            start, end = '<!-- applicability-table:start -->', '<!-- applicability-table:end -->'
            before, rest = original_authority.decode().split(start, 1)
            _, after = rest.split(end, 1)
            authority.write_text(before + start + '\n' + profile_table(data['profiles']) +
                                 '\n' + end + after)
            with self.assertRaisesRegex(ValueError, message):
                validate(self.root)
        finally:
            registry.write_bytes(original_registry)
            authority.write_bytes(original_authority)

    def test_native_authenticated_profile_is_explicit_local_source_navigation(self):
        result = validate(self.root)
        self.assertEqual(len(result['profiles']), 18)
        profile = next(p for p in result['profiles'] if p['id'] == NATIVE_STORAGE_PROFILE)
        self.assertEqual(profile['entrypoint'], NATIVE_STORAGE_ENTRY)
        for field in ('configuration', 'revision_pointer', 'consensus_revision', 'receipt'):
            self.assertIsNone(profile[field])
        self.assertEqual(profile['evidence_class'], 'source-binding')
        for path, symbols in NATIVE_STORAGE_TESTS.items():
            self.assertTrue({path + '::' + symbol for symbol in symbols} <= set(profile['tests']))
        self.assertFalse(result['acceptance_granted'])
        self.assertFalse(result['tests_executed_by_this_checker'])

    def test_native_profile_cannot_reuse_existing_consensus_configuration(self):
        def change(profile, data):
            configured = next(p for p in data['profiles'] if p['configuration'] is not None)
            for field in ('configuration', 'revision_pointer', 'consensus_revision'):
                profile[field] = configured[field]
        self.reject_native_profile_with_current_table(change, 'storage is local')

    def test_native_profile_cannot_substitute_valid_legacy_opener(self):
        self.reject_native_profile_with_current_table(
            lambda p, _: p['entrypoint'].update(symbol='Node::open'), 'explicit opener')

    def test_native_profile_requires_cli_migration_and_independent_storage_controls(self):
        for path in NATIVE_STORAGE_TESTS:
            with self.subTest(path=path):
                self.reject_native_profile_with_current_table(
                    lambda p, _, path=path: p.update(
                        tests=[s for s in p['tests'] if not s.startswith(path + '::')]),
                    'control selector coverage')

    def test_native_profile_cannot_substitute_standalone_archive_document(self):
        self.reject_native_profile_with_current_table(
            lambda p, _: p.update(document=
                'docs/protocol/pon-nakamoto-v1/details/AUTHENTICATED_STATE_ARCHIVE_V1.md'),
            'contract identity')

    def test_native_profile_retains_storage_recovery_and_evidence_owners(self):
        self.reject_native_profile_with_current_table(
            lambda p, _: p['modules'].remove('M08'), 'responsibility coverage')

    def test_duplicate_profile_controls_do_not_count_as_additional_coverage(self):
        self.reject_native_profile_with_current_table(
            lambda p, _: p['tests'].append(p['tests'][0]), 'duplicate profile test')

    def test_compact_rejection_and_storage_python_controls_bind_every_real_test(self):
        rows = validate(self.root)['procedures']
        row = next(r for r in rows if r['operation'] == 'M17.QualifyExecutedCampaign')
        selectors = set(row['evidence_selectors'])
        for path, count in [
            ('formal/pon-nakamoto-v1/test_account_multiproof_oracle.py', 28),
            ('formal/pon-nakamoto-v1/test_native_authenticated_storage_oracle.py', 28),
            ('formal/pon-nakamoto-v1/test_obligation_range_oracle.py', 13),
            ('scripts/ci/test_work_rejection_report.py', 75),
        ]:
            tree = ast.parse((self.root / path).read_text())
            expected = {path + '::' + cls.name + '.' + method.name
                        for cls in tree.body if isinstance(cls, ast.ClassDef)
                        for method in cls.body if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and method.name.startswith('test_')}
            self.assertEqual(len(expected), count, path)
            self.assertTrue(expected <= selectors, path)
        for path, symbol in [
            ('formal/pon-nakamoto-v1/native_authenticated_storage_oracle.py', 'compare_migration'),
            ('formal/pon-nakamoto-v1/account_multiproof_oracle.py', 'root_for_updates'),
            ('formal/pon-nakamoto-v1/obligation_range_oracle.py', 'check_observation'),
            ('formal/pon-nakamoto-v1/obligation_range_oracle.py', 'native_negative_controls'),
            ('scripts/pon_work_rejection_report.py', 'verify'),
        ]:
            self.assertIn({'path': path, 'symbol': symbol}, row['runtime_symbols'])
        self.assertIsNone(row['ordinary_product_entrypoint'])

    def test_factor_and_public_queue_bind_real_tests_without_execution(self):
        result = validate(self.root)
        profiles = {p['id']: p for p in result['profiles']}
        self.assertEqual(profiles['integer-factor-v2']['consensus_revision'], 11)
        self.assertIsNone(profiles['public-intake-v3-r9']['consensus_revision'])
        row = next(r for r in result['procedures']
                   if r['operation'] == 'M10.SubmitFactorContribution')
        self.assertEqual(len(row['evidence_selectors']), 4)
        self.assertEqual(row['evidence_class'], 'source-binding')
        self.assertFalse(result['tests_executed_by_this_checker'])
        self.assertFalse(result['acceptance_granted'])

    def test_helper_is_not_a_test_even_when_callable(self):
        with self.assertRaises(ValueError):
            check_test_selector(self.root, 'trillionnium/crates/trnm-pon-node/tests/local_mempool.rs::signature')

    def test_commented_or_string_literal_test_is_not_executable(self):
        path = self.root / 'fake_test.rs'
        try:
            for text in ['// #[test]\n// fn test_fake() {}',
                         '/* outer /* inner */ #[test] fn test_fake() {} */',
                         'const S: &str = r#"#[test] fn test_fake() {}"#;']:
                path.write_text(text)
                with self.assertRaises(ValueError):
                    check_test_selector(self.root, 'fake_test.rs::test_fake')
        finally:
            path.unlink(missing_ok=True)

    def test_stale_documented_profile_revision_rejects(self):
        path = self.root / 'docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md'
        original = path.read_text()
        try:
            path.write_text(original.replace(', revision9', ', revision8'))
            with self.assertRaisesRegex(ValueError, 'table drift'):
                validate(self.root)
        finally:
            path.write_text(original)

    def test_native_m06_execution_and_delta_name_actual_node_owner(self):
        rows = validate(self.root)['procedures']
        for operation in ['M06.ExecuteCandidate', 'M06.DeriveBranchDelta']:
            row = next(r for r in rows if r['operation'] == operation)
            self.assertEqual(row['controlled_entrypoint']['symbol'], 'Node::admit')
            self.assertEqual(row['persistence_owner']['symbol'], 'Node::open')
            self.assertIsNone(row['ordinary_product_entrypoint'])
            self.assertTrue(any('derived_commitment.rs::' in t for t in row['evidence_selectors']))

    def test_native_m05_reconciliation_is_explicit_not_ordinary_product(self):
        rows = validate(self.root)['procedures']
        row = next(r for r in rows if r['operation'] == 'M05.ReconsiderAfterReorg')
        self.assertEqual(row['controlled_entrypoint']['symbol'], 'Node::pool_status')
        self.assertEqual(row['runtime_symbols'][0]['symbol'], 'Node::pool_reconcile')
        self.assertIsNone(row['ordinary_product_entrypoint'])
        self.assertEqual(set(row['evidence_selectors']), {
            'trillionnium/crates/trnm-pon-node/tests/local_mempool.rs::queued_facts_reopen_exact_raws_real_typed_gate_and_funding_nonce_dependencies',
            'trillionnium/crates/trnm-pon-node/tests/local_mempool.rs::retained_groups_restore_after_real_heavier_fork_and_terminal_prune_is_monotonic',
            'trillionnium/crates/trnm-pon-node/src/store/mempool.rs::native_reconcile_and_submission_apply_each_retained_transaction_once_per_operation',
            'trillionnium/crates/trnm-pon-node/src/store/mempool.rs::signature_cache_survives_cancellation_and_unwind_without_publishing_suffix',
        })


if __name__ == '__main__':
    unittest.main(verbosity=2)
