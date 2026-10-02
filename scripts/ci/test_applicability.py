#!/usr/bin/env python3
"""Counterexamples to stale profiles and promoted navigation/CI evidence."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from check_applicability import ROOT, REGISTRY, validate, markdown
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

    def test_factor_and_public_queue_bind_real_tests_without_execution(self):
        result = validate(self.root)
        profiles = {p['id']: p for p in result['profiles']}
        self.assertEqual(profiles['integer-factor-v2']['consensus_revision'], 11)
        self.assertIsNone(profiles['public-intake-v3-r3']['consensus_revision'])
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
        self.assertEqual(len(row['evidence_selectors']), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
