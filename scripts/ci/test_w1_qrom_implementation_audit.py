#!/usr/bin/env python3
"""Fixed-source and actual saved-v2 metadata controls, not fresh proof trials."""
from __future__ import annotations

from contextlib import redirect_stderr
import copy
import io
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import w1_qrom_implementation_audit_v2 as audit
import w1_qrom_implementation_audit as historical_audit
import w1_control_tree_audit as control
import w1_profile_source_map as profile


class ImplementationAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract, _ = audit.load_contract(audit.ROOT)
        cls.assets = audit.load_pinned_files(audit.ROOT, cls.contract['saved_v2_files'])
        row = cls.contract['upstream_snapshot']
        snapshot = audit.load_pinned_files(audit.ROOT, [row])[row['path']]
        cls.sources, _ = audit.load_snapshot(snapshot, audit.UPSTREAM)
        cls.tree = control.audit_sources(cls.sources)
        cls.branch = cls.tree['final_join']['merkle_path']

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def copy_contract_inputs(self):
        paths = [audit.CONTRACT, self.contract['upstream_snapshot']['path']]
        paths += [row['path'] for row in self.contract['project_files'] + self.contract['saved_v2_files']
                  + self.contract['audit_helpers'] + self.contract['historical_inputs']]
        for relative in paths:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(audit.ROOT / relative, target)

    def changed_receipt(self, offset, data):
        assets = dict(self.assets)
        receipt = bytearray(assets[audit.FIXTURE + 'succinct.bin'])
        receipt[offset:offset + len(data)] = data
        assets[audit.FIXTURE + 'succinct.bin'] = bytes(receipt)
        return assets

    def test_actual_saved_v2_mapping_keeps_all_security_claims_unqualified(self):
        report = audit.build_report(audit.ROOT)
        self.assertEqual(report['schema'], 'TRNM-W1-QROM-IMPLEMENTATION-AUDIT2')
        self.assertEqual(report['result'], 'MAPPING_REPRODUCED_SECURITY_HOLD')
        self.assertEqual(report['qualification'], audit.QUALIFICATION)
        self.assertEqual(report['saved_v2']['historical_rv32im_segments'], 43)
        self.assertEqual(report['saved_v2']['outer_recursion_seal_po2_raw'], 18)
        self.assertTrue(report['saved_v2']['control_inclusion_matches_reconstructed_tree'])
        self.assertFalse(report['saved_v2']['fresh_cryptographic_verification'])
        self.assertFalse(report['saved_v2']['guest_elf_to_image_recomputed'])
        self.assertEqual(report['control_scope']['allowed_lift_po2_max'], 22)
        self.assertEqual(report['control_scope']['named_default_inner_programs'], 27)
        self.assertEqual(report['control_scope']['padding_leaf_count'], 229)
        self.assertFalse(report['control_scope']['padding_digest_has_no_accepting_code_proved'])
        self.assertEqual(report['control_scope']['generic_outer_verifier_explicit_po2_max'], 24)
        self.assertIsNone(report['field']['uniform_bit_oracle_sigma_justified'])
        self.assertTrue(all(v is None for k, v in report['lifetime_budget'].items() if k != 'policy_adopted'))
        self.assertTrue(all(row['state'] == 'UNRESOLVED' for row in report['open_obligations']))

    def test_changed_native_source_is_refused_before_mapping(self):
        self.copy_contract_inputs()
        for path in sorted(audit.CHANGED_PATHS | {
                'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs'}):
            target = self.root / path
            original = target.read_bytes()
            changed = bytearray(original)
            changed[100] ^= 1
            target.write_bytes(changed)
            with self.assertRaisesRegex(audit.AuditError, 'pinned input drift'):
                audit.build_report(self.root)
            target.write_bytes(original)

    def test_changed_audit_helper_is_refused_before_execution(self):
        self.copy_contract_inputs()
        for row in self.contract['audit_helpers']:
            target = self.root / row['path']
            original = target.read_bytes()
            target.write_bytes(original + b'\n# changed helper\n')
            with self.assertRaisesRegex(audit.AuditError, 'input exceeds bound|pinned input drift'):
                audit.build_report(self.root)
            target.write_bytes(original)

    def test_import_cache_and_search_path_cannot_replace_checked_helper_bytes(self):
        self.copy_contract_inputs()
        with mock.patch.object(profile, 'extract_stark_parameters', return_value={'QUERIES': 1}), \
                mock.patch.object(control, 'audit_sources', side_effect=AssertionError('wrong import')), \
                mock.patch.object(historical_audit, 'inspect_v2', side_effect=AssertionError('wrong engine')):
            report = audit.build_report(self.root)
        self.assertEqual(report['stark_parameters']['QUERIES'], 50)
        self.assertEqual(report['control_tree']['root'], audit.CONTROL_ROOT)
        self.assertEqual(report['helper_execution']['sources'], self.contract['audit_helpers'])
        self.assertFalse(report['helper_execution']['upstream_source_executed'])

    def test_version_two_transition_preserves_exact_historical_projection_and_unknowns(self):
        report = audit.build_report(audit.ROOT)
        scope = report['source_review']
        self.assertEqual(scope['changed_paths'], sorted(audit.CHANGED_PATHS))
        self.assertEqual(scope['selected_project_file_count'], 16)
        self.assertEqual(scope['unchanged_project_file_count'], 14)
        self.assertTrue(scope['historical_route_byte_projection_reproduced'])
        self.assertTrue(scope['historical_semantic_report_fields_reproduced'])
        for key in ('new_native_once_route_qualified', 'funded_service_decoder_qualified',
                    'whole_source_and_build_equivalence_proved'):
            self.assertIs(scope[key], False)
        inputs = audit.load_pinned_files(audit.ROOT, self.contract['historical_inputs'])
        review = audit.strict_json(inputs[audit.SOURCE_REVIEW])
        project = audit.load_pinned_files(audit.ROOT, self.contract['project_files'])
        for path in sorted(audit.CHANGED_PATHS):
            mutated = dict(project)
            data = bytearray(mutated[path])
            data[0] ^= 1  # The preserved part cannot drift behind unchanged review metadata.
            mutated[path] = bytes(data)
            with self.assertRaisesRegex(audit.AuditError, 'historical source projection differs'):
                audit.verify_reviewed_source_projection(mutated, review)

        inspect = audit.inspect_v2
        for key, value in (('fresh_cryptographic_verification', 0),
                           ('control_inclusion_matches_reconstructed_tree', 1),
                           ('outer_recursion_seal_po2_raw', 18.0)):
            def producer_regression(*args, key=key, value=value):
                observed = inspect(*args)
                observed[key] = value
                return observed
            with self.subTest(historical_json_type=key), \
                    mock.patch.object(audit, 'inspect_v2', side_effect=producer_regression), \
                    self.assertRaisesRegex(audit.AuditError, 'historical semantic mapping fields changed'):
                audit.build_report(audit.ROOT)

    def test_historical_engine_contract_report_and_review_remain_immutable_inputs(self):
        self.copy_contract_inputs()
        for row in self.contract['historical_inputs']:
            target = self.root / row['path']
            original = target.read_bytes()
            mutated = bytearray(original)
            mutated[len(mutated) // 2] ^= 1
            target.write_bytes(mutated)
            with self.assertRaisesRegex(audit.AuditError,
                                        'pinned input drift|unsupported implementation contract'):
                audit.build_report(self.root)
            target.write_bytes(original)

    def test_version_one_contract_still_refuses_the_changed_sources(self):
        self.assertEqual(historical_audit.CONTRACT,
                         'config/pon/w1-qrom-implementation-v1.json')
        self.assertEqual(audit.sha((audit.ROOT / audit.ENGINE).read_bytes()), audit.ENGINE_SHA256)
        with self.assertRaisesRegex(historical_audit.AuditError,
                                    'input exceeds bound|pinned input drift'):
            historical_audit.build_report(audit.ROOT)

    def test_changed_seal_word_is_rejected_by_full_artifact_identity(self):
        self.copy_contract_inputs()
        target = self.root / (audit.FIXTURE + 'succinct.bin')
        data = bytearray(target.read_bytes())
        data[12000] ^= 1
        target.write_bytes(data)
        with self.assertRaisesRegex(audit.AuditError, 'pinned input drift'):
            audit.build_report(self.root)

    def test_contract_cannot_promote_unknown_quantum_budget_or_qualification(self):
        self.copy_contract_inputs()
        for section, key, value in [('qualification', 'post_quantum_soundness_qualified', True),
                                    ('lifetime_budget', 'quantum_queries_lifetime', 0)]:
            changed = copy.deepcopy(self.contract)
            changed[section][key] = value
            (self.root / audit.CONTRACT).write_text(json.dumps(changed))
            with self.assertRaisesRegex(audit.AuditError, 'unsupported implementation contract'):
                audit.load_contract(self.root)

    def test_changed_source_snapshot_is_refused(self):
        self.copy_contract_inputs()
        target = self.root / self.contract['upstream_snapshot']['path']
        data = bytearray(target.read_bytes())
        data[len(data) // 2] ^= 1
        target.write_bytes(data)
        with self.assertRaisesRegex(audit.AuditError, 'pinned input drift'):
            audit.build_report(self.root)

    def test_parent_directory_symlink_is_refused(self):
        (self.root / 'config').symlink_to(audit.ROOT / 'config', target_is_directory=True)
        with self.assertRaisesRegex(audit.AuditError, 'symlink input'):
            audit.load_contract(self.root)

    def test_duplicate_keys_and_nonfinite_numbers_are_refused(self):
        for data in [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}']:
            with self.assertRaises(audit.AuditError):
                audit.strict_json(data)

    def test_external_commitment_substitution_is_refused(self):
        assets = dict(self.assets)
        assets[audit.FIXTURE + 'expected-artifacts.bin'] = b'\0' * 64
        with self.assertRaisesRegex(audit.AuditError, 'original raw matrix commitments'):
            audit.inspect_v2(assets, self.branch)

    def test_inner_and_outer_parameter_fields_are_separate_controls(self):
        receipt = self.assets[audit.FIXTURE + 'succinct.bin']
        at = receipt.index(struct.pack('<Q', 9) + b'poseidon2') + 17
        for offset, message in [(at, 'inner parameter'), (len(receipt) - 32, 'outer metadata')]:
            assets = self.changed_receipt(offset, bytes([receipt[offset] ^ 1]))
            with self.assertRaisesRegex(audit.AuditError, message):
                audit.inspect_v2(assets, self.branch)

    def test_real_control_inclusion_sibling_change_is_refused(self):
        receipt = self.assets[audit.FIXTURE + 'succinct.bin']
        at = receipt.index(struct.pack('<Q', 9) + b'poseidon2') + 17 + 32 + 12
        assets = self.changed_receipt(at, bytes([receipt[at] ^ 1]))
        with self.assertRaisesRegex(audit.AuditError, 'independently reconstructed tree'):
            audit.inspect_v2(assets, self.branch)

    def test_control_index_high_bits_are_refused(self):
        receipt = self.assets[audit.FIXTURE + 'succinct.bin']
        at = receipt.index(struct.pack('<Q', 9) + b'poseidon2') + 17 + 32
        assets = self.changed_receipt(at, struct.pack('<I', 257))
        with self.assertRaisesRegex(audit.AuditError, 'canonical join control branch'):
            audit.inspect_v2(assets, self.branch)

    def test_zero_seal_and_foreign_receipt_kind_are_refused(self):
        for offset, value in [(4, struct.pack('<Q', 0)), (0, struct.pack('<I', 2))]:
            with self.assertRaisesRegex(audit.AuditError, 'succinct seal framing'):
                audit.inspect_v2(self.changed_receipt(offset, value), self.branch)

    def test_fixed_receipt_trailing_data_is_refused(self):
        assets = dict(self.assets)
        assets[audit.FIXTURE + 'succinct.bin'] += b'\0'
        with self.assertRaises(audit.AuditError):
            audit.inspect_v2(assets, self.branch)

    def test_raw_po2_must_not_be_montgomery_decoded(self):
        assets = self.changed_receipt(12 + 32 * 4, struct.pack('<I', 18 * (1 << 32) % audit.P))
        with self.assertRaisesRegex(audit.AuditError, 'outer recursion trace po2'):
            audit.inspect_v2(assets, self.branch)

    def test_false_historical_guest_identity_is_refused(self):
        assets = dict(self.assets)
        history = audit.strict_json(assets[audit.FIXTURE + 'proof-result.json'])
        history['manifest']['guest_sha256'] = '0' * 64
        assets[audit.FIXTURE + 'proof-result.json'] = json.dumps(history).encode()
        with self.assertRaisesRegex(audit.AuditError, 'historical guest bytes'):
            audit.inspect_v2(assets, self.branch)

    def test_existing_output_is_not_replaced(self):
        output = self.root / 'keep.json'
        output.write_text('original evidence\n')
        with mock.patch.object(sys, 'argv', ['audit', '--output', str(output)]), \
                mock.patch.object(audit, 'build_report', return_value={'result': 'fixture-only'}), \
                redirect_stderr(io.StringIO()):
            self.assertEqual(audit.main(), 2)
        self.assertEqual(output.read_text(), 'original evidence\n')

    def test_fri_schedule_does_not_treat_boolean_as_po2(self):
        for value in [True, -1, 25]:
            with self.assertRaises(audit.AuditError):
                audit.fri_schedule(value)
        self.assertEqual(len(audit.fri_schedule(18)['folding_rounds']), 3)
        self.assertEqual(audit.fri_schedule(18)['final_coefficients_extension'], 64)
        self.assertEqual(len(audit.fri_schedule(22)['folding_rounds']), 4)


if __name__ == '__main__':
    unittest.main()
