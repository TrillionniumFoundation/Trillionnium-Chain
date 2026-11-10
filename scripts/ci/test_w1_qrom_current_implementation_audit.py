#!/usr/bin/env python3
"""Current mapping/source consistency controls; no native security qualification."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import w1_qrom_current_implementation_audit as current


class CurrentImplementationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit, cls.contract, cls.contract_raw = current.load_current(current.ROOT)
        cls.report = current.build_report(current.ROOT)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def copy_inputs(self):
        rows = self.contract['project_files'] + self.contract['audit_helpers']
        rows += self.contract['saved_v2_files'] + self.contract['local_path_closure']['files']
        rows += [self.contract['upstream_snapshot'], self.contract['historical_contract'],
                 self.contract['historical_reader']]
        for name in {row['path'] for row in rows} | {current.CONTRACT}:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(current.ROOT / name, target)

    def test_current_mapping_reaches_the_original_complete_saved_fixture(self):
        report = self.report
        self.assertEqual(report['result'], 'CURRENT_MAPPING_REPRODUCED_SECURITY_HOLD')
        self.assertEqual(report['qualification'], self.audit.QUALIFICATION)
        self.assertEqual(report['saved_v2']['historical_rv32im_segments'], 43)
        self.assertEqual(report['saved_v2']['outer_recursion_seal_po2_raw'], 18)
        self.assertTrue(report['saved_v2']['control_inclusion_matches_reconstructed_tree'])
        self.assertFalse(report['saved_v2']['fresh_cryptographic_verification'])
        self.assertFalse(report['saved_v2']['guest_elf_to_image_recomputed'])

    def test_fixed_parameters_and_fri_mapping_are_preserved(self):
        self.assertEqual(self.report['control_tree']['root'], self.audit.CONTROL_ROOT)
        self.assertEqual(self.report['parameter_digest_independently_recomputed'], self.audit.PARAMETERS)
        self.assertEqual(self.report['stark_parameters']['QUERIES'], 50)
        self.assertEqual(len(self.report['fri_schedules']), 25)
        self.assertEqual(self.report['field']['extension_degree'], 4)
        self.assertIsNone(self.report['field']['uniform_bit_oracle_sigma_justified'])

    def test_all_lifetime_and_cryptographic_obligations_remain_unknown(self):
        self.assertTrue(all(row['state'] == 'UNRESOLVED' for row in self.report['open_obligations']))
        self.assertTrue(all(value is None for key, value in self.report['lifetime_budget'].items()
                            if key != 'policy_adopted'))
        self.assertFalse(self.report['lifetime_budget']['policy_adopted'])
        for key in ('native_binary_executed', 'whole_repository_source_verified',
                    'third_party_source_closure_verified', 'provider_build_identity_verified',
                    'fresh_cryptographic_verification', 'git_commit_ancestry_verified'):
            self.assertIs(self.report[key], False)

    def test_old_contract_and_its_failure_remain_visible(self):
        historical = self.report['historical_v1']
        self.assertEqual(historical['result'], 'INPUT_REJECTED')
        self.assertFalse(historical['workflow_passed'])
        self.assertFalse(historical['named_roster_completed'])
        self.assertEqual(historical['reader_sha256'], current.LEGACY_READER_SHA256)
        with self.assertRaisesRegex(self.audit.AuditError, 'input exceeds bound'):
            self.audit.build_report(current.ROOT)
        for relative, expected in (
            ('evidence/pon-w1-qrom-current-20261110-685a/historical/current-v2.json', '846efa5cedfb811ae8255a5b3d5c0223e6e89180a89c9670e7bcb9204cbbed30'),
            ('evidence/pon-w1-qrom-current-20261110-685a/historical/current-auditor.py', '42f55e68fef753d4c63ca1749a2031d5b80e4184f9e4e316c7dd267dcdaa095f'),
            ('evidence/pon-w1-qrom-current-20261110-685a/historical/current-tests.py', '9e87e202e839e498008f4b8178379de2553bfc7bb8da0ca91df853e6a8886909'),
            ('evidence/pon-w1-qrom-current-20261110-685a/historical/current-mapping.md.txt', 'b072b80b628c83d501e9289f04a7c7287f5a35e98a56c6adc398e7667154b299'),
        ):
            self.assertEqual(hashlib.sha256((current.ROOT / relative).read_bytes()).hexdigest(), expected)
        prior = json.loads((current.ROOT / 'evidence/pon-w1-qrom-current-20261110-685a/historical/current-v2.json').read_bytes())
        self.assertEqual(prior['source_base_commit'], '189b9b5959d836ef6ae96e14fb285948e4920aa9')
        self.assertEqual(len(prior['local_path_closure']['files']), 137)

    def test_all_six_local_crates_and_literal_inputs_are_bound(self):
        result = self.report['local_path_closure']
        self.assertEqual(result['source_files_checked'], 138)
        self.assertTrue(result['source_before_after_equal'])
        manifests = set(self.contract['local_path_closure']['entry_manifests'])
        manifests.update(row['target'] for row in result['path_edges'])
        self.assertEqual(len(manifests), 6)
        names = {row['path'] for row in result['files']}
        self.assertIn('trillionnium/crates/trnm-protocol/src/funded_service_task_v1.rs', names)
        self.assertIn('trillionnium/crates/trnm-protocol/src/pon_wire/state_root_arithmetic.rs', names)
        self.assertIn('config/pon/work-profile-v1.json', names)
        self.assertIn('trillionnium/crates/trnm-crypto-primitives/examples/pon_fresh_rejection_cost.rs', names)
        self.assertEqual(self.report['source_base_commit'], '8d8c0e64e7a301fc111a6720721a14816639e5aa')
        for path in ('src/pq_root_v3.rs', 'src/pq_root_v3/tests.rs', 'tests/pq_root_v3_native.rs'):
            self.assertIn('trillionnium/crates/trnm-crypto-primitives/' + path, names)
        self.assertEqual(len(result['literal_include_files']), 8)

    def test_unlisted_rust_file_is_not_silently_accepted(self):
        self.copy_inputs()
        path = self.root / 'trillionnium/crates/trnm-protocol/src/unreviewed.rs'
        path.write_text('// additional ordinary module requires review\n')
        with self.assertRaisesRegex(current.AuditError, 'Rust source inventory differs'):
            current.build_report(self.root)
        path.unlink()
        # Omitting the reviewed example from a caller-supplied closure
        # still fails the complete inventory check independently of the
        # descriptor digest check; no examples directory is exempt.
        omitted = json.loads(self.contract_raw)
        omitted['local_path_closure']['files'] = [
            row for row in omitted['local_path_closure']['files']
            if row['path'] != 'trillionnium/crates/trnm-crypto-primitives/examples/pon_fresh_rejection_cost.rs']
        with self.assertRaisesRegex(current.AuditError, 'local Rust source inventory differs'):
            current.local_closure(self.root, omitted)

    def test_missing_funded_source_is_refused(self):
        self.copy_inputs()
        for relative in ('trillionnium/crates/trnm-protocol/src/funded_service_task_v1.rs',
                         'trillionnium/crates/trnm-crypto-primitives/examples/pon_fresh_rejection_cost.rs'):
            with self.subTest(missing_source=relative):
                self.copy_inputs()
                (self.root / relative).unlink()
                with self.assertRaises(OSError):
                    current.build_report(self.root)

    def test_local_path_manifest_change_requires_review(self):
        self.copy_inputs()
        path = self.root / 'formal/pon-nakamoto-v1/w1_zkvm/relation/Cargo.toml'
        raw = path.read_bytes()
        path.write_bytes(raw.replace(b'0.1.0', b'0.1.1', 1))
        with self.assertRaisesRegex(current.AuditError, 'current source pin differs'):
            current.build_report(self.root)

    def test_included_work_profile_change_requires_review(self):
        self.copy_inputs()
        path = self.root / 'config/pon/work-profile-v1.json'
        raw = path.read_bytes()
        path.write_bytes(raw.replace(b' ', b'\t', 1))
        with self.assertRaisesRegex(current.AuditError, 'current source pin differs'):
            current.build_report(self.root)

    def test_new_local_build_script_requires_review(self):
        self.copy_inputs()
        path = self.root / 'trillionnium/crates/trnm-protocol/build.rs'
        path.write_text('fn main() {}\n')
        with self.assertRaisesRegex(current.AuditError, 'new unreviewed build input'):
            current.build_report(self.root)

    def test_contract_edit_cannot_relabel_unreviewed_source(self):
        self.copy_inputs()
        path = self.root / current.CONTRACT
        value = json.loads(path.read_bytes())
        for revision in ('0' * 40, '189b9b5959d836ef6ae96e14fb285948e4920aa9'):
            with self.subTest(stale_source=revision):
                value['source_base_commit'] = revision
                path.write_text(json.dumps(value))
                with self.assertRaisesRegex(current.AuditError, 'unreviewed current implementation contract'):
                    current.build_report(self.root)

    def test_historical_reader_bytes_are_preserved(self):
        self.copy_inputs()
        path = self.root / current.LEGACY_READER
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(current.AuditError, 'historical reader differs'):
            current.build_report(self.root)

    def test_project_input_digests_are_the_reviewed_values(self):
        old, _ = self.audit.load_contract(current.ROOT)
        old_rows = {row['path']: row for row in old['project_files']}
        new_rows = {row['path']: row for row in self.contract['project_files']}
        self.assertEqual({name for name in old_rows if old_rows[name] != new_rows[name]}, current.CHANGED)
        for name in current.CHANGED:
            raw = (current.ROOT / name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), new_rows[name]['sha256'])

    def test_cli_report_is_created_once_and_never_replaces_prior_evidence(self):
        target = self.root / 'report.json'
        command = [sys.executable, str(current.ROOT / 'scripts/w1_qrom_current_implementation_audit.py'),
                   '--repo-root', str(current.ROOT), '--output', str(target)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        raw = target.read_bytes()
        self.assertEqual(json.loads(raw)['result'], 'CURRENT_MAPPING_REPRODUCED_SECURITY_HOLD')
        repeated = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(repeated.returncode, 2)
        self.assertEqual(target.read_bytes(), raw)


if __name__ == '__main__':
    unittest.main(verbosity=2)
