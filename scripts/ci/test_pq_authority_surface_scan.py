"""Positive HOLD and adversarial refusal for the Rust source surface scanner."""
import tempfile
from pathlib import Path
import unittest
from pq_authority_surface_scan import CRITICAL, AuditError, inspect


class TestPqAuthoritySurfaceScan(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        for p in CRITICAL:
            self.put(p, 'pub fn verify() { /* research code */ }\n')

    def put(self, path, data):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data)
        return target

    def test_incomplete_holding_status_and_curated_roles(self):
        r = inspect(self.root)
        self.assertEqual(r['status'], 'HOLD_INCOMPLETE_AUTHORITY_TRACING')
        self.assertFalse(r['whole_chain_pq_qualified'])
        self.assertEqual(r['reviewed_roles_mapped'], len(CRITICAL))
        self.assertEqual(r['unreviewed_indicator_files'], 0)

    def test_unknown_classic_and_pq_sources_remain_visible(self):
        self.put('trillionnium/crates/new-owner/src/effect.rs',
                 'use ed25519_dalek::Verifier;\nverify_strict(x);\nPqNativeVerifier::from_pin();\n')
        r = inspect(self.root)
        self.assertEqual(r['unreviewed_indicator_files'], 1)
        unknown = next(e for e in r['findings'] if e['role_review_hint'] == 'unreviewed-source-hit')
        self.assertEqual(unknown['classical_indicator_lines'], [1, 2])
        self.assertEqual(unknown['pq_indicator_lines'], [3])
        self.assertEqual(len(unknown['sha256']), 64)

    def test_crucial_file_removed_is_not_silent_success(self):
        (self.root / next(iter(CRITICAL))).unlink()
        with self.assertRaisesRegex(AuditError, 'critical source missing'):
            inspect(self.root)

    def test_non_crypto_owner_boundaries_are_visible_and_remain_unqualified(self):
        owners = (
            'trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs',
            'trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs',
            'trillionnium/crates/trnm-pon-node/src/store/storage_service.rs',
            'trillionnium/crates/trnm-service-settlement/src/native_budget.rs',
            'trillionnium/crates/trnm-data-availability/src/cell/closure.rs',
            'trillionnium/crates/trnm-data-availability/src/cell/retention.rs',
            'trillionnium/crates/trnm-pon-node/src/store/authenticated_migration/growth_rehearsal.rs',
        )
        report = inspect(self.root)
        entries = {entry['path']: entry for entry in report['findings']}
        for name in owners:
            with self.subTest(path=name):
                entry = entries[name]
                self.assertEqual(entry['role_review_hint'], CRITICAL[name])
                self.assertEqual(entry['classical_indicator_count'], 0)
                self.assertEqual(entry['pq_indicator_count'], 0)
                path = self.root / name
                data = path.read_bytes()
                path.unlink()
                with self.assertRaisesRegex(AuditError, 'critical source missing'):
                    inspect(self.root)
                path.write_bytes(data)
        self.assertFalse(inspect(self.root)['whole_chain_pq_qualified'])

    def test_refuse_source_symlink_and_directory_symlink(self):
        p = self.root / next(iter(CRITICAL))
        p.unlink()
        p.symlink_to(self.root / 'no-target')
        with self.assertRaises(AuditError):
            inspect(self.root)

    def test_refuse_oversize_and_invalid_utf8(self):
        path = 'trillionnium/crates/new-owner/src/effect.rs'
        p = self.put(path, 'a' * (1024 * 1024 + 1))
        with self.assertRaises(AuditError):
            inspect(self.root)
        p.write_bytes(b'\xff')
        with self.assertRaises(AuditError):
            inspect(self.root)


if __name__ == '__main__':
    unittest.main()
