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

    def test_all_crate_rust_surfaces_and_classical_pq_aliases_visible(self):
        fixtures = {
            'trillionnium/crates/new-owner/build.rs': 'use ring::signature::UnparsedPublicKey;\n',
            'trillionnium/crates/new-owner/examples/wallet.rs': 'use p256::ecdsa::VerifyingKey;\n',
            'trillionnium/crates/new-owner/tests/delegation.rs': 'use ed25519_dalek::VerifyingKey;\n',
            'trillionnium/crates/new-owner/benches/verify.rs': 'use pqcrypto_mldsa::mldsa65;\n',
            'trillionnium/crates/new-owner/generated/custom.rs': 'use slh_dsa::Verifier;\n',
        }
        for path, code in fixtures.items():
            self.put(path, code)
        report = inspect(self.root)
        unknown = {entry['path']: entry for entry in report['findings']
                   if entry['role_review_hint'] == 'unreviewed-source-hit'}
        self.assertEqual(set(unknown), set(fixtures))
        self.assertEqual(report['unreviewed_indicator_files'], len(fixtures))
        self.assertTrue(all(len(entry['sha256']) == 64 for entry in unknown.values()))
        self.assertEqual(unknown['trillionnium/crates/new-owner/examples/wallet.rs']['classical_indicator_lines'], [1])
        self.assertEqual(unknown['trillionnium/crates/new-owner/benches/verify.rs']['pq_indicator_lines'], [1])

    def test_non_src_symlink_and_invalid_source_fail_closed(self):
        outside = self.put('trillionnium/crates/new-owner/examples/probe.rs', 'use ed25519_dalek::Verifier;\n')
        outside.unlink()
        outside.symlink_to(self.root / 'not-a-real-file')
        with self.assertRaisesRegex(AuditError, 'symlink source'):
            inspect(self.root)
        outside.unlink()
        outside.write_bytes(b'\xff')
        with self.assertRaisesRegex(AuditError, 'nonutf8 Rust source'):
            inspect(self.root)

    def test_crucial_file_removed_is_not_silent_success(self):
        (self.root / next(iter(CRITICAL))).unlink()
        with self.assertRaisesRegex(AuditError, 'critical source missing'):
            inspect(self.root)

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
