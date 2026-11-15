"""Upstream-withdrawal controls; synthetic dependency edits never prove safety."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import w1_upstream_security as security


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/ci/w1_upstream_security.py'


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def source_pin(path, raw):
    return {'path': path, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


class Fixture:
    """Small declared-source fixture; no Rust execution or authentic proof claim."""
    def __init__(self, root):
        self.root = Path(root)
        self.sources = {}
        self.old_versions = {'risc0-zkvm': '3.0.6', 'risc0-circuit-recursion': '4.0.5',
                             'risc0-circuit-rv32im': '4.0.5', 'risc0-zkp': '3.0.5',
                             'risc0-groth16': '3.0.5'}
        for backend in security.BACKENDS:
            self.set_versions(backend, self.old_versions)
        self.sources[security.BACKENDS['v2_verifier'] + '/src/main.rs'] = (
            'const PROFILE_ID: &str = "' + security.HISTORICAL_PROFILE + '";\n').encode()
        self.sources[security.BACKENDS['hardened_verifier'] + '/src/profile.rs'] = (
            'pub const HASH_SUITE: &str = "poseidon2";\n'
            'pub const CONTROL_ID: &str = "' + security.HISTORICAL_CONTROL + '";\n'
            'pub const PARAMETERS: &str = "' + security.HISTORICAL_PARAMETERS + '";\n').encode()
        self.sources[security.BACKENDS['v2_verifier'] + '/src/image.rs'] = (
            'pub const IMAGE_ID: [u32; 8] = ['
            + ','.join(map(str, security.HISTORICAL_IMAGE)) + '];\n').encode()
        self.sources[security.RECEIPT] = b'SYNTHETIC historical receipt; never verified\n'
        self.sources[security.GUEST_ELF] = b'SYNTHETIC guest bytes; never executable\n'
        self.sources[security.PROOF_RESULT] = b'{"synthetic":true,"cryptographically_verified":false}\n'
        self.upstream_path = 'evidence/synthetic-upstream/snapshot.bin'
        self.sources[self.upstream_path] = b'SYNTHETIC upstream snapshot\n'
        self.register = json.loads((ROOT / security.DEFAULT_MANIFEST).read_bytes())
        self.write()

    def set_versions(self, backend, versions, source=security.REGISTRY):
        path = security.BACKENDS[backend]
        self.sources[path + '/Cargo.toml'] = (
            '[dependencies]\nrisc0-zkvm = { version = "=' + versions['risc0-zkvm']
            + '", default-features = false, features = ["std", "disable-dev-mode"] }\n').encode()
        self.sources[path + '/Cargo.lock'] = (
            'version = 4\n' + ''.join(
                '\n[[package]]\nname = "' + name + '"\nversion = "' + version
                + '"\nsource = "' + source + '"\nchecksum = "' + 'a' * 64 + '"\n'
                for name, version in versions.items())).encode()

    def write(self):
        saved = {security.RECEIPT, security.GUEST_ELF, security.PROOF_RESULT}
        mapping = {
            'schema': 'TRNM-W1-QROM-IMPLEMENTATION-CONTRACT2',
            'profile_id': security.HISTORICAL_PROFILE,
            'project_files': [source_pin(path, raw) for path, raw in sorted(self.sources.items())
                              if path not in saved and path != self.upstream_path],
            'saved_v2_files': [source_pin(path, self.sources[path]) for path in sorted(saved)],
            'upstream_snapshot': source_pin(self.upstream_path, self.sources[self.upstream_path]),
        }
        mapping_raw = encoded(mapping)
        self.register['mapping_contract'] = source_pin(security.MAPPING, mapping_raw)
        files = dict(self.sources)
        files[security.MAPPING] = mapping_raw
        files[security.DEFAULT_MANIFEST] = encoded(self.register)
        for path, raw in files.items():
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)


class UpstreamSecurityTests(unittest.TestCase):
    def fixture(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return Fixture(directory.name)

    def refused(self, fixture, message):
        with self.assertRaisesRegex(security.UpstreamSecurityError, message):
            security.inspect(fixture.root)

    def test_real_selected_sources_are_withdrawn_without_claiming_a_w1_exploit(self):
        result = security.inspect(ROOT)
        self.assertEqual(result['status'], 'KNOWN_AFFECTED_SELECTED_PROFILE')
        self.assertEqual(len(result['affected_locked_packages']), 15)
        requirements = {row['id']: row['sdk_requirement'] for row in result['backend_observations']}
        self.assertEqual(requirements, {'v2_verifier': '=3.0.6', 'hardened_verifier': '=3.0.6',
                                       'guest_v2': '=3.0.3'})
        self.assertIn('saved_receipt_sha256', result['retained_historical_identity_fields'])
        self.assertFalse(result['actual_w1_exploit_reproduced'])
        self.assertFalse(result['groth16_use_inferred_from_lock_presence'])
        self.assertFalse(result['fresh_verification_performed'])
        self.assertIsNone(result['security_bits_quantum'])
        self.assertIsNone(result['actual_lifetime_failure_bound'])
        self.assertFalse(result['whole_chain_pq_qualified'])

    def test_source_bound_diagnostic_keeps_historical_replay_separate(self):
        fixture = self.fixture()
        report = security.inspect(fixture.root)
        self.assertEqual(report['status'], 'KNOWN_AFFECTED_SELECTED_PROFILE')
        self.assertFalse(report['current_proof_use_eligible'])
        self.assertTrue(report['selected_inputs_before_after_equal'])
        self.assertIn('diagnostic-only', report['historical_replay_scope'])
        self.assertFalse(report['historical_artifacts_modified'])
        with self.assertRaises(security.UpstreamSecurityError):
            security.require_current(report)

    def test_only_upgrading_sdk_leaves_old_circuits_explicitly_blocked(self):
        fixture = self.fixture()
        mixed = dict(fixture.old_versions, **{'risc0-zkvm': '3.1.0'})
        for backend in security.BACKENDS:
            fixture.set_versions(backend, mixed)
        fixture.write()
        result = security.inspect(fixture.root)
        self.assertEqual(len(result['affected_locked_packages']), 12)
        self.assertIn('MIXED_OR_UNREVIEWED_PATCH_RELEASE_FAMILY', result['blockers'])
        self.assertFalse(result['current_proof_use_eligible'])

    def test_patched_version_strings_do_not_approve_old_proof_identity(self):
        fixture = self.fixture()
        for backend in security.BACKENDS:
            fixture.set_versions(backend, security.PATCH_RELEASE)
        fixture.write()
        report = security.inspect(fixture.root)
        self.assertEqual(report['status'], 'UNREVIEWED_MIGRATION')
        self.assertEqual(report['affected_locked_packages'], [])
        self.assertIn('guest_image_id', report['retained_historical_identity_fields'])
        self.assertIn('final_control_id', report['retained_historical_identity_fields'])
        self.assertIn('HISTORICAL_IDENTITY_REQUIRES_MIGRATION_REVIEW', report['blockers'])
        self.assertIn('REGENERATED_PROOF_AND_VERIFIER_BINDING_REQUIRED', report['blockers'])
        self.assertFalse(report['migration_approved'])

    def test_future_prerelease_and_build_labels_cannot_claim_a_reviewed_patch(self):
        for version in ('3.1.0-rc.1', '3.1.0+local', '3.2.0', '4.0.0'):
            with self.subTest(version=version):
                fixture = self.fixture()
                versions = dict(security.PATCH_RELEASE, **{'risc0-zkvm': version})
                fixture.set_versions('v2_verifier', versions)
                fixture.write()
                result = security.inspect(fixture.root)
                self.assertIn('UNREVIEWED_PACKAGE_VERSION_OR_SOURCE', result['blockers'])
                self.assertFalse(result['current_proof_use_eligible'])

    def test_git_fork_with_patched_label_is_not_the_published_package(self):
        fixture = self.fixture()
        fixture.set_versions('v2_verifier', security.PATCH_RELEASE,
                             source='git+https://example.invalid/unreviewed-risc0')
        fixture.write()
        report = security.inspect(fixture.root)
        self.assertTrue(any(row['assessment'] == 'UNREVIEWED_PACKAGE_SOURCE'
                            for row in report['unreviewed_locked_packages']))
        self.assertFalse(report['current_proof_use_eligible'])

    def test_manifest_label_cannot_replace_the_locked_sdk(self):
        fixture = self.fixture()
        path = security.BACKENDS['v2_verifier'] + '/Cargo.toml'
        fixture.sources[path] = fixture.sources[path].replace(b'=3.0.6', b'=3.1.0')
        fixture.write()
        self.refused(fixture, 'manifest SDK differs')

    def test_missing_or_duplicate_affected_package_is_refused(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                fixture = self.fixture()
                path = security.BACKENDS['v2_verifier'] + '/Cargo.lock'
                raw = fixture.sources[path]
                block = raw.split(b'\n[[package]]\n')[1]
                fixture.sources[path] = (raw + b'\n[[package]]\n' + block if duplicate
                                         else raw.replace(b'\n[[package]]\n' + block, b''))
                fixture.write()
                self.refused(fixture, 'missing or ambiguous locked crate')

    def test_source_tamper_is_refused_even_with_the_original_version_label(self):
        fixture = self.fixture()
        path = fixture.root / security.BACKENDS['v2_verifier'] / 'Cargo.lock'
        path.write_bytes(path.read_bytes().replace(b'3.0.6', b'3.1.0'))
        self.refused(fixture, 'source pin differs')

    def test_retained_receipt_tamper_is_not_accepted_as_historical_evidence(self):
        fixture = self.fixture()
        path = fixture.root / security.RECEIPT
        raw = path.read_bytes()
        path.write_bytes(b'X' + raw[1:])
        self.refused(fixture, 'source pin differs')

    def test_omitted_advisory_and_relabelled_safe_range_are_refused(self):
        for change in ('omit', 'range', 'format', 'typed_flag', 'approve'):
            with self.subTest(change=change):
                fixture = self.fixture()
                if change == 'omit':
                    fixture.register['advisories'].pop()
                elif change == 'range':
                    fixture.register['advisories'][0]['affected_before']['risc0-zkvm'] = '3.0.6'
                elif change == 'format':
                    fixture.register['release']['affected_receipt_formats'].remove('succinct')
                elif change == 'typed_flag':
                    fixture.register['release']['regeneration_required'] = 1
                else:
                    fixture.register['approved_current_profile_ids'] = [security.HISTORICAL_PROFILE]
                fixture.write()
                self.refused(fixture, 'policy|advisory|self-promotion')

    def test_a_mutated_report_boolean_cannot_create_current_use_authority(self):
        fixture = self.fixture()
        report = security.inspect(fixture.root)
        report['current_proof_use_eligible'] = True
        report['migration_approved'] = True
        with self.assertRaises(security.UpstreamSecurityError):
            security.require_current(report)

    def test_cli_diagnostic_zero_and_current_use_nonzero_are_distinct(self):
        fixture = self.fixture()
        command = [sys.executable, str(SCRIPT), '--root', str(fixture.root)]
        historical = subprocess.run(command, capture_output=True, timeout=15, check=False)
        current = subprocess.run(command + ['--require-current'], capture_output=True,
                                 timeout=15, check=False)
        self.assertEqual(historical.returncode, 0, historical.stderr)
        self.assertEqual(current.returncode, 2, current.stderr)
        self.assertEqual(historical.stdout, current.stdout)
        self.assertEqual(json.loads(current.stdout)['status'], 'KNOWN_AFFECTED_SELECTED_PROFILE')
        self.assertEqual(json.loads(current.stderr)['status'], 'REFUSE')

    def test_register_duplicate_key_and_source_symlink_are_refused(self):
        fixture = self.fixture()
        register = fixture.root / security.DEFAULT_MANIFEST
        raw = register.read_bytes()
        register.write_bytes(raw.replace(b'{', b'{"schema":"injected",', 1))
        with self.assertRaises(security.lifetime.BudgetError):
            security.inspect(fixture.root)
        fixture.write()
        path = fixture.root / security.RECEIPT
        path.unlink()
        path.symlink_to(fixture.root / security.GUEST_ELF)
        with self.assertRaises(security.SourceReadError):
            security.inspect(fixture.root)


if __name__ == '__main__':
    unittest.main()
