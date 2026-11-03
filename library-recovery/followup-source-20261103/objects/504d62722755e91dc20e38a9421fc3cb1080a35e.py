"""Tests for evidence-gate logic, using synthetic repositories only."""
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pq_audit', HERE / 'tools' / 'pq_audit.py')
auditor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auditor)
POLICY = json.loads((HERE / 'policy' / 'pq_policy.json').read_text())
BASE = json.loads((HERE / 'examples' / 'pq_evidence_UNREVIEWED.json').read_text())


def init_git(root):
    for command in [['git', 'init', '-q'], ['git', 'config', 'user.email', 'pq-gate@test.invalid'],
                    ['git', 'config', 'user.name', 'Gate test'], ['git', 'add', '.'],
                    ['git', 'commit', '-qm', 'fixture']]:
        subprocess.run(command, cwd=root, check=True, capture_output=True)
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'repo'
        self.repo.mkdir()
        manifest = self.repo / POLICY['proof']['candidate_manifest_path']
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({'pq_128_security_qualified': False,
                                        'production_consensus_activation': False}))
        (self.repo / 'evidence').mkdir()
        (self.repo / 'evidence' / 'artifact.txt').write_text('SYNTHETIC TEST ARTIFACT; NOT REAL SECURITY EVIDENCE\n')
        (self.repo / 'node.rs').write_text('fn verify_ed25519_signature() {}\n')
        self.sha = init_git(self.repo)
        self.e = copy.deepcopy(BASE)
        self.e['source_commit'] = self.sha

    def run_audit(self, evidence=None, mode='release'):
        return auditor.perform_audit(self.repo, POLICY, evidence or self.e, mode=mode, include_scan=True)

    def attest_dummy_artifact(self):
        a = self.repo / 'evidence' / 'artifact.txt'
        self.e['artifacts'] = {'synthetic': {'path': 'evidence/artifact.txt',
                                              'sha256': hashlib.sha256(a.read_bytes()).hexdigest()}}
        return ['synthetic']

    def prepare_synthetic_pass(self):
        ref = self.attest_dummy_artifact()
        self.e['inventory'] = {'entrypoints_enumerated': True, 'artifacts': ref}
        self.e['classic_usage_dispositions'] = {
            item['fingerprint']: {'disposition':'test_only', 'artifacts': ref}
            for item in auditor.scan_source(self.repo)['hits']
        }
        for route in self.e['routes'].values():
            route.update({'mode': 'pq-only', 'role_and_chain_bound': True,
                          'nonce_replay_rejected': True, 'signature_stripping_rejected': True,
                          'epoch_and_version_bound': True, 'rollback_rejected': True,
                          'classical_only_rejected': True, 'artifacts': ref})
        self.e['migration'].update({key: True for key in
          ('pq_owner_bound_before_classic_break', 'no_classical_fallback_post_cutover',
           'key_rotation_and_reorg_tested', 'unknown_algorithm_rejected')})
        self.e['migration']['artifacts'] = ref
        self.e['live_consensus_proof'].update({
            'backend': 'synthetic-not-a-real-proof', 'conservative_quantum_soundness_bits': 128,
            'independent_crypto_review_passed': True, 'no_groth16_or_classical_proof_fallback': True,
            'guest_verifier_transcript_parameter_bound': True, 'real_invalid_receipts_rejected': True,
            'rollback_and_reorg_proof_rejection_tested': True, 'artifacts': ref})
        p = self.e['pon_quantum']
        for k in ('full_valid_w1_oracle_modeled', 'precomputation_amortized', 'resource_and_uncompute_costed',
                  'block_propagation_and_reorg_costed', 'quantum_difficulty_attack_bounded',
                  'cumulative_work_fork_choice_tested', 'independent_adversarial_review_passed'):
            p[k] = True
        p['solver_cases'] = {x:'tested' for x in POLICY['required_solver_cases']}
        p['artifacts'] = ref
        for sect, keys in (
            ('recovery',('external_monotonic_anchor','internal_snapshot_replay_rejected',
                         'key_revocation_survives_reorg','power_loss_recovery_verified',
                         'downgrade_on_restore_rejected')),
            ('capacity',('ml_dsa_size_budget','invalid_signature_cpu_budget',
                         'invalid_proof_cpu_budget','network_propagation_p99_budget',
                         'peer_malformed_input_bounded','persistent_storage_budget'))):
            self.e[sect].update({k:True for k in keys})
            self.e[sect]['artifacts'] = ref

    def test_unreviewed_baseline_must_block(self):
        r = self.run_audit()
        self.assertEqual(r['verdict'], 'BLOCKED')
        self.assertGreater(r['check_counts']['BLOCKER'], 50)
        self.assertEqual(len(r['classic_crypto_review_leads']['hits']), 1)

    def test_synthetic_metadata_only_pass_not_a_certification(self):
        self.prepare_synthetic_pass()
        r = self.run_audit()
        self.assertEqual(r['verdict'], 'METADATA_READY_INDEPENDENT_SECURITY_REVIEW_STILL_REQUIRED')
        self.assertGreaterEqual(r['check_counts']['WARNING'], 1)  # inactive candidate
        self.assertIn('Does NOT independently prove', r['scope'])

    def test_unreviewed_classic_usage_blocks_even_when_other_gates_pass(self):
        self.prepare_synthetic_pass()
        self.e['classic_usage_dispositions'] = {}
        self.assertEqual(self.run_audit()['verdict'], 'BLOCKED')

    def test_release_cannot_skip_source_scan(self):
        self.prepare_synthetic_pass()
        r = auditor.perform_audit(self.repo, POLICY, self.e, mode='release', include_scan=False)
        self.assertEqual(r['verdict'], 'BLOCKED')

    def test_hybrid_or_is_never_accepted(self):
        self.prepare_synthetic_pass()
        self.e['routes']['hepta-handoff']['mode'] = 'hybrid-or'
        self.assertEqual(self.run_audit()['verdict'], 'BLOCKED')

    def test_missing_classic_downgrade_negative_test_blocks(self):
        self.prepare_synthetic_pass()
        self.e['routes']['node-ingress']['classical_only_rejected'] = False
        self.assertEqual(self.run_audit()['verdict'], 'BLOCKED')

    def test_inactive_route_requires_proof_no_live_authority(self):
        self.prepare_synthetic_pass()
        self.e['routes']['provider-discovery']['mode'] = 'inactive'
        self.assertEqual(self.run_audit()['verdict'], 'BLOCKED')
        self.e['routes']['provider-discovery']['no_live_authority'] = True
        self.assertNotEqual(self.run_audit()['verdict'], 'BLOCKED')

    def test_activation_with_unqualified_manifest_blocks(self):
        self.prepare_synthetic_pass()
        manifest = self.repo / POLICY['proof']['candidate_manifest_path']
        manifest.write_text(json.dumps({'pq_128_security_qualified': False,
                                        'production_consensus_activation': True}))
        r = self.run_audit(mode='scan')
        self.assertEqual(r['verdict'], 'BLOCKED')
        self.assertIn('w1-candidate:activation-safe', [x['id'] for x in r['checks'] if x['status']=='BLOCKER'])

    def test_dirty_source_blocks_release(self):
        self.prepare_synthetic_pass()
        (self.repo / 'node.rs').write_text('changed')
        self.assertEqual(self.run_audit()['verdict'], 'BLOCKED')

    def test_stale_source_commit_blocks_release(self):
        self.prepare_synthetic_pass()
        self.e['source_commit'] = '0' * 40
        self.assertEqual(self.run_audit()['verdict'], 'BLOCKED')

    def test_path_escape_rejected_even_if_digest_present(self):
        self.prepare_synthetic_pass()
        self.e['artifacts']['synthetic']['path'] = '../secret.txt'
        self.assertEqual(self.run_audit()['verdict'], 'BLOCKED')

    def test_bad_artifact_hash_blocks(self):
        self.prepare_synthetic_pass()
        self.e['artifacts']['synthetic']['sha256'] = '0'*64
        self.assertEqual(self.run_audit()['verdict'], 'BLOCKED')

    def test_untracked_evidence_file_rejected(self):
        self.prepare_synthetic_pass()
        (self.repo / 'evidence' / 'untracked.txt').write_text('not committed')
        self.e['artifacts']['synthetic']['path'] = 'evidence/untracked.txt'
        self.e['artifacts']['synthetic']['sha256'] = hashlib.sha256(b'not committed').hexdigest()
        self.assertEqual(self.run_audit()['verdict'], 'BLOCKED')

    def test_no_external_rollback_anchor_blocks(self):
        self.prepare_synthetic_pass()
        self.e['recovery']['external_monotonic_anchor'] = False
        self.assertEqual(self.run_audit()['verdict'], 'BLOCKED')

    def test_missing_solver_case_blocks(self):
        self.prepare_synthetic_pass()
        self.e['pon_quantum']['solver_cases'].pop('special_matrices')
        self.assertEqual(self.run_audit()['verdict'], 'BLOCKED')

    def test_missing_independent_review_blocks(self):
        self.prepare_synthetic_pass()
        self.e['live_consensus_proof']['independent_crypto_review_passed'] = False
        self.assertEqual(self.run_audit()['verdict'], 'BLOCKED')


if __name__ == '__main__':
    unittest.main()
