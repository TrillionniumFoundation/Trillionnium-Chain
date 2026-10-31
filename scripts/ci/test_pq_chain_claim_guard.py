"""Adversarial fixtures for the claim guard; deliberately no crypto pass tests."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from copy import deepcopy

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pq_chain_claim_guard import (BOUNDARY, CONFIG, CONSENSUS, CORPUS, DEVNET, GATES,
                                  PROOF_MANIFEST, UnsafePromotion, inspect)


class TestClaimGuard(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.configs = {
            CONFIG: {'schema': 'trnm-pon-post-quantum-transition-v1',
                     'status': 'research-only-no-activation',
                     'changes_existing_consensus': False,
                     'production_activation': False, 'allow_classical_fallback': False,
                     'reference_signature': {'algorithm': 'ML-DSA-65', 'signature_bytes': 3309,
                                             'public_key_bytes': 1952, 'signed_envelope_bytes': 3487,
                                             'native_account_migration_integrated': False},
                     'reference_key_exchange': {'tls_authenticated_deployed': False},
                     'existing_devnet_limits': {'post_quantum_transaction_wire_compatible': False,
                                                'max_transaction_bytes': 2048,
                                                'max_block_bytes': 1048576},
                     'candidate_limits_for_analysis_only': {'evaluated_for_network_or_security': False},
                     'conformance': {'tests_are_product_activation': False,
                                     'independent_accepted': False,
                                     'native_node_integrated': False}},
            CORPUS: {'assertions': {'production_activation': False, 'independent_accepted': False,
                                   'native_pq_node_integrated': False,
                                   'quantum_pon_hardness_qualified': False,
                                   'physical_rollback_resistant': False,
                                   'hepta_final_use_integrated': False,
                                   'public_wan_accepted': False,
                                   'allow_legacy_fallback': False}},
            CONSENSUS: {'runtime_implemented': False, 'work_profile_qualified': False,
                        'production_candidate': False, 'production_consensus_activation': False,
                        'public_testnet_ready': False, 'release_ready': False,
                        'active_consensus_implementation': None},
            DEVNET: {'production_activation': False, 'max_transaction_bytes': 2048,
                     'max_block_bytes': 1048576},
            BOUNDARY: {'consensus': {'production_candidate': False,
                                    'production_consensus_activation': False,
                                    'active_implementation': None}},
        }
        for name, obj in self.configs.items():
            self.put(name, json.dumps(obj).encode())
        for paths in GATES.values():
            for path in paths:
                if path not in self.configs:
                    self.put(path, b'research source only')

    def put(self, path, data):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def mutate(self, path, *keys, value=True):
        data = deepcopy(self.configs[path])
        item = data
        for key in keys[:-1]:
            item = item[key]
        item[keys[-1]] = value
        self.put(path, json.dumps(data).encode())

    def refused(self):
        with self.assertRaises(UnsafePromotion):
            inspect(self.root)

    def test_hold_is_not_pq_success(self):
        report = inspect(self.root)
        self.assertEqual(report['status'], 'HOLD')
        self.assertFalse(report['whole_chain_pq_qualified'])
        self.assertEqual(set(report['gates']), set(GATES))
        self.assertTrue(all(x['status'] == 'UNQUALIFIED' for x in report['gates'].values()))

    def test_classical_fallback_refused(self):
        self.mutate(CONFIG, 'allow_classical_fallback')
        self.refused()

    def test_production_activation_refused(self):
        self.mutate(BOUNDARY, 'consensus', 'production_consensus_activation')
        self.refused()

    def test_corrupt_independent_qualification_refused(self):
        self.mutate(CORPUS, 'assertions', 'independent_accepted')
        self.refused()

    def test_quantum_hardness_claim_refused(self):
        self.mutate(CORPUS, 'assertions', 'quantum_pon_hardness_qualified')
        self.refused()

    def test_rollback_claim_refused(self):
        self.mutate(CORPUS, 'assertions', 'physical_rollback_resistant')
        self.refused()

    def test_hepta_final_use_claim_refused(self):
        self.mutate(CORPUS, 'assertions', 'hepta_final_use_integrated')
        self.refused()

    def test_pq_128_guest_promotion_refused(self):
        self.put(PROOF_MANIFEST,
                 b'{"pq_128_security_qualified":true,"production_consensus_activation":false}')
        self.refused()

    def test_missing_proof_relation_refused(self):
        (self.root / GATES['proof_pq128'][0]).unlink()
        self.refused()

    def test_missing_authority_surface_inventory_refused(self):
        (self.root / 'scripts/ci/pq_authority_surface_scan.py').unlink()
        self.refused()

    def test_missing_pq_hepta_verifier_refused(self):
        (self.root / 'trillionnium/crates/trnm-research-protocol/src/hepta_handoff/pq.rs').unlink()
        self.refused()

    def test_missing_external_rollback_oracle_refused(self):
        (self.root / 'scripts/ci/pq_external_rollback_oracle.py').unlink()
        self.refused()

    def test_missing_quantum_daa_model_refused(self):
        (self.root / 'scripts/ci/pq_quantum_daa_scenarios.py').unlink()
        self.refused()

    def test_duplicate_json_keys_refused(self):
        self.put(DEVNET, b'{"production_activation":false,"production_activation":false}')
        self.refused()

    def test_symlink_source_refused(self):
        path = self.root / GATES['authorization'][0]
        path.unlink()
        path.symlink_to(self.root / CONSENSUS)
        self.refused()

    def test_unbounded_or_unaccepted_candidate_refused(self):
        self.mutate(CONFIG, 'candidate_limits_for_analysis_only',
                    'evaluated_for_network_or_security')
        self.refused()


if __name__ == '__main__':
    unittest.main()
