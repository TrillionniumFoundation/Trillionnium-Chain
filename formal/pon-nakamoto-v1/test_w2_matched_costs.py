"""P5 matched-cost research controls; must not invent W2 security proof."""
import unittest
import w2_matched_costs as M

class W2MatchedCostsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report=M.compare(seed=7,sample_count=8,security_bits=(8,12),
                             security_cap=65536)

    def test_one_exact_statement_across_every_candidate(self):
        r=self.report
        for field in ('challenge','task','target','header_sha256'):
            self.assertEqual(len(r[field]),64)
        self.assertEqual(r['w1']['proof_bytes'],49188)
        self.assertEqual(r['w1']['false_result'],'TRANSCRIPT')
        self.assertEqual(r['w2b']['witness_bytes'],131072)

    def test_known_unsound_sampling_counterexample_is_not_hidden(self):
        r=self.report['w2a']
        self.assertTrue(r['false_tile_missed'])
        self.assertFalse(r['complete_proof'])
        self.assertGreaterEqual(r['unsampled_corrupt_index'],0)

    def test_w2c_false_work_never_becomes_chainwork(self):
        r=self.report['w2c']
        self.assertGreater(len(r['arms']),1)
        for arm in r['arms']:
            self.assertFalse(arm['valid_chainwork'])
            if arm['arm']=='false-W1' and arm['complete_W1_result']:
                self.assertEqual(arm['complete_W1_result']['outcome'],'W1_TRANSCRIPT')

    def test_research_never_signals_production_or_soundness(self):
        r=self.report
        self.assertFalse(r['consensus_activation'])
        self.assertFalse(r['public_network_ready'])
        self.assertFalse(r['independent_review'])
        self.assertFalse(r['w1']['cheapest_miner_hardness_proven'])
        self.assertIsNone(r['w2c']['attacker_min_cost_bound'])
        self.assertFalse(r['w2b']['cryptographic_proof'])

    def test_invalid_configuration_fails_without_a_fallback(self):
        for kwargs in ({'sample_count':0},{'security_bits':(8,8)},
                       {'security_bits':(29,)},{'security_cap':0}):
            with self.assertRaises(ValueError):
                M.compare(**kwargs)

if __name__=='__main__':
    unittest.main(verbosity=2)
