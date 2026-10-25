"""Matched W1/W2 research study cannot promote incomplete prototypes."""
import unittest
import w2_candidate_comparison as R


class W2CandidateComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result=R.report(seed=3,sample_count=4,security_bits=(8,),security_cap=4096)

    def test_exact_shared_context_and_all_unsolved_safety_gates(self):
        x=self.result
        self.assertEqual(x['schema'],'trnm-w2-matched-research-comparison-v0')
        self.assertEqual(len(x['challenge']),64)
        self.assertFalse(x['native_work_acceptance'])
        self.assertFalse(x['independent_review'])
        self.assertFalse(x['consensus_activation'])
        self.assertEqual(x['w1']['proof_bytes'],49188)
        self.assertEqual(x['w1']['false_result'],'TRANSCRIPT')
        self.assertTrue(x['w2a']['false_tile_accepted_by_filter'])
        self.assertFalse(x['w2a']['cryptographic_proof'])
        self.assertEqual(x['w2b']['witness_bytes'],131072)
        self.assertFalse(x['w2b']['cryptographic_proof'])
        self.assertFalse(x['w2b']['succinct_verification'])
        self.assertFalse(x['w2c']['consensus_activation'])

    def test_real_sample_costs_and_exhaustion_keep_denominators(self):
        x=self.result
        for arm in ('valid_producer','valid_verifier','from_zero_full_refusal'):
            self.assertGreater(x['w1'][arm]['python_process_cpu_ns'],0)
        for arm in x['w2c']['arms']:
            self.assertEqual(arm['security_bits'],8)
            search=arm['search']
            self.assertGreaterEqual(search['attempted_hashes'],1)
            self.assertLessEqual(search['attempted_hashes'],search['cap'])
            self.assertIn(search['status'],('FOUND','EXHAUSTED'))
            if search['status']=='EXHAUSTED':
                self.assertIsNone(arm['full_w1_result'])
            elif arm['arm']=='from-zero-false-W1':
                self.assertEqual(arm['full_w1_result']['outcome'],'W1_TRANSCRIPT')
                self.assertFalse(arm['full_w1_result']['verified_work'])

    def test_over_cap_and_invalid_profiles_refused(self):
        for args in [(0,0,(8,),16),(1,33,(8,),16),(1,8,(7,),16),
                     (1,8,(8,),0)]:
            with self.assertRaises(ValueError):
                R.report(*args)


if __name__=='__main__':
    unittest.main(verbosity=2)
