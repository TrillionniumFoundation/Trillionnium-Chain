"""Bounded deterministic negative/positive research matrix controls."""
import unittest
from daa_lease_network_aggregate_v1 import cohort,full_campaign,quantile,wilson

class MultiSeedModel(unittest.TestCase):
    def test_zero_and_one_wilson_bounded_without_fabricating_certain_success(self):
        self.assertEqual(wilson(0,1)[0],0)
        self.assertEqual(wilson(1,1)[1],1)
        self.assertLess(wilson(1,1)[0],1)
        for n in (1,10,100):
            for k in range(n+1):
                low,high=wilson(k,n)
                self.assertTrue(0<=low<=high<=1)

    def test_denominator_and_no_silent_failure_exclusion(self):
        c=cohort('legacy','withholding',trials=25)
        self.assertEqual(len(c['all_trials']),25)
        self.assertEqual(c['agreement']['denominator'],25)
        self.assertEqual(sum(bool(r['all_views_agree']) for r in c['all_trials']),
                         c['agreement']['numerator'])
        self.assertTrue(any(not x['all_views_agree'] for x in c['all_trials']))
        self.assertFalse(c['production_qualified'])
        self.assertEqual(c['actual_w1_proofs'],0)

    def test_fixed_seed_replay_and_trial_ownership(self):
        c=cohort('asert_raw','partition',trials=20,seed_first=7)
        self.assertEqual(c,cohort('asert_raw','partition',trials=20,seed_first=7))
        self.assertEqual([r['seed'] for r in c['all_trials']],list(range(7,27)))
        self.assertIsNotNone(c['headers']['p95'])

    def test_all_18_modes_retained(self):
        report=full_campaign(trials=2)
        self.assertEqual(report['scenarios'],18)
        self.assertEqual(len(report['cohorts']),18)
        self.assertEqual(sum(len(x['all_trials']) for x in report['cohorts']),36)
        self.assertEqual(report['actual_w1_proofs'],0)

    def test_invalid_inputs_and_quantile_missing(self):
        self.assertIsNone(quantile([], .5))
        self.assertEqual(quantile([2,7,3,9], .75),7.)
        for vals,q in (([-1],.5),([1],-1),([1,False],.5)):
            with self.assertRaises(ValueError):quantile(vals,q)
        for k,n in ((-1,10),(11,10),(0,0)):
            with self.assertRaises(ValueError):wilson(k,n)
        with self.assertRaises(ValueError):cohort('legacy','unlisted')
        with self.assertRaises(ValueError):cohort('legacy','steady',trials=0)

if __name__=='__main__': unittest.main()
