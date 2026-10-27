"""Fail-closed standalone research arithmetic regressions, no native security claim."""
from __future__ import annotations
import unittest
from fractions import Fraction

from pon_confirmation_risk_research import (
    effective_share, eventual_catchup_probability, required_work,
    confirmation_policy, sample_catchup, campaign,
    post_outage_effective_share, outage_campaign,
)

class PoNConfirmationRiskResearch(unittest.TestCase):
    def test_effective_share_known_fraction(self):
        self.assertEqual(effective_share('3/10', '3'), Fraction(9, 16))
        self.assertEqual(effective_share('0', '8'), 0)
        self.assertEqual(effective_share('1', '1'), 1)

    def test_noncanonical_or_out_of_range_is_refused(self):
        for nominal, factor in [(0.1, '3'), (True, '3'), ('-1/2', '1'), ('1/3', '0'),
                                ('1/4','65'), (float('nan'), '1'), ('garbage', '1')]:
            with self.subTest(nominal=nominal,factor=factor):
                with self.assertRaises(ValueError): effective_share(nominal, factor)
        for q in (-0.1, 1.1, 'bad'):
            with self.assertRaises(ValueError): eventual_catchup_probability(q, 6)
        for z in (0,129,True,1.0):
            with self.assertRaises(ValueError): eventual_catchup_probability('1/4', z)

    def test_zero_half_majority_and_equal_race(self):
        self.assertEqual(eventual_catchup_probability(Fraction(0), 6), 0)
        for q in (Fraction(1,2), Fraction(3,5),Fraction(1)):
            self.assertEqual(eventual_catchup_probability(q,12), 1)
        for q in ('1/10','1/4','49/100'):
            self.assertEqual(eventual_catchup_probability(q,1),2*Fraction(q))

    def test_exact_small_depth_hand_enumeration(self):
        # z=2 q=1/4: sum k=0,1 plus the exact K>=2 tail.
        q,p=Fraction(1,4),Fraction(3,4)
        expected = ((p*p)*(q/p)**2 + 2*p*p*q*(q/p) +
                    (1-p*p*(1+2*q)))
        self.assertEqual(eventual_catchup_probability(q,2),expected)

    def test_deeper_observation_decreases_risk_below_half(self):
        for q in ('1/10','1/4','49/100'):
            risk=[eventual_catchup_probability(q,z) for z in (1,3,6,12,24)]
            self.assertEqual(risk,sorted(risk,reverse=True))

    def test_faster_valid_work_changes_effective_risk_not_native_work(self):
        slow = effective_share('3/10','1')
        fast = effective_share('3/10','3')
        self.assertEqual(fast,Fraction(9,16))
        self.assertLess(eventual_catchup_probability(slow,6),1)
        self.assertEqual(eventual_catchup_probability(fast,6),1)

    def test_target_chainwork_matches_legacy_formula(self):
        for target in (1, 2, (1<<200), (1<<255)-1):
            self.assertEqual(required_work(target),(1<<256)//(target+1))
        for invalid in (0,-1,2**256, True, 1.0):
            with self.assertRaises(ValueError):required_work(invalid)

    def test_depth_and_work_both_required_not_weighted_votes(self):
        easy = (1<<255)-1
        hard = (1<<254)-1
        # For easy target work=2, hard=4. Six easy descendants satisfy both.
        ok=confirmation_policy((easy,)*6, minimum_depth=6,work_multiplier=6,included_target=easy)
        self.assertTrue(ok['research_policy_condition'])
        self.assertFalse(ok['native_membership_checked'])
        # Three hard descendants accumulate enough work but fail depth.
        short=confirmation_policy((hard,)*3,minimum_depth=6,work_multiplier=6,included_target=easy)
        self.assertFalse(short['research_policy_condition'])
        self.assertTrue(short['work_condition'])
        # Six easier descendants under a much harder included target fail work.
        weak=confirmation_policy((easy,)*6,minimum_depth=6,work_multiplier=6,included_target=hard)
        self.assertFalse(weak['research_policy_condition'])
        self.assertTrue(weak['depth_condition'])

    def test_policy_rejects_bad_inputs(self):
        for args in [dict(minimum_depth=0,work_multiplier=6,included_target=2),
                     dict(minimum_depth=6,work_multiplier=0,included_target=2),
                     dict(minimum_depth=6,work_multiplier=6,included_target=0),
                     dict(minimum_depth=True,work_multiplier=6,included_target=2)]:
            with self.assertRaises(ValueError): confirmation_policy((2,),**args)

    def test_mc_censored_outcomes_not_claimed_safe(self):
        result=sample_catchup(effective_q=Fraction(1,10),depth=3,seed=42,trials=1024,max_extra=2)
        self.assertGreater(result['unfinished_censored'],0)
        self.assertLessEqual(Fraction(result['lower_fraction']),Fraction(result['upper_fraction']))
        self.assertFalse(result['simulates_native_W1'])
        for kw in [dict(effective_q=Fraction(1,4),depth=0,seed=1,trials=1),
                   dict(effective_q=Fraction(1,4),depth=3,seed=1,trials=0),
                   dict(effective_q=Fraction(1,4),depth=3,seed=-1,trials=10)]:
            with self.assertRaises(ValueError): sample_catchup(**kw)

    def test_monte_carlo_matches_exact_with_unfinished_denominator(self):
        q=Fraction(1,4)
        exact=eventual_catchup_probability(q,3)
        result=sample_catchup(effective_q=q,depth=3,seed=20261026,trials=2000,max_extra=1000)
        low=Fraction(result['lower_fraction'])
        high=Fraction(result['upper_fraction'])
        estimate=Fraction(result['model_adjusted_estimate'])
        self.assertLess(float(abs(estimate-exact)),0.05)
        self.assertLessEqual(low,estimate)
        self.assertLessEqual(estimate,high)
        self.assertGreaterEqual(high,low)

    def test_all_sources_down_does_not_invent_mining_when_everyone_unready(self):
        self.assertIsNone(post_outage_effective_share('3/10', '0', '0', '1'))
        self.assertEqual(post_outage_effective_share('0', '1', '0', '1'), 0)
        self.assertEqual(post_outage_effective_share('3/10','1','0','1'),0)
        self.assertEqual(post_outage_effective_share('3/10','0','1','1'),1)

    def test_maintenance_readiness_and_legitimate_speed_concentration(self):
        self.assertEqual(post_outage_effective_share('3/10','1','1','1'),Fraction(3,10))
        self.assertEqual(post_outage_effective_share('3/10','1/4','1','1'),Fraction(12,19))
        self.assertEqual(post_outage_effective_share('3/10','1/4','1','3'),Fraction(36,43))

    def test_noncanonical_outage_fractions_fail_closed(self):
        for q,h,a,s in [('1/4','-1/4','1','1'),('1/4','1','2','1'),
                        ('1/4','0','0','0'),(True,'1','1','1'),
                        ('1/4',0.5,'1','1')]:
            with self.subTest(q=q,h=h,a=a,s=s):
                with self.assertRaises(ValueError):
                    post_outage_effective_share(q,h,a,s)

    def test_outage_cases_bind_unavailability_not_zero_risk(self):
        report=outage_campaign()
        self.assertEqual(report['outage_scenarios'],6)
        self.assertEqual(len(report['outage_rows_sha256']),64)
        lost=[r for r in report['outage_data'] if r['scenario']=='all-capacity-gone'][0]
        self.assertFalse(lost['any_assumed_live_work'])
        self.assertIsNone(lost['conditional_catchup_z6'])
        self.assertIsNone(lost['effective_share'])
        concentrated=[r for r in report['outage_data']
                      if r['scenario']=='honest-quarter-ready'][0]
        self.assertEqual(concentrated['effective_share'],'12/19')
        self.assertEqual(concentrated['conditional_catchup_z6'],'1')

    def test_campaign_is_deterministic_and_scope_explicit(self):
        a,b=campaign(),campaign()
        self.assertEqual(a,b)
        self.assertEqual(a['cases'],64)
        self.assertEqual(a['outage_scenarios'],6)
        self.assertTrue(a['zero_native_proofs'])
        self.assertTrue(a['zero_independent_operators'])
        self.assertEqual(len(a['rows_sha256']),64)

if __name__=='__main__':unittest.main()
