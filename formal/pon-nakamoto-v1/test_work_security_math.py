"""Self-contained exact-arithmetic negative controls; no native W1 evidence."""
from __future__ import annotations
import hashlib
import json
import unittest
from fractions import Fraction as F

from work_security_math import (
    SecurityModelError, effective_work_fraction,
    ideal_private_catchup_risk, verifier_pressure, risk_matrix,
    frozen_campaign,
)


class IdealWorkSecurityArithmeticTests(unittest.TestCase):
    def test_effective_share_retains_nominal_when_costs_equal(self):
        for numerator in range(11):
            q = F(numerator, 10)
            self.assertEqual(effective_work_fraction(q, F(1)), q)
        self.assertEqual(effective_work_fraction(F(3, 10), F(3)), F(9, 16))
        self.assertEqual(effective_work_fraction(F(1, 4), F(3)), F(1, 2))

    def test_effective_share_monotone_and_no_invalid_proof_chainwork(self):
        for q in (F(1, 100), F(1, 4), F(3, 10)):
            values = [effective_work_fraction(q, s) for s in (F(1),F(3,2),F(3),F(8))]
            self.assertEqual(sorted(values), values)
            self.assertTrue(all(v >= q for v in values))

    def test_one_two_confirmation_closed_form(self):
        for q in (F(1,10),F(1,4),F(1,3)):
            self.assertEqual(ideal_private_catchup_risk(q, 1), 2*q)
        self.assertEqual(ideal_private_catchup_risk(F(1,4), 2), F(5,16))
        self.assertEqual(ideal_private_catchup_risk(F(1,3), 2), F(14,27))

    def test_zero_and_half_share_boundaries(self):
        for z in (1,2,6,12,96):
            self.assertEqual(ideal_private_catchup_risk(F(0), z), 0)
            for q in (F(1,2),F(3,4),F(1)):
                self.assertEqual(ideal_private_catchup_risk(q, z), 1)

    def test_risk_falls_with_depth_but_not_at_half_share(self):
        for q in (F(1,10),F(1,4),F(49,100)):
            vals = [ideal_private_catchup_risk(q, z) for z in (1,2,3,6,12,24,48,96)]
            self.assertEqual(sorted(vals, reverse=True), vals)
            self.assertTrue(all(0 < v < 1 for v in vals))

    def test_risk_increases_with_effective_adversary(self):
        for z in (1,6,12,24):
            vals = [ideal_private_catchup_risk(q,z) for q in (F(1,10),F(1,4),F(3,10),F(49,100),F(1,2))]
            self.assertEqual(sorted(vals), vals)

    def test_rejection_pressure_is_not_a_w1_verifier_or_safe_claim(self):
        actual_ratio_sampled = F(5177922, 1000000)
        o = verifier_pressure(F(1,4), actual_ratio_sampled, F(1,4))
        self.assertTrue(o['over_one_receiver_cpu'])
        self.assertFalse(o['public_network_safe'])
        self.assertFalse(verifier_pressure(F(0),F(1),F(1,2))['over_one_receiver_cpu'])

    def test_strict_refusals_and_boundaries(self):
        bad = (True, 0.25, '1/4', -1, F(-1,2),F(101,100),F(1,10000001))
        for item in bad:
            with self.subTest(item=item), self.assertRaises(SecurityModelError):
                effective_work_fraction(item,F(1))
        for speed in (True, 3.0, F(0),F(65),F(1,10000001)):
            with self.subTest(speed=speed), self.assertRaises(SecurityModelError):
                effective_work_fraction(F(1,4),speed)
        for depth in (0,97,True,1.1,'6'):
            with self.subTest(depth=depth), self.assertRaises(SecurityModelError):
                ideal_private_catchup_risk(F(1,4),depth)
        with self.assertRaises(SecurityModelError):
            verifier_pressure(F(1,2),F(1),F(11,10))

    def test_zero_safety_promotion_even_for_tiny_risk(self):
        data = risk_matrix(nominal_shares=(F(1,100),),legal_speedups=(F(1),),confirmation_depths=(48,))
        self.assertTrue(data['scenarios'][0]['ideal_model_below_proposed_limit'])
        self.assertFalse(data['accepted_security_gate'])
        self.assertFalse(data['scenarios'][0]['production_security_qualified'])

    def test_no_confirmation_depth_if_threefold_speedup_hits_half(self):
        data = risk_matrix(nominal_shares=(F(1,4),),legal_speedups=(F(3),),confirmation_depths=(6,12,24,48,96))
        self.assertTrue(all(s['no_finite_confirmation_guarantee'] and
                            s['catchup_risk_decimal']=='1.0000000000000000' for s in data['scenarios']))

    def test_duplicate_and_excess_workload_rejected(self):
        for args in [
            ((F(1,4),F(1,4)),(F(1),),(6,)),
            ((F(1,4),),(F(1),),(6,6)),
            ((F(1,4),),tuple(F(i) for i in range(1,18)),(6,)),
        ]:
            with self.assertRaises(SecurityModelError):
                risk_matrix(nominal_shares=args[0],legal_speedups=args[1],confirmation_depths=args[2])

    def test_frozen_campaign_is_reproducible_and_discloses_assumptions(self):
        x,y=frozen_campaign(),frozen_campaign()
        self.assertEqual(x,y)
        self.assertEqual(len(x['scenarios']),48)
        self.assertEqual(x['actual_w1_proofs'],0)
        self.assertFalse(x['consensus_activated'])
        self.assertFalse(x['hostile_wan_tested'])
        self.assertTrue(x['assumptions'])
        raw=json.dumps(x,sort_keys=True,separators=(',',':')).encode()
        self.assertEqual(len(hashlib.sha256(raw).hexdigest()),64)


if __name__ == '__main__':
    unittest.main()
