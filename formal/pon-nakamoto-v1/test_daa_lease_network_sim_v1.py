"""Synthetic network/Poisson model checks, never PoN W1 or WAN qualification."""
import unittest
from daa_lease_network_sim_v1 import (Campaign, Participant, Profile,
                                        INITIAL_TARGET, fixed_campaign)

class NetworkModel(unittest.TestCase):
    def actors(self, mode='maintenance', special=False):
        return (Participant('A', .6),
                Participant('B', .4, mode=mode, speed=1.7 if special else 1))

    def test_deterministic_source_identity_and_tips(self):
        p=Profile('legacy', seconds=400, seed=5)
        a=Campaign(p,self.actors()).run(); b=Campaign(p,self.actors()).run()
        self.assertEqual(a,b)
        self.assertEqual(a['created_headers'], sum(a['by_miner'].values()))
        self.assertTrue(a['not_native_w1'])
        self.assertTrue(a['perfect_history_fetch_assumption'])
        self.assertTrue(a['all_views_agree'])

    def test_three_candidate_profiles_execute_and_retain_prefix(self):
        reports=fixed_campaign()
        self.assertEqual(len(reports),18)
        self.assertEqual({r['profile']['algorithm'] for r in reports},
                         {'legacy','asert_raw','asert_mtp'})
        for r in reports:
            self.assertGreaterEqual(r['created_headers'],0)
            self.assertEqual(r['created_headers'],sum(r['by_miner'].values()))
            self.assertTrue(all(0<=v<=r['created_headers'] for v in r['confirmed_abstract'].values()))
            self.assertTrue(r['not_timestamp_attack_profitability'])

    def test_no_external_lease_can_stop_only_dependent_actor(self):
        base=Profile('asert_raw', seconds=650, seed=31, external_lease_lost_at=200)
        r=Campaign(base,self.actors('leased_only')).run()
        self.assertGreater(r['synthetic_maintenance_headers'],0)
        self.assertGreaterEqual(r['synthetic_leased_headers'],0)
        self.assertTrue(r['all_views_agree'])
        no_fallback=(Participant('A',.6,mode='leased_only'),
                     Participant('B',.4,mode='leased_only'))
        # Both actors entirely stop at 1; never fabricate a third task class.
        p=Profile('legacy', seconds=400, seed=31,external_lease_lost_at=1)
        dead=Campaign(p,no_fallback).run()
        self.assertEqual(dead['created_headers'],0)
        self.assertTrue(dead['all_views_agree'])

    def test_partition_catches_up_with_heavier_branch(self):
        p=Profile('legacy',seconds=700,seed=9,partition_from=80,partition_until=360)
        r=Campaign(p,self.actors()).run()
        self.assertTrue(r['all_views_agree'])
        self.assertGreater(r['created_headers'],10)
        self.assertGreater(sum(r['missing_ancestor_fetches_idealized'].values()),0)

    def test_efficiency_advantage_is_not_credited_as_model_utility(self):
        p=Profile('legacy', seconds=600, seed=49)
        r=Campaign(p,self.actors(special=True)).run()
        self.assertEqual(r['synthetic_leased_headers'],0)
        self.assertEqual(r['synthetic_maintenance_headers'],r['created_headers'])
        self.assertGreater(r['by_miner']['B'],0)

    def test_bad_parameters_fail_closed(self):
        for err in (dict(seconds=0), dict(base_rate=float('nan')),
                    dict(partition_from=30,partition_until=29),
                    dict(time_offset=121), dict(half_life=0)):
            with self.subTest(err=err),self.assertRaises(ValueError):
                Profile('legacy',**err)
        with self.assertRaises(ValueError):
            Campaign(Profile('legacy'),(Participant('A',.9),Participant('B',.4)))
        with self.assertRaises(ValueError):
            Participant('B',.4,speed=0)

if __name__=='__main__':
    unittest.main()
