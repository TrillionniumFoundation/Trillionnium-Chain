"""Synthetic scenario and accounting negative controls, not native PoN tests."""
from dataclasses import replace
import unittest
from pon_selfish_mining_research import Settings, simulate, campaign, effective_attacker_share

class WithholdingTests(unittest.TestCase):
    def test_seed_replay_and_conservation_across_40_seeds(self):
        for seed in range(40):
            p=Settings(seed=seed,discoveries=1000,outage_at=500)
            x=simulate(p)
            self.assertEqual(x,simulate(p))
            self.assertEqual(x['discoveries'],x['accepted_public_blocks']+x['orphan_honest']+x['orphan_attacker']+x['unpublished'])
            self.assertEqual(x['actual_w1_proofs'],0)
            self.assertFalse(x['production_activated'])

    def test_zero_attacker_means_all_honest_blocks_published(self):
        x=simulate(Settings(attacker_share=0,discoveries=200,outage_at=200))
        self.assertEqual(x['public_honest'],200)
        self.assertEqual(x['unpublished'],0)
        self.assertEqual(x['ties'],0)

    def test_all_attacker_without_rival_never_publishes_private_work(self):
        x=simulate(Settings(attacker_share=1,discoveries=200,outage_at=200))
        self.assertEqual(x['attacker_discoveries'],200)
        self.assertEqual(x['accepted_public_blocks'],0)
        self.assertEqual(x['unpublished'],200)

    def test_task_outage_without_remaining_maintenance_stops(self):
        p=Settings(discoveries=100,outage_at=20,honest_maintenance=0,attacker_maintenance=0)
        x=simulate(p)
        self.assertEqual(x['discoveries'],20)
        self.assertEqual(x['terminal_reason'],'no_available_work_capacity')
        self.assertIsNone(x['post_outage_effective_share'])

    def test_outage_effective_share_changes_without_changing_chainwork(self):
        p=Settings(discoveries=1000,outage_at=10,honest_maintenance=.1,attacker_maintenance=.8)
        self.assertGreater(effective_attacker_share(p,10),effective_attacker_share(p,0))
        x=simulate(p)
        self.assertTrue(x['source_outage_reached'])
        self.assertEqual(x['actual_daa_steps'],0)

    def test_honest_fork_race_gamma_affects_results(self):
        p=Settings(seed=177, discoveries=5000,outage_at=5000,gamma=0.)
        a=simulate(p);b=simulate(replace(p,gamma=1.))
        self.assertGreater(a['ties'],0)
        self.assertGreater(b['ties'],0)
        self.assertNotEqual(a['attacker_fraction_of_accepted'],b['attacker_fraction_of_accepted'])

    def test_speedup_changes_effective_lottery_share_only(self):
        p=Settings(discoveries=1000,outage_at=1000)
        self.assertGreater(effective_attacker_share(replace(p,attacker_legal_speedup=3),0),effective_attacker_share(p,0))
        self.assertFalse(simulate(replace(p,attacker_legal_speedup=3))['work_security_qualified'])

    def test_all_parameter_limits_refuse_invalid_types(self):
        for p in (Settings(seed=-1),Settings(seed=True),Settings(discoveries=0),Settings(outage_at=-1),
                  Settings(discoveries=20,outage_at=21),Settings(attacker_share=True),
                  Settings(attacker_share=1.1),Settings(gamma=float('nan')),
                  Settings(attacker_legal_speedup=.5),Settings(honest_maintenance=-.1),
                  Settings(attacker_maintenance=float('inf'))):
            with self.subTest(p=p),self.assertRaises(ValueError):p.validate()

    def test_canonical_campaign_and_nonclaims(self):
        a,b=campaign(),campaign()
        self.assertEqual(a['cases'],54)
        self.assertEqual(a['cases_sha256'],b['cases_sha256'])
        self.assertTrue(all(x['conservation_pass'] for x in a['rows']))
        self.assertFalse(a['qualification']['permissionless_security'])

if __name__=='__main__':unittest.main()
