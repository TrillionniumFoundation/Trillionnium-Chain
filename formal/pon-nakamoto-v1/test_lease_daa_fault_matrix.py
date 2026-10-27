"""Narrow negative controls for non-activated lease×DAA screening only."""
from __future__ import annotations

import json
import math
import unittest
from lease_daa_fault_matrix import (
    ALGORITHMS, CampaignConfig, SCENARIOS, campaign, effective_adversary_share,
    next_target, q4_recovery_sequence, simulate, stated_total_rate, INITIAL,
    TARGET_LIMIT, SPACING,
)


class FaultMatrixTests(unittest.TestCase):
    def test_grid_is_bounded_and_no_w1_evidence_claimed(self):
        report = campaign((0, 1), 64)
        self.assertEqual(report['run_count'], 2 * 4 * 3 * 3)
        self.assertFalse(report['qualification']['full_native_acceptance'])
        self.assertTrue(all(r['native_W1_proofs'] == 0 for r in report['runs']))
        self.assertTrue(all(r['all_simulated_timestamps_passed_MTP_and_skew'] for r in report['runs']))
        self.assertTrue(all(int(r['required_chainwork']) > 0 for r in report['runs']))
        self.assertEqual(report['runs_sha256'], campaign((0, 1), 64)['runs_sha256'])

    def test_same_seed_is_replayable_and_attack_changes_timestamp_choices(self):
        settings = CampaignConfig(seed=7, blocks=160)
        a = simulate(settings, 'legacy16', 'steady', 'honest')
        b = simulate(settings, 'legacy16', 'steady', 'endpoint_push')
        self.assertEqual(a, simulate(settings, 'legacy16', 'steady', 'honest'))
        self.assertEqual(a['attacker_discovered_headers'], b['attacker_discovered_headers'])
        self.assertEqual(a['blocks'], b['blocks'])
        self.assertTrue(b['non_honest_timestamp_headers'] > 0)
        self.assertNotEqual(a['required_chainwork'], b['required_chainwork'])

    def test_lease_lapse_changes_exogenous_capacity_not_source_credential(self):
        row = simulate(CampaignConfig(seed=10, blocks=120), 'asert_raw',
                       'all_leases_lapse', 'honest')
        self.assertEqual(row['assumed_explicit_maintenance_blocks'], 56)
        self.assertEqual(row['native_W1_proofs'], 0)
        self.assertFalse(q4_recovery_sequence()['valid_automatic_old_lease_renewal_after_expiry'])
        self.assertEqual(q4_recovery_sequence()['earliest_retained_slot_reuse_height'], 1101)
        self.assertEqual(stated_total_rate('all_leases_lapse', 65), .4)

    def test_effective_share_is_conditional_and_never_score_based(self):
        self.assertEqual(effective_adversary_share(0.0, 5.0), 0.0)
        self.assertEqual(effective_adversary_share(1.0, 5.0), 1.0)
        self.assertAlmostEqual(effective_adversary_share(0.3, 3.0), 0.5625)
        with self.assertRaises(ValueError):
            effective_adversary_share(0.3, 0)

    def test_legacy_daa_uses_ancestor_window_not_current_header_time(self):
        times = [h * SPACING for h in range(17)]
        self.assertEqual(next_target('legacy16', INITIAL,
                                     list(reversed(times[:15])), 15, 7200), INITIAL)
        self.assertEqual(next_target('legacy16', INITIAL,
                                     list(reversed(times[:16])), 16, 7200), INITIAL)
        for a in ALGORITHMS:
            with self.assertRaises(ValueError):
                next_target(a, INITIAL, [0], 20, 7200)

    def test_stale_future_or_unknown_scenarios_reject(self):
        with self.assertRaises(ValueError):
            CampaignConfig(seed=0, blocks=5000).validate()
        with self.assertRaises(ValueError):
            CampaignConfig(seed=0, half_life=0).validate()
        with self.assertRaises(ValueError):
            simulate(CampaignConfig(seed=0), 'no-such-daa', 'steady', 'honest')
        with self.assertRaises(ValueError):
            simulate(CampaignConfig(seed=0), 'legacy16', 'steady', 'no-such-attack')

    def test_staggered_32_slot_reclaim_boundaries(self):
        from daa_research_oracle import Lease, q4_slot_reclaimable
        original = [Lease(0, 1000, 1100, 1)] + [
            Lease(1, 1001, 1101, 1) for _ in range(31)
        ]
        self.assertEqual(len(original), 32)
        # A global slot generation can advance only through a properly signed
        # OPEN; this time-only test cannot issue such a signature.
        self.assertEqual(sum(q4_slot_reclaimable(x, 1101, "revoked")
                             for x in original), 1)
        self.assertEqual(sum(q4_slot_reclaimable(x, 1102, "revoked")
                             for x in original), 32)
        self.assertEqual(sum(q4_slot_reclaimable(x, 1100, "revoked")
                             for x in original), 0)


if __name__ == '__main__':
    unittest.main()
