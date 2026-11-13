"""Strict synthetic guards: multiplier changes winning chance, never chainwork."""
from __future__ import annotations

import unittest
from daa_fork_outage_research import Parameters, simulate
from daa_legal_cost_sensitivity import (
    CostAwareForkSimulator, campaign, effective_share, run, valid_speedup,
)


class LegalCostSensitivityTests(unittest.TestCase):
    def test_one_is_original_simulator_identically(self):
        for seed in (0, 1, 9):
            p = Parameters(seed=seed)
            original = simulate(p)
            candidate = run(p, 1.0)
            for key, value in original.items():
                self.assertEqual(candidate[key], value, key)
            self.assertFalse(candidate["cost_sensitivity"]["counts_faster_miner_as_extra_chainwork"])

    def test_valid_work_cost_advantage_can_cross_nominal_half_boundary(self):
        self.assertAlmostEqual(effective_share(.7, .3, 3), .9 / 1.6)
        self.assertLess(effective_share(.7, .3, 1), .5)
        self.assertGreater(effective_share(.7, .3, 3), .5)

    def test_source_dropout_reweights_valid_production_not_work_formula(self):
        p = Parameters(share_a=.65, a_maintenance_fraction=.35,
                       b_maintenance_fraction=.8, task_outage_at=24)
        out = run(p, 3)
        shares = out["cost_sensitivity"]
        self.assertGreater(shares["post_outage_effective_b_share"],
                           shares["pre_outage_effective_b_share"])
        self.assertFalse(shares["counts_faster_miner_as_extra_chainwork"])
        self.assertEqual(out["actual_w1_proofs"], 0)
        self.assertGreater(int(out["final_required_work"]), 0)

    def test_zero_available_work_is_not_repaired_by_speed_multiplier(self):
        p = Parameters(task_outage_at=0, a_maintenance_fraction=0,
                       b_maintenance_fraction=0)
        for speed in (1, 1.5, 3, 8):
            out = run(p, speed)
            self.assertEqual(out["simulated_blocks_produced"], 0)
            self.assertTrue(out["terminal_stopped"])
            self.assertEqual(out["stop_reason"], "no_assumed_work_capacity")
            self.assertIsNone(out["cost_sensitivity"]["post_outage_effective_b_share"])

    def test_bad_factors_and_capacity_are_not_finite_model_inputs(self):
        for speed in (0, -1, float("nan"), float("inf"), 100, True, "3"):
            with self.subTest(speed=speed), self.assertRaises(ValueError):
                valid_speedup(speed)
        for a, b in ((-1, .2), (.1, float("nan")),
                     (float("inf"), 1)):
            with self.assertRaises(ValueError):
                effective_share(a, b, 3)

    def test_campaign_reproducible_and_fails_closed_on_authority(self):
        x, y = campaign(), campaign()
        self.assertEqual(x["cases"], 3 * 3 * 2 * 4)
        self.assertEqual(x["cases_sha256"], y["cases_sha256"])
        self.assertFalse(x["qualification"]["production_consensus"])
        self.assertTrue(all(not row["cost_sensitivity"]["operator_evidence"]
                            and row["actual_w1_proofs"] == 0 for row in x["rows"]))


if __name__ == "__main__":
    unittest.main()
