"""Deterministic, bounded negative controls for P1-B's synthetic matrix."""
import unittest

from daa_adversarial_campaign_v1 import (
    BLOCKS, deterministic_draw, full_campaign, one_arm, rate_for,
)


class DaaAdversarialMatrixTests(unittest.TestCase):
    def test_same_seed_same_complete_result_and_different_seed(self):
        left = full_campaign(27)
        self.assertEqual(left, full_campaign(27))
        self.assertNotEqual(left["results"], full_campaign(28)["results"])
        self.assertEqual(len(left["results"]), 35)
        self.assertEqual(left["legal_strategy_sensitivity"]["conditional_effective_work_share"],
                         "9/16")
        self.assertFalse(left["production_eligible"])
        self.assertFalse(left["selfish_mining_proof"])

    def test_arrival_draw_not_zero_or_one(self):
        for height in (0, 1, 64, 128, 256):
            d = deterministic_draw(27, height)
            self.assertGreater(d, 0)
            self.assertLess(d, 1)

    def test_lease_loss_does_not_change_already_declared_maintenance(self):
        for daa in ("legacy16", "asert-raw", "asert-mtp"):
            result = one_arm("lease-loss", daa, 7200, 27)
            self.assertEqual(result["blocks"], BLOCKS)
            self.assertEqual(result["maintenance_blocks_without_external_lease"],
                             BLOCKS - 64)
            self.assertEqual(result["deferred_time_checks"], 0)
            self.assertEqual(result["valid_time_checks"], BLOCKS)

    def test_oscillation_and_partition_assumptions_are_explicit(self):
        self.assertEqual(str(rate_for("oscillation", 1)), "4")
        self.assertEqual(str(rate_for("oscillation", 33)), "1/4")
        self.assertEqual(str(rate_for("partition", 65)), "1/2")
        with self.assertRaises(ValueError):
            rate_for("secret-third-operator", 1)


if __name__ == "__main__":
    unittest.main()
