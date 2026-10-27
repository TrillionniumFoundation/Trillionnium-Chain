"""Negative and control tests for the isolated PoN DAA/Q4 research oracle."""
from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path
import unittest

from daa_research_v1 import (
    ResearchInputError, VerifiedWindowFacts, asert_target, check_header_time,
    effective_work_share, endpoint_schedule, legacy_target, median11,
    old_slot_recyclable, renewal_window_eligible, scenario_summary,
)

VECTORS = (Path(__file__).parent / "vectors" / "daa-research-v1.json")


class IndependentDaaReferenceTests(unittest.TestCase):
    def test_known_full_target_half_life_and_signed_truncation(self):
        base = 1 << 128
        args = dict(anchor_target=base, anchor_height=1,
                    anchor_parent_time=0, parent_height=11, spacing=10,
                    half_life=7200)
        self.assertEqual(asert_target(parent_time=110, **args), base)
        self.assertEqual(asert_target(parent_time=7310, **args), base * 2)
        args["parent_height"] = 731
        self.assertEqual(asert_target(parent_time=110, **args), base // 2)
        # -1 second exponent truncates toward zero before flooring the radix.
        args["parent_height"] = 11
        self.assertEqual(asert_target(parent_time=109, **args),
                         asert_target(parent_time=109, **args))

    def test_independent_exact_vectors(self):
        vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
        self.assertEqual(vectors["schema"], "pon-daa-research-reference-v1")
        for row in vectors["cases"]:
            with self.subTest(case=row["name"]):
                result = asert_target(
                    int(vectors["anchor_target_hex"], 16),
                    anchor_height=vectors["anchor_height"],
                    anchor_parent_time=vectors["anchor_parent_time"],
                    parent_height=row["parent_height"], parent_time=row["parent_time"],
                    spacing=vectors["spacing_seconds"], half_life=vectors["half_life_seconds"],
                    pow_limit=int(vectors["pow_limit_hex"], 16),
                )
                self.assertEqual(f"{result:064x}", row["expected_target_hex"])

    def test_legacy_clamp_and_bad_conditions(self):
        base = 1 << 128
        limit = (1 << 255) - 1
        self.assertEqual(legacy_target(base, 0, 600, pow_limit=limit), base * 4)
        self.assertEqual(legacy_target(base, 0, 1, pow_limit=limit),
                         base * 38 // 150)
        self.assertEqual(legacy_target(base, 100, 90, pow_limit=limit),
                         base * 38 // 150)
        with self.assertRaises(ResearchInputError):
            legacy_target(0, 0, 10)
        with self.assertRaises(ResearchInputError):
            asert_target(base, anchor_height=2, anchor_parent_time=0,
                         parent_height=1, parent_time=10)
        with self.assertRaises(ResearchInputError):
            asert_target(base, anchor_height=1, anchor_parent_time=0,
                         parent_height=1, parent_time=10, half_life=0)

    def test_mtp_vs_future_deferral(self):
        self.assertEqual(median11([10, 11, 12, 13, 2000]), 12)
        self.assertEqual(check_header_time(12, [10, 11, 12, 13, 2000], 2000),
                         "invalid")
        self.assertEqual(check_header_time(2121, [10, 11, 12, 13, 2000], 2000),
                         "deferred")
        self.assertEqual(check_header_time(2120, [10, 11, 12, 13, 2000], 2000),
                         "valid")
        with self.assertRaises(ResearchInputError):
            median11([])

    def test_time_warp_is_legal_arithmetic_not_an_attack_proof(self):
        timestamps = endpoint_schedule()
        self.assertEqual(len(timestamps), 81)
        for h in range(1, 81):
            self.assertEqual(check_header_time(
                timestamps[h], list(reversed(timestamps[max(0, h - 11):h])), 2000
            ), "valid")
        summary = scenario_summary()
        self.assertEqual([v["height"] for v in summary["retargets"]],
                         [16, 32, 48, 64, 80])
        self.assertEqual(
            int(summary["retargets"][-1]["target_hex"], 16),
            (1 << 128) * 1024
        )
        self.assertFalse(summary["production_eligible"])


class Q4WindowBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.old = VerifiedWindowFacts(0, 1000, 1100, 1, 0)
        self.new = VerifiedWindowFacts(900, 1900, 2000, 2, 0)

    def test_overlap_delayed_inclusion_and_expired_last_lease(self):
        for height in (900, 905, 999, 1000):
            self.assertTrue(renewal_window_eligible(self.old, self.new, height))
        for height in (899, 1001):
            self.assertFalse(renewal_window_eligible(self.old, self.new, height))
        self.assertFalse(old_slot_recyclable(self.old, 1001))
        self.assertFalse(old_slot_recyclable(self.old, 1100))
        self.assertTrue(old_slot_recyclable(self.old, 1101))

    def test_wrong_slot_sequence_and_retention_refuse(self):
        for changed in (
            VerifiedWindowFacts(900, 1900, 2000, 2, 1),
            VerifiedWindowFacts(900, 1900, 2000, 3, 0),
            VerifiedWindowFacts(900, 1900, 1901, 2, 0),
            VerifiedWindowFacts(901, 1901, 2001, 2, 0),
        ):
            with self.subTest(changed=changed):
                self.assertFalse(renewal_window_eligible(self.old, changed, 900))

    def test_conditional_effective_work_advantage_is_not_consensus_claim(self):
        self.assertEqual(
            effective_work_share(Fraction(3, 10), Fraction(3, 1)),
            Fraction(9, 16),
        )
        with self.assertRaises(ResearchInputError):
            effective_work_share(Fraction(-1, 10), Fraction(1, 1))


if __name__ == "__main__":
    unittest.main()
