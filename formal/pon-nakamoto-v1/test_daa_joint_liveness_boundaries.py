"""Unactivated cross-boundary regression for PoN Q4/Revision12 and candidate DAA.

Pure-Python oracle only: no W1 miner, signer, native Node, WAN or activation.
Assertions are invariant checks, not proof of proof-cost hardness.
"""
from __future__ import annotations

import unittest

from daa_research_oracle import (
    Lease, asert_target, legacy_retarget, mtp11, q4_atomic_renew,
    q4_slot_reclaimable, valid_time,
)

CAP = (1 << 255) - 1
ANCHOR = CAP // 4096


class JointLivenessAndDifficultyBoundaries(unittest.TestCase):
    def test_zero_optional_lease_never_becomes_implicit_source_authorization(self):
        """Expired old lease can't renew; maintenance's genesis authority is separate."""
        old = Lease(0, 1000, 1100, 1)
        next_lease = Lease(500, 1500, 1600, 2)
        self.assertTrue(q4_atomic_renew(old, next_lease, 999, True, True))
        for height in (1001, 1050, 1100, 1101):
            self.assertFalse(q4_atomic_renew(old, next_lease, height, True, True))
        for height in (1000, 1001, 1100):
            self.assertFalse(q4_slot_reclaimable(old, height, "expired"))
        self.assertTrue(q4_slot_reclaimable(old, 1101, "expired"))
        # A reclaimed slot does NOT imply approval to sign or submit.
        self.assertFalse(q4_atomic_renew(old, next_lease, 999, False, True))
        self.assertFalse(q4_atomic_renew(old, next_lease, 999, True, False))

    def test_shifted_clock_origin_does_not_alter_asert_difficulty(self):
        """Changing only the epoch origin cannot change cumulative difficulty."""
        for half_life in (3600, 7200, 14400, 28800):
            for height in (2, 16, 17, 79, 80, 1000):
                for delta in (-600, 0, 600, 7200):
                    anchor_time = 1_000_000
                    parent_time = anchor_time + (height - 1) * 10 + delta
                    expected = asert_target(ANCHOR, anchor_time, parent_time, 1,
                                            height, 10, half_life, CAP)
                    for translation in (0, 1, 86_400, 1_000_000_000):
                        actual = asert_target(ANCHOR, anchor_time + translation,
                                              parent_time + translation, 1,
                                              height, 10, half_life, CAP)
                        self.assertEqual(actual, expected)

    def test_one_extreme_timestamp_does_not_select_new_work_class(self):
        """DAA changes targets, not task authorization or valid work relation."""
        old = Lease(0, 1000, 1100, 1)
        replacement = Lease(500, 1500, 1600, 2)
        baseline = asert_target(ANCHOR, 1_000_000, 1_000_790,
                                1, 80, 10, 7200, CAP)
        manipulated = asert_target(ANCHOR, 1_000_000, 1_001_000,
                                   1, 80, 10, 7200, CAP)
        self.assertGreaterEqual(manipulated, baseline)
        self.assertFalse(q4_atomic_renew(old, replacement, 1001, True, True))
        # A target change never grants renewed lease eligibility.
        self.assertTrue(1 <= manipulated <= CAP)

    def test_legacy_factor_four_envelope_is_not_chainwork_credit(self):
        """The x4 clamp weakens each next target, never rewards an invalid ticket."""
        target = ANCHOR
        for _ in range(5):
            successor = legacy_retarget(target, 0, 2000, 16, 10, CAP)
            self.assertEqual(successor, target * 4)
            self.assertLess((1 << 256) // (successor + 1),
                            (1 << 256) // (target + 1))
            target = successor

    def test_future_deferral_and_mtp_boundary_remain_distinct(self):
        parents = [120, 119, 118, 117, 116, 115, 114, 113, 112, 111, 110]
        median = mtp11(parents)
        self.assertFalse(valid_time(median, parents, now=200, skew=120))
        self.assertTrue(valid_time(median + 1, parents, now=200, skew=120))
        self.assertTrue(valid_time(320, parents, now=200, skew=120))
        self.assertFalse(valid_time(321, parents, now=200, skew=120))


if __name__ == "__main__":
    unittest.main()
