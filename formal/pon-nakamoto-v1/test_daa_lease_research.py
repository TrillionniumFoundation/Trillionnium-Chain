"""Standalone independent integer/security-boundary tests, NOT real PoN acceptance."""
import json
import unittest
from daa_research_oracle import (
    Lease, asert_target, legacy_retarget, mtp11, q4_atomic_renew,
    q4_slot_reclaimable, valid_time,
)
from daa_lease_campaign import (
    HALF_LIFE, INITIAL, TARGET_LIMIT, fabricated_endpoint_schedule,
    lease_scenarios, run_campaign, targets, workload_times,
)


class DaaReferenceTests(unittest.TestCase):
    def test_fixed_point_vectors(self):
        cap = (1 << 240) - 1
        a = 1 << 220
        vectors = [
            (0, 10, 1, 2, 10, 7200, "0000000010000000000000000000000000000000000000000000000000000000"),
            (0, 20, 1, 2, 10, 7200, "000000001003f000000000000000000000000000000000000000000000000000"),
            (0, 0, 1, 2, 10, 7200, "000000000ffc1000000000000000000000000000000000000000000000000000"),
            (0, 2000, 1, 80, 10, 7200, "0000000011fa7000000000000000000000000000000000000000000000000000"),
            (0, 800, 1, 80, 10, 7200, "000000001003f000000000000000000000000000000000000000000000000000"),
            (2000, 1800, 1, 100, 10, 3600, "000000000cb95000000000000000000000000000000000000000000000000000"),
            (0, 1 << 20, 1, 2, 10, 3600, "0000" + "f" * 60),
            (1 << 20, 0, 1, 2, 10, 3600, "0" * 63 + "1"),
        ]
        for before, at_parent, ah, h, tau, hl, expected in vectors:
            with self.subTest(height=h, observed=at_parent):
                self.assertEqual(format(asert_target(a, before, at_parent, ah, h,
                                                    tau, hl, cap), "064x"), expected)

    def test_legacy_exact_integer_boundaries(self):
        x = 1 << 220
        self.assertEqual(legacy_retarget(x, 0, 600, 16, 10, TARGET_LIMIT), x * 4)
        self.assertEqual(legacy_retarget(x, 0, 1, 16, 10, TARGET_LIMIT), x * 38 // 150)
        self.assertEqual(legacy_retarget(x, 500, 1, 16, 10, TARGET_LIMIT), x * 38 // 150)

    def test_reject_bad_asert_parameters(self):
        valid = (1 << 220, 0, 10, 1, 2, 10, 7200, TARGET_LIMIT)
        for change in ({"candidate_height": 1}, {"half_life": 0},
                       {"anchor_height": 0}, {"spacing": 0},
                       {"parent_time": -1}, {"anchor_target": 0},
                       {"anchor_target": TARGET_LIMIT + 1}):
            keys = ["anchor_target", "anchor_parent_time", "parent_time", "anchor_height",
                    "candidate_height", "spacing", "half_life", "pow_limit"]
            kwargs = dict(zip(keys, valid))
            kwargs.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                asert_target(**kwargs)

    def test_mtp_and_future_acceptance(self):
        self.assertEqual(mtp11([9, 1, 11]), 9)
        self.assertTrue(valid_time(10, [9, 1, 11], 0, 120))
        self.assertFalse(valid_time(9, [9, 1, 11], 200, 120))
        self.assertFalse(valid_time(121, [1, 2, 3], 0, 120))
        with self.assertRaises(ValueError):
            mtp11([])


class JointBoundaryTests(unittest.TestCase):
    def test_lease_signature_and_retention_negative_controls(self):
        self.assertTrue(all(lease_scenarios().values()))
        old = Lease(0, 1000, 1100, 1)
        new = Lease(800, 1400, 1500, 2)
        self.assertFalse(q4_atomic_renew(old, new, 1001, True, True))
        self.assertFalse(q4_slot_reclaimable(old, 1100, "revoked"))
        self.assertTrue(q4_slot_reclaimable(old, 1101, "revoked"))
        with self.assertRaises(ValueError):
            Lease(0, 1000, 1101, 1)

    def test_80_header_timewarp_is_not_80_valid_pow_proofs(self):
        times = fabricated_endpoint_schedule()
        self.assertEqual(len(times), 81)
        for h in range(1, 81):
            self.assertTrue(valid_time(times[h], list(reversed(times[:h])), 2000))
        curves = targets(times)
        # Existing retarget arithmetic permits 5 x4 clamps when far from pow_limit.
        for i, h in enumerate((16, 32, 48, 64, 80), 1):
            self.assertEqual(curves["legacy"][h], INITIAL * (4 ** i))
        self.assertLess(curves["asert_raw"][80], INITIAL * 2)
        self.assertLess(curves["asert_mtp"][80], INITIAL * 2)

    def test_steady_oscillating_and_shock_use_identical_headers(self):
        for mode in ("steady", "oscillating", "hashrate_shock"):
            times = workload_times(mode)
            curves = targets(times)
            self.assertEqual({len(xs) for xs in curves.values()}, {161})
            self.assertTrue(all(1 <= t <= TARGET_LIMIT for xs in curves.values() for t in xs))

    def test_report_preserves_unaccepted_boundaries(self):
        report = run_campaign()
        self.assertFalse(report["production_qualified"])
        self.assertFalse(report["selected_consensus_revision_changed"])
        self.assertEqual(report["native_w1_proofs"], 0)
        self.assertTrue(report["heavier_fork_still_preferred"])
        self.assertEqual(len(report["timewarp_checkpoints"]), 5)
        self.assertEqual(json.loads(json.dumps(report)), report)


if __name__ == "__main__":
    unittest.main()
