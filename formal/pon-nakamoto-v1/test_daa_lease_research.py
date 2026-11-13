"""Standalone independent integer/security-boundary tests, NOT real PoN acceptance."""
import json
import unittest
from daa_research_oracle import (
    Lease, asert_target, legacy_retarget, mtp11, q4_atomic_renew,
    q4_slot_reclaimable, valid_time,
)
from daa_lease_campaign import (
    HALF_LIFE, INITIAL, TARGET_LIMIT, fabricated_endpoint_schedule,
    half_life_sensitivity, lease_scenarios, partition_selection_toy,
    selfish_withholding_toy, source_outage_toy, stochastic_mining_path,
    run_campaign, targets, workload_times,
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

    def test_512_seeded_asert_extreme_shift_vectors_agree_with_native_contract(self):
        import hashlib
        MASK = (1 << 64) - 1
        state = 0x62b7_f30a_c985_1d4e
        def next_u64():
            nonlocal state
            state ^= (state << 13) & MASK
            state ^= state >> 7
            state ^= (state << 17) & MASK
            state &= MASK
            return state
        digest = hashlib.sha256()
        for i in range(512):
            height = 2 + next_u64() % 1000
            before = 1_000_000 + next_u64() % 100_000
            deviation = next_u64() % 100_000 - 50_000
            parent = before + (height - 1) * 10 + deviation
            if i % 17 == 0:
                parent = MASK
            if i % 19 == 0:
                parent = 0
            half_life = (3600, 7200, 14400, 28800, 1)[i % 5]
            result = asert_target(1 << 220, before, parent, 1, height,
                                  10, half_life, (1 << 240) - 1)
            digest.update(result.to_bytes(32, "big"))
        self.assertEqual(
            digest.hexdigest(),
            "6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97",
        )
        self.assertEqual(
            asert_target(1 << 220, 1000000, MASK, 1, 2, 10, 1, (1 << 240) - 1),
            (1 << 240) - 1,
        )
        self.assertEqual(asert_target(1 << 220, MASK, 0, 1, 2, 10, 1,
                                      (1 << 240) - 1), 1)

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
        self.assertFalse(q4_slot_reclaimable(old, 1100, "active"))
        self.assertTrue(q4_slot_reclaimable(old, 1101, "active"))
        with self.assertRaises(ValueError):
            q4_slot_reclaimable(old, 1101, "unknown")
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

    def test_same_inputs_four_half_lives(self):
        grid = half_life_sensitivity(workload_times("hashrate_shock"))
        self.assertEqual(list(grid), ["3600", "7200", "14400", "28800"])
        self.assertTrue(grid["3600"]["last_target_ratio_asert_raw"] >
                        grid["28800"]["last_target_ratio_asert_raw"])

    def test_withholding_toy_is_deterministic_not_security_evidence(self):
        for a in (0.0, 0.2, 0.3, 0.4, 1.0):
            left = selfish_withholding_toy(a, 0.5, 20000, 1256)
            self.assertEqual(left, selfish_withholding_toy(a, 0.5, 20000, 1256))
            self.assertEqual(left["claim"], "toy-only-no-DAA-network-or-actual-PoW")
        self.assertEqual(selfish_withholding_toy(0, 0.5, 20000, 1256)["accepted_attacker"], 0)
        self.assertEqual(selfish_withholding_toy(1, 0.5, 20000, 1256)["accepted_honest"], 0)

    def test_source_dropout_and_partition_do_not_invent_operator_proofs(self):
        self.assertTrue(source_outage_toy()["3_controllers_unavailable"]["genesis_maintenance_task_available"])
        self.assertFalse(source_outage_toy()["3_controllers_unavailable"]["leased_task_available"])
        self.assertEqual(partition_selection_toy()["selected"], "A")
        self.assertFalse(partition_selection_toy()["actual_heavier_fork_reorg"])

    def test_stochastic_target_feedback_validity_and_repeatability(self):
        for scenario in ("steady", "shock", "oscillating", "maintenance_dropout"):
            for algorithm in ("legacy", "asert_raw", "asert_mtp"):
                with self.subTest(scenario=scenario, algorithm=algorithm):
                    x = stochastic_mining_path(algorithm, scenario, 20261025, 160, 7200, 0.3)
                    self.assertEqual(x, stochastic_mining_path(
                        algorithm, scenario, 20261025, 160, 7200, 0.3))
                    self.assertEqual(x["complete_header_time_validations"], 160)
                    self.assertEqual(x["real_w1_proofs"], 0)
                    self.assertGreater(x["elapsed_seconds"], 0)
                    self.assertGreater(x["p95_interval_seconds"], 0)

    def test_stochastic_target_feedback_refuses_bad_inputs(self):
        for patch in ({"algorithm": "unknown"}, {"scenario": "unknown"},
                      {"attacker_timestamp_share": 1.2}, {"blocks": 0},
                      {"half_life": 0}, {"seed": -1}):
            args = {"algorithm": "legacy", "scenario": "steady", "seed": 33}
            args.update(patch)
            with self.subTest(args=args), self.assertRaises(ValueError):
                stochastic_mining_path(**args)

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
