"""Research-only branch-local DAA / lease-source-outage negative controls."""
from dataclasses import replace
import unittest
from daa_fork_outage_research import (
    ALGORITHMS, ForkSimulator, Parameters, required_work, simulate, campaign,
    INITIAL, POW_LIMIT,
)

class ForkOutageScreenTests(unittest.TestCase):
    def test_expected_chainwork_not_height_or_best_ticket(self):
        self.assertGreater(required_work(INITIAL), required_work(INITIAL * 4))
        self.assertGreater(12 * required_work(INITIAL), 13 * required_work(INITIAL * 4))
        for bad in (0, POW_LIMIT + 1):
            with self.assertRaises(ValueError):
                required_work(bad)

    def test_equal_work_heal_preserves_local_fork_choices_until_strictly_heavier(self):
        p = Parameters(seed=11, share_a=.5, task_outage_at=1000,
                       timestamp_policy_a="honest", timestamp_policy_b="honest")
        s = ForkSimulator(p)
        left = s.mine("A", 0)
        right = s.mine("B", 0)
        self.assertIsNotNone(left)
        self.assertIsNotNone(right)
        self.assertNotEqual(left, right)
        s.tip_a, s.tip_b = left, right
        self.assertEqual(s.blocks[left].chainwork, s.blocks[right].chainwork)
        s.heal()
        self.assertTrue(s.equal_work_tie_at_heal)
        self.assertEqual(s.heal_preferred, "tie-retained")
        self.assertNotEqual(s.tip_a, s.tip_b)
        self.assertEqual(s.reorg_removed, 0)
        self.assertFalse(s.tie_resolved_after_heal)
        s.verify_all()
        self.assertTrue(s.round("healed"))
        self.assertEqual(s.tip_a, s.tip_b)
        self.assertEqual(s.tie_resolution_rounds, 1)
        self.assertTrue(s.tie_resolved_after_heal)
        self.assertIn(s.heal_resolution_winner, ("A", "B"))
        self.assertEqual(s.reorg_removed, 1)
        self.assertTrue(s.report()["shared_tip_after_heal"])

    def test_equal_work_partition_without_successor_reports_nonconvergence(self):
        p = Parameters(seed=7, share_a=.5, max_clock_seconds=100,
                       timestamp_policy_a="honest", timestamp_policy_b="honest")
        s = ForkSimulator(p)
        a, b = s.mine("A", 0), s.mine("B", 0)
        s.tip_a, s.tip_b = a, b
        s.heal()
        s.wall = float(s.p.genesis_time + s.p.max_clock_seconds + 1)
        self.assertFalse(s.round("healed"))
        self.assertNotEqual(s.tip_a, s.tip_b)
        out = s.report()
        self.assertEqual(out["stop_reason"], "bounded_wall_window_exhausted")
        self.assertFalse(out["shared_tip_after_heal"])
        self.assertEqual(out["final_required_work_scope"], "local-A-only")
        self.assertEqual(out["partition_heal_preferred"], "tie-retained")
        self.assertFalse(out["tie_resolved_by_strict_work"])

    def test_strict_work_fork_heals_without_waiting_for_another_block(self):
        s = ForkSimulator(Parameters(seed=13, share_a=.5,
                          timestamp_policy_a="honest", timestamp_policy_b="honest"))
        a = s.mine("A", 0)
        b = s.mine("B", 0)
        heavier = s.mine("B", b)
        s.tip_a, s.tip_b = a, heavier
        self.assertGreater(s.blocks[heavier].chainwork, s.blocks[a].chainwork)
        s.heal()
        self.assertEqual(s.heal_preferred, "B")
        self.assertEqual(s.tip_a, heavier)
        self.assertEqual(s.tip_b, heavier)
        self.assertFalse(s.equal_work_tie_at_heal)
        self.assertEqual(s.reorg_removed, 1)
        s.verify_all()

    def test_seeded_forks_and_heal_replay_exactly(self):
        p = Parameters(seed=11)
        a, b = simulate(p), simulate(p)
        self.assertEqual(a, b)
        self.assertTrue(a["partition_healed"])
        self.assertGreater(a["losing_branch_blocks_removed"], 0)
        self.assertEqual(a["actual_w1_proofs"], 0)
        self.assertFalse(a["consensus_activated"])

    def test_lease_expiry_without_maintenance_stalls_explicitly(self):
        p = Parameters(task_outage_at=24, a_maintenance_fraction=0,
                       b_maintenance_fraction=0)
        out = simulate(p)
        self.assertTrue(out["terminal_stopped"])
        self.assertEqual(out["stop_reason"], "no_assumed_work_capacity")
        self.assertFalse(out["partition_healed"])
        self.assertEqual(out["simulated_blocks_produced"], 24)

    def test_explicit_maintenance_capacity_preserves_liveness_only_in_model(self):
        p = Parameters(task_outage_at=24, a_maintenance_fraction=.2,
                       b_maintenance_fraction=.2)
        out = simulate(p)
        self.assertTrue(out["lease_outage_reached"])
        self.assertTrue(out["partition_healed"])
        self.assertEqual(out["tip_height"] >= p.warmup_blocks, True)
        self.assertEqual(out["actual_w1_proofs"], 0)

    def test_no_miner_even_before_outage_is_not_invented(self):
        p = Parameters(task_outage_at=0, a_maintenance_fraction=0,
                       b_maintenance_fraction=0)
        out = simulate(p)
        self.assertEqual(out["simulated_blocks_produced"], 0)
        self.assertEqual(out["stop_reason"], "no_assumed_work_capacity")

    def test_all_algorithms_branch_local_and_replay(self):
        for algorithm in ALGORITHMS:
            for seed in (0, 1, 7):
                with self.subTest(algorithm=algorithm, seed=seed):
                    p = Parameters(algorithm=algorithm, seed=seed)
                    out = simulate(p)
                    self.assertGreater(out["tip_height"], 0)
                    self.assertGreater(int(out["final_required_work"]), 0)
                    self.assertNotEqual(out["partition_heal_preferred"], "none")
                    self.assertEqual(out["real_network_transmissions"], 0)

    def test_median_push_changes_measurements_without_changing_ledger_rule(self):
        p = Parameters(seed=23, algorithm="legacy16")
        x = simulate(replace(p, timestamp_policy_b="honest"))
        y = simulate(replace(p, timestamp_policy_b="endpoint_push"))
        self.assertNotEqual(x["final_target_ratio"], y["final_target_ratio"])
        self.assertGreaterEqual(y["timestamp_unavailable_attempts"], 0)

    def test_invalid_inputs_fail_closed(self):
        for p in (
            Parameters(share_a=0), Parameters(share_a=1),
            Parameters(algorithm="false"), Parameters(half_life=0),
            Parameters(warmup_blocks=0), Parameters(split_blocks=0),
            Parameters(timestamp_policy_b="peer-data"),
            Parameters(a_maintenance_fraction=1.1),
            Parameters(seed=-1), Parameters(max_clock_seconds=0),
        ):
            with self.subTest(p=p), self.assertRaises(ValueError):
                ForkSimulator(p)

    def test_campaign_has_frozen_bound_and_reproducible_digest(self):
        out = campaign()
        self.assertEqual(out["cases"], 3 * 3 * 4 * 2)
        self.assertEqual(out["cases_sha256"], campaign()["cases_sha256"])
        self.assertTrue(all(r["actual_w1_proofs"] == 0 for r in out["rows"]))
        self.assertFalse(out["qualification"]["production_daa"])

if __name__ == "__main__":
    unittest.main()
