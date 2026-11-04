"""Finite honest-rate arithmetic checks; no work packets or network traffic."""
from dataclasses import replace
from fractions import Fraction
import json
from pathlib import Path
import tempfile
import unittest

from honest_rate_model import (MAX_EVENTS, Phase, Profile, U256, confirmations,
                               floor_ns, load_profile, simulate, standard_cases)

PROFILE = Path(__file__).resolve().parents[2] / "config/pon/devnet-v1.json"


class HonestRateModelTest(unittest.TestCase):
    def setUp(self):
        self.profile = load_profile(PROFILE)

    def test_steady_profile_exact_spacing_work_and_censored_tail(self):
        result = simulate(self.profile, (Phase(7200, Fraction(1)),), 7200)
        self.assertEqual(len(result.events), 720)
        self.assertEqual(result.events[-1].elapsed, 7200)
        self.assertEqual(result.total_complete_attempt_budget, 1440)
        self.assertEqual(result.unfinished_hazard, 0)
        self.assertTrue(all(event.target == self.profile.initial_target for event in result.events))
        self.assertEqual(result.events[-1].chainwork, 1440)
        first, tail = confirmations(result, self.profile, (1800, 7199))
        self.assertEqual(first["included_height"], 180)
        self.assertEqual(first["confirmation_wait_ns_floor"], 60_000_000_000)
        self.assertEqual(first["depth_satisfied_elapsed_ns_floor"], first["work_satisfied_elapsed_ns_floor"])
        self.assertEqual(tail["status"], "pending_confirmation")
        self.assertIsNone(tail["confirmed_elapsed_ns_floor"])

    def test_rate_boundary_carries_half_completed_hazard(self):
        result = simulate(self.profile, (Phase(5, Fraction(1)), Phase(30, Fraction(2))), 30)
        self.assertEqual(result.events[0].elapsed, Fraction(15, 2))
        self.assertEqual(result.events[0].timestamp, self.profile.genesis_time + 7)
        self.assertEqual(result.total_complete_attempt_budget, 11)
        self.assertEqual(result.unfinished_hazard, Fraction(1, 2))

    def test_partial_work_survives_a_zero_rate_outage_without_free_progress(self):
        result = simulate(self.profile, (Phase(5, Fraction(1)), Phase(25, Fraction(0)),
                                         Phase(40, Fraction(1))), 40)
        self.assertEqual([event.elapsed for event in result.events], [30, 40])
        self.assertEqual(result.total_complete_attempt_budget, 4)
        self.assertEqual(result.unfinished_hazard, 0)

    def test_boundary_completion_precedes_next_phase_and_horizon_never_adds_an_event(self):
        result = simulate(self.profile, (Phase(10, Fraction(1)), Phase(20, Fraction(0))), 20)
        self.assertEqual([event.elapsed for event in result.events], [10])
        result = simulate(self.profile, (Phase(19, Fraction(1)),), 19)
        self.assertEqual([event.elapsed for event in result.events], [10])
        self.assertEqual(result.unfinished_hazard, Fraction(9, 10))

    def test_first_retarget_uses_prior_fifteen_intervals_including_genesis(self):
        result = simulate(self.profile, (Phase(160, Fraction(4)),), 160)
        self.assertEqual(result.events[14].elapsed, Fraction(75, 2))
        # Integer completion timestamps are 0..37; lower clamp ceil(150/4)=38.
        target = self.profile.initial_target * 38 // 150
        self.assertEqual(result.events[15].target, target)
        expected_elapsed = Fraction(75, 2) + Fraction(U256, target + 1) / (self.profile.baseline_rate * 4)
        self.assertEqual(result.events[15].elapsed, expected_elapsed)
        self.assertEqual(result.events[15].chainwork, 30 + U256 // (target + 1))

    def test_pow_limit_prevents_making_slow_initial_network_easier(self):
        result = simulate(self.profile, (Phase(7200, Fraction(1, 4)),), 7200)
        self.assertEqual(len(result.events), 180)
        self.assertEqual(result.events[-1].chainwork, 360)
        self.assertTrue(all(event.target == self.profile.pow_limit for event in result.events))
        marker = confirmations(result, self.profile, (2400,))[0]
        self.assertEqual(marker["confirmation_wait_ns_floor"], 240_000_000_000)

    def test_no_supply_is_finite_and_keeps_markers_pending(self):
        result = simulate(self.profile, (Phase(7200, Fraction(0)),), 7200)
        self.assertEqual(result.events, ())
        self.assertEqual(result.total_complete_attempt_budget, 0)
        marker = confirmations(result, self.profile, (0,))[0]
        self.assertEqual(marker["status"], "pending_inclusion")
        self.assertFalse(marker["finalized"] or marker["execution_authority"])

    def test_confirmation_conditions_can_arrive_separately(self):
        result = simulate(self.profile, (Phase(240, Fraction(4)), Phase(7200, Fraction(1))), 7200)
        # The rate change affects difficulty only at the next boundary. Include
        # markers before both the first harder target and the later easier one.
        markers = confirmations(result, self.profile, (30, 500, 600, 700))
        separated = [row for row in markers if row["depth_satisfied_elapsed_ns_floor"]
                     != row["work_satisfied_elapsed_ns_floor"]]
        self.assertTrue(separated)
        self.assertTrue(any(row["work_satisfied_elapsed_ns_floor"]
                            > row["depth_satisfied_elapsed_ns_floor"] for row in separated))
        self.assertTrue(any(row["work_satisfied_elapsed_ns_floor"]
                            < row["depth_satisfied_elapsed_ns_floor"] for row in separated))
        for row in separated:
            self.assertEqual(row["confirmed_elapsed_ns_floor"],
                             max(row["depth_satisfied_elapsed_ns_floor"], row["work_satisfied_elapsed_ns_floor"]))

    def test_phase_partition_without_rate_change_preserves_exact_trajectory(self):
        one = simulate(self.profile, (Phase(720, Fraction(1)),), 720)
        split = simulate(self.profile, (Phase(113, Fraction(1)), Phase(527, Fraction(1)),
                                        Phase(720, Fraction(1))), 720)
        self.assertEqual(one, split)

    def test_all_cases_share_time_but_disclose_distinct_attempt_budgets(self):
        cases = standard_cases()
        results = {name: simulate(self.profile, phases, 7200) for name, phases in cases.items()}
        self.assertEqual({result.horizon_seconds for result in results.values()}, {7200})
        self.assertEqual(results["steady"].total_complete_attempt_budget, 1440)
        self.assertEqual(results["fourfold_step_and_restore"].total_complete_attempt_budget, 2880)
        self.assertEqual(results["quarter_rate_and_restore"].total_complete_attempt_budget, 1080)
        self.assertEqual(results["outage_and_restore"].total_complete_attempt_budget, 1380)

    def test_strict_profile_and_finite_input_bounds(self):
        config = json.loads(PROFILE.read_text())
        for key, value in (("production_activation", True), ("not_mainnet", 1),
                           ("retarget_factor", True), ("retarget_interval", 32),
                           ("initial_target_hex", "+" + config["initial_target_hex"]),
                           ("confirmation_depth", False)):
            with self.subTest(key=key):
                changed = dict(config, **{key: value})
                with self.assertRaises(ValueError):
                    Profile.from_config(changed)
        for phases, horizon in (((Phase(10, Fraction(1)),), True),
                                ((Phase(9, Fraction(1)),), 10),
                                ((Phase(10, Fraction(1)), Phase(9, Fraction(1))), 10),
                                ((Phase(10, Fraction(-1)),), 10),
                                ((Phase(10, Fraction(5)),), 10),
                                ((Phase(10, 1),), 10)):
            with self.subTest(phases=phases, horizon=horizon), self.assertRaises(ValueError):
                simulate(self.profile, phases, horizon)
        with self.assertRaisesRegex(ValueError, "GENESIS_TIME"):
            simulate(replace(self.profile, genesis_time=1 << 64), (Phase(10, Fraction(1)),), 10)
        self.assertLess(MAX_EVENTS, 100_000)
        self.assertEqual(floor_ns(Fraction(1, 3)), 333_333_333)

    def test_profile_reader_refuses_duplicate_nonfinite_and_oversized_inputs(self):
        for text in ('{"schema":"pon-devnet-2","schema":"pon-devnet-2"}',
                     '{"schema":NaN}', ' ' * 65_537):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "profile.json"
                path.write_text(text)
                with self.assertRaises(ValueError):
                    load_profile(path)


if __name__ == "__main__":
    unittest.main()
