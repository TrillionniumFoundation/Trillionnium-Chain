"""Budget boundaries, literal winner sets and complete paid failure denominators."""
from dataclasses import replace
from fractions import Fraction
from pathlib import Path
import copy
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "experiments"))

import w1_marked_domain_campaign as campaign
from quantum_adversarial_search import TrialCosts
from w1_bounded_search import PHASES, simulate_bounded_measurements
from w1_marked_domain import enumerate_domain, simulate_measurements


def fraction(value):
    return Fraction(value["numerator"], value["denominator"])


class BoundedLiteralSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        template = campaign.with_parameters(campaign.retained.reduced_template(), 1)
        cls.full = enumerate_domain(template)
        cls.empty = enumerate_domain(campaign.with_parameters(template, 1, target=1))
        cls.other_empty = enumerate_domain(campaign.with_parameters(template, 1, target=1, profile="PGH2"))
        cls.mixed_phase = enumerate_domain(campaign.with_parameters(template, 3))
        cls.cost = TrialCosts(2, 3, 5, 7, 11, 13, "upward")
        assert cls.full["domain_size"] == cls.full["marked_count"] == 2
        assert cls.full["prefix_restricted_marked_count"] == 0
        assert cls.empty["marked_count"] == cls.other_empty["marked_count"] == 0

    def run_full(self, deadline, **kwargs):
        return simulate_bounded_measurements(
            (self.full,), ((0, 2), (0, 2)), 2, 9, (self.cost,), str(deadline),
            propagation_seconds=(17,), **kwargs)

    def test_zero_horizon_starts_no_work(self):
        result = self.run_full(0)
        self.assertEqual(result["termination"], "horizon")
        self.assertEqual(result["trials"], [])
        self.assertEqual(result["domain_setup_charges"], 0)
        self.assertEqual(result["unstarted_predeclared_trials"], 2)
        self.assertEqual(fraction(result["elapsed_seconds_exact"]), 0)

    def test_every_incomplete_phase_retains_paid_cost_without_delivery(self):
        for deadline, phase in ((5, "domain_setup"), (14, "prepare"), (19, "iterations"),
                                (25, "measurement"), (33, "candidate_checks"),
                                (50, "proof"), (67, "propagation")):
            with self.subTest(deadline=deadline):
                result = self.run_full(deadline)
                self.assertEqual(result["termination"], "horizon")
                self.assertFalse(result["success"])
                self.assertEqual(result["trials"][0]["censored_phase"], phase)
                self.assertEqual(fraction(result["elapsed_seconds_exact"]), deadline)
                self.assertEqual(sum(map(fraction, result["phase_paid_seconds_exact"].values())), deadline)
                self.assertEqual(result["unstarted_predeclared_trials"], 1)

    def test_partial_iteration_costs_every_processor_but_is_not_completed_query(self):
        result = self.run_full(19)
        trial = result["trials"][0]
        self.assertEqual(trial["grover_iterations_completed_per_processor"], 1)
        self.assertEqual(fraction(trial["partial_iteration_seconds_exact"]), 1)
        self.assertEqual(result["grover_iterations_completed_all_processors"], 2)
        self.assertEqual(fraction(result["quantum_processor_seconds_exact"]), 2 * (2 + 4))
        self.assertTrue(result["partial_iteration_time_is_not_partial_gate_execution"])

    def test_no_measurement_draw_or_candidate_before_complete_readout(self):
        with patch("w1_bounded_search.sample_binary_probability", side_effect=AssertionError("premature draw")):
            result = self.run_full(25)
        self.assertEqual(result["completed_measurement_batches"], 0)
        self.assertEqual(result["candidate_checks_completed"], 0)
        self.assertEqual(result["trials"][0]["measurements"], [])

    def test_readout_boundary_does_not_grant_unchecked_winner(self):
        result = self.run_full(26)
        trial = result["trials"][0]
        self.assertEqual(result["completed_measurement_batches"], 1)
        self.assertEqual(len(trial["measurements"]), 2)
        self.assertTrue(all(row["winner"] is None for row in trial["measurements"]))
        self.assertFalse(trial["verified_winner_observed"])
        self.assertFalse(trial["proof_complete"])

    def test_partial_serial_checks_reveal_only_completed_candidates(self):
        result = self.run_full(35)
        trial = result["trials"][0]
        self.assertEqual(trial["candidate_checks_completed"], 1)
        self.assertEqual(fraction(trial["partial_candidate_check_seconds_exact"]), 2)
        self.assertTrue(trial["measurements"][0]["winner"])
        self.assertIsNone(trial["measurements"][1]["winner"])
        self.assertTrue(trial["verified_winner_observed"])
        self.assertFalse(trial["proof_complete"])
        self.assertFalse(result["success"])

    def test_proof_and_propagation_have_separate_completion_boundaries(self):
        result = self.run_full(51)
        trial = result["trials"][0]
        self.assertTrue(trial["proof_complete"])
        self.assertFalse(trial["propagation_complete"])
        self.assertFalse(result["success"])
        self.assertEqual(fraction(result["phase_paid_seconds_exact"]["proof"]), 11)
        self.assertEqual(fraction(result["phase_paid_seconds_exact"]["propagation"]), 0)

    def test_complete_delivery_at_exact_horizon_is_allowed_once(self):
        result = self.run_full(68)
        self.assertEqual(result["termination"], "delivered")
        self.assertTrue(result["success"])
        self.assertEqual(result["trials_started"], 1)
        self.assertEqual(result["candidate_checks_completed"], 2)
        self.assertEqual(fraction(result["quantum_processor_seconds_exact"]), 2 * (2 + 6 + 5))
        self.assertEqual(result["native_blocks_admitted"], 0)

    def test_unused_time_is_explicit_and_duplicate_winners_are_not_blocks(self):
        result = self.run_full(100)
        self.assertEqual(fraction(result["unused_horizon_seconds_exact"]), 32)
        self.assertEqual(sum(row["winner"] for row in result["trials"][0]["measurements"]), 2)
        self.assertEqual(fraction(result["phase_paid_seconds_exact"]["proof"]), 11)
        self.assertEqual(fraction(result["phase_paid_seconds_exact"]["propagation"]), 17)

    def test_legal_unmarked_candidates_succeed_with_empty_restricted_phase_set(self):
        result = self.run_full(68, predicate="prefix-restricted")
        trial = result["trials"][0]
        self.assertEqual(trial["evaluator_marked_count"], 0)
        self.assertEqual(trial["evaluator_legal_winner_count"], 2)
        self.assertEqual(trial["conditional_batch_phase_mark_probability"], 0)
        self.assertEqual(trial["conditional_batch_valid_candidate_probability"], 1)
        self.assertTrue(result["success"])

    def test_restricted_predicate_cannot_borrow_full_phase_probability(self):
        result = simulate_bounded_measurements(
            (self.mixed_phase,), ((0, 0),), 1, 4, (self.cost,), "100", predicate="prefix-restricted")
        trial = result["trials"][0]
        self.assertEqual(trial["evaluator_marked_count"], 2)
        self.assertEqual(trial["evaluator_legal_winner_count"], 8)
        self.assertEqual(trial["conditional_batch_phase_mark_probability"], .25)
        self.assertEqual(trial["conditional_batch_valid_candidate_probability"], 1)
        self.assertTrue(result["success"])

    def test_empty_legal_domain_remains_empty_across_paid_retries(self):
        result = simulate_bounded_measurements(
            (self.empty,), ((0, 0), (0, 1), (0, 2)), 2, 8, (self.cost,), "1000")
        self.assertEqual(result["termination"], "schedule-exhausted")
        self.assertFalse(result["success"])
        self.assertEqual(result["domain_setup_charges"], 1)
        self.assertEqual(result["candidate_checks_completed"], 6)
        self.assertEqual(fraction(result["elapsed_seconds_exact"]), 13 + 3 * (2 + 5 + 14) + 9)
        self.assertEqual(fraction(result["phase_paid_seconds_exact"]["proof"]), 0)

    def test_single_resident_setup_reuse_eviction_and_revisit_are_paid(self):
        result = simulate_bounded_measurements(
            (self.empty, self.other_empty), ((0, 0), (0, 0), (1, 0), (0, 0)),
            1, 5, (self.cost, replace(self.cost, domain_setup_seconds=19)), "1000")
        self.assertEqual([row["domain_setup_charged"] for row in result["trials"]], [True, False, True, True])
        self.assertEqual(fraction(result["phase_paid_seconds_exact"]["domain_setup"]), 13 + 19 + 13)

    def test_exact_retry_boundary_does_not_start_another_trial(self):
        result = simulate_bounded_measurements(
            (self.empty,), ((0, 0), (0, 1)), 1, 5, (self.cost,), "27")
        self.assertEqual(result["trials_started"], 1)
        self.assertEqual(result["termination"], "horizon")
        self.assertEqual(result["trials"][0]["censored_phase"], None)
        self.assertEqual(result["candidate_checks_completed"], 1)

    def test_zero_duration_proof_can_finish_after_checks_at_deadline(self):
        cost = TrialCosts(0, 1, 5, 7, 0, 0, "upward")
        result = simulate_bounded_measurements((self.full,), ((0, 0),), 1, 2, (cost,), "12")
        self.assertTrue(result["success"])
        self.assertTrue(result["trials"][0]["proof_complete"])

    def test_decimal_deadline_does_not_round_up_to_binary64_cost(self):
        cost = TrialCosts(0, 1, 1, .1, 0, 0, "upward")
        result = simulate_bounded_measurements((self.full,), ((0, 0),), 1, 2, (cost,), "1.1")
        self.assertFalse(result["success"])
        self.assertEqual(result["candidate_checks_completed"], 0)
        self.assertEqual(result["trials"][0]["censored_phase"], "candidate_checks")
        self.assertEqual(fraction(result["elapsed_seconds_exact"]), Fraction(11, 10))

    def test_completed_full_predicate_schedule_matches_legacy_sampling_and_costs(self):
        legacy = simulate_measurements((self.empty,), ((0, 0), (0, 2)), 2, 4, self.cost)
        bounded = simulate_bounded_measurements((self.empty,), ((0, 0), (0, 2)), 2, 4, (self.cost,), "1000")
        self.assertEqual(fraction(bounded["elapsed_seconds_exact"]), fraction(legacy["elapsed_assumed_seconds_exact"]))
        self.assertEqual([[x["nonce"] for x in row["measurements"]] for row in bounded["trials"]],
                         [[x["nonce"] for x in row["measurements"]] for row in legacy["trials"]])

    def test_census_membership_hash_and_scope_mutations_are_recomputed(self):
        for mutate in (lambda row: row.update(marked_count=0),
                       lambda row: row["outcomes"][0].update(winner=False),
                       lambda row: row.update(domain_sha256="0" * 64)):
            forged = copy.deepcopy(self.full)
            mutate(forged)
            with self.assertRaisesRegex(ValueError, "CENSUS_REPLAY_MISMATCH"):
                simulate_bounded_measurements((forged,), ((0, 0),), 1, 2, (self.cost,), "100")

    def test_invalid_plan_refuses_before_any_census_execution(self):
        valid = dict(domains=(self.full,), schedule=((0, 0),), processors=1,
                     seed=2, costs=(self.cost,), horizon_seconds="100")
        changes = ({"horizon_seconds": 100}, {"horizon_seconds": "NaN"},
                   {"horizon_seconds": "Infinity"}, {"horizon_seconds": "-1"},
                   {"horizon_seconds": "1e-101"}, {"horizon_seconds": "1e31"},
                   {"processors": True}, {"schedule": ((0, True),)},
                   {"schedule": ((1, 0),)}, {"costs": self.cost},
                   {"predicate": "approximate"}, {"propagation_seconds": (True,)})
        with patch("w1_bounded_search.replay_domain", side_effect=AssertionError("unexpected census")):
            for change in changes:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    simulate_bounded_measurements(**{**valid, **change})

    def test_replay_determinism_plan_identity_and_qualification_boundary(self):
        result = self.run_full(68)
        self.assertEqual(result, self.run_full(68))
        self.assertNotEqual(result["plan_sha256"], self.run_full(69)["plan_sha256"])
        self.assertEqual(set(result["phase_paid_seconds_exact"]), set(PHASES))
        for key in ("strategy_reads_marked_count", "independent_ticket_prior_used",
                    "quantum_hardware_executed", "physical_clock_calibrated",
                    "consensus_security_theorem", "attacker_optimality_proved",
                    "production_consensus_activation"):
            self.assertIs(result[key], False)


if __name__ == "__main__":
    unittest.main()
