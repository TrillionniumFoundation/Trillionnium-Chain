#!/usr/bin/env python3
"""Independent state-vector, probability-enumeration and endpoint controls."""
from decimal import Decimal, localcontext
from fractions import Fraction
import itertools
import json
import math
import random
import unittest

import quantum_stopping as q


def integrate_exponential(rate, duration):
    return duration if rate == 0 else -math.expm1(-rate * duration) / rate


def completion_distribution(stop, budget):
    """Direct finite K distribution plus the entire later-completion tail."""
    first = (Fraction(stop.context_setup_seconds) + Fraction(stop.attempt_seconds)
             + Fraction(stop.winning_witness_publication_seconds))
    at, survival, outcomes = first, 1.0, []
    while at <= Fraction(budget):
        outcomes.append((at, survival * stop.success_probability))
        survival *= 1 - stop.success_probability
        at += Fraction(stop.attempt_seconds)
    outcomes.append((None, survival))
    return outcomes


def enumerate_race(stops, budget, rate):
    """Enumerate independent K tuples; no event queue or survival segments."""
    wins, spent, expiry, ties = [0.0] * len(stops), 0.0, 0.0, 0.0
    distributions = [completion_distribution(stop, budget) for stop in stops]
    for outcomes in itertools.product(*distributions):
        probability = math.prod(value[1] for value in outcomes)
        finite = [value[0] for value in outcomes if value[0] is not None]
        at = min(finite) if finite else None
        duration = budget if at is None else float(at)
        spent += probability * integrate_exponential(rate, duration)
        surviving_external = math.exp(-rate * duration)
        if at is None:
            expiry += probability * surviving_external
        else:
            chosen = [i for i, value in enumerate(outcomes) if value[0] == at]
            for index in chosen:
                wins[index] += probability * surviving_external / len(chosen)
            if len(chosen) > 1:
                ties += probability * surviving_external
    return wins, spent, expiry, ties


class FiniteDomain(unittest.TestCase):
    def test_success_against_dense_state_vector_all_small_marked_sets(self):
        cases = 0
        for bits in range(1, 6):
            size = 1 << bits
            for marked in range(size + 1):
                state = [1 / math.sqrt(size)] * size
                for iterations in range(17):
                    actual = sum(amplitude * amplitude for amplitude in state[:marked])
                    self.assertAlmostEqual(q.grover_success(bits, marked, iterations), actual, delta=2e-13)
                    state = [-a if i < marked else a for i, a in enumerate(state)]
                    mean = sum(state) / size
                    state = [2 * mean - a for a in state]
                    cases += 1
        self.assertEqual(cases, 1139)

    def test_nearly_full_64_bit_domain_does_not_round_to_full(self):
        size, iterations = 1 << 64, 1 << 31
        broken = math.sin((2 * iterations + 1) * math.asin(math.sqrt((size - 1) / size))) ** 2
        with localcontext() as context:
            context.prec = 80
            x = Decimal(1) / (Decimal(2) ** 32)
            # Remaining asin terms affect the final phase by less than 1e-56.
            phase = (2 * iterations + 1) * (x + x ** 3 / 6 + 3 * x ** 5 / 40)
            cosine, term = Decimal(1), Decimal(1)
            for index in range(1, 45):
                term *= -(phase * phase) / ((2 * index - 1) * (2 * index))
                cosine += term
            expected = float(cosine * cosine)
        self.assertGreater(abs(broken - expected), 0.7)
        self.assertAlmostEqual(q.grover_success(64, size - 1, iterations), expected, delta=2e-15)

    def test_empty_domain_requires_independent_marking_assumption(self):
        self.assertEqual(q.empty_domain_probability(64, 0), 1)
        self.assertEqual(q.empty_domain_probability(64, 1), 0)
        self.assertAlmostEqual(q.empty_domain_probability(64, 2.0 ** -64), math.exp(-1), delta=1e-15)
        self.assertAlmostEqual(q.empty_domain_probability(3, 0.25), (3 / 4) ** 8, delta=1e-15)
        self.assertEqual(q.grover_success(64, 0, 10), 0)
        self.assertEqual(q.grover_success(64, 1 << 64, 10), 1)

    def test_large_accumulated_angle_is_rejected_for_all_marked_fractions(self):
        for iterations, minimum_error in (((1 << 52) - 1, 0.4), (1 << 40, 1e-5)):
            broken = math.sin((2 * iterations + 1) * math.asin(math.sqrt(0.5))) ** 2
            self.assertGreater(abs(broken - 0.5), minimum_error)
            with self.assertRaisesRegex(q.Reject, "PHASE_OUTSIDE_NUMERIC_DOMAIN"):
                q.grover_success(1, 1, iterations)
        # Restrict every large phase, including nonsymmetric and tiny fractions.
        for bits, marked in ((8, 31), (8, 225), (64, 1), (64, (1 << 64) - 1)):
            with self.assertRaisesRegex(q.Reject, "PHASE_OUTSIDE_NUMERIC_DOMAIN"):
                q.grover_success(bits, marked, 1 << 40)
        self.assertGreaterEqual(q.grover_success(1, 1, 40), 0)
        with self.assertRaises(q.Reject):
            q.grover_success(1, 1, 41)


class CampaignArithmetic(unittest.TestCase):
    def test_five_thousand_independent_K_enumerations(self):
        rng = random.Random(20261027)
        for _ in range(5000):
            stop = q.FixedStop(rng.choice([0, 0.01, 0.25, 0.5, 0.75, 1]),
                               rng.randint(1, 16) / 8, rng.randint(0, 16) / 8,
                               rng.randint(0, 16) / 8)
            budget = rng.randint(1, 64) / 4
            rate = rng.choice([0, 1e-6, 0.125, 1, 8])
            got = q.campaign(stop, rate, budget)
            wins, spent, expiry, _ = enumerate_race([stop], budget, rate)
            self.assertAlmostEqual(got["win_probability"], wins[0], delta=2e-13)
            self.assertAlmostEqual(got["expected_context_seconds"], spent, delta=3e-12)
            self.assertAlmostEqual(got["budget_expiry_probability"], expiry, delta=2e-13)
            self.assertAlmostEqual(got["win_probability"] + got["external_tip_probability"]
                                   + got["budget_expiry_probability"], 1, delta=3e-13)

    def test_zero_marked_no_tip_and_unbounded_does_not_fake_termination(self):
        got = q.campaign(q.FixedStop(0, 1))
        self.assertIsNone(got["expected_context_seconds"])
        self.assertEqual(got["win_probability"], 0)
        self.assertEqual(got["nontermination_probability"], 1)
        self.assertEqual(got["reward_per_expected_second"], 0)
        interrupted = q.campaign(q.FixedStop(0, 1), 0.25)
        self.assertEqual(interrupted["expected_context_seconds"], 4)
        self.assertEqual(interrupted["external_tip_probability"], 1)

    def test_no_tip_analytic_mean_includes_all_costs(self):
        for p in (1, 0.25, 2.0 ** -64):
            got = q.campaign(q.FixedStop(p, 2, 3, 5))
            self.assertAlmostEqual(got["win_probability"], 1, delta=2e-15)
            self.assertAlmostEqual(got["expected_context_seconds"] / (3 + 2 / p + 5), 1, delta=2e-15)
        stop = q.FixedStop(0.25, 2, 3, 5)
        for rate in (1e-9, 0.25, 1, 20):
            got = q.campaign(stop, rate)
            self.assertAlmostEqual(got["win_probability"] + rate * got["expected_context_seconds"], 1, delta=2e-15)

    def test_budget_boundaries_do_not_accept_partial_winning_tail(self):
        stop = q.FixedStop(1, 1, 0.5, 0.5)
        before = q.campaign(stop, 0, math.nextafter(2.0, -math.inf))
        at = q.campaign(stop, 0, 2.0)
        after = q.campaign(stop, 0, math.nextafter(2.0, math.inf))
        self.assertEqual(before["win_probability"], 0)
        self.assertEqual(before["budget_expiry_probability"], 1)
        self.assertEqual(at["win_probability"], 1)
        self.assertEqual(after["win_probability"], 1)
        # Input float .3 is genuinely earlier than three exact input float .1s.
        exact_binary = q.campaign(q.FixedStop(0.5, 0.1), 0, 0.3)
        self.assertEqual(exact_binary["completed_attempt_opportunities"], 2)
        during_setup = q.campaign(stop, 1, 0.25)
        self.assertEqual(during_setup["win_probability"], 0)
        self.assertAlmostEqual(during_setup["expected_context_seconds"], 1 - math.exp(-0.25))

    def test_interruptions_apply_during_success_witness_publication(self):
        stop = q.FixedStop(1, 1, 0, 4)
        got = q.campaign(stop, 0.25)
        self.assertAlmostEqual(got["win_probability"], math.exp(-1.25))
        self.assertAlmostEqual(got["expected_context_seconds"], (1 - math.exp(-1.25)) / 0.25)
        self.assertGreater(q.campaign(q.FixedStop(1, 1), 0.25)["win_probability"], got["win_probability"])

    def test_tiny_success_probability_retains_accumulated_failures(self):
        p = 2.0 ** -64
        self.assertEqual((1 - p) ** (1 << 64), 1)
        got = q.campaign(q.FixedStop(p, 1), 0, float(1 << 64))
        self.assertAlmostEqual(got["budget_expiry_probability"], math.exp(-1), delta=2e-15)
        self.assertAlmostEqual(got["win_probability"], 1 - math.exp(-1), delta=2e-15)
        self.assertAlmostEqual(got["expected_context_seconds"] / (1 << 64), 1 - math.exp(-1), delta=2e-15)

    def test_zero_iterations_still_pay_measurement_and_classical_check(self):
        timing = q.Timing(1, 2, 3, 4)
        stop = q.search_stop(8, 64, 0, timing)
        self.assertEqual(stop.attempt_seconds, 2)
        self.assertAlmostEqual(stop.success_probability, 0.25)
        self.assertAlmostEqual(q.campaign(stop)["expected_context_seconds"], 15)


class CompetingWorkers(unittest.TestCase):
    def test_classical_competition_and_zero_quantum_power_endpoint(self):
        got = q.poisson_classical_race(0.25, [0.5, 0.5])
        self.assertEqual(got["own_win_probability"], 0.2)
        self.assertEqual(got["competing_win_probability"], 0.8)
        self.assertEqual(got["expected_context_seconds"], 0.8)
        none = q.poisson_classical_race(0, [0.5, 0.5])
        self.assertEqual(none["own_win_probability"], 0)
        self.assertEqual(none["competing_win_probability"], 1)
        bounded = q.poisson_classical_race(0, [], 2)
        self.assertEqual(bounded["budget_expiry_probability"], 1)
        self.assertEqual(bounded["expected_context_seconds"], 2)

    def test_one_worker_event_model_reduces_to_closed_form(self):
        for p, rate, budget in itertools.product((0, 0.1, 1), (0, 0.25, 2), (0.25, 1, 3, 10)):
            stop = q.FixedStop(p, 0.5, 0.25, 0.25)
            closed, events = q.campaign(stop, rate, budget), q.fixed_stop_race([stop], budget, rate)
            self.assertAlmostEqual(events["worker_win_probabilities"][0], closed["win_probability"], delta=1e-14)
            for key in ("external_tip_probability", "budget_expiry_probability", "expected_context_seconds"):
                self.assertAlmostEqual(events[key], closed[key], delta=2e-13)

    def test_simultaneous_winners_have_explicit_research_tie_rule(self):
        got = q.fixed_stop_race([q.FixedStop(0.5, 1)] * 2, 2)
        self.assertEqual(got["worker_win_probabilities"], [0.46875, 0.46875])
        self.assertEqual(got["budget_expiry_probability"], 0.0625)
        self.assertEqual(got["expected_context_seconds"], 1.25)
        unequal = q.fixed_stop_race([q.FixedStop(0.2, 1), q.FixedStop(0.6, 1)], 1)
        self.assertAlmostEqual(unequal["worker_win_probabilities"][0], 0.14)
        self.assertAlmostEqual(unequal["worker_win_probabilities"][1], 0.54)
        self.assertAlmostEqual(unequal["budget_expiry_probability"], 0.32)

    def test_multiplayer_events_against_independent_geometric_tuple_enumeration(self):
        rng = random.Random(180903671)
        for _ in range(120):
            stops = [q.FixedStop(rng.choice([0, 0.2, 0.5, 1]), rng.randint(1, 4) / 2,
                                rng.randint(0, 2) / 2, rng.randint(0, 2) / 2)
                     for _ in range(rng.randint(2, 4))]
            budget, rate = rng.randint(1, 10) / 2, rng.choice([0, 0.1, 1])
            actual = q.fixed_stop_race(stops, budget, rate)
            wins, spent, expiry, ties = enumerate_race(stops, budget, rate)
            for actual_win, expected_win in zip(actual["worker_win_probabilities"], wins):
                self.assertAlmostEqual(actual_win, expected_win, delta=2e-13)
            self.assertAlmostEqual(actual["expected_context_seconds"], spent, delta=2e-12)
            self.assertAlmostEqual(actual["budget_expiry_probability"], expiry, delta=2e-13)
            self.assertAlmostEqual(actual["simultaneous_success_probability"], ties, delta=2e-13)


class ModelBoundaries(unittest.TestCase):
    def test_rejects_invalid_parameters_and_explicit_event_budget(self):
        for value in (-1, math.inf, math.nan, True):
            with self.assertRaises(q.Reject):
                q.Timing(value, 1)
            with self.assertRaises(q.Reject):
                q.campaign(q.FixedStop(0.5, 1), value)
        for p in (-0.1, 1.1, math.nan):
            with self.assertRaises(q.Reject):
                q.FixedStop(p, 1)
        for bits, marked, iterations in ((0, 0, 0), (65, 0, 0), (4, 17, 0), (4, 1, -1), (4, True, 1)):
            with self.assertRaises(q.Reject):
                q.grover_success(bits, marked, iterations)
        with self.assertRaises(q.Reject):
            q.Timing(1, 0)
        with self.assertRaisesRegex(q.Reject, "EVENT_BUDGET"):
            q.fixed_stop_race([q.FixedStop(0.5, 1)], 10001)
        with self.assertRaisesRegex(q.Reject, "DECLARED_STOP_SEARCH"):
            q.best_first_peak(64, 1, q.Timing(1, 1))
        with self.assertRaises(q.Reject):
            q.campaign(q.FixedStop(0.5, 1), 0, 0)

    def test_linear_scaled_full_costs_leave_uninterrupted_weight_rate_flat(self):
        base = q.Timing(0.1, 0.2, 0.3, 0.4)
        initial = q.best_first_peak(16, 256, base)["reward_per_expected_second"]
        for multiplier in (4, 16, 64):
            scaled = q.Timing(*(value * multiplier for value in (
                base.oracle_and_diffusion_seconds, base.measure_check_restart_seconds,
                base.context_setup_seconds, base.winning_witness_publication_seconds)))
            got = q.best_first_peak(16, 256, scaled)
            self.assertAlmostEqual(multiplier * got["reward_per_expected_second"], initial, delta=1e-13)

    def test_report_retains_assumptions_and_does_not_claim_physical_security(self):
        value = q.report()
        self.assertEqual(len(value["difficulty_vs_work_comparison"]), 45)
        self.assertEqual(len(value["two_worker_fixed_stop_examples"]), 4)
        for key in ("native_W1_executed_by_this_model", "full_clean_W1_plus_diffusion_time_measured",
                    "relative_rate_r_0_25_measured", "difficulty_retarget_or_protocol_semantics_changed",
                    "production_activation", "quantum_security_qualified"):
            self.assertFalse(value["scope"][key])
        self.assertTrue(all(t > 0 for t in value["timing_seconds_assumptions"].values()))
        linear = [row for row in value["difficulty_vs_work_comparison"]
                  if row["candidate"] == "fixed_fraction_linear_oracle"
                  and row["external_tip_rate_assumption"] == 0]
        for row in linear:
            self.assertAlmostEqual(row["relative_weight_per_second"], linear[0]["relative_weight_per_second"], delta=1e-13)
        omitted = value["oracle_only_scaling_negative_control"]
        self.assertEqual(omitted["best_declared_stop"]["iterations"], 0)
        self.assertFalse(omitted["valid_work_scaling_conclusion"])
        json.dumps(value, allow_nan=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
