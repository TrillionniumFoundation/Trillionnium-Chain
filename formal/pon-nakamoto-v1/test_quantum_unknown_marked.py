#!/usr/bin/env python3
"""Independent state-vector and terminal-path checks for the M-blind policy."""
from decimal import Decimal, localcontext
from fractions import Fraction
import inspect
import json
import math
import random
import unittest

import quantum_stopping as known
import quantum_unknown_marked as q


def enumerate_terminal_paths(bits, marked, timing, draw, windows, rate):
    """Direct j-sequence enumeration, then an exponential race on each terminal.

    Does not use stage moments, recurrence or the implementation's survival
    composition. Small domains use dense amplitude updates for every j.
    """
    size, probabilities = 1 << bits, []
    state = [1 / math.sqrt(1 << bits)] * (1 << bits)
    for _ in range(max(windows)):
        probabilities.append(math.fsum(a * a for a in state[:marked]))
        state = [-value if i < marked else value for i, value in enumerate(state)]
        mean = math.fsum(state) / size
        state = [2 * mean - value for value in state]
    wins, exhaustion, elapsed, queries, draws = [], [], [], [], []

    def add_terminal(mass, when, won):
        survival = math.exp(-rate * when)
        (wins if won else exhaustion).append(mass * survival)
        elapsed.append(mass * (when if rate == 0 else -math.expm1(-rate * when) / rate))

    def walk(index, mass, elapsed_time, query_count):
        if index == len(windows):
            add_terminal(mass, elapsed_time, False)
            queries.append(mass * query_count)
            draws.append(mass * index)
            return
        window = windows[index]
        for j in range(window):
            p = probabilities[j]
            weighted = mass / window
            when = elapsed_time + draw + timing.measure_check_restart_seconds + j * timing.oracle_and_diffusion_seconds
            add_terminal(weighted * p, when + timing.winning_witness_publication_seconds, True)
            queries.append(weighted * p * (query_count + j))
            draws.append(weighted * p * (index + 1))
            walk(index + 1, weighted * (1 - p), when, query_count + j)

    walk(0, 1.0, timing.context_setup_seconds, 0)
    return dict(win=math.fsum(wins), exhausted=math.fsum(exhaustion),
                elapsed=math.fsum(elapsed), queries=math.fsum(queries), draws=math.fsum(draws))


class UnknownMarkedPolicy(unittest.TestCase):
    def test_policy_has_no_marked_count_and_exact_rational_growth(self):
        self.assertEqual(list(inspect.signature(q.expanding_windows).parameters),
                         ["nonce_bits", "window_cap"])
        self.assertEqual(q.expanding_windows(6, 8), (1, 2, 2, 2, 3, 3, 3, 4, 5, 6, 7, 8, 8))
        self.assertEqual(q.expanding_windows(64, 1), (1,))
        self.assertEqual(q.expanding_windows(1, 1), (1,))
        results = [q.campaign(8, marked, known.Timing(0.1, 0.2), window_cap=16,
                              policy_draw_seconds=0.01, attempt_limit=5)
                   for marked in (0, 1, 63, 128, 255, 256)]
        self.assertTrue(all(result["policy"] == results[0]["policy"] for result in results))
        self.assertTrue(results[0]["policy"]["full_floor_sqrt_domain_cap"])
        self.assertFalse(q.campaign(64, 1, known.Timing(0.1, 0.2), window_cap=16,
                                   policy_draw_seconds=0.01)["policy"]["full_floor_sqrt_domain_cap"])

    def test_probabilities_against_dense_state_vectors_including_overshoot(self):
        cases = 0
        for bits in range(1, 6):
            size = 1 << bits
            for marked in range(size + 1):
                actual = q.marked_probabilities(bits, marked, 128)
                state = [1 / math.sqrt(size)] * size
                for j in range(128):
                    expected = math.fsum(a * a for a in state[:marked])
                    self.assertAlmostEqual(actual[j], expected, delta=8e-13)
                    state = [-value if i < marked else value for i, value in enumerate(state)]
                    mean = math.fsum(state) / size
                    state = [2 * mean - value for value in state]
                    cases += 1
        self.assertEqual(cases, 8576)

    def test_exact_quarter_fraction_and_nearly_full_64_bit_endpoint(self):
        self.assertEqual(q.marked_probabilities(2, 1, 9),
                         (0.25, 1.0, 0.25, 0.25, 1.0, 0.25, 0.25, 1.0, 0.25))
        size = 1 << 64
        got = q.marked_probabilities(64, size - 1, 10000)
        # Independent Decimal trigonometric series for cos((2j+1) asin(2^-32)).
        with localcontext() as context:
            context.prec = 90
            x = Decimal(1) / Decimal(2) ** 32
            theta = x + x ** 3 / 6 + 3 * x ** 5 / 40
            for j in (0, 1, 99, 9999):
                phase = (2 * j + 1) * theta
                term, cosine = Decimal(1), Decimal(1)
                for k in range(1, 20):
                    term *= -(phase * phase) / ((2 * k - 1) * (2 * k))
                    cosine += term
                self.assertAlmostEqual(got[j], float(cosine * cosine), delta=2e-16)
        rare = q.marked_probabilities(64, 1, 10000)
        self.assertEqual(rare[0], 2.0 ** -64)
        self.assertGreater(rare[-1], 0)

    def test_120_independent_random_iteration_terminal_path_enumerations(self):
        rng = random.Random(20261028)
        for _ in range(120):
            bits = rng.choice([2, 3, 4])
            marked = rng.randrange((1 << bits) + 1)
            cap = min(4, math.isqrt(1 << bits))
            policy = q.expanding_windows(bits, cap)
            count = rng.randint(1, 7)
            windows = [policy[min(i, len(policy) - 1)] for i in range(count)]
            timing = known.Timing(rng.randint(1, 8) / 8, rng.randint(1, 8) / 8,
                                  rng.randint(0, 8) / 8, rng.randint(0, 8) / 8)
            draw, rate = 0.125, rng.choice([0.0, 0.125, 1.0, 8.0])
            expected = enumerate_terminal_paths(bits, marked, timing, draw, windows, rate)
            actual = q.campaign(bits, marked, timing, window_cap=cap,
                                policy_draw_seconds=draw, attempt_limit=count, external_tip_rate=rate)
            self.assertAlmostEqual(actual["win_probability"], expected["win"], delta=1e-13)
            self.assertAlmostEqual(actual["attempt_limit_exhaustion_probability"], expected["exhausted"], delta=1e-13)
            self.assertAlmostEqual(actual["expected_context_seconds"], expected["elapsed"], delta=3e-12)
            self.assertAlmostEqual(actual["win_probability"] + actual["attempt_limit_exhaustion_probability"]
                                   + actual["external_tip_probability"], 1.0, delta=2e-13)
            if rate == 0:
                self.assertAlmostEqual(actual["expected_grover_iterations_without_interruption"],
                                       expected["queries"], delta=3e-12)
                self.assertAlmostEqual(actual["expected_draws_and_measurement_checks_without_interruption"],
                                       expected["draws"], delta=3e-12)
            else:
                self.assertIsNone(actual["expected_grover_iterations_without_interruption"])

    def test_cap_one_reduces_to_costed_classical_sampling_and_existing_exact_race(self):
        timing = known.Timing(0.5, 0.25, 0.5, 0.75)
        for marked in (0, 1, 64, 255, 256):
            for rate in (0.0, 0.125, 1.0, 32.0):
                actual = q.campaign(8, marked, timing, window_cap=1,
                                    policy_draw_seconds=0.125, external_tip_rate=rate)
                expected = known.campaign(known.FixedStop(marked / 256, 0.375, 0.5, 0.75), rate)
                for key in ("win_probability", "external_tip_probability", "nontermination_probability"):
                    self.assertAlmostEqual(actual[key], expected[key], delta=2e-15)
                if expected["expected_context_seconds"] is None:
                    self.assertIsNone(actual["expected_context_seconds"])
                else:
                    # The two exact mathematical decompositions round at
                    # different intermediate sums in binary64.
                    self.assertAlmostEqual(actual["expected_context_seconds"]
                                           / expected["expected_context_seconds"], 1, delta=2e-15)
                if rate == 0 and marked:
                    self.assertEqual(actual["expected_grover_iterations_without_interruption"], 0)
                    self.assertAlmostEqual(actual["expected_draws_and_measurement_checks_without_interruption"],
                                           256 / marked, delta=2e-13)

    def test_all_mandatory_costs_reconcile_without_interruptions(self):
        timing = known.Timing(0.125, 0.25, 0.5, 0.75)
        for marked in (1, 4, 64, 127, 255, 256):
            for limit in (None, 1, 8, 64):
                got = q.campaign(8, marked, timing, window_cap=16,
                                 policy_draw_seconds=0.125, attempt_limit=limit)
                expected = (timing.context_setup_seconds
                            + got["expected_grover_iterations_without_interruption"] * 0.125
                            + got["expected_draws_and_measurement_checks_without_interruption"] * 0.375
                            + got["win_probability"] * 0.75)
                self.assertAlmostEqual(got["expected_context_seconds"], expected, delta=4e-13)
        all_marked = q.campaign(8, 256, timing, window_cap=16, policy_draw_seconds=0.125)
        self.assertEqual(all_marked["expected_context_seconds"], 1.625)

    def test_empty_domain_limits_and_external_tip_remain_explicit(self):
        timing = known.Timing(0.1, 0.1, 0.2, 0.3)
        empty = q.campaign(64, 0, timing, window_cap=256, policy_draw_seconds=0.01)
        self.assertEqual(empty["win_probability"], 0)
        self.assertEqual(empty["nontermination_probability"], 1)
        self.assertIsNone(empty["expected_context_seconds"])
        limited = q.campaign(64, 0, timing, window_cap=256,
                             policy_draw_seconds=0.01, attempt_limit=48)
        self.assertEqual(limited["attempt_limit_exhaustion_probability"], 1)
        self.assertGreater(limited["expected_context_seconds"], 0)
        self.assertFalse(limited["policy"]["finite_exhaustion_proves_empty_domain"])
        interrupted = q.campaign(64, 0, timing, window_cap=256,
                                 policy_draw_seconds=0.01, external_tip_rate=0.25)
        self.assertAlmostEqual(interrupted["external_tip_probability"], 1, delta=2e-15)
        self.assertAlmostEqual(interrupted["expected_context_seconds"], 4, delta=2e-14)

    def test_tips_during_setup_draw_check_and_winning_publication_are_charged(self):
        timing = known.Timing(1, 2, 3, 5)
        actual = q.campaign(8, 256, timing, window_cap=16,
                            policy_draw_seconds=7, external_tip_rate=0.25)
        # All marked: j=0 and one attempt; completion is at 3+7+2+5=17.
        self.assertAlmostEqual(actual["win_probability"], math.exp(-0.25 * 17), delta=1e-15)
        self.assertAlmostEqual(actual["expected_context_seconds"], -math.expm1(-0.25 * 17) / 0.25)
        self.assertAlmostEqual(actual["win_probability"] + actual["external_tip_probability"], 1)

    def test_capped_policy_tail_matches_long_finite_campaign(self):
        timing = known.Timing(0.05, 0.1, 0.2, 0.3)
        for marked in (1, 4, 32, 64):
            for rate in (0.0, 0.1, 2.0):
                options = dict(window_cap=8, policy_draw_seconds=0.01, external_tip_rate=rate)
                infinite = q.campaign(6, marked, timing, **options)
                finite = q.campaign(6, marked, timing, attempt_limit=1000, **options)
                self.assertLess(finite["attempt_limit_exhaustion_probability"], 1e-50)
                self.assertAlmostEqual(infinite["win_probability"], finite["win_probability"], delta=2e-14)
                self.assertAlmostEqual(infinite["expected_context_seconds"], finite["expected_context_seconds"], delta=2e-13)

    def test_tiny_success_probability_keeps_finite_exit_and_large_expected_cost(self):
        actual = q.campaign(64, 1, known.Timing(1, 1), window_cap=1, policy_draw_seconds=1)
        self.assertEqual(actual["win_probability"], 1)
        self.assertEqual(actual["expected_context_seconds"], float(1 << 65))
        self.assertEqual(actual["expected_draws_and_measurement_checks_without_interruption"], float(1 << 64))
        with self.assertRaisesRegex(q.Reject, "EXPECTED_TIME_NUMERIC_RANGE"):
            q.campaign(64, 1, known.Timing(1, 1e300), window_cap=1, policy_draw_seconds=1)
        with self.assertRaisesRegex(q.Reject, "EXPECTED_TIME_NUMERIC_RANGE"):
            q.campaign(64, 0, known.Timing(1e-200, 1e-200), window_cap=1,
                       policy_draw_seconds=1e-200, external_tip_rate=1e-310)

    def test_nearly_full_domain_preserves_rare_failed_draw_work(self):
        actual = q.campaign(64, (1 << 64) - 1, known.Timing(1, 1),
                            window_cap=2, policy_draw_seconds=1)
        # First j=0 draw fails with probability 2^-64. Every later window
        # draws j uniformly from {0,1}, so expected queries is positive and
        # equals 2^-65 to binary64 precision. Rounding p to one erases it.
        self.assertGreater(actual["expected_grover_iterations_without_interruption"], 0)
        self.assertAlmostEqual(actual["expected_grover_iterations_without_interruption"]
                               / (2.0 ** -65), 1, delta=2e-15)

    def test_invalid_or_unbounded_enumeration_inputs_are_not_silently_clipped(self):
        timing = known.Timing(0.1, 0.1)
        base = dict(nonce_bits=8, marked=1, timing=timing, window_cap=16, policy_draw_seconds=0.01)
        for key, value in (("nonce_bits", True), ("nonce_bits", 0), ("nonce_bits", 65),
                           ("marked", -1), ("marked", 257), ("window_cap", 0),
                           ("window_cap", 17), ("policy_draw_seconds", 0),
                           ("policy_draw_seconds", float("nan")), ("attempt_limit", 0),
                           ("attempt_limit", 100001), ("external_tip_rate", -1)):
            with self.subTest(key=key, value=value):
                with self.assertRaises(q.Reject):
                    q.campaign(**dict(base, **{key: value}))
        with self.assertRaises(q.Reject):
            q.expanding_windows(64, 10001)
        json.dumps(q.campaign(**base), allow_nan=False)


if __name__ == "__main__":
    unittest.main()
