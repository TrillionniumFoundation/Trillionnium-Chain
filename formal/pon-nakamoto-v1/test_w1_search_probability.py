"""Independent full-vector rational controls for the interval probability kernel."""
from fractions import Fraction
import unittest

from w1_search_probability import (
    ProbabilityInterval, ProbabilityTrial, coupled_success_bounds, grover_success_bounds,
    probability_power_bounds, schedule_success_bounds,
)


def vector(n, marked, iterations, *, fault_after_oracle=False, fault_after_diffusion=False):
    """Unnormalized uniform amplitudes; operate on every basis state separately."""
    amplitudes = [Fraction(1) for _ in range(n)]
    for _ in range(iterations):
        amplitudes = [-value if index < marked else value for index, value in enumerate(amplitudes)]
        if fault_after_oracle:
            amplitudes = [amplitudes[index ^ 1] for index in range(n)]
        mean = sum(amplitudes) / n
        amplitudes = [2 * mean - value for value in amplitudes]
        if fault_after_diffusion:
            amplitudes = [amplitudes[index ^ 1] for index in range(n)]
    return amplitudes


def exact_success(amplitudes, legal, processors=1):
    single = sum(value**2 for value in amplitudes[:legal]) / len(amplitudes)
    return 1 - (1 - single)**processors


def read_interval(record):
    return ProbabilityInterval(Fraction(**record["lower"]), Fraction(**record["upper"]))


class SearchProbabilityTests(unittest.TestCase):
    def assert_contains(self, interval, exact):
        self.assertLessEqual(interval.lower, exact)
        self.assertGreaterEqual(interval.upper, exact)

    def test_dense_basis_exact_rational_sweep_includes_legal_unmarked_candidates(self):
        for n in (2, 4, 8, 16):
            for marked in range(n + 1):
                for iterations in range(9):
                    amplitudes = vector(n, marked, iterations)
                    self.assertEqual(sum(value**2 for value in amplitudes) / n, 1)
                    for legal in range(marked, n + 1):
                        for processors in (1, 3):
                            interval = grover_success_bounds(n, marked, legal, iterations, processors)
                            self.assert_contains(interval, exact_success(amplitudes, legal, processors))

    def test_exact_overshoot_zero_and_perfect_amplification_are_not_float_artifacts(self):
        for iterations in range(65):
            for marked in (1, 3):
                interval = grover_success_bounds(4, marked, marked, iterations)
                exact = exact_success(vector(4, marked, iterations), marked)
                self.assertEqual(interval.lower, exact)
                self.assertEqual(interval.upper, exact)
        self.assertEqual(grover_success_bounds(4, 3, 3, 1).upper, 0)
        self.assertEqual(grover_success_bounds(4, 1, 1, 1).lower, 1)

    def test_large_iteration_count_remains_bounded_and_tight_without_expanding_a_statevector(self):
        interval = grover_success_bounds(4096, 1, 7, 100_000_000, 64)
        self.assertLess(interval.upper - interval.lower, Fraction(1, 1 << 80))
        self.assertEqual(grover_success_bounds(4, 1, 1, 100_000_000).lower, 1)
        self.assertEqual(grover_success_bounds(4, 2, 3, 100_000_000).upper, Fraction(3, 4))

    def test_empty_phase_set_and_zero_iterations_still_accept_full_legal_set(self):
        for marked, iterations in ((0, 100_000_000), (1, 0), (4, 0)):
            bound = grover_success_bounds(16, marked, 4, iterations, 2)
            self.assertEqual(bound.lower, Fraction(7, 16))
            self.assertEqual(bound.upper, Fraction(7, 16))

    def test_timed_first_success_branches_include_a_censored_early_winner(self):
        trials = (ProbabilityTrial(4, 1, 1, 0, 1, Fraction(1), Fraction(10)),
                  ProbabilityTrial(4, 1, 1, 1, 1, Fraction(1), Fraction(1)))
        result = schedule_success_bounds(trials, "3")
        self.assertEqual(read_interval(result["delivery_probability"]).lower, Fraction(3, 4))
        self.assertEqual(read_interval(result["first_winner_censored_probability"]).upper, Fraction(1, 4))
        self.assertEqual(read_interval(result["search_censored_probability"]).upper, 0)
        self.assertEqual(read_interval(result["schedule_exhausted_without_winner_probability"]).upper, 0)
        earlier = schedule_success_bounds(trials, "2.999999999999999999999999999999")
        self.assertEqual(read_interval(earlier["delivery_probability"]).upper, 0)
        self.assertEqual(read_interval(earlier["first_winner_censored_probability"]).lower, 1)

    def test_zero_horizon_incomplete_checks_and_exact_deadline_are_distinct(self):
        trials = (ProbabilityTrial(4, 1, 1, 1, 2, Fraction(1, 10), Fraction(0)),)
        for deadline in ("0", "0.09999999999999999999999999"):
            result = schedule_success_bounds(trials, deadline)
            self.assertEqual(read_interval(result["delivery_probability"]).upper, 0)
            self.assertEqual(read_interval(result["search_censored_probability"]).lower, 1)
        self.assertEqual(read_interval(schedule_success_bounds(trials, "0.1")["delivery_probability"]).lower, 1)

    def test_exhausted_schedule_and_all_four_probability_branches_partition_exactly(self):
        trials = (ProbabilityTrial(8, 1, 3, 0, 1, Fraction(1), Fraction(0)),
                  ProbabilityTrial(8, 1, 3, 0, 1, Fraction(1), Fraction(5)))
        result = schedule_success_bounds(trials, "3")
        keys = ("delivery_probability", "first_winner_censored_probability",
                "search_censored_probability", "schedule_exhausted_without_winner_probability")
        exact = [read_interval(result[key]) for key in keys]
        self.assertEqual([item.lower for item in exact], [Fraction(3, 8), Fraction(15, 64), 0, Fraction(25, 64)])
        self.assertEqual(sum(item.lower for item in exact), 1)
        self.assertEqual(sum(item.upper for item in exact), 1)

    def test_exact_correlated_fault_channel_executes_basis_permutations_and_obeys_additive_union(self):
        # P(F1)=1/5; P(F2|not F1)=1/10 and P(F2|F1)=1/5.
        # Positive correlation is allowed, with each history-conditional bound
        # at most 1/5. Apply the corresponding X permutation at two distinct
        # stages of an actual four-basis-state Grover evolution.
        joint = {(False, False): Fraction(18, 25), (False, True): Fraction(2, 25),
                 (True, False): Fraction(4, 25), (True, True): Fraction(1, 25)}
        self.assertNotEqual(joint[True, True], Fraction(1, 5) * Fraction(3, 25))
        actual = sum(weight * exact_success(vector(4, 1, 1, fault_after_oracle=a,
                                                   fault_after_diffusion=b), 1)
                     for (a, b), weight in joint.items())
        ideal = grover_success_bounds(4, 1, 1, 1)
        coupled = coupled_success_bounds(ideal, Fraction(2, 5))
        self.assert_contains(coupled, actual)
        self.assertLess(actual, ideal.lower)
        self.assertEqual(sum(joint.values()), 1)

    def test_faults_selecting_only_winning_outcomes_refute_multiplicative_shortcut(self):
        ideal = grover_success_bounds(4, 1, 1, 0)
        # A single post-readout fault can target precisely the winning outcome.
        # Its marginal probability is 1/4, so the coupling union is 1/4.
        actual, epsilon = Fraction(0), Fraction(1, 4)
        self.assert_contains(coupled_success_bounds(ideal, epsilon), actual)
        self.assertGreater(ideal.lower * (1 - epsilon), actual)

    def test_probability_powers_do_not_underflow_positive_risk_to_zero(self):
        bounds = probability_power_bounds(Fraction(1, 10**100), 64)
        self.assertEqual(bounds.lower, 0)
        self.assertGreater(bounds.upper, 0)
        self.assertLessEqual(Fraction(1, 10**6400), bounds.upper)
        exact = probability_power_bounds(Fraction(1, 4), 16)
        self.assertEqual(exact.lower, Fraction(1, 1 << 32))
        self.assertEqual(exact.lower, exact.upper)

    def test_shapes_bounds_and_bool_aliases_are_refused(self):
        for args in ((True, 0, 0, 0), (3, 1, 1, 1), (4, 2, 1, 0),
                     (4, False, 1, 0), (4, 1, 1, True), (4, 1, 1, 0, False),
                     (4, 1, 1, 100_000_001), (8192, 1, 1, 0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                grover_success_bounds(*args)
        with self.assertRaises(ValueError):
            ProbabilityInterval(Fraction(0), 1)
        with self.assertRaises(ValueError):
            coupled_success_bounds(grover_success_bounds(4, 1, 1, 0), 0.1)
        with self.assertRaises(ValueError):
            probability_power_bounds(Fraction(1, 2), True)
        good = ProbabilityTrial(4, 1, 1, 0, 1, Fraction(1), Fraction(0))
        for trials, deadline in (([good], "1"), ((good,), 1), ((good,), "NaN"),
                                 ((ProbabilityTrial(4, 1, 1, 0, 1, 1.0, Fraction(0)),), "1")):
            with self.assertRaises(ValueError):
                schedule_success_bounds(trials, deadline)


if __name__ == "__main__":
    unittest.main()
