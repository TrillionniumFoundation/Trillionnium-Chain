"""Independent finite adversarial checks for fresh-work resource transfer."""
from fractions import Fraction
from itertools import product
import unittest

import fresh_work_query_floor_v0 as F
import fresh_work_resource_transfer_v0 as R


def number(value):
    return Fraction(value['numerator'], value['denominator'])


class DisclosedVerifierWorkTests(unittest.TestCase):
    def test_complete_leakage_zero_own_queries_does_not_make_credit_zero(self):
        # Hidden endpoint uniformly spans eight values. Verifier discloses it;
        # the coalition subsequently claims it. One cached replay costs L.
        size, length, target = 8, 3, 3
        award = F.nominal_award(target, bits=3, length=length)
        exact = sum(Fraction(award, size) for endpoint in range(size)
                    if endpoint <= target)
        self.assertEqual(exact, length)
        self.assertGreater(exact, F.expected_credit_bound(0, bits=3, length=length))
        self.assertLessEqual(exact, R.total_work_bound_with_verifier_budget(
            0, length, bits=3, length=length))

    def test_bounded_total_transfer_is_monotone_in_unobserved_verifier_work(self):
        # Q_V is not replaced by successful calls or a favorable observed mean.
        for q in range(5):
            for bound in range(5):
                mu = Fraction(q, 2)
                conservative = R.total_work_bound_with_verifier_budget(q, bound,
                    bits=10, length=3, expected_queries=mu)
                for actual_verifier in range(bound + 1):
                    explicit = F.expected_credit_bound(q + bound, bits=10, length=3,
                        expected_queries=mu + actual_verifier)
                    self.assertLessEqual(explicit, conservative)

    def test_replay_cap_counts_redundant_checkers_and_partial_crash_allowance(self):
        self.assertEqual(R.replay_step_query_cap(256), 16384)
        self.assertEqual(R.replay_step_query_cap(256, replays_per_submission=2), 32768)
        # Three completed callbacks plus one started callback of unknown progress:
        # never report the fourth callback as zero merely because it has no receipt.
        known_steps, unknown_callbacks, cap = 3 * 64, 1, 4
        conservative = known_steps + R.replay_step_query_cap(unknown_callbacks)
        self.assertEqual(conservative, R.replay_step_query_cap(cap))
        self.assertEqual(R.replay_step_query_cap(0), 0)

    def test_strict_caps_and_expected_query_type(self):
        for invalid in (True, 1.5, -1):
            with self.assertRaises(ValueError):
                R.replay_step_query_cap(invalid)
            with self.assertRaises(ValueError):
                R.total_work_bound_with_verifier_budget(1, invalid)
        for invalid in (0, -1, True, 1.0):
            with self.assertRaises(ValueError):
                R.replay_step_query_cap(1, replays_per_submission=invalid)
        for invalid in (0, 0.5, Fraction(-1), Fraction(2)):
            with self.assertRaises(ValueError):
                R.total_work_bound_with_verifier_budget(1, 2, expected_queries=invalid)


class BudgetAndFeedbackCounterexamples(unittest.TestCase):
    def test_independent_budgets_require_sum_even_for_one_candidate(self):
        report = R.copied_budget_counterexample()
        self.assertEqual(report['canonical_candidates'], 1)
        self.assertEqual(report['actual_submission_cap'], 128)
        exact = number(report['exact_expected_credit'])
        self.assertEqual(exact, 4)
        self.assertGreater(exact, number(report['incorrectly_assumed_local_bound']))
        self.assertLessEqual(exact, number(report['correctly_aggregated_bound']))
        self.assertFalse(report['observed_native_exploit'])

    def test_exact_distinct_guesses_enumerated_independently(self):
        for bits in range(2, 6):
            size = 1 << bits
            for target in range(1, size):
                award = F.nominal_award(target, bits=bits, length=3)
                for calls in (0, 1, 3, size + 7):
                    credit = 0
                    for endpoint in range(size):
                        for guess in range(min(calls, target + 1)):
                            if endpoint == guess:
                                credit += award
                                break
                    self.assertEqual(Fraction(credit, size),
                        R.winning_guesses_expectation(calls, target=target,
                                                     bits=bits, length=3))

    def test_one_extra_bit_is_not_endpoint_equality(self):
        report = R.endpoint_bit_leak_counterexample()
        self.assertEqual(report['oracle_worlds'], 256)
        self.assertEqual(report['maximum_verifier_calls'], 9)
        self.assertEqual(report['own_chain_queries'], 0)
        self.assertEqual(number(report['exact_expected_credit']), 64)
        self.assertGreater(number(report['exact_expected_credit']),
                           number(report['invalid_equality_only_bound']))
        self.assertLessEqual(number(report['exact_expected_credit']),
                           number(report['valid_total_work_bound_with_cached_verifier']))
        self.assertFalse(report['observed_native_side_channel'])

    def test_bit_leak_closes_on_first_equality_and_counts_all_other_calls(self):
        for bits in range(2, 10):
            size = 1 << bits
            report = R.endpoint_bit_leak_counterexample(bits=bits, target=size // 2 - 1)
            # Endpoint zero closes at the first reply; every other world uses
            # bits information replies plus its one final correct equality.
            self.assertEqual(number(report['mean_verifier_calls']),
                Fraction(1 + (size - 1) * (bits + 1), size))
            self.assertEqual(number(report['exact_expected_credit']), 64)
            self.assertEqual(report['successful_winning_worlds'], size // 2)

    def test_low_target_guess_allowance_stays_visible(self):
        for bits in (8, 64, 256):
            self.assertEqual(R.winning_guesses_expectation(1, target=1, bits=bits), 32)
            self.assertEqual(R.winning_guesses_expectation(2, target=1, bits=bits), 64)
            self.assertEqual(R.winning_guesses_expectation(100, target=1, bits=bits), 64)


class ExactQuantumControls(unittest.TestCase):
    def test_two_amplitude_formula_matches_independent_state_vector(self):
        for n in (1, 2, 4, 8):
            for marked_bits in product((False, True), repeat=n):
                # Coefficients of |x>/sqrt(n), not rounded floating amplitudes.
                amplitudes = [Fraction(1) for _ in range(n)]
                for rounds in range(4):
                    probability = sum(amplitudes[i] ** 2 for i in range(n)
                                      if marked_bits[i]) / n
                    self.assertEqual(probability, R.grover_probability(
                        n, sum(marked_bits), rounds))
                    phased = [-a if marked_bits[i] else a
                              for i, a in enumerate(amplitudes)]
                    mean = sum(phased) / n
                    amplitudes = [2 * mean - a for a in phased]

    def test_uniform_random_marking_average_does_not_select_lucky_worlds(self):
        n, p, bits, target = 4, Fraction(1, 8), 4, 1
        for rounds in range(4):
            expected = mass = Fraction(0)
            for subset in product((False, True), repeat=n):
                count = sum(subset)
                weight = p ** count * (1 - p) ** (n - count)
                mass += weight
                amplitudes = [Fraction(1) for _ in range(n)]
                for _ in range(rounds):
                    phased = [-a if subset[i] else a for i, a in enumerate(amplitudes)]
                    mean = sum(phased) / n
                    amplitudes = [2 * mean - a for a in phased]
                win = sum(amplitudes[i] ** 2 for i in range(n) if subset[i]) / n
                expected += weight * win
            report = R.quantum_random_candidates_counterexample(candidate_count=n,
                iterations=rounds, bits=bits, target=target, length=3)
            self.assertEqual(mass, 1)
            self.assertEqual(number(report['exact_success_probability']), expected)
            self.assertEqual(number(report['zero_marked_probability']), (1 - p) ** n)

    def test_fixed_quantum_strategy_exceeds_inapplicable_classical_credit_bound(self):
        report = R.quantum_random_candidates_counterexample()
        self.assertEqual(report['total_abstract_step_queries'], 768)
        self.assertEqual(report['forward_step_queries'], 320)
        self.assertEqual(report['uncomputation_step_queries'], 320)
        self.assertEqual(report['measured_candidate_check_step_queries'], 64)
        self.assertEqual(report['independent_verifier_step_queries'], 64)
        self.assertEqual(report['own_abstract_step_queries'], 704)
        self.assertEqual(report['marked_set_count'], 1 << 64)
        self.assertTrue(report['exceeds_classical_envelope'])
        self.assertGreater(number(report['exact_expected_credit']),
                           number(report['inapplicable_classical_credit_envelope']))
        self.assertFalse(report['coherent_native_circuit_implemented'])
        self.assertFalse(report['physical_resources_complete'])
        self.assertFalse(report['quantum_lower_bound_proved'])

    def test_zero_iterations_still_pay_for_measured_candidate_check(self):
        report = R.quantum_random_candidates_counterexample(iterations=0)
        self.assertEqual(report['total_abstract_step_queries'], 128)
        self.assertEqual(number(report['exact_success_probability']), Fraction(1, 64))
        self.assertEqual(number(report['exact_expected_credit']), 64)
        self.assertFalse(report['exceeds_classical_envelope'])

    def test_overrotation_and_empty_search_worlds_are_retained(self):
        self.assertEqual(R.grover_probability(4, 1, 1), 1)
        self.assertEqual(R.grover_probability(4, 1, 2), Fraction(1, 4))
        self.assertEqual(R.grover_probability(4, 0, 8), 0)
        self.assertEqual(R.grover_probability(4, 4, 8), 1)
        # A binomial k=0 world is a failure, not omitted from the denominator.
        report = R.quantum_random_candidates_counterexample()
        self.assertLessEqual(number(report['exact_success_probability']),
                            1 - number(report['zero_marked_probability']))

    def test_quantum_input_bounds_and_type_validation(self):
        for n in (0, 3, 512, True, 4.0):
            with self.assertRaises(ValueError):
                R.grover_probability(n, 1, 1)
        for marked in (-1, 5, True):
            with self.assertRaises(ValueError):
                R.grover_probability(4, marked, 1)
        for rounds in (-1, 65, True, 1.0):
            with self.assertRaises(ValueError):
                R.grover_probability(4, 1, rounds)


if __name__ == '__main__':
    unittest.main()
