import unittest
from fractions import Fraction
from itertools import product
from work_query_bound import (
    parameters, expected_first_query_credit, union_bound,
    step_envelope, fixed_query_tail,
    strict_credit_lower_bound, conditional_mean_work_share,
    equal_mean_work_share, sufficient_mean_work_share,
)


class TicketBoundTests(unittest.TestCase):
    def test_exhaustive_small_oracles_match_expected_credit(self):
        for bits in range(2, 8):
            modulus = 1 << bits
            for target in range(1, modulus):
                _, work = parameters(target, bits)
                actual = Fraction(sum(work for y in range(modulus) if y <= target), modulus)
                self.assertEqual(actual, expected_first_query_credit(target, bits))
                self.assertLessEqual(actual, 1)

    def test_full_width_off_by_one_and_no_floating_point(self):
        modulus = 1 << 256
        for target, work in [(1, modulus // 2), (modulus // 2 - 1, 2),
                             (modulus // 32 - 1, 32), (modulus - 1, 1)]:
            self.assertEqual(parameters(target), (modulus, work))
            self.assertEqual(expected_first_query_credit(target), 1)
        self.assertLess(expected_first_query_credit(modulus // 2), 1)

    def test_strict_rounding_bound_exhausts_every_small_legal_target_and_limit(self):
        for bits in range(2, 9):
            modulus = 1 << bits
            for limit in range(1, modulus):
                lower = strict_credit_lower_bound(limit, bits)
                for target in range(1, limit + 1):
                    # Independent oracle outcome enumeration is equivalent to
                    # d winning outcomes, each credited the integer weight.
                    weight = modulus // (target + 1)
                    actual = Fraction((target + 1) * weight, modulus)
                    self.assertGreater(actual, lower)
                    self.assertLessEqual(actual, 1)

    def test_current_pow_limit_has_nearly_three_halves_efficiency_ratio(self):
        modulus = 1 << 256
        limit, low_efficiency_target = modulus // 2 - 1, modulus // 3
        honest = Fraction(2 * (modulus // 3 + 1), modulus)
        self.assertEqual(parameters(low_efficiency_target)[1], 2)
        self.assertEqual(expected_first_query_credit(low_efficiency_target), honest)
        self.assertEqual(expected_first_query_credit(limit), 1)
        self.assertEqual(strict_credit_lower_bound(limit), Fraction(2, 3))
        self.assertLess(1 / honest, Fraction(3, 2))
        self.assertLess(Fraction(3, 2) - 1 / honest, Fraction(5, modulus))

    def test_equal_target_rate_model_recovers_existing_formula(self):
        for q in (Fraction(0), Fraction(1, 4), Fraction(2, 5), Fraction(1)):
            for advantage in (Fraction(1, 2), Fraction(1), Fraction(3)):
                for target in (1, 2, (1 << 255) - 1):
                    expected = q * advantage / (1 - q + q * advantage)
                    self.assertEqual(conditional_mean_work_share(q, advantage, target, target), expected)
                    self.assertEqual(equal_mean_work_share(advantage, target, target), 1 / (1 + advantage))

    def test_distinct_target_example_is_not_a_fifty_percent_resource_test(self):
        modulus = 1 << 256
        attack_target, honest_target = modulus // 2 - 1, modulus // 3
        share = conditional_mean_work_share(Fraction(9, 20), Fraction(1), attack_target, honest_target)
        self.assertGreater(share, Fraction(1, 2))
        self.assertLess(share, Fraction(27, 49))
        threshold = equal_mean_work_share(Fraction(1), attack_target, honest_target)
        self.assertGreater(threshold, Fraction(2, 5))
        self.assertLess(threshold, Fraction(41, 100))
        self.assertEqual(conditional_mean_work_share(threshold, Fraction(1), attack_target, honest_target),
                         Fraction(1, 2))

    def test_already_credit_adjusted_advantage_must_not_count_efficiency_twice(self):
        q, attempt_advantage = Fraction(2, 7), Fraction(5, 3)
        attack_target, honest_target = 7, 5
        credit_advantage = (attempt_advantage * expected_first_query_credit(attack_target, 4)
                            / expected_first_query_credit(honest_target, 4))
        expected = q * credit_advantage / (1 - q + q * credit_advantage)
        self.assertEqual(conditional_mean_work_share(q, attempt_advantage, attack_target, honest_target, 4),
                         expected)

    def test_sufficient_mean_work_bound_is_not_a_necessary_condition(self):
        for bits in range(2, 8):
            limit = (1 << bits) // 2 - 1
            for advantage in (Fraction(1, 2), Fraction(1), Fraction(3)):
                q_bound = sufficient_mean_work_share(advantage, limit, bits)
                self.assertEqual(q_bound, Fraction(2) / (2 + 3 * advantage))
                for attack_target in range(1, limit + 1):
                    for honest_target in range(1, limit + 1):
                        self.assertLess(conditional_mean_work_share(q_bound, advantage,
                                                                   attack_target, honest_target, bits),
                                        Fraction(1, 2))
        # A share above 2/5 can still yield lower mean work at matching targets.
        self.assertLess(conditional_mean_work_share(Fraction(9, 20), Fraction(1), 7, 7, 4),
                        Fraction(1, 2))

    def test_rounding_rate_model_rejects_nonexact_and_invalid_inputs(self):
        for q in (True, 0.25, Fraction(-1), Fraction(5, 4)):
            with self.assertRaises(ValueError):
                conditional_mean_work_share(q, Fraction(1), 1, 1)
        for s in (True, 1.0, Fraction(0), Fraction(-1)):
            for call in (lambda: conditional_mean_work_share(Fraction(1, 4), s, 1, 1),
                         lambda: equal_mean_work_share(s, 1, 1),
                         lambda: sufficient_mean_work_share(s, 7, 4)):
                with self.assertRaises(ValueError):
                    call()
        for limit, bits in ((0, 256), (16, 4), (7, True), (True, 4)):
            with self.assertRaises(ValueError):
                strict_credit_lower_bound(limit, bits)

    def test_adaptive_target_chosen_before_second_query(self):
        modulus, total = 8, 0
        for first in range(modulus):
            first_target = 1
            first_work = modulus // (first_target + 1)
            second_target = 1 + first % (modulus - 1)
            second_work = modulus // (second_target + 1)
            for second in range(modulus):
                total += (first_work if first <= first_target else 0)
                total += (second_work if second <= second_target else 0)
        self.assertLessEqual(Fraction(total, modulus * modulus), 2)

    def test_posthoc_target_counterexample_is_not_certified(self):
        modulus = 16
        credit = Fraction(sum(modulus // (max(1, y) + 1) for y in range(modulus)), modulus)
        self.assertGreater(credit, 1)

    def test_delegation_is_not_free_in_the_accounting(self):
        self.assertEqual(union_bound(1, 0, 0, 8), 0)
        self.assertEqual(union_bound(1, 0, 1, 8), Fraction(1, 128))
        self.assertGreater(union_bound(1, 0, 1, 8), 0)

    def test_fixed_target_first_success_and_optional_stop(self):
        probability = Fraction(1, 8)
        for queries in range(9):
            exact = 1 - (1 - probability) ** queries
            self.assertLessEqual(exact, union_bound(1, queries, 0, 4))
            expected_used = sum((1 - probability) ** i for i in range(queries))
            self.assertEqual(exact, probability * expected_used)

    def test_identity_splitting_does_not_change_total_query_budget(self):
        for split in [(31,), (1, 30), (1,) * 31, (3, 7, 8, 13)]:
            self.assertEqual(union_bound(1, sum(split), 0, 8), Fraction(31, 128))

    def test_invalid_parameters_rejected(self):
        for args in [(0, 256), (-1, 8), (256, 8), (True, 8), (1, 1), (1, 257)]:
            with self.assertRaises(ValueError):
                parameters(*args)
        for args in [(1, -1, 0, 8), (1, True, 0, 8), (1, 0, -1, 8)]:
            with self.assertRaises(ValueError):
                union_bound(*args)

    def test_exponential_envelope_all_small_targets(self):
        for bits in range(2, 7):
            modulus = 1 << bits
            cap = modulus // 2
            for base in (Fraction(9, 8), Fraction(3, 2), Fraction(2)):
                envelope = step_envelope(base, cap)
                for target in range(1, modulus):
                    _, weight = parameters(target, bits)
                    exact = 1 + Fraction(target + 1, modulus) * (base ** weight - 1)
                    self.assertLessEqual(exact, envelope)

    def test_full_width_target_with_bounded_weight(self):
        modulus = 1 << 256
        for weight in (1, 2, 4, 8, 16):
            target = modulus // weight - 1
            self.assertEqual(parameters(target)[1], weight)
            base = Fraction(5, 4)
            exact = 1 + Fraction(target + 1, modulus) * (base ** weight - 1)
            self.assertEqual(exact, step_envelope(base, weight))

    def test_adaptive_tree_fixed_horizon_tail(self):
        modulus, horizon, cap = 4, 4, 2
        base = Fraction(3, 2)
        credits = []
        for outputs in product(range(modulus), repeat=horizon):
            credit, last = 0, 0
            for index, output in enumerate(outputs):
                target = 1 + (credit + last + index) % (modulus - 1)
                weight = modulus // (target + 1)
                credit += weight * (output <= target)
                last = output
            credits.append(credit)
        for threshold in range(2 * horizon + 2):
            actual = Fraction(sum(s >= threshold for s in credits), len(credits))
            self.assertLessEqual(actual, fixed_query_tail(horizon, threshold, base, cap))

    def test_anytime_stopping_first_crossing_is_not_endpoint_only(self):
        modulus, horizon, cap = 4, 5, 2
        base = Fraction(2)
        envelope = step_envelope(base, cap)
        for threshold in (Fraction(3, 2), Fraction(2), Fraction(4)):
            hit = endpoint = 0
            for outputs in product(range(modulus), repeat=horizon):
                credit, crossed = 0, False
                for index, output in enumerate(outputs):
                    target = 1 + (credit + index) % (modulus - 1)
                    credit += (modulus // (target + 1)) * (output <= target)
                    crossed |= base ** credit / envelope ** (index + 1) >= threshold
                hit += crossed
                endpoint += base ** credit / envelope ** horizon >= threshold
            self.assertLessEqual(Fraction(hit, modulus ** horizon), 1 / threshold)
            self.assertGreaterEqual(hit, endpoint)

    def test_invalid_tail_inputs_do_not_return_a_confidence_claim(self):
        for base, cap in [(Fraction(1), 2), (2.0, 2), (Fraction(2), 0),
                          (Fraction(2), True), (Fraction(2), 4097)]:
            with self.assertRaises(ValueError):
                step_envelope(base, cap)
        for queries, credit in [(-1, 0), (True, 2), (1, -1), (4097, 1)]:
            with self.assertRaises(ValueError):
                fixed_query_tail(queries, credit, Fraction(2), 2)

    def test_tail_bound_saturation_and_zero_queries(self):
        self.assertEqual(fixed_query_tail(0, 0, Fraction(2), 2), 1)
        self.assertEqual(fixed_query_tail(4, 0, Fraction(2), 2), 1)
        self.assertLess(fixed_query_tail(4, 8, Fraction(2), 2), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
