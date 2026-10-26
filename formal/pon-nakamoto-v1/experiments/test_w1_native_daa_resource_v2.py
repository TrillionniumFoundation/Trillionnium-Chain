"""Exact controls for dynamic native-rule work accounting; no timing claims."""
import itertools
import unittest
from fractions import Fraction

import w1_native_daa_resource_v2 as model


class NativeRules(unittest.TestCase):
    def test_native_rule_constants(self):
        self.assertEqual((model.INTERVAL, model.SPACING, model.MEDIAN_WIDTH, model.FUTURE_SKEW),
                         (16, 10, 11, 120))

    def test_target_edges_and_integer_mean(self):
        for bits in (3, 4, 8):
            for target in range(1, model.target_limit(bits) + 1):
                p = Fraction(target + 1, 1 << bits)
                w = (1 << bits) // (target + 1)
                self.assertEqual(model.expected_work(target, bits), p * w)
                self.assertLessEqual(p * w, 1)
                self.assertGreater(p * w, 1 - p)
        with self.assertRaises(ValueError):
            model.work(0)

    def test_native_256_bit_edges(self):
        limit = (1 << 255) - 1
        self.assertEqual(model.work(limit), 2)
        self.assertEqual(model.expected_work(limit), 1)
        self.assertEqual(model.work(1), 1 << 255)
        self.assertEqual(model.expected_work(1), 1)
        self.assertLess(model.expected_work((1 << 256) // 3), 1)

    def test_retarget_floor_clamp_and_saturating_span(self):
        target = model.target_limit()
        low = max(1, target * 38 // 150)
        self.assertEqual(model.native_retarget(target, 100, 99), low)
        self.assertEqual(model.native_retarget(target, 100, 100), low)
        self.assertEqual(model.native_retarget(target, 100, 138), low)
        self.assertEqual(model.native_retarget(target, 100, 250), target)
        self.assertEqual(model.native_retarget(1, 100, 101), 1)
        self.assertEqual(model.native_retarget(target, 0, model.U64_MAX), target)

    def test_upper_median_and_future_boundary(self):
        model.native_time(11, (10, 1), 11)
        with self.assertRaisesRegex(ValueError, '^TIME$'):
            model.native_time(10, (10, 1), 11)
        model.native_time(220, (1,), 100)
        with self.assertRaisesRegex(ValueError, 'TIME_DEFERRED'):
            model.native_time(221, (1,), 100)
        model.native_time(model.U64_MAX, (1,), model.U64_MAX)

    def test_parent_timestamp_need_not_be_monotone(self):
        model.native_time(12, (600, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5), 1201)
        with self.assertRaisesRegex(ValueError, '^TIME$'):
            model.native_time(10, (600, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5), 1201)

    def test_exact_native_bookends(self):
        result = model.bookend_vectors()
        self.assertEqual(result['base_height'], 30)
        self.assertEqual(result['base_work'], 135)
        rows = result['branches']
        self.assertEqual([rows[k]['work32'] for k in ('tighten', 'unchanged', 'ease')], [31, 7, 2])
        self.assertEqual([rows[k]['raw_span'] for k in ('tighten', 'unchanged', 'ease')], [20, 150, 600])
        self.assertEqual([rows[k]['chainwork32'] for k in ('tighten', 'unchanged', 'ease')], [173, 149, 144])
        self.assertEqual(result['all_forest_work'], 196)

    def test_rule_schedule_has_no_wall_rate_claim(self):
        first = model.bookend_vectors(now=1201)
        delayed = model.bookend_vectors(now=1_000_000)
        self.assertEqual(first['branches'], delayed['branches'])
        self.assertFalse(first['native_execution_claim'])

    def test_daa_weight_cap_crossing_and_external_parent_gap(self):
        parent = model.bookend_parent()
        self.assertEqual(model.dda_weight_envelope((parent,), 1, 0)['weight_cap'], 7)
        self.assertEqual(model.dda_weight_envelope((parent,), 2, 0)['weight_cap'], 31)
        self.assertEqual(model.dda_weight_envelope((parent,), 1, 1)['weight_cap'], 31)
        self.assertEqual(model.dda_weight_envelope((parent,), 0, None)['weight_cap'], 0)
        self.assertEqual(model.dda_weight_envelope((parent,), 2, None)['weight_cap'], 1 << 255)

    def test_envelope_contains_all_small_rule_spans(self):
        for bits in (4, 8):
            for target in range(1, model.target_limit(bits) + 1):
                lower = max(1, target * 38 // 150)
                for span in (0, 1, 37, 38, 39, 149, 150, 151, 599, 600, 601):
                    self.assertGreaterEqual(model.native_retarget(target, 0, span, bits), lower)


class ResourceAccounting(unittest.TestCase):
    def test_bank_deduplication_and_conflicting_identity(self):
        self.assertEqual(model.known_bank_weight((('a', 31), ('a', 31), ('b', 2))), 33)
        with self.assertRaisesRegex(ValueError, 'BANK_IDENTITY_WEIGHT'):
            model.known_bank_weight((('a', 31), ('a', 2)))

    def test_bank_and_failure_are_not_free_queries(self):
        self.assertEqual(model.forest_markov_bound(0, 31, bank=31), 1)
        self.assertEqual(model.forest_markov_bound(0, 32, bank=31), 0)
        self.assertEqual(model.forest_markov_bound(0, 32, bank=31, failure=Fraction(1, 100)), Fraction(1, 100))
        self.assertEqual(model.forest_markov_bound(2, 38), Fraction(1, 19))
        self.assertEqual(model.forest_markov_bound(2, 38, bank=7), Fraction(2, 31))

    def test_mgf_is_exact_and_refuses_exponential_materialization(self):
        actual = model.forest_mgf_bound(2, 38, 31, Fraction(11, 10))
        self.assertIsInstance(actual, Fraction)
        self.assertGreater(actual, 0)
        self.assertLess(actual, 1)
        self.assertIsNone(model.forest_mgf_bound(2, 38, 1 << 255, Fraction(11, 10)))
        self.assertEqual(model.forest_mgf_bound(0, 32, 31, 2, bank=31), Fraction(1, 2))

    def test_convex_mgf_bound_for_every_small_native_target(self):
        z = Fraction(9, 8)
        for target in range(1, model.target_limit(8) + 1):
            w, p = model.work(target, 8), model.probability(target, 8)
            beta = 1 + (z ** 128 - 1) / 128
            self.assertLessEqual(1 + p * (z ** w - 1), beta)

    def test_adaptive_normalized_capital_mean_one(self):
        # Independent explicit enumeration of all branches of a predictable policy.
        z = Fraction(6, 5)
        total_mass = Fraction()
        expected_capital = Fraction()
        expected_work = Fraction()
        for outcomes in itertools.product((False, True), repeat=3):
            mass, amount = Fraction(1), 0
            rows = []
            for index, hit in enumerate(outcomes):
                target = 7 if index == 0 or not outcomes[index - 1] else 2
                p, w = model.probability(target, 4), model.work(target, 4)
                mass *= p if hit else 1 - p
                amount += w * hit
                rows.append((target, hit))
            total_mass += mass
            expected_capital += mass * model.adaptive_capital(tuple(rows), z, 4)
            expected_work += mass * amount
        self.assertEqual(total_mass, 1)
        self.assertEqual(expected_capital, 1)
        self.assertLessEqual(expected_work, 3)

    def test_budget_stopping_with_large_jump_not_fixed_binomial(self):
        # One paid chance with weight 8 succeeds with probability 1/8.
        target = 1
        p = model.probability(target, 4)
        self.assertEqual(p, Fraction(1, 8))
        self.assertEqual(model.forest_markov_bound(1, 8), p)
        self.assertGreater(p, 0)  # A unit-weight one-trial count would have zero tail at 8.

    def test_post_answer_target_choice_invalidates_mean_claim(self):
        total = sum(model.work(max(1, digest), 8) for digest in range(model.target_limit(8) + 1))
        self.assertGreater(Fraction(total, 1 << 8), 1)
        # This is a premise-failure control, NOT a legal header/DAA attack.

    def test_numeric_aliases_are_rejected(self):
        for bad in (True, 1.0, -1):
            with self.assertRaises(ValueError):
                model.forest_markov_bound(bad, 10)
        with self.assertRaises(ValueError):
            model.adaptive_capital(((7, 1),), Fraction(2), 4)


class FiniteAdaptivePolicy(unittest.TestCase):
    def test_two_query_native_dynamic_tail_has_independent_formula(self):
        root = model.bookend_parent()
        vectors = model.bookend_vectors()['branches']
        p = model.probability(root.target)
        hard = p * model.probability(vectors['tighten']['target32'])
        easy = p * model.probability(vectors['ease']['target32'])
        self.assertEqual(model.exact_finite_policy_tail(2, 38), hard)
        self.assertEqual(model.exact_finite_policy_tail(2, 9), easy)
        self.assertGreater(hard, 0)
        self.assertGreater(easy, hard)

    def test_native_dynamic_tail_obeys_all_forest_bound(self):
        for threshold in (1, 7, 9, 14, 38, 39, 63):
            actual = model.exact_finite_policy_tail(2, threshold)
            self.assertLessEqual(actual, model.forest_markov_bound(2, threshold))
            self.assertLessEqual(actual, model.forest_mgf_bound(2, threshold, 31, Fraction(11, 10)))

    def test_zero_budget_and_initial_preparation_boundary(self):
        self.assertEqual(model.exact_finite_policy_tail(0, 1), 0)
        self.assertEqual(model.exact_finite_policy_tail(0, 0), 1)
        self.assertEqual(model.exact_finite_policy_tail(1, 38), 0)

    def test_forest_dominates_heaviest_extension(self):
        for threshold in (7, 9, 14, 21, 38):
            self.assertLessEqual(model.exact_finite_policy_tail(3, threshold, metric='heaviest-extension', bits=8),
                                 model.exact_finite_policy_tail(3, threshold, bits=8))

    def test_limited_policy_does_not_accept_arbitrary_mode(self):
        with self.assertRaises(ValueError):
            model.exact_finite_policy_tail(5, 1)
        with self.assertRaises(ValueError):
            model.exact_finite_policy_tail(1, 1, metric='common-prefix')


if __name__ == '__main__':
    unittest.main()
