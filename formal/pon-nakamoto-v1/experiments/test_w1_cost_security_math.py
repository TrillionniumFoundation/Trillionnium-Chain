"""Finite, exact checks of the research model's probability and cost boundaries."""

from __future__ import annotations

import itertools
import unittest
from fractions import Fraction

from w1_cost_security_math import (
    binomial_pgf_upper,
    binomial_tail,
    effective_share,
    hybrid_acceleration,
    hybrid_unknown_useful_limit,
    minimum_floor_fraction,
    raw_share_at_threshold,
    report,
    target_probability,
)


class ExactCostSecurityMath(unittest.TestCase):
    def test_binomial_tail_matches_exhaustive_weighted_bit_strings(self):
        # Independent enumeration, including unequal Bernoulli probabilities.
        for q in range(7):
            for p in (Fraction(0), Fraction(1, 3), Fraction(1, 2), Fraction(1)):
                for threshold in range(q + 2):
                    enumerated = Fraction(0)
                    for bits in itertools.product((0, 1), repeat=q):
                        if sum(bits) >= threshold:
                            weight = Fraction(1)
                            for bit in bits:
                                weight *= p if bit else 1 - p
                            enumerated += weight
                    self.assertEqual(binomial_tail(q, p, threshold), enumerated)

    def test_generating_function_upper_really_bounds_exact_tails(self):
        for q in range(17):
            for p in (Fraction(0), Fraction(1, 32), Fraction(1, 2), Fraction(1)):
                for threshold in range(q + 2):
                    exact = binomial_tail(q, p, threshold)
                    for z in (Fraction(1), Fraction(3, 2), Fraction(4)):
                        self.assertGreaterEqual(
                            binomial_pgf_upper(q, p, threshold, z), exact
                        )

    def test_same_marginals_and_mean_do_not_imply_binomial_tail(self):
        independent_tail = binomial_tail(8, Fraction(1, 2), 8)
        # Eight perfectly correlated fair bits have the same per-bit marginals
        # and expected total of four, but all eight win with probability 1/2.
        correlated = ((Fraction(1, 2), 0), (Fraction(1, 2), 8))
        self.assertEqual(sum(prob * count for prob, count in correlated), 4)
        correlated_tail = sum(prob for prob, count in correlated if count >= 8)
        self.assertEqual(independent_tail, Fraction(1, 256))
        self.assertEqual(correlated_tail, Fraction(1, 2))
        self.assertGreater(correlated_tail, independent_tail)

    def test_observed_stopping_count_cannot_be_used_as_fixed_query_bound(self):
        # Stop at first hit, or at eight trials. Conditional on observed Q=1,
        # success is certain, unlike a precommitted one-query Bernoulli trial.
        stopped_after_one = []
        for bits in itertools.product((0, 1), repeat=8):
            attempts = next((i + 1 for i, bit in enumerate(bits) if bit), 8)
            if attempts == 1:
                stopped_after_one.append(int(any(bits[:attempts])))
        conditional = Fraction(sum(stopped_after_one), len(stopped_after_one))
        self.assertEqual(conditional, 1)
        self.assertEqual(binomial_tail(1, Fraction(1, 2), 1), Fraction(1, 2))

    def test_refunding_misses_is_not_a_one_attempt_physical_budget(self):
        actual = binomial_tail(8, Fraction(1, 2), 1)
        charged_only_on_success = binomial_tail(1, Fraction(1, 2), 1)
        self.assertEqual(actual, Fraction(255, 256))
        self.assertGreater(actual, charged_only_on_success)

    def test_target_zero_and_inclusive_threshold_boundaries(self):
        self.assertEqual(target_probability(0), 0)
        self.assertEqual(target_probability(1), Fraction(1, 1 << 255))
        self.assertEqual(target_probability((1 << 255) - 1), Fraction(1, 2))
        self.assertEqual(target_probability((1 << 251) - 1), Fraction(1, 32))
        self.assertEqual(target_probability((1 << 256) - 1), 1)
        for invalid in (-1, 1 << 256, True):
            with self.assertRaises(ValueError):
                target_probability(invalid)

    def test_share_threshold_is_exact_inverse_including_non_half_targets(self):
        for acceleration in (Fraction(1), Fraction(11, 10), Fraction(5, 4), Fraction(4)):
            for threshold in (Fraction(1, 3), Fraction(1, 2), Fraction(2, 3)):
                raw = raw_share_at_threshold(acceleration, threshold)
                self.assertEqual(effective_share(raw, acceleration), threshold)
                self.assertLess(effective_share(raw / 2, acceleration), threshold)
        self.assertEqual(raw_share_at_threshold(Fraction(2), Fraction(1, 2)), Fraction(1, 3))

    def test_hybrid_endpoints_and_explicit_floor_hardware_advantage(self):
        self.assertEqual(hybrid_acceleration(Fraction(0), Fraction(4), Fraction(2)), 4)
        self.assertEqual(hybrid_acceleration(Fraction(1), Fraction(4), Fraction(2)), 2)
        self.assertEqual(hybrid_unknown_useful_limit(Fraction(1, 10)), 10)
        self.assertEqual(hybrid_unknown_useful_limit(Fraction(1, 10), Fraction(2)), 20)
        self.assertIsNone(hybrid_unknown_useful_limit(Fraction(0)))
        for beta in (Fraction(1, 10), Fraction(1, 2), Fraction(1)):
            finite = hybrid_acceleration(beta, Fraction(4))
            limit = hybrid_unknown_useful_limit(beta)
            self.assertLessEqual(finite, limit)

    def test_minimum_floor_fraction_meets_target_and_smaller_fraction_fails(self):
        for useful in (Fraction(2), Fraction(4), Fraction(100)):
            for target in (Fraction(11, 10), Fraction(5, 4), Fraction(3, 2)):
                beta = minimum_floor_fraction(useful, target)
                self.assertIsNotNone(beta)
                self.assertEqual(hybrid_acceleration(beta, useful), target)
                self.assertGreater(hybrid_acceleration(beta * Fraction(999, 1000), useful), target)
        self.assertEqual(minimum_floor_fraction(Fraction(4), Fraction(5, 4)), Fraction(11, 15))
        self.assertEqual(minimum_floor_fraction(Fraction(2), Fraction(2)), 0)
        self.assertIsNone(minimum_floor_fraction(Fraction(4), Fraction(3, 2), Fraction(2)))

    def test_invalid_models_fail_instead_of_emitting_a_probability(self):
        for q, p in ((-1, Fraction(1, 2)), (4097, Fraction(1, 2)), (1, Fraction(2))):
            with self.assertRaises(ValueError):
                binomial_tail(q, p, 1)
        with self.assertRaises(ValueError):
            binomial_pgf_upper(2, Fraction(1, 2), 1, Fraction(1, 2))
        with self.assertRaises(ValueError):
            effective_share(Fraction(1, 2), Fraction(0))
        with self.assertRaises(ValueError):
            hybrid_acceleration(Fraction(2), Fraction(4))

    def test_report_retains_limits_and_does_not_claim_native_qualification(self):
        result = report()
        self.assertFalse(result["native_measurement"])
        self.assertFalse(result["work_hardness_qualified"])
        self.assertFalse(result["production_activation"])
        setup = result["one_setup_shared_across_four_parent_searches"]
        self.assertEqual(setup["actual_joint_cost_units"], 16)
        self.assertEqual(setup["discarded_parent_work_refund_units"], 0)
        self.assertEqual(len(result["preselected_sensitivity_targets"]), 4)


if __name__ == "__main__":
    unittest.main()
