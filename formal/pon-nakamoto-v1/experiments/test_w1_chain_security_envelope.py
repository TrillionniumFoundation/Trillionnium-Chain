#!/usr/bin/env python3
"""Independent finite controls for conditional chain-security arithmetic."""
from fractions import Fraction as F
from functools import lru_cache
from itertools import product
import unittest
from unittest.mock import patch

import w1_chain_security_envelope as model


class NativeArithmetic(unittest.TestCase):
    def test_actual_extreme_targets_and_big_integer_width(self):
        scale = 1 << 256
        self.assertEqual(model.required_work(1), 1 << 255)
        self.assertEqual(model.required_work(scale - 1), 1)
        self.assertEqual(model.required_work(scale // 2 - 1), 2)
        self.assertEqual(model.target_probability(scale // 2 - 1), F(1, 2))
        self.assertGreater((scale // 2 - 1) * 600, (1 << 256) - 1)

    def test_uniform_outcome_enumeration_matches_expected_weight(self):
        for bits in range(3, 10):
            scale = 1 << bits
            for target in range(1, scale):
                weight = model.required_work(target, bits)
                wins = sum(outcome <= target for outcome in range(scale))
                self.assertEqual(model.expected_work_per_opportunity(target, bits), F(wins * weight, scale))

    def test_floor_efficiency_minimum_by_exhaustive_small_spaces(self):
        for bits in range(3, 13):
            scale = 1 << bits
            values = [model.expected_work_per_opportunity(target, bits) for target in range(1, scale // 2)]
            self.assertGreater(min(values), F(2, 3))
            self.assertEqual(min(values), model.expected_work_per_opportunity(scale // 3, bits))
            self.assertEqual(max(values), 1)

    def test_256_bit_minimum_and_cross_target_ratio_are_not_one(self):
        scale = 1 << 256
        minimum = model.expected_work_per_opportunity(scale // 3)
        self.assertEqual(minimum, F(2, 3) + F(4, 3 * scale))
        self.assertLess(minimum, 1)
        self.assertLess(1 / minimum, F(3, 2))

    def test_zero_and_out_of_range_target_rejected(self):
        for value in [0, -1, 1 << 256, True, 1.0, "1"]:
            with self.assertRaises(ValueError):
                model.required_work(value)

    def test_reference_native_daa_schedule_integer_values(self):
        limit = (1 << 255) - 1
        first = model.retarget(limit, 0, 15, 16, 10, limit)
        second = model.retarget(first, 16, 31, 16, 10, limit)
        self.assertEqual(first, limit * 38 // 150)
        self.assertEqual(second, first * 38 // 150)
        next_targets = [model.retarget(second, first_time, last_time, 16, 10, limit)
                        for first_time, last_time in [(320, 470), (32, 47), (27, 627)]]
        self.assertEqual([model.required_work(v) for v in next_targets], [31, 123, 7])
        self.assertEqual(next_targets[2], second * 4)

    def test_daa_bounds_backward_times_and_parameter_overflow(self):
        limit = (1 << 255) - 1
        self.assertEqual(model.retarget(limit, 100, 0, 16, 10, limit), limit * 38 // 150)
        self.assertEqual(model.retarget(limit, 0, 10000, 16, 10, limit), limit)
        self.assertEqual(model.retarget(1, 0, 1, 16, 10, limit), 1)
        for interval, spacing in [(15, 10), (16, 0), (16, 1 << 64), (16, (1 << 64) // 15)]:
            with self.assertRaises(ValueError):
                model.retarget(limit, 0, 15, interval, spacing, limit)

    def test_median_allows_backward_adjacent_timestamp(self):
        self.assertEqual(model.timestamp_verdict(27, list(range(31, 20, -1)), 507, 120), "accept")
        self.assertEqual(model.timestamp_verdict(26, list(range(31, 20, -1)), 507, 120), "TIME")
        self.assertEqual(model.timestamp_verdict(628, [627] + list(range(46, 36, -1)), 507, 120), "TIME_DEFERRED")
        self.assertEqual(model.timestamp_verdict(628, [627] + list(range(46, 36, -1)), 508, 120), "accept")

    def test_timestamp_upper_median_and_u128_future_sum(self):
        self.assertEqual(model.timestamp_verdict(2, [1, 2], 10, 0), "TIME")
        self.assertEqual(model.timestamp_verdict((1 << 64) - 1, [1], (1 << 64) - 1, 120), "accept")
        with self.assertRaises(ValueError):
            model.timestamp_verdict(2, [], 10, 0)

    def test_post_reveal_target_choice_breaks_per_opportunity_bound(self):
        # Deliberately invalid challenge-binding model, never an actual W1 attack.
        scale, limit = 256, 127
        expected = sum(model.required_work(max(1, outcome), 8) for outcome in range(limit + 1)) / F(scale)
        self.assertGreater(expected, 1)
        self.assertTrue(all(model.expected_work_per_opportunity(target, 8) <= 1 for target in range(1, limit + 1)))


class ResourceAndDelay(unittest.TestCase):
    def test_effective_fraction_and_half_boundary(self):
        for kappa in [F(11, 10), F(5, 4), F(2), F(4)]:
            self.assertEqual(model.effective_share(1 / (1 + kappa), kappa), F(1, 2))
        self.assertEqual(model.effective_share(F(1, 3), F(5, 4)), F(5, 13))

    def test_delay_can_destroy_less_than_half_region(self):
        a, h = model.fixed_target_rates(F(1, 3), F(5, 4), F(1, 10))
        self.assertLess(a, h)
        self.assertTrue(model.delayed_region(a, h, 1)["fixed_target_model_feasible"])
        self.assertFalse(model.delayed_region(a, h, 10)["fixed_target_model_feasible"])
        self.assertEqual(model.kappa_ceiling(F(1, 3), F(1, 10), 10), F(6, 5))

    def test_boundary_is_not_strictly_secure(self):
        a, h = model.fixed_target_rates(F(1, 3), F(6, 5), F(1, 10))
        self.assertEqual(model.delayed_region(a, h, 10)["status"], "boundary")
        self.assertFalse(model.delayed_region(a, h, 10)["fixed_target_model_feasible"])

    def test_honest_availability_loss_is_explicit(self):
        a, h = model.fixed_target_rates(F(1, 3), 1, F(1, 10), F(1, 2))
        self.assertEqual(a, h)
        self.assertFalse(model.delayed_region(a, h, 0)["fixed_target_model_feasible"])

    def test_zero_rate_is_not_liveness(self):
        self.assertEqual(model.delayed_region(0, 0, 10)["status"], "no-honest-growth")
        self.assertIsNone(model.kappa_ceiling(F(1, 3), 0, 10))
        self.assertEqual(model.delayed_region(0, F(1, 10), 10)["pacer_rate"], F(1, 20))

    def test_interval_sensitivity_does_not_choose_production_threshold(self):
        for q in [F(1, 10), F(1, 3), F(2, 5)]:
            for delay in [0, 1, 10]:
                ceiling = model.kappa_ceiling(q, F(1, 10), delay)
                a = F(1, 10) * q * ceiling
                h = F(1, 10) * (1 - q)
                self.assertEqual(model.delayed_region(a, h, delay)["margin"], 0)


class CouplingAndCount(unittest.TestCase):
    def test_or_is_not_a_binomial_count(self):
        actual = model.grouped_or_pmf([2], F(1, 2))
        virtual = model.bernoulli_count_pmf(2, F(1, 2))
        self.assertEqual(actual, [F(1, 4), F(3, 4)])
        self.assertEqual(virtual, [F(1, 4), F(1, 2), F(1, 4)])
        self.assertEqual(1 - actual[0], 1 - virtual[0])
        self.assertNotEqual(actual, virtual)

    def test_grouped_or_independent_bit_enumeration(self):
        groups = [1, 2, 3]
        counts = [0] * (len(groups) + 1)
        for bits in product([0, 1], repeat=sum(groups)):
            offset = 0
            wins = 0
            for size in groups:
                wins += any(bits[offset:offset + size])
                offset += size
            counts[wins] += 1
        self.assertEqual(model.grouped_or_pmf(groups, F(1, 2)), [F(n, 64) for n in counts])

    def test_or_counts_are_dominated_not_equal(self):
        grouped = model.grouped_or_pmf([2, 3], F(1, 3))
        virtual = model.bernoulli_count_pmf(5, F(1, 3))
        for k in range(6):
            self.assertLessEqual(sum(grouped[k:]), sum(virtual[k:]))
        self.assertLess(sum(i * p for i, p in enumerate(grouped)), sum(i * p for i, p in enumerate(virtual)))

    def test_strict_heavier_and_tie_models_differ(self):
        self.assertEqual(model.private_catchup_from_deficit(F(1, 3), 0), F(1, 2))
        self.assertEqual(model.private_catchup_from_deficit(F(1, 3), 0, True), 1)
        self.assertEqual(model.private_catchup_from_deficit(F(1, 2), 6), 1)

    def test_known_deficit_formula_does_not_erase_wait_period(self):
        for q in [F(1, 10), F(1, 4), F(1, 3)]:
            known = model.private_catchup_from_deficit(q, 6)
            waiting = model.private_attack_after_honest_wait(q, 6)
            bank = model.private_attack_after_honest_wait(q, 6, 2)
            self.assertLess(known, waiting)
            self.assertLess(waiting, bank)

    def test_negative_binomial_against_separate_absorbing_recursion(self):
        for q in [F(1, 5), F(1, 3)]:
            for depth in range(1, 7):
                for bank in [0, 1, 2]:
                    for ties in [False, True]:
                        threshold = depth - bank + (0 if ties else 1)
                        @lru_cache(None)
                        def solve(honest, attacker):
                            if attacker >= threshold:
                                return F(1)
                            if honest == depth:
                                return (q / (1 - q))**(threshold - attacker)
                            return q * solve(honest, attacker + 1) + (1 - q) * solve(honest + 1, attacker)
                        self.assertEqual(model.private_attack_after_honest_wait(q, depth, bank, ties), solve(0, 0))

    def test_no_adversary_and_nonterminating_honest_wait(self):
        self.assertEqual(model.private_attack_after_honest_wait(0, 6), 0)
        self.assertEqual(model.private_attack_after_honest_wait(0, 6, 7), 1)
        with self.assertRaises(ValueError):
            model.private_attack_after_honest_wait(1, 6)


class ConditionalLead(unittest.TestCase):
    def test_exact_mgf_boundary_and_weighted_negative_drift(self):
        self.assertEqual(model.lead_mgf_upper(F(1, 5), F(3, 10), 1, 1, F(3, 2)), 1)
        self.assertEqual(model.lead_mgf_upper(F(1, 10), F(3, 5), 2, 1, F(3, 2)), F(37, 40))

    def test_adaptive_tree_crossing_matches_ville_bound(self):
        def policy(history):
            return (F(1, 10), F(3, 5), 2, 1) if history and history[-1] == "H" else (F(1, 5), F(3, 10), 1, 1)
        for bank in [0, 1]:
            for hurdle in [2, 3, 4]:
                probability = model.exact_adaptive_crossing(policy, 7, hurdle, bank)
                self.assertLessEqual(probability, model.lead_crossing_bound(F(3, 2), hurdle, bank))

    def test_crossing_enumeration_against_independent_bit_paths(self):
        probability = model.exact_adaptive_crossing(lambda _: (F(1, 4), F(3, 4), 1, 1), 6, 2)
        count = 0
        for choices in product(range(4), repeat=6):
            lead = 0
            crossed = False
            for bit in choices:
                lead += 1 if bit == 0 else -1
                crossed |= lead >= 2
            count += crossed
        self.assertEqual(probability, F(count, 4**6))

    def test_bank_failure_and_clipping_are_separate(self):
        self.assertEqual(model.lead_crossing_bound(2, 4, 1, F(1, 10)), F(9, 40))
        self.assertEqual(model.lead_crossing_bound(2, 4, 4), 1)
        self.assertEqual(model.lead_crossing_bound(2, 1, 0, F(3, 4)), 1)

    def test_mean_only_marginals_do_not_satisfy_conditional_mgf(self):
        # Correlated branch: after the first A all later steps are certainly A.
        first_mgf = model.lead_mgf_upper(F(1, 4), F(3, 4), 1, 1, 2)
        later_mgf = model.lead_mgf_upper(1, 0, 1, 1, 2)
        self.assertLessEqual(first_mgf, 1)
        self.assertGreater(later_mgf, 1)
        def correlated(history):
            if not history:
                return F(1, 4), F(3, 4), 1, 1
            return (1, 0, 1, 1) if history[0] == "A" else (0, 1, 1, 1)
        actual = model.exact_adaptive_crossing(correlated, 8, 8)
        self.assertEqual(actual, F(1, 4))
        self.assertGreater(actual, model.lead_crossing_bound(2, 8))

    def test_input_guards_refuse_floats_bools_and_impossible_probability(self):
        for bad in [True, 0.2, "1/5"]:
            with self.assertRaises(ValueError):
                model.lead_mgf_upper(bad, F(1, 2), 1, 1, 2)
        with self.assertRaises(ValueError):
            model.lead_mgf_upper(F(3, 4), F(1, 2), 1, 1, 2)
        with self.assertRaises(ValueError):
            model.lead_mgf_upper(F(1, 4), F(1, 2), 0, 1, 2)
        with self.assertRaises(ValueError):
            model.lead_crossing_bound(1, 4)

    def test_report_refuses_unreviewed_consensus_parameters(self):
        original = model.json.loads((model.ROOT / "config/pon/devnet-v1.json").read_text())
        for key, value in [("retarget_interval", 32), ("future_skew_seconds", 121),
                           ("target_spacing_seconds", 11), ("confirmation_depth", True),
                           ("production_activation", True)]:
            changed = dict(original, **{key: value})
            with patch.object(model.json, "loads", return_value=changed):
                with self.assertRaisesRegex(ValueError, "unreviewed"):
                    model.model_report()

    def test_generated_report_keeps_all_qualification_flags_false(self):
        result = model.model_report()
        self.assertFalse(result["O03_closed"])
        self.assertFalse(result["actual_W1_resource_bound_established"])
        self.assertFalse(result["all_adversarial_network_security_established"])
        self.assertFalse(result["production_activation"])
        self.assertEqual(len(result["fixed_target_rate_sensitivity"]), 16)
        self.assertEqual([row["required_work"] for row in result["reference_DAA_arithmetic"]], [31, 123, 7])


if __name__ == "__main__":
    unittest.main()
