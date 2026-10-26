"""Countermodels and exact enumeration for the declared v4 barriers."""
from fractions import Fraction
from itertools import permutations, product
import hashlib
import unittest
from unittest.mock import patch

import w1_instantiation_barriers_v4 as model
import w1_multi_instance_cost_v2 as geometry
import w1_sha256_model_boundary as sha


class PublicAlgorithmBoundaryTests(unittest.TestCase):
    def test_one_query_public_comparison_exactly_distinguishes_small_permutations(self):
        # A fixed local program predicts one image. Exhaust every ideal permutation.
        for size in range(2, 7):
            for expected in range(size):
                accepted = sum(int(table[0] == expected) for table in permutations(range(size)))
                total = 1
                for i in range(2, size + 1):
                    total *= i
                ideal_acceptance = Fraction(accepted, total)
                self.assertEqual(ideal_acceptance, Fraction(1, size))
                self.assertEqual(1 - ideal_acceptance, model.public_algorithm_advantage(size))

    def test_actual_public_sha_comparison_uses_one_queried_round_family_call(self):
        for block in (bytes(64), bytes(range(64)), b"\xff" * 64):
            calls = []

            def actual(state, requested_block):
                calls.append((state, requested_block))
                return sha.permutation(state, requested_block)

            self.assertTrue(model.compare_public_sha_round(actual, block))
            self.assertEqual(calls, [(sha.IV, block)])
        self.assertEqual(model.public_algorithm_advantage(1 << 256), 1 - Fraction(1, 1 << 256))

    def test_literal_noise_and_ticket_digest_do_not_require_hashlib_call_interface(self):
        challenge = bytes(range(32))
        messages = (
            geometry.noise_message(challenge, 3, 127),
            geometry.pon_message(b"ticket", challenge, bytes(reversed(range(32)))),
        )
        expected = tuple(hashlib.sha256(message).hexdigest() for message in messages)
        with patch.object(hashlib, "sha256", side_effect=AssertionError("counted interface used")):
            observations = tuple(model.inline_sha_digest(message) for message in messages)
        for result, digest in zip(observations, expected):
            self.assertEqual(result["digest_hex"], digest)
            self.assertEqual(result["hashlib_sha256_api_calls"], 0)
            self.assertEqual(result["scalar_compression_executions"], 2)
            self.assertIsNone(result["physical_resource_lower_bound"])


class ThresholdPropertyTests(unittest.TestCase):
    def test_all_prefix_family_outputs_win_while_uniform_range_has_smaller_probability(self):
        for bits in range(2, 9):
            for prefix in range(1, bits):
                row = model.prefix_family_parameters(bits, prefix)
                self.assertTrue(all(y <= row["threshold"] for y in range(row["image_size"])))
                uniform = Fraction(sum(y <= row["threshold"] for y in range(1 << bits)), 1 << bits)
                self.assertEqual(uniform, row["uniform_n_bit_threshold_probability"])
                self.assertEqual(row["prefix_family_threshold_probability"], 1)
                self.assertFalse(row["preserves_full_n_bit_preimage_or_collision_strength"])

    def test_exact_target_preimage_probability_over_every_small_random_function(self):
        for size in range(2, 6):
            for queries in range(5):
                tables = tuple(product(range(size), repeat=queries))
                for target in range(size):
                    successful = sum(target in table for table in tables)
                    self.assertEqual(Fraction(successful, len(tables)),
                                     model.fresh_preimage_probability(size, queries))

    def test_exact_collision_probability_over_every_small_random_function(self):
        for size in range(2, 6):
            for queries in range(6):
                tables = tuple(product(range(size), repeat=queries))
                collisions = sum(len(set(table)) < len(table) for table in tables)
                self.assertEqual(Fraction(collisions, len(tables)),
                                 model.fresh_collision_probability(size, queries))

    def test_256_bit_label_does_not_preserve_full_256_bit_security_in_countermodel(self):
        row = model.prefix_family_parameters(256, 64)
        self.assertEqual(row["random_suffix_bits"], 192)
        self.assertEqual(row["uniform_n_bit_threshold_probability"], Fraction(1, 1 << 64))
        self.assertEqual(model.fresh_preimage_probability(1 << 192, 1), Fraction(1, 1 << 192))
        self.assertEqual(model.fresh_collision_probability(1 << 192, 2), Fraction(1, 1 << 192))
        self.assertFalse(row["preserves_full_n_bit_preimage_or_collision_strength"])

    def test_invalid_entropy_and_query_parameters_rejected(self):
        for args in ((256, 0), (256, 256), (2, 3), (True, 1), (256, False)):
            with self.assertRaises(ValueError):
                model.prefix_family_parameters(*args)
        for function in (model.fresh_preimage_probability, model.fresh_collision_probability):
            for args in ((1, 2), (4, -1), (4, True), (False, 2)):
                with self.assertRaises(ValueError):
                    function(*args)


class AuxiliaryInputRouteTests(unittest.TestCase):
    def test_both_direct_presampling_branches_are_vacuous_across_parameter_grid(self):
        for openings in range(1, 10):
            for captured in (0, 1, 2048, 2049, 2 * 2049 + 1):
                for advice in (0, 1, 256):
                    for gamma_bits in (2, 5, 40):
                        for fixed in (*range(1, 2 * openings + 2), 1024, 1 << 32):
                            row = model.presampling_direct_lift(advice, captured, openings, gamma_bits, fixed)
                            self.assertEqual(row["combined_calls"], captured + 3594 * openings)
                            self.assertFalse(row["multiplicative_capacity_event_nonempty"])
                            self.assertFalse(row["additive_joint_bound_can_be_nontrivial"])
                            if row["additive_capacity_event_nonempty"]:
                                self.assertGreaterEqual(row["additive_loss_before_clipping"], 1)
                                self.assertLess(fixed, openings)

    def test_large_prefixed_table_reduces_additive_loss_but_loses_capacity_information(self):
        row = model.presampling_direct_lift(0, 0, 2, 40, 1 << 60)
        self.assertLess(row["additive_loss_before_clipping"], 1)
        self.assertFalse(row["additive_capacity_event_nonempty"])
        self.assertGreater(row["additive_capacity_threshold"], 2)

    def test_small_table_keeps_possible_capacity_violation_but_transfer_loss_exceeds_one(self):
        row = model.presampling_direct_lift(0, 0, 2, 40, 1)
        self.assertTrue(row["additive_capacity_event_nonempty"])
        self.assertEqual(row["additive_capacity_threshold"], 2)
        self.assertGreater(row["additive_loss_before_clipping"], 1)

    def test_checker_calls_cannot_be_omitted_when_miner_makes_zero_calls(self):
        row = model.presampling_direct_lift(1, 0, 1, 2, 1)
        self.assertEqual(row["combined_calls"], 3594)
        self.assertEqual(row["multiplicative_minimum_fixed_pairs"], 6 * 5 * 3594)
        self.assertGreater(row["additive_loss_before_clipping"], 1)

    def test_invalid_lift_parameters_rejected(self):
        for args in ((-1, 0, 1, 2, 1), (0, -1, 1, 2, 1), (0, 0, 0, 2, 1),
                     (0, 0, 1, 1, 1), (0, 0, 1, 2, 0), (True, 0, 1, 2, 1)):
            with self.assertRaises(ValueError):
                model.presampling_direct_lift(*args)


class ConditionalTransferTests(unittest.TestCase):
    def setUp(self):
        self.caps = model.CapturedCaps(4, 6, 3, 2, 5)
        self.parameters = {
            "target": 127, "retirement_threshold": 1, "additional_winners": 2,
            "event_loss": None, "resource_conversion_loss": None, "identity_loss": None,
            "size": 1 << 20, "trace_blocks": 2,
        }

    def test_unknown_failures_never_become_zero_or_an_actual_bound(self):
        row = model.conditional_native_tail(self.caps, **self.parameters)
        self.assertIsNone(row["conditional_formula_only"])
        self.assertEqual(set(row["missing_actual_hypotheses"]),
                         {"w1_event_domination", "resource_conversion", "identity_transfer"})
        self.assertFalse(row["actual_protocol_bound_established"])
        self.assertFalse(row["physical_cost_floor_established"])
        self.assertTrue(row["K0_is_not_assumed_zero"])
        self.assertFalse(row["matches_w1_geometry"])

    def test_exhaustive_four_coin_comparison_matches_conditional_formula(self):
        parameters = {**self.parameters, "event_loss": Fraction(1, 100),
                      "resource_conversion_loss": Fraction(1, 200), "identity_loss": Fraction(0)}
        row = model.conditional_native_tail(self.caps, **parameters)
        self.assertEqual(row["new_opportunity_cap"], 4)
        self.assertEqual(row["combined_calls"], 13)
        self.assertEqual(row["reference_cap"], 48)
        p = row["pbar"]
        direct = sum((p ** sum(bits) * (1 - p) ** (4 - sum(bits))
                      for bits in product((0, 1), repeat=4) if sum(bits) >= 2), Fraction(0))
        self.assertEqual(row["ideal_model_tail"], direct + row["join_failure"])
        self.assertEqual(row["conditional_formula_only"], direct + row["join_failure"] + Fraction(3, 200))
        self.assertFalse(row["actual_protocol_bound_established"])

    def test_audit_exposure_changes_failure_and_probability_but_never_miner_capacity(self):
        a = model.conditional_native_tail(self.caps, **self.parameters)
        b = model.conditional_native_tail(model.CapturedCaps(4, 6, 50, 2, 5), **self.parameters)
        self.assertEqual(a["new_opportunity_cap"], b["new_opportunity_cap"])
        self.assertGreater(b["combined_calls"], a["combined_calls"])
        self.assertGreater(b["join_failure"], a["join_failure"])
        self.assertGreater(b["pbar"], a["pbar"])

    def test_reward_fanout_and_other_counting_units_are_not_silently_imported(self):
        for changes in ({"fanout": 2}, {"fanout": True}, {"count_unit": "subsidy-payments"},
                        {"count_unit": "proof-encodings"}, {"count_unit": "hepta-model-upgrades"}):
            with self.assertRaises(ValueError):
                model.conditional_native_tail(self.caps, **{**self.parameters, **changes})

    def test_retirement_requires_prepaid_paths_and_is_not_an_extra_free_bank(self):
        with self.assertRaises(ValueError):
            model.conditional_native_tail(self.caps, **{**self.parameters, "retirement_threshold": 3})
        base = model.conditional_native_tail(self.caps, **{**self.parameters, "retirement_threshold": 0})
        retired = model.conditional_native_tail(self.caps, **self.parameters)
        self.assertEqual(base["new_opportunity_cap"] - retired["new_opportunity_cap"], 1)

    def test_missing_one_hypothesis_still_leaves_actual_transfer_unavailable(self):
        for missing in ("event_loss", "resource_conversion_loss", "identity_loss"):
            losses = dict(event_loss=Fraction(0), resource_conversion_loss=Fraction(0), identity_loss=Fraction(0))
            losses[missing] = None
            row = model.conditional_native_tail(self.caps, **{**self.parameters, **losses})
            self.assertIsNone(row["conditional_formula_only"])
            self.assertEqual(len(row["missing_actual_hypotheses"]), 1)

    def test_invalid_loss_values_and_nonpositive_native_targets_rejected(self):
        for changes in ({"event_loss": 0}, {"event_loss": 0.0}, {"event_loss": Fraction(-1)},
                        {"event_loss": Fraction(2)}, {"target": 0}, {"target": 1 << 20},
                        {"target": 1 << 19},
                        {"additional_winners": 0}, {"retirement_threshold": True}):
            with self.assertRaises(ValueError):
                model.conditional_native_tail(self.caps, **{**self.parameters, **changes})

    def test_outside_nontrivial_join_range_returns_trivial_bound_without_large_tail_loop(self):
        row = model.conditional_native_tail(
            model.CapturedCaps(0, 10 ** 100, 0, 1),
            **{**self.parameters, "retirement_threshold": 0, "size": 256},
        )
        self.assertEqual(row["join_failure"], 1)
        self.assertEqual(row["ideal_model_tail"], 1)
        self.assertIsNone(row["conditional_formula_only"])

    def test_huge_nontrivial_exact_tail_refuses_computation_instead_of_fabricating_result(self):
        with self.assertRaisesRegex(OverflowError, "exact binomial"):
            model.conditional_native_tail(
                model.CapturedCaps(0, 2049 * 129, 1, 1), target=1,
                retirement_threshold=0, additional_winners=1,
                event_loss=None, resource_conversion_loss=None, identity_loss=None,
            )

    def test_impossible_requested_winner_count_needs_no_large_exact_expansion(self):
        row = model.conditional_native_tail(
            model.CapturedCaps(0, 2049 * 129, 1, 1), target=1,
            retirement_threshold=0, additional_winners=130,
            event_loss=None, resource_conversion_loss=None, identity_loss=None,
        )
        self.assertEqual(row["ideal_model_tail"], row["join_failure"])
        self.assertTrue(row["matches_w1_geometry"])

    def test_summary_cannot_claim_a_native_sha_attack_or_production_closure(self):
        row = model.summary()
        for key in ("actual_sha_w1_attack_demonstrated", "actual_sha_instantiation_proved",
                    "arbitrary_auxiliary_input_w1_bound_proved", "production_activation", "benchmark"):
            self.assertIs(row["claims"][key], False)
        self.assertIsNone(row["actual_w1_hypotheses_are_unknown"]["conditional_formula_only"])


if __name__ == "__main__":
    unittest.main()
