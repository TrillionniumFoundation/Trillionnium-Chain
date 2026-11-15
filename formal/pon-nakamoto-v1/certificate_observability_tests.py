"""Exact counterexamples and finite algebra; no native performance/risk claims."""
from fractions import Fraction as F
from itertools import product
import unittest

import certificate_observability_models as model
from mandatory_units_query import QueryBudget


class SharedLifetimePackingTests(unittest.TestCase):
    def test_repeated_delivery_does_not_start_a_new_work_clock(self):
        ledger = model.UniqueReadyLedger((model.ReadyDelivery("same", 1, 128),
                                          model.ReadyDelivery("same", 9, 128)))
        self.assertEqual(ledger.total, 128)
        window = model.Window("after_known_output", 8, 10, F(128))
        self.assertEqual(ledger.new_credit(window), 0)
        with self.assertRaisesRegex(model.ObservabilityError, "WINDOW_REQUIREMENT_UNSATISFIED"):
            model.check_window_witness(ledger, (window,), (F(1),), F(128))

    def test_overlapping_windows_cannot_charge_one_output_twice(self):
        ledger = model.UniqueReadyLedger((model.ReadyDelivery("one", 2, 128),))
        windows = (model.Window("first", 0, 3, F(128)), model.Window("second", 1, 4, F(128)))
        with self.assertRaisesRegex(model.ObservabilityError, "OVERLAP_REUSES_GLOBAL_CREDIT"):
            model.check_window_witness(ledger, windows, (F(1), F(1)), F(256))
        checked = model.check_window_witness(ledger, windows, (F(1, 2), F(1, 2)), F(128))
        self.assertEqual(checked["global_credit_margin"], 128)
        self.assertEqual(checked["global_unique_credit"], 128)

    def test_disjoint_half_open_windows_give_additive_credit(self):
        ledger = model.UniqueReadyLedger((model.ReadyDelivery("one", 2, 128),
                                          model.ReadyDelivery("two", 4, 128)))
        windows = (model.Window("left", 0, 2, F(128)), model.Window("right", 2, 4, F(128)))
        checked = model.check_window_witness(ledger, windows, (F(1), F(1)), F(256))
        self.assertEqual(checked["window_new_credits"], (128, 128))
        self.assertEqual(checked["maximum_point_coverage"], 1)
        self.assertEqual(checked["global_credit_margin"], 256)

    def test_coverage_is_checked_even_at_unobserved_cuts(self):
        # The actual outputs avoid cut 6. Checking only their coverage would
        # silently accept a dual certificate invalid for another possible run.
        windows = (model.Window("wide", 0, 10, F(1)), model.Window("narrow", 5, 6, F(0)))
        with self.assertRaisesRegex(model.ObservabilityError, "OVERLAP_REUSES_GLOBAL_CREDIT"):
            model.interval_packing(windows, (F(1), F(1)))

    def test_sweep_matches_every_cut_on_all_small_interval_pairs(self):
        intervals = [(start, end) for start in range(4) for end in range(start + 1, 5)]
        for left, right in product(intervals, repeat=2):
            windows = (model.Window("left", *left, F(1)), model.Window("right", *right, F(1)))
            for multipliers in ((F(1, 2), F(1, 2)), (F(1), F(0)), (F(0), F(1))):
                direct = max(sum((weight for window, weight in zip(windows, multipliers)
                                  if window.start < cut <= window.end), F(0)) for cut in range(6))
                self.assertEqual(model.interval_packing(windows, multipliers)["maximum_point_coverage"], direct)

    def test_weighted_packing_can_improve_uniform_overlap_division(self):
        ledger = model.UniqueReadyLedger((model.ReadyDelivery("one", 2, 128),
                                          model.ReadyDelivery("two", 8, 128)))
        windows = (model.Window("left", 0, 5, F(128)), model.Window("right", 5, 10, F(128)),
                   model.Window("wide", 0, 10, F(128)))
        uniform = model.interval_packing(windows, (F(1, 2),) * 3)
        selected = model.check_window_witness(ledger, windows, (F(1), F(1), F(0)), F(256))
        self.assertEqual(uniform["global_credit_margin"], 192)
        self.assertEqual(selected["global_credit_margin"], 256)

    def test_a_fixed_probability_threshold_cannot_be_silently_lowered(self):
        ledger = model.UniqueReadyLedger((model.ReadyDelivery("one", 1, 128),))
        window = model.Window("window", 0, 2, F(128))
        with self.assertRaisesRegex(model.ObservabilityError, "FIXED_THRESHOLD_NOT_REACHED"):
            model.check_window_witness(ledger, (window,), (F(1),), F(129))

    def test_thirty_two_overlapping_windows_use_one_lifetime_tail(self):
        ledger = model.UniqueReadyLedger(tuple(model.ReadyDelivery(str(i), i, 128) for i in range(1, 33)))
        windows = tuple(model.Window(str(i), 0, 32, F(4096)) for i in range(32))
        checked = model.check_window_witness(ledger, windows, (F(1, 32),) * 32, F(4096))
        self.assertEqual(checked["global_credit_margin"], 4096)
        bound = model.global_mu1_event_bound(QueryBudget(1, 32, True, True), F(4096))
        self.assertEqual(bound["window_count_union_factor"], 1)
        self.assertLess(bound["fresh_global_bound"]["bound"], F(7, 100))
        self.assertFalse(bound["post_selection_conditional_probability"])
        self.assertFalse(bound["native_confirmation_risk_qualified"])

    def test_conflicting_identity_or_noncausal_input_is_refused(self):
        for deliveries, error in (
            ((model.ReadyDelivery("same", 1, 16), model.ReadyDelivery("same", 2, 32)), "IDENTITY_CREDIT_CONFLICT"),
            ((model.ReadyDelivery("one", 2, 16), model.ReadyDelivery("two", 1, 16)), "DELIVERY_CAUSAL_ORDER"),
            ((model.ReadyDelivery("one", 1, True),), "OUTPUT_CREDIT"),
            ((model.ReadyDelivery("one", 1, 129),), "OUTPUT_CREDIT_CAP"),
        ):
            with self.subTest(error=error), self.assertRaisesRegex(model.ObservabilityError, error):
                model.UniqueReadyLedger(deliveries)


class PredictableRiskBankTests(unittest.TestCase):
    def test_adaptive_prefix_spending_under_one_correlated_joint_law(self):
        law = model.ProbabilityTree((
            model.Leaf("left_bad", ("left", "bad"), F(1, 100)),
            model.Leaf("left_safe", ("left", "safe"), F(49, 100)),
            model.Leaf("right_bad", ("right", "bad"), F(1, 200)),
            model.Leaf("right_safe", ("right", "safe"), F(99, 200)),
        ))
        attempts = (
            model.Attempt("root", (), ("left_bad", "right_bad"), F(3, 200)),
            model.Attempt("after_left", ("left",), ("left_bad",), F(1, 50)),
            model.Attempt("after_right", ("right",), ("right_bad",), F(1, 100)),
        )
        result = model.check_predictable_risk_bank(law, attempts, F(7, 200))
        self.assertEqual(result["failure_union_probability"], F(3, 200))
        self.assertEqual(result["expected_allowance_spent"], F(3, 100))
        self.assertEqual(result["maximum_path_allowance_spent"], F(7, 200))
        self.assertFalse(result["independence_between_attempts_required"])
        self.assertFalse(result["actual_probability_law_authenticated"])

    def test_perfectly_correlated_failures_are_not_multiplied(self):
        law = model.ProbabilityTree((model.Leaf("bad", ("bad",), F(1, 10)),
                                     model.Leaf("safe", ("safe",), F(9, 10))))
        attempts = tuple(model.Attempt(str(i), (), ("bad",), F(1, 10)) for i in range(2))
        result = model.check_predictable_risk_bank(law, attempts, F(1, 5))
        self.assertEqual(result["failure_union_probability"], F(1, 10))
        self.assertGreater(result["failure_union_probability"], F(1, 10) ** 2)

    def test_postselection_does_not_preserve_unconditional_risk(self):
        law = model.ProbabilityTree((model.Leaf("bad", ("seen_bad", "emit"), F(1, 100)),
                                     model.Leaf("safe", ("safe",), F(99, 100))))
        attempt = model.Attempt("selected_start", ("seen_bad",), ("bad",), F(1, 100))
        with self.assertRaisesRegex(model.ObservabilityError, "INVALID_CONDITIONAL_RISK_AT_START"):
            model.check_predictable_risk_bank(law, (attempt,), F(1, 100))

    def test_declared_pathwise_bank_refuses_overspending_even_if_expectation_is_small(self):
        # This interface checks a pathwise bank. A separately proved expected
        # allocation bound is another sufficient theorem, not checked here.
        law = model.ProbabilityTree((model.Leaf("rare", ("rare",), F(1, 100)),
                                     model.Leaf("usual", ("usual",), F(99, 100))))
        attempts = (model.Attempt("root", (), (), F(1, 10)),
                    model.Attempt("rare_extra", ("rare",), (), F(1, 2)))
        with self.assertRaisesRegex(model.ObservabilityError, "PREDICTABLE_RISK_BUDGET_OVERSPENT"):
            model.check_predictable_risk_bank(law, attempts, F(1, 5))

    def test_failure_before_or_outside_its_start_is_refused(self):
        law = model.ProbabilityTree((model.Leaf("left", ("left",), F(1, 2)),
                                     model.Leaf("right", ("right",), F(1, 2))))
        with self.assertRaisesRegex(model.ObservabilityError, "FAILURE_BEFORE_OR_OUTSIDE_START"):
            model.check_predictable_risk_bank(law, (model.Attempt("wrong", ("left",), ("right",), F(1)),), F(1))

    def test_incomplete_or_nonprefix_probability_law_is_refused(self):
        with self.assertRaisesRegex(model.ObservabilityError, "PROBABILITY_MASS_NOT_ONE"):
            model.ProbabilityTree((model.Leaf("only", ("one",), F(1, 2)),))
        with self.assertRaisesRegex(model.ObservabilityError, "HISTORIES_NOT_PREFIX_FREE"):
            model.ProbabilityTree((model.Leaf("ancestor", ("one",), F(1, 2)),
                                   model.Leaf("descendant", ("one", "two"), F(1, 2))))


class ResidualAdviceAndObservabilityTests(unittest.TestCase):
    def test_first_success_restart_has_exact_conditional_risk_one(self):
        result = model.first_success_restart_counterexample(16)
        self.assertEqual(result["probability_a_start_exists"], 1 - F(15, 16) ** 16)
        self.assertEqual(result["conditional_success_at_every_selected_start"], 1)
        self.assertTrue(result["even_unconditional_reset_claim_violated"])
        self.assertEqual(result["risk_bank_refusal"], "INVALID_CONDITIONAL_RISK_AT_START")
        self.assertEqual(result["proper_conditional_residual_bound"], 1)
        self.assertEqual(result["global_lifetime_query_bound"], 1)

    def test_finite_oracle_truth_table_advice_sharp_probability(self):
        result = model.full_table_advice_countermodel(64, 1)
        self.assertEqual(result["sharp_worst_case_success_with_unrestricted_finite_advice"],
                         1 - F(15, 16) ** 64)
        self.assertGreater(result["sharp_worst_case_success_with_unrestricted_finite_advice"], F(98, 100))
        self.assertEqual(result["new_queries"], 0)
        self.assertFalse(result["finite_state_space_implies_small_risk"])
        self.assertFalse(result["actual_w1_residual_profile_attested"])

    def test_joint_record_profile_matches_explicit_four_bit_purification(self):
        p, size = F(1, 16), 4
        result = model.full_table_advice_countermodel(size, size, p)
        actual_tails = [F(0) for _ in range(size + 1)]
        # Keep the copied classical-advice register: different f labels are
        # orthogonal and their probabilities add, rather than amplitudes.
        for truth in product((0, 1), repeat=size):
            truth_probability = p ** sum(truth) * (1 - p) ** (size - sum(truth))
            for record in product((0, 1), repeat=size):
                probability = truth_probability
                for bit, dual in zip(truth, record):
                    one_probability = p if bit == 0 else 1 - p
                    probability *= one_probability if dual else 1 - one_probability
                for threshold in range(sum(record) + 1):
                    actual_tails[threshold] += probability
        self.assertEqual(tuple(actual_tails), result["joint_initial_squared_tail"])

    def test_same_local_state_admits_dirac_failure_probabilities_zero_and_one(self):
        result = model.synthetic_counterpair()
        low, high = result["world_without_private_chain"], result["world_with_private_chain"]
        self.assertEqual(low["local_projection_sha256"], high["local_projection_sha256"])
        self.assertEqual(low["failure_probability_under_this_dirac_law"], 0)
        self.assertEqual(high["failure_probability_under_this_dirac_law"], 1)
        self.assertEqual(result["worst_case_sound_local_risk_upper_bound"], 1)
        self.assertFalse(result["native_validation_performed_by_this_model"])
        self.assertFalse(result["native_failure_probability_estimated"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
