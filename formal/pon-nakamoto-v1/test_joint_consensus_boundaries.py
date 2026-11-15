"""Exact boundary controls; no W1, hardware or network attack claim."""
from fractions import Fraction
from math import isqrt
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

from joint_consensus_boundaries import (
    DESIRED_SPAN, MIN_SPAN, POW_LIMIT, SPACE, clamp_path,
    floor_credit_counterexample, rational_sqrt, report,
    square_root_cost_counterexample, square_root_weight_classical_counterexample,
    uniform_expected_queries,
)
from reference import retarget, work


def unratio(value):
    return Fraction(int(value["numerator"]), int(value["denominator"]))


class ClampCompositionBoundaries(unittest.TestCase):
    def test_ceiling_and_integer_recurrence_compose_across_six_epochs(self):
        self.assertEqual((DESIRED_SPAN, MIN_SPAN), (150, 38))
        self.assertEqual(Fraction(MIN_SPAN, DESIRED_SPAN), Fraction(19, 75))
        initial = (1 << 240) - 1
        rows = clamp_path(initial, [0] * 6)
        target = initial
        for epoch, row in enumerate(rows, 1):
            following = int(row["target_after_hex"], 16)
            # Independent quotient inequalities identify the floor exactly.
            self.assertLessEqual(75 * following, 19 * target)
            self.assertLess(19 * target, 75 * (following + 1))
            self.assertEqual(row["bounded_span"], 38)
            self.assertLessEqual(Fraction(following), initial * Fraction(19, 75) ** epoch)
            self.assertEqual(int(row["integer_work_after"]), SPACE // (following + 1))
            target = following
        self.assertGreater(unratio(rows[-1]["credited_work_ratio_from_initial"]), 3000)
        self.assertGreater(unratio(rows[-1]["uniform_query_ratio_from_initial"]), 3000)
        self.assertLess(unratio(rows[-1]["uniform_query_ratio_from_initial"]), 4 ** 6)

    def test_negative_zero_and_short_positive_spans_share_lower_clamp(self):
        initial = (1 << 240) - 1
        targets = [clamp_path(initial, [span])[0]["target_after_hex"]
                   for span in (-600, -1, 0, 1, 37, 38)]
        self.assertEqual(len(set(targets)), 1)
        self.assertNotEqual(targets[0], clamp_path(initial, [39])[0]["target_after_hex"])
        self.assertEqual(clamp_path(initial, [600])[0]["target_after_hex"],
                         clamp_path(initial, [601])[0]["target_after_hex"])

    def test_target_floor_stops_growth_and_inclusive_ratio_can_equal_four(self):
        rows = clamp_path(7, [0, 0])
        self.assertEqual([int(row["target_after_hex"], 16) for row in rows], [1, 1])
        self.assertEqual(unratio(rows[0]["realized_uniform_query_ratio"]), 4)
        self.assertGreater(unratio(rows[0]["realized_uniform_query_ratio"]), Fraction(75, 19))
        self.assertEqual(unratio(rows[1]["realized_uniform_query_ratio"]), 1)
        self.assertEqual(work(1), 1 << 255)

    def test_path_rejects_invalid_exact_arithmetic_inputs(self):
        for initial, spans in ((True, [0]), (0, [0]), (POW_LIMIT + 1, [0]),
                               (7, []), (7, [True]), (7, [0.0]), (7, [1 << 64]),
                               (7, [-(1 << 64)]), (7, [0] * 257)):
            with self.subTest(initial=initial, spans=spans), self.assertRaises(ValueError):
                clamp_path(initial, spans)


class ProbabilityAndCreditBoundaries(unittest.TestCase):
    def test_floor_can_make_integer_block_credit_jump_more_than_four(self):
        result = floor_credit_counterexample()
        row = result["selected_retarget"]
        self.assertEqual((row["integer_work_before"], row["integer_work_after"]), ("2", "11"))
        self.assertEqual(unratio(row["realized_credited_work_ratio"]), Fraction(11, 2))
        self.assertLess(unratio(row["realized_uniform_query_ratio"]), 4)
        self.assertTrue(result["integer_credit_ratio_exceeds_four"])
        self.assertTrue(result["actual_query_ratio_at_most_four"])
        self.assertLess(unratio(result["classical_credit_per_uniform_query_before"]), 1)
        self.assertLess(unratio(result["classical_credit_per_uniform_query_after"]), 1)

    def test_reduced_width_exhaustive_inclusive_and_floor_bounds(self):
        # Exhaustive algebraic toy width, explicitly not a 4096-header network.
        bits = 12
        space, limit = 1 << bits, (1 << (bits - 1)) - 1
        saw_credit_jump_over_four = False
        for target in range(1, limit + 1):
            following = retarget(target, 100, 0, 16, 10, limit)
            before = uniform_expected_queries(target, bits)
            after = uniform_expected_queries(following, bits)
            self.assertLessEqual(after, 4 * before)
            self.assertLessEqual(work(following, bits), 4 * work(target, bits) + 3)
            self.assertLessEqual(Fraction(work(target, bits)), before)
            self.assertLess(before - work(target, bits), 1)
            self.assertLessEqual(Fraction(work(target, bits)) / before, 1)
            saw_credit_jump_over_four |= work(following, bits) > 4 * work(target, bits)
            self.assertEqual(before * (target + 1), space)
        self.assertTrue(saw_credit_jump_over_four)

    def test_uniform_cost_keeps_plus_one_and_valid_target_domain(self):
        self.assertEqual(uniform_expected_queries(1), 1 << 255)
        self.assertEqual(uniform_expected_queries(POW_LIMIT), 2)
        self.assertNotEqual(uniform_expected_queries(7), Fraction(SPACE, 7))
        for target in (0, True, -1, SPACE, 1.0):
            with self.assertRaises(ValueError):
                uniform_expected_queries(target)


class CostAndWeightCounterexamples(unittest.TestCase):
    def test_quantum_relative_credit_amplification_is_exact_but_conditional(self):
        result = square_root_cost_counterexample()
        self.assertEqual(unratio(result["easy_uniform_expected_queries"]), 16)
        self.assertEqual(unratio(result["hard_uniform_expected_queries"]), 256)
        self.assertEqual(unratio(result["credited_work_ratio_hard_over_easy"]), 16)
        self.assertEqual(unratio(result["classical_query_cost_ratio_hard_over_easy"]), 16)
        self.assertEqual(unratio(result["hypothesized_quantum_cost_ratio_hard_over_easy"]), 4)
        self.assertEqual(unratio(result["classical_credit_per_cost_relative_ratio"]), 1)
        self.assertEqual(unratio(result["hypothesized_quantum_credit_per_cost_relative_ratio"]), 4)
        self.assertTrue(result["distinct_target_bound_relations_required"])
        self.assertFalse(result["stored_ticket_rethresholding_performed"])
        self.assertFalse(result["retarget_transition_cost_included"])
        self.assertFalse(result["native_attack_or_profitability_established"])

    def test_sqrt_per_block_scoring_changes_classical_cost_order(self):
        result = square_root_weight_classical_counterexample()
        self.assertEqual(unratio(result["easy_expected_classical_queries"]), 256)
        self.assertEqual(unratio(result["hard_expected_classical_queries"]), 256)
        self.assertEqual(result["easy_linear_chain_score"], result["hard_linear_chain_score"])
        self.assertEqual(unratio(result["easy_sum_of_square_root_block_scores"]), 64)
        self.assertEqual(unratio(result["hard_sum_of_square_root_block_scores"]), 16)
        self.assertEqual(unratio(result["cheap_sequence_score_advantage_at_equal_mean_cost"]), 4)
        # A strictly greater MEAN classical cost can also lose the new score.
        easy_cost, hard_cost = 16 * 16, 2 * 256
        easy_new_score, hard_new_score = 16 * isqrt(16), 2 * isqrt(256)
        self.assertLess(easy_cost, hard_cost)
        self.assertGreater(easy_new_score, hard_new_score)
        self.assertFalse(result["competing_branch_target_paths_or_transition_cost_included"])
        self.assertFalse(result["pathwise_equal_cost_or_success_probability_claimed"])
        self.assertFalse(result["sqrt_of_total_chainwork_changes_fork_order"])
        self.assertTrue(result["integer_floor_of_sqrt_total_can_create_new_ties"])
        self.assertEqual(isqrt(16), isqrt(17))

    def test_rational_square_root_never_returns_an_approximation(self):
        self.assertEqual(rational_sqrt(Fraction(16, 81)), Fraction(4, 9))
        self.assertEqual(rational_sqrt(Fraction(0)), 0)
        self.assertIsNone(rational_sqrt(Fraction(2)))
        for value in (Fraction(-1), 4, 4.0):
            with self.assertRaises(ValueError):
                rational_sqrt(value)


class ReportBoundaries(unittest.TestCase):
    def test_scope_keeps_arithmetic_separate_from_native_w1_execution(self):
        result = report()
        self.assertEqual(result["schema"], "trnm-joint-consensus-boundaries-v1")
        self.assertFalse(result["repeated_clamp"]["mtp_admissible_branch_or_production_clock_constructed_here"])
        self.assertFalse(result["minimum_target_boundary"]["difficulty_growth_is_unbounded"])
        self.assertFalse(result["target_binding"]["stored_ticket_rethresholding_performed"])
        self.assertFalse(result["target_binding"]["w1_binding_controls_executed_by_this_module"])
        self.assertTrue(all(value is False or value == 0 for value in result["limitations"].values()))
        self.assertEqual(json.loads(json.dumps(result)), result)

    def test_cli_report_is_exact_and_refuses_overwrite(self):
        script = Path(__file__).with_name("joint_consensus_boundaries.py")
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "boundary.json"
            completed = subprocess.run([sys.executable, str(script), "--output", str(out)],
                                       capture_output=True, text=True, check=True)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(json.loads(out.read_text(encoding="utf-8")), report())
            original = out.read_bytes()
            refused = subprocess.run([sys.executable, str(script), "--output", str(out)],
                                     capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(out.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
