"""Regression tests for source qualification, not native consensus security."""
from fractions import Fraction
from math import comb
import unittest

from mandatory_units_query import bernoulli_bounds
from quantum_bernoulli_source_audit import (
    DENSITY, Quadratic15, audit_report, certified_chain_tail,
    one_grover_partition_success, printed_bernoulli_expression,
    printed_chain_expression, printed_diagonal_geometric_expression,
    source_counterexample,
)


class QuantumBernoulliSourceAuditTests(unittest.TestCase):
    def test_one_query_strategy_exact(self):
        self.assertEqual(one_grover_partition_success(), Fraction(13073, 32768))

    def test_independent_statevector_calculation(self):
        # Direct phase + reflection on all 17 permutation classes, with exact
        # amplitudes. This does not call the closed-form Grover expression.
        expected = Fraction(0)
        for marked in range(17):
            phase_state = [Fraction(-1 if i < marked else 1, 4)
                           for i in range(16)]
            mean = sum(phase_state, Fraction(0)) / 16
            final_state = [2 * mean - amplitude for amplitude in phase_state]
            self.assertEqual(sum((a * a for a in final_state), Fraction(0)), 1)
            conditional = sum((final_state[i] ** 2 for i in range(marked)),
                              Fraction(0))
            probability = (comb(16, marked) * DENSITY ** marked
                           * (1 - DENSITY) ** (16 - marked))
            expected += probability * conditional
        self.assertEqual(expected, Fraction(13073, 32768))

    def test_exhaustive_truth_table_control(self):
        # Enumerate every 16-bit oracle, independently of binomial grouping.
        # The marked/unmarked amplitudes are (12-j)/16 and (4-j)/16.
        weight_by_marked_count = [15 ** (16 - j) for j in range(17)]
        numerator = 0
        for truth_table in range(1 << 16):
            j = truth_table.bit_count()
            marked = j * (12 - j) ** 2
            unmarked = (16 - j) * (4 - j) ** 2
            self.assertEqual(marked + unmarked, 256)
            numerator += weight_by_marked_count[j] * marked
        self.assertEqual(Fraction(numerator, 256 * 16 ** 16),
                         Fraction(13073, 32768))

    def test_three_partition_source_counterexample(self):
        exact_success = Fraction(2234219220017, 35184372088832)
        self.assertEqual(one_grover_partition_success() ** 3, exact_success)
        printed = printed_bernoulli_expression(3, 3)
        self.assertEqual(printed, Quadratic15(1786065, 461160, 67108864))
        self.assertTrue(printed.strictly_below(exact_success))
        witness = source_counterexample()
        self.assertTrue(witness["success_strictly_exceeds_printed_expression_exact"])
        self.assertEqual(
            witness["comparison_squared_gap"],
            "3636360139341798489242762333020607217664",
        )
        self.assertFalse(witness["full_value_chain_attack_demonstrated"])
        self.assertFalse(witness["actual_w1_attack_demonstrated"])

    def test_printed_progress_lemma_fails_exactly(self):
        # Two distinct fixed phase queries create a dual-record |11> amplitude
        # (2*sqrt(p*(1-p)))**2. Compare squares against printed Lemma 3.12.
        actual_amplitude = 4 * DENSITY * (1 - DENSITY)
        printed_upper_squared = 4 * (1 - DENSITY) * DENSITY ** 2
        self.assertEqual(actual_amplitude, Fraction(15, 64))
        self.assertEqual(actual_amplitude ** 2, Fraction(225, 4096))
        self.assertEqual(printed_upper_squared, Fraction(60, 4096))
        self.assertGreater(actual_amplitude ** 2, printed_upper_squared)

    def test_exact_quadratic_comparison(self):
        self.assertTrue(Quadratic15(0, 1, 1).strictly_below(Fraction(4)))
        self.assertFalse(Quadratic15(0, 1, 1).strictly_below(Fraction(3)))
        self.assertFalse(Quadratic15(2, 0, 2).strictly_below(Fraction(1)))
        self.assertFalse(Quadratic15(0, 0, 1).strictly_below(Fraction(0)))
        self.assertTrue(Quadratic15(0, 0, 1).strictly_below(Fraction(1)))

    def test_N_plus_k_substitution_is_algebra_only(self):
        self.assertEqual(printed_chain_expression(1, 1),
                         Quadratic15(285, 60, 256))
        report = audit_report(7, 7)
        self.assertEqual(report["printed_reduction_argument_N_plus_k"], 14)
        self.assertTrue(
            report["printed_chain_expression_only"]["strictly_below_one_exact"])
        self.assertFalse(report["source_bound_usable"])
        self.assertFalse(report["printed_expression_is_probability_certificate"])

    def test_geometric_expression_crossing_does_not_certify_source(self):
        self.assertFalse(
            printed_diagonal_geometric_expression(20).strictly_below(Fraction(1)))
        self.assertTrue(
            printed_diagonal_geometric_expression(21).strictly_below(Fraction(1)))
        report = audit_report(21, 21)
        self.assertEqual(report["status"], "REJECT_PRINTED_SOURCE_BOUND")
        self.assertFalse(report["source_bound_usable"])
        self.assertFalse(report["production_qualified"])

    def test_existing_conservative_proof_covers_counterexample(self):
        actual = one_grover_partition_success() ** 3
        conservative = bernoulli_bounds(3, 3, DENSITY)["bound"]
        self.assertGreaterEqual(conservative, actual)
        self.assertLess(conservative, 1)

    def test_existing_bit_query_tail_can_be_nontrivial(self):
        bound = bernoulli_bounds(64, 64, DENSITY)["bound"]
        self.assertLess(bound, Fraction(1, 1 << 15))
        self.assertGreater(bound, 0)

    def test_conservative_full_query_diagonal_remains_trivial(self):
        # The existing full-value simulation costs at most two bit queries.
        # Even granting chain extraction for free, no replacement diagonal
        # chain tail is certified by this conservative bound in the tested cap.
        for outputs in range(1, 65):
            with self.subTest(outputs=outputs):
                self.assertEqual(bernoulli_bounds(2 * outputs, outputs, DENSITY)
                                 ["bound"], Fraction(1))

    def test_numeric_input_validation(self):
        for n, k in [(0, 1), (1, 0), (1, 2), (True, 1), (1, True),
                     (4097, 1), (64, 65)]:
            with self.subTest(n=n, k=k):
                with self.assertRaises(ValueError):
                    printed_chain_expression(n, k)
        with self.assertRaises(ValueError):
            one_grover_partition_success(16, 0.0625)
        with self.assertRaises(ValueError):
            Quadratic15(0, -1, 1)
        with self.assertRaises(ValueError):
            Quadratic15(0, 1, 0)

    def test_rejected_source_cannot_issue_certificate(self):
        with self.assertRaisesRegex(ValueError, "PRINTED_SOURCE_BOUND_REJECTED"):
            certified_chain_tail(21, 21, preprocessing_charged=True,
                                 initial_state="terminal-oracle-independent")


if __name__ == "__main__":
    unittest.main()
