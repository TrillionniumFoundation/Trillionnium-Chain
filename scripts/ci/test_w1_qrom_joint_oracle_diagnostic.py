#!/usr/bin/env python3
"""Verify toy joint laws by exhaustive finite experiments and boundary controls."""
from __future__ import annotations

from collections import defaultdict
from fractions import Fraction
import itertools
import json
from pathlib import Path
import subprocess
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'scripts'))
import w1_qrom_joint_oracle_diagnostic as model


def fraction(value):
    return Fraction(int(value['numerator']), int(value['denominator']))


class JointOracleDiagnosticTests(unittest.TestCase):
    def assert_unqualified(self, result):
        for key, value in result['qualification'].items():
            self.assertIsNone(value) if key.endswith('_bits') else self.assertIs(value, False)

    def test_exhaustive_joint_distribution_has_uniform_marginals_and_nonzero_alias_gap(self):
        for cardinality in (2, 3, 5, 7):
            with self.subTest(cardinality=cardinality):
                shared, independent = defaultdict(Fraction), defaultdict(Fraction)
                for value in range(cardinality):
                    shared[(value, value)] += Fraction(1, cardinality)
                for pair in itertools.product(range(cardinality), repeat=2):
                    independent[pair] += Fraction(1, cardinality**2)
                for distribution in (shared, independent):
                    self.assertEqual(sum(distribution.values()), 1)
                    for axis in (0, 1):
                        marginal = defaultdict(Fraction)
                        for pair, probability in distribution.items():
                            marginal[pair[axis]] += probability
                        self.assertEqual(set(marginal.values()), {Fraction(1, cardinality)})
                total_variation = sum(abs(shared[pair] - independent[pair])
                                      for pair in independent) / 2
                equality_gap = sum(shared[(v, v)] - independent[(v, v)]
                                   for v in range(cardinality))
                data = model.example_input('alias')
                data['range_cardinality'] = cardinality
                report = model.make_report(data)
                self.assertEqual(fraction(report['joint_total_variation_distance']), total_variation)
                self.assertEqual(fraction(report['equality_test']['acceptance_probability_gap']), equality_gap)
                self.assertGreater(total_variation, 0)
                self.assert_unqualified(report)

    def test_distinct_encoded_inputs_positive_control_matches_product_law(self):
        for cardinality in (2, 3, 5):
            functions = list(itertools.product(range(cardinality), repeat=2))
            distribution = defaultdict(Fraction)
            for function in functions:
                distribution[(function[0], function[1])] += Fraction(1, len(functions))
            data = model.example_input('separated')
            data['range_cardinality'] = cardinality
            report = model.make_report(data)
            self.assertIs(report['encoded_inputs_alias'], False)
            self.assertEqual(fraction(report['joint_total_variation_distance']), 0)
            self.assertEqual(fraction(report['shared_joint_law']['probability_of_each_diagonal_pair']),
                             distribution[(0, 0)])
            self.assertEqual(fraction(report['shared_joint_law']['probability_of_each_off_diagonal_pair']),
                             distribution[(0, 1)])
            self.assertIs(report['scope']['actual_w1_statement_or_reachable_commitment_checked'], False)
            self.assert_unqualified(report)

    def test_degenerate_one_element_range_does_not_claim_distinguishability(self):
        data = model.example_input('alias')
        data['range_cardinality'] = 1
        report = model.make_report(data)
        self.assertEqual(fraction(report['joint_total_variation_distance']), 0)
        self.assertEqual(fraction(report['equal_prior_optimal_guess_success']), Fraction(1, 2))

    def test_gap_and_guess_success_use_distinct_advantage_conventions(self):
        report = model.make_report(model.example_input('alias'))
        self.assertEqual(fraction(report['equality_test']['shared_acceptance_probability']), 1)
        self.assertEqual(fraction(report['equality_test']['independent_acceptance_probability']), Fraction(1, 16))
        self.assertEqual(fraction(report['equality_test']['acceptance_probability_gap']), Fraction(15, 16))
        self.assertEqual(fraction(report['equal_prior_optimal_guess_success']), Fraction(31, 32))

    def test_absent_range_or_bytes_remain_unknown(self):
        for field in ('range_cardinality', 'left_encoded_input_hex', 'right_encoded_input_hex'):
            data = model.example_input('alias')
            data[field] = None
            report = model.make_report(data)
            self.assertIsNone(report['joint_total_variation_distance'])
            self.assertIsNone(report['equality_test']['acceptance_probability_gap'])
            self.assertIsNone(report['shared_joint_law']['probability_of_each_diagonal_pair'])
            self.assert_unqualified(report)
        report = model.make_report({'schema': model.INPUT_SCHEMA, 'input_kind': 'hypothetical'})
        self.assertIsNone(report['encoded_inputs_alias'])
        self.assertIsNone(report['each_single_output_point_probability'])

    def test_empty_encoding_is_an_actual_byte_string_not_unknown(self):
        data = model.example_input('alias')
        data['left_encoded_input_hex'] = data['right_encoded_input_hex'] = ''
        report = model.make_report(data)
        self.assertIs(report['encoded_inputs_alias'], True)
        self.assertEqual(fraction(report['joint_total_variation_distance']), Fraction(15, 16))

    def test_cardinality_is_explicit_and_no_native_digest_conversion_is_accepted(self):
        for key, value in (('sigma', 256), ('babybear_words', 8), ('quantum_security_bits', 128),
                           ('actual_poseidon_distribution_proved', True)):
            data = model.example_input('alias')
            data[key] = value
            with self.assertRaises(model.OracleModelError):
                model.make_report(data)
        for value in (True, False, 0, -1, 1.0, '01', '+2', '1e3', 1 << model.MAX_RANGE_BITS):
            data = model.example_input('alias')
            data['range_cardinality'] = value
            with self.subTest(value=value), self.assertRaises(model.OracleModelError):
                model.make_report(data)

    def test_noncanonical_or_unbounded_encoding_is_refused(self):
        for value in (True, [], 'A0', '0', '0x00', ' 00', '00 ' , '00' * (model.MAX_ENCODED_BYTES + 1)):
            data = model.example_input('alias')
            data['left_encoded_input_hex'] = value
            with self.subTest(value_type=type(value)), self.assertRaises(model.OracleModelError):
                model.make_report(data)

    def test_cli_examples_roundtrip_with_exact_fractions(self):
        script = str(REPO / 'scripts/w1_qrom_joint_oracle_diagnostic.py')
        for kind in ('alias', 'separated'):
            source = subprocess.run([sys.executable, script, '--example-input', kind],
                                    capture_output=True, check=True)
            result = subprocess.run([sys.executable, script, '--input', '-'], input=source.stdout,
                                    capture_output=True, check=True)
            self.assertEqual(json.loads(result.stdout), model.make_report(model.example_input(kind)))

    def test_cli_malformed_deep_duplicate_and_oversized_inputs_fail_structurally(self):
        script = str(REPO / 'scripts/w1_qrom_joint_oracle_diagnostic.py')
        for raw in (b'{"x": Infinity}', b'{"schema":1,"schema":2}',
                    b'[' * 16000 + b'0' + b']' * 16000,
                    b' ' * (model.MAX_INPUT_BYTES + 1)):
            with self.subTest(length=len(raw)):
                result = subprocess.run([sys.executable, script, '--input', '-'], input=raw,
                                        capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b'')
                report = json.loads(result.stderr)
                self.assertEqual(report['status'], 'invalid_input')
                self.assert_unqualified(report)


if __name__ == '__main__':
    unittest.main()
