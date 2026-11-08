#!/usr/bin/env python3
"""Negative controls for the conditional January 10.6 expression evaluator."""
from __future__ import annotations

import copy
from fractions import Fraction
import json
from pathlib import Path
import subprocess
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'scripts'))
import w1_qrom_composition_budget as budget


def fraction(value):
    return Fraction(int(value['numerator']), int(value['denominator']))


def encoded(value):
    value = Fraction(value)
    return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}


class CompositionBudgetTests(unittest.TestCase):
    def example(self):
        return copy.deepcopy(budget.example_input())

    def assert_unqualified(self, result):
        for key, value in result['qualification'].items():
            self.assertIsNone(value) if key.endswith('_bits') else self.assertIs(value, False)
        self.assertIsNone(result['theorem_11_3_instantiated_bound'])

    def test_unknown_inputs_never_become_zero_or_security_bits(self):
        result = budget.make_report({'schema': budget.INPUT_SCHEMA, 'input_kind': 'hypothetical'})
        for field in ('arithmetic_extraction_upper_expression', 'conditional_extraction_upper_expression',
                      'simulation_upper_expression', 'commutativity_upper_expression',
                      'expression_meets_hypothetical_target', 'expression_exceeds_one'):
            self.assertIsNone(result[field])
        self.assertTrue(all(item['expression'] is None for item in result['component_evaluations']))
        self.assert_unqualified(result)

    def test_enlarged_query_points_and_commutator_are_not_simple_error_sum(self):
        result = budget.make_report(self.example())
        self.assertEqual(result['query_points'], {'left_extractability': '14', 'right_extractability': '7',
                         'shared_commutativity': '23', 'simulation': '7', 'commutativity': '11'})
        self.assertEqual(result['terms']['commutator_coefficient'], '1696')
        expected = Fraction(408, 2**64) + Fraction(40704, 2**96)
        self.assertEqual(fraction(result['conditional_extraction_upper_expression']), expected)
        self.assertNotEqual(expected, Fraction(5**2 + 5 + 1, 2**64))
        self.assertEqual(fraction(result['simulation_upper_expression']), 0)
        self.assertEqual(fraction(result['commutativity_upper_expression']), Fraction(12, 2**96))
        self.assertEqual(result['composed_verifier_query_bound'], '5')
        self.assertEqual(result['composed_extractor_query_bound'], '13')
        self.assertIs(result['expression_meets_hypothetical_target'], True)
        self.assert_unqualified(result)

    def test_unknown_commutativity_does_not_disappear_under_zero_coefficient(self):
        data = self.example()
        data['queries']['q_e2'] = 0
        data['left']['errors']['commutativity'] = None
        result = budget.make_report(data)
        self.assertEqual(result['terms']['commutator_coefficient'], '0')
        self.assertIsNone(result['terms']['commutator_addend'])
        self.assertIsNone(result['conditional_extraction_upper_expression'])

    def test_component_must_cover_shifted_queries_not_only_original_t(self):
        data = self.example()
        data['left']['errors']['extractability']['max_queries'] = data['queries']['t']
        with self.assertRaisesRegex(budget.CompositionError, 'shifted query bound'):
            budget.make_report(data)
        data = self.example()
        data['left']['errors']['commutativity']['max_queries'] = data['queries']['q_com']
        with self.assertRaisesRegex(budget.CompositionError, 'shifted query bound'):
            budget.make_report(data)
        data = self.example()
        data['left']['errors']['extractability']['max_queries'] = 14
        self.assertIsNotNone(budget.make_report(data)['conditional_extraction_upper_expression'])

    def test_zero_envelope_without_domain_or_parameter_scope_stays_unknown(self):
        for field in ('max_queries', 'security_parameter', 'instance_size_bound'):
            with self.subTest(field=field):
                data = self.example()
                data['left']['errors']['extractability']['coefficients'] = [0]
                data['left']['errors']['extractability'][field] = None
                self.assertIsNone(budget.make_report(data)['conditional_extraction_upper_expression'])
        data = self.example()
        data['left']['errors']['extractability']['coefficients'] = [None, 0]
        self.assertIsNone(budget.make_report(data)['conditional_extraction_upper_expression'])

    def test_known_parameter_or_instance_slice_mismatch_is_refused(self):
        for field in ('security_parameter', 'instance_size_bound'):
            with self.subTest(field=field):
                data = self.example()
                data['right']['errors']['simulation'][field] += 1
                with self.assertRaisesRegex(budget.CompositionError, 'mismatched ' + field):
                    budget.make_report(data)

    def test_strict_relaxed_and_all_oracle_components_must_match(self):
        for field in budget.RELATION_FIELDS:
            with self.subTest(relation=field):
                data = self.example()
                data['right']['input_relation'][field] = 'f' * 64
                with self.assertRaisesRegex(budget.CompositionError, 'middle relation'):
                    budget.make_report(data)
        for field in budget.ORACLE_FIELDS:
            with self.subTest(oracle=field):
                data = self.example()
                data['right']['emulated_oracle'][field] = 'f' * 64
                with self.assertRaisesRegex(budget.CompositionError, 'emulated oracle'):
                    budget.make_report(data)

    def test_missing_description_blocks_conditional_claim_not_raw_arithmetic(self):
        for location in ('input_relation', 'emulated_oracle'):
            with self.subTest(location=location):
                data = self.example()
                data['left'][location] = None
                result = budget.make_report(data)
                self.assertIsNotNone(result['arithmetic_extraction_upper_expression'])
                self.assertIsNone(result['conditional_extraction_upper_expression'])
                self.assertIsNone(result['expression_meets_hypothetical_target'])
                self.assertIs(result['description_checks']['checks_prove_the_hypotheses'], False)
                self.assert_unqualified(result)

    def test_intermediate_size_requires_common_slice_coverage(self):
        data = self.example()
        data['intermediate_instance_size_bound'] = 1025
        with self.assertRaisesRegex(budget.CompositionError, 'common n'):
            budget.make_report(data)
        data['intermediate_instance_size_bound'] = None
        result = budget.make_report(data)
        self.assertIsNotNone(result['arithmetic_extraction_upper_expression'])
        self.assertIsNone(result['conditional_extraction_upper_expression'])

    def test_only_dependencies_of_missing_query_cost_are_suppressed(self):
        data = self.example()
        data['queries']['q_e1'] = None
        result = budget.make_report(data)
        self.assertIsNotNone(result['conditional_extraction_upper_expression'])
        self.assertIsNone(result['composed_extractor_query_bound'])
        data['queries']['q_v2'] = None
        result = budget.make_report(data)
        self.assertIsNone(result['conditional_extraction_upper_expression'])
        right = next(item for item in result['component_evaluations']
                     if item['stage'] == 'right' and item['component'] == 'extractability')
        self.assertIsNotNone(right['expression'])

    def test_exact_target_boundary_and_large_expression_are_not_clamped(self):
        data = self.example()
        value = fraction(budget.make_report(data)['conditional_extraction_upper_expression'])
        data['target_error'] = encoded(value)
        self.assertIs(budget.make_report(data)['expression_meets_hypothetical_target'], True)
        data['target_error'] = encoded(value - Fraction(1, value.denominator * 2))
        self.assertIs(budget.make_report(data)['expression_meets_hypothetical_target'], False)
        data['left']['errors']['extractability']['coefficients'] = [1]
        result = budget.make_report(data)
        self.assertGreater(fraction(result['conditional_extraction_upper_expression']), 2)
        self.assertIs(result['expression_exceeds_one'], True)
        self.assert_unqualified(result)

    def test_numeric_coercion_negative_coefficients_and_unknown_models_are_refused(self):
        for value in (True, False, 1.0, -1, '01', '+1', '1e2'):
            with self.subTest(value=value):
                data = self.example()
                data['queries']['t'] = value
                with self.assertRaises(budget.CompositionError):
                    budget.make_report(data)
        for value in (-1, True, 0.5, {'numerator': 1, 'denominator': 0}):
            with self.subTest(coefficient=value):
                data = self.example()
                data['left']['errors']['extractability']['coefficients'] = [value]
                with self.assertRaises(budget.CompositionError):
                    budget.make_report(data)
        data = self.example()
        data['left']['errors']['extractability']['kind'] = 'proved'
        with self.assertRaises(budget.CompositionError):
            budget.make_report(data)

    def test_input_cannot_override_version_security_or_qualification(self):
        for key, value in (('qualification', True), ('quantum_security_bits', 128),
                           ('latest_revision_equivalence_verified', True)):
            data = self.example()
            data[key] = value
            with self.assertRaises(budget.CompositionError):
                budget.make_report(data)
        data = self.example()
        data['schema'] = 'TRNM-W1-CDHZ-MARCH-COMPOSITION-INPUT1'
        with self.assertRaises(budget.CompositionError):
            budget.make_report(data)

    def test_zero_assumed_errors_never_qualify_three_independent_security_lines(self):
        data = self.example()
        for side in ('left', 'right'):
            for model in data[side]['errors'].values():
                model['coefficients'] = [0]
        result = budget.make_report(data)
        self.assertEqual(fraction(result['conditional_extraction_upper_expression']), 0)
        self.assertIs(result['expression_meets_hypothetical_target'], True)
        self.assert_unqualified(result)

    def test_cli_example_roundtrip_retains_exact_inputs(self):
        script = str(REPO / 'scripts/w1_qrom_composition_budget.py')
        source = subprocess.run([sys.executable, script, '--example-input'], capture_output=True, check=True)
        actual = subprocess.run([sys.executable, script, '--input', '-'], input=source.stdout,
                                capture_output=True, check=True)
        expected = budget.make_report(budget.example_input())
        self.assertEqual(json.loads(actual.stdout), expected)
        self.assert_unqualified(json.loads(actual.stdout))

    def test_cli_duplicate_nonfinite_deep_and_oversized_input_fail_structurally(self):
        script = str(REPO / 'scripts/w1_qrom_composition_budget.py')
        examples = [b'{"schema": 1, "schema": 2}', b'{"x": NaN}',
                    b'[' * 16000 + b'0' + b']' * 16000,
                    b' ' * (budget.MAX_INPUT_BYTES + 1)]
        for raw in examples:
            with self.subTest(length=len(raw)):
                result = subprocess.run([sys.executable, script, '--input', '-'], input=raw,
                                        capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b'')
                rejection = json.loads(result.stderr)
                self.assertEqual(rejection['status'], 'invalid_input')
                self.assertTrue(all(value is False or value is None
                                    for value in rejection['qualification'].values()))


if __name__ == '__main__':
    unittest.main()
