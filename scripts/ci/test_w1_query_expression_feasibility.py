#!/usr/bin/env python3
"""Exact boundaries, bounded refusal and non-qualification of query arithmetic."""

from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/w1_query_expression_feasibility.py'
SPEC = importlib.util.spec_from_file_location('w1_query_expression_feasibility', SCRIPT)
QUERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUERY)


class QueryExpressionTests(unittest.TestCase):
    def test_fixed_p3_expression_and_six_exact_minima(self):
        alpha = Fraction(2001, 4000)
        self.assertEqual(QUERY.query_term(64, alpha=alpha), Fraction(2001**64, 4000**64))
        for exponent, expected in [(0, 129), (16, 145), (32, 161),
                                   (64, 193), (128, 257), (256, 385)]:
            with self.subTest(exponent=exponent):
                factor = Fraction(1 << exponent)
                count = QUERY.minimum_queries(128, factor, alpha=alpha)
                self.assertEqual(count, expected)
                self.assertLessEqual(factor * alpha**count, Fraction(1, 1 << 128))
                self.assertGreater(factor * alpha**(count - 1), Fraction(1, 1 << 128))

    def test_equality_is_allowed_but_strict_johnson_boundary_is_different(self):
        self.assertEqual(QUERY.minimum_queries(128, Fraction(1), alpha=Fraction(1, 2)), 128)
        self.assertEqual(QUERY.minimum_queries(
            128, Fraction(1), alpha=Fraction(1000001, 2000000)), 129)
        self.assertEqual(QUERY.johnson_strict_necessary_queries(128, 0), 129)
        self.assertEqual(QUERY.johnson_strict_necessary_queries(128, 64), 193)

    def test_non_power_of_two_factor_and_zero_target(self):
        alpha, factor = Fraction(2, 3), Fraction(3, 2)
        count = QUERY.minimum_queries(8, factor, alpha=alpha)
        self.assertLessEqual(factor * alpha**count, Fraction(1, 256))
        self.assertGreater(factor * alpha**(count - 1), Fraction(1, 256))
        self.assertEqual(QUERY.minimum_queries(0, Fraction(1), alpha=alpha), 0)
        self.assertEqual(QUERY.minimum_queries(0, Fraction(2), alpha=Fraction(1, 2)), 1)
        self.assertEqual(QUERY.johnson_strict_necessary_queries(0, 0), 0)

    def test_no_default_alpha_can_leak_between_profiles(self):
        with self.assertRaises(TypeError):
            QUERY.query_term(64)
        with self.assertRaises(TypeError):
            QUERY.minimum_queries(128, Fraction(1))
        with self.assertRaises(QUERY.QueryExpressionRefusal):
            QUERY.make_report(assumed_multiplier=Fraction(1))
        with self.assertRaises(QUERY.QueryExpressionRefusal):
            QUERY.make_report(assumed_alpha=Fraction(1, 2))

    def test_float_bool_and_invalid_domains_are_refused(self):
        for alpha in [True, False, 0.5, 1, Fraction(0), Fraction(1), Fraction(3, 2)]:
            with self.subTest(alpha=alpha), self.assertRaises(QUERY.QueryExpressionRefusal):
                QUERY.minimum_queries(128, Fraction(1), alpha=alpha)
        for factor in [True, 1.0, 1, Fraction(0), Fraction(1, 2)]:
            with self.subTest(factor=factor), self.assertRaises(QUERY.QueryExpressionRefusal):
                QUERY.minimum_queries(128, factor, alpha=Fraction(1, 2))
        for value in [True, False, 128.0, -1]:
            with self.subTest(value=value):
                with self.assertRaises(QUERY.QueryExpressionRefusal):
                    QUERY.minimum_queries(value, Fraction(1), alpha=Fraction(1, 2))
                with self.assertRaises(QUERY.QueryExpressionRefusal):
                    QUERY.query_term(value, alpha=Fraction(1, 2))
                with self.assertRaises(QUERY.QueryExpressionRefusal):
                    QUERY.johnson_strict_necessary_queries(128, value)

    def test_extremely_close_to_one_is_refused_before_integer_powers(self):
        denominator = 1 << (QUERY.MAX_INPUT_INTEGER_BITS - 1)
        alpha = Fraction(denominator - 1, denominator)
        with patch('builtins.pow', side_effect=AssertionError('unexpected power')):
            with self.assertRaises(QUERY.QueryExpressionRefusal) as raised:
                QUERY.minimum_queries(128, Fraction(1), alpha=alpha)
        refusal = raised.exception.as_dict()
        self.assertEqual(refusal['code'], 'RESOURCE_LIMIT')
        self.assertEqual(refusal['field'], 'query_search')
        self.assertIn('Bernoulli', refusal['reason'])
        self.assertLessEqual(refusal['details']['maximum_queries_for_inputs'], QUERY.MAX_QUERIES)

    def test_finite_search_stops_when_bernoulli_shortcut_does_not_apply(self):
        original_pow = pow
        queried_exponents = []

        def observed_pow(base, exponent):
            queried_exponents.append(exponent)
            return original_pow(base, exponent)

        with patch.object(QUERY, 'MAX_QUERIES', 8), patch('builtins.pow', observed_pow):
            with self.assertRaises(QUERY.QueryExpressionRefusal) as raised:
                QUERY.minimum_queries(8, Fraction(1), alpha=Fraction(3, 4))
        self.assertEqual(raised.exception.code, 'RESOURCE_LIMIT')
        self.assertEqual(max(queried_exponents), 8)
        self.assertLessEqual(len(queried_exponents), 8)
        with patch.object(QUERY, 'MAX_QUERIES', 8):
            self.assertEqual(QUERY.minimum_queries(8, Fraction(1), alpha=Fraction(1, 2)), 8)

    def test_size_limits_are_checked_before_exponentiation(self):
        with patch('builtins.pow', side_effect=AssertionError('unexpected power')):
            cases = [
                lambda: QUERY.minimum_queries(QUERY.MAX_TARGET_BITS + 1, Fraction(1),
                                              alpha=Fraction(1, 2)),
                lambda: QUERY.query_term(QUERY.MAX_QUERIES + 1, alpha=Fraction(1, 2)),
                lambda: QUERY.query_term(1, alpha=Fraction(1, 1 << QUERY.MAX_INPUT_INTEGER_BITS)),
                lambda: QUERY.query_term(QUERY.MAX_QUERIES, alpha=Fraction(1, 1 << 1000)),
                lambda: QUERY.minimum_queries(128, Fraction(1 << QUERY.MAX_INPUT_INTEGER_BITS),
                                              alpha=Fraction(1, 2)),
            ]
            for case in cases:
                with self.subTest(case=case), self.assertRaises(QUERY.QueryExpressionRefusal) as raised:
                    case()
                self.assertEqual(raised.exception.code, 'RESOURCE_LIMIT')

    def test_successful_arithmetic_never_outputs_project_bits_or_qualification(self):
        report = QUERY.make_report(
            assumed_alpha=Fraction(1, 2), assumed_multiplier=Fraction(1))
        self.assertEqual(report['hypothetical_case']['least_queries_for_this_expression'], 128)
        self.assertEqual(len(report['p3_fixed_m_hypothetical_rows']), 6)
        self.assertAlmostEqual(report['fixed_p3_query_expression']
                               ['negative_log2_expression_approx'], 63.95384529640614, places=12)
        self.assertTrue(all(value is False or value is None
                            for value in report['qualification'].values()))
        self.assertIsNone(report['qualification']['unconditional_project_security_bits'])

        def check(record):
            if isinstance(record, dict):
                for key, value in record.items():
                    if key.endswith('_qualified'):
                        self.assertIs(value, False)
                    if key.endswith('security_bits'):
                        self.assertIsNone(value)
                    check(value)
            elif isinstance(record, list):
                for value in record:
                    check(value)
        check(report)

    def test_cli_default_and_explicit_hypothesis(self):
        for arguments in [[], ['--alpha', '1/2', '--assumed-multiplier', '3/2']]:
            result = subprocess.run([sys.executable, str(SCRIPT), *arguments],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, '')
            report = json.loads(result.stdout)
            self.assertEqual(report['status'], 'arithmetic_only')
            self.assertIn('hypothetical', report['multiplier_provenance'])
            self.assertTrue(all(value is False or value is None
                                for value in report['qualification'].values()))

    def test_cli_invalid_and_resource_inputs_return_structured_refusal(self):
        close_denominator = 1 << 1023
        close_alpha = f'{close_denominator - 1}/{close_denominator}'
        cases = [
            (['--assumed-multiplier', '1'], 'INVALID_INPUT'),
            (['--alpha', '0.5', '--assumed-multiplier', '1'], 'INVALID_INPUT'),
            (['--alpha', '1/0', '--assumed-multiplier', '1'], 'INVALID_INPUT'),
            (['--alpha', close_alpha, '--assumed-multiplier', '1'], 'RESOURCE_LIMIT'),
            (['--target-bits', '4097'], 'RESOURCE_LIMIT'),
            (['--alpha', '1/' + '9' * 700, '--assumed-multiplier', '1'], 'RESOURCE_LIMIT'),
            (['--target-bits', '4097', '--target-bits', '128'], 'INVALID_INPUT'),
            (['--alpha', '1/2', '--alpha', '1/3', '--assumed-multiplier', '1'], 'INVALID_INPUT'),
            (['--alpha', '1/2', '--assumed-multiplier', '1',
              '--assumed-multiplier', '2'], 'INVALID_INPUT'),
            (['--project-security-bits', '128'], 'INVALID_INPUT'),
        ]
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, str(SCRIPT), *arguments],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                report = json.loads(result.stderr)
                self.assertEqual(report['schema'], QUERY.OUTPUT_SCHEMA)
                self.assertEqual(report['status'], 'refused')
                self.assertEqual(report['error']['code'], expected)
                self.assertTrue(all(value is False or value is None
                                    for value in report['qualification'].values()))


if __name__ == '__main__':
    unittest.main()
