#!/usr/bin/env python3
"""Boundary tests for hypothetical arithmetic, not cryptographic qualification."""

from copy import deepcopy
from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/w1_qrom_conditional_budget.py'
SPEC = importlib.util.spec_from_file_location('w1_qrom_conditional_budget', SCRIPT)
BUDGET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUDGET)


def fraction(record):
    return Fraction(int(record['numerator']), int(record['denominator']))


def ratio(numerator, denominator=1):
    return {'numerator': numerator, 'denominator': denominator}


class ConditionalBudgetTests(unittest.TestCase):
    def test_no_inputs_remain_unknown_without_classical_or_width_defaults(self):
        report = BUDGET.make_report({'schema': BUDGET.INPUT_SCHEMA, 'input_kind': 'hypothetical'})
        self.assertIsNone(report['pqsr_component']['conditional_upper_expression'])
        self.assertIsNone(report['pqsr_component']['target_analysis']['kappa_rrbr_required_at_most'])
        self.assertIsNone(report['inputs']['merkle']['sigma'])
        self.assertTrue(all(value is None for value in
                            report['merkle_components']['conditional_expressions'].values()))
        self.assertFalse(report['qualification']['qrom_theorem_instantiated'])

    def test_unknown_factor_is_not_zero_or_silently_replaced_by_t(self):
        raw = BUDGET.example_input()
        raw['pqsr']['w'] = None
        raw['pqsr']['kappa_rrbr'] = 0
        raw['merkle']['sigma'] = None
        report = BUDGET.make_report(raw)
        self.assertIsNone(report['pqsr_component']['rrbr_coefficient'])
        self.assertIsNone(report['pqsr_component']['conditional_upper_expression'])
        self.assertIsNone(report['pqsr_component']['conditional_expression_meets_target'])
        self.assertTrue(all(value is None for value in
                            report['merkle_components']['conditional_expressions'].values()))

    def test_exact_threshold_and_one_rational_step_above_it(self):
        raw = {'schema': BUDGET.INPUT_SCHEMA, 'input_kind': 'hypothetical',
               'pqsr': {'t': 1, 'k': 1, 'w': 1, 'r_min': 10,
                        'target_error': ratio(1, 64), 'kappa_rrbr': None}}
        component = BUDGET.make_report(raw)['pqsr_component']
        threshold = component['target_analysis']['kappa_rrbr_required_at_most']
        self.assertEqual(fraction(threshold), Fraction(13, 491520))
        self.assertEqual(fraction(component['finite_randomness_addend']), Fraction(3, 1024))
        self.assertIsNone(component['conditional_expression_meets_target'])
        raw['pqsr']['kappa_rrbr'] = threshold
        boundary = BUDGET.make_report(raw)['pqsr_component']
        self.assertEqual(fraction(boundary['conditional_upper_expression']), Fraction(1, 64))
        self.assertTrue(boundary['conditional_expression_meets_target'])
        raw['pqsr']['kappa_rrbr'] = ratio(14, 491520)
        self.assertFalse(BUDGET.make_report(raw)['pqsr_component']['conditional_expression_meets_target'])

    def test_expression_floor_distinguishes_impossible_and_zero_allowance(self):
        raw = {'schema': BUDGET.INPUT_SCHEMA, 'input_kind': 'hypothetical',
               'pqsr': {'t': 0, 'k': 1, 'w': 0, 'r_min': 2,
                        'kappa_rrbr': 0, 'target_error': ratio(1, 4)}}
        impossible = BUDGET.make_report(raw)['pqsr_component']
        self.assertFalse(impossible['conditional_expression_meets_target'])
        self.assertTrue(impossible['target_analysis']['finite_randomness_addend_exceeds_target'])
        self.assertIsNone(impossible['target_analysis']['kappa_rrbr_required_at_most'])
        raw['pqsr']['target_error'] = ratio(1, 2)
        equality = BUDGET.make_report(raw)['pqsr_component']
        self.assertEqual(fraction(equality['target_analysis']['kappa_rrbr_required_at_most']), 0)
        self.assertTrue(equality['conditional_expression_meets_target'])

    def test_fractional_mass_and_expression_above_one_are_not_rounded_or_clamped(self):
        raw = {'schema': BUDGET.INPUT_SCHEMA, 'input_kind': 'hypothetical',
               'pqsr': {'t': 3, 'k': 2, 'w': ratio(3, 2), 'r_min': 8,
                        'kappa_rrbr': ratio(1, 1000), 'target_error': ratio(1, 8)}}
        component = BUDGET.make_report(raw)['pqsr_component']
        self.assertEqual(fraction(component['rrbr_coefficient']), 1680)
        self.assertEqual(fraction(component['conditional_upper_expression']), Fraction(2763, 1600))
        self.assertFalse(component['conditional_expression_meets_target'])

    def test_merkle_components_are_distinct_and_exact(self):
        raw = {'schema': BUDGET.INPUT_SCHEMA, 'input_kind': 'hypothetical',
               'merkle': {'t': 2, 'k': 3, 'w_vc': ratio(1, 2), 'sigma': 10,
                          'ell_max': 8, 'n': 2, 'q_s': 5, 'target_error': ratio(1, 2)}}
        report = BUDGET.make_report(raw)
        terms = report['merkle_components']['conditional_expressions']
        self.assertEqual({key: fraction(value) for key, value in terms.items()},
                         {'commutativity': Fraction(45, 64),
                          'extraction_correctness': Fraction(1, 8),
                          'offline_extractability': Fraction(35, 64),
                          'online_indistinguishability': Fraction(15, 32)})
        self.assertIsNone(report['theorem_11_3_full_bound'])
        self.assertIsNone(report['theorem_10_6_composed_bound'])

    def test_passing_every_component_never_qualifies_a_project(self):
        report = BUDGET.make_report(BUDGET.example_input())
        self.assertTrue(report['pqsr_component']['conditional_expression_meets_target'])
        self.assertTrue(all(report['merkle_components']['each_expression_meets_component_target'].values()))
        self.assertTrue(all(value is False or value is None for value in report['qualification'].values()))
        self.assertIsNone(report['qualification']['unconditional_project_security_bits'])
        self.assertFalse(report['source']['latest_revision_full_text_equivalence_verified'])
        self.assertEqual(report['source']['indexed_manuscript_date'], '2026-01-01')
        self.assertIsNone(report['theorem_11_3_full_bound'])
        self.assertIsNone(report['theorem_10_6_composed_bound'])

    def test_256_is_only_an_explicit_hypothetical_width_and_can_fail_budget(self):
        raw = BUDGET.example_input()
        raw['merkle']['sigma'] = 256
        report = BUDGET.make_report(raw)
        terms = report['merkle_components']['conditional_expressions']
        self.assertGreater(fraction(terms['online_indistinguishability']), Fraction(1, 1 << 128))
        self.assertFalse(report['merkle_components']['each_expression_meets_component_target']
                         ['online_indistinguishability'])
        self.assertFalse(report['qualification']['complete_w1_attack_established'])

    def test_bool_float_and_malformed_fractions_are_rejected(self):
        for section, keys in (('pqsr', BUDGET.PQSR_FIELDS), ('merkle', BUDGET.MERKLE_FIELDS)):
            for key in keys:
                for value in (True, False, 1.0, '1e3'):
                    raw = BUDGET.example_input()
                    raw[section][key] = value
                    with self.subTest(section=section, key=key, value=value):
                        with self.assertRaises(BUDGET.BudgetError):
                            BUDGET.make_report(raw)
        for value in (ratio(True, 2), ratio(1, False), ratio(None, 2), ratio(1, 0),
                      {'numerator': 1}, {'numerator': 1, 'denominator': 2, 'claimed_bits': 1}):
            raw = BUDGET.example_input()
            raw['pqsr']['w'] = value
            with self.subTest(value=value), self.assertRaises(BUDGET.BudgetError):
                BUDGET.make_report(raw)

    def test_domain_and_query_mass_inconsistencies_are_rejected(self):
        cases = [('pqsr', 't', -1), ('pqsr', 'k', 0), ('pqsr', 'w', (1 << 64) + 1),
                 ('pqsr', 'r_min', 0), ('pqsr', 'kappa_rrbr', ratio(3, 2)),
                 ('pqsr', 'target_error', 0), ('merkle', 'w_vc', ratio((1 << 65) + 1, 2)),
                 ('merkle', 'sigma', 0), ('merkle', 'sigma', BUDGET.MAX_EXPONENT + 1),
                 ('merkle', 'ell_max', 3), ('merkle', 'n', 17),
                 ('merkle', 'q_s', (16 << 20) + 1)]
        for section, key, value in cases:
            raw = BUDGET.example_input()
            raw[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(BUDGET.BudgetError):
                BUDGET.make_report(raw)

    def test_input_cannot_override_qualification_or_request_project_certification(self):
        for extra in ({'qualification': {'qrom_theorem_instantiated': True}},
                      {'input_kind': 'project'}, {'schema': 'OTHER'}):
            raw = deepcopy(BUDGET.example_input())
            raw.update(extra)
            with self.subTest(extra=extra), self.assertRaises(BUDGET.BudgetError):
                BUDGET.make_report(raw)

    def test_cli_exact_input_round_trip_and_duplicate_or_nonfinite_rejection(self):
        example = subprocess.run([sys.executable, str(SCRIPT), '--example-input'],
                                 capture_output=True, text=True, check=True)
        result = subprocess.run([sys.executable, str(SCRIPT), '--input', '-'],
                                input=example.stdout, capture_output=True, text=True, check=True)
        report = json.loads(result.stdout)
        self.assertEqual(report['inputs']['pqsr']['t'], str(1 << 64))
        self.assertIsNone(report['qualification']['quantum_security_bits'])
        for bad in ('{"schema": "first", "schema": "second"}',
                    '{"schema": NaN}', '{"schema": Infinity}'):
            result = subprocess.run([sys.executable, str(SCRIPT), '--input', '-'],
                                    input=bad, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, '')
            self.assertIsNone(json.loads(result.stderr)['qualification']['quantum_security_bits'])

    def test_cli_deep_json_below_byte_limit_returns_structured_rejection(self):
        prefix = ('{"schema":"' + BUDGET.INPUT_SCHEMA + '",'
                  '"input_kind":"hypothetical","pqsr":{"t":')
        # Byte limits alone do not bound JSON nesting. This previously raised
        # an uncaught RecursionError instead of emitting invalid_input.
        payload = prefix + '[' * 16000 + '0' + ']' * 16000 + '}}'
        self.assertLess(len(payload.encode('utf-8')), BUDGET.MAX_INPUT_BYTES)
        result = subprocess.run([sys.executable, str(SCRIPT), '--input', '-'],
                                input=payload, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        report = json.loads(result.stderr)
        self.assertEqual(report['schema'], BUDGET.OUTPUT_SCHEMA)
        self.assertEqual(report['status'], 'invalid_input')
        self.assertTrue(all(value is False or value is None
                            for value in report['qualification'].values()))


if __name__ == '__main__':
    unittest.main()
