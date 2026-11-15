#!/usr/bin/env python3
"""Regression tests for exact-source component budgets, never QROM qualification."""
from __future__ import annotations

from fractions import Fraction
import importlib.util
import itertools
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('w1_security_budget', ROOT / 'scripts/w1_security_budget.py')
assert SPEC is not None and SPEC.loader is not None
BUDGET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUDGET)
RV32IM = {'w_accum': 103, 'n_trace_polys': 315, 'biggest_combo': 6}
RECURSION = {'w_accum': 12, 'n_trace_polys': 163, 'biggest_combo': 6}


class FormulaTests(unittest.TestCase):
    def test_query_term_is_exactly_two_to_minus_100(self):
        errors = BUDGET.component_errors(20, 50, RV32IM)
        self.assertEqual(errors['toy_terms']['fri_queries'], Fraction(1, 1 << 100))
        self.assertGreater(errors['toy_sum'], Fraction(1, 1 << 100))

    def test_128_budget_cannot_be_reached_by_query_increase(self):
        for taps in (RV32IM, RECURSION):
            for po2 in (13, 18, 20, 22, 24):
                with self.subTest(taps=taps, po2=po2):
                    self.assertIsNone(BUDGET.min_queries_for_toy_budget(po2, taps, 128))
                    floor = BUDGET.component_errors(po2, 4096, taps)['toy_query_independent_floor']
                    self.assertGreater(floor, Fraction(1, 1 << 128))

    def test_64_queries_alone_exhaust_128_budget(self):
        errors = BUDGET.component_errors(18, 64, RECURSION)
        self.assertEqual(errors['toy_terms']['fri_queries'], Fraction(1, 1 << 128))
        self.assertGreater(errors['toy_sum'], Fraction(1, 1 << 128))

    def test_upstream_comment_97_is_reproduced_at_po2_20(self):
        result = BUDGET.error_record(BUDGET.component_errors(20, 50, RV32IM)['toy_sum'])
        self.assertGreater(result['negative_log2_display_only'], 97.14)
        self.assertLess(result['negative_log2_display_only'], 97.15)

    def test_upstream_comment_95_is_not_reproduced_at_po2_24(self):
        result = BUDGET.error_record(BUDGET.component_errors(24, 50, RV32IM)['toy_sum'])
        self.assertGreater(result['negative_log2_display_only'], 93.34)
        self.assertLess(result['negative_log2_display_only'], 93.35)
        at_22 = BUDGET.error_record(BUDGET.component_errors(22, 50, RV32IM)['toy_sum'])
        self.assertGreater(at_22['negative_log2_display_only'], 95.29)
        self.assertLess(at_22['negative_log2_display_only'], 95.30)

    def test_proven_formula_is_separate_from_toy_formula(self):
        errors = BUDGET.component_errors(18, 50, RV32IM)
        self.assertEqual(errors['proven_terms']['fri_queries'], Fraction(33, 64) ** 50)
        bits = BUDGET.error_record(errors['proven_sum_upper'])['negative_log2_display_only']
        self.assertGreater(bits, 45.30)
        self.assertLess(bits, 45.31)
        self.assertGreater(errors['proven_sum_upper'], errors['toy_sum'])

    def test_query_search_returns_minimum_and_exact_boundary(self):
        for target in (40, 90, 96, 97):
            q = BUDGET.min_queries_for_toy_budget(20, RV32IM, target)
            self.assertIsInstance(q, int)
            value = BUDGET.component_errors(20, q, RV32IM)
            self.assertLessEqual(value['toy_sum'], Fraction(1, 1 << target))
            self.assertGreater(BUDGET.component_errors(20, q - 1, RV32IM)['toy_sum'],
                               Fraction(1, 1 << target))

    def test_sqrt_enclosure_and_perfect_square(self):
        for value in (Fraction(1, 4), Fraction(1, 3), Fraction(262150, 1048576)):
            low, high = BUDGET.sqrt_interval(value)
            self.assertLessEqual(low * low, value)
            self.assertGreaterEqual(high * high, value)
            self.assertLessEqual(high - low, Fraction(1, 1 << 128))
        self.assertEqual(BUDGET.sqrt_interval(Fraction(1, 4)), (Fraction(1, 2), Fraction(1, 2)))

    def test_integer_ceiling_is_minimal(self):
        rho, combo, alpha = Fraction(262150, 1048576), 6, Fraction(33, 64)
        m = BUDGET.exact_ceil_m(rho, combo, alpha)
        self.assertEqual(m, 6)
        self.assertGreaterEqual((m * combo * alpha) ** 2, (m * combo + 1) ** 2 * rho)
        self.assertLess(((m - 1) * combo * alpha) ** 2, ((m - 1) * combo + 1) ** 2 * rho)

    def test_unsupported_domains_and_boolean_integers_are_rejected(self):
        for po2, queries in ((12, 50), (25, 50), (18, 0), (18, 4097), (True, 50), (18, True)):
            with self.subTest(po2=po2, queries=queries), self.assertRaises(BUDGET.BudgetError):
                BUDGET.component_errors(po2, queries, RV32IM)
        with self.assertRaises(BUDGET.BudgetError):
            BUDGET.exact_ceil_m(Fraction(1, 3), 6, Fraction(1, 2))

    def test_negative_log_is_not_absolute_value(self):
        # An error expression above one must not become a positive security claim.
        self.assertEqual(BUDGET.error_record(Fraction(2))['negative_log2_display_only'], -1.0)

    def test_display_log_handles_tiny_exact_terms(self):
        self.assertEqual(BUDGET.error_record(Fraction(1, 1 << 8192))['negative_log2_display_only'], 8192.0)

    def test_passing_small_component_budget_never_qualifies_full_proof(self):
        rv = {'w_accum': 103, 'w_code': 1, 'w_data': 211,
              'n_trace_polys': 315, 'biggest_combo': 6, 'tap_count': 790}
        rec = {'w_accum': 12, 'w_code': 23, 'w_data': 128,
               'n_trace_polys': 163, 'biggest_combo': 6, 'tap_count': 643}
        sources = {'risc0-circuit-rv32im-4.0.5/src/zirgen/taps.rs': 'unit fixture',
                   'risc0-circuit-recursion-4.0.5/src/taps.rs': 'unit fixture'}
        with patch.object(BUDGET, 'tap_parameters', side_effect=[rv, rec]):
            report = BUDGET.make_report(sources, [], 'unit-fixture-no-source-validation', 1)
        self.assertTrue(all(row['upstream_toy_model']['meets_research_error_budget']
                            for row in report['rows']))
        self.assertFalse(report['qualification']['qrom_theorem_instantiated'])
        self.assertIsNone(report['qualification']['quantum_security_bits'])
        self.assertIsNone(report['qualification']['full_recursive_security_bits'])
        self.assertFalse(report['qualification']['production_qualified'])
        self.assertFalse(report['research_target']['protocol_policy_adopted'])

    def test_sampler_bias_matches_exhaustive_small_ideal_domain(self):
        counts = [0] * 4
        for draws in itertools.product(range(17), repeat=4):
            selected = next((word for word in draws if word != 0), 0)
            counts[selected & 3] += 1
        distance = sum(abs(Fraction(count, 17 ** 4) - Fraction(1, 4))
                       for count in counts) / 2
        self.assertEqual(distance, BUDGET.ideal_sampler_bias(17, 2))
        self.assertGreater(BUDGET.ideal_sampler_bias(2013265921, 26), Fraction(1, 1 << 128))

    def test_sampler_formula_rejects_unsupported_width(self):
        for domain, bits in ((2013265921, 28), (17, 5), (True, 2)):
            with self.subTest(domain=domain, bits=bits), self.assertRaises(BUDGET.BudgetError):
                BUDGET.ideal_sampler_bias(domain, bits)


class SourceBoundaryTests(unittest.TestCase):
    def lock_text(self):
        lines = ['version = 4']
        for key, pin in BUDGET.PACKAGES.items():
            name, version = key.rsplit('-', 1)
            lines.extend(['[[package]]', f'name = "{name}"', f'version = "{version}"',
                          f'source = "{BUDGET.REGISTRY}"', f'checksum = "{pin["archive"]}"'])
        return '\n'.join(lines)

    def test_corrupt_archive_rejected_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / 'Cargo.lock'
            lock.write_text(self.lock_text())
            (root / 'risc0-zkp-3.0.5.crate').write_bytes(b'not the pinned archive')
            with self.assertRaisesRegex(BUDGET.BudgetError, 'archive checksum mismatch'):
                BUDGET.load_sources(lock, root)

    def test_lock_drift_and_duplicate_package_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / 'Cargo.lock'
            text = self.lock_text()
            lock.write_text(text.replace(BUDGET.REGISTRY, 'git+https://example.invalid/source'))
            with self.assertRaisesRegex(BUDGET.BudgetError, 'unexpected registry'):
                BUDGET.load_sources(lock, root)
            lock.write_text(text + '\n' + text[text.index('[[package]]'):])
            with self.assertRaisesRegex(BUDGET.BudgetError, 'duplicate lock package'):
                BUDGET.load_sources(lock, root)

    def test_symlink_input_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / 'actual'
            actual.write_text(self.lock_text())
            (root / 'Cargo.lock').symlink_to(actual)
            with self.assertRaisesRegex(BUDGET.BudgetError, 'symlink input'):
                BUDGET.load_sources(root / 'Cargo.lock', root)

    def test_malformed_lock_roster_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / 'Cargo.lock'
            lock.write_text('package = [1, 2]')
            with self.assertRaisesRegex(BUDGET.BudgetError, 'invalid lock package entry'):
                BUDGET.load_sources(lock, root)

    def test_source_pins_agree_with_existing_locked_source_map(self):
        old = json.loads((ROOT / 'evidence/pon-w1-transparent-profile-20261104/security-map.json').read_text())
        compared = 0
        for package in old['packages']:
            name = package['name'] + '-' + package['version']
            if name not in BUDGET.PACKAGES:
                continue
            pin = BUDGET.PACKAGES[name]
            self.assertEqual(package['locked_archive_sha256'], pin['archive'])
            for file in package['selected_source_files']:
                if file['path'] in pin['files']:
                    self.assertEqual(file['sha256'], pin['files'][file['path']])
                    compared += 1
        self.assertEqual(compared, 8)

    def test_tap_parser_uses_register_offsets_not_number_of_taps(self):
        text = '''
        TapData { offset: 0, back: 0, group: 0, combo: 0, skip: 2, }
        TapData { offset: 0, back: 1, group: 0, combo: 0, skip: 2, }
        TapData { offset: 0, back: 0, group: 1, combo: 1, skip: 1, }
        TapData { offset: 0, back: 0, group: 2, combo: 1, skip: 1, }
        combo_begin: &[0, 2, 3], group_begin: &[0, 2, 3, 4],
        '''
        result = BUDGET.tap_parameters(text)
        self.assertEqual(result, {'w_accum': 1, 'w_code': 1, 'w_data': 1,
                                 'n_trace_polys': 3, 'biggest_combo': 2, 'tap_count': 4})
        with self.assertRaises(BUDGET.BudgetError):
            BUDGET.tap_parameters(text.replace('offset: 0, back: 0, group: 1',
                                              'offset: 2, back: 0, group: 1'))
        with self.assertRaises(BUDGET.BudgetError):
            BUDGET.tap_parameters(text.replace('group_begin: &[0, 2, 3, 4]',
                                              'group_begin: &[0, 1, 3, 4]'))


if __name__ == '__main__':
    unittest.main()
