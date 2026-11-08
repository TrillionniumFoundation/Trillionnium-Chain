"""Independent component assembly and adversarial controls for the BCS adapter."""
import copy
from fractions import Fraction
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import w1_qrom_bcs_budget as budget


def fraction(value):
    return Fraction(int(value['numerator']), int(value['denominator']))


def independent_components(p, fs, vc, multi):
    """Assemble named envelopes at a real-mass assignment, before optimization."""
    t, k, v = p['t'], p['k'], p['q_v']
    d = p['q_r_input'] + p['q_r_output']
    u, total = 2 * t + 1, t + 1 + v + k + d
    den = 1 << p['sigma']
    rrbr = Fraction(int(p['kappa_rrbr']['numerator']), int(p['kappa_rrbr']['denominator']))
    sr = 80 * (t + k + 1) * (fs + k) * rrbr + Fraction((t + k + 1) * k, 1 << p['r_min'])
    extract = Fraction(8 * p['n_y'] * p['ell_max'], den)
    qset = p['q_y'] + p['q_pi'] + p['ell_max'] * p['n_y_prime']
    offline = (160 * vc * u**2 + 16 * qset * (p['ell_max'].bit_length() - 1)) / den
    online = 240 * (vc + v + d) * total**2 / den
    commutator = Fraction(2 * v**2 * 240 * (t + 1 + k + v + 1), den)
    return 4 * sr + 4 * extract + 8 * offline + 4 * online + commutator


class BCSBudgetTests(unittest.TestCase):
    def test_example_matches_separate_exact_hand_calculation(self):
        report = budget.make_report(budget.example_input())
        expected = Fraction(17920, 1 << 80) + Fraction(64, 1 << 64) + Fraction(2028160, 1 << 96)
        self.assertEqual(fraction(report['arithmetic_maximized_upper_expression']), expected)
        self.assertEqual(report['an_attaining_mass_assignment'], {'w_fs': '5', 'w_vc': '0', 'w_m': '0'})
        self.assertEqual(report['query_points']['online_t'], '16')

    def test_continuous_simplex_max_covers_fractional_masses_and_is_attained(self):
        for rrbr in [Fraction(1, 1 << 80), Fraction(0)]:
            raw = budget.example_input()
            raw['parameters']['kappa_rrbr'] = {'numerator': str(rrbr.numerator), 'denominator': str(rrbr.denominator)}
            result = budget.make_report(raw)
            maximum = fraction(result['arithmetic_maximized_upper_expression'])
            p = raw['parameters']
            for fs_numerator in range(21):
                for vc_numerator in range(21 - fs_numerator):
                    fs, vc = Fraction(fs_numerator, 4), Fraction(vc_numerator, 4)
                    multi = Fraction(5) - fs - vc
                    self.assertLessEqual(independent_components(p, fs, vc, multi), maximum)
            vertex = {key: Fraction(value) for key, value in result['an_attaining_mass_assignment'].items()}
            self.assertEqual(independent_components(p, vertex['w_fs'], vertex['w_vc'], vertex['w_m']), maximum)

    def test_all_purposes_cannot_independently_receive_full_budget(self):
        raw = budget.example_input()
        correct = fraction(budget.make_report(raw)['arithmetic_maximized_upper_expression'])
        invalid_assignment = independent_components(raw['parameters'], Fraction(5), Fraction(5), Fraction(0))
        self.assertGreater(invalid_assignment, correct)

    def test_verifier_checks_are_charged_to_ordinary_vc_mass(self):
        raw = budget.example_input()
        report = budget.make_report(raw)
        self.assertEqual(fraction(report['additional_fixed_vc_check_mass_addend']), Fraction(737280, 1 << 96))
        raw['parameters']['q_v'] = 0
        with self.assertRaisesRegex(ValueError, 'at least k Fiat-Shamir'):
            budget.make_report(raw)

    def test_enlarged_query_domain_rejects_original_t_only(self):
        for key, limit in [('vc_max_queries', 15), ('commutativity_max_queries', 10), ('pqsr_max_queries', 4)]:
            raw = budget.example_input()
            raw['declared_query_domains'][key] = limit
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'enlarged query point'):
                budget.make_report(raw)

    def test_missing_domain_blocks_conditional_expression_only(self):
        raw = budget.example_input()
        raw['declared_query_domains']['vc_max_queries'] = None
        report = budget.make_report(raw)
        self.assertIsNotNone(report['arithmetic_maximized_upper_expression'])
        self.assertIsNone(report['conditional_expression_on_declared_query_domains'])
        self.assertIsNone(report['hypothetical_expression_meets_target'])

    def test_unknown_factor_survives_zero_mass_and_zero_rrbr(self):
        raw = budget.example_input()
        raw['parameters'].update(t=0, q_v=2, sigma=None, kappa_rrbr=0)
        report = budget.make_report(raw)
        self.assertIsNone(report['arithmetic_maximized_upper_expression'])
        self.assertIsNone(report['additional_fixed_vc_check_mass_addend'])
        self.assertGreater(fraction(report['constant_terms']['finite_randomness']), 0)

    def test_unknown_inputs_never_supply_digest_width_or_security_bits(self):
        report = budget.make_report({'schema': budget.INPUT_SCHEMA, 'input_kind': 'hypothetical'})
        self.assertIsNone(report['arithmetic_maximized_upper_expression'])
        self.assertIsNone(report['inputs']['parameters']['sigma'])
        self.assertIsNone(report['qualification']['unconditional_project_security_bits'])
        self.assertIsNone(report['qualification']['whole_lifetime_failure_bound'])

    def test_unhelpful_expression_is_not_clamped_and_passing_example_does_not_qualify(self):
        raw = budget.example_input()
        raw['parameters'].update(sigma=1, r_min=1, kappa_rrbr=1)
        report = budget.make_report(raw)
        self.assertIs(report['expression_exceeds_one'], True)
        self.assertGreater(fraction(report['arithmetic_maximized_upper_expression']), 1)
        for source in [raw, budget.example_input()]:
            flags = budget.make_report(source)['qualification']
            for field in ('qrom_theorem_instantiated', 'complete_w1_soundness_qualified',
                          'post_quantum_soundness_qualified', 'quantum_work_qualified', 'production_qualified'):
                self.assertIs(flags[field], False)

    def test_invalid_numeric_scope_and_qualification_overrides_are_refused(self):
        for key, bad in [('t', True), ('q_v', 1.5), ('k', 0), ('ell_max', 3),
                         ('sigma', 4097), ('kappa_rrbr', Fraction(1, 2)), ('q_y', 17), ('q_pi', 33)]:
            raw = budget.example_input()
            raw['parameters'][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                budget.make_report(raw)
        raw = budget.example_input()
        raw['qualification'] = {'qrom_theorem_instantiated': True}
        with self.assertRaises(ValueError):
            budget.make_report(raw)

    def test_cli_duplicate_nonfinite_and_oversize_input_are_refused(self):
        for data in [b'{"schema":1,"schema":2}', b'{"schema":NaN}', b' ' * 131073]:
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/w1_qrom_bcs_budget.py'), '--input', '-'],
                                    input=data, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stderr)['status'], 'invalid_input')


if __name__ == '__main__':
    unittest.main()
