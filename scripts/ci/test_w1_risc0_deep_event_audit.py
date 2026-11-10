#!/usr/bin/env python3
"""Independent tiny-field enumeration of the named exceptional-set counts."""
from fractions import Fraction
from itertools import product
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import w1_risc0_deep_event_audit as audit

ROOT = Path(os.environ.get('TRNM_TEST_REPOSITORY', Path(__file__).resolve().parents[2]))


def mul(a, b, p, nonresidue):
    # F_p[T]/(T^4-nonresidue), written without the counting formula.
    values = [0] * 7
    for i, left in enumerate(a):
        for j, right in enumerate(b):
            values[i + j] += left * right
    for i in range(6, 3, -1):
        values[i - 4] += nonresidue * values[i]
    return tuple(value % p for value in values[:4])


def power(a, exponent, p, nonresidue):
    result = (1, 0, 0, 0)
    while exponent:
        if exponent & 1:
            result = mul(result, a, p, nonresidue)
        a = mul(a, a, p, nonresidue)
        exponent //= 2
    return result


def enumerate_events(p, nonresidue, trace_log2, shift):
    # Check irreducibility independently by all monic degree-1/2 divisors.
    assert all(pow(value, 4, p) != nonresidue for value in range(p))
    for linear, constant in product(range(p), repeat=2):
        coefficients = [-nonresidue, 0, 0, 0, 1]
        for i in range(4, 1, -1):
            quotient = coefficients[i]
            coefficients[i-1] -= quotient*linear
            coefficients[i-2] -= quotient*constant
        assert any(value % p for value in coefficients[:2])
    n = 1 << trace_log2
    domain = {value for value in range(1, p) if pow(value, 4*n, p) == 1}
    assert len(domain) == 4*n
    poles = zeros = both = 0
    for z in product(range(p), repeat=4):
        # Directly check z^4 in D and the shifted zerofier, independently of
        # the cyclic-group subgroup-order and intersection calculations.
        fourth = mul(mul(z, z, p, nonresidue), mul(z, z, p, nonresidue), p, nonresidue)
        pole = fourth[1:] == (0, 0, 0) and fourth[0] in domain
        shifted = tuple(shift * component % p for component in z)
        zero = power(shifted, n, p, nonresidue) == (1, 0, 0, 0)
        poles += pole
        zeros += zero
        both += pole and zero
    return poles, zeros, both


class DeepEventTests(unittest.TestCase):
    def test_direct_small_extension_enumeration_disjoint_and_overlap(self):
        # 2 is primitive in F_5 and F_13; T^4-2 is irreducible there.
        # This includes both the disjoint-coset and contained-coset cases.
        for p, nonresidue, log, shift in ((5, 2, 0, 3), (13, 2, 0, 3), (13, 2, 0, 1)):
            with self.subTest(p=p, shift=shift):
                actual = enumerate_events(p, nonresidue, log, shift)
                counted = audit.count_events(p, log, shift)
                expected = tuple(int(counted[key]) for key in (
                    'rational_denominator_pole_set_size', 'trace_zerofier_zero_set_size', 'intersection_size'))
                self.assertEqual(actual, expected)
                self.assertEqual(int(counted['two_named_events_union_size']), actual[0]+actual[1]-actual[2])

    def test_exact_fixed_domains_have_seventeen_n_union(self):
        for log in range(25):
            with self.subTest(log=log):
                result = audit.count_events(audit.P, log)
                self.assertEqual(int(result['rational_denominator_pole_set_size']), 16*(1 << log))
                self.assertEqual(result['intersection_size'], '0')
                self.assertEqual(int(result['two_named_events_union_size']), 17*(1 << log))
                fraction = result['ideal_uniform_two_events_union_probability']
                self.assertEqual(Fraction(int(fraction['numerator']), int(fraction['denominator'])),
                                 Fraction(17*(1 << log), audit.P**4))

    def test_rejects_nonprime_and_nonexistent_base_domains(self):
        for p, log in ((9, 0), (15, 0), (13, 1), (audit.P, 25)):
            with self.subTest(p=p, log=log), self.assertRaises(audit.DeepEventError):
                audit.count_events(p, log)

    def test_rejects_bool_float_and_shift_zero(self):
        for p, log, shift in ((True, 0, 3), (audit.P, True, 3), (audit.P, 1.0, 3),
                              (audit.P, 18, True), (audit.P, 18, 0)):
            with self.subTest(p=p, log=log, shift=shift), self.assertRaises(audit.DeepEventError):
                audit.count_events(p, log, shift)

    def test_current_fixed_source_and_security_hold(self):
        result = audit.build_report(ROOT)
        self.assertEqual(result['status'], 'TWO_NAMED_IDEAL_FIELD_EVENTS_COUNTED_SECURITY_HOLD')
        self.assertEqual(len(result['domains']), 25)
        self.assertEqual(result['domains'][18]['two_named_events_union_size'], str(17*2**18))
        qualification = result['qualification']
        self.assertTrue(qualification['two_named_exceptional_set_cardinalities_checked'])
        self.assertFalse(qualification['actual_poseidon2_conditional_uniformity_proved'])
        self.assertFalse(qualification['complete_bad_event_coverage_proved'])
        self.assertFalse(qualification['rbr_or_fri_soundness_bound_established'])
        self.assertIsNone(qualification['quantum_security_bits'])
        self.assertFalse(qualification['consensus_admission'])

    def test_snapshot_byte_mutation_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / audit.SNAPSHOT
            target.parent.mkdir(parents=True)
            raw = bytearray((ROOT / audit.SNAPSHOT).read_bytes())
            raw[-1] ^= 1
            target.write_bytes(raw)
            with self.assertRaisesRegex(audit.DeepEventError, 'snapshot identity differs'):
                audit.build_report(root)

    def test_missing_and_symlinked_snapshot_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(audit.DeepEventError):
                audit.build_report(root)
            target = root / audit.SNAPSHOT
            target.parent.mkdir(parents=True)
            target.symlink_to(ROOT / audit.SNAPSHOT)
            with self.assertRaises(audit.DeepEventError):
                audit.build_report(root)


if __name__ == '__main__':
    unittest.main(verbosity=2)
