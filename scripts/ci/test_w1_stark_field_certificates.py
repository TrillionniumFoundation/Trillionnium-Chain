#!/usr/bin/env python3
"""Independent finite-algebra and fixed-source controls; no proof attacks."""
from __future__ import annotations

from contextlib import redirect_stderr
from itertools import product
import io
import json
import math
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import w1_stark_field_certificates as field


def reference_divides(polynomial, divisor, p):
    """Small-field schoolbook division, independent of the certificate helpers."""
    residual = list(polynomial)
    for offset in range(len(polynomial) - len(divisor), -1, -1):
        coefficient = residual[offset + len(divisor) - 1] % p
        for index, value in enumerate(divisor):
            residual[offset + index] = (residual[offset + index] - coefficient * value) % p
    return not any(residual)


def reference_irreducible(polynomial, p):
    degree = len(polynomial) - 1
    for factor_degree in range(1, degree // 2 + 1):
        for values in product(range(p), repeat=factor_degree):
            if reference_divides(polynomial, values + (1,), p):
                return False
    return True


def reference_bezout(left, polynomial, right, probe, p):
    total = [0] * max(len(left) + len(polynomial), len(right) + len(probe), 1)
    for a, b in ((left, polynomial), (right, probe)):
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                total[i + j] = (total[i + j] + x * y) % p
    return total[0] == 1 and not any(total[1:])


class FixedFieldCertificates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs, cls.risc_sources, cls.p3_sources, _ = field.load_sources(ROOT)
        cls.risc = field.parse_risc_parameters(cls.risc_sources)
        cls.p3 = field.parse_p3_parameters(cls.p3_sources, cls.inputs)
        cls.report = field.build_report(ROOT)

    def test_lucas_certificates_independently_recompute(self):
        for instance in self.report["fields"].values():
            with self.subTest(p=instance["characteristic"]):
                p = int(instance["characteristic"])
                certificate = instance["primality"]
                witness = int(certificate["witness"])
                product_value = 1
                for factor in certificate["factorization"]:
                    q, exponent = int(factor["prime"]), int(factor["exponent"])
                    self.assertTrue(all(q % d != 0 for d in range(2, math.isqrt(q) + 1)))
                    product_value *= q ** exponent
                    self.assertEqual(math.gcd(pow(witness, (p - 1) // q, p) - 1, p), 1)
                self.assertEqual(product_value, p - 1)
                self.assertEqual(pow(witness, p - 1, p), 1)

    def test_rabin_matches_exhaustive_small_field_factorization(self):
        checked = 0
        for p, degree in ((3, 2), (5, 2), (7, 2), (3, 4), (5, 4)):
            for coefficients in product(range(p), repeat=degree):
                polynomial = coefficients + (1,)
                expected = reference_irreducible(polynomial, p)
                try:
                    certificate = field.irreducibility_certificate(p, polynomial)
                except field.CertificateError:
                    accepted = False
                else:
                    accepted = certificate["extension_irreducible_certified"]
                self.assertEqual(accepted, expected, (p, polynomial))
                checked += 1
        self.assertEqual(checked, 789)

    def test_large_field_nonresidue_values(self):
        self.assertEqual(field.BABYBEAR % 4, 1)
        self.assertEqual(pow(field.BABYBEAR - 11, (field.BABYBEAR - 1) // 2, field.BABYBEAR),
                         field.BABYBEAR - 1)
        self.assertEqual(pow(7, (field.GOLDILOCKS - 1) // 2, field.GOLDILOCKS), field.GOLDILOCKS - 1)

    def test_published_bezout_identities_independently_check(self):
        for instance in self.report["fields"].values():
            certificate = instance["irreducibility"]
            convert = lambda key: tuple(map(int, certificate[key]))
            self.assertTrue(reference_bezout(
                convert("bezout_coefficient_for_polynomial"), convert("polynomial_low_to_high"),
                convert("bezout_coefficient_for_probe"), convert("gcd_probe_low_to_high"),
                int(instance["characteristic"])))

    def test_published_frobenius_residues(self):
        for name, instance in self.report["fields"].items():
            p, degree = int(instance["characteristic"]), int(instance["extension_degree"])
            rows = {int(row["power_of_characteristic"]): tuple(map(int, row["residue_low_to_high"]))
                    for row in instance["irreducibility"]["frobenius_residues"]}
            self.assertEqual(rows[degree], (0, 1), name)
            self.assertEqual(rows[degree // 2], (0, p - 1), name)

    def test_incomplete_prime_factorization_refused(self):
        with self.assertRaisesRegex(field.CertificateError, "incomplete factorization"):
            field.prime_certificate(field.BABYBEAR, 31, ((2, 27), (3, 1)))

    def test_nonprime_factor_refused(self):
        with self.assertRaisesRegex(field.CertificateError, "nonprime Lucas factor"):
            field.prime_certificate(field.BABYBEAR, 31, ((2, 27), (15, 1)))

    def test_root_of_power_two_is_not_full_lucas_witness(self):
        with self.assertRaisesRegex(field.CertificateError, "required prime-power order"):
            field.prime_certificate(field.BABYBEAR, 137, ((2, 27), (3, 1), (5, 1)))

    def test_boolean_and_float_arithmetic_inputs_refused(self):
        for value in (True, 3.0, "3"):
            with self.subTest(value=value), self.assertRaises(field.CertificateError):
                field.prime_certificate(value, 2, ((2, 1),))

    def test_reducible_large_field_polynomials_refused(self):
        for p, polynomial in ((field.BABYBEAR, (field.BABYBEAR - 1, 0, 0, 0, 1)),
                              (field.GOLDILOCKS, (field.GOLDILOCKS - 4, 0, 1))):
            with self.subTest(p=p), self.assertRaisesRegex(field.CertificateError, "reducible"):
                field.irreducibility_certificate(p, polynomial)

    def test_all_source_roots_independently_have_exact_order(self):
        expected_lengths = {"risc0_babybear_fp4": 28, "plonky3_goldilocks_fp2": 33}
        for name, instance in self.report["fields"].items():
            p = int(instance["characteristic"])
            rows = instance["multiplicative_domains"]["entries"]
            self.assertEqual(len(rows), expected_lengths[name])
            for row in rows:
                order, root = int(row["order"]), int(row["root"])
                self.assertEqual(pow(root, order, p), 1)
                if order > 1:
                    self.assertEqual(pow(root, order // 2, p), p - 1)

    def test_wrong_order_and_inverse_roots_refused(self):
        parameters = self.risc
        roots = list(parameters["roots"])
        roots[-1] = roots[-2]
        with self.assertRaisesRegex(field.CertificateError, "root exact order"):
            field.root_table_certificate(parameters["p"], roots, 27)
        inverse = list(parameters["inverse_roots"])
        inverse[-1] = 1
        with self.assertRaisesRegex(field.CertificateError, "inverse root table"):
            field.root_table_certificate(parameters["p"], parameters["roots"], 27, inverse)

    def test_p3_and_risc_fields_cannot_be_substituted(self):
        changed = dict(self.risc_sources)
        path = "risc0/core/src/field/baby_bear.rs"
        changed[path] = changed[path].replace("15 * (1 << 27) + 1", "1 * (1 << 64) + 1")
        with self.assertRaisesRegex(field.CertificateError, "unsupported RISC"):
            field.parse_risc_parameters(changed)
        inputs = dict(self.inputs)
        path = field.P3_ROOT + "src/tagged_sha3.rs"
        inputs[path] = inputs[path].replace(b"BinomialExtensionField<Val, 2>", b"BinomialExtensionField<Val, 4>")
        with self.assertRaisesRegex(field.CertificateError, "P3 field/type/PCS"):
            field.parse_p3_parameters(self.p3_sources, inputs)

    def test_missing_or_changed_source_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in field.SOURCE_PINS:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, target)
            changed = root / (field.P3_ROOT + "src/proof_config.rs")
            raw = changed.read_bytes()
            changed.write_bytes(b" " + raw[1:])
            with self.assertRaisesRegex(field.CertificateError, "source SHA-256 differs"):
                field.build_report(root)
            changed.unlink()
            with self.assertRaises(OSError):
                field.build_report(root)

    def test_no_security_promotion_or_rounded_json_numbers(self):
        q = self.report["qualification"]
        for key in ("fri_soundness_qualified", "rbr_knowledge_soundness_qualified",
                    "post_quantum_soundness_qualified", "recursive_composition_qualified",
                    "compiled_field_arithmetic_equivalence_proved", "production_qualified",
                    "consensus_admission", "native_binary_executed"):
            self.assertIs(q[key], False)
        self.assertIsNone(q["security_bits_quantum"])
        self.assertIsNone(q["whole_lifetime_failure_bound"])
        for instance in self.report["fields"].values():
            self.assertIs(instance["characteristic_two_additive_domain_hypothesis_matches"], False)
            self.assertIs(instance["this_mismatch_proves_fri_soundness"], False)
        def check(value):
            self.assertNotIsInstance(value, float)
            self.assertFalse(type(value) is int)
            if isinstance(value, dict):
                for item in value.values():
                    check(item)
            elif isinstance(value, list):
                for item in value:
                    check(item)
        check(self.report)
        self.assertEqual(json.loads(json.dumps(self.report)), self.report)

    def test_failure_cli_does_not_claim_algebra_success(self):
        with tempfile.TemporaryDirectory() as directory:
            captured = io.StringIO()
            with redirect_stderr(captured):
                result = field.main(["--repo-root", directory])
            self.assertEqual(result, 2)
            report = json.loads(captured.getvalue())
            self.assertEqual(report["status"], "INPUT_REJECTED")
            self.assertIs(report["algebraic_facts_certified"], False)
            self.assertIsNone(report["security_bits_quantum"])


if __name__ == "__main__":
    unittest.main()
