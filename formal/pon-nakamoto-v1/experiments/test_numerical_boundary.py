"""Exact arithmetic and structure controls; these are not learning benchmarks."""
from __future__ import annotations

from fractions import Fraction
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import numerical_boundary as research


class NumericalBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.operators = research.operator_sensitivity()
        cls.floating = research.field_float_controls()

    def test_positive_negative_zero_and_exact_subnormals(self):
        self.assertEqual(research.ieee_fraction(0, 23), Fraction())
        self.assertEqual(research.ieee_fraction(0x80000000, 23), Fraction())
        self.assertEqual(research.ieee_fraction(1, 23), Fraction(1, 1 << 149))
        self.assertEqual(research.ieee_fraction(0x80000001, 23), -Fraction(1, 1 << 149))
        self.assertEqual(research.ieee_fraction(1, 7), Fraction(1, 1 << 133))

    def test_ties_are_even_before_clipping_and_one_ulp_changes_the_result(self):
        for value, expected in ((0.03125, 0), (0.09375, 2), (0.15625, 2),
                                (-0.03125, 0), (-0.09375, -2)):
            self.assertEqual(research.quantize_reference(research.fp32_bits(value), 23, 4, 128), (expected, False))
        halfway = research.fp32_bits(0.03125)
        self.assertEqual(research.quantize_reference(halfway - 1, 23, 4, 128), (0, False))
        self.assertEqual(research.quantize_reference(halfway + 1, 23, 4, 128), (1, False))
        self.assertEqual(research.quantize_reference(research.fp32_bits(8.03125), 23, 4, 128), (128, False))
        self.assertEqual(research.quantize_reference(research.fp32_bits(8.09375), 23, 4, 128), (128, True))

    def test_nan_and_infinity_are_rejected_instead_of_saturated(self):
        for mantissa, patterns in ((7, (0x7f80, 0xff80, 0x7fc1, 0x7f81)),
                                   (23, (0x7f800000, 0xff800000, 0x7fc00001, 0x7f800001))):
            for bits in patterns:
                with self.subTest(mantissa=mantissa, bits=bits), self.assertRaisesRegex(ValueError, "NONFINITE"):
                    research.quantize_reference(bits, mantissa, 4, 128)

    def test_alias_and_unbounded_research_parameters_are_rejected(self):
        for bits in (True, -1, 1 << 32):
            with self.assertRaisesRegex(ValueError, "IEEE_ENCODING"):
                research.ieee_fraction(bits, 23)
        for scale, clip in ((True, 128), (33, 128), (4, False), (4, 0), (4, 1 << 31)):
            with self.assertRaisesRegex(ValueError, "RESEARCH_QUANTIZATION_PARAMETERS"):
                research.quantize_reference(0, 23, scale, clip)

    def test_real_vector_operator_control_has_exact_and_lossy_cases(self):
        rows = {(row["weight_scale_power"], row["activation_scale_power"]): row
                for row in self.operators["scale_controls"]}
        self.assertEqual(set(rows), set(research.SCALES))
        self.assertEqual(rows[(14, 6)]["max_absolute_product_error"], ["0", "1"])
        self.assertGreater(Fraction(*map(int, rows[(14, 4)]["max_absolute_product_error"])), 0)
        self.assertGreater(Fraction(*map(int, rows[(8, 2)]["max_absolute_product_error"])), 0)
        self.assertGreater(self.operators["clipping_control"]["weight_clipped"], 0)
        self.assertGreater(self.operators["clipping_control"]["activation_clipped"], 0)
        self.assertFalse(self.operators["training_executed"])

    def test_padding_produces_exact_zero_columns_and_a_rank_ceiling(self):
        rows = self.operators["token_padding_controls"]
        self.assertEqual([r["retained_token_columns"] for r in rows], list(research.TOKEN_COUNTS))
        for row in rows:
            self.assertLessEqual(row["rank_mod_q"], row["retained_token_columns"])
            self.assertTrue(row["padded_output_columns_are_exact_zero"])

    def test_real_W1_noise_cannot_be_silently_replaced_by_float_accumulation(self):
        self.assertGreater(self.floating["float32_mismatches"], 0)
        self.assertGreater(self.floating["float64_mismatches"], 0)
        self.assertEqual(len(self.floating["observations"]), 32)
        self.assertFalse(self.floating["float_substitution_preserves_W1"])

    def test_larger_quantization_ranges_need_a_new_signed_decode_bound(self):
        self.assertLessEqual(self.floating["current_clip_bound"], self.floating["half_field"])
        self.assertGreater(self.floating["expanded_both_clip_32767_bound"], self.floating["half_field"])
        self.assertFalse(self.floating["expanded_signed_decode_matches_integer"])

    def test_native_probe_corpus_contains_nonfinite_and_nondefault_controls(self):
        cases = research.quantizer_cases()
        self.assertTrue(any(row["expected"].get("error") == "NONFINITE" for row in cases))
        self.assertTrue(any(row["expected"].get("clipped") is True for row in cases))
        self.assertTrue(any(not row["default_private_primitive_parameters"] for row in cases))
        self.assertTrue(any(row["default_private_primitive_parameters"] for row in cases))


if __name__ == "__main__":
    unittest.main(verbosity=2)
