"""Pure mathematical tests only; native differential is test_model_composition.py."""
import unittest
import model_composition_oracle as oracle


def model(value=0):
    coefficients = [0] * oracle.COEFFICIENTS
    coefficients[1542] = value
    return tuple(coefficients)


class ModelCompositionOracleTests(unittest.TestCase):
    def test_codec_round_trip_and_invalid_minimum(self):
        family = bytes(range(32))
        values = list(model())
        values[0], values[-1] = -32767, 32767
        raw = oracle.encode_model(family, values)
        self.assertEqual(len(raw), 7756)
        self.assertEqual(oracle.decode_model(raw, family), tuple(values))
        self.assertEqual(raw[:6], b'ILM2\x02\x00')
        values[0] = -32768
        with self.assertRaisesRegex(ValueError, '^FACTOR_MODEL_RANGE$'):
            oracle.encode_model(family, values)

    def test_boolean_and_float_are_not_integer_coefficients(self):
        for value in [True, 1.0, -32768, 32768]:
            coefficients = list(model())
            coefficients[1] = value
            with self.assertRaisesRegex(ValueError, '^FACTOR_MODEL_RANGE$'):
                oracle.encode_model(bytes(32), coefficients)

    def test_nonzero_parent_is_counted_once(self):
        parent, first, second = model(10), model(13), model(8)
        self.assertEqual(oracle.derive(parent, [first, second]), model(11))
        self.assertEqual(oracle.derive(parent, [first, second], 0), second)
        self.assertEqual(oracle.derive(parent, [first, second], 1), first)

    def test_wide_intermediates_and_invalid_omission(self):
        for sign in [-1, 1]:
            parent = model(sign * 20000)
            components = [model(sign * n) for n in [32000, 32000, 2000]]
            self.assertEqual(oracle.derive(parent, components), model(sign * 26000))
            with self.assertRaisesRegex(ValueError, '^MODEL_COMPOSITION_RANGE$'):
                oracle.derive(parent, components, 2)

    def test_exact_subset_checks_use_all_coordinates(self):
        parent = model(10)
        components = [model(n) for n in [13, 7, 15]]
        with self.assertRaisesRegex(ValueError, '^MODEL_COMPOSITION_REDUNDANT_SUBSET$'):
            oracle.reject_redundant_subsets(parent, components)
        distinct = list(components[1])
        distinct[-1] = 1
        self.assertEqual(oracle.reject_redundant_subsets(parent, [components[0], distinct, components[2]]), 4)
        self.assertEqual(oracle.reject_redundant_subsets(parent, [model(n) for n in [11, 12, 14, 18]]), 11)

    def test_router_and_class_ties_use_the_lowest_index(self):
        x = [0] * 256 + [8]
        coefficients = list(model())
        coefficients[771 + 256] = 1
        coefficients[771 + 257 + 256] = 1
        coefficients[2 * 771 + 2 * 257 + 256] = 7
        coefficients[3 * 771 + 257 + 256] = 7
        self.assertEqual(oracle.predictions(coefficients, [x]), [2])
        coefficients[2 * 771 + 257 + 256] = 7
        self.assertEqual(oracle.predictions(coefficients, [x]), [1])

    def test_base_and_expert_logits_add_without_scaling_or_rounding(self):
        x = [0] * 256 + [8]
        coefficients = list(model())
        coefficients[2 * 257 + 256] = 32767
        coefficients[2 * 771 + 257 + 256] = 32766
        self.assertEqual(oracle.predictions(coefficients, [x]), [2])
        coefficients[257 + 256] = 2
        self.assertEqual(oracle.predictions(coefficients, [x]), [1])

    def test_unsigned_budget_domain_excludes_bools_and_overflow(self):
        self.assertEqual(oracle.uint((1 << 64) - 1), (1 << 64) - 1)
        for value in [-1, True, 1.0, 1 << 64]:
            with self.assertRaisesRegex(ValueError, '^MODEL_COMPOSITION_RANGE$'):
                oracle.uint(value)


if __name__ == '__main__':
    unittest.main(verbosity=2)
