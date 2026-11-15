"""Independent arithmetic controls for the scoped author-slide component."""
from fractions import Fraction as F
import json
from pathlib import Path
import unittest

from fast_daa_reference_component import (
    COMPONENT_ID, MAX_BLOCKS_PER_CHAIN, MAX_CHAINS, MAX_INPUT_BITS,
    UnspecifiedCase, approx_agree, retarget_component,
)


REFERENCES = ("chain-a", "chain-b", "chain-c", "chain-d")


def evaluate(histories=None, **kwargs):
    if histories is None:
        histories = {ref: [10] for ref in REFERENCES}
    return retarget_component(REFERENCES, histories, eta=1,
                              ideal_blocks=kwargs.get("ideal_blocks", 1),
                              dampening=kwargs.get("dampening", 2))


class ApproximateAgreementControls(unittest.TestCase):
    def test_representatives_differ_from_ordinary_trimmed_mean(self):
        values = [30, 3, 1, 11, 20, 9, 2, 10]
        # Sorted retained values are 3,9,10,11. Chunk representatives are 3,10.
        self.assertEqual(approx_agree(values, 2), F(13, 2))
        self.assertNotEqual(approx_agree(values, 2), F(3 + 9 + 10 + 11, 4))
        self.assertEqual(approx_agree(list(reversed(values)), 2), F(13, 2))

    def test_exact_positive_scaling(self):
        values = [1, 2, 3, 9, 10, 11, 20, 30]
        self.assertEqual(approx_agree([F(7, 3) * x for x in values], 2),
                         F(7, 3) * approx_agree(values, 2))

    def test_partial_chunks_and_invalid_trimming_are_rejected(self):
        with self.assertRaisesRegex(UnspecifiedCase, "PARTIAL_REPRESENTATIVE_CHUNK"):
            approx_agree([1] * 7, 2)
        for eta in (True, 0, -1, 1.0, F(1), 2):
            with self.subTest(eta=eta), self.assertRaisesRegex(ValueError, "TRIM_REQUIRES"):
                approx_agree([1] * 6, eta)

    def test_bad_numbers_and_oversized_inputs_are_rejected(self):
        for value in (True, 1.0, "1", F(0), -1, float("nan"),
                      1 << MAX_INPUT_BITS, F(1, 1 << MAX_INPUT_BITS)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                approx_agree([1, 2, 3, value], 1)
        with self.assertRaisesRegex(ValueError, "BOUNDED_SEQUENCE"):
            approx_agree([1] * (MAX_CHAINS + 1), 1)
        with self.assertRaisesRegex(ValueError, "BOUNDED_SEQUENCE"):
            approx_agree(iter([1, 2, 3, 4]), 1)


class RetargetControls(unittest.TestCase):
    def test_varying_odd_histories_exact_hand_calculation(self):
        histories = dict(zip(REFERENCES, (
            [2, 4, 9], [1, 4, 6, 8, 11], [3, 8, 10], [1, 3, 7, 10, 11, 15, 19],
        )))
        result = evaluate(histories, ideal_blocks=3)
        self.assertEqual(result.chain_medians, (4, 6, 8, 10))
        self.assertEqual(result.chain_ratios, (F(5, 4), F(5, 3), F(7, 8), F(11, 5)))
        self.assertEqual(result.difficulty_representatives, (6, 8))
        self.assertEqual(result.ratio_representatives, (F(5, 4), F(5, 3)))
        self.assertEqual(result.reference_difficulty, F(7))
        self.assertEqual(result.reference_ratio, F(35, 24))
        self.assertEqual(result.next_difficulty, F(245, 24))

    def test_clipping_uses_both_reciprocal_bounds(self):
        high = evaluate({ref: [10, 10, 10] for ref in REFERENCES}, dampening=F(3, 2))
        self.assertEqual(high.reference_ratio, 3)
        self.assertEqual(high.clipped_ratio, F(3, 2))
        self.assertEqual(high.next_difficulty, 15)
        low = evaluate(ideal_blocks=4, dampening=F(3, 2))
        self.assertEqual(low.reference_ratio, F(1, 4))
        self.assertEqual(low.clipped_ratio, F(2, 3))
        self.assertEqual(low.next_difficulty, F(20, 3))

    def test_scale_homogeneity_and_reference_permutation(self):
        histories = {ref: [i + 1, i + 3, i + 7] for i, ref in enumerate(REFERENCES)}
        original = evaluate(histories, ideal_blocks=3)
        scale = F(7, 3)
        scaled = evaluate({ref: [scale * x for x in values] for ref, values in histories.items()},
                          ideal_blocks=3)
        self.assertEqual(scaled.reference_ratio, original.reference_ratio)
        self.assertEqual(scaled.next_difficulty, scale * original.next_difficulty)
        reordered = retarget_component(tuple(reversed(REFERENCES)), histories, eta=1,
                                       ideal_blocks=3, dampening=2)
        self.assertEqual(reordered.next_difficulty, original.next_difficulty)

    def test_missing_empty_and_even_histories_refuse_undefined_policies(self):
        for bad, reason in ((None, "MISSING_CHAIN_REFERENCE"),
                            ([], "EMPTY_CHAIN_HISTORY"), ([10, 20], "EVEN_LENGTH_MEDIAN")):
            histories = {ref: [10] for ref in REFERENCES}
            histories[REFERENCES[0]] = bad
            with self.subTest(reason=reason), self.assertRaisesRegex(UnspecifiedCase, reason):
                evaluate(histories)
        with self.assertRaisesRegex(UnspecifiedCase, "MISSING_CHAIN_REFERENCE"):
            evaluate({ref: [10] for ref in REFERENCES[:-1]})

    def test_reference_and_history_bounds(self):
        histories = {ref: [10] for ref in REFERENCES}
        with self.assertRaisesRegex(ValueError, "DUPLICATE_REFERENCE"):
            retarget_component(("a", "a", "b", "c"), histories, eta=1,
                               ideal_blocks=1, dampening=2)
        with self.assertRaisesRegex(ValueError, "UNREFERENCED_CHAIN_HISTORY"):
            evaluate({**histories, "not-referenced": [10]})
        histories[REFERENCES[0]] = [10] * (MAX_BLOCKS_PER_CHAIN + 2)
        with self.assertRaisesRegex(ValueError, "CHAIN_HISTORY_BOUNDED_SEQUENCE"):
            evaluate(histories)
        long_histories = {str(i): [1] * MAX_BLOCKS_PER_CHAIN for i in range(8)}
        with self.assertRaisesRegex(ValueError, "TOTAL_BLOCK_BUDGET"):
            retarget_component(tuple(long_histories), long_histories, eta=2,
                               ideal_blocks=1, dampening=2)

    def test_parameter_types_and_false_values_are_not_silently_coerced(self):
        for name in ("ideal_blocks", "dampening"):
            for value in (False, 0, -1, 2.0, "2", 1 << MAX_INPUT_BITS):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    evaluate(**{name: value})
        with self.assertRaisesRegex(ValueError, "DAMPENING_BELOW_ONE"):
            evaluate(dampening=F(1, 2))

    def test_report_and_source_manifest_keep_full_protocol_unimplemented(self):
        result = evaluate()
        report = json.loads(json.dumps(result.report()))
        self.assertEqual(report["next_difficulty"], {"numerator": 10, "denominator": 1})
        for flag in ("complete_protocol_implemented", "production_activation", "quantum_security_established"):
            self.assertIs(report[flag], False)
        manifest = json.loads((Path(__file__).parent / "vectors" /
                               "fast-daa-author-slides-retarget-v1.json").read_text())
        self.assertEqual(manifest["component_id"], COMPONENT_ID)
        self.assertEqual(manifest["source"]["pdf_sha256"],
                         "4ec8a855db8ac45118eb15b0783d665a3deadd4f27302f2a500a2b19d3a9311a")
        self.assertEqual(manifest["source"]["verified_formula_pdf_pages_1_based"], [61, 62, 63])
        self.assertIs(manifest["complete_protocol_implemented"], False)


if __name__ == "__main__":
    unittest.main()
