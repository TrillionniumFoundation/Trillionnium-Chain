"""Small exact controls; no NumPy, trained fixture or timing claim is required."""
import copy
from fractions import Fraction
import random
import unittest

from contract_wire import canonical
from ledger import FAMILY
from model_contract import CLASSES, DIM, SCALE, infer
from useful_cell_numeric_v1 import (
    NUMERIC_PROFILE, OUTPUT_ROWS, centered_decode, checked_signed_bound,
    compare_behavior, evaluate_exact,
)
from work_oracle import Q, mm


def model_fixture():
    return {
        "schema": "hepta-source-owner-linear-256-v1",
        "family": FAMILY.hex(), "scale": SCALE, "source": "numeric-control-only",
        "base": [[0] * DIM for _ in range(3)],
        "router": [[0] * DIM for _ in range(3)],
        "deltas": [[[0] * DIM for _ in range(3)] for _ in range(3)],
        "feature": "signed-token-hash-256-clipped8-plus-bias-v1", "classes": CLASSES[:],
    }


def features():
    return [0] * (DIM - 1) + [8]


class SignedBoundsTests(unittest.TestCase):
    def test_odd_half_boundary_uses_exact_doubling(self):
        self.assertEqual(checked_signed_bound(3, 4, 4, p=97), 48)
        self.assertEqual(checked_signed_bound(0, 0, 0, bias=48, p=97), 48)
        self.assertEqual(checked_signed_bound(0, 0, 0, bias=-48, p=97), 48)
        for bias in (1, -1):
            with self.subTest(bias=bias), self.assertRaisesRegex(ValueError, "SIGNED_DECODE_RANGE"):
                checked_signed_bound(3, 4, 4, bias=bias, p=97)
        self.assertEqual(centered_decode(49, p=97), -48)

    def test_merged_weights_require_their_own_doubled_bound(self):
        single = checked_signed_bound(DIM, 8, 32767)
        merged = checked_signed_bound(DIM, 8, 65534)
        self.assertEqual(single, 67368952)
        self.assertEqual(merged, 134737904)
        self.assertEqual(merged, 2 * single)
        self.assertEqual(checked_signed_bound(3, 4, 4, p=97), 48)
        with self.assertRaisesRegex(ValueError, "SIGNED_DECODE_RANGE"):
            checked_signed_bound(3, 4, 8, p=97)

    def test_bound_construction_does_not_wrap_or_overflow_abs(self):
        for args in ((1 << 128, 8, 32767, 0),
                     (1, 1 << 128, 1 << 128, 0),
                     (0, 0, 0, -(1 << 63))):
            with self.subTest(args=args), self.assertRaisesRegex(ValueError, "SIGNED_DECODE_RANGE"):
                checked_signed_bound(*args)

    def test_negative_limits_and_noninteger_aliases_are_rejected(self):
        for args in ((-1, 4, 4), (1, -4, 4), (1, 4, -4)):
            with self.subTest(args=args), self.assertRaisesRegex(ValueError, "SIGNED_BOUND_RANGE"):
                checked_signed_bound(*args)
        for position in range(4):
            for invalid in (True, 1.0, Fraction(1), "1"):
                args = [1, 1, 1, 0]
                args[position] = invalid
                with self.subTest(position=position, invalid=invalid), self.assertRaisesRegex(
                        ValueError, "SIGNED_BOUND_TYPE"):
                    checked_signed_bound(*args)

    def test_centered_decode_requires_canonical_residues(self):
        for signed in range(-48, 49):
            self.assertEqual(centered_decode(signed % 97, p=97), signed)
        self.assertEqual(centered_decode(Q // 2), Q // 2)
        self.assertEqual(centered_decode(Q // 2 + 1), -(Q // 2))
        for invalid in (-1, 97, 98, True, 1.0, Fraction(1)):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "FIELD_ELEMENT"):
                centered_decode(invalid, p=97)

    def test_ambiguous_or_noninteger_moduli_are_rejected(self):
        for p in (0, 1, 2, 96, -97, True, 97.0, Fraction(97)):
            with self.subTest(p=p), self.assertRaisesRegex(ValueError, "FIELD_MODULUS"):
                checked_signed_bound(1, 1, 1, p=p)
            with self.subTest(p=p), self.assertRaisesRegex(ValueError, "FIELD_MODULUS"):
                centered_decode(0, p=p)


class ExactCellTests(unittest.TestCase):
    def test_declared_scales_and_integer_only_semantics(self):
        self.assertEqual(NUMERIC_PROFILE["feature_dimensions"], 257)
        self.assertEqual(NUMERIC_PROFILE["coefficient_scale"], 1024)
        self.assertEqual(NUMERIC_PROFILE["feature_scale"], 8)
        self.assertEqual(NUMERIC_PROFILE["output_scale"], 8192)
        self.assertEqual(NUMERIC_PROFILE["inference_rounding"], "none")
        self.assertEqual(NUMERIC_PROFILE["overflow"], "reject")
        self.assertEqual(NUMERIC_PROFILE["saturation"], "none")
        self.assertEqual(NUMERIC_PROFILE["runtime_quantizer"], "none")
        self.assertEqual(NUMERIC_PROFILE["floating_point_support"], "none")
        self.assertEqual(NUMERIC_PROFILE["field_modulus"], Q)
        self.assertIsInstance(canonical(NUMERIC_PROFILE), bytes)

    def test_sparse_all_tile_regions_and_bias_have_exact_known_outputs(self):
        model = model_fixture()
        model["base"][0][0] = 2
        model["base"][1][256] = 3
        model["base"][2][64] = -4
        model["router"][0][128] = 1
        model["router"][1][192] = 2
        model["router"][2][255] = 3
        model["deltas"][0][0][63] = 4
        model["deltas"][1][1][127] = -5
        model["deltas"][2][2][191] = 6
        row = features()
        for coordinate, value in ((0, 1), (63, 2), (64, -1), (127, 3),
                                  (128, 4), (191, -2), (192, 5), (255, 1)):
            row[coordinate] = value
        other = [-value for value in row[:-1]] + [8]
        original_model, original_rows = copy.deepcopy(model), copy.deepcopy([row, other])
        result = evaluate_exact(model, [row, other])
        self.assertEqual(result, {
            "products": [[2, -2], [24, 24], [4, -4], [4, -4], [10, -10], [3, -3],
                         [8, -8], [0, 0], [0, 0], [0, 0], [-15, 15], [0, 0],
                         [0, 0], [0, 0], [-12, 12]],
            "routes": [1, 2], "logits": [[2, 9, 4], [-2, 24, 8]], "predictions": [1, 1],
        })
        self.assertEqual(model, original_model)
        self.assertEqual([row, other], original_rows)

    def test_lowest_index_ties_include_negative_and_nonzero_winners(self):
        model, row = model_fixture(), features()
        self.assertEqual(evaluate_exact(model, [row])["routes"], [0])
        self.assertEqual(evaluate_exact(model, [row])["predictions"], [0])
        row[0] = 1
        for name in ("router", "base"):
            model[name][0][0] = -3
            model[name][1][0] = -2
            model[name][2][0] = -2
        result = evaluate_exact(model, [row])
        self.assertEqual(result["routes"], [1])
        self.assertEqual(result["predictions"], [1])

    def test_extreme_positive_and_negative_outputs_are_not_rescaled_or_saturated(self):
        bound = checked_signed_bound(DIM, 8, 32767)
        for sign in (-1, 1):
            model = model_fixture()
            for matrix in [model["base"], model["router"]] + model["deltas"]:
                for row in matrix:
                    row[:] = [sign * 32767] * DIM
            result = evaluate_exact(model, [[8] * DIM])
            self.assertEqual(result["products"], [[sign * bound] for _ in range(OUTPUT_ROWS)])
            self.assertEqual(result["logits"], [[sign * 2 * bound] * 3])
            self.assertEqual(result["routes"], [0])
            self.assertEqual(result["predictions"], [0])

    def test_no_inference_rounding_erases_a_small_integer_score(self):
        model, row = model_fixture(), features()
        row[0] = 1
        model["router"][2][0] = 1
        model["deltas"][2][2][0] = 1
        result = evaluate_exact(model, [row])
        self.assertEqual(result["logits"], [[0, 0, 1]])
        self.assertEqual(result["routes"], [2])
        self.assertEqual(result["predictions"], [2])

    def test_seeded_integer_predictions_match_existing_scalar_contract(self):
        rng = random.Random(20261105)
        model = model_fixture()
        for matrix in [model["base"], model["router"]] + model["deltas"]:
            for row in matrix:
                row[:] = [rng.randrange(-32767, 32768) for _ in range(DIM)]
        rows = [[rng.randrange(-8, 9) for _ in range(DIM - 1)] + [8] for _ in range(19)]
        self.assertEqual(evaluate_exact(model, rows)["predictions"], infer(model, rows))

    def test_complete_integer_products_equal_centered_field_contraction(self):
        model = model_fixture()
        for number, matrix in enumerate([model["base"], model["router"]] + model["deltas"]):
            for label, row in enumerate(matrix):
                row[:] = [((number + 3) * (label + 1) * (coordinate + 1)) % 65535 - 32767
                          for coordinate in range(DIM)]
        rows = [[coordinate % 17 - 8 for coordinate in range(DIM - 1)] + [8],
                [8] * DIM]
        weights = model["base"] + model["router"] + [row for delta in model["deltas"] for row in delta]
        field = mm([value % Q for row in weights for value in row],
                   [row[coordinate] % Q for coordinate in range(DIM) for row in rows],
                   OUTPUT_ROWS, DIM, len(rows))
        decoded = [centered_decode(value) for value in field]
        self.assertEqual([value for row in evaluate_exact(model, rows)["products"] for value in row],
                         decoded)

    def test_input_shape_bias_type_range_and_batch_are_enforced(self):
        valid = features()
        invalid_rows = [[], [valid] * 65, [valid[:-1]], [valid + [0]],
                        [[0] * DIM], (valid,), [tuple(valid)], [{"x": valid}]]
        for invalid in (True, 1.0, Fraction(1), -9, 9, 1 << 100):
            row = valid[:]
            row[0] = invalid
            invalid_rows.append([row])
        for rows in invalid_rows:
            with self.subTest(rows_type=type(rows).__name__), self.assertRaises(ValueError):
                evaluate_exact(model_fixture(), rows)
        result = evaluate_exact(model_fixture(), [valid] * 64)
        self.assertEqual(len(result["routes"]), 64)
        self.assertTrue(all(len(row) == 64 for row in result["products"]))

    def test_invalid_artifact_numbers_and_unknown_numeric_schemas_are_rejected(self):
        for invalid in (True, 1.0, Fraction(1), -32768, 32768, 1 << 100):
            model = model_fixture()
            model["deltas"][2][2][256] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                evaluate_exact(model, [features()])
        for field, value in (("scale", 1024.0), ("scale", 512),
                             ("schema", "bf16"), ("runtime_quantizer", "round-to-nearest")):
            model = model_fixture()
            model[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                evaluate_exact(model, [features()])


class BehaviorComparisonTests(unittest.TestCase):
    def report(self, reference, candidate, reference_routes=None, candidate_routes=None,
               reference_stops=None, candidate_stops=None):
        batch = len(reference)
        return compare_behavior(
            reference, candidate,
            reference_routes=[0] * batch if reference_routes is None else reference_routes,
            candidate_routes=[0] * batch if candidate_routes is None else candidate_routes,
            reference_stops=[False] * batch if reference_stops is None else reference_stops,
            candidate_stops=[False] * batch if candidate_stops is None else candidate_stops,
        )

    def test_tiny_exact_error_can_flip_lowest_index_route(self):
        reference = [[Fraction(1, 2), Fraction(50001, 100000)]]
        candidate = [[Fraction(round(value * 1000), 1000) for value in reference[0]]]
        reference_route = max(range(2), key=reference[0].__getitem__)
        candidate_route = max(range(2), key=candidate[0].__getitem__)
        self.assertEqual((reference_route, candidate_route), (1, 0))
        report = self.report(reference, candidate, [reference_route], [candidate_route])
        self.assertEqual(report["numeric"]["mean_absolute_error"], [1, 200000])
        self.assertEqual(report["numeric"]["max_absolute_error"], [1, 100000])
        self.assertFalse(report["routes"]["all_agree"])
        self.assertEqual(report["routes"]["agreement_fraction"], [0, 1])
        self.assertTrue(report["stops"]["all_agree"])
        self.assertIsInstance(canonical(report), bytes)

    def test_tiny_exact_error_can_cross_the_stop_threshold(self):
        threshold = Fraction(1, 2)
        reference = [[Fraction(49999, 100000)]]
        candidate = [[Fraction(1, 2)]]
        report = self.report(reference, candidate,
                             reference_stops=[reference[0][0] >= threshold],
                             candidate_stops=[candidate[0][0] >= threshold])
        self.assertEqual(report["numeric"]["mean_absolute_error"], [1, 100000])
        self.assertTrue(report["routes"]["all_agree"])
        self.assertFalse(report["stops"]["all_agree"])

    def test_equal_numbers_do_not_imply_equal_decision_observations(self):
        report = self.report([[1, 1]], [[Fraction(1), 1]], [0], [1], [False], [True])
        self.assertTrue(report["numeric"]["all_agree"])
        self.assertEqual(report["numeric"]["mean_absolute_error"], [0, 1])
        self.assertFalse(report["routes"]["all_agree"])
        self.assertFalse(report["stops"]["all_agree"])

    def test_agreement_denominators_are_separate_and_complete(self):
        report = self.report([[0, -1], [2, 3]], [[0, -1], [2, 4]],
                             [0, 1], [0, 2], [False, True], [False, True])
        self.assertEqual(report["numeric"]["count"], 4)
        self.assertEqual(report["numeric"]["matches"], 3)
        self.assertEqual(report["numeric"]["mean_absolute_error"], [1, 4])
        self.assertEqual(report["routes"]["count"], 2)
        self.assertEqual(report["routes"]["matches"], 1)
        self.assertEqual(report["routes"]["agreement_fraction"], [1, 2])
        self.assertEqual(report["stops"]["matches"], 2)

    def test_float_bool_and_mismatched_observations_are_rejected(self):
        for value in (True, 0.5, float("nan"), float("inf"), "0"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "BEHAVIOR_NUMBER"):
                self.report([[value]], [[0]])
        for reference, candidate in (([], []), ([[0]], []), ([[0]], [[0, 1]]),
                                     ([[0], [1, 2]], [[0], [1]]), ([[0]] * 65, [[0]] * 65)):
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                self.report(reference, candidate)
        for route in (True, 1.0, Fraction(1), -1, 3):
            with self.subTest(route=route), self.assertRaisesRegex(ValueError, "BEHAVIOR_ROUTES"):
                self.report([[0]], [[0]], reference_routes=[route])
        for stop in (0, 1, "false", None):
            with self.subTest(stop=stop), self.assertRaisesRegex(ValueError, "BEHAVIOR_STOPS"):
                self.report([[0]], [[0]], reference_stops=[stop])
        with self.assertRaisesRegex(ValueError, "BEHAVIOR_ROUTES"):
            self.report([[0]], [[0]], reference_routes=[])
        with self.assertRaisesRegex(ValueError, "BEHAVIOR_STOPS"):
            self.report([[0]], [[0]], candidate_stops=[])


if __name__ == "__main__":
    unittest.main(verbosity=2)
