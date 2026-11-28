"""Synthetic same-candidate reference computations and strict refusal controls."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import pft_candidate_readback as identity
import pft_reference_consumption as consumer
import test_pft_normal_equation_readback as normal_fixtures

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "evidence/pft-reference-consumption-20261128"
NORMAL = ROOT / "evidence/pft-normal-equation-readback-20261128"
OBSERVATIONS = []


def tearDownModule():
    path = os.environ.get("TRNM_PFT_REFERENCE_CONTROL_RECORDS")
    if path:
        with Path(path).open("xb") as output:
            output.write(identity.canonical(OBSERVATIONS) + b"\n")


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.candidate = (NORMAL / "SYNTHETIC_CANDIDATE.json").read_bytes()
        self.bundle = (NORMAL / "SYNTHETIC_CONTRIBUTIONS.json").read_bytes()
        self.normal = (NORMAL / "EXPECTED.json").read_bytes()
        self.features = (CAPTURE / "SYNTHETIC_FEATURES.json").read_bytes()
        self.expected = identity.decode((CAPTURE / "EXPECTED.json").read_bytes())
        self.feature_value = identity.decode(self.features)
        self.fixture = normal_fixtures.NormalEquationTests()
        self.fixture.setUp()

    def observe(self, *args):
        record = dict(test=self.id(), input_sha256=[identity.sha(raw) for raw in args[:4]])
        try:
            result = consumer.consume_reference(*args)
            record["receipt"] = result
            return result
        except Exception as error:
            record.update(error_type=type(error).__name__, error_code=str(error))
            raise
        finally:
            OBSERVATIONS.append(record)

    def arguments(self, features=None, candidate_case=None):
        candidate, bundle, normal = self.candidate, self.bundle, self.normal
        value = copy.deepcopy(self.feature_value if features is None else features)
        if candidate_case is not None:
            candidate, bundle, expected_normal = candidate_case
            normal = identity.canonical(expected_normal)
            c = identity.decode(candidate)
            value["contract_sha256"] = c["contract_sha256"]
            for name in ("feature_program_sha256", "normalization_sha256", "time_semantics_sha256"):
                value[name] = c["contract"][name]
        raw = identity.canonical(value)
        expected = dict(self.expected, normal_expectations_sha256=identity.sha(normal),
                        feature_input_sha256=identity.sha(raw))
        return candidate, bundle, normal, raw, expected

    def test_profile_is_the_precommitted_exact_profile(self):
        raw = (CAPTURE / "PROTOCOL.json").read_bytes()
        self.assertEqual(identity.sha(raw), consumer.PROTOCOL_SHA256)
        profile = identity.decode(raw)
        self.assertEqual(set(profile["feature_fields"]), consumer.FEATURE_FIELDS)
        self.assertEqual(set(profile["expectations_fields"]), consumer.EXPECTED_FIELDS)
        self.assertEqual(profile["max_rows"], consumer.MAX_ROWS)
        self.assertEqual(profile["max_feature_elements"], consumer.MAX_FEATURE_ELEMENTS)
        self.assertEqual(profile["max_feature_input_bytes"], consumer.MAX_FEATURE_BYTES)

    def test_hand_computed_outputs_and_false_authority(self):
        result = self.observe(self.candidate, self.bundle, self.normal, self.features, self.expected)
        self.assertEqual(result["prediction"], [[1., 2.], [1., -1.], [-1., 7.]])
        self.assertTrue(result["same_candidate_reference_inference_computed"])
        self.assertEqual(result["candidate_sha256"], identity.sha(self.candidate))
        self.assertEqual(result["prediction_shape"], [3, 2])
        for name in consumer.FALSE_CLAIMS:
            self.assertIs(result[name], False, name)

    def test_fsum_keeps_a_real_cancellation_term(self):
        candidate, packets = copy.deepcopy(self.fixture.candidate), copy.deepcopy(self.fixture.packets)
        candidate["contract"].update(dimension=3, outputs=1)
        candidate.update(weight_shape=[3, 1], weight=[[1e16], [1.], [-1e16]])
        contract = identity.sha(identity.canonical(candidate["contract"]))
        for index, packet in enumerate(packets):
            packet["body"].update(contract_sha256=contract,
                gram=[[1. if i == j else 0. for j in range(3)] for i in range(3)],
                rhs=[[2.5e16], [2.5], [-2.5e16]] if index == 0 else [[0.], [0.], [0.]], yty=[[1e34]])
        case = self.fixture.rebound(candidate=candidate, packets=packets)
        value = dict(self.feature_value, features=[[1., 1., 1.]], row_ids=self.feature_value["row_ids"][:1])
        self.assertEqual(self.observe(*self.arguments(value, case))["prediction"], [[1.]])

    def test_rehashed_wrong_weight_retains_numeric_refusal_without_inference(self):
        self.fixture.candidate["weight"][0][0] += .1
        result = self.observe(*self.arguments(candidate_case=self.fixture.rebound()))
        self.assertEqual(result["status"], "REFUSED_NORMAL_EQUATION_INCONSISTENCY")
        self.assertFalse(result["same_candidate_reference_inference_computed"])
        self.assertNotIn("prediction", result)
        self.assertGreater(result["normal_equation_observation"]["max_scaled_backward_error"], 1e-10)

    def test_independent_raw_pins_refuse_changed_inputs(self):
        for index in (0, 2, 3):
            args = [self.candidate, self.bundle, self.normal, self.features, self.expected]
            args[index] += b" "
            with self.subTest(input=index), self.assertRaises(ValueError):
                self.observe(*args)

    def test_other_contract_or_feature_semantics_refuse(self):
        for key in ("contract_sha256", "feature_program_sha256", "normalization_sha256", "time_semantics_sha256"):
            value = dict(self.feature_value, **{key: "a" * 64})
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, "REFERENCE_(CONTRACT|FEATURE_SEMANTICS)"):
                self.observe(*self.arguments(value))

    def test_request_id_hard_type_and_matching_scope(self):
        for value in (True, 7, "A" * 64, "a" * 63, "a" * 64):
            args = list(self.arguments())
            args[-1]["request_id"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.observe(*args)

    def test_exact_fields_duplicate_json_and_other_schemas_refuse(self):
        for field in ("extra", "schema"):
            args = list(self.arguments())
            if field == "extra":
                args[-1]["extra"] = 0
            else:
                del args[-1][field]
            with self.subTest(expected=field), self.assertRaisesRegex(ValueError, "EXPECTED_FIELDS"):
                self.observe(*args)
        for value in (dict(self.feature_value, extra=0), dict(self.feature_value, schema="hepta.experimental-model.v1"),
                      dict(self.feature_value, model_family="pon-cell-stateful-native-int257-v1")):
            with self.subTest(feature=value.get("schema")), self.assertRaises(ValueError):
                self.observe(*self.arguments(value))
        raw = self.features.replace(b'"schema":', b'"schema":"duplicate","schema":', 1)
        with self.assertRaisesRegex(ValueError, "DUPLICATE_KEY"):
            self.observe(self.candidate, self.bundle, self.normal, raw,
                         dict(self.expected, feature_input_sha256=identity.sha(raw)))

    def test_dimensions_duplicate_rows_and_nonfinite_values_refuse(self):
        variants = [dict(self.feature_value, features=[[1.]]),
                    dict(self.feature_value, row_ids=[self.feature_value["row_ids"][0]] * 3)]
        for number in (True, 5e-324, 1e308):
            value = copy.deepcopy(self.feature_value)
            value["features"][0][0] = number
            variants.append(value)
        for index, value in enumerate(variants):
            with self.subTest(input=index), self.assertRaises(ValueError):
                self.observe(*self.arguments(value))
        value = copy.deepcopy(self.feature_value)
        value["features"][0][0] = float("nan")
        raw = json.dumps(value, allow_nan=True).encode()
        with self.assertRaisesRegex(ValueError, "NONFINITE_JSON"):
            self.observe(self.candidate, self.bundle, self.normal, raw,
                         dict(self.expected, feature_input_sha256=identity.sha(raw)))

    def test_nonzero_product_underflow_refuses(self):
        case = self.fixture.scalar_case([1.], [1e-200], 5e-201)
        value = dict(self.feature_value, features=[[1e-200]], row_ids=self.feature_value["row_ids"][:1])
        with self.assertRaisesRegex(ValueError, "PRODUCT_UNDERFLOW"):
            self.observe(*self.arguments(value, case))

    def test_row_and_byte_limits_refuse(self):
        value = dict(self.feature_value, features=[[0., 0.]] * (consumer.MAX_ROWS + 1))
        with self.assertRaisesRegex(ValueError, "ROW_LIMIT"):
            self.observe(*self.arguments(value))
        with self.assertRaisesRegex(ValueError, "FEATURE_LIMIT"):
            self.observe(self.candidate, self.bundle, self.normal, b" " * (consumer.MAX_FEATURE_BYTES + 1), self.expected)

    def test_real_cli_output_refusals_and_receipt_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in
                     ("candidate", "bundle", "normal", "features", "expected", "receipt")]
            for path, raw in zip(paths, (self.candidate, self.bundle, self.normal, self.features,
                                        identity.canonical(self.expected))):
                path.write_bytes(raw)
            command = [sys.executable, "-B", consumer.__file__, *(str(p) for p in paths)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            original = paths[-1].read_bytes()
            receipt = identity.decode(original)
            self.assertEqual(receipt["prediction"], [[1., 2.], [1., -1.], [-1., 7.]])
            OBSERVATIONS.append(dict(test=self.id(), receipt=receipt, cli_returncode=result.returncode))
            collision = subprocess.run(command, capture_output=True, timeout=10)
            self.assertNotEqual(collision.returncode, 0)
            self.assertEqual(paths[-1].read_bytes(), original)
            OBSERVATIONS.append(dict(test=self.id(), collision_returncode=collision.returncode,
                                     receipt_unchanged_sha256=identity.sha(original)))
            paths[3].write_bytes(b"different input")
            paths[-1] = Path(directory) / "refusal"
            result = subprocess.run([sys.executable, "-B", consumer.__file__, *(str(p) for p in paths)],
                                    capture_output=True, text=True, timeout=10)
            receipt = identity.decode(paths[-1].read_bytes())
            self.assertEqual(result.returncode, 2)
            self.assertEqual(receipt["error_code"], "PFT_REFERENCE_FEATURE_PIN")
            OBSERVATIONS.append(dict(test=self.id(), receipt=receipt, cli_returncode=result.returncode))


if __name__ == "__main__":
    unittest.main()
