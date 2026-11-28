"""Synthetic arithmetic/refusal controls; no real training or final-test access."""
import copy
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

import pft_candidate_readback as identity
import pft_normal_equation_readback as normal

CAPTURE = Path(__file__).resolve().parents[1] / "evidence/pft-normal-equation-readback-20261128"
OBSERVATIONS = []


def tearDownModule():
    target = os.environ.get("TRNM_PFT_NEQ_CONTROL_RECORDS")
    if target:
        with Path(target).open("xb") as output:
            output.write(identity.canonical(OBSERVATIONS) + b"\n")


class NormalEquationTests(unittest.TestCase):
    def setUp(self):
        self.candidate_raw = (CAPTURE / "SYNTHETIC_CANDIDATE.json").read_bytes()
        self.bundle_raw = (CAPTURE / "SYNTHETIC_CONTRIBUTIONS.json").read_bytes()
        self.expected = identity.decode((CAPTURE / "EXPECTED.json").read_bytes())
        self.candidate, self.packets = identity.decode(self.candidate_raw), identity.decode(self.bundle_raw)

    def observe(self, candidate_raw, bundle_raw, expected):
        record = dict(test=self.id(), candidate_sha256=identity.sha(candidate_raw),
                      contributions_sha256=identity.sha(bundle_raw), expected_sha256=identity.sha(identity.canonical(expected)))
        try:
            result = normal.verify_normal_equations(candidate_raw, bundle_raw, expected)
            record["receipt"] = result
            return result
        except Exception as error:
            record.update(error_type=type(error).__name__, error_code=str(error))
            raise
        finally:
            OBSERVATIONS.append(record)

    def rebound(self, *, candidate=None, packets=None, rebuild_head=True):
        # Controls deliberately re-pin synthetic bad solver outputs: identity
        # alone must not certify the numerical relationship to supplied stats.
        candidate = copy.deepcopy(candidate if candidate is not None else self.candidate)
        packets = copy.deepcopy(packets if packets is not None else self.packets)
        contract = candidate["contract"]
        candidate["contract_canonical_json"] = identity.canonical(contract).decode()
        candidate["contract_sha256"] = identity.sha(candidate["contract_canonical_json"].encode())
        for packet in packets:
            packet["payload_sha256"] = identity.sha(identity.canonical(packet["body"]))
        if rebuild_head:
            material = dict(contract_sha256=candidate["contract_sha256"], batches=sorted(
                [p["body"]["batch_id"], p["payload_sha256"]] for p in packets))
            candidate.update(head_material_canonical_json=identity.canonical(material).decode(),
                             head=identity.sha(identity.canonical(material)), revision=len(packets))
        candidate["weight_sha256"] = identity.sha(b"".join(
            struct.pack("<" + "d" * len(row), *row) for row in candidate["weight"]))
        candidate_raw, bundle_raw = identity.canonical(candidate), identity.canonical(packets)
        expected = copy.deepcopy(self.expected)
        expected["candidate"].update({key: candidate[key] for key in ("contract_sha256", "head", "weight_sha256")})
        expected["candidate"].update(candidate_sha256=identity.sha(candidate_raw),
                                     parent_model_sha256=contract["parent_model_sha256"])
        expected["contributions_sha256"] = identity.sha(bundle_raw)
        return candidate_raw, bundle_raw, expected

    def check(self, **kwargs):
        return self.observe(*self.rebound(**kwargs))

    def scalar_case(self, grams, rhs, weight, regularizer=1.0):
        candidate = copy.deepcopy(self.candidate)
        candidate["contract"].update(dimension=1, outputs=1, regularizer=regularizer)
        digest = identity.sha(identity.canonical(candidate["contract"]))
        packets = []
        for index, (g, h) in enumerate(zip(grams, rhs)):
            body = dict(contract_sha256=digest, batch_id=f"batch-{index}",
                        source_sha256=identity.sha(f"synthetic-source-{index}".encode()),
                        sample_ids=[identity.sha(f"synthetic-sample-{index}".encode())], count=1,
                        gram=[[g]], rhs=[[h]], yty=[[1e32]])
            packets.append(dict(body=body, payload_sha256=identity.sha(identity.canonical(body))))
        candidate.update(weight_shape=[1, 1], weight=[[weight]], count=len(packets))
        return self.rebound(candidate=candidate, packets=packets)

    def test_frozen_profile_digest_constants_and_limits_match(self):
        raw = (CAPTURE / "PROTOCOL.json").read_bytes()
        self.assertEqual(identity.sha(raw), normal.PROTOCOL_SHA256)
        profile = identity.decode(raw)
        for key, value in (("backward_error_limit", normal.BACKWARD_ERROR_LIMIT),
                ("symmetry_limit", normal.SYMMETRY_LIMIT), ("max_bundle_bytes", normal.MAX_BUNDLE_BYTES),
                ("max_packets", normal.MAX_PACKETS), ("max_total_samples", normal.MAX_TOTAL_SAMPLES),
                ("max_numeric_elements", normal.MAX_NUMERIC_ELEMENTS),
                ("max_packet_samples", normal.MAX_PACKET_SAMPLES)):
            self.assertEqual(profile[key], value)

    def test_correct_supplied_statistics_and_one_regularizer(self):
        result = self.observe(self.candidate_raw, self.bundle_raw, self.expected)
        self.assertTrue(result["normal_equations_consistent_with_supplied_bound_statistics"])
        self.assertEqual(result["max_scaled_backward_error"], 0.0)
        self.assertEqual((result["supplied_packets"], result["declared_sample_count"]), (2, 8))
        for key in normal.FALSE_CLAIMS:
            self.assertIs(result[key], False, key)

    def test_rehashed_wrong_weight_is_numerically_refused(self):
        self.candidate["weight"][0][0] += .1
        result = self.check(candidate=self.candidate)
        self.assertFalse(result["normal_equations_consistent_with_supplied_bound_statistics"])
        self.assertGreater(result["max_scaled_backward_error"], normal.BACKWARD_ERROR_LIMIT)

    def test_regularization_per_packet_is_not_the_aggregate_objective(self):
        self.candidate["weight"] = [[3.5 / 4.0, 7.0 / 4.0], [4.5 / 5.0, -4.5 / 5.0]]
        result = self.check(candidate=self.candidate)
        self.assertFalse(result["normal_equations_consistent_with_supplied_bound_statistics"])

    def test_fixed_threshold_preserves_small_error_and_rejects_larger_error(self):
        for delta, consistent in ((1e-11, True), (1e-8, False)):
            candidate = copy.deepcopy(self.candidate)
            candidate["weight"][0][0] += delta
            with self.subTest(delta=delta):
                result = self.check(candidate=candidate)
                self.assertEqual(result["normal_equations_consistent_with_supplied_bound_statistics"], consistent)
                self.assertGreater(result["max_scaled_backward_error"], 0)

    def test_fsum_retains_cancellation_term(self):
        result = self.observe(*self.scalar_case([1., 1., 1.], [1e16, 1., -1e16], .25))
        self.assertEqual(result["max_scaled_backward_error"], 0)

    def test_conditional_equations_do_not_claim_psd_or_global_optimality(self):
        result = self.observe(*self.scalar_case([-2.], [1.], -1.))
        self.assertTrue(result["normal_equations_consistent_with_supplied_bound_statistics"])
        self.assertFalse(result["positive_semidefiniteness_verified"])
        self.assertFalse(result["global_optimality_verified"])

    def test_exact_zero_denominator_has_exact_zero_residual(self):
        result = self.observe(*self.scalar_case([-1.], [0.], 2.))
        self.assertEqual(result["max_scaled_backward_error"], 0)

    def test_duplicate_and_conflicting_batch_ids_both_refuse(self):
        for conflict in (False, True):
            packets = copy.deepcopy(self.packets)
            extra = copy.deepcopy(packets[0])
            if conflict:
                extra["body"]["rhs"][0][0] += 1
            packets.append(extra)
            with self.subTest(conflict=conflict), self.assertRaisesRegex(ValueError, "DUPLICATE_OR_CONFLICTING_BATCH"):
                self.check(packets=packets, rebuild_head=False)

    def test_sample_reuse_within_and_across_batches_refuses(self):
        for same in (False, True):
            packets = copy.deepcopy(self.packets)
            target = packets[0 if same else 1]["body"]
            target["sample_ids"][-1] = packets[0]["body"]["sample_ids"][0]
            target["sample_ids"].sort()
            with self.subTest(within=same), self.assertRaisesRegex(ValueError, "SAMPLE_REUSE"):
                self.check(packets=packets)

    def test_mixed_contract_and_incomplete_head_refuse(self):
        self.packets[1]["body"]["contract_sha256"] = "a" * 64
        with self.assertRaisesRegex(ValueError, "MIXED_CONTRACT"):
            self.check(packets=self.packets)
        with self.assertRaisesRegex(ValueError, "INCOMPLETE_OR_DIFFERENT_HEAD"):
            self.check(packets=self.packets[:1], rebuild_head=False)

    def test_wrong_bundle_payload_and_protocol_pins_refuse(self):
        expected = copy.deepcopy(self.expected)
        expected["contributions_sha256"] = "a" * 64
        with self.assertRaisesRegex(ValueError, "BUNDLE_PIN"):
            self.observe(self.candidate_raw, self.bundle_raw, expected)
        expected = copy.deepcopy(self.expected)
        expected["protocol_sha256"] = "a" * 64
        with self.assertRaisesRegex(ValueError, "EXPECTED_PROFILE"):
            self.observe(self.candidate_raw, self.bundle_raw, expected)
        self.packets[0]["payload_sha256"] = "a" * 64
        raw = identity.canonical(self.packets)
        with self.assertRaisesRegex(ValueError, "PAYLOAD_PIN"):
            self.observe(self.candidate_raw, raw, dict(self.expected, contributions_sha256=identity.sha(raw)))

    def test_asymmetry_dimensions_boolean_and_count_refuse(self):
        mutations = [lambda b: b["gram"][0].__setitem__(1, .1),
                     lambda b: b["yty"][0].__setitem__(1, .1),
                     lambda b: b.__setitem__("rhs", [[0.]]),
                     lambda b: b["gram"][0].__setitem__(0, True),
                     lambda b: b.__setitem__("count", True),
                     lambda b: b.__setitem__("count", 3)]
        for index, mutate in enumerate(mutations):
            packets = copy.deepcopy(self.packets)
            mutate(packets[0]["body"])
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                self.check(packets=packets)

    def test_nan_subnormal_underflow_and_overflow_refuse(self):
        raw = self.bundle_raw.replace(b'"count":4', b'"count":NaN', 1)
        with self.assertRaisesRegex(ValueError, "NONFINITE_JSON"):
            self.observe(self.candidate_raw, raw, dict(self.expected, contributions_sha256=identity.sha(raw)))
        for args in (([1.], [0.], 5e-324, 1.), ([1e-200], [0.], 1e-200, 1e-200),
                     ([1e308, 1e308], [1., 1.], 1., 1.)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.observe(*self.scalar_case(*args))

    def test_byte_and_packet_bounds_refuse_before_matrix_work(self):
        with self.assertRaisesRegex(ValueError, "BUNDLE_LIMIT"):
            self.observe(self.candidate_raw, b" " * (normal.MAX_BUNDLE_BYTES + 1), self.expected)
        raw = identity.canonical([self.packets[0]] * (normal.MAX_PACKETS + 1))
        with self.assertRaisesRegex(ValueError, "PACKET_LIMIT"):
            self.observe(self.candidate_raw, raw, dict(self.expected, contributions_sha256=identity.sha(raw)))

    def test_cli_retains_numeric_failure_and_refusal_without_overwrite(self):
        self.candidate["weight"][0][0] += .1
        candidate, bundle, expected = self.rebound(candidate=self.candidate)
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("candidate", "bundle", "expected", "receipt")]
            for path, raw in zip(paths, (candidate, bundle, identity.canonical(expected))):
                path.write_bytes(raw)
            command = [sys.executable, "-B", normal.__file__, *(str(p) for p in paths)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            receipt = identity.decode(paths[-1].read_bytes())
            self.assertEqual(receipt["status"], "INCONSISTENT_WITH_SUPPLIED_BOUND_STATISTICS")
            OBSERVATIONS.append(dict(test=self.id(), receipt=receipt))
            original = paths[-1].read_bytes()
            collision = subprocess.run(command, capture_output=True, timeout=10)
            self.assertNotEqual(collision.returncode, 0)
            self.assertEqual(paths[-1].read_bytes(), original)
            paths[-1] = Path(directory) / "refusal"
            paths[1].write_bytes(b"invalid original bundle")
            refused = subprocess.run([sys.executable, "-B", normal.__file__, *(str(p) for p in paths)],
                                     capture_output=True, text=True, timeout=10)
            self.assertEqual(refused.returncode, 2)
            receipt = identity.decode(paths[-1].read_bytes())
            self.assertEqual(receipt["error_code"], "NEQ_BUNDLE_PIN")
            self.assertFalse(receipt["normal_equations_consistent_with_supplied_bound_statistics"])
            OBSERVATIONS.append(dict(test=self.id(), receipt=receipt))


if __name__ == "__main__":
    unittest.main()
