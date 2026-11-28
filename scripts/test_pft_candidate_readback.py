"""Public synthetic controls for research identity readback, never adoption."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

import pft_candidate_readback as pft

CAPTURE = Path(__file__).resolve().parents[1] / "evidence/pft-candidate-readback-20261128"


class PftCandidateTests(unittest.TestCase):
    def setUp(self):
        self.raw = (CAPTURE / "SYNTHETIC_CANDIDATE.json").read_bytes()
        self.candidate = json.loads(self.raw)
        self.expected = json.loads((CAPTURE / "EXPECTED.json").read_bytes())

    def altered(self, candidate, *, update=None):
        raw = pft.canonical(candidate)
        expected = dict(self.expected, candidate_sha256=pft.sha(raw))
        if update:
            expected.update(update)
        return pft.review_candidate(raw, expected)

    def test_exact_synthetic_candidate_matches_without_authority(self):
        result = pft.review_candidate(self.raw, self.expected)
        self.assertEqual(result["status"], "STRUCTURALLY_CONSISTENT_UNAUTHENTICATED")
        self.assertEqual(result["weight_shape"], [2, 2])
        self.assertEqual((result["revision"], result["sample_count_declared"]), (2, 2))
        self.assertTrue(result["candidate_pin_tuple_matches"])
        for key, value in result.items():
            if key.endswith(("verified", "authenticated", "authorized", "compatible")) or key.startswith("authorizes_"):
                self.assertIs(value, False, key)
        self.assertFalse(result["execution_authority"])
        self.assertFalse(result["production_activation"])

    def test_each_independent_pin_is_required(self):
        for key in ("candidate_sha256", "contract_sha256", "head", "weight_sha256", "parent_model_sha256"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                pft.review_candidate(self.raw, dict(self.expected, **{key: "f" * 64}))
        with self.assertRaisesRegex(ValueError, "EXPECTED_FIELDS"):
            pft.review_candidate(self.raw, {})

    def test_exact_candidate_bytes_do_not_accept_whitespace_rewrite(self):
        with self.assertRaisesRegex(ValueError, "CANDIDATE_PIN"):
            pft.review_candidate(self.raw + b" ", self.expected)

    def test_recomputed_candidate_digest_cannot_hide_different_weight(self):
        self.candidate["weight"][0][0] += .1
        with self.assertRaisesRegex(ValueError, "WEIGHT_PIN"):
            self.altered(self.candidate)

    def test_fixed_ieee754_little_endian_row_order_and_signed_zero(self):
        candidate = copy.deepcopy(self.candidate)
        candidate["contract"].update(dimension=2, outputs=2)
        candidate["contract_canonical_json"] = pft.canonical(candidate["contract"]).decode()
        candidate["contract_sha256"] = pft.sha(candidate["contract_canonical_json"].encode())
        head = json.loads(candidate["head_material_canonical_json"])
        head["contract_sha256"] = candidate["contract_sha256"]
        candidate["head_material_canonical_json"] = pft.canonical(head).decode()
        candidate["head"] = pft.sha(candidate["head_material_canonical_json"].encode())
        candidate.update(weight_shape=[2, 2], weight=[[1.0, -2.5], [0.0, -0.0]])
        bits = bytes.fromhex("000000000000f03f00000000000004c000000000000000000000000000000080")
        candidate["weight_sha256"] = hashlib.sha256(bits).hexdigest()
        update = {key: candidate[key] for key in ("contract_sha256", "head", "weight_sha256")}
        self.assertTrue(self.altered(candidate, update=update)["candidate_pin_tuple_matches"])
        candidate["weight"][1][1] = 0.0
        with self.assertRaisesRegex(ValueError, "WEIGHT_PIN"):
            self.altered(candidate, update=update)

    def test_contract_object_must_match_its_original_canonical_text(self):
        self.candidate["contract"]["epoch"] += 1
        with self.assertRaisesRegex(ValueError, "CONTRACT_TEXT_MISMATCH"):
            self.altered(self.candidate)

    def test_contract_epoch_or_feature_semantics_cannot_be_self_retargeted(self):
        for key in ("feature_program_sha256", "normalization_sha256", "objective_sha256", "time_semantics_sha256"):
            candidate = copy.deepcopy(self.candidate)
            candidate["contract"][key] = "a" * 64
            candidate["contract_canonical_json"] = pft.canonical(candidate["contract"]).decode()
            candidate["contract_sha256"] = pft.sha(candidate["contract_canonical_json"].encode())
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "CONTRACT_PIN"):
                self.altered(candidate)

    def test_noncanonical_or_duplicate_nested_contract_refuses(self):
        for text in (self.candidate["contract_canonical_json"] + " ",
                     self.candidate["contract_canonical_json"].replace("{", '{"epoch":0,', 1)):
            candidate = dict(self.candidate, contract_canonical_json=text)
            with self.subTest(text=text[:30]), self.assertRaises(ValueError):
                self.altered(candidate)

    def test_duplicate_root_key_is_not_silently_last_value_wins(self):
        raw = self.raw.replace(b"{", b'{"schema":"pft-online-candidate-v1",', 1)
        with self.assertRaisesRegex(ValueError, "DUPLICATE_KEY"):
            pft.review_candidate(raw, dict(self.expected, candidate_sha256=pft.sha(raw)))

    def test_head_revision_order_duplicates_and_contract_are_checked(self):
        original = json.loads(self.candidate["head_material_canonical_json"])
        variants = []
        for batches in (list(reversed(original["batches"])), original["batches"][:-1],
                        [original["batches"][0]] * self.candidate["revision"]):
            variants.append(dict(original, batches=batches))
        variants.append(dict(original, contract_sha256="b" * 64))
        for head in variants:
            candidate = dict(self.candidate, head_material_canonical_json=pft.canonical(head).decode())
            candidate["head"] = pft.sha(candidate["head_material_canonical_json"].encode())
            with self.subTest(head=head), self.assertRaises(ValueError):
                self.altered(candidate, update={"head": candidate["head"]})

    def test_strict_count_shape_and_weight_scalar_types(self):
        for key, value in (("count", True), ("count", 0), ("revision", True), ("revision", 100001),
                           ("weight_shape", [2, True]), ("weight_shape", [2, 3]),
                           ("weight", [[True] * 2] * 2), ("weight", [["0"] * 2] * 2),
                           ("weight", [[0.0]] * 2), ("weight", [])):
            with self.subTest(key=key, value=str(value)[:20]), self.assertRaises(ValueError):
                self.altered(dict(self.candidate, **{key: value}))

    def test_nonfinite_json_and_overflowed_real_refuse(self):
        for value in (float("nan"), float("inf")):
            candidate = copy.deepcopy(self.candidate)
            candidate["weight"][0][0] = value
            raw = json.dumps(candidate).encode()
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "NONFINITE_JSON"):
                pft.review_candidate(raw, dict(self.expected, candidate_sha256=pft.sha(raw)))
        candidate = copy.deepcopy(self.candidate)
        candidate["weight"][0][0] = 10**400
        with self.assertRaisesRegex(ValueError, "PFT_REAL"):
            self.altered(candidate)

    def test_research_contract_limits_and_native_family_substitution_refuse(self):
        for key, value in (("dimension", True), ("dimension", 1025), ("outputs", 33),
                           ("epoch", -1), ("regularizer", 0), ("regularizer", True),
                           ("model_family", "hepta.experimental-model.v1"),
                           ("dtype", "float32"), ("aggregation", "sum")):
            candidate = copy.deepcopy(self.candidate)
            candidate["contract"][key] = value
            candidate["contract_canonical_json"] = pft.canonical(candidate["contract"]).decode()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.altered(candidate)

    def test_extra_authority_field_and_schema_or_encoding_upgrades_refuse(self):
        for changed in (dict(self.candidate, authorizes_native_payment=True),
                        dict(self.candidate, schema="pft-online-candidate-v2"),
                        dict(self.candidate, weight_encoding="float64-be-c-rowmajor")):
            with self.subTest(changed=changed["schema"]), self.assertRaises(ValueError):
                self.altered(changed)
        with self.assertRaisesRegex(ValueError, "EXPECTED_RESEARCH_SCOPE"):
            pft.review_candidate(self.raw, dict(self.expected, model_family="native-int257"))

    def test_bounded_input_and_explicit_cli_expectations(self):
        with self.assertRaisesRegex(ValueError, "BYTE_LIMIT"):
            pft.decode(b" " * 10, maximum=9)
        with self.assertRaisesRegex(ValueError, "BYTE_LIMIT"):
            pft.read_bounded(CAPTURE / "SYNTHETIC_CANDIDATE.json", 1)
        result = subprocess.run([sys.executable, "-B", pft.__file__,
            str(CAPTURE / "SYNTHETIC_CANDIDATE.json"), str(CAPTURE / "EXPECTED.json")],
            capture_output=True, text=True, timeout=10, check=True)
        self.assertEqual(json.loads(result.stdout), pft.review_candidate(self.raw, self.expected))
        self.assertEqual(result.stderr, "")
        missing = subprocess.run([sys.executable, "-B", pft.__file__,
            str(CAPTURE / "SYNTHETIC_CANDIDATE.json")], capture_output=True, timeout=10)
        self.assertNotEqual(missing.returncode, 0)
        self.assertEqual(missing.stdout, b"")


if __name__ == "__main__":
    unittest.main()
