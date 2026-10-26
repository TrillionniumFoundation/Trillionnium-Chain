#!/usr/bin/env python3
"""Semantic and evidence-binding controls; synthetic timing is never execution evidence."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import read_w1_task_product_research as reader
import run_w1_task_product_research as runner


class RegistrationControls(unittest.TestCase):
    def setUp(self):
        self.plan = json.loads((ROOT / "formal/pon-nakamoto-v1/experiments/w1_task_product_plan_v1.json").read_text())

    def test_registration_rejects_order_seed_omission_and_timeout_changes(self):
        for change in (lambda p: p["jobs"].reverse(), lambda p: p["jobs"].pop(),
                       lambda p: p["jobs"][0]["args"].__setitem__(1, "8103"),
                       lambda p: p["jobs"][0].__setitem__("timeout_seconds", 180.0)):
            value = copy.deepcopy(self.plan)
            change(value)
            with self.assertRaises(ValueError):
                runner.validate_plan(value)
        self.assertEqual(len(runner.validate_plan(self.plan)), 2)

    def test_authority_or_clock_changes_are_not_accepted(self):
        for key, value in (("production_activation", True), ("hardware_attested", 0),
                           ("node_admission_measured", True), ("operation_clock", "process-cpu"),
                           ("collection_output_limit_bytes", float(runner.OUTPUT_LIMIT))):
            plan = copy.deepcopy(self.plan)
            plan[key] = value
            with self.assertRaises(ValueError):
                runner.validate_plan(plan)

    def test_wrong_external_manifest_pin_precedes_decode_and_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "campaign.json").write_text("not-json")
            with patch.object(reader, "read_raw", side_effect=AssertionError("must not replay")):
                with self.assertRaisesRegex(ValueError, "EXTERNAL_MANIFEST_PIN"):
                    reader.read_bundle(folder, expected_head="1" * 40, expected_tree="2" * 40,
                                       expected_plan_sha256="3" * 64, expected_binary_sha256="4" * 64,
                                       expected_manifest_sha256="5" * 64)

    def test_duplicate_and_nonfinite_json_are_rejected(self):
        for value in ('{"seed":8101,"seed":8102}', '{"wall_ns":NaN}'):
            with self.assertRaises(ValueError):
                runner.decode(value)


class RelationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        a, b = reader.material(8101, "zero")
        task = reader.oracle.task_id(a, b)
        challenge = reader.H("task-product-facts-challenge-v1", struct.pack("<Q", 8101),
                             b"main-zero", struct.pack("<Q", 0), task)
        proof = reader.oracle.prove(challenge, a, b)
        cls.row = dict(type="case", id="main-zero-0", group="main-zero", family="zero", ordinal=0,
                       challenge=challenge.hex(), task=task.hex(), target=reader.TARGET.hex(),
                       proof_hex=proof.hex(), proof_sha256=hashlib.sha256(proof).hexdigest(),
                       material_wall_ns=1, prove_wall_ns=1, reference_wall_ns=1)
        cls.case = reader.verify_case(cls.row, 8101, "main-zero", "zero", 0)

    def call(self, arm="facts", warm=True):
        return dict(type="verify", case_id=self.case["id"], arm=arm, order=0, wall_ns=10,
                    ticket=self.case["ticket"], product_sha256=self.case["product_sha256"],
                    progress=dict(before_replay=1, noise=self.case["noise_calls"], matrix_rows_before_product=128,
                                  transcript_tiles=512, before_product=1,
                                  matrix_rows_after_product=0 if warm else 200, before_verified_work=1),
                    observation=dict(lookup_probes=1, lookup_contended=False, exact_inputs_found=warm,
                                     product_reused=warm, transcript_entered=True, transcript_completed=True,
                                     product_reconstruction_entered=not warm, product_reconstruction_completed=not warm,
                                     publication_probes=0 if warm else 1, publication="none" if warm else "stored"))

    def test_canonical_scalar_case_accepts_and_seed_alias_does_not(self):
        self.assertEqual(reader.verify_case(self.row, 8101, "main-zero", "zero", 0), self.case)
        with self.assertRaisesRegex(ValueError, "REGISTERED_STATEMENT"):
            reader.verify_case(self.row, 8102, "main-zero", "zero", 0)

    def test_rehashed_wrong_product_still_fails_complete_relation(self):
        row = dict(self.row)
        proof = bytearray.fromhex(row["proof_hex"])
        proof[4 + 2 * 4096 * 4] = 1
        row.update(proof_hex=proof.hex(), proof_sha256=hashlib.sha256(proof).hexdigest())
        with self.assertRaisesRegex(ValueError, "PRODUCT"):
            reader.verify_case(row, 8101, "main-zero", "zero", 0)

    def test_rehashed_wrong_trace_still_fails_complete_relation(self):
        row = dict(self.row)
        proof = bytearray.fromhex(row["proof_hex"])
        proof[-1] ^= 1
        row.update(proof_hex=proof.hex(), proof_sha256=hashlib.sha256(proof).hexdigest())
        with self.assertRaisesRegex(ValueError, "TRANSCRIPT"):
            reader.verify_case(row, 8101, "main-zero", "zero", 0)

    def test_material_label_and_noncanonical_bytes_are_not_authority(self):
        row = dict(self.row, family="identity")
        with self.assertRaisesRegex(ValueError, "REGISTERED_STATEMENT|REGISTERED_MATERIAL"):
            reader.verify_case(row, 8101, "main-zero", "identity", 0)
        row = dict(self.row)
        proof = bytearray.fromhex(row["proof_hex"])
        proof[4:8] = struct.pack("<I", reader.oracle.Q)
        row.update(proof_hex=proof.hex(), proof_sha256=hashlib.sha256(proof).hexdigest())
        with self.assertRaisesRegex(ValueError, "REGISTERED_MATERIAL"):
            reader.verify_case(row, 8101, "main-zero", "zero", 0)

    def test_instrumented_warm_call_requires_all_fresh_tiles(self):
        row = self.call()
        self.assertTrue(reader.verify_call(row, self.case, "facts", 0, True, 1)["product_reused"])
        row["progress"]["transcript_tiles"] = 0
        with self.assertRaisesRegex(ValueError, "COMPLETE_FRESH_TRANSCRIPT"):
            reader.verify_call(row, self.case, "facts", 0, True, 1)

    def test_wrong_cold_warm_or_publication_claim_rejected(self):
        for field, value in (("product_reused", False), ("publication", "stored"),
                             ("transcript_completed", False), ("lookup_contended", True)):
            row = self.call()
            row["observation"][field] = value
            with self.assertRaisesRegex(ValueError, "EXACT_CACHE_PATH"):
                reader.verify_call(row, self.case, "facts", 0, True, 1)

    def test_integer_aliases_or_wrong_arm_order_rejected(self):
        for field, value in (("wall_ns", True), ("order", False), ("arm", "raw")):
            row = self.call()
            row[field] = value
            with self.assertRaises(ValueError):
                reader.verify_call(row, self.case, "facts", 0, True, 1)

    def test_boolean_progress_and_verdict_substitution_rejected(self):
        row = self.call()
        row["progress"]["before_product"] = True
        with self.assertRaisesRegex(ValueError, "COMPLETE_FRESH_TRANSCRIPT"):
            reader.verify_call(row, self.case, "facts", 0, True, 1)
        row = self.call()
        row["ticket"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "VERIFIED_OUTPUT"):
            reader.verify_call(row, self.case, "facts", 0, True, 1)

    def test_incomplete_raw_file_has_no_successful_readback(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "partial.stdout"
            path.write_text(json.dumps(dict(type="start")) + "\n")
            with self.assertRaisesRegex(ValueError, "COMPLETE_ROW_SET"):
                reader.read_raw(path, 8101)

    def test_zero_time_is_not_infinite_gain_and_regression_is_retained(self):
        self.assertIsNone(reader.fraction(1, 0))
        self.assertEqual(reader.fraction(10, 20), dict(numerator=1, denominator=2, decimal=0.5))


if __name__ == "__main__":
    unittest.main()
