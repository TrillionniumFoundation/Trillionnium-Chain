"""Pinned receipt-origin tests; synthetic data, no physical attestation."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import four_propositions_w1_v2 as w1
import test_four_propositions_w1_v2 as w1_fixtures
import w1_execution_receipt_bridge_v1 as bridge
import work_oracle as oracle

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
PUBLIC = PRIVATE.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
SOURCE = {"commit": "11" * 20, "tree": "22" * 20}
BINARY = "33" * 32
COMMAND = "44" * 32
ENVIRONMENT = "55" * 32


def sign(receipt):
    body = dict(receipt)
    body.pop("signature", None)
    receipt["signature"] = PRIVATE.sign(
        bridge.SIGNING_DOMAIN + bridge.canonical(body)).hex()


def repin(value, pins):
    sign(value["receipt"])
    pins["input_sha256"] = bridge.sha(value)


def fixture(relation):
    w1_input, w1_pins = w1_fixtures.fixture(relation, utility=False)
    w1_view = w1.project(w1_input, w1_pins, source_root=ROOT)
    receipt = dict(
        schema=bridge.RECEIPT_SCHEMA,
        source_before=dict(SOURCE),
        source_after=dict(SOURCE),
        binary_before_sha256=BINARY,
        binary_after_sha256=BINARY,
        command_sha256=COMMAND,
        environment_sha256=ENVIRONMENT,
        relation={
            name: w1_view["relation"]["statement"][name]
            for name in ("challenge", "target", "task")
        } | {"proof_sha256": w1_view["relation"]["proof_sha256"]},
        completed=True,
        exit_code=0,
        result=dict(
            ticket=w1_view["relation"]["ticket"],
            product_bytes_sha256=w1_view["relation"]["product_bytes_sha256"],
            output_content=w1_view["derived_binding"]["output_content"],
            qualified_work=w1_view["derived_binding"]["qualified_work"],
            w1_view_sha256=w1.sha(w1_view),
        ),
        signer_public_key=PUBLIC,
        signature="00" * 64,
    )
    value = dict(schema=bridge.INPUT_SCHEMA, w1_input=w1_input,
                 receipt=receipt)
    pins = dict(
        schema=bridge.PIN_SCHEMA,
        input_sha256="00" * 32,
        w1_pins=w1_pins,
        expected_source=dict(SOURCE),
        expected_binary_sha256=BINARY,
        expected_command_sha256=COMMAND,
        expected_environment_sha256=ENVIRONMENT,
        signer_public_key=PUBLIC,
    )
    repin(value, pins)
    return value, pins


def project(value, pins):
    return bridge.project(value, pins, source_root=ROOT)


class W1ExecutionReceiptBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        a = [int(i // oracle.N == i % oracle.N)
             for i in range(oracle.CELLS)]
        b = [(i * 17 + 3) % oracle.Q for i in range(oracle.CELLS)]
        challenge = b"\x07" * 32
        proof = oracle.prove(challenge, a, b)
        cls.relation = dict(
            challenge=challenge.hex(),
            target="ff" * 32,
            task=oracle.task_id(a, b).hex(),
            proof_hex=proof.hex(),
        )

    def test_signed_receipt_binds_exact_replayed_w1_view(self):
        result = project(*fixture(self.relation))
        self.assertTrue(result["receipt_signature_verified"])
        self.assertTrue(result["execution_receipt_origin_authenticated"])
        self.assertTrue(result["execution_receipt_statement_binding_verified"])
        self.assertTrue(result["execution_receipt_source_identity_pinned"])
        self.assertTrue(result["execution_receipt_binary_digest_pinned"])
        self.assertEqual(result["source_identity"], SOURCE)
        self.assertEqual(result["binary_sha256"], BINARY)
        self.assertEqual(result["original_w1_view"]["relation"]["status"],
                         "VERIFIED_SUPPLIED_W1_RELATION")

    def test_receipt_authentication_grants_no_physical_or_external_claim(self):
        result = project(*fixture(self.relation))
        for name in (
            "execution_source_provenance_authenticated",
            "physical_execution_authenticated",
            "native_header_statement_authenticated",
            "native_admission_verified",
            "cross_proposition_semantic_binding_authenticated",
            "real_customer_authenticity_verified",
            "independent_net_benefit_verified",
            "signer_independence_verified",
        ):
            self.assertFalse(result[name], name)
        self.assertIsNone(result["all_algorithm_cost_bound"])
        self.assertFalse(any(result["authority"].values()))
        original = result["original_w1_view"]["original_accounting_view"]
        self.assertTrue(all(not row["proven"]
                            for row in original["propositions"].values()))

    def test_signature_and_signer_are_independently_pinned(self):
        value, pins = fixture(self.relation)
        value["receipt"]["signature"] = "00" * 64
        pins["input_sha256"] = bridge.sha(value)
        with self.assertRaisesRegex(ValueError, "W1_RECEIPT_SIGNATURE"):
            project(value, pins)

        value, pins = fixture(self.relation)
        other = Ed25519PrivateKey.generate()
        value["receipt"]["signer_public_key"] = other.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw).hex()
        body = dict(value["receipt"])
        body.pop("signature")
        value["receipt"]["signature"] = other.sign(
            bridge.SIGNING_DOMAIN + bridge.canonical(body)).hex()
        pins["input_sha256"] = bridge.sha(value)
        with self.assertRaisesRegex(ValueError, "W1_RECEIPT_SIGNER_PIN"):
            project(value, pins)

    def test_producer_repin_cannot_change_reviewed_source_or_binary(self):
        for field in ("source", "binary"):
            value, pins = fixture(self.relation)
            if field == "source":
                changed = {"commit": "aa" * 20, "tree": "bb" * 20}
                value["receipt"]["source_before"] = changed
                value["receipt"]["source_after"] = changed
            else:
                value["receipt"]["binary_before_sha256"] = "aa" * 32
                value["receipt"]["binary_after_sha256"] = "aa" * 32
            repin(value, pins)
            with self.subTest(field=field), self.assertRaisesRegex(
                    ValueError, "W1_RECEIPT_(SOURCE|BINARY)_PIN"):
                project(value, pins)

    def test_before_after_drift_refuses_even_with_fresh_signature(self):
        for field, expected in (("source_after", "SOURCE_CHANGED"),
                                ("binary_after_sha256", "BINARY_CHANGED")):
            value, pins = fixture(self.relation)
            if field == "source_after":
                value["receipt"][field] = {
                    "commit": "aa" * 20, "tree": "bb" * 20}
            else:
                value["receipt"][field] = "aa" * 32
            repin(value, pins)
            with self.subTest(field=field), self.assertRaisesRegex(
                    ValueError, "W1_RECEIPT_" + expected):
                project(value, pins)

    def test_signed_statement_and_result_tampering_refuse(self):
        cases = (
            ("relation", "proof_sha256", "aa" * 32, "RELATION_BINDING"),
            ("result", "output_content", "aa" * 32, "RESULT_BINDING"),
            ("result", "w1_view_sha256", "aa" * 32, "RESULT_BINDING"),
        )
        for container, field, changed, error in cases:
            value, pins = fixture(self.relation)
            value["receipt"][container][field] = changed
            repin(value, pins)
            with self.subTest(field=field), self.assertRaisesRegex(
                    ValueError, "W1_RECEIPT_" + error):
                project(value, pins)

    def test_incomplete_or_failed_process_cannot_authenticate(self):
        for field, changed in (("completed", False), ("exit_code", 1)):
            value, pins = fixture(self.relation)
            value["receipt"][field] = changed
            repin(value, pins)
            with self.subTest(field=field), self.assertRaisesRegex(
                    ValueError, "W1_RECEIPT_PROCESS_RESULT"):
                project(value, pins)

    def test_unknown_fields_and_json_aliases_refuse(self):
        for place in ("input", "receipt", "pins"):
            value, pins = fixture(self.relation)
            target = (value if place == "input" else
                      value["receipt"] if place == "receipt" else pins)
            target["production_activation"] = True
            if place != "pins":
                repin(value, pins)
            with self.subTest(place=place), self.assertRaisesRegex(
                    ValueError, "W1_RECEIPT_FIELDS"):
                project(value, pins)
        for raw in (b'{"a":1,"a":2}', b'{"a":1.0}',
                    b'{"a":NaN}', b'[]' * (2 * 1024 * 1024 + 1)):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                bridge.loads(raw)

    def test_v2_reader_source_drift_refuses_before_projection(self):
        value, pins = fixture(self.relation)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "formal/pon-nakamoto-v1/four_propositions_w1_v2.py"
            path.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / path.relative_to(root), path)
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError,
                                        "W1_RECEIPT_SOURCE_BYTES"):
                bridge.project(value, pins, source_root=root)

    def test_cli_round_trip_and_changed_report_refusal(self):
        value, pins = fixture(self.relation)
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "input.json").write_bytes(bridge.canonical(value))
            (folder / "pins.json").write_bytes(bridge.canonical(pins))
            command = [
                sys.executable, "-B", str(Path(bridge.__file__)),
                "--input", str(folder / "input.json"),
                "--pins", str(folder / "pins.json"),
                "--source-root", str(ROOT),
            ]
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            result = subprocess.run(
                command, capture_output=True, timeout=30, env=env)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            report = json.loads(result.stdout)
            self.assertEqual(report, project(value, pins))
            report["physical_execution_authenticated"] = True
            (folder / "view.json").write_bytes(bridge.canonical(report))
            refused = subprocess.run(
                command + ["--check-view", str(folder / "view.json")],
                capture_output=True, timeout=30, env=env)
            self.assertEqual(refused.returncode, 2, refused.stderr.decode())
            self.assertEqual(refused.stdout, b"")
            self.assertIn(b"W1_RECEIPT_VIEW_MISMATCH", refused.stderr)


if __name__ == "__main__":
    unittest.main()
