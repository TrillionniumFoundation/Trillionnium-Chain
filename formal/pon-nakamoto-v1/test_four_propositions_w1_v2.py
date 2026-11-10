"""Scalar relation/content integration; synthetic matrices, no native qualification."""
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
from unittest.mock import patch

import four_propositions_w1_v2 as bridge
import four_propositions_v1 as legacy
import test_four_propositions_v1 as fixtures
import work_oracle as oracle

ROOT = Path(__file__).resolve().parents[2]


def repin(value, pins):
    fixtures.repin(value["accounting_input"], pins["accounting_pins"])
    pins["input_sha256"] = bridge.sha(value)


def fixture(relation, *, utility=True):
    accounting, accounting_pins = fixtures.fixture(demand=False, utility=False)
    accounting["binding"].update(bridge.derive_binding(relation, source_root=ROOT))
    if utility:
        fixtures.add_utility(accounting)
    value = dict(schema=bridge.INPUT_SCHEMA, accounting_input=accounting,
                 relation=copy.deepcopy(relation))
    pins = dict(schema=bridge.PIN_SCHEMA, input_sha256="0" * 64,
                statement={k: relation[k] for k in ("challenge", "target", "task")},
                proof_sha256=hashlib.sha256(bytes.fromhex(relation["proof_hex"])).hexdigest(),
                accounting_pins=accounting_pins)
    repin(value, pins)
    return value, pins


def project(value, pins):
    return bridge.project(value, pins, source_root=ROOT)


class W1AccountingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = [int(i // oracle.N == i % oracle.N) for i in range(oracle.CELLS)]
        cls.b = [(i * 17 + 3) % oracle.Q for i in range(oracle.CELLS)]
        cls.relations = []
        twice_identity = [2 * x for x in cls.a]
        half_b = [(x * pow(2, -1, oracle.Q)) % oracle.Q for x in cls.b]
        for index, a, b in ((1, cls.a, cls.b), (2, cls.a, cls.b), (1, twice_identity, half_b)):
            challenge = bytes([index]) * 32
            proof = oracle.prove(challenge, a, b)
            cls.relations.append(dict(challenge=challenge.hex(), target="ff" * 32,
                task=oracle.task_id(a, b).hex(), proof_hex=proof.hex()))

    def test_fresh_namespace_exact_vectors(self):
        expected = dict(inputs="a86210e188f3175935c0889abe476264ad0e7d4b3c0719931279a78915e1fd97",
            work_profile="pon-matmul-transcript-64-v1",
            task_content="7c2ae2ba8c038735be49e31a2f9d1017dfdcfef35b71004bab73963cec989c85",
            output_spec="fa5b3a1cec58999d95236a982eb55524b38e10b2e7735d2f1800e58273e305fc",
            output_content="22dc7e05e41d8ee1e49c57e06add5df37e971276c894618e31b30a973e4ed811")
        qualified = ["a195a4e643f9a34f8f68dcc0358a85f7c049e2b918974b6fd13035ccd8edb595",
                     "3d41a72c89f7b54680150d1446b02458a2fb2dc83bb5f956d124f61f3e99c7f2"]
        for relation, work in zip(self.relations, qualified):
            result = project(*fixture(relation, utility=False))
            self.assertEqual(result["derived_binding"], {**expected, "qualified_work": work})
            self.assertEqual(result["unique_output_key"],
                             "b33d660478a3c0e0951880943955e7aff610c3f02c2d83ff92b2364775ba3e64")

    def test_real_scalar_relation_is_replayed_before_accounting(self):
        value, pins = fixture(self.relations[0])
        with patch.object(oracle, "verify", wraps=oracle.verify) as verifier:
            result = project(value, pins)
        self.assertEqual(verifier.call_count, 1)
        self.assertEqual(result["schema"], bridge.SCHEMA)
        # I*B=B independently checks the product and its byte order.
        self.assertEqual(result["relation"]["product_bytes_sha256"],
                         hashlib.sha256(oracle.field_bytes(self.b)).hexdigest())
        self.assertEqual(result["original_accounting_view"], legacy.project(
            value["accounting_input"], pins["accounting_pins"], source_root=ROOT))

    def test_nonce_variants_share_exact_content_key_and_keep_all_costs(self):
        values = [fixture(r) for r in self.relations[:2]]
        bindings = [v[0]["accounting_input"]["binding"] for v in values]
        for key in ("inputs", "task_content", "output_spec", "output_content"):
            self.assertEqual(bindings[0][key], bindings[1][key])
        self.assertNotEqual(bindings[0]["qualified_work"], bindings[1]["qualified_work"])
        snapshots = []
        for value, pins in values:
            result = project(value, pins)["original_accounting_view"]
            snapshots.append(result["propositions"]["utility"]["facts"]["output_accounting"]["snapshot"])
        self.assertEqual(snapshots[0], snapshots[1])
        self.assertEqual(snapshots[0]["unique_useful_outputs_actually_adopted"], 1)
        self.assertEqual(snapshots[0]["downstream_adoption_events"], 2)
        self.assertEqual(snapshots[0]["cost_totals"]["cpu_ns"], 80)
        self.assertIsNone(snapshots[0]["cost_totals"]["gpu_ns"])

    def test_different_inputs_with_coincident_product_keep_distinct_task_identity(self):
        first = bridge.derive_binding(self.relations[0], source_root=ROOT)
        second = bridge.derive_binding(self.relations[2], source_root=ROOT)
        self.assertEqual(first["output_content"], second["output_content"])
        self.assertNotEqual(first["task_content"], second["task_content"])
        self.assertNotEqual(first["inputs"], second["inputs"])

    def test_relation_success_does_not_supply_other_propositions_or_authority(self):
        result = project(*fixture(self.relations[0], utility=False))
        original = result["original_accounting_view"]
        self.assertFalse(any(result["authority"].values()))
        for proposition in original["propositions"].values():
            self.assertFalse(proposition["proven"])
        for name in ("demand", "utility", "sybil"):
            self.assertEqual(original["propositions"][name]["observation_state"], "MISSING")
        self.assertIsNone(original["propositions"]["sybil"]["facts"]["all_algorithm_cost_bound"])

    def test_every_derived_content_field_must_match(self):
        for field in ("inputs", "task_content", "output_spec", "output_content", "qualified_work", "work_profile"):
            value, pins = fixture(self.relations[0], utility=False)
            value["accounting_input"]["binding"][field] = "wrong" if field == "work_profile" else "ab" * 32
            repin(value, pins)
            with self.subTest(field=field), self.assertRaises(ValueError):
                project(value, pins)

    def test_producer_repin_cannot_change_reviewer_statement(self):
        for field in ("challenge", "target", "task"):
            value, pins = fixture(self.relations[0], utility=False)
            value["relation"][field] = "ab" * 32
            repin(value, pins)
            with self.subTest(field=field), self.assertRaises(ValueError):
                project(value, pins)

    def test_proof_digest_is_independently_pinned(self):
        value, pins = fixture(self.relations[0], utility=False)
        pins["proof_sha256"] = "ab" * 32
        with self.assertRaises(ValueError):
            project(value, pins)

    def test_full_verifier_failure_cannot_become_success(self):
        value, pins = fixture(self.relations[0], utility=False)
        with patch.object(oracle, "verify", side_effect=ValueError("RELATION_REJECTED")):
            with self.assertRaises(ValueError):
                project(value, pins)

    def test_noncanonical_hex_lengths_trailing_bytes_and_type_aliases_refuse(self):
        malformed = [dict(proof_hex=self.relations[0]["proof_hex"] + "00"),
                     dict(proof_hex=self.relations[0]["proof_hex"][:-2]),
                     dict(proof_hex=self.relations[0]["proof_hex"].upper()),
                     dict(challenge="00 " * 32), dict(target=True), dict(task=None)]
        for changes in malformed:
            relation = {**self.relations[0], **changes}
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError):
                bridge.derive_binding(relation, source_root=ROOT)

    def test_strict_json_refuses_aliases_duplicates_and_size(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":NaN}', b'[]' * (4 * 1024 * 1024)):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                bridge.loads(raw)

    def test_unknown_fields_cannot_promote_qualification(self):
        for place in ("input", "relation", "pins"):
            value, pins = fixture(self.relations[0], utility=False)
            target = value if place == "input" else value["relation"] if place == "relation" else pins
            target["production_activation"] = True
            repin(value, pins)
            with self.subTest(place=place), self.assertRaises(ValueError):
                project(value, pins)

    def test_native_environment_does_not_switch_explicit_scalar_verifier(self):
        value, pins = fixture(self.relations[0], utility=False)
        expected = project(value, pins)
        with patch.dict(os.environ, {"TRNM_NATIVE_WORK": "/nonexistent/not-selected"}):
            self.assertEqual(project(value, pins), expected)

    def test_source_drift_refuses_before_verification(self):
        value, pins = fixture(self.relations[0], utility=False)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in {**legacy.SOURCE_BLOBS, "formal/pon-nakamoto-v1/four_propositions_v1.py": ""}:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            path = root / "formal/pon-nakamoto-v1/work_oracle.py"
            path.write_bytes(path.read_bytes() + b"\n")
            with patch.object(oracle, "verify", side_effect=AssertionError("must not execute")):
                with self.assertRaises(ValueError):
                    bridge.project(value, pins, source_root=root)

    def test_cli_round_trip_and_false_success_report_refusal(self):
        value, pins = fixture(self.relations[0], utility=False)
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "input.json").write_bytes(bridge.canonical(value))
            (folder / "pins.json").write_bytes(bridge.canonical(pins))
            command = [sys.executable, "-B", str(Path(bridge.__file__)), "--input", str(folder / "input.json"),
                       "--pins", str(folder / "pins.json"), "--source-root", str(ROOT)]
            result = subprocess.run(command, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            report = json.loads(result.stdout)
            self.assertEqual(report, project(value, pins))
            report["authority"]["production_activation"] = True
            (folder / "report.json").write_bytes(bridge.canonical(report))
            refused = subprocess.run(command + ["--check-view", str(folder / "report.json")],
                                     capture_output=True, timeout=30)
            self.assertEqual(refused.returncode, 2, refused.stderr.decode())
            self.assertEqual(refused.stdout, b"")

    def test_real_scalar_verifier_refuses_corruption_after_digest_repin(self):
        for changed, expected_error in (("magic", "VERSION"), ("product", "PRODUCT"),
                                        ("trace", "TRANSCRIPT"), ("zero-target", "TARGET")):
            value, pins = fixture(self.relations[0], utility=False)
            relation = value["relation"]
            proof = bytearray.fromhex(relation["proof_hex"])
            if changed == "zero-target":
                relation["target"] = "00" * 32
                pins["statement"]["target"] = relation["target"]
            else:
                position = {"magic": 0, "product": 4 + 2 * oracle.CELLS * 4,
                            "trace": len(proof) - 1}[changed]
                proof[position] ^= 1
                relation["proof_hex"] = proof.hex()
            self.assertEqual(len(proof), bridge.PROOF_BYTES)
            pins["proof_sha256"] = hashlib.sha256(proof).hexdigest()
            repin(value, pins)
            # Both input and proof digests agree; the actual pinned scalar
            # relation checker must still reject these simple invalid fixtures.
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    ValueError, "^" + expected_error + "$"):
                project(value, pins)

    def test_fresh_signed_demand_binds_verified_v2_matrix_roots(self):
        value, pins = fixture(self.relations[0], utility=False)
        accounting = value["accounting_input"]
        binding = accounting["binding"]
        demand_fixture = fixtures.demand_fixture
        demand = demand_fixture.DemandTests()
        demand.setUp()
        # These are fresh synthetic records. Every record is signed again
        # under the new contract; no historical signature is reinterpreted.
        bundle = demand.bundle()
        bundle["contract"].update({name: binding[name] for name in
                                   ("inputs", "output_spec", "qualified_work")})
        contract = demand_fixture.validate_contract(bundle["contract"])

        def fresh_record(record):
            body = record["body"]
            payload = copy.deepcopy(body["payload"])
            if body["kind"] == "request":
                payload["terms"] = contract
            if "output" in payload:
                payload["output"] = binding["output_content"]
            if body["kind"] == "delivery":
                payload["verification"] = bridge.sha(dict(
                    schema="synthetic-v2-scalar-relation-observation",
                    proof_sha256=pins["proof_sha256"]))
            role = next(name for name, key in demand.keys.items() if key == body["signer"])
            return demand.sign(body["kind"], payload, contract, role)

        for field in ("request", "funding", "provenance", "delivery", "acceptance",
                      "dispute", "evaluation", "availability", "adoption"):
            if bundle[field] is not None:
                bundle[field] = fresh_record(bundle[field])
        bundle["payments"] = [fresh_record(record) for record in bundle["payments"]]
        demand.book = demand.new_book()
        observation = demand.observe(bundle)
        accounting["demand"] = dict(actions=[dict(bundle=bundle, expected_contract=contract,
            expected_anchor=demand.anchor, height=100, observation=observation)],
            snapshot=demand.book.snapshot())
        pins["accounting_pins"]["demand"] = dict(
            owner_keys={role: demand.keys[role] for role in demand_fixture.ROLES},
            registry_root=demand.registry, bonus_cap=10, max_records=4096)
        repin(value, pins)
        result = project(value, pins)
        demand_view = result["original_accounting_view"]["propositions"]["demand"]
        self.assertEqual(demand_view["observation_state"], "OBSERVED")
        self.assertEqual(demand_view["facts"]["composition"]["observations"][0]["paid"],
                         dict(service=20, evaluation=7, availability=3, improvement=0))
        self.assertEqual(bundle["delivery"]["body"]["payload"]["output"],
                         result["derived_binding"]["output_content"])
        self.assertTrue(result["relation"]["full_transcript_and_product_verified"])
        self.assertFalse(result["real_customer_authenticity_verified"])
        self.assertFalse(demand_view["proven"])
        self.assertFalse(any(result["authority"].values()))


if __name__ == "__main__":
    unittest.main()
