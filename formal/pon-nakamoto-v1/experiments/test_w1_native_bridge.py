#!/usr/bin/env python3
"""Reader trust-boundary controls; native Node execution is a separate Rust run.

The packet controls use a retained full PNW1 relation. The small invented
trajectory fixtures exercise artifact structure only and assert no native or
quantum execution. Expensive native/DAG replay is never mocked and then counted
as a native observation.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("native_bridge_under_test", HERE / "w1_native_bridge.py")
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


def claim_fixture():
    return {
        "genesis_timestamp": 100,
        "claims": dict(bridge.FIXTURE_CLAIMS),
        "initial_resources": {"coherent_quantum_state_supplied": False,
                              "winner_advice_available_to_fixed_policy_sampler": False,
                              "observer_has_full_census": True},
        "fixed_plan": {"nonce_bits": 3, "private_miner": 1, "root_timestamp": 116,
                       "child_timestamp": 117, "sample_seed": 9,
                       "horizon_seconds": "4", "max_attempts": 2},
    }


def structural_path():
    fixture = {"clock_origin_timestamp": 260, "prefix": {"tip_id": "prefix"},
               "contexts": [
                   {"context_id": "root", "parent_id": "prefix",
                    "winner_children": [{"nonce": 3, "block_id": "a"}]},
                   {"context_id": "child", "parent_id": "a",
                    "winner_children": [{"nonce": 1, "block_id": "b"}]},
               ]}
    trajectory = [
        {"edge": {"observation": {"proof_complete": True, "block_id": "a"}}},
        {"edge": {"observation": {"proof_complete": True, "block_id": "b"}}},
        {"edge": {"terminal_risk": 1,
                  "observation": {"time": {"numerator": 3, "denominator": 2},
                                  "publication_complete": True, "private_chain": ["a", "b"]}}},
    ]
    return fixture, trajectory


@contextmanager
def structural_verifier(directory, expected):
    """Mock mathematical replay only; exercise real raw-file/source guards."""
    fixture = {"native_source": {"source_sha256": {"native.rs": "native-fixture-digest"}}}
    snapshot = {"git_head": "structural-head", "source_sha256": {"reader.py": "reader-digest"}}
    files = {"native-fixture.json": json.dumps(fixture).encode() + b" \n",
             "finite-certificate.json": b" { }\n", "classical-certificate.json": b"{  } \n",
             "bridge-samples.json": json.dumps(expected).encode() + b"\n\n"}
    for name, raw in files.items():
        (directory / name).write_bytes(raw)
    with mock.patch.object(bridge, "load_fixture", return_value=(fixture, bridge.sha(files["native-fixture.json"]), 0)), \
            mock.patch.object(bridge, "check_cost_premises"), \
            mock.patch.object(bridge, "verify_finite_certificate"), \
            mock.patch.object(bridge, "sample_report", return_value=expected), \
            mock.patch.object(bridge, "sources", return_value=snapshot) as source_probe, \
            mock.patch.object(bridge, "native_source_inventory", return_value=fixture["native_source"]["source_sha256"]) as native_probe:
        yield {"files": files, "snapshot": snapshot, "source_probe": source_probe,
               "native_probe": native_probe}


class NativeBridgeReaderTests(unittest.TestCase):
    def test_duplicate_and_nonfinite_json_rejected(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                bridge.strict_load(raw)

    def test_qualification_escalation_and_extra_claim_rejected(self):
        bridge.check_fixture_claims(claim_fixture())
        for name in ("quantum_hardware_executed", "quantum_mining_qualified", "production_activation",
                     "original_service_profile_requalified", "online_search_sample_executed"):
            fixture = claim_fixture()
            fixture["claims"][name] = True
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "NATIVE_FIXTURE_CLAIMS"):
                bridge.check_fixture_claims(fixture)
        fixture = claim_fixture()
        fixture["claims"]["all_attacks_covered"] = True
        with self.assertRaisesRegex(ValueError, "NATIVE_FIXTURE_CLAIMS"):
            bridge.check_fixture_claims(fixture)

    def test_coherent_state_or_winner_advice_not_silently_free(self):
        for name in ("coherent_quantum_state_supplied", "winner_advice_available_to_fixed_policy_sampler"):
            fixture = claim_fixture()
            fixture["initial_resources"][name] = True
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "INITIAL_ADVICE_SCOPE"):
                bridge.check_fixture_claims(fixture)

    def test_seed_domain_horizon_and_attempt_plan_are_frozen(self):
        for key, value in (("sample_seed", 10), ("nonce_bits", 4), ("horizon_seconds", "40"),
                           ("max_attempts", 3), ("child_timestamp", 118)):
            fixture = claim_fixture()
            fixture["fixed_plan"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "NATIVE_FIXED_PLAN_CHANGED"):
                bridge.check_fixture_claims(fixture)

    def test_full_nonce_inventory_includes_misses_in_order(self):
        domain = {"domain_size": 3, "marked_nonces": [1],
                  "outcomes": [{"winner": False}, {"winner": True}, {"winner": False}]}
        context = {"all_nonce_outcomes": [
            {"nonce": i, "native_winner": i == 1, "complete_native_proof_generated": True,
             "native_fixture_admitted": i == 1, "native_verifier_error": None if i == 1 else "Target"}
            for i in range(3)], "winner_children": []}
        context["winner_children"] = [{**context["all_nonce_outcomes"][1], "child_context_id": None}]
        bridge.check_outcome_inventory(context, domain)
        mutations = []
        deleted = copy.deepcopy(context)
        deleted["all_nonce_outcomes"].pop(0)
        mutations.append(deleted)
        reordered = copy.deepcopy(context)
        reordered["all_nonce_outcomes"].reverse()
        mutations.append(reordered)
        winner_removed = copy.deepcopy(context)
        winner_removed["winner_children"] = []
        mutations.append(winner_removed)
        miss_promoted = copy.deepcopy(context)
        miss_promoted["all_nonce_outcomes"][0]["native_fixture_admitted"] = True
        mutations.append(miss_promoted)
        renamed_packet = copy.deepcopy(context)
        renamed_packet["winner_children"][0]["packet_file"] = "different-packet.pnk"
        mutations.append(renamed_packet)
        for mutated in mutations:
            with self.subTest(mutated=mutated), self.assertRaises(ValueError):
                bridge.check_outcome_inventory(mutated, domain)

    def test_complete_cost_premises_cannot_be_replaced_by_a_new_valid_model(self):
        fixture = {"contexts": [{}, {}]}
        parameters = bridge.cost_premises(fixture)[3]
        bridge.check_cost_premises({"parameters": parameters}, fixture)
        mutations = []
        for name, value in (("horizon_seconds", "40"), ("physical_qubit_budget", 10**17),
                            ("max_attempts", 3), ("iterations", [0, 2])):
            changed = copy.deepcopy(parameters)
            changed[name] = value
            mutations.append(changed)
        changed = copy.deepcopy(parameters)
        changed["classical_costs"][0]["per_winner_proof_ns"] = 1
        mutations.append(changed)
        changed = copy.deepcopy(parameters)
        changed["physical_model"]["magic_state_error"] = "1e-60"
        mutations.append(changed)
        changed = copy.deepcopy(parameters)
        changed["lifecycle_model"]["initialization_parallel_patches"] = 10**12
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(parameters=changed), self.assertRaisesRegex(ValueError, "BRIDGE_COST_PREMISES_CHANGED"):
                bridge.check_cost_premises({"parameters": changed}, fixture)

    def test_structural_published_path_keeps_nonce_parent_and_clock(self):
        fixture, path = structural_path()
        record = bridge.normalize_run(fixture, "structural", "unit-structure-only", path, {})
        self.assertEqual(record["native_observed_now"], 261)
        self.assertEqual(record["packets_to_submit"], [
            {"context_id": "root", "nonce": 3, "block_id": "a", "parent_id": "prefix"},
            {"context_id": "child", "nonce": 1, "block_id": "b", "parent_id": "a"},
        ])

    def test_structural_unpublished_and_censored_paths_submit_nothing(self):
        fixture, path = structural_path()
        path[-1]["edge"]["observation"]["publication_complete"] = False
        path[-1]["edge"]["terminal_risk"] = 0
        record = bridge.normalize_run(fixture, "structural", "unit-structure-only", path, {})
        self.assertEqual(record["packets_to_submit"], [])
        self.assertFalse(record["expected_reorganization"])
        path[-1]["edge"]["observation"]["time"] = {"numerator": 4, "denominator": 1}
        self.assertEqual(bridge.normalize_run(fixture, "s", "unit-structure-only", path, {})["native_observed_now"], 264)

    def test_structural_missing_proof_and_wrong_parent_rejected(self):
        fixture, path = structural_path()
        path[0]["edge"]["observation"]["proof_complete"] = False
        with self.assertRaisesRegex(ValueError, "UNPROVED_SELECTED_BLOCK"):
            bridge.normalize_run(fixture, "s", "unit-structure-only", path, {})
        fixture, path = structural_path()
        fixture["contexts"][1]["parent_id"] = "wrong-parent"
        with self.assertRaisesRegex(ValueError, "SELECTED_PARENT_BINDING"):
            bridge.normalize_run(fixture, "s", "unit-structure-only", path, {})

    def test_structural_over_horizon_and_float_time_rejected(self):
        fixture, path = structural_path()
        for value in ({"numerator": 4_000_000_001, "denominator": 1_000_000_000},
                      {"numerator": 4.0, "denominator": 1},
                      {"numerator": 1, "denominator": 0}):
            path[-1]["edge"]["observation"]["time"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                bridge.normalize_run(fixture, "s", "unit-structure-only", path, {})

    def test_create_only_output_refuses_before_census(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in bridge.OUTPUTS:
                with self.subTest(name=name):
                    path = directory / name
                    path.write_bytes(b"retained original failure")
                    with mock.patch.object(bridge, "load_fixture") as loader:
                        with self.assertRaisesRegex(ValueError, "OUTPUT_ALREADY_EXISTS"):
                            bridge.observe(directory)
                        loader.assert_not_called()
                    self.assertEqual(path.read_bytes(), b"retained original failure")
                    path.unlink()

    def test_writer_cannot_replace_file_or_follow_existing_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "result.json"
            bridge.write_new(path, {"old": True})
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                bridge.write_new(path, {"new": True})
            link = directory / "link.json"
            link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                bridge.write_new(link, {"new": True})
            self.assertEqual(path.read_bytes(), original)

    def test_regular_file_and_size_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            real = directory / "real"
            real.write_bytes(b"1234")
            link = directory / "link"
            link.symlink_to(real)
            with self.assertRaisesRegex(ValueError, "REGULAR_FILE_REQUIRED"):
                bridge.read(link)
            with self.assertRaisesRegex(ValueError, "FILE_SIZE_BOUND"):
                bridge.read(real, 3)

    def test_structural_replay_rejects_run_deletion_rename_cost_and_claim_tamper(self):
        expected = {"schema": bridge.SCHEMA, "runs": [{"name": "fixed-q0-seed9", "cost": 4}],
                    "claims": dict(bridge.CLAIMS)}
        mutations = []
        for operation in ("delete", "rename", "cost", "qualify"):
            modified = copy.deepcopy(expected)
            if operation == "delete":
                modified["runs"] = []
            elif operation == "rename":
                modified["runs"][0]["name"] = "different-seed"
            elif operation == "cost":
                modified["runs"][0]["cost"] = 0
            else:
                modified["claims"]["quantum_mining_qualified"] = True
            mutations.append(modified)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with structural_verifier(directory, expected):
                self.assertEqual(bridge.verify(directory)["status"], "VERIFIED")
                for modified in mutations:
                    (directory / "bridge-samples.json").write_text(json.dumps(modified))
                    with self.subTest(modified=modified), self.assertRaisesRegex(ValueError, "BRIDGE_SAMPLE_REPLAY_MISMATCH"):
                        bridge.verify(directory)


    def test_verifier_receipt_identifies_exact_raw_bytes_source_and_runtime(self):
        expected = {"runs": [{"name": "structural-only"}]}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with structural_verifier(directory, expected) as setup:
                receipt = bridge.verify(directory)
                self.assertEqual(receipt["verified_inputs"],
                                 {name: bridge.sha(raw) for name, raw in setup["files"].items()})
                self.assertEqual(receipt["source_snapshot"], setup["snapshot"])
                self.assertEqual(receipt["runtime_identity"]["executable"], bridge.sys.executable)
                self.assertEqual(receipt["runtime_identity"]["version"], bridge.sys.version)
                self.assertEqual(receipt["runtime_identity"]["implementation"], bridge.sys.implementation.name)
                self.assertEqual(receipt["native_blocks_admitted_by_python_reader"], 0)
                self.assertFalse(receipt["quantum_hardware_executed"])
                # Whitespace is intentionally distinct from a JSON reserialization.
                raw = setup["files"]["bridge-samples.json"]
                self.assertNotEqual(bridge.sha(raw), bridge.sha(bridge.json_bytes(expected)))

    def test_each_raw_input_cannot_change_between_verification_and_receipt(self):
        expected = {"runs": [{"name": "structural-only"}]}
        names = ("native-fixture.json", "finite-certificate.json",
                 "classical-certificate.json", "bridge-samples.json")
        for changed_name in names:
            with self.subTest(name=changed_name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                with structural_verifier(directory, expected):
                    original_read = bridge.read
                    mutated = False
                    def racing_read(path, *args, **kwargs):
                        nonlocal mutated
                        raw = original_read(path, *args, **kwargs)
                        if path.name == "bridge-samples.json" and not mutated:
                            mutated = True
                            target = directory / changed_name
                            target.write_bytes(target.read_bytes() + b" ")
                        return raw
                    with mock.patch.object(bridge, "read", side_effect=racing_read), \
                            self.assertRaisesRegex(ValueError, "BRIDGE_INPUT_CHANGED_DURING_VERIFY"):
                        bridge.verify(directory)
                    self.assertTrue(mutated)

    def test_python_and_native_source_changes_during_verification_rejected(self):
        expected = {"runs": []}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with structural_verifier(directory, expected) as setup:
                setup["source_probe"].side_effect = [setup["snapshot"], {"git_head": "changed"}]
                with self.assertRaisesRegex(ValueError, "BRIDGE_SOURCE_CHANGED"):
                    bridge.verify(directory)
            with structural_verifier(directory, expected) as setup:
                setup["native_probe"].return_value = {"native.rs": "changed"}
                with self.assertRaisesRegex(ValueError, "NATIVE_SOURCE_CHANGED"):
                    bridge.verify(directory)


class CompleteScalarPacketTests(unittest.TestCase):
    """Actual complete retained PNW1 scalar checks, without native Node claims."""
    @classmethod
    def setUpClass(cls):
        # The top-level header/work vectors describe independent contracts.
        # This retained pair explicitly belongs to one accepted-block fixture.
        cls.header = (bridge.FORMAL / "vectors/accepted-block/header.bin").read_bytes()
        cls.proof = (bridge.FORMAL / "vectors/accepted-block/work.bin").read_bytes()
        cls.decoded = bridge.wire.header_decode(cls.header)

    def record(self, directory, header=None, proof=None):
        header = self.header if header is None else header
        proof = self.proof if proof is None else proof
        decoded = bridge.wire.header_decode(header)
        identifier = bridge.wire.H("block", header, proof[-32:]).hex()
        raw = header + b"\0\0" + proof
        name = f"packets/{identifier}.pnk"
        (directory / "packets").mkdir(exist_ok=True)
        (directory / name).write_bytes(raw)
        return {"packet_file": name, "packet_sha256": bridge.sha(raw),
                "header_hex": header.hex(), "proof_sha256": bridge.sha(proof),
                "trace": proof[-32:].hex(), "nonce": decoded["nonce"], "block_id": identifier,
                "parent_id": decoded["parent"].hex(), "height": decoded["height"],
                "timestamp": decoded["timestamp"], "target_hex": decoded["target"].hex()}

    def test_retained_complete_scalar_packet_positive(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            row = self.record(directory)
            self.assertEqual(bridge.check_packet(directory, row), (self.header, self.proof))

    def test_product_tamper_with_all_file_digests_updated_still_rejected(self):
        proof = bytearray(self.proof)
        proof[4 + 2 * 4096 * 4] ^= 1
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            row = self.record(directory, proof=bytes(proof))
            with self.assertRaisesRegex(ValueError, "PRODUCT"):
                bridge.check_packet(directory, row)

    def test_packet_substitution_and_parent_metadata_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            row = self.record(directory)
            wrong = dict(row, parent_id="00" * 32)
            with self.assertRaisesRegex(ValueError, "PACKET_METADATA"):
                bridge.check_packet(directory, wrong)
            wrong = dict(row, packet_file="../escape.pnk")
            with self.assertRaisesRegex(ValueError, "PACKET_PATH"):
                bridge.check_packet(directory, wrong)
            wrong = dict(row, packet_sha256="00" * 32)
            with self.assertRaisesRegex(ValueError, "PACKET_DIGEST"):
                bridge.check_packet(directory, wrong)


if __name__ == "__main__":
    unittest.main()
