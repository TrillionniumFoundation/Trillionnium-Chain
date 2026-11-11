#!/usr/bin/env python3
"""Adversarial controls for the per-purpose hash inventory, not crypto proofs."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import hash_use_contract as contract

ROOT = Path(__file__).resolve().parents[2]


class HashUseContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (ROOT / contract.DEFAULT_MANIFEST).read_bytes()
        cls.manifest = contract.strict_json(cls.raw)
        cls.sources = {path: (ROOT / path).read_bytes()
                       for path in cls.manifest["source_files"]}

    def data(self):
        return copy.deepcopy(self.manifest)

    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix="hash-use-contract-") as temporary:
            root = Path(temporary).resolve()
            for path, raw in {contract.DEFAULT_MANIFEST: self.raw, **self.sources}.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            yield root

    def refused(self, data):
        with self.assertRaises(contract.ContractError):
            contract.validate_manifest(data)

    def test_declaration_validation_never_claims_source_inspection_or_security(self):
        result = contract.validate_manifest(self.data())
        self.assertEqual(result["status"], "HOLD_NO_GO")
        self.assertFalse(result["source_files_checked"])
        self.assertFalse(result["source_semantics_refinement_proved"])
        self.assertFalse(result["complete_callgraph_coverage_proved"])
        self.assertIsNone(result["actual_lifetime_failure_bound"])
        self.assertIsNone(result["security_bits"])
        self.assertFalse(result["production_activation"])

    def test_actual_reviewed_source_inspection_preserves_hold(self):
        result = contract.inspect(ROOT)
        self.assertTrue(result["source_files_checked"])
        self.assertEqual(result["declared_use_count"], 17)
        self.assertEqual(result["declared_source_count"], 26)
        self.assertFalse(result["source_revision_authenticated"])
        self.assertFalse(result["whole_chain_hash_query_scope_closed"])
        self.assertFalse(result["whole_chain_pq_qualified"])

    def test_missing_or_added_use_cannot_narrow_or_expand_the_review(self):
        for key in ("model-legacy-root", "transaction-root", "history-block-anchor",
                    "signature-tpq1-payload", "storage-cell-chunks"):
            with self.subTest(key=key):
                data = self.data()
                del data["uses"][key]
                self.refused(data)
        data = self.data()
        data["uses"]["new-live-owner"] = copy.deepcopy(data["uses"]["transaction-root"])
        self.refused(data)

    def test_attack_selection_orders_are_distinct_and_not_interchangeable(self):
        data = self.data()
        goals = data["games"]
        orders = [goals[name]["selection_order"] for name in (
            "fixed-target-preimage", "fixed-message-second-preimage", "chosen-pair-collision")]
        self.assertEqual(len(set(orders)), 3)
        goals["chosen-pair-collision"] = copy.deepcopy(goals["fixed-target-preimage"])
        self.refused(data)

    def test_collision_game_cannot_be_omitted_for_signature_or_root_binding(self):
        for key in ("model-full-payload", "transaction-root", "signature-tpq1-payload"):
            with self.subTest(key=key):
                data = self.data()
                data["uses"][key]["attack_games"].remove("chosen-pair-collision")
                self.refused(data)

    def test_work_threshold_cannot_be_replaced_by_a_single_target_hash_game(self):
        data = self.data()
        data["uses"]["work-threshold"]["attack_games"] = ["fixed-target-preimage"]
        self.refused(data)

    def test_width_exponent_is_not_a_lifetime_probability_or_concrete_bit_claim(self):
        notes = self.data()["query_model_notes"]
        row = notes["ideal_output_width_examples"][0]
        self.assertEqual(row["output_bits"], 256)
        self.assertEqual(row["collision_exponent"], {"numerator": "256", "denominator": "3"})
        self.assertEqual(row["preimage_exponent"], {"numerator": "256", "denominator": "2"})
        for key in ("examples_are_security_bits", "examples_are_lifetime_failure_bounds"):
            data = self.data()
            data["query_model_notes"][key] = True
            self.refused(data)

    def test_primitive_relabel_width_change_and_unknown_algorithm_refused(self):
        for key, value in (("output_bits", 512), ("construction", "SHA-256-is-PQ128-everywhere")):
            data = self.data()
            data["primitives"]["sha256"][key] = value
            self.refused(data)
        data = self.data()
        data["uses"]["model-legacy-root"]["primitives"] = ["unknown-secure-hash"]
        self.refused(data)

    def test_domain_omission_or_transfer_requires_a_new_review(self):
        for key in ("transaction-root", "storage-bep52-root", "profile-byte-commitment"):
            data = self.data()
            data["uses"][key]["encoding"]["domains"] = ["CCH1 domains inherited automatically"]
            self.refused(data)

    def test_consumed_width_cannot_hide_truncation_or_drop_a_role(self):
        data = self.data()
        outputs = data["uses"]["signature-tpq1-payload"]["consumed_outputs"]
        outputs["payload_commitment"]["consumed_bits"] = 256
        self.refused(data)
        outputs["payload_commitment"]["truncation"] = "explicit-bit-prefix"
        self.refused(data)  # Even explicit truncation changes the reviewed consumer.
        data = self.data()
        data["uses"]["signature-tpq1-payload"]["consumed_outputs"].pop("qtx1_owner_context")
        self.refused(data)

    def test_unmapped_proof_output_cannot_inherit_digest_width(self):
        data = self.data()
        output = data["uses"]["proof-risc0-selected"]["consumed_outputs"]["risc0_merkle_and_transcript_outputs"]
        output.update(consumed_bits=256, truncation="none")
        self.refused(data)
        data = self.data()
        output = data["uses"]["proof-p3-tagged-reference"]["consumed_outputs"]["sampled_fiat_shamir_field_challenges"]
        output.update(consumed_bits=512, truncation="none")
        self.refused(data)
        data = self.data()
        outputs = data["uses"]["work-threshold"]["consumed_outputs"]
        self.assertEqual(outputs["raw_noise_hash_output"]["consumed_bits"], 256)
        self.assertIsNone(outputs["sampled_noise_field_words"]["consumed_bits"])
        outputs["sampled_noise_field_words"].update(
            primitive="sha256", consumed_bits=256, truncation="none")
        self.refused(data)

    def test_literal_metadata_cannot_be_claimed_as_transitive_full_content(self):
        data = self.data()
        data["uses"]["model-full-payload"]["legacy_reference_roles"] = []
        self.refused(data)
        data = self.data()
        data["uses"]["model-direct-dependencies"]["migration"]["transitive_dependency_closure_proved"] = True
        self.refused(data)

    def test_proof_parameter_profiles_cannot_be_pooled_or_replaced(self):
        for change in ("pool", "queries", "profile"):
            data = self.data()
            proof = data["proof_profiles"]
            if change == "pool":
                proof["parameter_sets_may_be_combined_for_qualification"] = True
            elif change == "queries":
                proof["selected_risc0"]["expected_identity"]["fri"]["queries"] = 64
            else:
                proof["selected_risc0"]["profile_id"] = proof["tagged_p3_reference"]["profile_id"]
            self.refused(data)

    def test_proof_width_or_fri_parameters_cannot_supply_soundness(self):
        data = self.data()
        data["proof_profiles"]["tagged_p3_reference"]["qrom_soundness_bound"] = "2^-128"
        self.refused(data)
        data = self.data()
        data["uses"]["proof-risc0-selected"]["attack_games"] = ["merkle-binding"]
        self.refused(data)

    def test_source_map_cannot_self_repin_changed_source(self):
        data = self.data()
        first = next(iter(data["source_files"]))
        data["source_files"][first]["sha256"] = hashlib.sha256(b"replacement").hexdigest()
        data["source_files"][first]["bytes"] = len(b"replacement")
        self.refused(data)

    def test_source_paths_cannot_be_removed_redirected_or_duplicated(self):
        for path in ("../outside", "/outside", "file\\outside", "./inside", "inside\x00suffix"):
            data = self.data()
            data["uses"]["transaction-root"]["source_paths"] = [path]
            self.refused(data)
        data = self.data()
        paths = data["uses"]["transaction-root"]["source_paths"]
        paths.append(paths[0])
        self.refused(data)
        data = self.data()
        data["source_files"].pop(next(iter(data["source_files"])))
        self.refused(data)

    def test_bool_int_aliases_wrong_types_and_extra_fields_refused(self):
        for field, value in (("production_activation", 0), ("security_bits", False)):
            data = self.data()
            data["qualification"][field] = value
            self.refused(data)
        data = self.data()
        data["source_files"][next(iter(data["source_files"]))]["bytes"] = True
        self.refused(data)
        for data in ([], {**self.data(), "approved": True}):
            self.refused(data)

    def test_numeric_bounds_source_trust_and_scope_self_certification_refused(self):
        for key in self.manifest["qualification"]:
            data = self.data()
            data["qualification"][key] = "128" if data["qualification"][key] is None else True
            self.refused(data)
        data = self.data()
        data["source_binding"] = "source-hash-proves-pq-security"
        self.refused(data)

    def test_wrapper_can_only_describe_the_old_digest_literal(self):
        migration = self.data()["uses"]["model-legacy-root"]["migration"]
        migration.update(input_material="legacy-digest-wrapper", claimed_scope="literal-digest-only")
        result = contract.review_migration(migration)
        self.assertTrue(result["wrapper_preserves_every_inner_collision"])
        self.assertFalse(result["old_commitment_collision_risk_removed"])
        self.assertFalse(result["migration_authorized"])

    def test_wrapper_cannot_claim_original_content_or_recovered_provenance(self):
        migration = self.data()["uses"]["model-legacy-root"]["migration"]
        migration.update(input_material="legacy-digest-wrapper", claimed_scope="literal-digest-only")
        for key, value in (("claimed_scope", "direct-encoded-content-only"),
                           ("original_bytes_required", True),
                           ("old_commitment_strengthened", True),
                           ("historical_provenance_restored", True)):
            bad = copy.deepcopy(migration)
            bad[key] = value
            with self.assertRaises(contract.ContractError):
                contract.review_migration(bad)

    def test_small_inner_collision_survives_a_real_sha512_wrapper(self):
        # A deliberately 8-bit toy inner digest, not a SHA-256 collision claim.
        # Pigeonhole search is bounded to 257 distinct messages.
        seen = {}
        pair = None
        for index in range(257):
            message = index.to_bytes(4, "big")
            inner = hashlib.sha256(message).digest()[:1]
            if inner in seen:
                pair = seen[inner], message
                break
            seen[inner] = message
        self.assertIsNotNone(pair)
        left, right = pair
        self.assertNotEqual(left, right)
        wrapper = lambda message: hashlib.sha512(hashlib.sha256(message).digest()[:1]).digest()
        self.assertEqual(wrapper(left), wrapper(right))
        # This one explicit pair separates under a direct full-byte SHA-512.
        # It neither proves SHA-512 security nor authenticates either message.
        self.assertNotEqual(hashlib.sha512(left).digest(), hashlib.sha512(right).digest())

    def test_direct_recomputation_still_grants_no_old_history_or_adoption(self):
        migration = self.data()["uses"]["model-direct-dependencies"]["migration"]
        result = contract.review_migration(migration)
        self.assertTrue(result["full_content_recomputation_required"])
        self.assertFalse(result["prerequisites_fulfilled"])
        self.assertFalse(result["old_commitment_collision_risk_removed"])
        self.assertFalse(result["migration_authorized"])

    def test_missing_migration_prerequisite_and_unknown_material_refused(self):
        original = self.data()["uses"]["migration-full-state"]["migration"]
        for index in range(len(original["requirements"])):
            value = copy.deepcopy(original)
            value["requirements"].pop(index)
            with self.assertRaises(contract.ContractError):
                contract.review_migration(value)
        for material in ("automatic-upgrade", [], None):
            value = copy.deepcopy(original)
            value["input_material"] = material
            with self.assertRaises(contract.ContractError):
                contract.review_migration(value)

    def test_strict_json_refuses_duplicate_numeric_unicode_and_nesting_ambiguity(self):
        for raw in (b'{"uses":{},"uses":{}}', b'{"x":NaN}', b'{"x":Infinity}',
                    b'{"x":1.0}', b'{"x":123456789012345678901}',
                    b'{"x":"\\ud800"}', b'{"x":"\xff"}', b'[]',
                    b'{"x":' + b'[' * 65 + b'0' + b']' * 65 + b'}',
                    b' ' * (contract.MAX_BYTES + 1)):
            with self.subTest(raw=raw[:35]):
                with self.assertRaises(contract.ContractError):
                    contract.strict_json(raw)

    def test_missing_source_and_same_size_source_mutation_refused(self):
        selected = next(iter(self.manifest["source_files"]))
        with self.fixture() as root:
            target = root / selected
            raw = target.read_bytes()
            target.unlink()
            with self.assertRaisesRegex(contract.ContractError, "missing source"):
                contract.inspect(root)
            target.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
            with self.assertRaisesRegex(contract.ContractError, "source bytes differ"):
                contract.inspect(root)

    def test_symlink_source_and_symlink_manifest_refused(self):
        selected = next(iter(self.manifest["source_files"]))
        with self.fixture() as root:
            target = root / selected
            retained = root / "original-source"
            target.rename(retained)
            target.symlink_to(retained)
            with self.assertRaisesRegex(contract.ContractError, "symlink"):
                contract.inspect(root)
            target.unlink()
            retained.rename(target)
            manifest = root / contract.DEFAULT_MANIFEST
            retained = root / "original-manifest"
            manifest.rename(retained)
            manifest.symlink_to(retained)
            with self.assertRaisesRegex(contract.ContractError, "symlink"):
                contract.inspect(root)

    def test_symlink_repository_ancestor_refused(self):
        with self.fixture() as root:
            with tempfile.TemporaryDirectory(prefix="hash-root-alias-") as temporary:
                alias = Path(temporary).resolve() / "alias"
                alias.symlink_to(root, target_is_directory=True)
                with self.assertRaisesRegex(contract.ContractError, "symlink"):
                    contract.inspect(alias)

    def test_nonregular_fifo_and_oversize_source_refused_without_blocking(self):
        selected = next(iter(self.manifest["source_files"]))
        with self.fixture() as root:
            target = root / selected
            target.unlink()
            os.mkfifo(target)
            with self.assertRaisesRegex(contract.ContractError, "nonregular"):
                contract.inspect(root)
            target.unlink()
            with target.open("wb") as stream:
                stream.truncate(contract.MAX_SOURCE_BYTES + 1)
            with self.assertRaisesRegex(contract.ContractError, "oversize"):
                contract.inspect(root)

    def test_cli_success_is_hold_and_failure_is_refuse_exit_two(self):
        with self.fixture() as root:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(contract.main(["--root", str(root)]), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "HOLD_NO_GO")
            self.assertFalse(result["whole_chain_pq_qualified"])
            (root / contract.DEFAULT_MANIFEST).write_bytes(b'{"schema":1,"schema":2}')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(contract.main(["--root", str(root)]), 2)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "REFUSE")
            self.assertIsNone(result["actual_lifetime_failure_bound"])
            self.assertFalse(result["production_activation"])

    def test_manifest_path_traversal_and_changed_review_base_refused(self):
        data = self.data()
        data["review_base_revision"] = "0" * 40
        self.refused(data)
        for path in ("../outside.json", "/tmp/outside.json", "config/../outside.json"):
            with self.assertRaises(contract.ContractError):
                contract.inspect(ROOT, path)


if __name__ == "__main__":
    unittest.main()
