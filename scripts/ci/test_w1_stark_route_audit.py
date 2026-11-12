#!/usr/bin/env python3
"""Route identity and claim-boundary regressions on the actual pinned sources."""
from __future__ import annotations

import copy
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import w1_stark_route_audit as audit  # noqa: E402
import w1_stark_field_certificates as field  # noqa: E402


class RouteAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = audit.strict_json((ROOT / audit.REGISTRY_PATH).read_bytes())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for pin in self.registry["source_inputs"]:
            target = self.root / pin["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / pin["path"], target)
        self.request = copy.deepcopy(self.registry)

    def reject(self):
        with self.assertRaises((audit.RouteAuditError, ValueError)):
            audit.audit(self.root, self.request)

    def test_actual_routes_keep_distinct_fields_and_unknown_security(self):
        result = audit.audit(self.root, self.request)
        self.assertEqual(result["status"], "ROUTE_MAPPING_REPRODUCED_SECURITY_HOLD")
        self.assertEqual(result["route_count"], 3)
        risc, poseidon, sha3 = result["routes"]
        self.assertEqual(risc["field"]["characteristic"], "2013265921")
        self.assertEqual(risc["field"]["extension_degree"], "4")
        self.assertEqual(poseidon["field"]["characteristic"], "18446744069414584321")
        self.assertEqual(sha3["field"]["extension_degree"], "2")
        self.assertEqual(risc["fri"]["queries"], 50)
        self.assertEqual(poseidon["fri"]["queries"], 64)
        self.assertEqual(sha3["primitive_model"]["digest_bytes"], 64)
        self.assertEqual(sha3["full_w1_fixed_components"][0]["proof_magic_hex"], b"W1S3SH01".hex())
        self.assertEqual(sha3["full_w1_fixed_components"][1]["evaluation_log2"], 16)
        self.assertEqual(len(set(result["route_fingerprints"].values())), 3)
        for field in ("source_to_binary_refinement_proved", "full_dependency_closure_reproduced",
                      "native_proofs_generated_or_verified"):
            self.assertFalse(result[field])
        for route in result["routes"]:
            self.assertIsNone(route["qualification"]["quantum_security_bits"])
            self.assertIsNone(route["qualification"]["complete_noninteractive_security_bits"])
            self.assertFalse(route["qualification"]["consensus_admission"])
            self.assertFalse(route["proximity_scope"]["all_proximity_gap_results_excluded"])
            self.assertEqual(route["proximity_scope"]["small_base_field_and_list_size_review"], "OPEN")

    def test_retained_version_progress_does_not_promote_security(self):
        result = audit.audit(self.root, self.request)
        progress = result["routes"][0]["retained_obligation_progress"]
        self.assertEqual(progress["historical_obligation_count"], 15)
        self.assertEqual(progress["pinned_revision_subobligations_closed"], 1)
        self.assertEqual(progress["other_historical_obligations_remaining"], 14)
        self.assertEqual(progress["full_security_obligation_count_discharged"], 0)
        self.assertEqual(len(progress["eight_interfaces_closed"]), 8)
        self.assertTrue(all(value is False for value in progress["eight_interfaces_closed"].values()))

    def test_known_poseidon_premises_keep_actual_binding_open(self):
        premise = audit.audit(self.root, self.request)["routes"][1]["primitive_premises"]
        self.assertEqual(premise["unrestricted_compressor_collision_resistance"], "REFUTED")
        self.assertEqual(premise["independent_leaf_branch_function_model"], "REFUTED")
        self.assertEqual(premise["actual_pruned_mmcs_binding"], "OPEN")
        self.assertIsNone(premise["concrete_restricted_tree_binding_bits"])
        self.assertFalse(premise["conditional_estimator_is_raw_compressor_bound"])
        self.assertFalse(premise["false_w1_proof_inferred"])
        self.request["routes"][1]["primitive_premises"]["actual_pruned_mmcs_binding"] = "PROVED"
        self.reject()

    def test_tagged_frames_do_not_promote_transcript_history(self):
        model = audit.audit(self.root, self.request)["routes"][2]["transcript_model"]
        for key in ("per_message_semantic_tags", "observe_call_boundaries_encoded",
                    "consumed_output_byte_count_encoded_before_observe",
                    "generic_transcript_history_injectivity_claimed",
                    "input_role_framing_is_transcript_history_proof", "fixed_w1_forgery_inferred"):
            self.assertIs(model[key], False)
        self.assertEqual(model["actual_schedule_knowledge_soundness"], "OPEN")
        self.request["routes"][2]["transcript_model"]["generic_transcript_history_injectivity_claimed"] = True
        self.reject()

    def test_primitive_premise_helpers_require_actual_source_anchors(self):
        inputs = audit.read_inputs(self.root, self.request["source_inputs"])
        old = inputs[audit.P3 + "/src/proof_config.rs"].decode()
        contract = inputs[audit.P3_PRIMITIVE_CONTRACT].decode()
        new = inputs[audit.P3 + "/src/tagged_sha3.rs"].decode()
        self.assertEqual(audit.poseidon_primitive_premises(old, contract)["actual_pruned_mmcs_binding"], "OPEN")
        with self.assertRaises(audit.RouteAuditError):
            audit.poseidon_primitive_premises(old, contract.replace("They do not establish", "They establish"))
        with self.assertRaises(audit.RouteAuditError):
            audit.poseidon_primitive_premises(old.replace("conditional_estimator_input_only", "concrete_bound"), contract)
        with self.assertRaises(audit.RouteAuditError):
            audit.tagged_transcript_premises(new.replace("generic transcript-history injectivity is not claimed",
                                                        "generic transcript-history injectivity proved"))

    def test_direct_domain_obstruction_is_cardinality_not_binary_only(self):
        # The theorem's necessary cardinality holds in odd characteristic too;
        # an independent finite enumeration checks it separately from 2-adicity.
        for prime in (3, 5, 7):
            for exponent in (1, 2):
                for h in (0, 1):
                    for n in range(2 + h, 5):
                        theorem_size = (prime ** exponent) ** (2 * n - h)
                        self.assertEqual(theorem_size % prime, 0)
                        self.assertGreaterEqual(2 * n - h, 4)
            result = audit.dktz_direct_domain_cardinality(prime, 4)
            self.assertFalse(result["direct_domain_hypothesis_matched"])
            for ell in range(5):
                self.assertEqual(math.gcd(2 ** ell, prime), 1)
            self.assertEqual(result["padding_restriction_or_other_result_applicability"], "OPEN")
            self.assertFalse(result["fri_soundness_inferred"])

    def test_direct_domain_helper_rejects_types_and_capacity_confusion(self):
        for prime, adicity, fixed in ((2, 4, None), (True, 4, None), (3.0, 4, None),
                                      (3, True, None), (3, -1, None), (3, 65, None),
                                      (3, 4, [True]), (3, 4, [5]), (3, 4, []),
                                      (3, 4, [2, 2]), (3, 4, [1.0])):
            with self.subTest(prime=prime, adicity=adicity, fixed=fixed):
                with self.assertRaises(audit.RouteAuditError):
                    audit.dktz_direct_domain_cardinality(prime, adicity, fixed)

    def test_route_domain_certificates_keep_other_proximity_results_open(self):
        result = audit.audit(self.root, self.request)
        for route in result["routes"]:
            cert = route["proximity_scope"]["dktz_theorem_5_22_direct_domain"]
            self.assertEqual((cert["theorem"], cert["printed_page"]), ("5.22", 50))
            self.assertEqual(cert["certified_characteristic"], route["field"]["characteristic"])
            self.assertFalse(cert["direct_domain_hypothesis_matched"])
            self.assertFalse(cert["all_proximity_gap_results_excluded"])
            self.assertFalse(cert["fri_soundness_inferred"])
            self.assertEqual(route["proximity_scope"]["small_base_field_and_list_size_review"], "OPEN")
        tagged = result["routes"][2]["proximity_scope"]["dktz_theorem_5_22_direct_domain"]
        self.assertEqual(tagged["fixed_tagged_evaluation_log2"], [15, 16])
        self.request["routes"][2]["proximity_scope"]["dktz_theorem_5_22_direct_domain"]["fri_soundness_inferred"] = True
        self.reject()

    def test_rejects_incompatible_field_certificate_status_and_security_claims(self):
        original = field.build_report(self.root)
        for key, value in (("fri_soundness_qualified", True), ("security_bits_quantum", 128)):
            changed = copy.deepcopy(original)
            changed["qualification"][key] = value
            with self.subTest(key=key), patch.object(field, "build_report", return_value=changed):
                self.reject()
        changed = copy.deepcopy(original)
        changed["status"] = "FULL_SECURITY_QUALIFIED"
        with patch.object(field, "build_report", return_value=changed):
            self.reject()

    def test_allowed_root_is_distinct_from_final_control_id(self):
        result = audit.audit(self.root, self.request)
        identity = result["routes"][0]["statement_identity"]
        self.assertEqual(identity["allowed_control_root"],
                         "a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56")
        self.assertNotEqual(identity["allowed_control_root"], identity["final_control_id"])
        self.assertEqual(len(identity["allowed_control_ids"]), 27)
        self.assertIn(identity["final_control_id"], identity["allowed_control_ids"])
        self.assertFalse(identity["allowed_program_semantics_proved"])
        self.request["routes"][0]["statement_identity"]["allowed_control_root"] = identity["final_control_id"]
        self.reject()

    def test_historical_pdf_identity_does_not_become_fresh_retrieval(self):
        result = audit.audit(self.root, self.request)
        literature = result["literature_review"]
        self.assertFalse(literature["fresh_pdf_bytes_or_pdf_hashes_established"])
        self.assertEqual(literature["historical_cdhz_pdf_identity"]["sha256"],
                         "2cfb88c76732d9f39f4b1943b4aabc0390dd3d17830d91d910c38e16e4bb5a30")
        self.request["literature_review"]["fresh_pdf_bytes_or_pdf_hashes_established"] = True
        self.reject()

    def test_rejects_historical_pdf_identity_relabeling(self):
        self.request["literature_review"]["historical_cdhz_pdf_identity"]["sha256"] = "0" * 64
        self.reject()

    def test_rejects_cross_route_field_and_profile_substitution(self):
        for field in ("field", "profile_id", "fri"):
            with self.subTest(field=field):
                self.request = copy.deepcopy(self.registry)
                self.request["routes"][1][field] = copy.deepcopy(self.request["routes"][0][field])
                self.reject()
        self.request = copy.deepcopy(self.registry)
        self.request["routes"][1] = copy.deepcopy(self.request["routes"][2])
        self.reject()

    def test_rejects_conditional_bits_digest_bits_and_null_to_zero_promotions(self):
        for route, field, value in ((1, "quantum_security_bits", 128),
                                    (2, "complete_noninteractive_security_bits", 256),
                                    (0, "lifecycle_security_bits", 0)):
            with self.subTest(route=route, field=field):
                self.request = copy.deepcopy(self.registry)
                self.request["routes"][route]["qualification"][field] = value
                self.reject()

    def test_rejects_bool_integer_alias(self):
        self.request["routes"][2]["fri"]["max_log_arity"] = True
        self.reject()

    def test_rejects_binary_field_claim_and_blanket_rs_exclusion(self):
        self.request["routes"][2]["field"]["characteristic"] = "2"
        self.reject()
        self.request = copy.deepcopy(self.registry)
        self.request["routes"][0]["proximity_scope"]["all_proximity_gap_results_excluded"] = True
        self.reject()

    def test_rejects_small_base_field_obligation_erasure(self):
        self.request["routes"][2]["open_obligations"].remove(audit.SMALL_FIELD_OBLIGATION)
        self.reject()

    def test_rejects_mmcs_and_domain_separation_claim_promotion(self):
        self.request["routes"][2]["structural_mmcs_result"]["quantum_commitment_extractor"] = True
        self.reject()
        self.request = copy.deepcopy(self.registry)
        self.request["routes"][2]["primitive_model"]["independent_role_oracles_qualified"] = True
        self.reject()

    def test_rejects_version_correspondence_as_full_obligation_closure(self):
        self.request["routes"][0]["retained_obligation_progress"]["full_security_obligation_count_discharged"] = 1
        self.reject()
        self.request = copy.deepcopy(self.registry)
        self.request["routes"][0]["historical_obligation_roster"].pop(0)
        self.reject()

    def test_rejects_changed_extension_and_magic(self):
        self.request["routes"][2]["field"]["extension_polynomial_low_to_high"] = ["11", "0", "0", "0", "1"]
        self.reject()
        self.request = copy.deepcopy(self.registry)
        self.request["routes"][2]["full_w1_fixed_components"][0]["proof_magic_hex"] = b"W1S3PC01".hex()
        self.reject()

    def test_rejects_source_mutation_with_unchanged_manifest(self):
        target = self.root / (audit.P3 + "/src/proof_config.rs")
        original = target.read_bytes()
        changed = original.replace(b"NUM_QUERIES: usize = 64", b"NUM_QUERIES: usize = 50")
        self.assertNotEqual(original, changed)
        target.write_bytes(changed)
        self.reject()

    def test_rejects_source_and_json_pin_changed_together(self):
        for relative in (audit.P3 + "/src/tagged_sha3.rs", audit.QROM_MAPPING):
            with self.subTest(relative=relative):
                self.request = copy.deepcopy(self.registry)
                target = self.root / relative
                original = target.read_bytes()
                changed = original + b"\n"
                target.write_bytes(changed)
                pin = next(row for row in self.request["source_inputs"] if row["path"] == relative)
                pin.update(bytes=len(changed), sha256=audit.sha256(changed))
                try:
                    self.reject()
                finally:
                    target.write_bytes(original)

    def test_rejects_missing_source(self):
        (self.root / audit.PROOF_CHAIN).unlink()
        self.reject()

    def test_rejects_symlink_source(self):
        target = self.root / audit.HARDENED
        target.unlink()
        target.symlink_to(ROOT / audit.HARDENED)
        self.reject()

    def test_rejects_changed_dependency_archive(self):
        path = audit.P3 + "/security_model_audit/vendor_primary/p3-goldilocks-0.8.0.crate"
        target = self.root / path
        raw = bytearray(target.read_bytes())
        raw[-1] ^= 1
        target.write_bytes(raw)
        self.reject()

    def test_rejects_registry_scope_and_production_overrides(self):
        self.request["qualification"]["production_qualified"] = True
        self.reject()
        for field, value in (("source_scope", "full_binary_and_security_certificate"),
                             ("accepted", True), ("source_base_commit", "0" * 40)):
            with self.subTest(field=field):
                self.request = copy.deepcopy(self.registry)
                self.request[field] = value
                self.reject()

    def test_strict_parser_rejects_duplicates_floats_and_nonfinite(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":1.0}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(audit.RouteAuditError):
                audit.strict_json(raw)

    def test_cli_rejection_preserves_hold_and_nonzero_exit(self):
        self.request["qualification"]["consensus_admission"] = True
        path = self.root / audit.REGISTRY_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.request), encoding="utf-8")
        child = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/w1_stark_route_audit.py"),
                                "--repository", str(self.root)], capture_output=True, text=True, check=False)
        self.assertEqual(child.returncode, 2)
        result = json.loads(child.stdout)
        self.assertEqual(result["status"], "INPUT_REJECTED")
        self.assertEqual(result["qualification"]["status"], "HOLD_NO_GO")
        self.assertFalse(result["qualification"]["consensus_admission"])
        self.assertFalse(result["source_mapping_reproduced"])


if __name__ == "__main__":
    unittest.main()
