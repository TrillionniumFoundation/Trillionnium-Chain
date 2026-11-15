"""Controls for construction/accounting scope and refusal of promoted claims."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import quantum_oracle_resources as accounting
import w1_quantum_evidence_scope as scope
from test_w1_quantum_oracle import fixture
from w1_quantum_oracle import OracleProgram, Shape
from w1_quantum_restricted_oracle import PrefixRestrictedProgram


def request():
    # The numbers are explicitly synthetic classical/physical premises; these
    # tests only inspect their labeling and the derived circuit accounting.
    return replace(accounting.example(True), physical_models=())


class EvidenceScopeControls(unittest.TestCase):
    def test_generic_unknown_does_not_claim_repository_has_no_construction(self):
        report = scope.build_report(accounting.example())
        self.assertEqual(report["scope"], "GENERIC_CONDITIONAL_ACCOUNTING")
        self.assertFalse(report["construction_status"]["schedule_rebuilt_from_source"])
        self.assertIsNone(report["construction"])
        self.assertIsNone(report["accounting"]["complete_quantum_cost"])
        self.assertEqual(report["accounting"]["cost_evidence_kind"], "UNKNOWN_MISSING_STAGES")
        self.assertFalse(report["accounting"]["legacy_field_is_repository_wide_absence_claim"])
        self.assertFalse(report["historical_construction_reference"]["used_as_current_execution_or_qualification"])

    def test_forged_constructed_provenance_cannot_promote_caller_counts(self):
        supplied = request()
        supplied = replace(supplied, scope="CALLER_SUPPLIED_UNVERIFIED_PREDICATE",
                           circuits={name: replace(stage, provenance="constructed-w1/" + "a" * 64)
                                     for name, stage in supplied.circuits.items()})
        report = scope.build_report(supplied)
        self.assertFalse(report["construction_status"]["schedule_rebuilt_from_source"])
        self.assertFalse(report["construction_status"]["exact_native_shape_construction"])
        self.assertEqual(report["accounting"]["cost_evidence_kind"], "CALLER_ASSERTED_BUDGET_TOTAL")
        self.assertFalse(report["accounting"]["caller_circuit_budgets_replaced_by_reconstruction"])

    def test_native_full_construction_is_not_execution_or_security(self):
        report = scope.build_report(request(), fixture(Shape(), nonce_bits=64).spec(), "full")
        self.assertTrue(report["construction_status"]["exact_native_shape_construction"])
        self.assertTrue(report["construction_status"]["full_fixed_context_construction"])
        self.assertFalse(report["construction_status"]["legal_subset_construction"])
        self.assertFalse(report["construction_status"]["full_legal_predicate_equivalence_proved"])
        self.assertEqual(report["construction"]["phase_oracle_gate_count"], 17_718_016_715)
        self.assertEqual(report["construction"]["logical_qubits"], 22_253_173)
        self.assertTrue(all(value is False for value in report["execution_by_this_invocation"].values()))
        self.assertTrue(all(value is False for value in report["qualification"].values()))

    def test_native_subset_does_not_inherit_full_predicate_claim(self):
        report = scope.build_report(request(), fixture(Shape(), nonce_bits=64).spec(), "prefix-restricted")
        self.assertTrue(report["construction_status"]["exact_native_shape_construction"])
        self.assertTrue(report["construction_status"]["legal_subset_construction"])
        self.assertFalse(report["construction_status"]["full_fixed_context_construction"])
        self.assertFalse(report["construction_status"]["all_bounded_noise_branches_in_selected_construction"])
        self.assertFalse(report["construction"]["full_legal_winner_predicate_equivalence"])
        self.assertEqual(report["construction"]["phase_oracle_gate_count"], 15_992_168_955)

    def test_reduced_shapes_never_acquire_native_shape_qualification(self):
        for predicate in scope.PREDICATES:
            with self.subTest(predicate=predicate):
                report = scope.build_report(request(), fixture().spec(), predicate)
                self.assertTrue(report["construction_status"]["reduced_shape_control"])
                self.assertFalse(report["construction_status"]["exact_native_shape_construction"])
                self.assertFalse(report["construction_status"]["full_fixed_context_construction"])
                self.assertFalse(report["construction_status"]["legal_subset_construction"])
                self.assertTrue(all(value is False for value in report["execution_by_this_invocation"].values()))

    def test_all_circuit_budgets_are_rederived_including_inverse_and_diffusion(self):
        spec = fixture().spec()
        for predicate, cls in (("full", OracleProgram), ("prefix-restricted", PrefixRestrictedProgram)):
            report = scope.build_report(request(), spec, predicate)
            construction = cls(fixture()).resources()
            counts = report["accounting"]["complete_quantum_cost"]["per_grover_iteration"]
            self.assertEqual(counts["gate_count"], construction["phase_oracle_gate_count"] +
                             construction["diffusion"]["gate_count"])
            self.assertNotEqual(counts["gate_count"], 160)
            self.assertTrue(report["accounting"]["caller_circuit_budgets_replaced_by_reconstruction"])

    def test_generic_v1_accounting_output_is_preserved_byte_for_byte(self):
        supplied = request()
        original = scope.canonical(accounting.account(supplied))
        report = scope.build_report(supplied)
        self.assertEqual(scope.canonical(accounting.account(supplied)), original)
        self.assertEqual(report["accounting"]["original_report_sha256"], scope.digest(accounting.account(supplied)))
        self.assertFalse(accounting.account(supplied)["full_W1_oracle_constructed"])

    def test_exact_roundtrip_and_repeat_reconstruction_match(self):
        for predicate in (None, *scope.PREDICATES):
            with self.subTest(predicate=predicate):
                record = scope.build_report(request(), fixture().spec() if predicate else None, predicate)
                verified = scope.verify_report(scope.strict_load(scope.canonical(record)))
                self.assertEqual(verified["result"], "REBUILD_MATCH")
                self.assertFalse(verified["native_node_admission_verified"])

    def test_rehashed_claims_counts_sources_and_references_are_rejected(self):
        record = scope.build_report(request(), fixture().spec(), "full")
        mutations = [
            ("qualification", "quantum_mining_security_qualified", True),
            ("execution_by_this_invocation", "native_node_executed", True),
            ("construction_status", "exact_native_shape_construction", True),
            ("construction_status", "full_legal_predicate_equivalence_proved", True),
            ("accounting", "original_report_sha256", "0" * 64),
            ("historical_construction_reference", "read_or_verified_by_this_invocation", True),
        ]
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                changed = deepcopy(record)
                changed[section][key] = value
                changed["report_sha256"] = scope.digest({k: v for k, v in changed.items() if k != "report_sha256"})
                with self.assertRaisesRegex(ValueError, "REBUILD_MISMATCH"):
                    scope.verify_report(changed)
        changed = deepcopy(record)
        changed["source_sha256"][scope.OWN_PATH] = "0" * 64
        with self.assertRaisesRegex(ValueError, "REBUILD_MISMATCH"):
            scope.verify_report(changed)
        changed = deepcopy(record)
        changed["accounting"]["complete_quantum_cost"]["per_grover_iteration"]["gate_count"] -= 1
        with self.assertRaisesRegex(ValueError, "REBUILD_MISMATCH"):
            scope.verify_report(changed)

    def test_forged_predicate_or_injected_native_flag_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, "PREDICATE_REQUIRED"):
            scope.build_report(request(), fixture().spec(), "native-verified")
        with self.assertRaisesRegex(ValueError, "SPEC_REQUIRED"):
            scope.build_report(request(), predicate="full")
        with self.assertRaisesRegex(ValueError, "SPEC_SCHEMA"):
            scope.build_report(request(), {**fixture().spec(), "native_verified": True}, "full")
        with self.assertRaisesRegex(ValueError, "PREDICATE_REQUIRED"):
            scope.build_report(request(), fixture().spec())

    def test_source_change_during_report_fails_closed(self):
        original = scope.source_fingerprint(None)
        changed = {**original, scope.OWN_PATH: "0" * 64}
        with patch.object(scope, "source_fingerprint", side_effect=[original, changed]):
            with self.assertRaisesRegex(ValueError, "SOURCE_CHANGED_DURING_REPORT"):
                scope.build_report(request())

    def test_json_and_output_refuse_ambiguity_and_overwrite(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.0}',
                    ('{"x":' + str(1 << 256) + '}').encode()):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                scope.strict_load(raw)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            record = scope.build_report(request())
            scope.write_atomic(path, record)
            original = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "OUTPUT_EXISTS"):
                scope.write_atomic(path, record)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(scope.verify_report(scope.strict_load(scope.read(path)))["result"], "REBUILD_MATCH")


if __name__ == "__main__":
    unittest.main(verbosity=2)
