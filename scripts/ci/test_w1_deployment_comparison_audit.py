#!/usr/bin/env python3
"""Adversarial retained-evidence tests; fixtures are not proofs or process facts."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "audit_w1_deployment_comparison.py"
spec = importlib.util.spec_from_file_location("w1_comparison_audit", SOURCE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(root, receipt="2" * 64):
    root.mkdir()
    ids = {name + "_sha256": str(index) * 64 for index, name in
           enumerate(("verifier", "receipt", "input", "header", "expected_artifacts"), 1)}
    ids["receipt_sha256"] = receipt
    ids.update(verifier_bytes=100, receipt_bytes=20, input_bytes=10,
               header_bytes=318, expected_artifacts_bytes=64, journal_sha256="6" * 64)
    resource = {"boot_id": "fixture-boot", "hostname": "fixture-host", "cpu_affinity": [2, 3],
                "cgroup_membership": "0::/fixture-only\n", "same_supervisor": True,
                "same_verifier_binary": True, "same_original_deadline_supplied": True,
                "task_exclusive_resource_ownership_established": False}
    order = ["native", "proof", "proof", "native"] * 2
    report = {"schema": audit.COMPARISON, "operation_complete": True, "error": None,
              "deadline_exhausted_at_snapshot": False, "fresh_proof_generations": 0,
              "independent_receipts": 1, "admission_authorized": False, "production_qualified": False,
              "cryptographic_security_qualified": False, "original_business_budget_reproduced": False,
              "planned_order": order, "identities": ids, "resource_observation": resource,
              "original_deadline_clock_boot_id": "fixture-boot", "started_monotonic": 1.0,
              "original_deadline_monotonic": 100.0, "rows": []}
    intent = {"schema": audit.COMPARISON, "planned_order": order,
              "identities": {k: v for k, v in ids.items() if k != "journal_sha256"},
              "resource_observation": resource, "deadline_monotonic": 100.0, "deadline_boot_id": "fixture-boot"}
    write(root / "intent.json", intent)
    for i, (kind, inner) in enumerate(zip(order, [2, 12, 20, 4, 3, 24, 32, 5])):
        stage_root = root / f"row-{i:04d}-{kind}"
        stage_root.mkdir()
        value = {"fixture": "not-a-proof", "schema": "TRNM-W1-V2-NATIVE-ONCE1" if kind == "native" else "TRNM-W1-V2-FULL-VERIFY1",
                 "profile_id": audit.PROFILE, "iterations": 1, "admission_authorized": False,
                 "header_sha256": ids["header_sha256"], "expected_artifacts_sha256": ids["expected_artifacts_sha256"],
                 "journal_sha256": ids["journal_sha256"], "work_id": "7" * 64}
        if kind == "native":
            value.update(input_sha256=ids["input_sha256"], input_bytes=10,
                         full_replay_calls=1, full_native_verify_ns=[inner * 1000000])
        else:
            value.update(receipt_sha256=receipt, receipt_bytes=20,
                         independent_proof_trials=1, decode_and_verify_ns=[inner * 1000000])
        stage = {"schema": "TRNM-W1-STAGE-MEASUREMENT3", "returncode": 0, "stage_process_complete": True,
                 "error": None, "canceled_signal": None, "cancellation_event": None, "termination_reasons": [],
                 "timed_out": False, "deadline_exhausted_at_snapshot": False,
                 "completion_observed_before_deadline": True, "owned_session_observation_complete": True,
                 "process_group_remaining_after_child_exit": False, "final_owned_session_members": [],
                 "final_known_group_probes": [{"group": 100 + i, "state": "ABSENT"}],
                 "started_monotonic": 2.0 + i, "wall_seconds": .2, "effective_deadline_monotonic": 100.0,
                 "observer_boot_id": "fixture-boot", "environment": {"RAYON_NUM_THREADS": "2"},
                 "rusage": {"user_seconds": .01, "system_seconds": .001}}
        stage["stdout_sha256"] = write(stage_root / "stdout.log", value)
        write(stage_root / "result.json", stage)
        row = {"index": i, "kind": kind, "dispatched": True, "accepted": True,
               "observation_error": None, "stage": stage, "verifier_report": value, "inner_ns": inner * 1000000}
        write(root / f"row-{i:04d}-observation.json", row)
        report["rows"].append(row)
    cost = {}
    for kind in ("native", "proof"):
        values = [row["inner_ns"] for row in report["rows"] if row["kind"] == kind]
        cost[kind] = {"verifier_inner_ns": audit.descriptive(values), "cold_process_wall_seconds": audit.descriptive([.2] * 4),
                      "wait4_cpu_seconds": audit.descriptive([.011] * 4)}
    cost.update(proof_over_native_inner_median=22 / 3.5, proof_over_native_cold_wall_median=1,
                receipt_over_native_payload_bytes=2, verification_inner_benefit_observed=False,
                cold_process_benefit_observed=False, payload_byte_benefit_observed=False)
    report["cost_comparison"] = cost
    return report, write(root / "result.json", report)


def sync_row(root, report, index):
    row = report["rows"][index]
    stage_root = root / f"row-{index:04d}-{row['kind']}"
    row["stage"]["stdout_sha256"] = write(stage_root / "stdout.log", row["verifier_report"])
    write(stage_root / "result.json", row["stage"])
    write(root / f"row-{index:04d}-observation.json", row)
    return write(root / "result.json", report)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "arm-1"
        self.report, self.pin = fixture(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def run_audit(self, pin=None):
        return audit.audit([(self.root / "result.json", pin or self.pin)])

    def test_block_contrast_uses_each_abba_block_not_ratio_of_marginal_medians(self):
        result = self.run_audit()
        arm = result["arms"][0]
        self.assertAlmostEqual(arm["recomputed_cost"]["proof_over_native_inner_median"], 44 / 7)
        self.assertAlmostEqual(arm["block_contrasts"]["proof_over_native_mean"]["median"], 37 / 6)
        self.assertEqual(arm["block_contrasts"]["proof_minus_native_mean_ns"]["median"], 18500000)
        self.assertEqual(result["accepted_verification_rows"], 8)
        self.assertEqual(result["fresh_proof_generations"], 0)
        self.assertIsNone(result["gpu_ns"])
        for key in ("causal_speedup_established", "population_tail_established", "resource_billing_complete",
                    "full_process_tree_reaping_established", "generation_schemes_compared"):
            self.assertIs(result[key], False)

    def test_two_receipts_do_not_become_sixteen_fresh_generations(self):
        other = self.base / "arm-2"
        _, pin = fixture(other, "8" * 64)
        result = audit.audit([(self.root / "result.json", self.pin), (other / "result.json", pin)])
        self.assertEqual(result["distinct_receipt_byte_identities"], 2)
        self.assertEqual(result["accepted_verification_rows"], 16)
        self.assertEqual(result["fresh_proof_generations"], 0)

    def test_wrong_digest_and_duplicate_reports_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.run_audit("0" * 64)
        with self.assertRaisesRegex(ValueError, "duplicate comparison"):
            audit.audit([(self.root / "result.json", self.pin)] * 2)

    def test_raw_stdout_replacement_invalidates_embedded_evidence(self):
        path = self.root / "row-0001-proof/stdout.log"
        value = json.loads(path.read_text())
        value["decode_and_verify_ns"] = [1]
        write(path, value)
        with self.assertRaisesRegex(ValueError, "retained raw bytes"):
            self.run_audit()

    def test_relabeling_or_dropping_rows_does_not_pass_acceptance_booleans(self):
        for mutation in (lambda r: r["rows"].reverse(), lambda r: r["rows"].pop(),
                         lambda r: r["rows"][0].update(index=True)):
            report = copy.deepcopy(self.report)
            mutation(report)
            pin = write(self.root / "result.json", report)
            with self.assertRaises(ValueError):
                self.run_audit(pin)

    def test_forged_aggregate_is_recomputed_and_rejected(self):
        self.report["cost_comparison"]["proof_over_native_inner_median"] = .01
        pin = write(self.root / "result.json", self.report)
        with self.assertRaisesRegex(ValueError, "aggregate value mismatch"):
            self.run_audit(pin)

    def test_linked_records_still_reject_profile_source_count_and_clock_drift(self):
        mutations = [
            ("verifier_report", "independent_proof_trials", True),
            ("verifier_report", "receipt_sha256", "9" * 64),
            ("verifier_report", "work_id", "a" * 64),
            ("stage", "returncode", False),
            ("stage", "observer_boot_id", "other-boot"),
            ("stage", "effective_deadline_monotonic", 200.0),
            ("stage", "environment", {"RAYON_NUM_THREADS": "8"}),
            ("stage", "cancellation_event", {"signal": 15}),
            ("stage", "final_owned_session_members", [{"pid": 99}]),
            ("stage", "started_monotonic", 1.1),
        ]
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                report = copy.deepcopy(self.report)
                report["rows"][1][section][key] = value
                pin = sync_row(self.root, report, 1)
                with self.assertRaises(ValueError):
                    self.run_audit(pin)
        sync_row(self.root, self.report, 1)

    def test_intent_mismatch_and_late_cancel_prevent_complete_audit(self):
        path = self.root / "intent.json"
        intent = json.loads(path.read_text())
        intent["deadline_monotonic"] = 200
        write(path, intent)
        with self.assertRaisesRegex(ValueError, "prior comparison intent"):
            self.run_audit()
        write(self.root / "operation-cancellation.json", {"after_snapshot": True})
        with self.assertRaisesRegex(ValueError, "cancellation sidecar"):
            self.run_audit()

    def test_nonfinite_duplicate_keys_and_symlink_fail_closed(self):
        path = self.base / "invalid.json"
        for raw in ('{"a":1,"a":2}', '{"nested":{"value":1e999}}', '{"a":NaN}'):
            path.write_text(raw)
            with self.assertRaises(ValueError):
                audit.read_record(path)
        path.unlink()
        path.symlink_to(self.root / "result.json")
        with self.assertRaisesRegex(ValueError, "regular evidence"):
            audit.read_record(path)

    def test_caller_cannot_omit_independent_report_pin(self):
        for pin in (None, False, 0, "", "a" * 63, "A" * 64):
            with self.subTest(pin=pin), self.assertRaisesRegex(ValueError, "SHA-256 required"):
                audit.audit([(self.root / "result.json", pin)])

    def test_raw_record_boolean_and_float_aliases_do_not_match_pinned_integers(self):
        path = self.root / "row-0000-observation.json"
        mutations = [("index", False), ("dispatched", 1), ("accepted", 1),
                     ("inner_ns", float(self.report["rows"][0]["inner_ns"]))]
        for key, value in mutations:
            row = copy.deepcopy(self.report["rows"][0])
            row[key] = value
            write(path, row)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "retained raw bytes"):
                self.run_audit()
        write(path, self.report["rows"][0])

    def test_intent_type_aliases_cannot_replace_original_declaration(self):
        path = self.root / "intent.json"
        original = json.loads(path.read_text())
        for change in (lambda r: r["identities"].update(header_bytes=318.0),
                       lambda r: r["resource_observation"].update(task_exclusive_resource_ownership_established=0),
                       lambda r: r.update(deadline_monotonic=100)):
            intent = copy.deepcopy(original)
            change(intent)
            write(path, intent)
            with self.assertRaisesRegex(ValueError, "prior comparison intent"):
                self.run_audit()
        write(path, original)

    def test_utf16_and_utf32_do_not_become_utf8_evidence(self):
        path = self.base / "encoded.json"
        for encoding in ("utf-16", "utf-32"):
            path.write_bytes('{"x":1}'.encode(encoding))
            with self.subTest(encoding=encoding), self.assertRaises(ValueError):
                audit.read_record(path)
        self.assertIs(audit.finite(10 ** 400), False)

    def test_fifo_evidence_cannot_block_the_bounded_reader(self):
        path = self.base / "fifo"
        os.mkfifo(path)
        command = ("import sys;sys.path.insert(0,sys.argv[1]);"
                   "import audit_w1_deployment_comparison as m;"
                   "\ntry:m.read_record(sys.argv[2])"
                   "\nexcept ValueError:sys.exit(0)"
                   "\nelse:sys.exit(1)")
        observed = subprocess.run([sys.executable, "-c", command, str(SOURCE.parent), str(path)],
                                  capture_output=True, text=True, timeout=2)
        self.assertEqual(observed.returncode, 0, observed.stderr)

    def test_late_cancellation_after_arm_read_prevents_audit_completion(self):
        original = audit.audit_comparison
        def inspect_then_cancel(*args):
            value = original(*args)
            write(self.root / "operation-cancellation.json", {"after_arm_read": True})
            return value
        with patch.object(audit, "audit_comparison", inspect_then_cancel):
            with self.assertRaisesRegex(ValueError, "cancellation sidecar"):
                self.run_audit()

    def test_dangling_cancellation_paths_are_not_absence(self):
        for path in (self.root / "operation-cancellation.json",
                     self.root / "row-0001-proof/operation-cancellation.json"):
            path.symlink_to(self.base / "missing-target")
            with self.assertRaisesRegex(ValueError, "cancellation sidecar"):
                self.run_audit()
            path.unlink()

    def test_raw_change_after_arm_read_prevents_audit_completion(self):
        original = audit.audit_comparison
        def inspect_then_change(*args):
            value = original(*args)
            path = self.root / "row-0001-proof/stdout.log"
            path.write_text(path.read_text() + " ")
            return value
        with patch.object(audit, "audit_comparison", inspect_then_change):
            with self.assertRaises(ValueError):
                self.run_audit()

    def test_exclusive_resource_claim_is_not_inherited_from_retained_records(self):
        self.report["resource_observation"]["task_exclusive_resource_ownership_established"] = True
        path = self.root / "intent.json"
        intent = json.loads(path.read_text())
        intent["resource_observation"] = self.report["resource_observation"]
        write(path, intent)
        pin = write(self.root / "result.json", self.report)
        with self.assertRaisesRegex(ValueError, "recorded supervisor"):
            self.run_audit(pin)

    def test_aggregate_cardinality_requires_an_integer(self):
        self.report["cost_comparison"]["native"]["verifier_inner_ns"]["count"] = 4.0
        pin = write(self.root / "result.json", self.report)
        with self.assertRaisesRegex(ValueError, "count must be an integer"):
            self.run_audit(pin)

    def test_existing_output_is_never_overwritten(self):
        with self.assertRaisesRegex(ValueError, "output already exists"):
            audit.main(["--comparison", str(self.root / "result.json"), self.pin,
                        "--out", str(self.root / "result.json")])
        self.assertEqual(hashlib.sha256((self.root / "result.json").read_bytes()).hexdigest(), self.pin)


if __name__ == "__main__":
    unittest.main()
