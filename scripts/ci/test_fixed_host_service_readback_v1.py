#!/usr/bin/env python3
"""Mutation regressions for retained failed F0 evidence, not native benchmarks."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "fixed_host_service_readback_v1",
    ROOT / "formal/pon-nakamoto-v1/experiments/fixed_host_service_readback_v1.py",
)
READER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READER)
SOURCE = ROOT / "evidence/pon-fixed-host-root-f0-b5bb-readback-20261105/analysis.json"


class FixedHostServiceReadback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.retained = READER.load_strict(SOURCE)

    def value(self):
        return copy.deepcopy(self.retained)

    def rejected(self, value, expected):
        result = READER.evaluate(value)
        self.assertFalse(result["evidence_consistent"])
        self.assertEqual(result["original_gate_status"], "INVALID_EVIDENCE")
        self.assertIn(expected, result["evidence_errors"])
        self.assertEqual(len(result["all_planned_rounds"]), 6)
        self.assertEqual(result["planned_business_packet_exposures"], 42)
        self.assertFalse(result["service_qualified"])
        return result

    def test_original_failure_is_consistent_and_not_a_new_run(self):
        result = READER.evaluate(self.retained)
        self.assertTrue(result["evidence_consistent"], result["evidence_errors"])
        self.assertEqual(result["original_gate_status"], "FAIL")
        self.assertEqual(result["next_required_gate"], "BASELINE_MUST_PASS")
        self.assertEqual(result["scheduled_slo_successes"], 0)
        self.assertEqual(result["planned_confirmations"], 6)
        self.assertEqual(result["planned_business_packet_exposures"], 42)
        self.assertEqual(result["new_native_runs"], 0)
        self.assertFalse(result["release_ready"])
        self.assertFalse(result["continuous_novel_attack_service_qualified"])
        self.assertFalse(result["original_issue_639_16_producer_gate_covered"])
        self.assertEqual(result["legal_cheap_work_economics"], "NOT_MEASURED_BY_F0")

    def test_missing_duplicate_and_unknown_round_do_not_reduce_denominator(self):
        for mutation in ("missing", "duplicate", "unknown"):
            with self.subTest(mutation=mutation):
                value = self.value()
                if mutation == "missing":
                    del value["rounds"][0]
                elif mutation == "duplicate":
                    value["rounds"].append(copy.deepcopy(value["rounds"][0]))
                else:
                    value["rounds"][0]["round"] = 8
                self.rejected(value, "baseline:ROUND_ROSTER:0")

    def test_missing_phase_retains_all_exposures(self):
        value = self.value()
        del value["phases"]["valid-work-root"]
        self.rejected(value, "valid-work-root:ORIGINAL_PACKET_DENOMINATOR")

    def test_original_limits_deadline_and_producer_count_are_not_relaxable(self):
        for key, changed in (("four_second_slo_ns", 30_000_000_000),
                             ("phase_seconds", 60), ("attackers", 4),
                             ("round_start_seconds", [2, 6, 10]),
                             ("planned_confirmations", 4),
                             ("planned_business_packets", 24),
                             ("seed_transfers", True)):
            with self.subTest(key=key):
                value = self.value()
                value["inputs"][key] = changed
                self.rejected(value, "ORIGINAL_INPUT:" + key)
        value = self.value()
        value["phases"]["baseline"]["public_host_observations"]["outside-before"]["limits"]["cpu.max"] = "100000 100000"
        self.rejected(value, "baseline:ORIGINAL_HOST:outside-before")

    def test_different_backend_does_not_replace_original_gate(self):
        value = self.value()
        value["phases"]["baseline"]["state_backend"] = "growth-v2"
        self.rejected(value, "baseline:ORIGINAL_BACKEND")

    def test_duration_measured_after_actual_start_cannot_replace_scheduled_time(self):
        value = self.value()
        row = value["rounds"][1]
        row["elapsed_from_scheduled_ns"] = row["actual_ended_ns"] - row["actual_started_ns"]
        self.rejected(value, "baseline:ELAPSED_RECOMPUTATION:1")

    def test_exact_four_second_completion_is_still_a_failure(self):
        value = self.value()
        row = value["rounds"][0]
        row.update(actual_started_ns=1_000_000_000, actual_ended_ns=5_000_000_000,
                   elapsed_from_scheduled_ns=4_000_000_000,
                   confirmed_inside_original_window=True, four_second_slo_met=False)
        result = READER.evaluate(value)
        self.assertTrue(result["evidence_consistent"], result["evidence_errors"])
        self.assertEqual(result["scheduled_slo_successes"], 0)
        self.assertFalse(result["all_planned_rounds"][0]["four_second_slo_met"])

    def test_unobserved_round_cannot_supply_confirmation(self):
        value = self.value()
        row = value["rounds"][4]
        self.assertFalse(row["observed_exactly_once"])
        row["confirmed_inside_original_window"] = True
        self.rejected(value, "valid-work-root:UNOBSERVED_ROUND_HAS_RESULT:1")

    def test_network_ack_does_not_turn_failed_confirmations_green(self):
        value = self.value()
        for phase in value["phases"].values():
            phase["packets"].update(observed_attempts=21, timely_network_ack=21, unobserved=0)
            phase["finite_phase_criteria_met"] = True
        result = READER.evaluate(value)
        self.assertTrue(result["evidence_consistent"], result["evidence_errors"])
        self.assertEqual(result["scheduled_slo_successes"], 0)
        self.assertEqual(result["next_required_gate"], "BASELINE_MUST_PASS")
        self.assertEqual(result["original_gate_status"], "FAIL")

    def test_packet_attempt_and_unobserved_counts_reconcile_to_21(self):
        value = self.value()
        value["phases"]["baseline"]["packets"]["observed_attempts"] = 17
        self.rejected(value, "baseline:PACKET_ATTEMPT_RECONCILIATION")

    def test_changed_source_receipt_and_missing_report_binding_are_rejected(self):
        value = self.value()
        value["bindings"]["source_after"]["sha256"] = "0" * 64
        self.rejected(value, "UNCHANGED_SOURCE_RECEIPTS")
        value = self.value()
        value["finalization"]["denominator"]["report_sha256"] = "0" * 64
        self.rejected(value, "RAW_REPORT_BINDING")

    def test_inflated_final_success_count_is_rejected(self):
        value = self.value()
        value["finalization"]["denominator"]["four_second_slo_successes"] = 6
        self.rejected(value, "FINAL_SLO_COUNT")

    def test_nested_costs_are_preserved_without_addition(self):
        result = READER.evaluate(self.retained)
        costs = result["phase_results"][0]["cost_observations"]
        self.assertEqual(costs["client_import"], self.retained["phases"]["baseline"]["client_import"])
        self.assertEqual(costs["client_host_checks"], self.retained["phases"]["baseline"]["client_host_checks_sum"])
        self.assertEqual(set(costs), {"client_import", "client_host_checks", "native_stages", "overlap_policy"})

    def test_duplicate_and_nonfinite_json_are_rejected(self):
        cases = ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e999}')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for text in cases:
                with self.subTest(text=text):
                    path.write_text(text)
                    with self.assertRaises(ValueError):
                        READER.load_strict(path)
            path.write_bytes(b" " * 1_048_577)
            with self.assertRaisesRegex(ValueError, "READBACK_TOO_LARGE"):
                READER.load_strict(path)


if __name__ == "__main__":
    unittest.main()
