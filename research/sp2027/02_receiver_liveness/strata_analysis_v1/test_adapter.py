"""Synthetic contract tests; these inputs are not native experimental records."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import adapter

spec = importlib.util.spec_from_file_location("sp27_strata_audit_test", adapter.HERE.parent / "audit_strata_ci.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def fixture():
    runner = audit.load_runner()
    plan = runner.planned_phases()
    lib = adapter.reader().load_frozen("legacy")
    packets = []
    for index in range(7):
        header = b"PNH1" + bytes([index]) + bytes(313)
        transactions = b"\x01\x00" + (159).to_bytes(2, "little") + bytes(159) if index == 0 else b"\x00\x00"
        packets.append((header + transactions + b"PNW1" + bytes(49184)).hex())
    acquisition = {"schema": "sp27-receiver-seven-packet-acquisition-v1", "signed_honest_packets": packets,
                   "packet_ids": [lib.decode_packet_fields(wire)["id"] for wire in packets]}
    identity = adapter.business_identity(acquisition)
    raw = {"business_started_ns": 10, "confirmation_ended_ns": adapter.WINDOW_NS - 1,
        "client_confirmed_before_original_window_end": True,
        "independent_client_confirmation": {"confirmed": True, "transaction": identity["transaction_id"],
            "included_block": identity["expected_block_id"], "policy": "installed-depth-and-required-work",
            "depth": 6, "required_work_delta": "0c", "work_delta": "0c", "execution_authority": False,
            "finalized": False, "reorged": False},
        "independent_final_confirmation_stage": {"observation_returned": True,
            "confirmation_started_ns": 20, "confirmation_ended_ns": 30},
        "independent_history_page_replay": [{"replay_accepted": True, "replay_error": None,
                                           "native_import_observation": {"synthetic_test_only": True}}]}
    row = {**plan[0], "completed": True, "attempted": True, "host_before_verified": True, "host_after_verified": True}
    prepared = {"source_before": {"commit": "a" * 40, "tree": "b" * 40}, "binary": {"sha256": "c" * 64}}
    return plan, {"qualification": "NO_GO", "phases": [row]}, {plan[0]["phase_id"]: raw}, acquisition, prepared, {
        plan[0]["phase_id"]: {"member": "synthetic/health-000.json", "sha256": "d" * 64}}


class AdapterTests(unittest.TestCase):
    def consume(self, values=None, accepted=True):
        return adapter.build_export(*(values or fixture()), accepted, "synthetic-only", synthetic=True)

    def health_operation(self, result):
        return next(row for row in result["analyzed"]["operations"] if row["run_id"].endswith("/health-000"))

    def test_t_minus_one_and_unstarted_denominator_really_consumed(self):
        result = self.consume()
        ops = result["analyzed"]["operations"]
        self.assertEqual(len(ops), 13)
        self.assertEqual(sum(row["confirmed_in_window"] for row in ops), 1)
        self.assertEqual(sum(row["outcome"] == "unstarted" for row in ops), 12)
        self.assertTrue(all(row["scheduled_ns"] is None for row in result["schedule"]))
        self.assertEqual(result["contract"]["evidence_scope"], "synthetic_validation")

    def test_t_and_t_plus_one_with_false_gate_are_late_not_timely(self):
        for end in (adapter.WINDOW_NS, adapter.WINDOW_NS + 1):
            values = fixture()
            raw = next(iter(values[2].values()))
            raw["confirmation_ended_ns"], raw["client_confirmed_before_original_window_end"] = end, False
            op = self.health_operation(self.consume(values))
            self.assertFalse(op["confirmed_in_window"])
            self.assertEqual(op["outcome"], "late_confirmed")

    def test_endpoint_below_t_false_native_gate_stays_unconfirmed(self):
        values = fixture()
        next(iter(values[2].values()))["client_confirmed_before_original_window_end"] = False
        op = self.health_operation(self.consume(values))
        self.assertEqual(op["outcome"], "unconfirmed")
        self.assertTrue(op["native_window_gate_failed"])
        self.assertFalse(op["confirmed_in_window"])

    def test_true_native_gate_at_t_refused(self):
        values = fixture()
        next(iter(values[2].values()))["confirmation_ended_ns"] = adapter.WINDOW_NS
        with self.assertRaisesRegex(ValueError, "NATIVE_GATE_CLOCK_CONTRADICTION"):
            self.consume(values)

    def test_positive_ack_cannot_substitute_native_replay(self):
        values = fixture()
        next(iter(values[2].values()))["independent_history_page_replay"] = []
        with self.assertRaisesRegex(ValueError, "POSITIVE_INDEPENDENT_NATIVE_IMPORT"):
            self.consume(values)

    def test_positive_summary_without_observation_is_refused(self):
        values = fixture()
        next(iter(values[2].values()))["independent_client_confirmation"] = None
        with self.assertRaisesRegex(ValueError, "NATIVE_GATE_WITHOUT_CONFIRMATION"):
            self.consume(values)

    def test_wrong_prepared_transaction_is_refused(self):
        values = fixture()
        next(iter(values[2].values()))["independent_client_confirmation"]["transaction"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "POSITIVE_PREPARED_TRANSACTION_BLOCK_BINDING"):
            self.consume(values)

    def test_host_attestation_missing_is_refused(self):
        values = fixture()
        values[1]["phases"][0]["host_after_verified"] = None
        with self.assertRaisesRegex(ValueError, "POSITIVE_PHASE_HOST_ATTESTATION"):
            self.consume(values)

    def test_strict_campaign_rejection_blocks_import(self):
        with self.assertRaisesRegex(ValueError, "STRICT_CAMPAIGN_READER_REQUIRED"):
            self.consume(accepted=False)

    def test_attempted_without_raw_is_unknown_not_unstarted(self):
        values = fixture()
        values[1]["phases"][0]["completed"] = False
        values[2].clear()
        op = self.health_operation(self.consume(values))
        self.assertEqual(op["outcome"], "unknown")
        self.assertIsNone(op["request_started_ns"])

    def test_missing_cpu_not_imputed_zero(self):
        values = audit.numeric([10, None, 20])
        self.assertEqual(values["observed_sum"], 30)
        self.assertIsNone(values["complete_sum"])
        self.assertEqual(values["unknown"], 1)
        self.assertIsNone(audit.numeric(None)["observed_sum"])
        self.assertEqual(audit.numeric([])["complete_sum"], 0)

    def test_cache_hit_is_not_native_replay_and_absence_is_unknown(self):
        cached = {"work_rejection": {"completed": True, "cache": {
            "cached_rejection_returned": True, "native_verifier_started": False,
            "native_verifier_returned": False, "full_replay_started": False}}}
        self.assertFalse(audit.replay_state(cached)["full_native_replay"])
        self.assertTrue(audit.replay_state(cached)["cached_rejection_returned"])
        self.assertIsNone(audit.replay_state({"full_work_started": True})["full_native_replay"])

    def test_missing_control_input_map_does_not_create_zero_load_or_cost(self):
        _, result = audit.record_telemetry({"observations": {"records": []}},
                                          "late-reject", None, audit.load_runner())
        self.assertIsNone(result["matched_claimed_body_connections"])
        self.assertIsNone(result["full_native_replays_observed"])
        self.assertIsNone(result["matched_full_work_thread_cpu_ns"]["complete_sum"])

    def test_writer_uses_real_frozen_analyzer_output(self):
        result = self.consume()
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / "consumer"
            adapter.write_export(result, out)
            manifest = json.loads((out / "consumer/validated_input_manifest.json").read_bytes())
            self.assertEqual(manifest["analyzer_sha256"], adapter.ANALYZER_SHA256)
            self.assertEqual(len(manifest["inputs"]), 3)
            with self.assertRaises(FileExistsError):
                adapter.write_export(result, out)

    def test_timeout_missing_report_retains_diagnosis_without_native_fabrication(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            raw = root / "raw"
            (raw / "native/raw").mkdir(parents=True)
            (raw / "native/plan.json").write_text(json.dumps({"synthetic_only": True}))
            (raw / "native/raw/health-000-started.json").write_text(json.dumps({"synthetic_only": True}))
            (raw / "manifest.json").write_text(json.dumps({"process": {"exit_code": -9, "timed_out": True}}))
            out = root / "analysis"
            result = audit.audit(raw, out, "synthetic-timeout-only")
            self.assertEqual(result["analysis_qualification"], "NO_GO")
            self.assertFalse(result["strict_campaign_reader"]["accepted"])
            self.assertEqual(result["frozen_06_consumer"]["status"], "NOT_IMPORTED")
            self.assertIsNone(result["validated_native_counts"]["unstarted_phases"])
            self.assertEqual(result["diagnostic_observed_counts"]["no_start_file_observed"], 12)
            self.assertEqual(result["analysis_first_evidence_gap"]["first_started_without_complete_raw"], "health-000")
            self.assertIsNone(result["native_collector_first_divergence"])
            self.assertTrue(result["outer_execution"]["actual_process_record"]["timed_out"])
            self.assertFalse((raw / "native/report.json").exists())


if __name__ == "__main__":
    unittest.main()
