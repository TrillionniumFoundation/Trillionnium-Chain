"""Harness contract tests; synthetic records are never W1 execution evidence."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "run_receiver_comparison.py"
SPEC = importlib.util.spec_from_file_location("receiver_comparison", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def kernel():
    return {"errors": [], "cgroup_relative": "/test", "affinity": [0],
            "lineage": [{"path": "/sys/fs/cgroup/test", "limits": {
                "cpu.max": "25000 100000", "memory.max": "2147483648",
                "memory.swap.max": "0", "pids.max": "256"}}]}


def measured(result, wall=1.0, cpu=0.25):
    return {"exit_code": 0, "timed_out": False, "receipt_error": None,
            "receipt": {"result": result, "outer_seconds": wall / 2},
            "wall_seconds": wall, "user_seconds": cpu * 0.8,
            "system_seconds": cpu * 0.2, "cpu_seconds": cpu, "peak_rss_kib": 12,
            "kernel_before": kernel(), "kernel_child_before_exec": kernel(),
            "kernel_after": kernel()}


def contract():
    phase_names = {
        "N": ("output_directory_create", "native_input_read_binding", "node_open_recovery",
              "node_current_context_and_before_observation", "native_admission",
              "native_activation", "native_readback"),
        "P": ("proof_start_owner_open_and_reserve", "output_directory_create",
              "proof_input_read_binding", "proof_bundle_persistence", "complete_proof_verification",
              "node_open_recovery", "node_before_observation", "node_admission_activation_readback",
              "post_admission_readback", "proof_start_owner_snapshot"),
    }
    identity = {"operator_plan_sha256": "11" * 32, "packet_sha256": "22" * 32, "packet_bytes": 49_600}
    plan = {"input_identity": identity, "application_payload_bytes": {"N": 49_600, "P": 4_023_956},
            "genesis": "33" * 32, "cpu_affinity": [0],
            "proof_start_policy": {"owner_id": "44" * 32},
            "expected_kernel_limits": {"cpu.max": "25000 100000", "memory.max": "2147483648"},
            "planned_order": [{"index": i, "variant": v} for i, v in enumerate(MODULE.ORDER)]}
    owner = {"owner_id": "44" * 32, "maximum_starts": 4, "occupied_slots": 0, "exhausted": False}
    before = {"owner": owner, "qualification": "HOLD_NO_GO", "production_activation": False}
    after = copy.deepcopy(before)
    after["owner"].update(occupied_slots=4, exhausted=True)
    rows = []
    slot = 0
    for index, variant in enumerate(MODULE.ORDER):
        outcome = {"block": "55" * 32, "native_admitted": True, "native_admission_path_invoked": True,
                   "activation_requested": True, "activation_error": None, "late_cancellation": None,
                   "active_before": plan["genesis"], "generation_before": 0,
                   "native_observation": {"stored_exact": True, "active_chain_member": True},
                   "native_observation_error": None, "native_admission_seconds": 0.01}
        common = {"input_identity": identity, "qualification": "HOLD_NO_GO", "production_activation": False,
                  "node_opened": True,
                  "metrics": {"schema": "trnm-w1-receiver-metrics-v1", "mode": "native" if variant == "N" else "proof-plus-native",
                              "payload_bytes": plan["application_payload_bytes"][variant], "phases_are_disjoint": True,
                              "phases": [{"stage": name, "wall_seconds": 0.01, "outcome": "ok"}
                                         for name in phase_names[variant]]}}
        if variant == "N":
            result = {**common, **outcome, "schema": "trnm-w1-node-native-admit-v1", "both_real_proofs_verified": False}
        else:
            slot += 1
            reservation = {"slot": slot, "purpose": "admission", "reserved_before_work": True}
            outcome.update(schema="trnm-w1-node-adapter-admission-v3", both_real_proofs_verified=True,
                           proof_start=reservation)
            result = {**common, "schema": "trnm-w1-node-adapter-exercise-v2", "requested_cancellation": "none",
                      "outcome": outcome, "error": None, "proof_start": reservation,
                      "proof_start_owner_snapshot": {"occupied_slots": slot}, "proof_start_owner_snapshot_error": None}
        rows.append({"index": index, "variant": variant, "fresh_output_directory": True,
                     "expected_proof_slot": slot if variant == "P" else None,
                     "measurement": measured(result, 0.2 if variant == "N" else 1.2)})
    return {"plan": plan, "receivers": rows, "owner_init": measured(before, wall=8.0),
            "owner_status": measured(after, wall=0.4), "source_before": {"test_only": "frozen"},
            "source_after": {"test_only": "frozen"}, "fatal_errors": []}


class ComparisonContractTests(unittest.TestCase):
    def test_complete_local_observation_never_claims_end_to_end_or_new_proofs(self):
        summary = MODULE.summarize(contract())
        self.assertEqual(summary["local_receiver_comparison"], "PASS")
        self.assertEqual(summary["end_to_end_benefit"], "NOT_MEASURED")
        self.assertIsNone(summary["receiver_count_break_even"])
        self.assertEqual(summary["new_complete_proofs"], 0)
        self.assertEqual(summary["distinct_input_tasks"], 1)
        self.assertEqual(summary["qualification"], "HOLD_NO_GO")
        self.assertFalse(summary["network_transport_measured"])
        self.assertFalse(summary["production_activation"])

    def test_exit_zero_with_exercise_error_is_not_success(self):
        data = contract()
        data["receivers"][1]["measurement"]["receipt"]["result"].update(error="ordinary I/O error", outcome=None)
        result = MODULE.summarize(data)
        self.assertNotEqual(result["local_receiver_comparison"], "PASS")
        self.assertIsNone(result["medians"])
        self.assertTrue(any("exit zero" in item for item in result["errors"]))

    def test_changed_identity_or_same_size_wrong_payload_refuses_comparison(self):
        for kind in ("identity", "payload"):
            data = contract()
            result = data["receivers"][1]["measurement"]["receipt"]["result"]
            if kind == "identity":
                result["input_identity"] = dict(result["input_identity"], packet_sha256="66" * 32)
            else:
                result["metrics"]["payload_bytes"] -= data["plan"]["input_identity"]["packet_bytes"]
            self.assertNotEqual(MODULE.summarize(data)["local_receiver_comparison"], "PASS", kind)

    def test_proof_reservation_remains_charged_and_bound(self):
        for field in ("slot", "purpose", "reserved_before_work"):
            data = contract()
            reservation = data["receivers"][1]["measurement"]["receipt"]["result"]["proof_start"]
            reservation[field] = {"slot": 2, "purpose": "reopen_observation", "reserved_before_work": False}[field]
            self.assertNotEqual(MODULE.summarize(data)["local_receiver_comparison"], "PASS", field)

    def test_owner_provisioning_is_retained_separately_from_receiver_medians(self):
        summary = MODULE.summarize(contract())
        self.assertEqual(summary["owner_costs"]["provisioning"]["wall_seconds"], 8.0)
        self.assertEqual(summary["medians"]["N"]["wall_seconds"], 0.2)
        self.assertEqual(summary["medians"]["P"]["wall_seconds"], 1.2)
        self.assertEqual(summary["medians"]["N"]["fresh_receiver_processes"], 4)
        data = contract()
        data["owner_status"]["receipt"]["result"]["owner"]["occupied_slots"] = 3
        self.assertNotEqual(MODULE.summarize(data)["local_receiver_comparison"], "PASS")

    def test_missing_duplicate_or_reordered_attempt_cannot_use_success_subset(self):
        for mutation in ("missing", "duplicate", "reordered"):
            data = contract()
            if mutation == "missing":
                data["receivers"].pop()
            elif mutation == "duplicate":
                data["receivers"].append(copy.deepcopy(data["receivers"][0]))
            else:
                data["receivers"][0], data["receivers"][1] = data["receivers"][1], data["receivers"][0]
            summary = MODULE.summarize(data)
            self.assertNotEqual(summary["local_receiver_comparison"], "PASS", mutation)
            self.assertIsNone(summary["medians"])

    def test_changed_kernel_limit_or_affinity_is_incomparable(self):
        for mutation in ("cpu", "ancestor", "affinity", "missing"):
            data = contract()
            value = data["receivers"][1]["measurement"]["kernel_child_before_exec"]
            if mutation == "cpu":
                value["lineage"][0]["limits"]["cpu.max"] = "max 100000"
            elif mutation == "ancestor":
                value["lineage"].append({"path": "/sys/fs/cgroup", "limits": {"memory.max": "1024"}})
            elif mutation == "affinity":
                value["affinity"] = [0, 1]
            else:
                value["errors"] = ["readback unavailable"]
            self.assertNotEqual(MODULE.summarize(data)["local_receiver_comparison"], "PASS", mutation)

    def test_failed_or_timed_out_process_remains_in_denominator(self):
        for field, value in (("exit_code", 2), ("timed_out", True), ("receipt_error", "missing last record")):
            data = contract()
            data["receivers"][1]["measurement"][field] = value
            summary = MODULE.summarize(data)
            self.assertEqual(summary["recorded_receiver_processes"], 8)
            self.assertNotEqual(summary["local_receiver_comparison"], "PASS")
            self.assertIsNone(summary["medians"])

    def test_same_native_block_fresh_node_and_actual_activation_required(self):
        for mutation in ("block", "fresh", "generation", "activation"):
            data = contract()
            row = data["receivers"][0]
            result = row["measurement"]["receipt"]["result"]
            if mutation == "block":
                result["block"] = "66" * 32
            elif mutation == "fresh":
                row["fresh_output_directory"] = False
            elif mutation == "generation":
                result["generation_before"] = 1
            else:
                result["native_observation"]["active_chain_member"] = False
            self.assertNotEqual(MODULE.summarize(data)["local_receiver_comparison"], "PASS", mutation)

    def test_source_drift_and_nonfinite_or_boolean_metrics_are_not_passes(self):
        data = contract()
        data["source_after"] = {"test_only": "changed"}
        self.assertNotEqual(MODULE.summarize(data)["local_receiver_comparison"], "PASS")
        for bad in (float("nan"), float("inf"), -1, True):
            data = contract()
            data["receivers"][0]["measurement"]["wall_seconds"] = bad
            self.assertNotEqual(MODULE.summarize(data)["local_receiver_comparison"], "PASS")

    def test_duplicate_json_keys_and_nonfinite_constants_are_rejected(self):
        for text in ('{"result":{},"result":{}}', '{"wall":NaN}', '{"wall":Infinity}'):
            with self.assertRaises(ValueError):
                MODULE.strict_json(text)

    def test_whole_process_median_is_not_reconstructed_from_phase_medians(self):
        data = contract()
        for index, row in enumerate(data["receivers"]):
            if row["variant"] == "N":
                row["measurement"]["wall_seconds"] = [0.5, 3.5, 4.5, 8.5][(0, 3, 4, 7).index(index)]
                phases = row["measurement"]["receipt"]["result"]["metrics"]["phases"]
                phases[0]["wall_seconds"] = 0.001
        summary = MODULE.summarize(data)
        self.assertEqual(summary["medians"]["N"]["wall_seconds"], 4.0)

    def test_missing_duplicate_or_reordered_phase_is_not_complete(self):
        for variant in ("N", "P"):
            for mutation in ("missing", "duplicate", "reordered"):
                data = contract()
                row = next(row for row in data["receivers"] if row["variant"] == variant)
                phases = row["measurement"]["receipt"]["result"]["metrics"]["phases"]
                if mutation == "missing":
                    phases.pop()
                elif mutation == "duplicate":
                    phases.append(copy.deepcopy(phases[0]))
                else:
                    phases[0], phases[1] = phases[1], phases[0]
                self.assertNotEqual(MODULE.summarize(data)["local_receiver_comparison"], "PASS",
                                    variant + " " + mutation)

    def test_disjoint_phase_and_outer_clocks_must_have_consistent_boundaries(self):
        for changed_clock in (0.001, 2.0):
            data = contract()
            data["receivers"][0]["measurement"]["receipt"]["outer_seconds"] = changed_clock
            summary = MODULE.summarize(data)
            self.assertNotEqual(summary["local_receiver_comparison"], "PASS")
            self.assertIsNone(summary["medians"])

    def test_kill_before_setsid_falls_back_only_to_owned_unreaped_pid(self):
        # Mock only the OS sends; no signal is sent to an unrelated process.
        with mock.patch.object(MODULE.os, "killpg", side_effect=ProcessLookupError) as group, \
             mock.patch.object(MODULE.os, "kill") as child:
            MODULE.kill_owned_child(12345)
            group.assert_called_once_with(12345, MODULE.signal.SIGKILL)
            child.assert_called_once_with(12345, MODULE.signal.SIGKILL)
        with mock.patch.object(MODULE.os, "killpg") as group, \
             mock.patch.object(MODULE.os, "kill") as child:
            MODULE.kill_owned_child(12345)
            group.assert_called_once_with(12345, MODULE.signal.SIGKILL)
            child.assert_not_called()
        with mock.patch.object(MODULE.os, "killpg", side_effect=ProcessLookupError), \
             mock.patch.object(MODULE.os, "kill", side_effect=ProcessLookupError):
            MODULE.kill_owned_child(12345)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux wait4 test")
class ProcessMeasurementTests(unittest.TestCase):
    def test_real_child_failure_keeps_raw_streams_and_rusage(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            record = MODULE.measure(
                [sys.executable, "-c", "import sys; print('kept stdout'); print('kept stderr', file=sys.stderr); sys.exit(7)"],
                directory / "attempt", dict(os.environ), directory, 5.0)
            self.assertEqual(record["exit_code"], 7)
            self.assertFalse(record["timed_out"])
            self.assertEqual((directory / "attempt/stdout.jsonl").read_text(), "kept stdout\n")
            self.assertIn("kept stderr", (directory / "attempt/stderr.txt").read_text())
            self.assertGreater(record["wall_seconds"], 0)
            self.assertGreater(record["cpu_seconds"], 0)
            self.assertGreater(record["peak_rss_kib"], 0)
            self.assertIsNotNone(record["receipt_error"])
            self.assertEqual(record["kernel_child_before_exec"]["pid"], record["pid"])
            saved = json.loads((directory / "attempt/measurement.json").read_text())
            self.assertEqual(saved["stdout"]["sha256"], MODULE.sha(directory / "attempt/stdout.jsonl"))

    def test_benign_sleep_timeout_is_not_relabelled_a_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            record = MODULE.measure(
                [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(5)"],
                directory / "attempt", dict(os.environ), directory, 0.15)
            self.assertTrue(record["timed_out"])
            self.assertEqual(record["exit_code"], -9)
            self.assertIsNone(record["receipt"])
            self.assertIsNotNone(record["timeout_request_monotonic_ns"])
            self.assertGreaterEqual(record["timeout_cleanup_seconds"], 0)
            # Shared-host scheduling may consume the timeout before exec/print.
            # An empty log is retained evidence of unknown progress, not an
            # invented successful start or a completed cryptographic rejection.
            raw_stdout = (directory / "attempt/stdout.jsonl").read_bytes()
            self.assertIn(raw_stdout, (b"", b"started\n"))
            self.assertEqual(record["stdout"]["bytes"], len(raw_stdout))
            self.assertEqual(record["stdout"]["sha256"], MODULE.sha(directory / "attempt/stdout.jsonl"))


if __name__ == "__main__":
    unittest.main()
