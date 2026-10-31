#!/usr/bin/env python3
"""Recompute bounded diagnostics from original N8 reports, without native work."""

import gzip
import hashlib
import io
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
MAX_ENTRY = 64 * 1024 * 1024
SOURCE = "540d72356a921da31dde1113537382e5c0f0c4fd"
PROFILE = "history-account-graph-resource-fence-v1"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    provenance = json.loads((HERE / "provenance.json").read_text())
    assert provenance["source_commit"] == SOURCE
    entries = {entry["archive_entry"]: entry for entry in provenance["entries"]}
    assert len(entries) == len(provenance["entries"])

    def read(name):
        entry = entries[name]
        path = (HERE / entry["retained_path"]).resolve()
        assert path.is_relative_to(HERE / "original")
        assert path.stat().st_size == entry["compressed_bytes"] <= MAX_ENTRY
        compressed = path.read_bytes()
        assert sha(compressed) == entry["compressed_sha256"]
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            raw = stream.read(MAX_ENTRY + 1)
        assert len(raw) == entry["raw_bytes"] <= MAX_ENTRY
        assert sha(raw) == entry["raw_sha256"]
        return raw

    # Verify every retained entry, including failure logs that are not parsed.
    for name in entries:
        read(name)

    def document(name):
        return json.loads(read(name))

    before = document("source-before.json")
    after = document("source-after-native.json")
    assert before == after
    assert before["tested_commit"] == SOURCE and before["tracked_worktree_verified"] is True
    results = document("results.json")
    assert results["expected_head"] == SOURCE and results["history_resource_profile"] == PROFILE
    assert results["complete_success"] is False
    assert results["failure"] == "ORIGINAL_THREE_RUN_CAMPAIGN_FAILED"
    binary = results["binary"]
    assert binary["sha256_before"] == binary["sha256_after"]
    assert binary["sha256_before"] == document("binary-before.json")["sha256_before"]
    rows = []
    for run in range(1, 4):
        report_name = f"run-{run}-raw/report.json"
        report = document(report_name)
        terminal = document(f"run-{run}-result.json")
        phase_reader = document(f"run-{run}-phase-readback.json")
        verifier_reader = document(f"run-{run}-verifier-readback.json")
        assert terminal["report_sha256"] == entries[report_name]["raw_sha256"]
        assert terminal["report_validation_failure"] is None
        assert terminal["actual_verifier_boundary_readback"] is True
        assert terminal["step"]["returncode"] == 101
        assert terminal["complete_success"] is False and terminal["original_criteria_met"] is False
        assert report["economics_complete"] is True and report["finite_experiment_criteria_met"] is False
        assert report["schema"] == "native-public-pure-history-raw-campaign-v1"
        assert report["work_profile"] == "pure-history-raw-v1"
        assert phase_reader["source_report_sha256"] == entries[report_name]["raw_sha256"]
        assert verifier_reader["complete"] is True and verifier_reader["history_resource_profile"] == PROFILE
        assert [phase["mode"] for phase in report["phases"]] == ["baseline", "from-zero", "late-product"]
        for index, phase in enumerate(report["phases"]):
            mode = phase["mode"]
            actor_count = 0 if mode == "baseline" else 24
            assert phase["history_resource_profile"] == PROFILE
            assert phase["duration_seconds"] == 30
            assert phase["attacker_processes_ready"] == phase["attacker_processes_requested"] == actor_count
            assert phase["all_signed_rounds_confirmed_in_window"] is True
            assert phase["receiver_client_state_equal"] is True
            assert phase["observer_complete"] is True
            assert phase["actor_reports_successful_without_cap_or_kill"] is True
            assert phase["pure_history_acknowledgements_verified"] is True
            assert phase["verifier_errors"] == []
            assert phase["full_work_accepted"] == 21
            assert phase["service_outcome"]["Ok"]["mutation_cpu_clock_failures"] == 0
            assert phase["final_meter"]["in_flight"] == 0
            assert phase["final_meter"]["accounting_unavailable"] is False
            confirmations = phase["confirmations"]
            assert len(confirmations) == 3
            for item in confirmations:
                observed = item["observation"]
                assert item["confirmed_inside_pressure_window"] is True
                assert 0 < item["ended_ns"] < 30_000_000_000
                assert observed["confirmed"] is True and observed["depth"] == 6
                assert observed["finalized"] is False and observed["execution_authority"] is False
            verifier = phase["history_verifier_process"]
            assert verifier["completed_successfully"] is True and verifier["exit_success"] is True
            assert verifier["parent_forced_kill"] is False and verifier["report"]["error"] is None
            assert verifier["parent_after_reap"]["pids.current"] == 0
            native = verifier["report"]["result"]
            assert native["clean_node_close"] is True and native["binary_sha256"] == binary["sha256_before"]
            assert verifier["parent_before_spawn"]["cpu.max"] == "25000 100000"
            graph = native["history_graph_resource"]["counters"]
            assert graph["imports_closed"] == graph["imports"] == 21
            assert graph["imports_failed"] == graph["graph_aborts"] == graph["scope_failures"] == 0
            assert graph["graph_entries"] == graph["graph_exits"] == 249
            assert graph["graph_node_checkpoints"] == graph["graph_completed_node_bodies"] == 370383
            assert graph["graph_full_resource_checks"] == 47076 and graph["kernel_checks"] == 77178
            assert graph["graph_max_node_window"] == 8
            assert graph["kernel_failed_checks"] == graph["kernel_cpu_unknown_calls"] == 0
            assert graph["binding_failed_checks"] == graph["unfinished_scopes"] == 0
            assert sum(call["operation"] == "import" for call in native["calls"]) == 21
            assert sum(call["operation"] == "confirmation" for call in native["calls"]) == 3

            depletion_count, remaining, debit = 0, [], []
            for sample in phase["budget_samples"]:
                observed = sample["meter"]["Ok"]
                flow, meter = observed["actual_flow"], observed["meter"]
                depleted = (flow["remaining_paid_credit_ns"] < 100_000_000
                            and flow["paid_cpu_debit_ns"] > 1_900_000_000
                            and observed["clock_failures"] == 0
                            and meter["accounting_unavailable"] is False)
                assert observed["depleted"] is depleted
                depletion_count += int(depleted)
                remaining.append(flow["remaining_paid_credit_ns"])
                debit.append(flow["paid_cpu_debit_ns"])
            assert depletion_count == 0
            assert phase["genuine_budget_depletion_observed"] is False
            assert phase["depletion_at_ns"] is None
            assert not any(item["paid_credit_depletion_observed_during_round"] for item in confirmations)
            if actor_count:
                assert all(count > 0 for count in phase["attack_calls_overlapping_each_signed_round"])
                assert all(item["receiver_hostile_work_rejected_during_round"] for item in confirmations)
                assert phase["full_work_failed"] > 0
                assert all(call["status"] != "ok" for child in phase["children"]
                           for call in child["report"]["result"]["calls"])
            assert phase["finite_phase_criteria_met"] is (actor_count == 0)
            assert phase_reader["phases"][index]["original_phase_criteria_met"] is (actor_count == 0)
            assert phase_reader["phases"][index]["actual_depletion_samples"] == 0
            assert verifier_reader["phases"][index]["all_ipc_bytes_read_back"] is True
            calls_cpu = sum(call["measurement"]["process_cpu_ns"] for call in native["calls"])
            assert verifier_reader["phases"][index]["call_process_cpu_ns"] == calls_cpu
            rows.append({
                "run": run, "mode": mode,
                "reported_original_phase_criteria_met": phase["finite_phase_criteria_met"],
                "reported_full_state_equality": phase["receiver_client_state_equal"],
                "confirmation_times_ns": [item["ended_ns"] for item in confirmations],
                "confirmation_depths": [item["observation"]["depth"] for item in confirmations],
                "call_process_cpu_ns": calls_cpu,
                "budget_sample_count": len(phase["budget_samples"]),
                "actual_depletion_samples": depletion_count,
                "minimum_observed_paid_credit_ns": min(remaining),
                "maximum_observed_paid_cpu_debit_ns": max(debit),
                "attackers_ready": actor_count,
                "attack_calls_overlapping_each_round": phase["attack_calls_overlapping_each_signed_round"],
                "full_work_accepted": phase["full_work_accepted"],
                "full_work_failed": phase["full_work_failed"],
                "graph_resource_counters": graph,
                "failing_original_requirements": [] if actor_count == 0 else [
                    "observed genuine paid-credit depletion",
                    "paid-credit depletion overlapping at least one signed round",
                ],
            })
    output = {
        "schema": "pon-retained-history-n8-readback-v1",
        "source_commit": SOURCE, "source_tree": before["tested_tree"],
        "workflow_run_id": provenance["workflow_run_id"], "artifact_id": provenance["artifact_id"],
        "archive_sha256": provenance["archive_sha256"], "binary_sha256": binary["sha256_before"],
        "retained_entry_hashes_verified": len(entries),
        "scope": "Readback of exact historical aggregate reports and their original independent-reader summaries. Recomputes timing sums, graph counters, sampled depletion and reported predicates; does not newly re-run native work, inspect every original IPC file, independently re-verify State equality, or establish a cross-profile speedup. Nested CPU scopes are not additive. No continuous absence-of-depletion claim follows from finite samples.",
        "new_native_execution": False, "production_qualified": False,
        "original_three_run_campaign_passed": False,
        "work_profile": "pure-history-raw-v1", "history_resource_profile": PROFILE,
        "phase_count": len(rows), "in_window_depth_six_confirmations": 27,
        "passing_original_baseline_phases": 3,
        "hostile_phases_missing_required_depletion": 6,
        "phases": rows,
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
