#!/usr/bin/env python3
"""Append descriptive statistics to this exact already-consumed native batch.

This does not launch native work, alter the frozen analyzer, pool other batches,
impute missing counters, or estimate a causal effect from two phases per arm.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

EXPECTED_RECEIPT = "51e0e351a93f3fe70fef3e809c0e2204a1eb7dcfbe5c5fd9d7c3e03f8e66c8f1"
ARMS = ("transport", "early-reject", "late-reject", "valid-expensive")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def require(condition, code):
    if not condition:
        raise ValueError(code)


def numeric(values):
    known = [value for value in values if type(value) is int]
    return {"n": len(values), "known": len(known), "missing": len(values) - len(known),
        "values": values, "observed_sum": sum(known),
        "complete_sum": sum(known) if len(known) == len(values) else None,
        "mean": sum(known) / len(values) if values and len(known) == len(values) else None,
        "minimum": min(known) if known else None, "maximum": max(known) if known else None}


def difference(left, right):
    return left - right if type(left) is int and type(right) is int else None


def ms(value):
    return "NOT_RECORDED" if value is None else f"{value / 1e6:.6f}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    source = args.analysis_dir.resolve(strict=True)
    dest = args.out_dir.resolve()
    require(not dest.exists() and not dest.is_relative_to(source), "CREATE_ONLY_SEPARATE_OUTPUT")
    receipt_path = source / "CONSUMER_RECEIPT.json"
    require(sha(receipt_path.read_bytes()) == EXPECTED_RECEIPT, "CONSUMER_RECEIPT_CHANGED")
    receipt = json.loads(receipt_path.read_bytes())
    require(receipt["analysis_qualification"] == "COLLECTED_CONTROL_SERIES"
            and receipt["strict_campaign_reader"]["accepted"] is True
            and receipt["frozen_06_consumer"]["status"] == "CONSUMED", "CONSUMED_BATCH_REQUIRED")
    inventory = {row["member"]: row for row in receipt["outputs"]}
    names = ("phase_table.json", "phase_ledger.json", "connection_records.jsonl")
    identities = []
    for name in names:
        path = source / name
        require(sha(path.read_bytes()) == inventory[name]["sha256"]
                and path.stat().st_size == inventory[name]["bytes"], "CONSUMED_INPUT_CHANGED:" + name)
        identities.append(inventory[name])
    table = {row["phase_id"]: row for row in json.loads((source / "phase_table.json").read_bytes())}
    ledger = json.loads((source / "phase_ledger.json").read_bytes())
    records = [json.loads(line) for line in (source / "connection_records.jsonl").read_text().splitlines()]
    phases = []
    for row in ledger:
        phase_id, arm, t = row["phase_id"], row["arm"], row["telemetry"]
        business = t["business"]
        require(business["client_confirmation_latency_ns"]
                == business["confirmation_ended_ns"] - business["business_started_ns"], "BUSINESS_LATENCY_BINDING")
        matched = [record for record in records if record["phase_id"] == phase_id
                   and record["matched_control_packet_indices"]]
        calls = t["raw_call_records"]
        call_starts = [call.get("started_ns") for call in calls]
        arrivals = [record.get("accepted_in_original_traffic_epoch_ns") for record in matched]
        work_spans = [next((span for span in record["submit_phases"] if span["phase"] == "work"), None)
                      for record in matched]
        stages = {phase: {state: sum(any(span["phase"] == phase and span.get(state) is True
                    for span in record["submit_phases"]) for record in matched)
                    for state in ("started", "completed", "accepted")}
                  for phase in ("body_decode", "decode", "context", "work", "admission", "submit_result")}
        metrics = t["service_metrics"]
        phases.append({"planned_index": row["planned_index"], "phase_id": phase_id,
            "arm": arm, "kind": row["kind"], "confirmed": table[phase_id]["frozen_consumer_confirmed"],
            "native_final_gate": table[phase_id]["native_final_gate"],
            "business_started_ns": business["business_started_ns"],
            "confirmation_endpoint_ns": business["confirmation_ended_ns"],
            "business_release_to_confirmation_latency_ns": business["client_confirmation_latency_ns"],
            "remaining_original_window_at_endpoint_ns": 4_000_000_000 - business["confirmation_ended_ns"],
            "control_integrity_met": business["control_integrity_met"],
            "actual_calls_started": t["actual_calls_started"],
            "actual_calls_started_inside_window": t["actual_calls_started_inside_window"],
            "control_body_bytes_per_request": t["control_input_canonical_body_bytes"],
            "actual_recorded_canonical_body_bytes_sum": t["call_recorded_body_bytes"]["complete_sum"],
            "call_start_ns": numeric(call_starts), "observer_accepted_ns": numeric(arrivals),
            "offering_lateness_ns": t["offering_lateness_ns"],
            "call_status_counts": t["call_status_counts"], "target_stage_attained": t["observer"]["target_stage_attained"],
            "matched_body_checked_count": t["observer"]["matched_actual_body_checked"],
            "stage_counts": stages if arm else None,
            "matched_control_work_spans_explicitly_unstarted": sum(span is not None and span.get("started") is False for span in work_spans)
                if arm else None,
            "matched_control_dispatch_accepted": sum(record["dispatch_accepted"] is True for record in matched) if arm else None,
            "native_full_replay_observed": table[phase_id]["full_native_replays_observed"],
            "cached_rejections_observed": table[phase_id]["cached_rejections_observed"],
            "cache_replay_classification_unknown": table[phase_id]["replay_classification_unknown"],
            "paid_task_queue_wait_sum_ns": table[phase_id]["matched_control_paid_queue_wall_sum_ns"],
            "full_work_calling_thread_cpu_sum_ns": table[phase_id]["matched_control_full_work_thread_cpu_sum_ns"],
            "dispatch_calling_thread_cpu_sum_ns": table[phase_id]["matched_control_dispatch_thread_cpu_sum_ns"],
            "independent_replay_calling_thread_cpu_ns": table[phase_id]["independent_replay_caller_cpu_ns"],
            "matched_queue_distributions": t["observer"]["matched_queues"],
            "deadline_and_cancellation": t["deadline_and_cancellation"],
            "service_peak_counters": {key: value for key, value in metrics.items() if key.startswith("peak_")},
            "independent_history_replay_count": len(business["independent_history_page_replay"]),
            "independent_history_replay_results": dict(Counter(
                "accepted" if record["replay_accepted"] is True else "refused"
                for record in business["independent_history_page_replay"])),
            "raw_sha256": table[phase_id]["raw_sha256"]})
    require(len(phases) == 13 and all(row["confirmed"] is True for row in phases), "BATCH_RESULT_CHANGED")
    controls = [row for row in phases if row["arm"]]
    require(len(controls) == 8 and all(row["actual_calls_started"] == row["target_stage_attained"]
            == row["matched_body_checked_count"] == 16 for row in controls), "CONTROL_OBSERVED_DENOMINATOR")
    fields = ("confirmation_endpoint_ns", "business_release_to_confirmation_latency_ns", "paid_task_queue_wait_sum_ns",
              "full_work_calling_thread_cpu_sum_ns", "dispatch_calling_thread_cpu_sum_ns",
              "independent_replay_calling_thread_cpu_ns")
    arms = []
    for arm in ARMS:
        rows = [row for row in controls if row["arm"] == arm]
        require(len(rows) == 2, "TWO_OBSERVED_PHASES_PER_ARM")
        arms.append({"arm": arm, "n_phases": 2, "phase_ids_in_execution_order": [row["phase_id"] for row in rows],
            "confirmed_business_operations": sum(row["confirmed"] for row in rows),
            "actual_calls_started": sum(row["actual_calls_started"] for row in rows),
            "matched_body_checked_count": sum(row["matched_body_checked_count"] for row in rows),
            "target_stage_attained": sum(row["target_stage_attained"] for row in rows),
            "numeric_summaries": {field: numeric([row[field] for row in rows]) for field in fields},
            "reverse_minus_forward": {field: difference(rows[1][field], rows[0][field]) for field in fields}})
    blocks = [{row["arm"]: row for row in controls[:4]}, {row["arm"]: row for row in controls[4:]}]
    contrasts = []
    for left, right in (("late-reject", "early-reject"), ("valid-expensive", "late-reject"), ("early-reject", "transport")):
        contrasts.append({"contrast": left + " minus " + right,
            "alignment": "execution half, first T/E/L/V then V/L/E/T; not randomized matched pairs",
            "phase_pairs": [[block[left]["phase_id"], block[right]["phase_id"]] for block in blocks],
            "numeric_differences": {field: numeric([difference(block[left][field], block[right][field]) for block in blocks]) for field in fields},
            "causal_estimator": False})
    statistics = {"schema": "sp27-strata-descriptive-statistics-v1", "experiment_id": receipt["experiment_id"],
        "primary_consumer_receipt_sha256": EXPECTED_RECEIPT, "input_files": identities,
        "native_collector_qualification": receipt["native_collector_qualification"],
        "analysis_qualification": receipt["analysis_qualification"], "native_counts": receipt["validated_native_counts"],
        "confirmed_business_operations": 13, "health_and_sentinel_confirmations": 5,
        "pressure_control_confirmations": 8, "control_requests_started": sum(row["actual_calls_started"] for row in controls),
        "actual_control_canonical_body_bytes_sum": sum(row["actual_recorded_canonical_body_bytes_sum"] for row in controls),
        "phase_details": phases, "arm_summaries": arms, "within_execution_half_contrasts": contrasts,
        "actual_process": receipt["outer_execution"]["actual_process_record"],
        "input_acquisition_costs": receipt["input_acquisition_costs"],
        "statistical_significance_claimed": False, "confidence_interval_estimated": False,
        "causal_mechanism_status": "UNKNOWN", "new_native_experiments": 0,
        "historical_agent_06_author_ack": "NOT_OBSERVED", "coordinator_ack": "NOT_OBSERVED",
        "scope": ["Two phases per arm from one balanced campaign, not independent randomized replications",
            "Four-second deadline, 0.25 CPU and 2 GiB resource gates are unchanged",
            "Same count and canonical body bytes do not establish identical actual arrival timing or instantaneous load",
            "Endpoints use each phase's traffic epoch; release-to-confirmation latencies use the separately recorded release",
            "Queue sums add per-request waits; they are not a critical-path duration or queue depth",
            "Dispatch and full-work CPU are calling-thread counters and have nested intervals; scoped-worker CPU is excluded",
            "Missing pre-work full-work CPU is retained null, even when an explicit native Work span says unstarted",
            "No cost total adds full-work, dispatch, independent replay, input-acquisition or whole-child counters together",
            "Valid inputs also exercise admission, execution, fork choice and storage",
            "The bounded 16-single-attempt schedule differs from the prior sustained-pressure pair; neither batch overwrites the other"]}
    lines = ["# Observed balanced strata campaign: descriptive result", "",
        "The frozen strict reader and unchanged SP27-06 analyzer both consumed the actual original batch successfully. "
        "All 13 planned phases completed: five healthy controls/sentinels and eight pressure controls. "
        "Every business operation confirmed strictly before its original four-second deadline, and every pressure phase met native control integrity. "
        "Native and analysis qualification are `COLLECTED_CONTROL_SERIES`; no first-divergence or reader rejection was recorded. "
        "The causal mechanism remains **UNKNOWN**.", "",
        "## All thirteen observed endpoints", "",
        "Times below are milliseconds from each phase's original traffic epoch; the latency column subtracts the actual recorded business release. "
        "The phases have separate epochs and are not one wall-clock timeline.", "",
        "| Index | Phase | Confirmation endpoint (ms) | Release-to-confirmation latency (ms) | Native gate |",
        "| ---: | --- | ---: | ---: | --- |"]
    for row in phases:
        lines.append(f"| {row['planned_index']} | {row['phase_id']} | {ms(row['confirmation_endpoint_ns'])} | "
                     f"{ms(row['business_release_to_confirmation_latency_ns'])} | true |")
    lines += ["", "## Two observed phases per arm", "",
        "Each phase offered 16 single-attempt requests. All 16 matching bodies were actually checked and reached the intended native stage. "
        "Every canonical Submit body was 99,043 bytes (1,584,688 bytes per phase; physical network bytes are not inferred). "
        "Transport and early-reject had 16 explicitly unstarted Work spans per phase. Late and valid each had 16 actual native full replays per phase with no cached rejection returned. "
        "Missing pre-work CPU fields remain null in the machine-readable output.", "",
        "| Arm | Business confirmations | First endpoint (ms) | Second endpoint (ms) | Second minus first (ms) | Mean release-to-confirmation latency (ms) |",
        "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for row in arms:
        ends = row["numeric_summaries"]["confirmation_endpoint_ns"]["values"]
        lines.append(f"| {row['arm']} | 2/2 | {ms(ends[0])} | {ms(ends[1])} | "
            f"{ms(row['reverse_minus_forward']['confirmation_endpoint_ns'])} | "
            f"{ms(row['numeric_summaries']['business_release_to_confirmation_latency_ns']['mean'])} |")
    lines += ["", "## Contrasts aligned by execution half", "",
        "These are descriptive subtractions, not causal estimates or significance tests. "
        "The first half used T/E/L/V and the second V/L/E/T, with a healthy midpoint sentinel. "
        "Both raw endpoint differences and release-adjusted latency differences are retained in `STATISTICS.json`. "
        "The table reports release-to-confirmation latency differences.", "",
        "| Contrast | First half difference (ms) | Second half difference (ms) | Arithmetic mean (ms) |",
        "| --- | ---: | ---: | ---: |"]
    for row in contrasts:
        values = row["numeric_differences"]["business_release_to_confirmation_latency_ns"]
        lines.append(f"| {row['contrast']} | {ms(values['values'][0])} | {ms(values['values'][1])} | {ms(values['mean'])} |")
    lines += ["", "## Actual arrival timing and partial native costs", "",
        "Equal request counts and body lengths did not produce identical arrival profiles. "
        "The paid-queue column is the sum of 16 per-request waits, not one critical-path delay. "
        "CPU columns are the recorded calling-thread scope, exclude scoped worker CPU, and have nested intervals; "
        "full-work CPU must not be added to dispatch CPU or treated as complete verification cost.", "",
        "| Control phase | Observer accepts min–max (ms) | Paid queue wait sum (ms) | Full-work calling-thread CPU (ms) | Dispatch calling-thread CPU (ms) |",
        "| --- | ---: | ---: | ---: | ---: |"]
    for row in controls:
        arrivals = row["observer_accepted_ns"]
        lines.append(f"| {row['phase_id']} | {ms(arrivals['minimum'])}–{ms(arrivals['maximum'])} | "
            f"{ms(row['paid_task_queue_wait_sum_ns'])} | {ms(row['full_work_calling_thread_cpu_sum_ns'])} | "
            f"{ms(row['dispatch_calling_thread_cpu_sum_ns'])} |")
    lines += ["", "The JSON retains all actual call times, lateness distributions, stage counts, service peak counters, "
        "recorded deadline/cancellation metrics and independent replay results. No cancellation cause or queue depth is inferred. "
        "The native process lasted 54.134029355 s with 9.483126 s of whole-child CPU; this is an outer measured total, "
        "not the sum of the nested phase counters. Complete strata-input acquisition recorded 0.732009246 s wall and "
        "0.174794390 s process CPU, including negative construction and valid producer paths; it is not a pure prover measurement.", "",
        "## Interpretation boundary", "",
        "This bounded schedule did not reproduce the prior sustained-pressure pair's failed confirmation. "
        "It does not refute that retained original observation or establish resistance to another load, duration or schedule. "
        "Two observations per arm from one host/campaign do not identify a general causal effect. The valid arm includes "
        "admission, execution, fork choice and storage, and actual arrival timing differed between phases. "
        "No extra native runs were added to obtain a preferred outcome, and no other health batch or historical corpus was pooled. "
        "The original Agent 06 author and coordinator acknowledgments remain `NOT_OBSERVED`.", "",
        "Primary evidence: `../strata_analysis_v1/CONSUMER_RECEIPT.json`, SHA-256 `" + EXPECTED_RECEIPT + "`. "
        "The companion statistics receipt binds the exact consumed input files, this summarizer and its outputs.", ""]
    dest.mkdir(parents=True, exist_ok=False)
    (dest / "STATISTICS.json").write_bytes(canonical(statistics))
    (dest / "DESCRIPTIVE_RESULT.md").write_text("\n".join(lines))
    frozen = {"schema": "sp27-strata-descriptive-statistics-freeze-v1", "script_sha256": sha(Path(__file__).read_bytes()),
        "command_arguments": sys.argv, "primary_consumer_receipt_sha256": EXPECTED_RECEIPT,
        "input_files": identities, "new_native_experiments": 0, "mechanism_status": "UNKNOWN",
        "outputs": [{"file": path.name, "bytes": path.stat().st_size, "sha256": sha(path.read_bytes())}
                    for path in sorted(dest.iterdir()) if path.is_file()]}
    (dest / "RECEIPT.json").write_bytes(canonical(frozen))
    print(json.dumps({"output": str(dest), "receipt_sha256": sha((dest / "RECEIPT.json").read_bytes()),
                      "planned": 13, "confirmed": 13, "controls": 8, "new_native_experiments": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
