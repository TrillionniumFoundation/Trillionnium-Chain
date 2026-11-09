#!/usr/bin/env python3
"""Retain observed work and costs without inventing independently useful tasks.

The only input adapter is the existing, externally pinned 44-record historical
SmolLM/Cell corpus. Its original reader owns all release, command, model and
authority checks. This adapter exposes the accounting gaps and original costs;
it does not execute work or accept a new declaration of business usefulness.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

import cell_model_metrics as cell

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "trnm-useful-task-observation-report-v1"
RESEARCH = "actual/research-result.json"
TRAINING = tuple(f"training/gen{n}/actual-receipt.json" for n in (1, 2, 3))


def origin(manifest, name, pointer=""):
    pin = manifest["files"][name]
    return {"source_path": pin["source_path"], "sha256": pin["sha256"],
            "git_blob_sha1": pin["git_blob_sha1"], "json_pointer": pointer}


def reported_sum(values, unit):
    """An arithmetic observation, never a complete task-cost certificate."""
    known = [cell.integer(value, "COST_INTEGER") for value in values if value is not None]
    return {"unit": unit, "retained_slots": len(values), "known_slots": len(known),
            "unknown_slots": len(values) - len(known),
            "sum_known": sum(known) if known else None,
            "complete_arithmetic_sum": sum(known) if len(known) == len(values) and values else None,
            "unknown_reason": "RETAINED_COST_VALUE_MISSING" if len(known) != len(values) else None,
            "scope": "arithmetic sum of reported worker-stage values only; not whole-process or whole-task cost"}


def command_observations(manifest, raw):
    """Keep all fixed input slots, including the retained failed transfer."""
    roster = [(f"training/gen{n}/command.json", "training-command") for n in (1, 2, 3)]
    roster += [(f"actual/transport/{name}-command.json",
                "controlled-refusal" if name == "offline-publisher-negative" else "release-acquisition")
               for name in cell.TRANSFERS]
    roster += [(f"actual/transport/materialize-{n}-command.json", "cache-materialization")
               for n in range(manifest["expected_release"]["cells"])]
    roster.append(("failures/optimized-original/publisher-to-replica-command.json", "failed-release-acquisition"))
    rows = []
    for name, kind in roster:
        command, elapsed = cell.command(raw[name])
        code = command["returncode"]
        rows.append({"slot": name, "kind": kind, "origin": origin(manifest, name),
                     "returncode": code,
                     "reported_outcome": "returned-zero" if code == 0 else "signalled" if code < 0 else "returned-nonzero",
                     "reported_elapsed_seconds": cell.rational(elapsed),
                     "clock": "historical elapsed_seconds; original start/end and common clock are not retained",
                     "full_process_family_cpu_ns": None, "physical_network_bytes": None,
                     "unknown_reason": "HISTORICAL_COMMAND_HAS_NO_PROCESS_FAMILY_CPU_OR_PHYSICAL_NETWORK_METER"})
    return {"retained_command_slots": len(rows), "rows": rows,
            "return_code_counts": dict(Counter(row["reported_outcome"] for row in rows)),
            "global_planned_attempts": None,
            "unknown_reason": "FIXED_RETAINED_ROSTER_IS_NOT_A_GLOBAL_ATTEMPT_CENSUS",
            "combined_command_wall_seconds": None,
            "combined_wall_unknown_reason": "NO_COMMON_CLOCK_OR_COMPLETE_NONOVERLAPPING_LIFETIME_COVERAGE"}


def training_observations(manifest, raw):
    rows, events, labels = [], [], Counter()
    for name in TRAINING:
        receipt = cell.parse(raw[name])
        operation = receipt["operation_id"]
        cell.require(type(operation) is str and 1 <= len(operation.encode()) <= 128, "TRAINING_OPERATION_ID")
        labels[operation] += 1
        stages = []
        for index, event in enumerate(receipt["cost_events"]):
            stages.append(dict(event, origin=origin(manifest, name, f"/cost_events/{index}")))
            events.append(event)
        rows.append({"origin": origin(manifest, name), "generation": receipt["generation"],
                     "declared_operation_id": operation, "input_sha256": receipt["input_sha256"],
                     "artifact": receipt["artifact"], "outcome": receipt["outcome"],
                     "reported_process_wall_ns": receipt["process_wall_ns"],
                     "reported_process_peak_rss_bytes": receipt["process_peak_rss_bytes"],
                     "stages": stages})
    return {"retained_training_receipt_slots": len(rows), "retained_stage_slots": len(events),
            "distinct_declared_operation_ids": len(labels),
            "reused_operation_labels": sorted(label for label, count in labels.items() if count > 1),
            "operation_identity_scope": "receipt labels; neither independent business demand nor authenticated invocations",
            "rows": rows,
            "stage_cpu_ns": reported_sum([event["cpu_ns"] for event in events], "ns"),
            "stage_wall_ns": reported_sum([event["wall_ns"] for event in events], "ns"),
            "stage_read_bytes": reported_sum([event["bytes_read"] for event in events], "bytes"),
            "stage_written_bytes": reported_sum([event["bytes_written"] for event in events], "bytes"),
            "clock": "reported CPU/wall deltas; original endpoints and a common clock are not in this corpus",
            "io_scope": "reported worker-stage I/O deltas; not wire bytes, unique bytes or device durability",
            "enclosing_process_and_command_values_added_to_stage_sums": False,
            "interval_overlap_independently_verified": False,
            "complete_process_family_cpu_ns": None,
            "unknown_reason": "WORKER_STAGES_EXCLUDE_UNMETERED_WORK_AND_OTHER_PROCESS_OWNERS"}


def project_records(manifest, raw):
    """Project retained raw records, also checking their pins for direct API use."""
    cell.require(type(raw) is dict and set(raw) == set(manifest["files"]), "COMPLETE_RECORD_DENOMINATOR")
    for name, data in raw.items():
        cell.require(type(data) is bytes and hashlib.sha256(data).hexdigest() == manifest["files"][name]["sha256"],
                     "FILE_SHA256")
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        cell.require(blob == manifest["files"][name]["git_blob_sha1"], "GIT_BLOB_IDENTITY")
    original = cell.project(manifest, raw)
    research = cell.parse(raw[RESEARCH])
    comparison = cell.parse(raw["actual/frozen-comparison.json"])
    commands = command_observations(manifest, raw)
    training = training_observations(manifest, raw)
    forward_rows = []
    for index, row in enumerate(research["raw_forward_observations"]):
        observed = row["observation"]
        forward_rows.append({"origin": origin(manifest, RESEARCH, f"/raw_forward_observations/{index}"),
                             "request_id": observed["request_id"], "artifact": observed["artifact"],
                             "input_sha256": observed["input_sha256"],
                             "reported_execution_ns": observed["execution_ns"], "correct": row["correct"]})
    unknown = {
        "independent_demand": "INDEPENDENT_CUSTOMER_DEMAND_AND_ORIGINAL_AUTHORIZATION_NOT_SUPPLIED",
        "independent_acceptance": "INDEPENDENT_FUTURE_TASK_ACCEPTANCE_NOT_SUPPLIED",
        "unique_business_task_identity": "OPERATION_AND_FIXTURE_LABELS_DO_NOT_ESTABLISH_BUSINESS_TASK_IDENTITY",
        "complete_attempt_census": "FAILED_CANCELLED_UNPUBLISHED_AND_OTHER_OWNER_ATTEMPTS_NOT_EXHAUSTIVELY_OBSERVED",
        "common_observation_window": "ORIGINAL_COMMON_MONOTONIC_WINDOW_NOT_SUPPLIED",
        "full_cost": "PREPARATION_PROOF_PROPAGATION_RECOVERY_AND_ALL_PROCESS_COSTS_NOT_COMPLETELY_OBSERVED",
        "retention": "INDEPENDENT_OLD_CAPABILITY_RETENTION_NOT_SUPPLIED",
        "net_value": "INDEPENDENT_BENEFIT_AND_COMPLETE_COST_DENOMINATION_NOT_SUPPLIED",
    }
    coverage = {
        "preparation": {"status": "partial", "observed": "worker material/import/load/adapter stages",
                        "unknown_reason": "PACKING_RELEASE_PREPARATION_PREPROCESSING_AND_CACHE_HORIZON_NOT_IN_SUPPLIED_CORPUS"},
        "training": {"status": "partial", "observed": "three retained worker-stage rosters",
                     "unknown_reason": "PROCESS_FAMILY_AND_UNOBSERVED_ATTEMPTS_NOT_COVERED"},
        "evaluation": {"status": "partial", "observed": f"{len(forward_rows)} operator-controlled action-scoring forward records",
                       "unknown_reason": unknown["independent_acceptance"]},
        "proof": {"status": "not_observed_in_supplied_corpus", "observed": None,
                  "unknown_reason": "NO_PROOF_OPERATION_OR_COST_RECEIPT_IN_THIS_CORPUS"},
        "propagation": {"status": "partial", "observed": f"two complete loopback acquisitions and {manifest['expected_release']['cells']} cache materializations",
                        "unknown_reason": "PHYSICAL_WIRE_ALL_PROVIDER_CPU_AND_FULL_ATTEMPT_CENSUS_MISSING"},
        "failed_cancelled_unpublished": {"status": "partial", "observed": "one failed transfer and one controlled refusal",
                                         "unknown_reason": unknown["complete_attempt_census"]},
        "recovery": {"status": "not_observed_in_supplied_corpus", "observed": None,
                     "unknown_reason": "COMPLETE_RESTART_REORG_RECONCILIATION_COST_NOT_SUPPLIED"},
    }
    return {
        "schema": SCHEMA, "scope": "readback-of-pinned-historical-smollm-cell-corpus",
        "records_retained_at_commit": manifest["retained_at_commit"],
        "recorded_native_source_commit": manifest["recorded_native_source_commit"],
        "recorded_native_binary_sha256": original["recorded_native_binary_sha256"],
        "recorded_worker_source_pins": research["source_pins"], "raw_file_count": len(raw),
        "original_reader_schema": original["schema"],
        "useful_task_throughput": {
            "unique_independently_accepted_tasks": None, "tasks_per_second": None,
            "common_window_ns": None, "global_planned_attempts": None,
            "unknown_reasons": {key: unknown[key] for key in (
                "independent_demand", "independent_acceptance", "unique_business_task_identity",
                "complete_attempt_census", "common_observation_window")},
            "qualified": False,
        },
        "commands": commands, "training": training,
        "model_scoring": {
            "origin": origin(manifest, RESEARCH, "/raw_forward_observations"),
            "retained_forward_records": len(forward_rows),
            "distinct_fixture_request_labels": len(comparison["tasks"]),
            "request_label_scope": "same operator-controlled fixture roster scored by two model arms",
            "rows": forward_rows, "component_metrics": original["model_compute"],
            "clock": "reported forward execution_ns only; not cold-load-to-response or common business window",
            "independent_future_task_acceptance": None,
            "independent_future_task_acceptance_unknown_reason": unknown["independent_acceptance"],
            "old_capability_retention": None, "retention_unknown_reason": unknown["retention"],
        },
        "cell_distribution": original["cell_distribution"],
        "earlier_failed_attempt": original["earlier_failed_attempt"],
        "cost_coverage": coverage,
        "complete_task_cost": {"cpu_ns": None, "gpu_ns": None, "wall_ns": None,
                               "physical_network_bytes": None, "energy_joules": None, "money_minor": None,
                               "unknown_reason": unknown["full_cost"]},
        "net_value": {"value": None, "unit": None, "unknown_reason": unknown["net_value"]},
        "fresh_executions_by_reader": 0, "native_origin_authenticated": False,
        "clock_or_meter_authenticated": False, "independent_evaluation_certified": False,
        "model_adoption_qualified": False, "production_activation": False, "qualification": "HOLD_NO_GO",
    }


def read_report(manifest_path, expected_sha256):
    manifest, raw = cell.load_bundle(manifest_path, expected_sha256)
    result = project_records(manifest, raw)
    result["input_manifest_sha256"] = expected_sha256
    result["reader_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result["original_reader_sha256"] = hashlib.sha256(Path(cell.__file__).read_bytes()).hexdigest()
    return result


def write_report(output, encoded):
    output = Path(output).resolve(strict=False)
    cell.require(not output.is_relative_to(ROOT), "OUTPUT_MUST_BE_OUTSIDE_SOURCE")
    with output.open("x", encoding="utf-8") as handle:
        handle.write(encoded)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = read_report(args.manifest, args.manifest_sha256)
        encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
        if args.output is not None:
            write_report(args.output, encoded)
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(json.dumps({"schema": SCHEMA, "status": "invalid-input-or-output", "error": str(error)}), file=sys.stderr)
        return 2
    print(encoded, end="")
    return 1  # The readback is valid; independent useful-task qualification is HOLD.


if __name__ == "__main__":
    raise SystemExit(main())
