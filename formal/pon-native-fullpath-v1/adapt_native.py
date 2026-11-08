#!/usr/bin/env python3
"""Read the actual four-start collector without inventing omitted phases.

The expected original preregistration digest comes from outside the measurement
output. Normalization is deterministic, performed AFTER collection, and never
described as a newly frozen preregistration. Original files remain untouched.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import fullpath_gate as gate

SOURCE_SCHEMA = "trnm-native-fullpath-process-observations-v1"
PLAN_SCHEMA = "trnm-native-fullpath-process-preregistration-v1"
CONTEXT_SCHEMA = "trnm-native-fullpath-process-context-v1"
ATTEMPTS = {
    "valid": ("honest", ["produce", "receive", "observe"], "candidate.pnp2"),
    "duplicate": ("honest", ["duplicate", "duplicate-observe"], "candidate.pnp2"),
    "late_product": ("hostile", ["late-product", "late-product-observe"], "late-product.pnp2"),
    "cancelled": ("honest", ["cancelled", "cancelled-observe"], "candidate.pnp2"),
}
SEMANTICS = {
    "search": "native generation including setup, signed transfer, execution, nonce search and winner verification",
    "winner_prepare": "post-boundary native packet serialization, canonical roundtrip and fsync",
    "propagation": "parent-observed same-host IPC through complete packet read and canonical decode",
    "verification": "receiver cold-open, complete W1 replay, execution and SQL admission",
    "acceptance": "activation, writer close, independent observer cold-open and exact native readback",
}


def reference(path, raw):
    return {"path": path, "sha256": gate.sha256(raw)}


def write_once(root, path, value):
    raw = gate.canonical(value) + b"\n"
    output = root / path
    try:
        with output.open("xb") as stream:
            stream.write(raw)
    except FileExistsError:
        gate.require(gate.Evidence(root).read(path) == raw, "NORMALIZED_OUTPUT_ALREADY_DIFFERS")
    return reference(path, raw)


def event(row, name):
    if row is None:
        return None
    values = [value for value in row["events"] if value["value"].get("event") == name]
    gate.require(len(values) <= 1, "DUPLICATE_NATIVE_EVENT")
    return values[0] if values else None


def successful(row, final_event):
    return bool(row is not None and row["exit_code"] == 0 and not row["timed_out"]
                and row["process_started"] is True and row["process_reaped"] is True
                and row["pipes_resolved"] is True and row["process_group_resolved"] is True
                and row["owner_unresolved"] is False and row["dispatch_blocked_by"] is None
                and row["cleanup_attempted"] is False
                and not row["stderr_error_event"] and not row.get("_stderr_error_observed", False)
                and not any(value["value"].get("event") == "error" or value["value"].get("status") == "error"
                            for value in row["events"])
                and not any(row[field] for field in ("reader_errors", "feeder_errors", "process_errors",
                                                     "cleanup_errors", "output_errors"))
                and event(row, final_event) is not None)


def retained_reference(value):
    gate.keys(value, {"path", "sha256", "complete"}, "PROCESS_ARTIFACT_KEYS")
    gate.require(type(value["complete"]) is bool, "PROCESS_ARTIFACT_COMPLETENESS")
    if not value["complete"]:
        gate.require(value["sha256"] is None, "UNSTABLE_ARTIFACT_CANNOT_CLAIM_DIGEST")
        return None
    gate.hex_value(value["sha256"], "PROCESS_ARTIFACT_DIGEST")
    return {field: value[field] for field in ("path", "sha256")}


def process_rows(report, evidence):
    result = {}
    allowed = {item for _, names, _ in ATTEMPTS.values() for item in names}
    previous_end = 0
    for original_row in gate.rows(report["processes"], "PROCESS_COUNT", len(allowed)):
        row = dict(original_row)
        gate.require(type(row) is dict and row.get("id") in allowed and row["id"] not in result,
                     "PROCESS_IDENTITY")
        try:
            original = gate.decode(evidence.read(row["id"] + ".process.json"))
        except FileNotFoundError:
            gate.require(bool(report.get("collection_errors")), "MISSING_PROCESS_ORIGINAL")
            original = None
        if original is not None:
            gate.require(original == row, "PROCESS_ROW_DIFFERS_FROM_ORIGINAL")
        start = gate.integer(row["start_ns"], "PROCESS_START", previous_end)
        previous_end = gate.integer(row["end_ns"], "PROCESS_END", start)
        gate.require(previous_end <= report["observed_through_ns"], "PROCESS_AFTER_REPORTED_END")
        if row["pid"] is None:
            gate.require(row["process_started"] is False
                         and (bool(row["process_errors"]) or row["dispatch_blocked_by"] is not None),
                         "MISSING_PID_WITHOUT_LAUNCH_ERROR")
        else:
            gate.integer(row["pid"], "PROCESS_PID", 1)
        if row["exit_code"] is None:
            gate.require(row["pid"] is None or row["process_reaped"] is False
                         or row.get("owner_unresolved") is True, "MISSING_EXIT_WITHOUT_UNRESOLVED_OWNER")
        else:
            gate.integer(row["exit_code"], "PROCESS_EXIT", -255, 255)
        for field in ("timed_out", "process_started", "process_reaped", "pipes_resolved",
                      "process_group_resolved", "owner_unresolved", "cleanup_attempted",
                      "resource_accounting_complete", "stderr_error_event"):
            gate.require(type(row[field]) is bool, "PROCESS_BOOLEAN_TYPE")
        if row["dispatch_blocked_by"] is not None:
            gate.require(row["dispatch_blocked_by"] in result and row["process_started"] is False,
                         "PROCESS_BLOCKED_OWNER")
        for field in ("reader_errors", "feeder_errors", "process_errors", "cleanup_errors",
                      "cleanup_notes", "output_errors"):
            for item in gate.rows(row[field], "PROCESS_ERRORS", 32):
                gate.name(item, "PROCESS_ERROR")
        gate.integer(row["cpu_ns"], "PROCESS_CPU")
        gate.integer(row["peak_rss_upper_bound_bytes"], "PROCESS_RSS")
        gate.integer(row["stdin_bytes_written"], "PROCESS_STDIN", maximum=gate.PACKET_LIMIT)
        for field, suffix in (("stdout", ".stdout.ndjson"), ("stderr", ".stderr.txt")):
            gate.require(row[field]["path"] == row["id"] + suffix, "ORIGINAL_STREAM_PATH")
            row[field] = retained_reference(row[field])
        raw = evidence.artifact(row["stdout"], 4 * 1024 * 1024) if row["stdout"] else None
        decoded, malformed = [], False
        if raw is not None:
            for line in raw.splitlines():
                try:
                    decoded.append(gate.decode(line))
                except ValueError:
                    malformed = True
            gate.require(not malformed or row["reader_errors"], "UNREPORTED_INVALID_NATIVE_OUTPUT")
        # Collector read errors are retained, but an aggregate cannot silently
        # replace/drop a valid original event. Malformed raw JSON is unusable.
        timestamps = gate.rows(row["events"], "PROCESS_EVENTS", 32)
        if raw is not None:
            gate.require([value.get("value") for value in timestamps] == decoded, "NATIVE_STDOUT_EVENT_MISMATCH")
        previous = start
        for value in timestamps:
            gate.keys(value, {"at_ns", "value"}, "TIMESTAMPED_EVENT_KEYS")
            previous = gate.integer(value["at_ns"], "PARENT_EVENT_TIME", previous, previous_end)
            gate.require(type(value["value"]) is dict and value["value"].get("schema") == gate.PROCESS_SCHEMA,
                         "NATIVE_EVENT_SCHEMA")
        row["_stderr_error_observed"] = False
        if row["stderr"] is not None:
            stderr = evidence.artifact(row["stderr"], 4 * 1024 * 1024)
            for line in stderr.splitlines():
                try:
                    value = gate.decode(line)
                except ValueError:
                    continue
                if type(value) is dict and (value.get("event") == "error" or value.get("status") == "error"):
                    row["_stderr_error_observed"] = True
        if raw is None or malformed:
            # Original aggregate events remain retained, but no stable raw
            # receipt exists from which to construct a complete native phase.
            row["events"] = []
            row["stdout"] = None
        if original is None:
            row["resource_accounting_complete"] = False
        result[row["id"]] = row
    return result


def error_event(row, evidence):
    if row is None or row["stderr"] is None:
        return None
    raw = evidence.artifact(row["stderr"])
    if not raw.strip():
        return None
    try:
        values = gate.process_events(raw)
    except ValueError:
        return None
    errors = [value for value in values if value.get("event") == "error"]
    gate.require(len(errors) <= 1, "DUPLICATE_NATIVE_ERROR")
    return errors[0] if errors else None


def failure(row, evidence, *, hostile=False):
    if row is None:
        return "error"
    if row["timed_out"]:
        return "timeout"
    value = error_event(row, evidence)
    if value is not None and value.get("cancelled") is True:
        return "cancelled"
    if hostile and value is not None and value.get("cancelled") is False and value.get("error") == "WORK:Product":
        if value.get("stage") == "verification" and gate.progress_counts(value) == [1, 512, 1, 0]:
            return "rejected"
    return "error"


def normalize_attempt(identity, processes, packet, packet_ref, context_sha256, evidence):
    _, names, _ = ATTEMPTS[identity]
    owned = [processes[value] for value in names if value in processes]
    producer = processes.get("produce") if identity == "valid" else None
    receiver = processes.get(names[1] if identity == "valid" else names[0])
    observer = processes.get(names[-1])
    stages = []
    claim_sha256 = packet["claim_sha256"] if packet else None

    def add(phase, start, end, status, receipt):
        stages.append(dict(phase=phase, started_ns=start, ended_ns=end, status=status,
                           claim_sha256=claim_sha256, receipt=receipt))

    terminal = "error"
    if producer is not None:
        search, prepared = event(producer, "search_complete"), event(producer, "produce_complete")
        if search is not None:
            add("search", producer["start_ns"], search["at_ns"], "complete", producer["stdout"])
            if prepared is not None and successful(producer, "produce_complete"):
                add("winner_prepare", search["at_ns"], producer["end_ns"], "complete", producer["stdout"])
            else:
                terminal = failure(producer, evidence)
                add("winner_prepare", search["at_ns"], producer["end_ns"], terminal, producer["stderr"])
        else:
            terminal = failure(producer, evidence)
            add("search", producer["start_ns"], producer["end_ns"], terminal, producer["stderr"])
    if receiver is not None:
        gate.require(not stages or stages[-1]["status"] == "complete", "RECEIVER_AFTER_FAILED_PRODUCER")
        received, admitted = event(receiver, "packet_received"), event(receiver, "admission_complete")
        if received is None:
            terminal = failure(receiver, evidence)
            add("propagation", receiver["start_ns"], receiver["end_ns"], terminal, receiver["stderr"])
        else:
            add("propagation", receiver["start_ns"], received["at_ns"], "complete", receiver["stdout"])
            if admitted is not None:
                # Admission returned normally. A later activation error is a
                # separate failure and does not rewrite completed native replay.
                add("verification", received["at_ns"], admitted["at_ns"], "complete", receiver["stdout"])
                reused = admitted["value"].get("admission_reused_existing")
                gate.require(type(reused) is bool, "NATIVE_REUSE_TYPE")
                if successful(receiver, "receive_complete") and successful(observer, "observe_complete"):
                    add("acceptance", admitted["at_ns"], observer["end_ns"], "complete", observer["stdout"])
                    terminal = "duplicate" if reused else "accepted"
                else:
                    failed_row = observer if successful(receiver, "receive_complete") else receiver
                    terminal = failure(failed_row, evidence)
                    end = failed_row["end_ns"] if failed_row else receiver["end_ns"]
                    add("acceptance", admitted["at_ns"], end, terminal,
                        failed_row["stderr"] if failed_row else None)
            else:
                terminal = failure(receiver, evidence, hostile=identity == "late_product")
                add("verification", received["at_ns"], receiver["end_ns"], terminal, receiver["stderr"])
    checks = []
    observed = event(observer, "observe_complete")
    if packet is not None and successful(observer, "observe_complete"):
        native = observed["value"].get("native_observation")
        gate.require(type(native) is dict, "NATIVE_OBSERVATION_MISSING")
        # This collector has no descendant-block producer. A nonzero depth must
        # come with its real packet path in a fresh adapter schema; never fake it.
        canonical_path = [packet_ref] if native.get("active_chain_member") is True else []
        checks.append(dict(at_ns=observed["at_ns"], receipt=observer["stdout"], canonical_path=canonical_path))
    resource_complete = all(row["resource_accounting_complete"] for row in owned)
    return dict(id=identity, context_sha256=context_sha256, status=terminal,
        packet=packet_ref, claim=packet["claim"] if packet else None, stages=stages,
        cpu_ns=sum(row["cpu_ns"] for row in owned) if resource_complete else None,
        peak_rss_bytes=max((row["peak_rss_upper_bound_bytes"] for row in owned), default=0) if resource_complete else None,
        wire_bytes=sum(row["stdin_bytes_written"] for row in owned) if resource_complete else None, canonical_checks=checks)


def adapt(root, expected_preregistration_sha256):
    root = Path(root)
    evidence = gate.Evidence(root)
    gate.hex_value(expected_preregistration_sha256, "EXPECTED_PREREGISTRATION_DIGEST")
    original_plan_raw = evidence.read("preregistration.json")
    gate.require(gate.sha256(original_plan_raw) == expected_preregistration_sha256,
                 "ORIGINAL_PREREGISTRATION_DIGEST")
    plan = gate.decode(original_plan_raw)
    original_context_raw = evidence.read("context.json")
    context = gate.decode(original_context_raw)
    report_raw = evidence.read("process-observations.json")
    report = gate.decode(report_raw)
    gate.require(plan.get("schema") == PLAN_SCHEMA and context.get("schema") == CONTEXT_SCHEMA
                 and report.get("schema") == SOURCE_SCHEMA, "ORIGINAL_SCHEMA")
    original_context_sha256 = gate.sha256(original_context_raw)
    gate.require(plan["context_sha256"] == report["context_sha256"] == original_context_sha256
                 and report["manifest_sha256"] == expected_preregistration_sha256, "ORIGINAL_CONTEXT_BINDING")
    gate.require(context["scope"] == "same-host-development-component-observation", "ORIGINAL_SCOPE")
    native_context = context["native_context"]
    gate.require(gate.decode(evidence.read("context.stdout.json")) == native_context, "NATIVE_CONTEXT_ORIGINAL")
    for field in ("source_commit", "source_tree"):
        gate.hex_value(context[field], "ORIGINAL_SOURCE_ID", 20)
    for field in ("binary_sha256", "collector_sha256"):
        gate.hex_value(context[field], "ORIGINAL_BINARY_OR_COLLECTOR")
    for field in ("source_and_binary_unchanged", "owner_unresolved", "resource_accounting_complete"):
        gate.require(type(report[field]) is bool, "REPORT_BOOLEAN_TYPE")
    for error in gate.rows(report["collection_errors"], "COLLECTION_ERRORS", 32):
        gate.name(error, "COLLECTION_ERROR")
    gate.require(plan["required_depth"] == 6 and type(plan["required_depth"]) is int
                 and plan["observation_end_ns"] == 4_000_000_000, "ORIGINAL_BUSINESS_THRESHOLDS")
    contract = context["original_business_contract"]
    for field in ("deadline_ns", "required_depth", "memory_bytes", "swap_bytes", "pids", "hostile_workers"):
        gate.integer(contract[field], "ORIGINAL_CONTRACT_INTEGER")
    gate.require(contract == dict(deadline_ns=4_000_000_000, required_depth=6, cpu_cores="0.25",
                                  memory_bytes=2147483648, swap_bytes=0, pids=256, hostile_workers=16),
                 "ORIGINAL_HOST_CONTRACT_CHANGED")
    scheduled = gate.rows(plan["schedule"], "ORIGINAL_SCHEDULE", 4)
    gate.require([row["id"] for row in scheduled] == list(ATTEMPTS), "ORIGINAL_START_DENOMINATOR")
    for row in scheduled:
        gate.integer(row["scheduled_ns"], "ORIGINAL_SCHEDULE_TIME")
        gate.require(type(row["requires_new_search"]) is bool, "ORIGINAL_SEARCH_TYPE")
        gate.require(row == dict(id=row["id"], cohort=ATTEMPTS[row["id"]][0], mode="native",
                                 requires_new_search=row["id"] == "valid", scheduled_ns=0,
                                 deadline_ns=4_000_000_000, parent_hex=native_context["parent_hex"],
                                 task_hex=native_context["task_hex"]), "ORIGINAL_START_CHANGED")
    gate.integer(report["observed_through_ns"], "ORIGINAL_OBSERVATION_END")
    processes = process_rows(report, evidence)
    original_attempts = gate.rows(report["attempts"], "ORIGINAL_ATTEMPTS", 4)
    gate.require([row["id"] for row in original_attempts] == list(ATTEMPTS), "MISSING_ORIGINAL_START")
    for row in original_attempts:
        planned_processes = ATTEMPTS[row["id"]][1]
        gate.require(row.get("planned_processes") == planned_processes
                     and row.get("processes") == [name for name in planned_processes if name in processes],
                     "ORIGINAL_PROCESS_ASSIGNMENT")
        if row.get("status") == "observed":
            gate.require(row["processes"] == planned_processes, "ORIGINAL_PROCESS_ASSIGNMENT")
        else:
            gate.require(row.get("status") == "error" and row.get("reason") in
                         {"NO_COMPLETE_SOURCE_PACKET", "COLLECTOR_ERROR", "OWNER_UNRESOLVED", "PROCESS_CONTROL_ERROR"},
                         "ORIGINAL_UNAVAILABLE_START")
    normalized_context = dict(schema="trnm-pon-fullpath-context-v1", scope="same-host-component-observation",
        clock_id="parent-monotonic:" + expected_preregistration_sha256,
        source_sha256=gate.sha256(gate.canonical({field: context[field] for field in
                                                ("source_commit", "source_tree", "collector_sha256")})),
        binary_sha256=context["binary_sha256"], resource_contract_sha256=gate.sha256(gate.canonical(contract)),
        workload_sha256=gate.sha256(gate.canonical({"schedule": scheduled, "workload": context["workload"]})),
        network_hex=native_context["network_hex"], parameters_hex=native_context["parameters_hex"],
        genesis_hex=native_context["genesis_hex"], stage_semantics=SEMANTICS,
        original_context=reference("context.json", original_context_raw),
        original_preregistration=reference("preregistration.json", original_plan_raw),
        original_observations=reference("process-observations.json", report_raw),
        source_and_binary_consistency_observed=report["source_and_binary_unchanged"],
        process_ownership_resolved=not report["owner_unresolved"],
        normalization_scope="post-collection deterministic readback; never a new preregistration",
        wire_limit_scope="native packet cap times four original submissions; no WAN bandwidth SLO",
        resource_enforcement=context["resource_enforcement"])
    context_ref = write_once(root, "gate-context.json", normalized_context)
    manifest = dict(schema=gate.MANIFEST_SCHEMA, context=context_ref,
        observation_end_ns=plan["observation_end_ns"], required_depth=plan["required_depth"],
        minimum_reorg_window_ns=0, maximum_total_cpu_ns=1_000_000_000,
        maximum_peak_rss_bytes=contract["memory_bytes"], maximum_total_wire_bytes=gate.PACKET_LIMIT * 4,
        minimum_timely_ppm=1_000_000, minimum_samples_per_group=1,
        schedule=[dict(id=row["id"], cohort=row["cohort"], mode="native", scheduled_ns=row["scheduled_ns"],
                       deadline_ns=row["deadline_ns"], reorg_observe_until_ns=plan["observation_end_ns"],
                       parent_hex=row["parent_hex"], task_hex=row["task_hex"])
                  for row in scheduled])
    manifest_ref = write_once(root, "gate-manifest.json", manifest)
    attempts = []
    for identity, (_, _, packet_path) in ATTEMPTS.items():
        packet, packet_ref = None, None
        try:
            raw = evidence.read(packet_path, gate.PACKET_LIMIT)
        except FileNotFoundError:
            raw = None
        if raw is not None:
            packet = gate.parse_packet(raw)
            packet_ref = reference(packet_path, raw)
        attempts.append(normalize_attempt(identity, processes, packet, packet_ref, context_ref["sha256"], evidence))
    resources_complete = (report["resource_accounting_complete"] and not report["owner_unresolved"]
                          and report["source_and_binary_unchanged"])
    normalized_report = dict(schema=gate.REPORT_SCHEMA, manifest_sha256=manifest_ref["sha256"],
        context_sha256=context_ref["sha256"], clock_id=normalized_context["clock_id"],
        observed_through_ns=report["observed_through_ns"], resources=dict(cpu_ns=report["cpu_ns"] if resources_complete else None,
            peak_rss_bytes=report["peak_rss_upper_bound_bytes"] if resources_complete else None,
            wire_bytes=report["stdin_bytes_written"] if resources_complete else None),
        attempts=attempts)
    write_once(root, "gate-observations.json", normalized_report)
    result = gate.read_campaign(root, manifest_ref["sha256"], manifest_path="gate-manifest.json",
                                report_path="gate-observations.json")
    result["original_preregistration_sha256"] = expected_preregistration_sha256
    result["original_observations_sha256"] = gate.sha256(report_raw)
    result["normalized_after_collection"] = True
    write_once(root, "gate-readback.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--preregistration-sha256", required=True)
    args = parser.parse_args()
    try:
        result = adapt(args.evidence, args.preregistration_sha256)
    except (OSError, ValueError, KeyError, TypeError, OverflowError) as exc:
        print(json.dumps(dict(evidence_valid=False, error=str(exc), overall_gate="HOLD",
                              security_gate="HOLD", production_activation=False), sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 1


if __name__ == "__main__":
    sys.exit(main())
