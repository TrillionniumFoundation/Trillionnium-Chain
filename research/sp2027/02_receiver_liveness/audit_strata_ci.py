#!/usr/bin/env python3
"""Read immutable extracted SP27 strata originals; append diagnostic/06 outputs.

Even a missing native report produces an explicitly analysis-side NO_GO ledger.
It never creates a collector report, a native first-divergence, or a raw record.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE / "strata_analysis_v1"))
import adapter

VERSION = "sp27-02-strata-ci-audit-v1"
QUEUES = ("challenge_wait", "grant_wait", "paid_task_queue_wait", "response_write")


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            adapter.require(key not in value, "DUPLICATE_JSON_KEY:" + key)
            value[key] = item
        return value

    def invalid(value):
        raise ValueError("NONFINITE_JSON:" + value)

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def load_runner():
    sys.path.insert(0, str(ROOT / "scripts/ci"))
    return adapter.load_module(ROOT / "scripts/ci/run_sp27_strata_controls.py",
                               "sp27_strata_observed_runner", adapter.RUNNER_SHA256)


class Originals:
    def __init__(self, root):
        self.root = root.resolve(strict=True)
        self.files, self.errors = {}, []

    def observe(self, member, retain=False):
        relative = Path(member)
        adapter.require(not relative.is_absolute() and ".." not in relative.parts, "MEMBER_ESCAPE")
        path = self.root / relative
        adapter.require(path.resolve().is_relative_to(self.root), "MEMBER_SYMLINK_ESCAPE")
        before = path.lstat()
        adapter.require(stat.S_ISREG(before.st_mode), "MEMBER_NOT_REGULAR:" + member)
        h, parts = hashlib.sha256(), []
        with path.open("rb") as handle:
            while block := handle.read(1024 * 1024):
                h.update(block)
                if retain:
                    parts.append(block)
        after = path.lstat()
        adapter.require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                        "MEMBER_CHANGED_DURING_READ:" + member)
        observed = {"member": member, "bytes": after.st_size, "sha256": h.hexdigest()}
        adapter.require(member not in self.files or self.files[member] == observed,
                        "MEMBER_CHANGED_BETWEEN_READS:" + member)
        self.files[member] = observed
        return observed, b"".join(parts) if retain else None

    def json(self, member):
        try:
            observed, raw = self.observe(member, retain=True)
            value = strict_json(raw)
            adapter.require(type(value) is dict, "JSON_OBJECT_REQUIRED:" + member)
            return value
        except (OSError, ValueError, TypeError) as error:
            self.errors.append({"member": member, "error": type(error).__name__ + ":" + str(error)})
            return None


def project(value, keys):
    source = value if type(value) is dict else {}
    return {key: source.get(key) for key in keys}


def numeric(values):
    """Partial observed sums are separate from complete totals; null is not zero."""
    if values is None:
        return {"observations": None, "known": None, "unknown": None,
                "observed_sum": None, "complete_sum": None, "minimum": None, "maximum": None}
    known = [value for value in values if adapter.unsigned(value)]
    return {"observations": len(values), "known": len(known), "unknown": len(values) - len(known),
            "observed_sum": sum(known), "complete_sum": sum(known) if len(known) == len(values) else None,
            "minimum": min(known) if known else None, "maximum": max(known) if known else None}


def body_digest(value):
    if type(value) is list and len(value) == 32 and all(type(x) is int and 0 <= x < 256 for x in value):
        return bytes(value).hex()
    return None


def replay_state(record):
    rejection = record.get("work_rejection")
    cache = rejection.get("cache") if type(rejection) is dict else None
    if type(cache) is not dict:
        return {"full_native_replay": None, "cached_rejection_returned": None,
                "native_verifier_started": None, "native_verifier_returned": None,
                "full_replay_started": None, "observation_status": "NOT_RECORDED"}
    keys = ("cached_rejection_returned", "native_verifier_started", "native_verifier_returned", "full_replay_started")
    flags = project(cache, keys)
    known = type(rejection.get("completed")) is bool and all(type(flags[key]) is bool for key in keys)
    return {**flags, "full_native_replay": (
        rejection["completed"] and flags["native_verifier_started"] and flags["native_verifier_returned"]
        and flags["full_replay_started"] and not flags["cached_rejection_returned"]) if known else None,
        "observation_status": "RECORDED" if known else "INCOMPLETE_FIELDS"}


def record_telemetry(raw, arm, requests, runner):
    snapshot = raw.get("observations")
    records = snapshot.get("records") if type(snapshot) is dict else None
    if type(records) is not list:
        return [], {"records_observed": None, "status": "NOT_RECORDED"}
    identities = {}
    if type(requests) is list:
        for i, wire in enumerate(requests):
            body = json.dumps({"op": "submit", "packet": wire}, separators=(",", ":")).encode()
            identities.setdefault(runner.native.H("public-request-body-v3", body).hex(), []).append(i)
    clock = raw.get("business_receive_clock")
    offset = clock.get("traffic_epoch_in_observer_ns") if type(clock) is dict else None
    rows = []
    for i, record in enumerate(records):
        if type(record) is not dict:
            rows.append({"record_index": i, "status": "MALFORMED_OBSERVER_RECORD"})
            continue
        phases = record.get("submit_phases")
        digest = body_digest(record.get("body_digest"))
        matched = identities.get(digest, [])
        by_name = {row.get("phase"): row for row in phases if type(row) is dict} if type(phases) is list else {}
        checked = by_name.get("body_decode", {})
        checked = (all(checked.get(key) is True for key in ("started", "completed", "accepted"))
                   if checked else None)
        attained, stage_error = None, None
        if arm is not None and matched:
            try:
                _, _, attained = runner.observed_stage(record, arm)
            except (ValueError, TypeError, KeyError) as error:
                stage_error = type(error).__name__ + ":" + str(error)
        lifecycle = record.get("lifecycle")
        accepted = lifecycle.get("accepted_ns") if type(lifecycle) is dict else None
        mapped = accepted - offset if adapter.unsigned(accepted) and adapter.unsigned(offset) else None
        rows.append({"record_index": i, "connection_id": record.get("connection_id"),
            "operation": record.get("operation"), "body_digest": digest,
            "matched_control_packet_indices": matched,
            "body_binding_scope": "control-input-map-unavailable" if type(requests) is not list else
                "actual-body-checked" if matched and checked is True
                else ("hello-claim-only" if matched else "unmatched-or-pre-hello"),
            "actual_body_checked": checked, "target_stage_attained": attained,
            "stage_read_error": stage_error, "replay": replay_state(record),
            "lifecycle": lifecycle, "accepted_in_original_traffic_epoch_ns": mapped,
            "accepted_strictly_before_T": mapped < adapter.WINDOW_NS if mapped is not None else None,
            "submit_phases": phases, "queues": project(record, QUEUES),
            "frames": record.get("frames"), "error_diagnostics": record.get("error_diagnostics"),
            **project(record, ("full_work_started", "full_work_accepted", "full_work_thread_cpu_ns",
                "dispatch_started", "dispatch_accepted", "dispatch_thread_cpu_ns", "dispatch_error_code",
                "application_bytes_read", "application_bytes_written", "physical_network_bytes",
                "terminal_phase", "terminal_error_code", "complete", "observation_failed",
                "response_frame_complete", "connection_closed", "task_created", "task_closed"))})
    matched_rows = [row for row in rows if row.get("matched_control_packet_indices")]
    replay_rows = [row.get("replay", {}) for row in matched_rows]
    mapping_known = type(requests) is list
    metric = lambda name: numeric([row.get(name) for row in matched_rows] if mapping_known else None)
    count_if_known = lambda value: value if mapping_known else None
    return rows, {"status": "RECORDED", "records_observed": len(records),
        "coverage": project(snapshot, ("schema", "accepted_connections_seen", "records_not_retained",
            "measurement_failures", "counter_overflow", "cpu_intervals_are_nested_not_additive",
            "stream_bytes_are_physical_network_bytes", "submit_phase_cpu_excludes_scoped_workers")),
        "control_input_mapping_available": mapping_known,
        "matched_claimed_body_connections": count_if_known(len(matched_rows)),
        "matched_actual_body_checked": count_if_known(sum(row.get("actual_body_checked") is True for row in matched_rows)),
        "target_stage_attained": count_if_known(sum(row.get("target_stage_attained") is True for row in matched_rows)),
        "target_stage_unknown": count_if_known(sum(row.get("target_stage_attained") is None for row in matched_rows)),
        "full_native_replays_observed": count_if_known(sum(row.get("full_native_replay") is True for row in replay_rows)),
        "cached_rejections_observed": count_if_known(sum(row.get("cached_rejection_returned") is True for row in replay_rows)),
        "replay_classification_unknown": count_if_known(sum(row.get("full_native_replay") is None for row in replay_rows)),
        "unmatched_or_pre_hello_records": count_if_known(len(rows) - len(matched_rows)),
        "matched_full_work_thread_cpu_ns": metric("full_work_thread_cpu_ns"),
        "matched_dispatch_thread_cpu_ns": metric("dispatch_thread_cpu_ns"),
        "matched_application_bytes_read": metric("application_bytes_read"),
        "matched_application_bytes_written": metric("application_bytes_written"),
        "matched_queues": {name: numeric([
            row.get("queues", {}).get(name, {}).get("wall_ns")
            if type(row.get("queues", {}).get(name)) is dict else None for row in matched_rows]
            if mapping_known else None) for name in QUEUES},
        "nested_costs_must_not_be_added": True, "equal_arrived_load_established": False}


def phase_telemetry(raw, arm, requests, runner):
    attacks = raw.get("attacks")
    calls = [call for worker in attacks if type(worker) is dict
             for call in (worker.get("calls") or []) if type(call) is dict] if type(attacks) is list else None
    original_calls = calls
    calls = calls or []
    connections, observer = record_telemetry(raw, arm, requests, runner)
    body_sizes = [len(json.dumps({"op": "submit", "packet": wire}, separators=(",", ":")).encode())
                  for wire in requests] if type(requests) is list else None
    started = [call for call in calls if adapter.unsigned(call.get("started_ns"))
               and call.get("status") != "not_started_original_deadline"]
    try:
        decision = adapter.reader().window_decision(raw.get("independent_client_confirmation"),
            raw.get("confirmation_ended_ns"), adapter.WINDOW_NS,
            raw.get("client_confirmed_before_original_window_end"))
        decision_error = None
    except (ValueError, TypeError, KeyError) as error:
        decision, decision_error = None, type(error).__name__ + ":" + str(error)
    service = raw.get("service")
    metrics = service.get("metrics") if type(service) is dict else None
    return {"window_ns": raw.get("requested_window_ns"), "workers": raw.get("workers"),
        "control_input_canonical_body_bytes": body_sizes,
        "control_input_body_bytes_total": sum(body_sizes) if body_sizes is not None else None,
        "control_call_records": len(calls) if original_calls is not None else None,
        "actual_calls_started": len(started) if original_calls is not None else None,
        "actual_calls_started_inside_window": sum(row["started_ns"] < adapter.WINDOW_NS for row in started)
            if original_calls is not None else None,
        "actual_calls_started_at_or_after_T": sum(row["started_ns"] >= adapter.WINDOW_NS for row in started)
            if original_calls is not None else None,
        "not_started_original_deadline": sum(call.get("status") == "not_started_original_deadline" for call in calls)
            if original_calls is not None else None,
        "call_status_counts": dict(Counter(str(call.get("status")) for call in calls)) if original_calls is not None else None,
        "offering_lateness_ns": numeric([call.get("offering_lateness_ns") for call in calls] if original_calls is not None else None),
        "call_recorded_body_bytes": numeric([call.get("recorded_request_bytes") for call in started] if original_calls is not None else None),
        "raw_call_records": original_calls, "observer": observer,
        "native_stage_readback": raw.get("stage_readback"),
        "native_arrival_plan": raw.get("arrival_plan"),
        "window_predicate_only": decision, "window_predicate_error": decision_error,
        "business": project(raw, ("business_started_ns", "confirmation_ended_ns", "client_confirmation_latency_ns",
            "client_confirmed_before_original_window_end", "client_confirmed_transactions",
            "independent_client_confirmation", "independent_history_page_replay", "independent_final_confirmation_stage",
            "honest_submissions", "honest_history", "honest_heads", "verification_errors",
            "invariant_target_met", "finite_business_target_met", "control_integrity_met",
            "full_native_state_equal", "receiver_matches_valid_honest_prefix")),
        "costs": project(raw, ("reader_cpu_ns", "attacker_workers_cpu_ns", "attacker_workers_cpu_scope",
            "independent_replay_and_confirmation_cpu_ns", "independent_replay_and_confirmation_wall_ns",
            "initial_meter", "final_meter", "accounting_closed")),
        "service_error": service.get("error") if type(service) is dict else None,
        "service_metrics": metrics,
        "deadline_and_cancellation": {"original_window_ns": raw.get("requested_window_ns"),
            "calls_returned_after_deadline": sum(row.get("returned_after_deadline") is True for row in calls)
                if original_calls is not None else None,
            "calls_deadline_flag_unknown": sum(type(row.get("returned_after_deadline")) is not bool for row in calls)
                if original_calls is not None else None,
            "actual_native_metrics": {key: value for key, value in metrics.items()
                if any(term in key for term in ("expired", "cancel", "abandoned", "disconnected", "skipped", "closed", "refusal"))}
                if type(metrics) is dict else None,
            "cancellation_cause_inferred": False, "queue_depth_inferred_from_wait_time": False},
        "validity_control_scope": raw.get("validity_control_scope")}, connections


def observed_plan_ledger(originals, plan, validated_report=None):
    """Missing start files mean not observed, unless a valid terminal report binds them."""
    recorded = {row["phase_id"]: row for row in validated_report["phases"]} if validated_report else {}
    ledger, phases, identities = [], {}, {}
    for expected in plan:
        phase_id = expected["phase_id"]
        prefix = "native/raw/" + phase_id
        members = {name: prefix + suffix for name, suffix in (
            ("started", "-started.json"), ("invoked", "-invoked.json"), ("index", "-index.json"),
            ("host_before", "-host-before.json"), ("host_after", "-host-after.json"),
            ("panic", "-panic.json"), ("raw", ".json"))}
        observed = {name: originals.json(member) for name, member in members.items()
                    if (originals.root / member).exists()}
        raw = observed.get("raw")
        if raw is not None:
            phases[phase_id] = raw
            identities[phase_id] = originals.files[members["raw"]]
        index = recorded.get(phase_id)
        if validated_report is not None:
            status = ("COMPLETED" if index and index.get("completed") is True else
                      "ATTEMPTED_INCOMPLETE" if index else "UNSTARTED")
        else:
            status = ("RAW_RECORD_PRESENT_NOT_VALIDATED" if raw is not None else
                      "START_RECORD_WITHOUT_COMPLETE_RAW" if observed.get("started") is not None else
                      "NO_START_RECORD_OBSERVED")
        ledger.append({**expected, "analysis_phase_status": status,
            "native_attempted": index.get("attempted") if index else (False if validated_report is not None else None),
            "native_completed": index.get("completed") if index else (False if validated_report is not None else None),
            "start_record_observed": "started" in observed,
            "invocation_record_observed": "invoked" in observed,
            "raw_json_object_observed": raw is not None,
            "raw_index_claim": observed.get("index"),
            "native_panic_record": observed.get("panic"),
            "original_files": {name: originals.files.get(member) for name, member in members.items()
                               if member in originals.files}})
    return ledger, phases, identities


def outer_observations(originals, prepared, manifest, runner):
    checks = {}
    if type(prepared) is dict:
        checks["preparation_complete"] = (prepared.get("schema") == runner.PREPARATION
            and prepared.get("completed") is True and prepared.get("failures") == []
            and prepared.get("native_tests_executed") is False)
        checks["preparation_source_stable"] = (prepared.get("source_before") is not None
            and runner.same_json(prepared.get("source_before"), prepared.get("source_after")))
        build = prepared.get("build")
        checks["build_completed"] = (type(build) is dict and type(build.get("exit_code")) is int
            and build["exit_code"] == 0 and build.get("timed_out") is False)
        for stream in ("stdout", "stderr"):
            member = "build/" + stream
            checks["build_" + stream + "_sha_matches"] = None
            if type(build) is dict and (originals.root / member).exists():
                observed, _ = originals.observe(member)
                checks["build_" + stream + "_sha_matches"] = observed["sha256"] == build.get(stream + "_sha256")
        checks["retained_binary_sha_matches_prepared"] = None
        if (originals.root / runner.native.TARGET).exists():
            observed, _ = originals.observe(runner.native.TARGET)
            checks["retained_binary_sha_matches_prepared"] = observed["sha256"] == (prepared.get("binary") or {}).get("sha256")
    else:
        checks["preparation_complete"] = None
    process = manifest.get("process") if type(manifest) is dict else None
    checks["execution_complete"] = (manifest.get("schema") == runner.SCHEMA
        and manifest.get("collection_completed") is True and manifest.get("failures") == []) if type(manifest) is dict else None
    checks["process_completed"] = (type(process.get("exit_code")) is int and process["exit_code"] == 0
        and process.get("timed_out") is False) if type(process) is dict else None
    checks["execution_source_binary_match_preparation"] = (
        runner.same_json(manifest.get("source_before"), prepared.get("source_before"))
        and runner.same_json(manifest.get("source_after"), prepared.get("source_before"))
        and runner.same_json(manifest.get("binary_before"), prepared.get("binary"))
        and runner.same_json(manifest.get("binary_after"), prepared.get("binary"))) if type(manifest) is dict and type(prepared) is dict else None
    for stream in ("stdout", "stderr"):
        member = "run/" + stream
        checks["execution_" + stream + "_sha_matches"] = None
        if type(process) is dict and (originals.root / member).exists():
            observed, _ = originals.observe(member)
            checks["execution_" + stream + "_sha_matches"] = observed["sha256"] == process.get(stream + "_sha256")
    return {"checks": checks, "all_checks_verified": bool(checks) and all(value is True for value in checks.values()),
            "actual_process_record": process, "native_process_fields_not_reconstructed": True}


def csv_table(rows, path):
    fields = ["planned_index", "phase_id", "kind", "arm", "analysis_phase_status", "native_attempted",
        "native_completed", "actual_calls_started", "canonical_body_bytes", "offering_lateness_sum_ns",
        "matched_claimed_body_connections", "matched_actual_body_checked", "target_stage_attained",
        "full_native_replays_observed", "cached_rejections_observed", "replay_classification_unknown",
        "native_final_gate", "confirmation_ended_ns", "frozen_consumer_outcome", "frozen_consumer_confirmed",
        "control_integrity_met", "matched_control_paid_queue_wall_sum_ns", "matched_control_full_work_thread_cpu_sum_ns",
        "matched_control_dispatch_thread_cpu_sum_ns", "independent_replay_caller_cpu_ns", "raw_sha256"]
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: "NOT_VERIFIED" if row.get(key) is None else
                json.dumps(row[key], sort_keys=True) if type(row[key]) in (dict, list) else row[key] for key in fields})


def audit(input_dir, out, experiment_id):
    runner = load_runner()
    originals = Originals(input_dir)
    out = out.resolve()
    adapter.require(not out.is_relative_to(originals.root), "OUTPUT_MUST_NOT_MODIFY_ARCHIVE")
    adapter.require(not out.exists(), "CREATE_ONLY_OUTPUT_EXISTS")
    plan = runner.planned_phases()
    prepared = originals.json("preparation.json")
    manifest = originals.json("manifest.json")
    original_report = originals.json("native/report.json")
    original_plan = originals.json("native/plan.json")
    native_first = originals.json("native/first-divergence.json") if (originals.root / "native/first-divergence.json").exists() else None
    strict_report, readback, strict_error = None, {}, None
    try:
        adapter.require(type(prepared) is dict, "PREPARATION_NOT_READABLE")
        strict_report, report_file, readback = runner.read_campaign(originals.root, prepared)
        adapter.require(runner.same_json(strict_report, original_report), "REPORT_CHANGED")
        readback = {"report.json": report_file, **readback}
        # Preserve the actual reader's file hashes without transplanting its
        # temporary extraction inode/path metadata into producer identity.
        for member, observed in readback.items():
            local, _ = originals.observe("native/" + member)
            adapter.require(local["sha256"] == observed["sha256"], "READER_READBACK_CHANGED")
    except (OSError, ValueError, KeyError, TypeError) as error:
        strict_report = None
        strict_error = type(error).__name__ + ":" + str(error)
    ledger, phases, raw_identities = observed_plan_ledger(originals, plan, strict_report)
    acquisition = originals.json("native/business-acquisition.json") if (originals.root / "native/business-acquisition.json").exists() else None
    native_identities = {when: originals.json("native/identity-" + when + ".json")
                         if (originals.root / ("native/identity-" + when + ".json")).exists() else None
                         for when in ("before", "after")}
    input_acquisition = originals.json("native/strata-input-acquisition-native.json") if (
        originals.root / "native/strata-input-acquisition-native.json").exists() else None
    inputs = {}
    for i, arm in enumerate(runner.ARMS):
        member = f"native/inputs/arm-{i:03}.json"
        if (originals.root / member).exists():
            stream = originals.json(member)
            inputs[arm] = stream.get("requests") if stream else None
    # Every retained raw file, including partial preparation and panic evidence,
    # enters the identity inventory even if the strict campaign reader refused.
    for path in sorted((originals.root / "native").rglob("*")):
        if path.is_file():
            originals.observe(path.relative_to(originals.root).as_posix())
    outer = outer_observations(originals, prepared, manifest, runner)
    export, consumer_error = None, None
    if strict_report is not None:
        try:
            export = adapter.build_export(plan, strict_report, phases, acquisition, prepared,
                raw_identities, True, experiment_id)
        except (ValueError, KeyError, TypeError) as error:
            consumer_error = type(error).__name__ + ":" + str(error)
    consumer_ops = {row["run_id"].rsplit("/", 1)[1]: row for row in export["analyzed"]["operations"]} if export else {}
    phase_rows, table, connections = [], [], []
    for row in ledger:
        phase_id, arm = row["phase_id"], row["arm"]
        raw = phases.get(phase_id)
        telemetry, records = (phase_telemetry(raw, arm, inputs.get(arm), runner) if raw is not None else ({}, []))
        for record in records:
            connections.append({"phase_id": phase_id, "raw_member": raw_identities[phase_id]["member"],
                                "raw_sha256": raw_identities[phase_id]["sha256"], **record})
        phase_rows.append({**row, "telemetry": telemetry})
        observer, business = telemetry.get("observer", {}), telemetry.get("business", {})
        op = consumer_ops.get(phase_id, {})
        table.append({**{key: row[key] for key in ("planned_index", "phase_id", "kind", "arm", "analysis_phase_status", "native_attempted", "native_completed")},
            "actual_calls_started": telemetry.get("actual_calls_started"),
            "canonical_body_bytes": telemetry.get("control_input_canonical_body_bytes"),
            "offering_lateness_sum_ns": telemetry.get("offering_lateness_ns", {}).get("complete_sum"),
            **project(observer, ("matched_claimed_body_connections", "matched_actual_body_checked", "target_stage_attained",
                "full_native_replays_observed", "cached_rejections_observed", "replay_classification_unknown")),
            "native_final_gate": business.get("client_confirmed_before_original_window_end"),
            "confirmation_ended_ns": business.get("confirmation_ended_ns"),
            "frozen_consumer_outcome": op.get("outcome"), "frozen_consumer_confirmed": op.get("confirmed_in_window"),
            "control_integrity_met": business.get("control_integrity_met"),
            "matched_control_paid_queue_wall_sum_ns": observer.get("matched_queues", {}).get("paid_task_queue_wait", {}).get("complete_sum"),
            "matched_control_full_work_thread_cpu_sum_ns": observer.get("matched_full_work_thread_cpu_ns", {}).get("complete_sum"),
            "matched_control_dispatch_thread_cpu_sum_ns": observer.get("matched_dispatch_thread_cpu_ns", {}).get("complete_sum"),
            "independent_replay_caller_cpu_ns": telemetry.get("costs", {}).get("independent_replay_and_confirmation_cpu_ns"),
            "raw_sha256": raw_identities.get(phase_id, {}).get("sha256")})
    incomplete = next((row for row in ledger if row["start_record_observed"] and not row["raw_json_object_observed"]), None)
    first_without_raw = next((row for row in ledger if not row["raw_json_object_observed"]), None)
    native_qualification = original_report.get("qualification") if original_report else None
    qualified_collection = (strict_report is not None and native_qualification == "COLLECTED_CONTROL_SERIES"
                            and outer["all_checks_verified"] and export is not None)
    counts = project(strict_report, ("planned_phases", "attempted_phases", "helper_invoked_phases", "completed_phases",
        "incomplete_phases", "unstarted_phases", "healthy_completed_phases", "pressure_controls_planned",
        "pressure_controls_attempted", "pressure_controls_executed", "pressure_controls_unstarted"))
    receipt = {"schema": VERSION, "experiment_id": experiment_id, "source_digests": adapter.source_digests(),
        "input_directory": str(originals.root), "native_collector_qualification": native_qualification,
        "producer_preparation_identity": project(prepared, ("job", "source_before", "source_after", "binary")),
        "native_run_identities": native_identities,
        "analysis_python_version": sys.version,
        "reader_imported_source_sha256": {str(Path(module.__file__).resolve().relative_to(ROOT)):
            adapter.digest(Path(module.__file__).read_bytes()) for module in list(sys.modules.values())
            if getattr(module, "__file__", None) and Path(module.__file__).suffix == ".py"
            and Path(module.__file__).resolve().is_relative_to(ROOT / "scripts/ci")},
        "input_acquisition_costs": project(input_acquisition, ("schema", "canonical_submit_body_bytes_each",
            "negative_preparation_wall_ns", "negative_preparation_process_cpu_ns", "complete_acquisition_wall_ns",
            "complete_acquisition_process_cpu_ns", "nested_cost_intervals_are_not_additive", "cost_scope",
            "valid_expensive_is_not_a_pure_W1_intervention", "input_legality")),
        "actual_valid_input_generation": [project(row, ("worker", "producer_mine_returned", "packet_id",
            "generation_wall_ns", "generation_process_cpu_ns", "cost_scope"))
            for row in input_acquisition.get("valid_generation", [])] if input_acquisition else None,
        "analysis_qualification": "COLLECTED_CONTROL_SERIES" if qualified_collection else "NO_GO",
        "strict_campaign_reader": {"accepted": strict_report is not None, "error": strict_error,
            "source_sha256": adapter.RUNNER_SHA256, "readback_files": readback},
        "frozen_06_consumer": {"status": "CONSUMED" if export else "NOT_IMPORTED",
            "error": consumer_error, "analyzer_sha256": adapter.ANALYZER_SHA256,
            "import_scope": "entire validated planned campaign, including explicit unstarted phases" if export else None},
        "validated_native_counts": counts,
        "diagnostic_observed_counts": {"declared_plan_phase_count": len(plan),
            "declared_plan_source": "pinned collector source; actual native plan separately retained",
            "native_plan_observed": original_plan is not None,
            "started_files": sum(row["start_record_observed"] for row in ledger),
            "invoked_files": sum(row["invocation_record_observed"] for row in ledger),
            "raw_json_objects": len(phases),
            "no_start_file_observed": sum(not row["start_record_observed"] for row in ledger),
            "missing_start_file_proves_unstarted_without_validated_report": False},
        "outer_execution": outer, "native_collector_first_divergence": native_first,
        "native_report_first_divergence": original_report.get("first_divergence") if original_report else None,
        "analysis_first_evidence_gap": {"first_started_without_complete_raw": incomplete["phase_id"] if incomplete else None,
            "first_planned_without_complete_raw": first_without_raw["phase_id"] if first_without_raw else None,
            "reader_rejection": strict_error, "consumer_rejection": consumer_error,
            "is_native_collector_first_divergence": False},
        "original_read_errors": originals.errors, "input_files": list(originals.files.values()),
        "mechanism_status": "UNKNOWN", "mechanism_inference_from_n_two_per_arm": False,
        "statistical_scope": "descriptive only; eight predeclared forward/reverse control phases; no p-values or significance claim",
        "balanced_execution_is_randomized": False, "pool_with_other_batches": False,
        "full_lifecycle_cost_known": False, "valid_expensive_is_pure_verifier_cost_control": False,
        "native_records_rewritten": False, "new_native_experiments": 0}
    out.mkdir(parents=True, exist_ok=False)
    (out / "phase_ledger.json").write_bytes(adapter.canonical(phase_rows))
    (out / "phase_table.json").write_bytes(adapter.canonical(table))
    csv_table(table, out / "phase_table.csv")
    with (out / "connection_records.jsonl").open("x", encoding="utf-8") as handle:
        for row in connections:
            handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
    if export:
        adapter.write_export(export, out / "frozen_06_consumption")
    receipt["outputs"] = [{"member": path.relative_to(out).as_posix(), "bytes": path.stat().st_size,
                           "sha256": adapter.digest(path.read_bytes())} for path in sorted(out.rglob("*")) if path.is_file()]
    (out / "CONSUMER_RECEIPT.json").write_bytes(adapter.canonical(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="unchanged extracted sp27-receiver-strata directory")
    parser.add_argument("--out", type=Path, required=True, help="new append-only analysis output directory")
    parser.add_argument("--experiment-id", required=True, help="separate batch identity, normally CI run/job/artifact")
    args = parser.parse_args()
    result = audit(args.input, args.out, args.experiment_id)
    print(json.dumps({"analysis_qualification": result["analysis_qualification"],
                      "native_collector_qualification": result["native_collector_qualification"],
                      "strict_reader_accepted": result["strict_campaign_reader"]["accepted"],
                      "consumer_status": result["frozen_06_consumer"]["status"],
                      "receipt": str(args.out / "CONSUMER_RECEIPT.json")}, sort_keys=True))
    return 0 if result["analysis_qualification"] == "COLLECTED_CONTROL_SERIES" else 2


if __name__ == "__main__":
    raise SystemExit(main())
