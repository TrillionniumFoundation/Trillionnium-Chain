#!/usr/bin/env python3
"""Read both original service contracts, retaining failures and unknown costs.

This reader never runs a node, changes an acceptance gate, or combines the
four-second Host cohort with the three-run, thirty-second campaign. Original
readers perform their existing consistency checks on pinned bytes. Missing
attempts keep their original denominator; a complete readback remains HOLD.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "formal" / "pon-native-fullpath-v1"))
import fullpath_gate as gate  # noqa: E402
import pon_public_v3_phase_read as phases  # noqa: E402
import read_original_native_campaign as original_campaign  # noqa: E402
import transaction_throughput as transactions  # noqa: E402

SCHEMA = "trnm-throughput-execution-report-v1"
HOST_MODES = ("attack-free-baseline", "from-zero-pressure")
HOST_WINDOW_NS = 4_000_000_000
CAMPAIGN_WINDOW_NS = 30_000_000_000
RUNS = (1, 2, 3)
ROUNDS = (0, 1, 2)
LOCK_PHASES = ("context_owner_wait", "admission_owner_wait", "commit_owner_wait")
MAX_ROWS = 65_536
HOST_CONTRACT = {
    "id": "original-host-service-4s",
    "deadline_ns": HOST_WINDOW_NS, "deadline_comparison": "strictly_before",
    "cpu_cores": "0.25", "memory_bytes": 2_147_483_648,
    "swap_bytes": 0, "pids": 256, "kernel_cpu_burst_us": 0,
    "modes": list(HOST_MODES), "hostile_workers_by_mode": [0, 16],
    "honest_submissions_per_phase": 7, "confirmation_targets_per_phase": 1,
    "required_depth": 6, "required_work_multiplier": 6,
}
CAMPAIGN_CONTRACT = {
    "id": "original-three-run-service-campaign-30s",
    "deadline_ns": CAMPAIGN_WINDOW_NS, "deadline_comparison": "strictly_before",
    "complete_runs": 3, "phases_per_run": 3, "confirmation_rounds_per_phase": 3,
    "seed_transfers": 1024, "seed_blocks": 4, "business_blocks_per_phase": 21,
    "modes": list(phases.MODES), "hostile_workers_by_mode": [0, 24, 24],
    "workers": 2, "credit_burst_cpu_ns": 2_000_000_000,
    "credit_refill_cpu_ns_per_second": 250_000_000,
    "start_reserve_cpu_ns": 100_000_000,
    "controller_resources": {
        "cpu_max": "400000 100000", "memory_max": "17179869184", "nice": 10,
    },
    "receiver_resource_placement": "retain the original per-run placement; not inferred from controller ceilings",
}


def require(value, message):
    if not value:
        raise ValueError(message)


def number(value):
    require(type(value) is int and 0 <= value < 1 << 64, "nonnegative u64 required")
    return value


def optional_number(value):
    return None if value is None else number(value)


def optional_boolean(value):
    require(value is None or type(value) is bool, "boolean or unknown required")
    return value


def same_value(value, expected):
    """Do not accept JSON booleans in place of original integer parameters."""
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return value.keys() == expected.keys() and all(
            same_value(value[key], item) for key, item in expected.items())
    if isinstance(expected, list):
        return len(value) == len(expected) and all(
            same_value(a, b) for a, b in zip(value, expected))
    return value == expected


def statistics(values, *, unit="ns", complete=False):
    """Descriptive known-only values and separately withheld complete-cohort tails."""
    values = [optional_number(value) for value in values]
    known = sorted(value for value in values if value is not None)
    n = len(known)
    minimum = {50: 2, 95: 20, 99: 100}
    ranks = {f"p{p}": known[(n * p + 99) // 100 - 1] if n >= needed else None
             for p, needed in minimum.items()}
    return {
        "unit": unit, "retained_slots": len(values), "known_count": n,
        "unknown_count": len(values) - n,
        "sum_known": sum(known) if known else None,
        "min_known": known[0] if known else None, "max_known": known[-1] if known else None,
        "known_only_percentiles": ranks,
        "complete_cohort_percentiles": ranks if complete and n == len(values) else dict.fromkeys(ranks),
        "minimum_samples": {f"p{p}": needed for p, needed in minimum.items()},
        "cohort_complete": complete and n == len(values),
        "method": "nearest-rank; descriptive only; no independence or population-confidence claim",
    }


def unknown_metrics():
    return {
        "status": "not_observed", "cpu": None, "network": None, "wal": None,
        "sql_commit_calls": None,
        "lock_wait": None, "queue": None, "per_request_owner_lifetime": None,
        "malicious_rejection": None, "cancellation": None, "recovery": None,
        "coverage": None,
    }


def round_slot(index, raw=None):
    """Retain one planned confirmation, including incomplete negative windows.

    Positive observations retain the original depth/work/identity conditions.
    A negative return before the end of the window does not prove a zero for the
    complete window. A contradictory reported zero is also kept unknown.
    """
    slot = {"round": index, "record_present": raw is not None,
            "reported_in_window": None, "supported_in_window": None,
            "status": "not_observed", "started_ns": None, "ended_ns": None,
            "successful_latency_ns": None, "observed_terminal_elapsed_ns": None,
            "transaction": None, "native_observation": None, "observed_reorged": None, "conflicts": []}
    if raw is None:
        return slot
    require(type(raw) is dict and number(raw.get("round")) == index, "round identity mismatch")
    reported = optional_boolean(raw.get("confirmed_inside_pressure_window"))
    start, end = (optional_number(raw.get(key)) for key in ("started_ns", "ended_ns"))
    require(start is None or end is None or start <= end, "round clock reversal")
    observation = raw.get("observation")
    require(observation is None or type(observation) is dict, "native confirmation object required")
    native = optional_boolean((observation or {}).get("confirmed"))
    reorged = optional_boolean((observation or {}).get("reorged"))
    slot.update(reported_in_window=reported, started_ns=start, ended_ns=end,
                observed_terminal_elapsed_ns=end - start if start is not None and end is not None else None,
                transaction=raw.get("transaction"), native_observation=observation,
                observed_reorged=reorged, status="unknown")
    if slot["transaction"] is not None:
        original_campaign.exact_digest(slot["transaction"])
    if reported is True:
        require(start is not None and end is not None and start <= end < CAMPAIGN_WINDOW_NS,
                "positive round outside original thirty-second window")
        require(native is True and observation.get("reorged") is False
                and observation.get("finalized") is False and observation.get("execution_authority") is False
                and type(observation.get("depth")) is int and observation["depth"] == 6
                and number(observation.get("observed_height")) - number(observation.get("included_height")) == 6
                and observation.get("transaction") == raw.get("transaction")
                and observation.get("included_block") == raw.get("included_block")
                and observation.get("observed_tip") == raw.get("tip"), "positive round native binding mismatch")
        for key in ("transaction", "included_block", "tip"):
            original_campaign.exact_digest(raw.get(key))
        require(int(original_campaign.exact_digest(observation.get("work_delta"), 128), 16)
                >= int(original_campaign.exact_digest(observation.get("required_work_delta"), 128), 16),
                "positive round cumulative-work mismatch")
        slot.update(supported_in_window=True, status="reported_native_confirmation_in_window",
                    successful_latency_ns=end - start)
    elif reported is False:
        if native is True and (end is None or end < CAMPAIGN_WINDOW_NS):
            slot["conflicts"].append("ZERO_WITH_EARLY_OR_UNTIMED_NATIVE_POSITIVE")
            slot["status"] = "contradictory_observation"
        elif end is not None and end >= CAMPAIGN_WINDOW_NS:
            slot.update(supported_in_window=False,
                        status="late_native_confirmation" if native is True else "not_confirmed_at_window_end")
        else:
            slot["status"] = "not_confirmed_in_incomplete_window"
    return slot


def round_counts(slots):
    yes = sum(row["supported_in_window"] is True for row in slots)
    no = sum(row["supported_in_window"] is False for row in slots)
    unknown = len(slots) - yes - no
    return {"planned": len(slots), "records_present": sum(row["record_present"] for row in slots),
            "observed_supported_timely": yes, "observed_supported_not_timely": no,
            "unknown": unknown, "total_timely": yes if not unknown else None,
            "status_counts": dict(Counter(row["status"] for row in slots))}


def transaction_identity_observations(slots):
    """Deduplicate timely transaction hashes without relabeling round counts.

    A retained round is not necessarily a new transaction or a business task.
    Unknown rounds and missing positive identities prevent an exact total, while
    the distinct retained positive hashes remain an observational lower bound.
    """
    labels = []
    unknown_rounds = missing_identity = 0
    for row in slots:
        timely = optional_boolean(row["supported_in_window"])
        if timely is None:
            unknown_rounds += 1
        elif timely is True:
            transaction = row.get("transaction")
            if transaction is None:
                missing_identity += 1
            else:
                original_campaign.exact_digest(transaction)
                labels.append(transaction)
    distinct = len(set(labels))
    complete = unknown_rounds == 0 and missing_identity == 0
    return {
        "schema": "trnm-campaign-transaction-identity-observation-v1",
        "planned_round_slots": len(slots),
        "timely_rounds_with_transaction_identity": len(labels),
        "repeated_timely_transaction_observations": len(labels) - distinct,
        "unknown_timeliness_round_slots": unknown_rounds,
        "timely_rounds_missing_transaction_identity": missing_identity,
        "distinct_timely_transaction_identities_lower_bound": distinct,
        "distinct_timely_transaction_identities": distinct if complete else None,
        "complete_within_planned_round_slots": complete,
        "unique_business_transactions": None,
        "transactions_per_second": None,
        "scope": "deduplicated native transaction-hash observations in the original planned rounds; "
                 "neither independent business demand, a complete service transaction census nor sustainable throughput",
    }


def call_census(rows, *, planned=None):
    require(type(rows) is list and len(rows) <= MAX_ROWS, "bounded calls required")
    statuses = Counter()
    durations = []
    indices = []
    for row in rows:
        require(type(row) is dict, "call object required")
        status = row.get("status")
        require(status is None or type(status) is str, "call status string or unknown required")
        statuses[status if status is not None else "unknown"] += 1
        durations.append(row.get("elapsed_wall_ns"))
        if planned is not None and row.get("packet_index") is not None:
            index = number(row["packet_index"])
            require(index < planned, "unplanned caller packet index")
            indices.append(index)
    return {"planned": planned, "recorded_attempts": len(rows),
            "status_counts": dict(statuses),
            "observed_distinct_planned_slots": len(set(indices)) if planned is not None else None,
            "repeated_planned_slot_attempts": len(indices) - len(set(indices)) if planned is not None else None,
            "attempts_without_plan_slot_binding": len(rows) - len(indices) if planned is not None else None,
            "unobserved_or_unbound_planned_slots": planned - len(set(indices)) if planned is not None else None,
            "terminal_call_duration": statistics(durations),
            "scope": "caller returns, not receiver acceptance or independently confirmed transactions"}


def interval_latency(slots, *, phase=False, complete=False):
    """Entered, finished and unfinished slots have separate denominators."""
    entered = [slot for slot in slots if slot is not None and (
        slot.get("started") is True if phase else slot.get("started_ns") is not None)]
    terminal = [slot for slot in entered if slot.get("completed") is True]
    unfinished = [slot for slot in entered if slot.get("completed") is not True]
    return {"retained_record_slots": len(slots), "phase_or_wait_slots_missing": sum(slot is None for slot in slots),
            "entered": len(entered), "terminal": len(terminal), "unfinished": len(unfinished),
            "unentered_or_entry_clock_unknown": len(slots) - len(entered),
            "terminal_latency": statistics([slot.get("wall_ns") for slot in terminal],
                complete=complete and not unfinished and all(slot is not None for slot in slots)),
            "unfinished_observed_elapsed": statistics([slot.get("wall_ns") for slot in unfinished]),
            "scope": "per entered slot; unfinished elapsed is spent wall time, not terminal latency; inclusive stages are not additive"}


def sql_commit_snapshots(raw_phase):
    """Retain existing actual commit-call totals without inventing WAL timing."""
    locations = ("native_history_arithmetic_before", "native_history_arithmetic_after",
                 "client_native_history_arithmetic_before", "client_native_history_arithmetic_after")
    names = ("admission_persistence", "atomic", "reorg_step", "reorg_termination")
    snapshots = {}
    for location in locations:
        parent = raw_phase.get(location)
        require(parent is None or type(parent) is dict, "native arithmetic snapshot object required")
        value = parent.get("sql_commit") if parent is not None else None
        snapshots[location] = value
        if value is None:
            continue
        require(type(value) is dict and value.get("schema") in (
            "pon-native-sql-commit-call-observation-v1", "pon-native-legacy-reorg-sql-commit-call-observation-v1")
            and value.get("has_consensus_authority") is False and type(value.get("observation_failed")) is bool,
            "native SQL commit observation scope required")
        sites = value.get("sites")
        if sites is None:
            require(value["observation_failed"], "missing SQL sites without observation failure")
            continue
        require(type(sites) is list and len(sites) == 4 and all(type(row) is dict for row in sites)
                and [row.get("site") for row in sites] == list(names),
                "original four SQL commit sites required")
        for row in sites:
            totals = row.get("totals")
            counters = ("calls_started", "calls_returned", "calls_succeeded", "calls_failed",
                        "calls_abandoned", "calls_unwinding", "cpu_ns_known_sum", "wall_unknown_calls",
                        "cpu_known_calls", "cpu_unknown_calls")
            require(type(totals) is dict and set(totals) == set(counters) | {"wall_ns", "cpu_ns"},
                    "native SQL totals shape required")
            for key in counters:
                number(totals[key])
            for key in ("wall_ns", "cpu_ns"):
                optional_number(totals[key])
            live = optional_number(row.get("calls_in_flight"))
            if value["observation_failed"]:
                continue  # Preserve saturated/incomplete raw counters; do not grant complete totals.
            returned, abandoned = totals["calls_returned"], totals["calls_abandoned"]
            measured = returned + abandoned
            require(live is not None and totals["calls_started"] == measured + live
                    and returned == totals["calls_succeeded"] + totals["calls_failed"]
                    and totals["cpu_known_calls"] + totals["cpu_unknown_calls"] == measured
                    and totals["wall_unknown_calls"] <= measured and totals["calls_unwinding"] <= measured,
                    "native SQL call census mismatch")
            require((totals["wall_ns"] is not None) is (measured > 0 and totals["wall_unknown_calls"] == 0)
                    and (totals["cpu_ns"] is not None) is (measured > 0 and totals["cpu_unknown_calls"] == 0)
                    and (totals["cpu_ns"] is None or totals["cpu_ns"] == totals["cpu_ns_known_sum"]),
                    "native SQL unknown/complete time mismatch")
    return {"snapshots": snapshots, "snapshots_observed": sum(value is not None for value in snapshots.values()),
            "difference_between_snapshots": None, "per_request_latency_percentiles": None,
            "physical_wal_bytes": None, "physical_fsync_latency_ns": None,
            "scope": "original cumulative Transaction::commit API observations; before/after owner epochs are not authenticated; no subtraction, request-tail or physical fsync claim"}


def first_error_latency(rows, *, complete):
    original = phases.request_error_timing_summary(rows)
    if original is None:
        return None
    result = {"original_readback": original, "retained_request_records": len(rows)}
    for name in ("first_dispatch_error", "first_terminal_error"):
        values = []
        for row in rows:
            captured = row.get("error_timing")
            event = captured.get(name) if captured is not None else None
            if event is not None:
                start = row["lifecycle"]["accepted_ns"]
                stamp = event["observed_ns"]
                values.append(stamp - start if not captured["observation_failed"]
                              and start is not None and stamp is not None else None)
        coverage = (complete and not original["historical_records_without_extension"]
                    and not original["measurement_failed_records"])
        measured = statistics(values, complete=coverage)
        result[name] = {"latency": measured,
                        "no_event_captured": original[name]["no_event_captured"],
                        "max_complete_captured_event_cohort_ns": measured["max_known"] if measured["cohort_complete"] else None}
    result["scope"] = "actual first error appearance per owner; retain its own typed cause; not response delivery, final owner closure, cancellation signal or a future worst-case bound"
    return result


def cancellation_latency(rows, *, complete):
    """Keep signal brackets, worker return and final resource closure distinct."""
    original = phases.request_cancellation_summary(rows)
    if original is None:
        return None
    groups = defaultdict(list)
    for record in original["records"]:
        groups[record["source"]].append(record)
    result = []
    for source in sorted(groups, key=lambda value: value or ""):
        records = groups[source]
        group = {"first_signal_source": source, "retained_records": len(records)}
        for name in ("worker_return", "all_request_owners_closed"):
            values = [record[name] for record in records]
            complete_group = (complete and source is not None
                and original["historical_records_without_extension"] == 0
                and original["measurement_failed_records"] == 0
                and original["first_flag_transition_records"] == len(rows)
                and all(value["status"] == "bracketed" for value in values))
            group[name] = {
                "status_counts": dict(Counter(value["status"] for value in values)),
                "signal_to_terminal_lower_bound_ns": statistics(
                    [value["lower_ns"] for value in values], complete=complete_group),
                "signal_to_terminal_upper_bound_ns": statistics(
                    [value["upper_ns"] for value in values], complete=complete_group),
                "exact_signal_to_terminal_latency_ns": None,
            }
        result.append(group)
    return {
        "schema": "trnm-request-cancellation-latency-bounds-v1",
        "by_first_signal_source": result,
        "original_readback": original,
        "scope": "actual request-flag write bracket to per-request worker return and all request "
                 "owners closed; ordinary connection cleanup remains separate; no external-caller "
                 "signal, process exit, future stopping bound, effect rollback or service qualification",
    }


def request_metrics(observer, *, role_calls=None):
    """Project original native counters; no stage totals become whole-request costs."""
    if observer is None:
        return unknown_metrics()
    require(type(observer) is dict, "observer object required")
    schema = observer.get("schema")
    require(schema in tuple(f"public-v3-local-request-resource-observation-v{n}" for n in (1, 2, 3, 4)),
            "unsupported original request observer")
    rows = observer.get("records")
    require(type(rows) is list and len(rows) <= MAX_ROWS, "bounded request records required")
    require(all(type(row) is dict for row in rows), "request record object required")
    require(all(row.get("submit_phases") is None or type(row["submit_phases"]) is list for row in rows),
            "phase slots must be an array or historically unknown")
    v4 = schema.endswith("-v4")
    instrumented_rows = [row for row in rows if row.get("submit_phases") is not None]
    instrumented = not schema.endswith("-v1") and len(instrumented_rows) == len(rows)
    # Historical Host reports may retain only a partial receiver snapshot. Keep
    # their missing stage slots unknown instead of manufacturing empty stages.
    require(not v4 or instrumented, "v4 phase slots required")
    measured = phases.execution_summary(rows, instrumented, observer_v4=v4)
    if instrumented_rows and not instrumented and not schema.endswith("-v1"):
        measured["submit_phases"] = phases.execution_summary(instrumented_rows, True)["submit_phases"]
    measured["records_without_phase_slots"] = len(rows) - len(instrumented_rows)
    seen, omitted, failures = (optional_number(observer.get(key)) for key in
                              ("accepted_connections_seen", "records_not_retained", "measurement_failures"))
    overflow = optional_boolean(observer.get("counter_overflow"))
    require(seen is None or seen >= len(rows) + (omitted or 0), "receiver census contradiction")
    complete = (seen == len(rows) and omitted == 0 and failures == 0 and overflow is False
                and all(row.get("complete") is True and row.get("observation_failed") is False for row in rows))
    lifecycle = phases.request_owner_lifecycle_summary(rows)
    error_timing = first_error_latency(rows, complete=complete)
    cancellation = cancellation_latency(rows, complete=complete)
    reactor_io = phases.reactor_io_summary(rows)
    stage_slots = {name: [next((slot for slot in row.get("submit_phases") or []
                               if slot.get("phase") == name), None) for row in rows]
                   for name in LOCK_PHASES}
    lifetimes, rejected_phase_durations, observed_reject_times = [], [], []
    roles = defaultdict(set)
    for role, calls in (role_calls or {}).items():
        for call in calls:
            body = phases.digest(call.get("public_request_body_digest"))
            if body is not None:
                roles[body].add(role)
    matched, ambiguous, unassigned = [], 0, 0
    for row in rows:
        life = row.get("lifecycle") or {}
        accepted, closed, task = (optional_number(life.get(key)) for key in
                                  ("accepted_ns", "connection_closed_ns", "task_closed_ns"))
        all_closed = row.get("connection_closed") is True and (
            row.get("task_created") is False or row.get("task_closed") is True)
        finish = max(closed, task if row.get("task_created") is True else closed) if (
            all_closed and closed is not None and (row.get("task_created") is False or task is not None)) else None
        lifetimes.append(finish - accepted if finish is not None and accepted is not None else None)
        body = phases.digest(row.get("body_digest"))
        candidates = roles.get(body, set()) if body is not None else set()
        if len(candidates) > 1:
            ambiguous += 1
        elif not candidates:
            unassigned += 1
        elif candidates == {"attack"}:
            matched.append(row)
            rejected = [slot for slot in row.get("submit_phases") or []
                        if slot.get("completed") is True and slot.get("accepted") is False]
            # Several inclusive phases can describe one failed request. Keep
            # their durations separate; max is never a sum of nested costs.
            durations, times = [], []
            for slot in rejected:
                durations.append(optional_number(slot.get("wall_ns")))
                end = optional_number(slot.get("ended_ns"))
                require(accepted is None or end is None or accepted <= end,
                        "rejecting phase precedes receiver accept")
                times.append(end - accepted if end is not None and accepted is not None else None)
            rejected_phase_durations.append(max(durations) if durations and None not in durations else None)
            observed_reject_times.append(max(times) if times and None not in times else None)
    terminal_codes = Counter(row.get("terminal_error_code") for row in rows if row.get("terminal_error_code") is not None)
    dispatch_codes = Counter(row.get("dispatch_error_code") for row in rows if row.get("dispatch_error_code") is not None)
    return {
        "status": "retained_native_observations", "observer_schema": schema,
        "coverage": {"accepted_connections_seen": seen, "retained_records": len(rows),
                     "records_not_retained": omitted, "measurement_failures": failures,
                     "counter_overflow": overflow, "all_seen_records_closed_and_retained": complete,
                     "unobserved_client_attempts": None},
        "cpu": {"dispatch_thread": statistics([row.get("dispatch_thread_cpu_ns") for row in rows
                                                  if row.get("dispatch_started") is True]),
                "dispatch_unentered_or_unknown": sum(row.get("dispatch_started") is not True for row in rows),
                "full_work_thread": statistics([row.get("full_work_thread_cpu_ns") for row in rows
                                                   if row.get("full_work_started") is True]),
                "full_work_unentered_or_unknown": sum(row.get("full_work_started") is not True for row in rows),
                "settlement": measured.get("cpu_settlement"), "whole_request_cpu_ns": None,
                "scope": "nested thread intervals and separately named original settlement samples; do not add them"},
        "network": {key: statistics([row.get(key) for row in rows], unit="bytes", complete=complete)
                    for key in ("application_bytes_read", "application_bytes_written")}
                   | {"physical_network_bytes": None,
                      "reactor_frame_io": reactor_io,
                      "scope": "observed application socket bytes only; excludes physical framing/retransmissions"},
        "wal": {"status": "not_observed", "bytes": None, "fsync_wall_ns": None,
                "scope": "durable-commit or CPU-settlement wall time is not WAL/fsync instrumentation"},
        "lock_wait": {"stages": [{"phase": name, **interval_latency(slots, phase=True, complete=complete)}
                                  for name, slots in stage_slots.items()],
                      "all_lock_wait_ns": None,
                      "scope": "named owner-wait stages only; no claim to all locks or additive totals"},
        "queue": {name: interval_latency([row.get(name) for row in rows], complete=complete) if v4 else None
                  for name in ("paid_task_queue_wait", "challenge_wait", "grant_wait")}
                 | {
                  "occupancy_high_water": None,
                  "scope": "per-request entered waits; cumulative waiter sums are not request percentiles"},
        "per_request_owner_lifetime": {
            "accept_to_all_owners_closed": statistics(lifetimes, complete=complete),
            "original_owner_readback": lifecycle,
            "scope": "connection/task ownership closure, not cancellation acknowledgement or transaction confirmation"},
        "malicious_rejection": {
            "retained_attack_claim_records": len(matched), "ambiguous_role_records": ambiguous,
            "unattributed_records": unassigned,
            "dispatch_rejected_records": sum(row.get("dispatch_accepted") is False for row in matched),
            "dispatch_unknown_records": sum(row.get("dispatch_accepted") is None for row in matched),
            "first_error_latency": first_error_latency(matched, complete=complete and not ambiguous and not unassigned),
            "max_rejecting_stage_wall_per_request": statistics(rejected_phase_durations),
            "accept_to_last_observed_rejecting_stage_per_request": statistics(observed_reject_times),
            "final_terminal_rejection_latency_ns": None, "worst_case_rejection_bound_ns": None,
            "scope": "body-claim role correlation, not sender authentication; one maximum per retained matched request, no nested sums; missing stages or first-event extensions remain unknown; first errors are separate from response delivery and final owner closure"},
        "cancellation": {
            "all_request_first_errors": error_timing,
            "typed_terminal_errors": dict(terminal_codes) if v4 else None,
            "typed_dispatch_errors": dict(dispatch_codes) if v4 else None,
            "records_with_typed_cancel": sum(any(row.get(key) == "PUBLIC_REQUEST_CANCELLED" for key in
                ("terminal_error_code", "dispatch_error_code")) for row in rows) if v4 else None,
            "signal_to_stop_latency_ns": None, "effects_reconciled": None,
            "scope": "typed errors may follow an accepted dispatch; socket close is not proof of cancellation",
            **({"request_flag_observation": cancellation} if cancellation is not None else {})},
        "recovery": {"status": "not_observed", "planned_recovery_attempts": None,
                     "completed_recoveries": None, "latency_ns": None,
                     "scope": "journal-persisted flags and task closure do not establish restart/reorg recovery"},
        "original_execution_readback": measured,
    }


def missing_host():
    return {"contract": HOST_CONTRACT, "input_status": "not_supplied",
            "phases": [{"mode": mode, "planned_confirmations": 1, "observed_confirmations": None,
                        "status": "not_observed", "metrics": unknown_metrics()}
                       for mode in HOST_MODES], "original_readback": None}


def read_host(path, expected_sha256):
    original_campaign.exact_digest(expected_sha256)
    path = Path(path)
    raw = gate.Evidence(path.parent).read(path.name, 32 * 1024 * 1024)
    require(gate.sha256(raw) == expected_sha256, "Host report SHA256 mismatch")
    document = gate.decode(raw)
    # Bind every original reader reread and every new projection to one snapshot.
    with tempfile.TemporaryDirectory(prefix="trnm-execution-host-") as directory:
        snapshot = Path(directory) / "report.json"
        snapshot.write_bytes(raw)
        old = transactions.read_host_report(snapshot, expected_sha256)
    output = []
    for raw_phase, projected in zip(document["phases"], old["phases"]):
        attack_calls = [row for worker in raw_phase.get("attacks") or [] for row in worker.get("calls") or []]
        roles = {"attack": attack_calls, "honest": raw_phase["honest_submissions"],
                 "history": raw_phase["honest_history"], "head": raw_phase["honest_heads"]}
        metrics = request_metrics(raw_phase.get("observations"), role_calls=roles)
        metrics["sql_commit_calls"] = sql_commit_snapshots(raw_phase)
        output.append({"mode": projected["mode"], "planned_confirmations": 1,
                       "observed_confirmations": projected["supported_independent_confirmation_count"],
                       "status": "retained_observation",
                       "confirmation": projected,
                       "honest_submission_census": call_census(raw_phase["honest_submissions"], planned=7),
                       "metrics": metrics})
    return {"contract": HOST_CONTRACT, "input_status": "pinned_original_report",
            "report_sha256": expected_sha256, "phases": output, "original_readback": old}


def missing_phase(mode):
    rounds = [round_slot(index) for index in ROUNDS]
    return {"mode": mode, "record_present": False, "status": "not_observed",
            "rounds": rounds,
            "transaction_identity_observation": transaction_identity_observations(rounds),
            "metrics": unknown_metrics(), "original_phase_readback": None}


def missing_campaign():
    runs = [{"number": number, "record_present": False, "status": "not_observed",
             "phases": [missing_phase(mode) for mode in phases.MODES]} for number in RUNS]
    return {"contract": CAMPAIGN_CONTRACT, "input_status": "not_supplied", "runs": runs,
            "confirmation_denominator": round_counts([slot for run in runs
                for phase in run["phases"] for slot in phase["rounds"]]),
            "transaction_identity_observation": transaction_identity_observations([slot for run in runs
                for phase in run["phases"] for slot in phase["rounds"]]),
            "strict_original_acceptance_reader_executed": False}


def project_phase(raw, original):
    mode = raw["mode"]
    target = missing_phase(mode)
    target.update(record_present=True, original_phase_readback=original)
    expected_attackers = 0 if mode == "baseline" else 24
    if "duration_seconds" in raw:
        require(type(raw["duration_seconds"]) is int and raw["duration_seconds"] == 30,
                "original thirty-second phase changed")
    if raw.get("startup_or_campaign_error") is not None:
        require(not raw.get("confirmations"), "startup failure cannot silently discard confirmations")
        target.update(status="startup_or_campaign_error", error=raw["startup_or_campaign_error"])
        return target
    require(type(raw.get("attacker_processes_requested")) is int
            and raw["attacker_processes_requested"] == expected_attackers,
            "original 0/24/24 attacker plan changed")
    ready = optional_number(raw.get("attacker_processes_ready"))
    require(ready is None or ready <= expected_attackers, "attacker ready count exceeds original plan")
    rows = raw["confirmations"]
    require(type(rows) is list and len(rows) <= 3, "original three round slots required")
    mapped = {}
    for row in rows:
        index = number(row.get("round"))
        require(index in ROUNDS and index not in mapped, "duplicate or unplanned round")
        mapped[index] = row
    target["rounds"] = [round_slot(index, mapped.get(index)) for index in ROUNDS]
    target["transaction_identity_observation"] = transaction_identity_observations(target["rounds"])
    children = raw["children"]
    require(type(children) is list and len(children) <= expected_attackers, "unplanned attacker children")
    attacks = [row for child in children for row in ((child.get("report") or {}).get("result") or {}).get("calls", [])]
    roles = {"attack": attacks, "honest": raw["submissions"], "history": raw["history"]}
    target.update(status="retained_observation", declared_phase_criteria_met=raw.get("finite_phase_criteria_met"),
                  attacker_processes_requested=expected_attackers, attacker_processes_ready=ready,
                  attacker_child_records=len(children), missing_attacker_child_records=expected_attackers - len(children),
                  confirmation_counts=round_counts(target["rounds"]),
                  successful_confirmation_latency=statistics([row["successful_latency_ns"] for row in target["rounds"]]),
                  honest_submission_census=call_census(raw["submissions"], planned=21),
                  history_call_census=call_census(raw["history"], planned=21),
                  attacker_call_census=call_census(attacks),
                  metrics=request_metrics(raw["receiver_observation"], role_calls=roles))
    target["metrics"]["sql_commit_calls"] = sql_commit_snapshots(raw)
    return target


def read_campaign(root, manifest_sha256, expected_head, expected_tree, *, retained_subset=False):
    """Reuse pinned artifact I/O, while retaining failed and absent original runs.

    This is deliberately separate from original_campaign.read_campaign(), whose
    successful-native acceptance requirements are unchanged. The run header's
    original plan must match; actual failures and absent records do not alter it.
    """
    original_campaign.exact_digest(expected_head, 40)
    original_campaign.exact_digest(expected_tree, 40)
    bundle = (original_campaign.SubsetBundle if retained_subset else original_campaign.Bundle)(root, manifest_sha256)
    try:
        result = bundle.json("results.json")
        require(type(result) is dict, "campaign result object required")
        identity = {"schema": "pon-original-native-campaign-ci-v1",
                    "expected_head": expected_head, "expected_tree": expected_tree,
                    "source_kind": "head", "profile": "release", "toolchain": "1.95.0",
                    "state_backend": "authenticated-v1", "planned_complete_runs": 3,
                    "original_inputs": original_campaign.INPUTS,
                    "build_timeout_seconds": 1800, "original_campaign_outer_timeout_seconds": 600,
                    "expected_resources": CAMPAIGN_CONTRACT["controller_resources"]}
        require(all(same_value(result.get(key), value) for key, value in identity.items()),
                "original campaign identity/resource/window/denominator mismatch")
        if retained_subset:
            require(same_value(bundle.retention.get("source"), {"head": expected_head, "tree": expected_tree}),
                    "retained subset source mismatch")
        attempts = result.get("attempts")
        require(type(attempts) is list and len(attempts) <= 3, "bounded original attempts required")
        indexed = {}
        for attempt in attempts:
            require(type(attempt) is dict, "attempt object required")
            index = number(attempt.get("number"))
            require(index in RUNS and index not in indexed, "duplicate or unplanned run")
            require(attempt.get("report_directory") == f"run-{index}-raw", "original report directory mismatch")
            indexed[index] = attempt
        out = missing_campaign()
        out.update(input_status="pinned_original_bundle", artifact_manifest_sha256=manifest_sha256,
                   simulated_control=result.get("simulated_control") is True,
                   measured_head=expected_head, measured_tree=expected_tree,
                   artifact_coverage=bundle.coverage, original_manifest_files=len(bundle.files),
                   verified_original_files=len(bundle.verified_paths),
                   original_result={key: result.get(key) for key in
                       ("complete_success", "failure", "finalization_failures", "build", "binary",
                        "public_phase_placement", "expected_public_policy_id")})
        for run in out["runs"]:
            index = run["number"]
            attempt = indexed.get(index)
            name = f"run-{index}-raw/report.json"
            if attempt is None:
                require(name not in bundle.verified_paths, "retained report without its original run record")
                continue
            run.update(record_present=True, original_attempt=attempt, status="run_record_without_report")
            result_name = f"run-{index}-result.json"
            if result_name in bundle.verified_paths:
                require(bundle.json(result_name) == attempt, "duplicate original attempt record disagrees")
            if name not in bundle.verified_paths:
                run["report_retention"] = "not_retained" if name in bundle.files else "not_listed_by_producer"
                continue
            require(attempt.get("report_sha256") == bundle.files[name]["sha256"], "original run report hash mismatch")
            report = bundle.json(name)
            require(type(report) is dict, "campaign report object required")
            out["simulated_control"] |= report.get("simulated_control") is True
            require(report.get("schema") == "native-public-v3-separate-process-campaign-v2"
                    and report.get("state_backend") == "authenticated-v1" and "work_profile" not in report,
                    "original campaign namespace required; research profiles remain separate")
            prep = report.get("preparation")
            require(type(prep) is dict and prep.get("state_backend") == "authenticated-v1"
                    and same_value(prep.get("actual_signed_seed_transfers"), 1024)
                    and same_value(prep.get("seed_blocks"), 4) and same_value(prep.get("business_blocks"), 21),
                    "original preparation workload mismatch")
            require(all(report.get(key) is not True for key in (
                "cryptographic_hardness_qualified", "work_profile_qualified", "independent_operators",
                "wan_qualified", "production_candidate", "release_ready")), "unsupported native qualification claim")
            derived = phases.analyze(report)
            pin = result.get("expected_public_policy_id")
            if pin is not None:
                original_campaign.exact_digest(pin)
                require("public_resource_policy" in report
                        and phases.identify_observation(report["public_resource_policy"])["policy_id"] == pin,
                        "pinned public resource policy mismatch")
            run.update(status="retained_original_report", report_sha256=attempt["report_sha256"],
                       declared_finite_criteria_met=report.get("finite_experiment_criteria_met"),
                       preparation_cpu_ns=derived["honest_preparation_cpu_ns"],
                       preparation_wall_ns=derived["honest_preparation_wall_ns"],
                       phases=[project_phase(raw, projected) for raw, projected in zip(report["phases"], derived["phases"])])
        out["confirmation_denominator"] = round_counts([slot for run in out["runs"]
            for phase in run["phases"] for slot in phase["rounds"]])
        out["transaction_identity_observation"] = transaction_identity_observations([slot for run in out["runs"]
            for phase in run["phases"] for slot in phase["rounds"]])
        out["scope"] = {"reads_failed_attempts": True, "reader_executes_native_test": False,
                        "hash_consistency_is_not_execution_or_custody_authentication": True,
                        "resource_enforcement_verified": False, "source_receipts_revalidated": False,
                        "successful_original_acceptance_reader_unchanged": True,
                        "observed_rounds_are_not_independent_trials": True,
                        "sustainable_business_tps": None}
        return out
    finally:
        bundle.close()


def build_report(*, host_report=None, host_report_sha256=None, campaign_dir=None,
                 campaign_manifest_sha256=None, expected_head=None, expected_tree=None, retained_subset=False):
    require((host_report is None) == (host_report_sha256 is None), "Host path and SHA256 required together")
    campaign_args = (campaign_dir, campaign_manifest_sha256, expected_head, expected_tree)
    require(all(value is None for value in campaign_args) or all(value is not None for value in campaign_args),
            "campaign path, manifest SHA256, head and tree required together")
    require(not retained_subset or campaign_dir is not None, "subset flag requires campaign input")
    host = read_host(host_report, host_report_sha256) if host_report is not None else missing_host()
    campaign = read_campaign(campaign_dir, campaign_manifest_sha256, expected_head, expected_tree,
                             retained_subset=retained_subset) if campaign_dir is not None else missing_campaign()
    simulated = (host["original_readback"] or {}).get("simulated_control") is True or campaign.get("simulated_control") is True
    return {"schema": SCHEMA, "qualification": "HOLD_NO_GO", "native_executions_started": 0,
            "contains_explicit_simulated_control": simulated,
            "original_host_4s": host, "original_campaign_30s": campaign,
            "reader_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "original_reader_sha256": {module.__name__: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
                                       for module in (transactions, original_campaign, phases)},
            "scope": {"contracts_combined": False, "deadlines_relaxed": False,
                      "cross_contract_latency_pooling": False, "combined_tps": None,
                      "original_acceptance_gates_changed": False, "production_activation": False,
                      "reader_file_hashes_are_runtime_attestation": False,
                      "missing_measurements_are_zero": False,
                      "completed_readback_is_service_qualification": False}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-report", type=Path)
    parser.add_argument("--host-report-sha256")
    parser.add_argument("--campaign-dir", type=Path)
    parser.add_argument("--campaign-manifest-sha256")
    parser.add_argument("--expected-head")
    parser.add_argument("--expected-tree")
    parser.add_argument("--retained-subset", action="store_true")
    parser.add_argument("--output", type=Path, help="Create a new report; never overwrite original observations")
    args = vars(parser.parse_args(argv))
    output = args.pop("output")
    try:
        require(args["host_report"] is not None or args["campaign_dir"] is not None, "at least one pinned input is required")
        report = build_report(**args)
        raw = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if output is not None:
            with output.open("x", encoding="utf-8") as stream:
                stream.write(raw)
        else:
            print(raw, end="")
    except (OSError, ValueError, KeyError, TypeError, IndexError, RecursionError) as error:
        print(f"execution report refused: {error}", file=sys.stderr)
        return 2
    return 1  # Valid retained evidence remains HOLD, including historical passes.


if __name__ == "__main__":
    raise SystemExit(main())
