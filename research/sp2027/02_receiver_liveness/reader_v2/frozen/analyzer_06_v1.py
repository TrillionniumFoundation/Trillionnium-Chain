#!/usr/bin/env python3
"""Strict finite-window business-confirmation accounting (standard library only).

The analyzer checks evidence structure, bindings and declared policy predicates.
It does not execute a chain verifier, authenticate an observer, or prove finality.
Use a native authenticated observation path for those responsibilities.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA = "sp27-confirmed-goodput-contract-v1"
SCOPES = {"native_experiment", "archival_reanalysis", "synthetic_validation"}
EVENT_TYPES = {"request_start", "confirmation", "invalidate", "failure", "cancelled", "not_started",
               "unknown", "ack", "head", "admitted", "seed", "stage", "attempt_end",
               "attack_start", "attack_stop", "observer_end", "resource"}
FLAGS = ("full_verification", "admission", "host", "history", "activation")
ADDITIVE = {"cpu_ns", "read_bytes", "write_bytes", "network_rx_bytes",
            "network_tx_bytes", "energy_microjoules"}
GAUGES = {"peak_rss_bytes", "storage_bytes"}
RESOURCE_SCOPES = {"setup", "warmup", "window", "drain", "recovery", "whole_lifecycle"}
HEX = re.compile(r"(?:0x)?[0-9a-fA-F]+\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ValidationError(ValueError):
    """Malformed or internally contradictory evidence; no usable result emitted."""


def require(condition, code):
    if not condition:
        raise ValidationError(code)


def integer(value, code, nullable=False):
    if nullable and value is None:
        return None
    require(type(value) is int and value >= 0, code)
    return value


def string(value, code, nullable=False):
    if nullable and value is None:
        return None
    require(type(value) is str and bool(value.strip()), code)
    return value


def boolean(value, code):
    require(type(value) is bool, code)
    return value


def work(value, code):
    require(type(value) is str and HEX.fullmatch(value) is not None, code)
    return int(value, 16)


def _finite(value):
    if isinstance(value, dict):
        for v in value.values():
            _finite(v)
    elif isinstance(value, list):
        for v in value:
            _finite(v)
    elif isinstance(value, float):
        require(math.isfinite(value), "NONFINITE_NUMBER")


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        require(k not in result, "DUPLICATE_JSON_KEY:" + k)
        result[k] = v
    return result


def _constant(_value):
    raise ValidationError("NONFINITE_NUMBER")


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"),
                          object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("INVALID_JSON:" + str(path)) from exc


def read_jsonl(path):
    rows = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line, object_pairs_hook=_pairs, parse_constant=_constant)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"INVALID_JSONL:{path}:{line_number}") from exc
        require(isinstance(row, dict), f"JSONL_OBJECT_REQUIRED:{line_number}")
        rows.append(row)
    return rows


def load(contract_path, schedule_path=None, events_path=None):
    """Load three explicit paths, or a directory with their conventional names."""
    base = Path(contract_path)
    if base.is_dir():
        require(schedule_path is None and events_path is None, "AMBIGUOUS_PATHS")
        return load(base / "contract.json", base / "schedule.jsonl", base / "events.jsonl")
    require(schedule_path is not None and events_path is not None, "THREE_INPUT_PATHS_REQUIRED")
    return read_json(base), read_jsonl(schedule_path), read_jsonl(events_path)


def _validate_contract(contract):
    require(isinstance(contract, dict), "CONTRACT_OBJECT")
    _finite(contract)
    require(contract.get("schema") == SCHEMA, "CONTRACT_SCHEMA")
    scope = contract.get("evidence_scope")
    require(scope in SCOPES, "EVIDENCE_SCOPE")
    require(isinstance(contract.get("runs"), list) and contract["runs"], "RUNS_REQUIRED")
    runs = {}
    for r in contract["runs"]:
        require(isinstance(r, dict), "RUN_OBJECT")
        rid = string(r.get("run_id"), "RUN_ID")
        require(rid not in runs, "DUPLICATE_RUN:" + rid)
        for name in ("chain_instance_id", "profile_id", "clock_id", "observer_id"):
            string(r.get(name), "RUN_" + name.upper())
        a = integer(r.get("window_start_ns"), "WINDOW_START")
        b = integer(r.get("window_end_ns"), "WINDOW_END")
        require(a < b, "WINDOW_ORDER")
        p = r.get("confirmation_policy")
        require(isinstance(p, dict), "CONFIRMATION_POLICY")
        string(p.get("policy_id"), "POLICY_ID")
        integer(p.get("min_depth"), "MIN_DEPTH")
        require(p.get("semantics") in {"first_observed", "valid_at_window_end"}, "CONFIRMATION_SEMANTICS")
        require(p.get("window_end_rule", "inclusive") in {"inclusive", "exclusive"}, "WINDOW_END_RULE")
        if scope == "native_experiment":
            require("window_end_rule" in p, "NATIVE_WINDOW_END_RULE_REQUIRED")
        if "require_native_window_gate" in p:
            boolean(p["require_native_window_gate"], "NATIVE_WINDOW_GATE_POLICY_TYPE")
        if p.get("required_work_delta") is not None:
            work(p["required_work_delta"], "POLICY_WORK")
        if "invalidation_coverage_complete" in p:
            boolean(p["invalidation_coverage_complete"], "INVALIDATION_COVERAGE_TYPE")
        identity = r.get("identity")
        require(isinstance(identity, dict), "RUN_IDENTITY")
        for name in ("source_commit", "source_tree", "binary_sha256", "config_sha256"):
            value = identity.get(name)
            if value is not None:
                length = 40 if name in {"source_commit", "source_tree"} else 64
                require(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value), "IDENTITY_" + name.upper())
            elif scope == "native_experiment":
                raise ValidationError("NATIVE_IDENTITY_MISSING:" + name)
        if "expected_resource_owners" in r:
            owners = r["expected_resource_owners"]
            require(isinstance(owners, list), "RESOURCE_OWNERS")
            for owner in owners:
                string(owner, "RESOURCE_OWNER")
            require(len(owners) == len(set(owners)), "DUPLICATE_RESOURCE_OWNER")
        if "resource_inventory_complete" in r:
            boolean(r["resource_inventory_complete"], "RESOURCE_INVENTORY_TYPE")
        if "event_coverage_complete" in r:
            boolean(r["event_coverage_complete"], "EVENT_COVERAGE_TYPE")
        recovery = r.get("recovery")
        if recovery is not None:
            require(isinstance(recovery, dict), "RECOVERY_OBJECT")
            for name in ("attack_stop_ns", "bin_ns", "consecutive_bins", "min_planned_per_bin", "latency_slo_ns"):
                integer(recovery.get(name), "RECOVERY_" + name.upper())
            require(recovery["bin_ns"] > 0 and recovery["consecutive_bins"] > 0 and recovery["min_planned_per_bin"] > 0,
                    "RECOVERY_POSITIVE_PARAMETERS")
            require(a <= recovery["attack_stop_ns"] <= b, "RECOVERY_STOP_OUTSIDE_WINDOW")
            fraction = recovery.get("min_success_fraction")
            require(type(fraction) in {int, float} and 0 <= fraction <= 1, "RECOVERY_FRACTION")
        runs[rid] = r
    return runs


def _validate_schedule(schedule, runs, scope):
    require(isinstance(schedule, list), "SCHEDULE_LIST")
    operations, tx_owner = {}, {}
    for row in schedule:
        require(isinstance(row, dict), "SCHEDULE_OBJECT")
        _finite(row)
        oid = string(row.get("operation_id"), "OPERATION_ID")
        require(oid not in operations, "DUPLICATE_OPERATION:" + oid)
        rid = row.get("run_id")
        require(rid in runs, "SCHEDULE_UNKNOWN_RUN")
        r = runs[rid]
        scheduled = integer(row.get("scheduled_ns"), "SCHEDULED_NS", nullable=True)
        if scope == "native_experiment":
            require(scheduled is not None, "NATIVE_PLANNED_ARRIVAL_MISSING")
        if scheduled is not None:
            require(r["window_start_ns"] <= scheduled < r["window_end_ns"], "SCHEDULE_OUTSIDE_WINDOW")
        deadline = integer(row.get("deadline_ns"), "DEADLINE_NS", nullable=True)
        if deadline is not None and scheduled is not None:
            require(deadline >= scheduled, "DEADLINE_BEFORE_SCHEDULE")
        string(row.get("plan_provenance"), "PLAN_PROVENANCE")
        ids = row.get("transaction_ids")
        require(isinstance(ids, list) and ids, "TRANSACTION_IDS_REQUIRED")
        for tx in ids:
            string(tx, "TRANSACTION_ID")
            key = (r["chain_instance_id"], tx)
            require(key not in tx_owner, "TRANSACTION_ALIASES_MULTIPLE_OPERATIONS:" + tx)
            tx_owner[key] = oid
        require(len(ids) == len(set(ids)), "DUPLICATE_TRANSACTION_ID")
        for name in ("content_id", "useful_compute_id", "useful_compute_evidence"):
            string(row.get(name), name.upper(), nullable=True)
        if row.get("required_work_delta") is not None:
            work(row["required_work_delta"], "SCHEDULE_WORK")
        require(row.get("required_work_delta") is not None or r["confirmation_policy"].get("required_work_delta") is not None,
                "FROZEN_REQUIRED_WORK_MISSING")
        operations[oid] = row
    return operations


def _validate_events(events, runs, operations):
    require(isinstance(events, list), "EVENTS_LIST")
    unique, duplicates = {}, 0
    for e in events:
        require(isinstance(e, dict), "EVENT_OBJECT")
        _finite(e)
        eid = string(e.get("event_id"), "EVENT_ID")
        if eid in unique:
            require(unique[eid] == e, "CONFLICTING_EVENT_ID:" + eid)
            duplicates += 1
            continue
        rid = e.get("run_id")
        require(rid in runs, "EVENT_UNKNOWN_RUN")
        kind = e.get("type")
        require(kind in EVENT_TYPES, "EVENT_TYPE")
        integer(e.get("at_ns"), "EVENT_TIMESTAMP", nullable=True)
        string(e.get("clock_id"), "EVENT_CLOCK")
        string(e.get("actor_id"), "EVENT_ACTOR")
        string(e.get("attempt_id"), "ATTEMPT_ID", nullable=True)
        oid = e.get("operation_id")
        if oid is not None:
            require(oid in operations and operations[oid]["run_id"] == rid, "EVENT_OPERATION_BINDING")
        elif kind in {"request_start", "confirmation", "invalidate", "failure", "cancelled", "unknown", "not_started"}:
            raise ValidationError("OPERATION_REQUIRED:" + kind)
        if kind == "confirmation":
            for name in ("transaction_id", "block_id", "policy_id"):
                string(e.get(name), "CONFIRMATION_" + name.upper())
            integer(e.get("depth"), "CONFIRMATION_DEPTH")
            work(e.get("work_delta"), "CONFIRMATION_WORK")
            work(e.get("required_work_delta"), "CONFIRMATION_REQUIRED_WORK")
            boolean(e.get("execution_authority"), "CONFIRMATION_AUTHORITY_TYPE")
            if "native_window_gate" in e:
                boolean(e["native_window_gate"], "NATIVE_WINDOW_GATE_TYPE")
            flags = e.get("flags")
            require(isinstance(flags, dict), "CONFIRMATION_FLAGS")
            for name in FLAGS:
                if name in flags:
                    boolean(flags[name], "CONFIRMATION_FLAG_TYPE:" + name)
            proof = e.get("provenance")
            require(isinstance(proof, dict), "CONFIRMATION_PROVENANCE")
            require(type(proof.get("artifact_sha256")) is str and SHA256.fullmatch(proof["artifact_sha256"]), "PROVENANCE_SHA256")
            string(proof.get("member"), "PROVENANCE_MEMBER")
            pointer = proof.get("pointer")
            require(type(pointer) is str and (pointer == "" or pointer.startswith("/")), "PROVENANCE_POINTER")
        elif kind == "invalidate":
            string(e.get("target_event_id"), "INVALIDATION_TARGET")
        elif kind == "resource":
            require(e.get("metric") in ADDITIVE | GAUGES, "RESOURCE_METRIC")
            integer(e.get("value"), "RESOURCE_VALUE")
            string(e.get("owner_id"), "RESOURCE_OWNER")
            require(e.get("scope") in RESOURCE_SCOPES, "RESOURCE_SCOPE")
            boolean(e.get("inclusive"), "RESOURCE_INCLUSIVE")
            require(e.get("coverage") in {"complete", "partial", "unknown"}, "RESOURCE_COVERAGE")
            a = integer(e.get("started_ns"), "RESOURCE_START", nullable=True)
            b = integer(e.get("ended_ns"), "RESOURCE_END", nullable=True)
            require((a is None) == (b is None), "RESOURCE_PARTIAL_INTERVAL")
            if a is not None:
                require(a <= b, "RESOURCE_INTERVAL_REVERSED")
        unique[eid] = e
    for e in unique.values():
        if e["type"] == "invalidate":
            target = unique.get(e["target_event_id"])
            require(target is not None and target["type"] == "confirmation", "UNKNOWN_INVALIDATION_TARGET")
            require(target["operation_id"] == e["operation_id"] and target["run_id"] == e["run_id"], "INVALIDATION_BINDING")
            if e["clock_id"] == target["clock_id"] and e.get("at_ns") is not None and target.get("at_ns") is not None:
                require(e["at_ns"] >= target["at_ns"], "INVALIDATION_BEFORE_CONFIRMATION")
    return list(unique.values()), duplicates


def _confirmation_reasons(e, op, run, started, invalidations):
    p = run["confirmation_policy"]
    reasons = []
    if e["actor_id"] != run["observer_id"]:
        reasons.append("WRONG_OBSERVER")
    if e["clock_id"] != run["clock_id"]:
        reasons.append("CLOCK_DOMAIN_UNMAPPED")
    if e["at_ns"] is None:
        reasons.append("CONFIRMATION_TIME_MISSING")
    else:
        if e["at_ns"] < run["window_start_ns"]:
            reasons.append("CONFIRMATION_BEFORE_WINDOW")
        if op["scheduled_ns"] is not None and e["at_ns"] < op["scheduled_ns"]:
            reasons.append("CONFIRMATION_BEFORE_SCHEDULE")
        if started is not None and e["at_ns"] < started:
            reasons.append("CONFIRMATION_BEFORE_REQUEST")
    if e["transaction_id"] not in op["transaction_ids"]:
        reasons.append("TRANSACTION_BINDING")
    if op.get("expected_block_id") is not None and e["block_id"] != op["expected_block_id"]:
        reasons.append("BLOCK_BINDING")
    if e["policy_id"] != p["policy_id"]:
        reasons.append("POLICY_BINDING")
    if e["depth"] < p["min_depth"]:
        reasons.append("INSUFFICIENT_DEPTH")
    frozen_value = op.get("required_work_delta")
    frozen = work(frozen_value if frozen_value is not None else p.get("required_work_delta"), "FROZEN_WORK")
    if work(e["required_work_delta"], "WORK") != frozen:
        reasons.append("REQUIRED_WORK_BINDING")
    if work(e["work_delta"], "WORK") < frozen:
        reasons.append("INSUFFICIENT_WORK")
    if e["execution_authority"]:
        reasons.append("OBSERVATION_AUTHORITY_MISMATCH")
    if p.get("require_native_window_gate") is True and e.get("native_window_gate") is not True:
        reasons.append("NATIVE_WINDOW_GATE_NOT_TRUE")
    reasons.extend("MISSING_OR_FALSE_" + flag.upper() for flag in FLAGS if e["flags"].get(flag) is not True)
    if p["semantics"] == "valid_at_window_end":
        if p.get("invalidation_coverage_complete") is not True:
            reasons.append("INVALIDATION_COVERAGE_UNKNOWN")
        for invalid in invalidations:
            if invalid["target_event_id"] != e["event_id"]:
                continue
            if invalid["at_ns"] is None or invalid["clock_id"] != run["clock_id"]:
                reasons.append("INVALIDATION_TIME_UNKNOWN")
            elif invalid["at_ns"] <= run["window_end_ns"]:
                reasons.append("INVALIDATED_BY_WINDOW_END")
    return reasons


def _before_endpoint(at, end, policy):
    return at <= end if policy.get("window_end_rule", "inclusive") == "inclusive" else at < end


def _quantiles(values, successes, planned):
    v = sorted(values)
    result = {"n_observed": len(v), "n_successes": successes,
              "n_missing_among_successes": successes - len(v), "planned_denominator": planned,
              "nonconfirmation_count": planned - successes,
              "nonconfirmation_fraction": (planned - successes) / planned if planned else None,
              "definition": "nearest-rank, conditional on timely valid confirmation and observed latency"}
    for q in (50, 90, 95, 99):
        result["p" + str(q)] = v[(q * len(v) + 99) // 100 - 1] if v else None
    result["max"] = max(v) if v else None
    return result


def _resources(events, run, confirmations):
    rows = [e for e in events if e["type"] == "resource"]
    output = {"records": len(rows), "inclusive_nested_records_excluded": sum(e["inclusive"] for e in rows),
              "inclusive_observations": [
                  {"event_id": e["event_id"], "metric": e["metric"], "value": e["value"],
                   "owner_id": e["owner_id"], "scope": e["scope"], "coverage": e["coverage"],
                   "clock_id": e["clock_id"], "started_ns": e["started_ns"], "ended_ns": e["ended_ns"],
                   "native_field": e.get("native_field"), "provenance": e.get("provenance"),
                   "excluded_from_sum_reason": e.get("nonadditive_reason", "inclusive nested span; never add to its enclosing owner interval")}
                  for e in rows if e["inclusive"]],
              "no_wall_fraction_cpu_imputation": True, "metrics": {}, "all_costs_measured": False,
              "coverage_note": "Observed scoped costs are partial unless both the owner inventory and every required record are complete."}
    expected = set(run.get("expected_resource_owners", []))
    inventory_complete = run.get("resource_inventory_complete") is True and bool(expected)
    for metric in sorted(ADDITIVE | GAUGES):
        selected = [e for e in rows if e["metric"] == metric and not e["inclusive"]]
        if not selected:
            continue
        owners = defaultdict(list)
        for e in selected:
            owners[e["owner_id"]].append(e)
        details = {}
        all_unambiguous = True
        window_known = True
        window_total = 0
        for owner, measurements in sorted(owners.items()):
            unknown_interval = any(e["started_ns"] is None for e in measurements)
            clocks = {e["clock_id"] for e in measurements}
            if metric in ADDITIVE and not unknown_interval and len(clocks) == 1:
                ordered = sorted(measurements, key=lambda x: (x["started_ns"], x["ended_ns"], x["event_id"]))
                for prev, nxt in zip(ordered, ordered[1:]):
                    require(prev["ended_ns"] <= nxt["started_ns"], "OVERLAPPING_EXCLUSIVE_RESOURCE_SPANS:" + owner + ":" + metric)
            unambiguous = len(measurements) == 1 or (not unknown_interval and len(clocks) == 1)
            all_unambiguous &= unambiguous
            values = [e["value"] for e in measurements]
            total = sum(values) if metric in ADDITIVE and unambiguous else None
            details[owner] = {"records": len(measurements), "observed_total": total,
                              "max_observed_gauge": max(values) if metric in GAUGES else None,
                              "scopes": sorted({e["scope"] for e in measurements}),
                              "coverage_complete": all(e["coverage"] == "complete" for e in measurements),
                              "intervals_unambiguous": unambiguous}
            for e in measurements:
                a, b = e["started_ns"], e["ended_ns"]
                if e["clock_id"] != run["clock_id"] or a is None:
                    window_known = False
                elif a >= run["window_start_ns"] and b <= run["window_end_ns"]:
                    window_total += e["value"]
                elif b <= run["window_start_ns"] or a >= run["window_end_ns"]:
                    pass
                else:
                    window_known = False
        complete = inventory_complete and set(owners) == expected and all(e["coverage"] == "complete" for e in selected) and all_unambiguous
        total = sum(e["value"] for e in selected) if metric in ADDITIVE and all_unambiguous else None
        output["metrics"][metric] = {"owners": details, "observed_disjoint_total": total,
                                     "complete_total": total if complete else None,
                                     "coverage_complete": complete,
                                     "exact_window_total": window_total if metric in ADDITIVE and complete and window_known else None,
                                     "observed_cost_per_confirmation": total / confirmations if total is not None and confirmations else None,
                                     "gauge_peaks_are_not_summed": metric in GAUGES}
    output["all_costs_measured"] = False  # Unlisted metric/owner coverage cannot be inferred.
    return output


def _recovery(run, ops):
    cfg = run.get("recovery")
    if cfg is None:
        return {"status": "not_measured", "recovery_time_ns": None, "reason": "NO_PREDECLARED_RECOVERY_CRITERION"}
    stop, width = cfg["attack_stop_ns"], cfg["bin_ns"]
    bins, consecutive = [], 0
    recovered = None
    for a in range(stop, run["window_end_ns"], width):
        b = a + width
        if b > run["window_end_ns"]:
            break
        group = [o for o in ops if o["scheduled_ns"] is not None and a <= o["scheduled_ns"] < b]
        good = sum(o["confirmed_in_window"] and o["confirmation_ns"] is not None
                   and _before_endpoint(o["confirmation_ns"], b, run["confirmation_policy"])
                   and o["confirmation_ns"] - o["scheduled_ns"] <= cfg["latency_slo_ns"] for o in group)
        passing = len(group) >= cfg["min_planned_per_bin"] and good / len(group) >= cfg["min_success_fraction"]
        consecutive = consecutive + 1 if passing else 0
        bins.append({"start_ns": a, "end_ns": b, "planned": len(group), "timely": good, "passing": passing})
        if recovered is None and consecutive >= cfg["consecutive_bins"]:
            recovered = {"status": "observed", "recovery_time_ns": b - stop,
                         "sustained_interval_start_ns": b - cfg["consecutive_bins"] * width,
                         "criterion_confirmed_at_ns": b}
    if recovered is None:
        recovered = {"status": "right_censored", "recovery_time_ns": None,
                     "observed_post_stop_ns": run["window_end_ns"] - stop}
    recovered["bins"] = bins
    recovered["definition"] = "time until all predeclared consecutive recovery bins have completed"
    return recovered


def analyze(contract, schedule=None, events=None):
    """Analyze dictionaries/lists, or a directory path using load(path)."""
    if isinstance(contract, (str, Path)):
        require(schedule is None and events is None, "PATH_ANALYSIS_TAKES_ONE_ARGUMENT")
        contract, schedule, events = load(contract)
    runs = _validate_contract(contract)
    operations = _validate_schedule(schedule, runs, contract["evidence_scope"])
    clean, duplicates = _validate_events(events, runs, operations)
    by_op, by_run = defaultdict(list), defaultdict(list)
    for event in clean:
        by_run[event["run_id"]].append(event)
        if event.get("operation_id") is not None:
            by_op[event["operation_id"]].append(event)
    op_results = []
    rejected = []
    for oid, op in sorted(operations.items(), key=lambda kv: (kv[1]["run_id"], kv[0])):
        r = runs[op["run_id"]]
        own = by_op[oid]
        starts = [e["at_ns"] for e in own if e["type"] == "request_start" and e["clock_id"] == r["clock_id"] and e["at_ns"] is not None]
        started = min(starts) if starts else None
        explicitly_unstarted = any(e["type"] == "not_started" and e["clock_id"] == r["clock_id"] for e in own)
        require(not (explicitly_unstarted and started is not None), "CONTRADICTORY_NOT_STARTED_AND_REQUEST_START")
        if started is not None:
            require(started >= r["window_start_ns"], "REQUEST_BEFORE_WINDOW")
            require(op["scheduled_ns"] is None or started >= op["scheduled_ns"], "REQUEST_BEFORE_SCHEDULE")
        invalidations = [e for e in own if e["type"] == "invalidate"]
        valid, observed_gate_failed = [], []
        for e in own:
            if e["type"] != "confirmation":
                continue
            reasons = _confirmation_reasons(e, op, r, started, invalidations)
            if reasons:
                rejected.append({"event_id": e["event_id"], "operation_id": oid, "run_id": r["run_id"], "reasons": reasons})
                if set(reasons) == {"NATIVE_WINDOW_GATE_NOT_TRUE"}:
                    observed_gate_failed.append(e)
            else:
                valid.append(e)
        valid.sort(key=lambda e: (e["at_ns"], e["event_id"]))
        observed_gate_failed.sort(key=lambda e: (e["at_ns"], e["event_id"]))
        first = valid[0] if valid else (observed_gate_failed[0] if observed_gate_failed else None)
        native_gate_failed = first is not None and not valid
        confirmed_at = first["at_ns"] if first else None
        time_inside = confirmed_at is not None and _before_endpoint(confirmed_at, r["window_end_ns"], r["confirmation_policy"])
        timely = time_inside and not native_gate_failed
        terminal = [e for e in own if e["type"] in {"failure", "cancelled", "unknown"}]
        terminal_known = [e for e in terminal if e["clock_id"] == r["clock_id"] and e["at_ns"] is not None and e["at_ns"] <= r["window_end_ns"]]
        terminal_time_unknown = [e for e in terminal if e["clock_id"] != r["clock_id"] or e["at_ns"] is None]
        terminal_known.sort(key=lambda e: (e["at_ns"], e["event_id"]))
        if timely:
            outcome = "confirmed"
        elif confirmed_at is not None and not time_inside:
            outcome = "late_confirmed"
        elif native_gate_failed:
            outcome = "unconfirmed"
        elif terminal_known:
            outcome = {"failure": "failed", "cancelled": "cancelled", "unknown": "unknown"}[terminal_known[-1]["type"]]
        elif terminal_time_unknown:
            outcome = "unknown"
        elif started is None:
            outcome = "unstarted" if explicitly_unstarted or (not own and r.get("event_coverage_complete") is True) else "unknown"
        else:
            outcome = "unconfirmed"
        sched = op["scheduled_ns"]
        end_latency = confirmed_at - sched if timely and sched is not None else None
        service = confirmed_at - started if timely and started is not None else None
        deadline = op.get("deadline_ns")
        slo = None
        if deadline is not None:
            if timely and confirmed_at <= deadline:
                slo = True
            elif deadline <= r["window_end_ns"]:
                slo = False
        administrative_censoring = not timely and outcome in {"unconfirmed", "unstarted", "late_confirmed"}
        op_results.append({"operation_id": oid, "run_id": r["run_id"], "chain_instance_id": r["chain_instance_id"],
                           "profile_id": r["profile_id"], "scheduled_ns": sched, "request_started_ns": started,
                           "start_lateness_ns": started - sched if started is not None and sched is not None else None,
                           "deadline_ns": deadline, "confirmation_ns": confirmed_at, "confirmed_in_window": timely,
                           "deadline_success": slo, "outcome": outcome, "end_to_end_latency_ns": end_latency,
                           "actual_start_latency_ns": service, "confirmation_event_id": first["event_id"] if first else None,
                           "native_window_gate_failed": native_gate_failed,
                           "observed_confirmation_latency_from_schedule_ns": confirmed_at - sched if confirmed_at is not None and sched is not None else None,
                           "observed_late_latency_from_schedule_ns": confirmed_at - sched if confirmed_at is not None and not time_inside and sched is not None else None,
                           "confirmed_transaction_id": first["transaction_id"] if first else None,
                           "content_id": op.get("content_id"), "useful_compute_id": op.get("useful_compute_id"),
                           "useful_compute_evidence_present": bool(op.get("useful_compute_evidence")),
                           "confirmation_observations": sum(e["type"] == "confirmation" for e in own),
                           "invalidation_observations": len(invalidations),
                           "terminal_outcomes_observed": sorted({e["type"] for e in terminal}),
                           "administratively_censored_at_window": administrative_censoring,
                           "censor_elapsed_from_schedule_ns": r["window_end_ns"] - sched if administrative_censoring and sched is not None else None,
                           "observation_window_elapsed_from_schedule_ns": r["window_end_ns"] - sched if not timely and sched is not None else None,
                           "latency_missing_is_not_zero": True})
    reports = []
    for rid, r in sorted(runs.items()):
        group = [o for o in op_results if o["run_id"] == rid]
        success = [o for o in group if o["confirmed_in_window"]]
        n, k = len(group), len(success)
        elapsed = r["window_end_ns"] - r["window_start_ns"]
        known_slo = [o for o in group if o["deadline_success"] is not None]
        latency = [o["end_to_end_latency_ns"] for o in success if o["end_to_end_latency_ns"] is not None]
        counts = Counter(latency)
        cumulative, cdf = 0, []
        for t, count in sorted(counts.items()):
            cumulative += count
            cdf.append({"latency_ns": t, "confirmed_by_latency": cumulative, "planned_denominator": n,
                        "fraction_of_all_planned": cumulative / n if n else None})
        content_known = [o for o in success if o["content_id"] is not None]
        useful_known = [o for o in success if o["useful_compute_id"] is not None and o["useful_compute_evidence_present"]]
        identity_missing = sorted(k for k in ("source_commit", "source_tree", "binary_sha256", "config_sha256") if r["identity"].get(k) is None)
        reports.append({"run_id": rid, "chain_instance_id": r["chain_instance_id"], "profile_id": r["profile_id"],
                        "identity": r["identity"], "identity_missing": identity_missing,
                        "confirmation_policy": r["confirmation_policy"], "window_ns": elapsed,
                        "planned_operations": n, "confirmed_operations": k,
                        "window_success_fraction": k / n if n else None,
                        "deadline_before_window_success_fraction": k / n if n else None,
                        "goodput": {"numerator_confirmed_operations": k, "denominator_window_ns": elapsed,
                                    "operations_per_second": k * 1_000_000_000 / elapsed,
                                    "interpretation": "fixed-workload finite-window goodput; not saturated capacity"},
                        "operation_slo": {"declared_operations": len(known_slo), "successful": sum(o["deadline_success"] for o in known_slo),
                                          "over_all_planned": sum(o["deadline_success"] for o in known_slo) / n if n and len(known_slo) == n else None,
                                          "complete_coverage": bool(n) and len(known_slo) == n},
                        "outcome_counts": dict(sorted(Counter(o["outcome"] for o in group).items())),
                        "unique_confirmed_transaction_ids": len({o["confirmed_transaction_id"] for o in success}),
                        "content": {"known_unique": len({o["content_id"] for o in content_known}), "known_operations": len(content_known),
                                    "missing_operations": k - len(content_known), "complete_unique_count": len({o["content_id"] for o in content_known}) if len(content_known) == k else None},
                        "new_useful_computation": {"known_unique": len({o["useful_compute_id"] for o in useful_known}), "known_operations": len(useful_known),
                                                   "missing_operations": k - len(useful_known), "complete_unique_count": len({o["useful_compute_id"] for o in useful_known}) if len(useful_known) == k else None,
                                                   "claim_depends_on_external_usefulness_evidence": True},
                        "latency_from_schedule_ns": _quantiles(latency, k, n),
                        "latency_from_actual_start_ns": _quantiles([o["actual_start_latency_ns"] for o in success if o["actual_start_latency_ns"] is not None], k, n),
                        "planned_denominator_cdf": cdf,
                        "planned_arrival_missing": sum(o["scheduled_ns"] is None for o in group),
                        "administratively_censored_count": sum(o["administratively_censored_at_window"] for o in group),
                        "rejected_confirmation_events": [e for e in rejected if e["run_id"] == rid],
                        "telemetry_counts": dict(sorted(Counter(e["type"] for e in by_run[rid]).items())),
                        "resources": _resources(by_run[rid], r, k), "recovery": _recovery(r, group),
                        "metadata": r.get("metadata", {})})
    return {"schema": "sp27-confirmed-goodput-analysis-v1", "evidence_scope": contract["evidence_scope"],
            "new_native_experiments_executed_by_analyzer": 0,
            "identical_event_replays_deduplicated": duplicates,
            "no_cryptographic_or_observer_authentication_claim": True,
            "no_pooling_across_runs": True, "runs": reports, "operations": op_results}


def write_outputs(result, out_dir, input_paths=None):
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    summary = {k: v for k, v in result.items() if k != "operations"}
    (dest / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    rows = result["operations"]
    fields = list(rows[0]) if rows else ["operation_id", "run_id", "outcome", "confirmed_in_window"]
    with (dest / "operations.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v for k, v in row.items()})
    identity = {"schema": "sp27-analysis-input-identity-v1", "analyzer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "inputs": [{"name": Path(path).name, "bytes": Path(path).stat().st_size,
                            "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()} for path in (input_paths or [])]}
    (dest / "validated_input_manifest.json").write_text(json.dumps(identity, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--schedule", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = analyze(*load(args.contract, args.schedule, args.events))
        write_outputs(result, args.out_dir, [args.contract, args.schedule, args.events])
    except (ValidationError, OSError) as exc:
        parser.exit(2, "ANALYSIS_REFUSED: " + str(exc) + "\n")
    print(json.dumps({"status": "ANALYZED", "runs": len(result["runs"]), "planned_operations": len(result["operations"]),
                      "scope": result["evidence_scope"], "new_native_experiments": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
