#!/usr/bin/env python3
"""Read a preregistered WAN campaign without dropping failures or missing rows.

This is an evidence-accounting reader, not operator authentication, independent
administration attestation or a release authority. No local JSON can grant
public_network_ready. A missing scheduled request is an explicit failure.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
from pathlib import Path

MAX_FILE = 64 * 1024 * 1024
OUTCOMES = {"confirmed", "timeout", "busy", "unavailable", "rejected", "cancelled", "send_failed"}


def integer(value, label, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(label)
    return value


def bounded(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_FILE:
        raise ValueError("INPUT_FILE_BOUND")
    data = path.read_bytes()
    if len(data) > MAX_FILE:
        raise ValueError("INPUT_FILE_BOUND")
    return data


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def decode(data):
    def reject(value):
        raise ValueError("NONFINITE_JSON_NUMBER:" + value)
    return json.loads(data, object_pairs_hook=no_duplicates, parse_constant=reject)


def digest(value, label):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(label)
    return value


def evaluate_v1(manifest, observations):
    if manifest.get("schema") != "trnm-wan-preregistration-v1":
        raise ValueError("MANIFEST_SCHEMA")
    start = integer(manifest["start_unix_ms"], "START", 1)
    end = integer(manifest["end_unix_ms"], "END", start + 72 * 3600 * 1000)
    required_depth = integer(manifest["confirmation_depth"], "REQUIRED_DEPTH", 1)
    operators = {row["id"]: row for row in manifest["operators"]}
    if len(operators) != len(manifest["operators"]) or len(operators) < 3:
        raise ValueError("THREE_DISTINCT_OPERATORS_REQUIRED")
    for row in operators.values():
        for name in ("id", "administrator", "failure_domain", "endpoint"):
            if type(row[name]) is not str or not row[name].strip():
                raise ValueError("OPERATOR_IDENTITY")
        digest(row["external_attestation_sha256"], "ATTESTATION_REFERENCE")
    if len({row["administrator"] for row in operators.values()}) < 3 or len({row["failure_domain"] for row in operators.values()}) < 3:
        raise ValueError("ADMINISTRATION_OR_FAILURE_DOMAIN_COLLISION")
    for name in ("chain_source_sha256", "hepta_source_sha256", "threat_model_sha256"):
        digest(manifest[name], name)
    cohorts = {row["id"]: row for row in manifest["cohorts"]}
    if not cohorts or len(cohorts) != len(manifest["cohorts"]):
        raise ValueError("COHORT_IDENTITY")
    for cohort in cohorts.values():
        integer(cohort["max_confirmation_ms"], "CONFIRMATION_DEADLINE", 1)
        integer(cohort["minimum_samples_per_operator"], "SAMPLE_FLOOR", 1)
        if not 0 < integer(cohort["minimum_timely_ppm"], "SLO", 1) <= 1_000_000:
            raise ValueError("SLO")
    schedule = {row["id"]: row for row in manifest["schedule"]}
    if not schedule or len(schedule) != len(manifest["schedule"]) or len(schedule) > 1_000_000:
        raise ValueError("SCHEDULE_IDENTITY_OR_BOUND")
    groups = collections.defaultdict(list)
    operations = set()
    for row in schedule.values():
        if row["operator"] not in operators or row["cohort"] not in cohorts:
            raise ValueError("UNKNOWN_SCHEDULE_OWNER")
        at = integer(row["scheduled_unix_ms"], "SCHEDULE_TIME", start)
        if at + cohorts[row["cohort"]]["max_confirmation_ms"] > end:
            raise ValueError("SCHEDULE_OUTSIDE_WINDOW")
        digest(row["operation_sha256"], "ORIGINAL_OPERATION")
        if row["operation_sha256"] in operations:
            raise ValueError("REPEATED_ORIGINAL_OPERATION")
        operations.add(row["operation_sha256"])
        groups[row["operator"], row["cohort"]].append(row)
    # A strong aggregate cannot hide a missing administrator or hostile cohort.
    for operator in operators:
        for cohort, policy in cohorts.items():
            if len(groups[operator, cohort]) < policy["minimum_samples_per_operator"]:
                raise ValueError("MISSING_OPERATOR_COHORT_DENOMINATOR")

    actual = {}
    for row in observations:
        identity = row["id"]
        if identity not in schedule or identity in actual:
            raise ValueError("UNSCHEDULED_OR_DUPLICATE_OBSERVATION")
        planned = schedule[identity]
        for name in ("operator", "cohort", "operation_sha256"):
            if row[name] != planned[name]:
                raise ValueError("OBSERVATION_CONTEXT_MISMATCH")
        if row["outcome"] not in OUTCOMES:
            raise ValueError("OUTCOME")
        elapsed = integer(row["elapsed_ms"], "ELAPSED")
        started = integer(row["started_unix_ms"], "STARTED", planned["scheduled_unix_ms"])
        terminal = integer(row["terminal_unix_ms"], "TERMINAL", started)
        if elapsed != terminal - planned["scheduled_unix_ms"]:
            raise ValueError("SCHEDULED_TO_TERMINAL_LATENCY_REQUIRED")
        for name in ("cpu_ns", "peak_rss_bytes", "rx_bytes", "tx_bytes"):
            integer(row[name], name)
        digest(row["raw_receipt_sha256"], "RAW_RECEIPT_REFERENCE")
        if row["outcome"] == "confirmed":
            digest(row["block_id"], "CONFIRMED_BLOCK")
            if integer(row["confirmed_depth"], "CONFIRMED_DEPTH", 1) < required_depth:
                raise ValueError("INSUFFICIENT_CONFIRMATION")
            integer(row["observed_chainwork_delta"], "CONFIRMED_CHAINWORK", 1)
        actual[identity] = row

    reports = []
    for (operator, cohort), planned in sorted(groups.items()):
        policy = cohorts[cohort]
        rows = [actual.get(row["id"]) for row in planned]
        counts = collections.Counter("missing" if row is None else row["outcome"] for row in rows)
        timely = sum(row is not None and row["outcome"] == "confirmed" and row["elapsed_ms"] <= policy["max_confirmation_ms"] for row in rows)
        latencies = sorted(row["elapsed_ms"] for row in rows if row is not None and row["outcome"] == "confirmed")
        # Success-only latency is explicitly labeled. All planned operations,
        # including missing/unsent requests, remain in the service denominator.
        def quantile(p):
            return latencies[math.ceil(p * len(latencies))-1] if latencies else None
        reports.append(dict(operator=operator, cohort=cohort, scheduled=len(planned),
            recorded=sum(row is not None for row in rows), outcomes=dict(counts),
            timely_confirmed=timely, timely_ppm=timely * 1_000_000 // len(planned),
            success_only_p50_ms=quantile(.5), success_only_p99_ms=quantile(.99),
            resources={name: sum(row[name] for row in rows if row is not None) for name in ("cpu_ns", "rx_bytes", "tx_bytes")},
            peak_rss_bytes=max((row["peak_rss_bytes"] for row in rows if row is not None), default=None),
            accounting_complete=counts["missing"] == 0,
            arithmetic_slo_met=counts["missing"] == 0 and timely * 1_000_000 >= policy["minimum_timely_ppm"] * len(planned)))
    return dict(schema="trnm-wan-evidence-accounting-v1", declared_duration_ms=end-start,
        scheduled=len(schedule), recorded=len(actual), missing=len(schedule)-len(actual),
        cohorts=reports, all_cohort_arithmetic_slos_met=all(row["arithmetic_slo_met"] for row in reports),
        external_operator_attestations_verified=False, physical_wan_duration_verified=False,
        raw_receipts_cryptographically_verified=False, independent_accepted=False,
        public_network_ready=False, production_activation=False,
        scope="Arithmetic accounting only; separately authenticate original receipts, independent administrators, wall-clock duration and source/binary identities")


V2_DURATION_MS = 72 * 3600 * 1000
V2_RESOURCES = ("cpu_ns", "peak_rss_bytes", "rx_bytes", "tx_bytes", "funding_units")
V2_SUCCESS = {"confirmation": "confirmed", "cell_retrieval": "retrieved",
              "replica_repair": "repaired", "recovery": "recovered"}
V2_CELL_FIELDS = {"manifest_sha256", "payload_sha256", "payload_bytes"}
V2_RECOVERY_FIELDS = {
    "reconcile": {"effect_sha256", "target_receipt_sha256"},
    "verified_sync": {"tip_sha256", "state_root_sha256"},
    "restart": {"state_root_sha256", "frontier_sha256"},
}


def exact_keys(value, keys, label):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError(label)


def v2_integer(value, label, minimum=0):
    result = integer(value, label, minimum)
    if result > 2**64 - 1:
        raise ValueError(label)
    return result


def v2_name(value, label):
    if type(value) is not str or not value or value.strip() != value or len(value) > 2048:
        raise ValueError(label)
    return value


def indexed(rows, keys, label, maximum):
    if type(rows) is not list or not 1 <= len(rows) <= maximum:
        raise ValueError(label)
    result = {}
    for row in rows:
        exact_keys(row, keys, label)
        identity = v2_name(row["id"], label)
        if identity in result:
            raise ValueError(label)
        result[identity] = row
    return result


def operator_ids(values, operators, label):
    if type(values) is not list or len(values) > len(operators):
        raise ValueError(label)
    for value in values:
        v2_name(value, label)
    if len(set(values)) != len(values) or any(value not in operators for value in values):
        raise ValueError(label)
    return set(values)


def cell_fields(value):
    for name in ("manifest_sha256", "payload_sha256"):
        digest(value[name], "CELL_IDENTITY")
    v2_integer(value["payload_bytes"], "CELL_BYTES", 1)


def v2_criteria(cohort, operators):
    kind, criteria = cohort["kind"], cohort["success_criteria"]
    if kind == "confirmation":
        exact_keys(criteria, {"minimum_confirmed_depth", "minimum_chainwork_delta"}, "CONFIRMATION_CRITERIA")
        for name in criteria:
            v2_integer(criteria[name], name, 1)
    elif kind == "cell_retrieval":
        exact_keys(criteria, {"minimum_source_operators"}, "RETRIEVAL_CRITERIA")
        if v2_integer(criteria["minimum_source_operators"], "SOURCE_FLOOR", 1) > len(operators):
            raise ValueError("SOURCE_FLOOR")
    elif kind == "replica_repair":
        exact_keys(criteria, {"minimum_complete_replicas", "minimum_administrators", "minimum_failure_domains"}, "REPAIR_CRITERIA")
        for name in criteria:
            if v2_integer(criteria[name], name, 3) > len(operators):
                raise ValueError("REPAIR_CRITERIA")
    elif kind == "recovery":
        exact_keys(criteria, {"mode", "maximum_redispatched_effects", "maximum_new_payments"}, "RECOVERY_CRITERIA")
        if v2_name(criteria["mode"], "RECOVERY_MODE") not in V2_RECOVERY_FIELDS:
            raise ValueError("RECOVERY_MODE")
        for name in ("maximum_redispatched_effects", "maximum_new_payments"):
            if v2_integer(criteria[name], name) != 0:
                raise ValueError("RECOVERY_REEXECUTION_FORBIDDEN")
    else:
        raise ValueError("COHORT_KIND")


def v2_expected(cohort, expected, operators):
    kind = cohort["kind"]
    if kind == "confirmation":
        exact_keys(expected, set(), "CONFIRMATION_EXPECTED")
    elif kind == "cell_retrieval":
        exact_keys(expected, V2_CELL_FIELDS | {"forbidden_source_operators"}, "RETRIEVAL_EXPECTED")
        cell_fields(expected)
        forbidden = operator_ids(expected["forbidden_source_operators"], operators, "FORBIDDEN_SOURCE")
        if len(operators) - len(forbidden) < cohort["success_criteria"]["minimum_source_operators"]:
            raise ValueError("SOURCE_FLOOR")
    elif kind == "replica_repair":
        exact_keys(expected, V2_CELL_FIELDS | {"effect_sha256"}, "REPAIR_EXPECTED")
        cell_fields(expected)
        digest(expected["effect_sha256"], "REPAIR_EFFECT")
    else:
        fields = V2_RECOVERY_FIELDS[cohort["success_criteria"]["mode"]]
        exact_keys(expected, fields, "RECOVERY_EXPECTED")
        for name in fields:
            digest(expected[name], name)


def v2_success(cohort, planned, row, operators):
    kind, criteria = cohort["kind"], cohort["success_criteria"]
    expected, result = planned["expected"], row["result"]
    if row["outcome"] != V2_SUCCESS[kind]:
        if row["outcome"] not in OUTCOMES - {"confirmed"}:
            raise ValueError("OUTCOME_KIND_MISMATCH")
        exact_keys(result, set(), "FAILED_RESULT")
        return False
    if kind == "confirmation":
        exact_keys(result, {"block_id", "confirmed_depth", "observed_chainwork_delta"}, "CONFIRMATION_RESULT")
        digest(result["block_id"], "CONFIRMED_BLOCK")
        depth = v2_integer(result["confirmed_depth"], "CONFIRMED_DEPTH")
        work = v2_integer(result["observed_chainwork_delta"], "CONFIRMED_CHAINWORK")
        return depth >= criteria["minimum_confirmed_depth"] and work >= criteria["minimum_chainwork_delta"]
    if kind in ("cell_retrieval", "replica_repair"):
        additional = {"source_operators"} if kind == "cell_retrieval" else {"effect_sha256", "complete_replica_operators"}
        exact_keys(result, V2_CELL_FIELDS | additional, "CELL_RESULT")
        cell_fields(result)
        same_cell = all(result[name] == expected[name] for name in V2_CELL_FIELDS)
        if kind == "cell_retrieval":
            sources = operator_ids(result["source_operators"], operators, "SOURCE_OPERATORS")
            return (same_cell and len(sources) >= criteria["minimum_source_operators"]
                    and not sources.intersection(expected["forbidden_source_operators"]))
        digest(result["effect_sha256"], "REPAIR_EFFECT")
        replicas = operator_ids(result["complete_replica_operators"], operators, "REPLICA_OPERATORS")
        administrators = {operators[name]["administrator"] for name in replicas}
        domains = {operators[name]["failure_domain"] for name in replicas}
        return (same_cell and result["effect_sha256"] == expected["effect_sha256"]
                and len(replicas) >= criteria["minimum_complete_replicas"]
                and len(administrators) >= criteria["minimum_administrators"]
                and len(domains) >= criteria["minimum_failure_domains"])
    fields = V2_RECOVERY_FIELDS[criteria["mode"]]
    exact_keys(result, fields | {"mode", "redispatched_effects", "new_payments"}, "RECOVERY_RESULT")
    for name in fields:
        digest(result[name], name)
    redispatch = v2_integer(result["redispatched_effects"], "RECOVERY_REDISPATCH")
    payments = v2_integer(result["new_payments"], "RECOVERY_PAYMENTS")
    return (result["mode"] == criteria["mode"] and all(result[name] == expected[name] for name in fields)
            and redispatch <= criteria["maximum_redispatched_effects"]
            and payments <= criteria["maximum_new_payments"])


def evaluate_v2(manifest, observations):
    references = {"chain_source_sha256", "hepta_source_sha256", "chain_binary_sha256",
                  "hepta_binary_sha256", "threat_model_sha256", "load_fault_plan_sha256"}
    exact_keys(manifest, references | {"schema", "preregistered_unix_ms", "start_unix_ms", "end_unix_ms",
                                      "operators", "cohorts", "windows", "schedule"}, "V2_MANIFEST_FIELDS")
    if manifest["schema"] != "trnm-wan-preregistration-v2":
        raise ValueError("MANIFEST_SCHEMA")
    start = v2_integer(manifest["start_unix_ms"], "START", 1)
    end = v2_integer(manifest["end_unix_ms"], "END", start + V2_DURATION_MS)
    if v2_integer(manifest["preregistered_unix_ms"], "PREREGISTRATION", 1) >= start:
        raise ValueError("PREREGISTRATION_MUST_PRECEDE_RUN")
    for name in references:
        digest(manifest[name], name)
    operators = indexed(manifest["operators"], {"id", "administrator", "failure_domain", "endpoint",
                        "external_attestation_sha256"}, "OPERATOR_IDENTITY", 64)
    for row in operators.values():
        for name in ("administrator", "failure_domain", "endpoint"):
            v2_name(row[name], "OPERATOR_IDENTITY")
        digest(row["external_attestation_sha256"], "ATTESTATION_REFERENCE")
    if (len(operators) < 3 or len({row["administrator"] for row in operators.values()}) < 3
            or len({row["failure_domain"] for row in operators.values()}) < 3):
        raise ValueError("THREE_ADMINISTRATORS_AND_FAILURE_DOMAINS_REQUIRED")
    windows = indexed(manifest["windows"], {"id", "start_unix_ms", "end_unix_ms", "report_by_unix_ms"}, "WINDOW_IDENTITY", 4096)
    previous = start
    for window in windows.values():
        at = v2_integer(window["start_unix_ms"], "WINDOW_START", start)
        until = v2_integer(window["end_unix_ms"], "WINDOW_END", at + 1)
        v2_integer(window["report_by_unix_ms"], "WINDOW_REPORT_CUTOFF", until)
        if at != previous or until > end:
            raise ValueError("WINDOWS_MUST_PARTITION_CAMPAIGN")
        previous = until
    if previous != end:
        raise ValueError("WINDOWS_MUST_PARTITION_CAMPAIGN")
    cohort_fields = {"id", "kind", "max_completion_ms", "minimum_samples_per_operator_per_window",
                     "minimum_timely_ppm", "tail_quantile_ppm", "minimum_tail_samples_per_operator_per_window",
                     "max_tail_latency_ms", "window_resource_limits", "success_criteria"}
    cohorts = indexed(manifest["cohorts"], cohort_fields, "COHORT_IDENTITY", 128)
    if len(operators) * len(cohorts) * len(windows) > 100_000:
        raise ValueError("ACCOUNTING_GROUP_BOUND")
    for cohort in cohorts.values():
        for name in ("max_completion_ms", "minimum_samples_per_operator_per_window",
                     "minimum_tail_samples_per_operator_per_window", "max_tail_latency_ms"):
            v2_integer(cohort[name], name, 1)
        for name in ("minimum_timely_ppm", "tail_quantile_ppm"):
            if v2_integer(cohort[name], name, 1) > 1_000_000:
                raise ValueError(name)
        exact_keys(cohort["window_resource_limits"], V2_RESOURCES, "FROZEN_RESOURCE_LIMITS_REQUIRED")
        for name in V2_RESOURCES:
            v2_integer(cohort["window_resource_limits"][name], name)
        v2_criteria(cohort, operators)
    schedule = indexed(manifest["schedule"], {"id", "operator", "cohort", "window", "operation_sha256",
                       "scheduled_unix_ms", "expected"}, "SCHEDULE_IDENTITY_OR_BOUND", 1_000_000)
    groups, coverage, operations = collections.defaultdict(list), collections.defaultdict(list), set()
    for row in schedule.values():
        for name, known in (("operator", operators), ("cohort", cohorts), ("window", windows)):
            if v2_name(row[name], "SCHEDULE_CONTEXT") not in known:
                raise ValueError("UNKNOWN_SCHEDULE_CONTEXT")
        window, cohort = windows[row["window"]], cohorts[row["cohort"]]
        at = v2_integer(row["scheduled_unix_ms"], "SCHEDULE_TIME", window["start_unix_ms"])
        if at + cohort["max_completion_ms"] > window["end_unix_ms"]:
            raise ValueError("SCHEDULE_OUTSIDE_WINDOW")
        digest(row["operation_sha256"], "ORIGINAL_OPERATION")
        if row["operation_sha256"] in operations:
            raise ValueError("REPEATED_ORIGINAL_OPERATION")
        operations.add(row["operation_sha256"])
        v2_expected(cohort, row["expected"], operators)
        groups[row["operator"], row["cohort"], row["window"]].append(row)
        coverage[row["operator"], row["cohort"]].append(at)
    spans = {(operator, cohort): max(times) - min(times) if times else 0
             for operator in operators for cohort in cohorts for times in [coverage[operator, cohort]]}
    actual, receipts = {}, set()
    observation_fields = {"id", "operator", "cohort", "window", "operation_sha256", "outcome", "started_unix_ms",
                          "terminal_unix_ms", "recorded_unix_ms", "elapsed_ms", "resources", "raw_receipt_sha256", "result"}
    for row in observations:
        exact_keys(row, observation_fields, "V2_OBSERVATION_FIELDS")
        identity = v2_name(row["id"], "OBSERVATION_IDENTITY")
        if identity not in schedule or identity in actual:
            raise ValueError("UNSCHEDULED_OR_DUPLICATE_OBSERVATION")
        planned = schedule[identity]
        if any(row[name] != planned[name] for name in ("operator", "cohort", "window", "operation_sha256")):
            raise ValueError("OBSERVATION_CONTEXT_MISMATCH")
        v2_name(row["outcome"], "OUTCOME")
        started = v2_integer(row["started_unix_ms"], "STARTED", planned["scheduled_unix_ms"])
        terminal = v2_integer(row["terminal_unix_ms"], "TERMINAL", started)
        v2_integer(row["recorded_unix_ms"], "RECORDED", terminal)
        if v2_integer(row["elapsed_ms"], "ELAPSED") != terminal - planned["scheduled_unix_ms"]:
            raise ValueError("SCHEDULED_TO_TERMINAL_LATENCY_REQUIRED")
        exact_keys(row["resources"], V2_RESOURCES, "OBSERVATION_RESOURCE_FIELDS")
        for name in V2_RESOURCES:
            v2_integer(row["resources"][name], name)
        receipt = digest(row["raw_receipt_sha256"], "RAW_RECEIPT_REFERENCE")
        if receipt in receipts:
            raise ValueError("REPLAYED_RAW_RECEIPT")
        receipts.add(receipt)
        success = v2_success(cohorts[planned["cohort"]], planned, row, operators)
        actual[identity] = (row, success)

    reports = []
    for operator in sorted(operators):
        for cohort_id, policy in sorted(cohorts.items()):
            for window_id, window in windows.items():
                planned = groups[operator, cohort_id, window_id]
                rows = [actual.get(item["id"]) for item in planned]
                recorded = [entry for entry in rows if entry is not None]
                counts = collections.Counter("missing" if entry is None else entry[0]["outcome"] for entry in rows)
                late = sum(row["recorded_unix_ms"] > window["report_by_unix_ms"] for row, _ in recorded)
                outside = sum(row["terminal_unix_ms"] > window["end_unix_ms"] for row, _ in recorded)
                eligible = [row for row, success in recorded if success
                            and row["recorded_unix_ms"] <= window["report_by_unix_ms"]
                            and row["terminal_unix_ms"] <= window["end_unix_ms"]]
                timely = sum(row["elapsed_ms"] <= policy["max_completion_ms"] for row in eligible)
                latencies = sorted(row["elapsed_ms"] for row in eligible)
                quantile = (latencies[(policy["tail_quantile_ppm"] * len(latencies) + 999_999) // 1_000_000 - 1]
                            if latencies else None)
                resources = {name: (max((row["resources"][name] for row, _ in recorded), default=0)
                                   if name == "peak_rss_bytes" else sum(row["resources"][name] for row, _ in recorded))
                             for name in V2_RESOURCES}
                complete = counts["missing"] == 0 and late == 0 and outside == 0
                sample_floor = len(planned) >= policy["minimum_samples_per_operator_per_window"]
                tail_met = (len(latencies) >= policy["minimum_tail_samples_per_operator_per_window"]
                            and quantile is not None and quantile <= policy["max_tail_latency_ms"])
                resources_met = all(resources[name] <= policy["window_resource_limits"][name] for name in V2_RESOURCES)
                coverage_met = spans[operator, cohort_id] >= V2_DURATION_MS
                ratio_met = bool(planned) and timely * 1_000_000 >= policy["minimum_timely_ppm"] * len(planned)
                reports.append(dict(operator=operator, cohort=cohort_id, kind=policy["kind"], window=window_id,
                    scheduled=len(planned), recorded=len(recorded), outcomes=dict(counts),
                    successful_results=sum(success for _, success in recorded),
                    success_criteria_failures=sum(not success and row["outcome"] == V2_SUCCESS[policy["kind"]] for row, success in recorded),
                    late_records=late, terminal_outside_window=outside, timely_successful=timely,
                    timely_ppm=timely * 1_000_000 // len(planned) if planned else None,
                    eligible_success_only_tail_samples=len(latencies), success_only_tail_quantile_ppm=policy["tail_quantile_ppm"],
                    success_only_tail_latency_ms=quantile, tail_requirement_met=tail_met,
                    reported_resources=resources, resource_limits_met=resources_met,
                    sample_floor_met=sample_floor, accounting_complete=complete,
                    operator_cohort_schedule_span_ms=spans[operator, cohort_id],
                    minimum_campaign_schedule_span_met=coverage_met,
                    arithmetic_slo_met=complete and sample_floor and tail_met and resources_met and coverage_met and ratio_met))
    return dict(schema="trnm-wan-evidence-accounting-v2", declared_duration_ms=end-start,
        scheduled=len(schedule), recorded=len(actual), missing=len(schedule)-len(actual), cohorts=reports,
        all_cohort_arithmetic_slos_met=all(row["arithmetic_slo_met"] for row in reports),
        external_operator_attestations_verified=False, physical_wan_duration_verified=False,
        raw_receipts_cryptographically_verified=False, preregistration_independently_verified=False,
        source_binary_identities_verified=False, independent_accepted=False, pn5_accepted=False,
        public_network_ready=False, production_activation=False,
        scope="Typed/windowed arithmetic only; JSON does not authenticate receipts, preregistration, duration, operators, funding, physical replicas or source/binary identities")


def evaluate(manifest, observations):
    if manifest.get("schema") == "trnm-wan-preregistration-v2":
        return evaluate_v2(manifest, observations)
    return evaluate_v1(manifest, observations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest"); parser.add_argument("observations")
    args = parser.parse_args()
    raw_manifest, raw_rows = bounded(args.manifest), bounded(args.observations)
    rows = [decode(line) for line in raw_rows.splitlines() if line.strip()]
    report = evaluate(decode(raw_manifest), rows)
    report.update(manifest_sha256=hashlib.sha256(raw_manifest).hexdigest(), observations_sha256=hashlib.sha256(raw_rows).hexdigest())
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["all_cohort_arithmetic_slos_met"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
