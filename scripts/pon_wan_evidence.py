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


def evaluate(manifest, observations):
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
    for row in schedule.values():
        if row["operator"] not in operators or row["cohort"] not in cohorts:
            raise ValueError("UNKNOWN_SCHEDULE_OWNER")
        at = integer(row["scheduled_unix_ms"], "SCHEDULE_TIME", start)
        if at + cohorts[row["cohort"]]["max_confirmation_ms"] > end:
            raise ValueError("SCHEDULE_OUTSIDE_WINDOW")
        digest(row["operation_sha256"], "ORIGINAL_OPERATION")
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
        integer(row["elapsed_ms"], "ELAPSED")
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
