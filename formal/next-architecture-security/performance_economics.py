#!/usr/bin/env python3
"""Strict, read-only reconciliation of a declared campaign's complete denominator.

This is an accounting calculation, not authentication of meters, payment origin,
finality, independent customers, or a production/economic qualification decision.
The supplied monetary units must already be comparable; no token/fiat exchange
rate, missing cost, or unobserved operation is manufactured by this reader.
"""
from __future__ import annotations

import argparse
from collections import Counter
from fractions import Fraction
import json
from pathlib import Path
import re

SCHEMA = "trnm-next-performance-economics-input-v1"
MAX_OPERATIONS = 10000
KINDS = {"consensus_confirmation", "work_verification", "cell_retrieval", "device_load"}
ACCEPTED_UNITS = {
    "consensus_confirmation": "confirmed_transactions",
    "work_verification": "verified_statements",
    "cell_retrieval": "verified_payload_bytes",
    "device_load": "execution_ready_models",
}
OUTCOMES = {"success", "rejected", "cancelled", "timeout", "unknown", "not_started"}
METERS = ("cpu_ns", "gpu_ns", "received_bytes", "sent_bytes", "storage_byte_ns")
PEAKS = ("peak_rss_bytes", "peak_vram_bytes")
MONEY_KINDS = {"external_customer_revenue", "protocol_subsidy", "internal_transfer", "refund"}
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


def require(value, code):
    if not value:
        raise ValueError(code)


def integer(value, code, *, positive=False):
    require(type(value) is int and int(positive) <= value < 1 << 128, code)
    return value


def optional_integer(value, code):
    return None if value is None else integer(value, code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def fraction(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


def total(values):
    values = list(values)
    return None if any(value is None for value in values) else sum(values)


def quantile(values, numerator, denominator):
    """Finite nearest-rank order statistic, never a population guarantee."""
    values = sorted(values)
    if not values:
        return None
    rank = (len(values) * numerator + denominator - 1) // denominator
    return values[max(0, rank - 1)]


def summarize(document):
    require(type(document) is dict and set(document) == {
        "schema", "campaign_id", "clock_scope", "window_ns", "money_unit",
        "planned", "observations", "settlements",
    }, "DOCUMENT_FIELDS")
    require(document["schema"] == SCHEMA, "SCHEMA")
    require(type(document["campaign_id"]) is str and ID.fullmatch(document["campaign_id"]), "CAMPAIGN_ID")
    require(document["clock_scope"] == "single-observer-monotonic", "CLOCK_SCOPE")
    window = integer(document["window_ns"], "WINDOW", positive=True)
    require(type(document["money_unit"]) is str and ID.fullmatch(document["money_unit"]), "MONEY_UNIT")
    planned, observations = document["planned"], document["observations"]
    require(type(planned) is list and 0 < len(planned) <= MAX_OPERATIONS, "PLAN_SIZE")
    require(type(observations) is list and len(observations) == len(planned), "COMPLETE_DENOMINATOR")
    expected = {}
    for row in planned:
        require(type(row) is dict and set(row) == {"operation_id", "kind", "deadline_ns", "accepted_unit"}, "PLAN_FIELDS")
        op = row["operation_id"]
        require(type(op) is str and ID.fullmatch(op) and op not in expected, "PLAN_ID")
        require(type(row["kind"]) is str and row["kind"] in KINDS, "PLAN_KIND")
        require(row["accepted_unit"] == ACCEPTED_UNITS[row["kind"]], "ACCEPTED_UNIT")
        require(integer(row["deadline_ns"], "DEADLINE", positive=True) <= window, "DEADLINE_WINDOW")
        expected[op] = row
    seen, groups = set(), {kind: [] for kind in KINDS}
    fields = {"operation_id", "outcome", "started_ns", "finished_ns", "accepted_units", "cost_minor", "lifecycle_terminal"} | set(METERS) | set(PEAKS)
    for row in observations:
        require(type(row) is dict and set(row) == fields, "OBSERVATION_FIELDS")
        op = row["operation_id"]
        require(type(op) is str and op in expected and op not in seen, "OBSERVATION_ID")
        seen.add(op)
        outcome = row["outcome"]
        require(type(outcome) is str and outcome in OUTCOMES, "OUTCOME")
        start = optional_integer(row["started_ns"], "START")
        finish = optional_integer(row["finished_ns"], "FINISH")
        units = integer(row["accepted_units"], "ACCEPTED_UNITS")
        require(outcome == "success" or units == 0, "FAILED_OPERATION_CREDIT")
        require(type(row["lifecycle_terminal"]) is bool, "LIFECYCLE_TERMINAL")
        if outcome == "not_started":
            require(start is None and finish is None, "NOT_STARTED_CLOCK")
        else:
            require(start is not None, "MISSING_START")
            require(finish is None or finish >= start, "CLOCK_ORDER")
        if outcome not in {"unknown", "not_started"}:
            require(finish is not None, "MISSING_TERMINAL")
        require(not row["lifecycle_terminal"] or outcome == "not_started" or finish is not None,
                "LIFECYCLE_TERMINAL_WITHOUT_FINISH")
        for name in (*METERS, *PEAKS, "cost_minor"):
            optional_integer(row[name], "METER:" + name)
        groups[expected[op]["kind"]].append(row)
    require(seen == set(expected), "COMPLETE_DENOMINATOR")
    metrics = {}
    for kind, rows in sorted(groups.items()):
        successful = [r for r in rows if r["outcome"] == "success"]
        on_time = [r for r in successful if r["finished_ns"] <= expected[r["operation_id"]]["deadline_ns"]]
        latencies = [r["finished_ns"] - r["started_ns"] for r in successful]
        count = len(rows)
        metrics[kind] = {
            "accepted_unit": ACCEPTED_UNITS[kind],
            "planned": count,
            "outcomes": dict(sorted(Counter(r["outcome"] for r in rows).items())),
            "successful": len(successful), "on_time_successful": len(on_time),
            "deadline_success_fraction": fraction(Fraction(len(on_time), count)) if count else None,
            "on_time_accepted_units": sum(r["accepted_units"] for r in on_time),
            "on_time_units_per_second": fraction(Fraction(sum(r["accepted_units"] for r in on_time) * 10**9, window)) if count else None,
            "successful_latency_samples": len(latencies),
            "successful_latency_p50_nearest_rank_ns": quantile(latencies, 1, 2),
            "successful_latency_p95_ns": quantile(latencies, 95, 100) if len(latencies) >= 20 else None,
            "successful_latency_p99_ns": quantile(latencies, 99, 100) if len(latencies) >= 100 else None,
            "p99_independent_population_estimate": False,
            "sampled_success_max_ns": max(latencies) if latencies else None,
            "all_outcome_resource_totals": {name: total(r[name] for r in rows) if rows else None for name in METERS},
            "resource_missing_observations": {name: sum(r[name] is None for r in rows) for name in METERS},
            "maximum_observed_operation_peaks": {
                name: max((r[name] for r in rows), default=None) if rows and all(r[name] is not None for r in rows) else None
                for name in PEAKS
            },
            "cost_minor_including_failures": total(r["cost_minor"] for r in rows) if rows else None,
        }
    settlements = document["settlements"]
    require(type(settlements) is list and len(settlements) <= MAX_OPERATIONS * 4, "SETTLEMENT_LIMIT")
    receipts, sums = set(), {kind: 0 for kind in MONEY_KINDS}
    for row in settlements:
        require(type(row) is dict and set(row) == {"receipt_id", "operation_id", "kind", "amount_minor", "money_unit"}, "SETTLEMENT_FIELDS")
        receipt = row["receipt_id"]
        require(type(receipt) is str and re.fullmatch(r"[0-9a-f]{64}", receipt) and receipt not in receipts, "SETTLEMENT_REPLAY")
        receipts.add(receipt)
        require(type(row["operation_id"]) is str and row["operation_id"] in expected, "SETTLEMENT_OPERATION")
        require(type(row["kind"]) is str and row["kind"] in MONEY_KINDS, "SETTLEMENT_KIND")
        require(row["money_unit"] == document["money_unit"], "MONEY_UNIT_MISMATCH")
        amount = optional_integer(row["amount_minor"], "SETTLEMENT_AMOUNT")
        name = row["kind"]
        sums[name] = None if amount is None or sums[name] is None else sums[name] + amount
    all_cost = total(row["cost_minor"] for row in observations)
    net = None if any(v is None for v in (sums["external_customer_revenue"], sums["refund"], all_cost)) else sums["external_customer_revenue"] - sums["refund"] - all_cost
    terminal = all(row["lifecycle_terminal"] for row in observations)
    return {
        "schema": "trnm-next-performance-economics-report-v1",
        "campaign_id": document["campaign_id"], "scope": "declared-complete-campaign-arithmetic-only",
        "complete_declared_denominator": True, "planned_operations": len(planned),
        "metrics": metrics,
        "economics": {
            "money_unit": document["money_unit"], "declared_settlements": sums,
            "declared_observed_to_date_cost_minor": all_cost,
            "conditional_observed_to_date_external_net_minor_excluding_subsidy_and_internal_transfers": net,
            "all_declared_lifecycles_terminal": terminal,
            "conditional_completed_declared_lifecycle_cost_minor": all_cost if terminal else None,
            "conditional_completed_declared_lifecycle_external_net_minor": net if terminal else None,
            "missing_cost_observations": sum(r["cost_minor"] is None for r in observations),
            "unobserved_costs_and_settlements_excluded": True,
            "future_obligations_complete": False,
            "meter_authenticity_verified": False, "external_customer_independence_verified": False,
            "settlement_authenticity_verified": False, "sustainable_rewards_qualified": False,
        },
        "qualification": "HOLD_NO_GO", "global_malicious_cost_bound_proved": False,
        "native_finality_authenticated": False, "public_throughput_qualified": False,
        "production_activation": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    with args.input.open("rb") as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    require(len(raw) <= 16 * 1024 * 1024, "INPUT_LIMIT")
    document = json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("NONFINITE_JSON")))
    print(json.dumps(summarize(document), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
