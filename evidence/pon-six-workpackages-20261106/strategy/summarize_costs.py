#!/usr/bin/env python3
"""Reproduce paid cost denominators and descriptive fixed-strategy rankings.

This consumes the already checked readbacks. Ranking is after observation;
neither a fastest-per-sample oracle nor an adaptive miner was executed. Native
process totals include every captured exit and are separate from producer CPU.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys


def summarize(capture):
    capture = Path(capture)
    grid = json.loads((capture / "grid-readback.json").read_text())
    manifest = json.loads((capture / "manifest.json").read_text())
    strategy_totals, rankings, grid_counts = {}, [], Counter()
    fields = ("actual_setup_calls", "actual_searches", "attempts", "target_hits", "exhausted_searches",
              "proof_materializations", "serialized_proof_bytes")
    for shard in grid["shards"]:
        costs = shard["strategy_costs"]
        ranked = sorted(costs, key=lambda value: value["inclusive_cohort_total"]["cpu_ns"])
        rankings.append(dict(selection=shard["selection"],
            ranking_by_all_eight_samples_cpu=[dict(strategy=value["strategy"],
                cpu_ns=value["inclusive_cohort_total"]["cpu_ns"], setup_cpu_ns=value["setup_total"]["cpu_ns"],
                attempts=value["attempts"], target_hits=value["target_hits"]) for value in ranked],
            sparse_eager_over_dense_eager=dict(numerator=costs[2]["inclusive_cohort_total"]["cpu_ns"],
                                              denominator=costs[0]["inclusive_cohort_total"]["cpu_ns"]),
            sparse_lazy_over_dense_lazy=dict(numerator=costs[3]["inclusive_cohort_total"]["cpu_ns"],
                                            denominator=costs[1]["inclusive_cohort_total"]["cpu_ns"])))
        for cost in costs:
            totals = strategy_totals.setdefault(cost["strategy"], Counter())
            for field in fields:
                totals[field] += cost[field]
                grid_counts[field] += cost[field]
            for target, phase in (("producer_cpu_ns", "inclusive_cohort_total"),
                    ("setup_cpu_ns", "setup_total"), ("separate_evidence_cpu_ns", "separate_attempt_evidence_total"),
                    ("separate_mutation_cpu_ns", "separate_product_mutation_total")):
                totals[target] += cost[phase]["cpu_ns"]
            totals["producer_wall_ns"] += cost["inclusive_cohort_total"]["wall_ns"]
            totals["native_legal_accept_calls"] += cost["native_outcome_counts"]["legal"].get("Accepted", 0)
            totals["native_negative_product_refusals"] += cost["native_outcome_counts"]["product-last"].get("Product", 0)
            totals["separate_verifier_cpu_ns"] += sum(path["cpu_ns"]
                for case in cost["verification"].values() for path in case.values())
    controls, by_purpose = Counter(), {}
    inputs = [capture / "grid-readback.json", capture / "manifest.json"]
    for command in manifest["commands"]:
        receipt = command["process"]
        totals = by_purpose.setdefault(command["purpose"], dict(commands=0, user_cpu_seconds=0.0,
            system_cpu_seconds=0.0, wall_seconds=0.0, max_single_process_peak_rss_bytes=0,
            failed_processes=0, timed_out=0))
        totals["commands"] += 1
        # Unknown resource data is never replaced with zero. Incomplete input
        # cannot be emitted as a complete numeric cost summary by this reader.
        for key in ("cpu_user_seconds", "cpu_system_seconds", "peak_rss_bytes"):
            if receipt[key] is None:
                raise ValueError("unknown native resource observation: " + key)
        totals["user_cpu_seconds"] += receipt["cpu_user_seconds"]
        totals["system_cpu_seconds"] += receipt["cpu_system_seconds"]
        totals["wall_seconds"] += receipt["elapsed_wall_seconds"]
        totals["max_single_process_peak_rss_bytes"] = max(totals["max_single_process_peak_rss_bytes"], receipt["peak_rss_bytes"])
        totals["failed_processes"] += not receipt["process_complete"]
        totals["timed_out"] += receipt["timed_out"]
        path = capture / command["name"] / "readback.json"
        inputs.append(path)
        if command["purpose"] == "search-cost":
            continue
        report = json.loads(path.read_text())
        controls["commands"] += 1
        controls["expected_outcomes_observed"] += report["control_expected_outcome_observed"]
        for cost in report["strategy_costs"]:
            for field in fields:
                controls[field] += cost[field]
            controls["producer_cpu_ns"] += cost["inclusive_cohort_total"]["cpu_ns"]
    for totals in by_purpose.values():
        totals["total_cpu_seconds"] = totals["user_cpu_seconds"] + totals["system_cpu_seconds"]
        totals["cpu_and_rss_scope"] = "direct native process Linux wait4; not aggregate host resource or public-service qualification"
    return dict(schema="pon-w1-preparation-v4-derived-paid-denominators", qualification_status="HOLD",
        record_consistency=grid["record_consistency"], source_unchanged=manifest["source_unchanged"],
        binary_unchanged=manifest["binary_unchanged"], cost_grid_counts=dict(grid_counts),
        cost_grid_misses=grid_counts["attempts"] - grid_counts["target_hits"],
        unique_search_streams_after_strategy_horizon_deduplication=grid["unique_search_streams"],
        cost_grid_strategy_paid_totals={key: dict(value) for key, value in strategy_totals.items()},
        separate_controls=dict(controls), outer_native_process_totals=by_purpose,
        per_shard_observed_rankings=rankings, rankings_selected_after_observation=True,
        adaptive_best_of_samples_policy_executed=False, cross_horizon_statistical_pooling=False,
        cheapest_legal_strategy_lower_bound_established=False, external_ordinary_hepta_material_executed=False,
        gpu_measurement="NOT_RUN", arm_measurement="NOT_RUN", full_low_rank_implementation_measured=False,
        batching_measured=False, cross_run_cache_attack_measured=False,
        derived_input_sha256={str(path.relative_to(capture)): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs},
        security_assumptions=["fixed canonical PNW1 relation and FullLimb implementation used by all four cells",
            "fixed deterministic primitive challenges are not live parent or task eligibility",
            "uniform-ticket probabilities 1/2 and 1/32 are assumptions, not established lower bounds",
            "source and software clocks recorded locally, no independent source/hardware/energy attestation"])


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("summarize_costs.py CAPTURE_DIRECTORY NEW_SUMMARY_JSON")
    with Path(sys.argv[2]).open("w") as output:
        json.dump(summarize(sys.argv[1]), output, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")
