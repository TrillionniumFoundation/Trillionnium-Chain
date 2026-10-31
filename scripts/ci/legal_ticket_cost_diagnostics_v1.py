"""Optional paired diagnostics over the unchanged complete legal-cost V5 grid.

This is a derivation, not another collector or a new acceptance gate. The
original V5 reader validates every input first. Two counterbalanced rounds on
one shared host provide descriptive paired observations, not independent host
samples or a confidence interval on the best possible legal implementation.
"""
from __future__ import annotations

from pathlib import Path
import sys

from check_legal_ticket_cost_v5 import ARMS, HORIZONS, summed, validate

# Reuse the original exact-ratio and explicitly conditional effective-work
# model. A first-admission cost observation does not calibrate the separate
# synthetic DAA/withholding simulator or measure network adversarial share.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from read_original_native_campaign import cost_ratio, work_share_sensitivity

SCHEMA = "pon-legal-ticket-paired-cost-diagnostics-v1"
CLOCKS = ("wall_ns", "process_cpu_ns")
SCOPES = {
    "outer": "observed_outer",
    "all_exclusive_phases": "all_exclusive_phases",
    "recurring": "recurring_producer_encode_admission",
}


def complete_sum(values):
    values = list(values)
    return sum(values) if all(value is not None for value in values) else None


def difference(alternative, reference):
    return alternative - reference if alternative is not None and reference is not None else None


def generation_partition(row):
    """These three intervals partition generation; setup is not reassigned."""
    partitions = {name: [] for name in
                  ("winning_trials", "misses_before_winner", "exhausted_search_trials")}
    for search in row["searches"]:
        for trial in search["trials"]:
            key = ("winning_trials" if trial["target_hit"] else
                   "misses_before_winner" if search["won"] else "exhausted_search_trials")
            partitions[key].append(trial["generation"])
    return {key: {"attempts": len(values), "timing": summed(values)}
            for key, values in partitions.items()}


def cohort(row):
    setup = row["phases"]["producer_setup"]
    return {
        "round": row["round"], "horizon": row["search_horizon"],
        "reuse": row["reuse"], "strategy": row["strategy"],
        "searches": len(row["searches"]), "attempts": row["attempts"],
        "winners": row["winners"], "exhausted_searches": row["exhausted"],
        "actual_setup_calls": row["producer_setup_calls"],
        "setup": setup,
        "observed_setup_per_search_ns": {
            clock: cost_ratio(setup[clock], len(row["searches"])) for clock in CLOCKS},
        "generation_partition": generation_partition(row),
        "complete_scopes": {
            scope: {"timing": row[field], "ns_per_first_admission": {
                clock: cost_ratio(row[field][clock], row["winners"]) for clock in CLOCKS}}
            for scope, field in SCOPES.items()},
        "outer_minus_exclusive_phases_ns": {
            clock: difference(row["observed_outer"][clock], row["all_exclusive_phases"][clock])
            for clock in CLOCKS},
    }


def compare(reference, alternative):
    """Both full rounds stay in each fixed strategy; unknown clocks stay null."""
    rounds = []
    for left, right in zip(reference, alternative):
        rounds.append({
            "round": left["round"], "attempts": left["attempts"], "winners": left["winners"],
            "exhausted_searches": left["exhausted"],
            "reference_setup_calls": left["producer_setup_calls"],
            "alternative_setup_calls": right["producer_setup_calls"],
            "scopes": {scope: {
                clock: {
                    "reference_total_ns": left[field][clock],
                    "alternative_total_ns": right[field][clock],
                    "alternative_minus_reference_ns": difference(right[field][clock], left[field][clock]),
                    "reference_over_alternative": cost_ratio(left[field][clock], right[field][clock])
                        if left["winners"] else None,
                } for clock in CLOCKS} for scope, field in SCOPES.items()},
        })
    winners = sum(row["winners"] for row in reference)
    aggregate = {}
    for scope, field in SCOPES.items():
        aggregate[scope] = {}
        for clock in CLOCKS:
            left_total = complete_sum(row[field][clock] for row in reference)
            right_total = complete_sum(row[field][clock] for row in alternative)
            deltas = [row["scopes"][scope][clock]["alternative_minus_reference_ns"] for row in rounds]
            comparable = winners > 0 and left_total is not None and right_total is not None
            aggregate[scope][clock] = {
                "reference_total_ns": left_total, "alternative_total_ns": right_total,
                "reference_ns_per_first_admission": cost_ratio(left_total, winners),
                "alternative_ns_per_first_admission": cost_ratio(right_total, winners),
                "ratio_of_complete_totals": cost_ratio(left_total, right_total) if comparable else None,
                "paired_alternative_minus_reference_ns": deltas,
                "alternative_lower_in_both_rounds": all(value is not None and value < 0 for value in deltas)
                    if comparable else None,
                "population_confidence_interval": None,
            }
    left_cpu = aggregate["outer"]["process_cpu_ns"]["reference_total_ns"]
    right_cpu = aggregate["outer"]["process_cpu_ns"]["alternative_total_ns"]
    # A zero or unknown clock is not infinitely cheap valid work. No winner is
    # not a winning-work cost. Do not drop a failed search or an unknown round.
    sensitivity = (work_share_sensitivity(left_cpu, right_cpu)
                   if winners and left_cpu is not None and left_cpu > 0
                   and right_cpu is not None and right_cpu > 0 else None)
    return {
        "paired_rounds": rounds, "winning_first_admissions": winners,
        "attempts": sum(row["attempts"] for row in reference),
        "exhausted_searches": sum(row["exhausted"] for row in reference),
        "aggregate": aggregate,
        "conditional_full_outer_cpu_work_share": sensitivity,
    }


def derive(rows):
    validate(rows)
    index = {(row["round"], row["search_horizon"], row["reuse"], row["strategy"]): row
             for row in rows[1:-1]}
    fixed, reuse = [], []
    for horizon in HORIZONS:
        for retained in (False, True):
            reference = [index[(r, horizon, retained, "prepared-generic")] for r in (0, 1)]
            for arm in ARMS:
                if arm == "prepared-generic":
                    continue
                alternative = [index[(r, horizon, retained, arm)] for r in (0, 1)]
                fixed.append({"horizon": horizon, "reuse": retained,
                              "reference_strategy": "prepared-generic", "alternative_strategy": arm,
                              **compare(reference, alternative)})
        for arm in ARMS:
            reference = [index[(r, horizon, False, arm)] for r in (0, 1)]
            alternative = [index[(r, horizon, True, arm)] for r in (0, 1)]
            reuse.append({"horizon": horizon, "strategy": arm,
                          "reference_reuse": False, "alternative_reuse": True,
                          **compare(reference, alternative)})
    return {
        "schema": SCHEMA, "raw_schema": rows[0]["schema"],
        "cohorts": [cohort(row) for row in rows[1:-1]],
        "fixed_strategy_pairs": fixed, "actual_setup_reuse_pairs": reuse,
        "boundaries": {
            "costs_include_all_failed_searches": True,
            "per_round_fastest_strategies_combined": False,
            "two_rounds_are_independent_host_samples": False,
            "population_confidence_interval_qualified": False,
            "winning_only_proof_assembly_measured": False,
            "global_support_setup_reallocated_to_strategies": False,
            "fresh_native_execution": False,
            "full_transcripts_independently_replayed": False,
            "calibrates_conditional_daa_model": False,
            "global_minimum_proved": False, "production_qualified": False,
        },
        "scope": [
            "All paired rounds remain separate; ratios use complete summed costs of one fixed strategy, not a mean of ratios or per-round winners.",
            "The three generation partitions are disjoint. Setup, encoding and first native admission are already inside recurring, exclusive and outer scopes; do not add nested scopes.",
            "Observed setup divided by actual searches describes this retained run; it does not project another reuse horizon or remove failed searches.",
            "Outer cohorts include native admission, cold reopen and readback. Global probes, final serialization and tempdir cleanup remain only in the full native capture and are not arbitrarily assigned to strategies.",
            "Two counterbalanced rounds from a shared host do not justify population intervals, independent-host claims or a hardware lower bound. Descriptive differences can change sign.",
            "Effective-work sensitivity reuses the existing conditional CPU-budget model. It additionally assumes these sibling first-admission costs represent network work, linear CPU throughput, identical task/target distributions and equal availability; these assumptions are not measured here.",
            "Winning trial generation includes full proof assembly on every attempted nonce. This schema cannot isolate the cost of assembling only a winning proof or bound a cheaper legal strategy.",
        ],
    }
