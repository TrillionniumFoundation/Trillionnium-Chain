#!/usr/bin/env python3
"""Preregistered descriptive analysis of the exact 58-job W1 readback.

This consumes an already independently verified readback. It does not repeat
bundle authentication or make CPU/hardware attestation, universal-kappa, model
utility, or permissionless-security claims. Pairing never uses measured speed.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
from read_w1_cost_research import require, uint64
from w1_joint_challenge_reader import options_from_args as joint_options
from w1_parent_reuse_reader import options_from_args as parent_options

PLAN = ROOT / "formal/pon-nakamoto-v1/experiments/w1_adaptive_joint_campaign_v1.json"
JOINT = "pon_w1_joint_research"
PARENT = "pon_w1_parent_reuse_research"
SCHEMA = "pon-w1-next-research-derived-v1"
CONTROLS = (
    ("zero-before-registration", "TASK"),
    ("material-mismatch", "TASK_MATERIAL"),
    ("stale-admission-after-renewal", "TASK_ADMISSION_CONTEXT"),
    ("zero-after-revocation", "TASK"),
)
MAX_INPUT_BYTES = 64 * 1024 * 1024


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "DUPLICATE_JSON_KEY")
        out[key] = value
    return out


def reject_constant(_):
    raise ValueError("NONFINITE_JSON")


def load_json(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    require(len(raw) <= MAX_INPUT_BYTES, "INPUT_TOO_LARGE")
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant), raw


def exact_fraction(numerator, denominator):
    """Keep the actual integer operands as well as their reduced ratio."""
    uint64(numerator, "NEGATIVE_NUMERATOR") if numerator < (1 << 64) else require(type(numerator) is int, "NUMERATOR")
    require(type(denominator) is int and denominator >= 0, "DENOMINATOR")
    if denominator == 0:
        require(numerator == 0, "POSITIVE_NUMERATOR_WITH_ZERO_DENOMINATOR")
        return None
    value = Fraction(numerator, denominator)
    return {"numerator": numerator, "denominator": denominator,
            "reduced_numerator": value.numerator, "reduced_denominator": value.denominator,
            "decimal": float(value)}


def rate_ratio(new_count, new_cpu, baseline_count, baseline_cpu):
    for value in (new_count, new_cpu, baseline_count, baseline_cpu):
        uint64(value, "RATE_OPERAND")
    require(new_count == 0 or new_cpu > 0, "NEW_ZERO_CPU_DENOMINATOR")
    require(baseline_count == 0 or baseline_cpu > 0, "BASELINE_ZERO_CPU_DENOMINATOR")
    if not all((new_count, new_cpu, baseline_count, baseline_cpu)):
        return None
    return exact_fraction(new_count * baseline_cpu, baseline_count * new_cpu)


def stage_shares(stages, denominator):
    require(type(stages) is dict and all(type(k) is str for k in stages), "STAGE_FIELDS")
    total = sum(uint64(v, "STAGE_CPU") for v in stages.values())
    require(total <= denominator, "STAGE_SUM_EXCEEDS_DENOMINATOR")
    return {"charged": {k: {"cpu_ns": v, "share": exact_fraction(v, denominator)}
                        for k, v in sorted(stages.items())},
            "unattributed_cpu_ns": denominator - total,
            "unattributed_share": exact_fraction(denominator - total, denominator),
            "denominator_cpu_ns": denominator}


def command_observation(row, native_endpoint, posthoc=0):
    resource = row["whole_waited_child_resources"]
    usage = row["whole_command_usage"]
    whole = uint64(resource["user_cpu_ns"], "WHOLE_USER_CPU") + uint64(resource["system_cpu_ns"], "WHOLE_SYSTEM_CPU")
    peak = uint64(usage["maximum_resident_set_kib"], "COMMAND_MAX_RSS")
    # GNU time's decimal output is an independent coarse observation. Do not
    # treat its printed centiseconds as a native nanosecond measurement.
    printed = Fraction(usage["user_seconds_decimal"]) + Fraction(usage["system_seconds_decimal"])
    require(printed >= 0, "GNU_TIME_NEGATIVE_CPU")
    return {
        "whole_waited_child_cpu_ns": whole,
        "whole_command_maximum_rss_kib": peak,
        "memory_scope": "one-command-maximum-not-sum-or-concurrent-total",
        "gnu_time_printed_cpu_seconds": {"numerator": printed.numerator, "denominator": printed.denominator},
        "native_endpoint_cpu_ns": native_endpoint, "posthoc_process_cpu_ns": posthoc,
        "whole_child_minus_native_and_posthoc_cpu_ns": whole - native_endpoint - posthoc,
        "residual_is_signed": True,
        "residual_scope": "startup-final-output-framework-wrappers-and-clock-accounting-differences; no causal attribution",
        "cross_observer_reconciliation": row.get("cpu_observer_reconciliation"),
    }


def joint_metrics(row):
    require(row["schema"] == "pon-w1-joint-challenge-verified-v1", "JOINT_SCHEMA")
    options, end, attempts = row["options"], row["end"], row["attempts"]
    require(type(attempts) is list and len(attempts) == end["attempts"] ==
            row["all_completed_proofs_python_replayed"], "JOINT_REPLAY_COUNTS")
    seen, hits, budget_unique, budget_hits = set(), 0, set(), set()
    for index, attempt in enumerate(attempts):
        require(attempt["index"] == index and attempt["task"] == row["task"], "JOINT_COMPACT_INDEX_TASK")
        identity = attempt["semantic_id"]
        require(type(identity) is str and len(identity) == 64, "JOINT_SEMANTIC")
        unique = identity not in seen
        require(attempt["unique"] is unique and type(attempt["target_hit"]) is bool, "JOINT_COMPACT_FLAGS")
        cpu = uint64(attempt["inclusive_producer_cpu_ns"], "JOINT_COMPLETION_CPU")
        within = options["cpu_budget_ns"] is None or cpu <= options["cpu_budget_ns"]
        require(attempt["inclusive_within_cpu_budget"] is within, "JOINT_BUDGET_FENCE")
        seen.add(identity)
        hits += int(attempt["target_hit"])
        if within:
            budget_unique.add(identity)
            if attempt["target_hit"]:
                budget_hits.add(identity)
    require(end["unique_opportunities"] == len(seen) and end["target_hits"] == hits and
            end["inclusive_budget_unique_opportunities"] == len(budget_unique) and
            end["inclusive_budget_unique_target_hits"] == len(budget_hits), "JOINT_DERIVED_COUNTS")
    inclusive = uint64(end["inclusive_producer_cpu_ns"], "JOINT_INCLUSIVE")
    core = uint64(end["charged_core_cpu_ns"], "JOINT_CORE")
    observer = uint64(end["observer_cpu_ns"], "JOINT_OBSERVER")
    elapsed = uint64(end["elapsed_cpu_ns"], "JOINT_ELAPSED")
    require(inclusive + observer == elapsed and core <= inclusive and
            sum(row["stage_cpu_ns"].values()) == core, "JOINT_DENOMINATORS")
    budget = options["cpu_budget_ns"]
    cap = len(attempts) == options["attempts"]
    require((end["status"] == "attempt-cap-complete") is cap, "JOINT_CAP_STATUS")
    if not cap:
        require(end["status"] == "inclusive-cpu-budget-exhausted" and budget is not None and
                inclusive >= budget, "JOINT_EARLY_STOP")
    return {
        "job": row["job"], "options": options, "status": end["status"],
        "completed_records": len(attempts), "unique_completed_opportunities": len(seen),
        "unique_completed_winners": end["unique_target_hits"],
        "within_budget_unique_opportunities": len(budget_unique), "within_budget_unique_winners": len(budget_hits),
        "inclusive_cpu_ns": inclusive, "charged_core_cpu_ns": core, "observer_cpu_ns": observer,
        "inclusive_ns_per_unique_opportunity": exact_fraction(inclusive, len(seen)) if seen else None,
        "unique_opportunities_per_inclusive_cpu_ns": exact_fraction(len(seen), inclusive),
        "unique_opportunities_per_core_cpu_ns": exact_fraction(len(seen), core),
        "attempt_cap_reached": cap, "requested_attempt_cap": options["attempts"],
        "budget_overshoot_cpu_ns": None if budget is None else max(0, inclusive - budget),
        "cap_is_censoring_not_maximum_budget_yield": True,
        "stages_over_inclusive": stage_shares(row["stage_cpu_ns"], inclusive),
        "command": command_observation(row, elapsed),
    }


def admission_cpu(record):
    stamp = record.get("admission_completed")
    return None if stamp is None else uint64(stamp["process_cpu_ns"], "ADMISSION_CPU")


def parent_metrics(row):
    require(row["schema"] == "pon-w1-parent-reuse-readback-v1", "PARENT_SCHEMA")
    options, counts = row["options"], row["counts"]
    attempts, acquisitions = row["attempts"], row["acquisitions"]
    require(type(attempts) is list and type(acquisitions) is list and
            counts["research_completed_proofs"] == len(attempts) and
            counts["acquisitions"] == len(acquisitions), "PARENT_RECORD_COUNTS")
    replay = row["python_replayed"]
    require(replay["research_proofs"] == len(attempts) and replay["acquisition_winners"] == len(acquisitions) and
            row["retained_proof_records_replayed"] == replay["full_relation_records"] ==
            len(attempts) + len(acquisitions) + replay["posthoc_reconstruction_records"], "PARENT_REPLAY_COUNTS")
    original_count = sum(uint64(a["original_make_complete_attempts"], "ORIGINAL_SEARCH_COUNT", 1) for a in acquisitions)
    require(counts["original_make_completed_proofs"] == original_count and
            counts["original_make_failed_target_proofs"] == original_count - len(acquisitions) and
            replay["posthoc_reconstruction_records"] == original_count, "ORIGINAL_POSTHOC_SEPARATION")
    budget = options["cpu_budget_ns"]
    all_within, research_within, all_winners = set(), set(), set()
    research_semantics = {a["semantic_id"] for a in attempts}
    for kind, records in (("research", attempts), ("acquisition", acquisitions)):
        require([a["id"] for a in records] == list(range(len(records))), "PARENT_COMPACT_IDS")
        for record in records:
            require(type(record["target_hit"]) is bool, "PARENT_HIT")
            admitted = admission_cpu(record)
            require((admitted is not None) is record["target_hit"], "PARENT_ADMISSION_BINDING")
            if record["target_hit"]:
                all_winners.add(record["semantic_id"])
                if budget is None or admitted <= budget:
                    all_within.add(record["semantic_id"])
                    if kind == "research":
                        research_within.add(record["semantic_id"])
    require(counts["research_unique_complete_semantics"] == len(research_semantics) and
            counts["all_work_unique_winners"] == len(all_winners) and
            counts["all_work_unique_admitted_within_budget"] == len(all_within) and
            counts["research_unique_admitted_within_budget"] == len(research_within), "PARENT_BUDGET_COUNTS")
    controls = row["controls"]
    require(type(controls) is list and len(controls) <= 4, "PARENT_CONTROLS")
    for index, control in enumerate(controls):
        require((control["name"], control["error"]) == CONTROLS[index] and
                control["scope"] == "native_reported", "PARENT_CONTROL_RESULT")
    require(type(row["controls_completed"]) is bool, "PARENT_CONTROL_COMPLETION")
    complete = row["status"] == "planned-rounds-complete"
    if complete:
        require(row["controls_completed"] and len(controls) == 4 and
                len(attempts) == options["rounds"] * options["attempts_per_parent"] and
                counts["rounds_completed"] == options["rounds"], "PARENT_PLANNED_COMPLETION")
    if row["controls_completed"]:
        require(len(controls) == 4, "PARENT_CONTROL_NOT_ALL_EXECUTED")
    strategy = uint64(row["strategy_cpu_ns"], "STRATEGY_CPU")
    posthoc = uint64(row["posthoc_process_cpu_ns"], "POSTHOC_CPU")
    require(complete or (row["status"] in ("process-cpu-budget-stopped", "process-cpu-budget-stopped-before-context") and
                        budget is not None and strategy >= budget), "PARENT_STOP_STATUS")
    shares = stage_shares(row["charge_cpu_ns_by_stage"], strategy)
    require(shares["unattributed_cpu_ns"] == row["unattributed_strategy_cpu_ns"], "PARENT_STAGE_RESIDUAL")
    return {
        "job": row["job"], "options": options, "status": row["status"], "counts": counts,
        "genuine_research_records": len(attempts), "auxiliary_original_winning_records": len(acquisitions),
        "original_make_completed_attempts": original_count,
        "posthoc_reconstructed_records": replay["posthoc_reconstruction_records"],
        "posthoc_reconstruction_new_work_credit": 0,
        "all_work_admitted_within_budget_unique": len(all_within),
        "research_admitted_within_budget_unique": len(research_within),
        "strategy_cpu_ns": strategy, "posthoc_process_cpu_ns": posthoc,
        "all_work_within_budget_per_strategy_cpu_ns": exact_fraction(len(all_within), strategy) if all_within else None,
        "planned_strategy_complete": complete, "attempt_cap_reached": len(attempts) == options["rounds"] * options["attempts_per_parent"],
        "budget_overshoot_cpu_ns": None if budget is None else max(0, strategy - budget),
        "controls_completed": row["controls_completed"],
        "lifecycle_observation": "complete-native-reported" if complete and row["controls_completed"] else "incomplete-no-pass-claim",
        "controls": [{"name": name, "expected_error": error,
                      "observed": next((v for v in controls if v["name"] == name), None),
                      "executed_expected_rejection": any(v["name"] == name for v in controls)}
                     for name, error in CONTROLS],
        "stages_over_strategy": shares, "command": command_observation(row, strategy, posthoc),
    }


def key_without(options, excluded):
    return json.dumps({key: value for key, value in options.items() if key != excluded},
                      sort_keys=True, separators=(",", ":"))


def joint_pair(left, right, metrics):
    require(left["options"]["producer"] == "avx2-joint" and
            right["options"]["producer"] == "prepared-sequential" and
            key_without(left["options"], "producer") == key_without(right["options"], "producer"), "JOINT_PAIR_SCOPE")
    overlap = min(len(left["attempts"]), len(right["attempts"]))
    fields = ("index", "challenge", "task", "ticket", "semantic_id", "block_id")
    for a, b in zip(left["attempts"], right["attempts"]):
        require(all(a[field] == b[field] for field in fields), "JOINT_OVERLAPPING_IDENTITY")
    a, b = metrics[left["job"]], metrics[right["job"]]
    phase = "short" if left["job"].startswith("joint.short.") else "long" if left["job"].startswith("joint.long.") else "control"
    return {
        "phase": phase, "avx2_job": left["job"], "sequential_job": right["job"],
        "options_except_producer": {k: v for k, v in left["options"].items() if k != "producer"},
        "overlapping_identity_records_checked": overlap, "nonempty_identity_overlap": overlap > 0,
        "all_completed_inclusive_rate_ratio_avx2_over_sequential": rate_ratio(
            a["unique_completed_opportunities"], a["inclusive_cpu_ns"],
            b["unique_completed_opportunities"], b["inclusive_cpu_ns"]),
        "all_completed_core_rate_ratio_avx2_over_sequential": rate_ratio(
            a["unique_completed_opportunities"], a["charged_core_cpu_ns"],
            b["unique_completed_opportunities"], b["charged_core_cpu_ns"]),
        "avx2": a, "sequential": b,
        "scope": "finite-registered-same-task-seed-target-budget-mode-width; observed complete-work rates only",
    }


def compact_identity(record):
    return {key: value for key, value in record.items()
            if key not in ("completed", "admission_completed", "original_search_completed")}


def parent_pair(hot, cold, metrics):
    require(hot["options"]["cache"] == "hot" and cold["options"]["cache"] == "cold" and
            key_without(hot["options"], "cache") == key_without(cold["options"], "cache"), "PARENT_PAIR_SCOPE")
    identical = True
    for field in ("attempts", "acquisitions"):
        left, right = [compact_identity(v) for v in hot[field]], [compact_identity(v) for v in cold[field]]
        require(all(a == b for a, b in zip(left, right)), "PARENT_OVERLAPPING_IDENTITY")
        identical &= left == right
    a, b = metrics[hot["job"]], metrics[cold["job"]]
    ratio = None
    if identical:
        ratio = rate_ratio(a["all_work_admitted_within_budget_unique"], a["strategy_cpu_ns"],
                           b["all_work_admitted_within_budget_unique"], b["strategy_cpu_ns"])
    return {
        "hot_job": hot["job"], "cold_job": cold["job"],
        "options_except_cache": {k: v for k, v in hot["options"].items() if k != "cache"},
        "all_research_and_acquisition_identities_identical": identical,
        "rate_suppressed_for_censored_identity_sequences": not identical,
        "all_work_within_budget_strategy_rate_ratio_hot_over_cold": ratio,
        "hot": a, "cold": b,
        "different_strategies_or_future_parents_compared": False,
    }


def analyze(readback):
    require(type(readback) is dict and readback.get("schema") == SCHEMA, "READBACK_SCHEMA")
    plan, plan_bytes = load_json(PLAN)
    require(readback["plan_sha256"] == hashlib.sha256(plan_bytes).hexdigest(), "REGISTERED_PLAN_HASH")
    registered = plan["jobs"]
    jobs = readback["jobs"]
    require(type(jobs) is list and len(jobs) == len(registered) == 58, "EXACT_58_JOBS")
    require([r["job"] for r in jobs] == [r["name"] for r in registered] and
            len({r["job"] for r in jobs}) == 58, "REGISTERED_JOB_ORDER_AND_SET")
    for key in ("external_identity_pins_checked", "posthoc_replay_provides_no_selection_feedback",
                "all_retained_full_proof_records_independently_replayed"):
        require(readback[key] is True, "READBACK_VERIFICATION:" + key)
    for key in ("native_execution_attested_by_reader", "native_qualification_independently_reexecuted_by_python",
                "hardware_attested", "universal_kappa_bound_established", "hardness_accepted",
                "production_activation", "new_training_qualification"):
        require(readback[key] is False, "READBACK_AUTHORITY:" + key)
    metrics, joint_groups, parent_groups, parent_controls = {}, defaultdict(dict), defaultdict(dict), []
    for row, registration in zip(jobs, registered):
        require(row["binary"] == registration["binary"], "REGISTERED_BINARY")
        options = (joint_options if row["binary"] == JOINT else parent_options)(registration["args"])
        require(row["options"] == options, "REGISTERED_EXACT_OPTIONS")
        if row["binary"] == JOINT:
            metrics[row["job"]] = joint_metrics(row)
            group = joint_groups[key_without(options, "producer")]
            require(options["producer"] not in group, "DUPLICATE_JOINT_ARM")
            group[options["producer"]] = row
        else:
            require(row["binary"] == PARENT, "UNKNOWN_BINARY")
            metrics[row["job"]] = parent_metrics(row)
            if row["job"].startswith("parent.") and options["seed"] in (2201, 2202):
                group = parent_groups[key_without(options, "cache")]
                require(options["cache"] not in group, "DUPLICATE_PARENT_CACHE")
                group[options["cache"]] = row
            else:
                parent_controls.append(metrics[row["job"]])
    require(len(joint_groups) == 21 and len(parent_groups) == 6 and len(parent_controls) == 4, "REGISTERED_PAIR_COUNTS")
    joint_pairs = []
    for group in joint_groups.values():
        require(set(group) == {"avx2-joint", "prepared-sequential"}, "JOINT_ARM_SET")
        joint_pairs.append(joint_pair(group["avx2-joint"], group["prepared-sequential"], metrics))
    require(Counter(p["phase"] for p in joint_pairs) == {"short": 12, "long": 3, "control": 6}, "JOINT_PHASE_COUNTS")
    parent_pairs = []
    for group in parent_groups.values():
        require(set(group) == {"hot", "cold"}, "PARENT_CACHE_SET")
        parent_pairs.append(parent_pair(group["hot"], group["cold"], metrics))
    joint_rows = [r for r in jobs if r["binary"] == JOINT]
    parent_rows = [r for r in jobs if r["binary"] == PARENT]
    require(len(joint_rows) == 42 and len(parent_rows) == 16, "FAMILY_JOB_COUNTS")
    genuine = sum(len(r["attempts"]) for r in joint_rows + parent_rows)
    auxiliary = sum(len(r["acquisitions"]) for r in parent_rows)
    posthoc = sum(r["python_replayed"]["posthoc_reconstruction_records"] for r in parent_rows)
    all_replayed = sum(r["all_completed_proofs_python_replayed"] for r in joint_rows) + sum(
        r["retained_proof_records_replayed"] for r in parent_rows)
    require(all_replayed == genuine + auxiliary + posthoc, "ALL_REPLAY_RECORD_ACCOUNTING")
    global_research = {a["semantic_id"] for row in jobs for a in row["attempts"]}
    global_aux = {a["semantic_id"] for row in parent_rows for a in row["acquisitions"]}
    return {
        "schema": "pon-w1-adaptive-joint-analysis-v1",
        "source": readback["source"], "plan_sha256": readback["plan_sha256"],
        "raw_manifest_sha256": readback["raw_manifest_sha256"], "reader_sha256": readback["reader_sha256"],
        "binaries": readback["binaries"],
        "input_trust": "requires-the-owner-verified-source-bound-readback; this analysis does not reauthenticate raw bundles",
        "counts": {
            "jobs": 58, "joint_jobs": 42, "parent_jobs": 16, "joint_pairs": 21,
            "joint_short_pairs": 12, "joint_long_pairs": 3, "joint_control_pairs": 6,
            "parent_main_cache_pairs": 6, "parent_other_or_budget_controls": 4,
            "genuine_research_proof_records": genuine,
            "auxiliary_original_winning_proof_records": auxiliary,
            "posthoc_reconstructed_proof_records": posthoc,
            "all_full_proof_records_independently_replayed": all_replayed,
            "distinct_research_semantics_across_counterfactual_jobs": len(global_research),
            "distinct_auxiliary_semantics_across_counterfactual_jobs": len(global_aux),
            "distinct_all_recorded_work_semantics_across_jobs": len(global_research | global_aux),
            "parent_planned_strategy_complete": sum(metrics[r["job"]]["planned_strategy_complete"] for r in parent_rows),
            "parent_lifecycle_controls_complete": sum(r["controls_completed"] for r in parent_rows),
        },
        "joint_pairs": joint_pairs, "parent_main_cache_pairs": parent_pairs,
        "parent_other_or_budget_controls": parent_controls,
        "all_jobs_in_registered_order": [metrics[row["job"]] for row in jobs],
        "maximum_single_command_rss_kib": max(v["command"]["whole_command_maximum_rss_kib"] for v in metrics.values()),
        "hardware": readback["hardware"], "energy_joules": None, "network_transfer_measured": False,
        "hardware_attested": False, "universal_kappa_bound_established": False,
        "hardness_accepted": False, "production_activation": False, "new_training_qualification": False,
        "original_internal_miss_bytes_retained_when_generated": False,
        "posthoc_reconstructions_create_new_work_credit": False,
        "counterfactual_jobs_or_sibling_winners_summed_into_chainweight": False,
        "joint_and_parent_rate_denominators_combined": False,
        "limitations": [
            "All ratios describe these finite registered jobs; they are not a universal adversarial cost bound.",
            "Joint rates use actual completed unique opportunities and actual inclusive/core CPU, including overrun cost.",
            "Parent rates require the same policy and identical complete research/acquisition identity histories.",
            "Budget-truncated parent histories retain observations but suppress the paired ratio when lengths differ.",
            "Reaching an attempt cap does not establish maximum yield under the nominal budget.",
            "Posthoc reconstruction and auxiliary original winners remain separate from new research work.",
            "A completed readback is not completion of all four native lifecycle controls.",
            "RSS is per-command peak; whole-child residuals retain signs and observation-scope differences.",
            "Near-q matrices are structured canonical-word boundaries, not hardness exemplars.",
        ],
    }


def write_analysis(readback_path, output_path):
    require(not Path(output_path).exists(), "OUTPUT_ALREADY_EXISTS")
    readback, raw = load_json(readback_path)
    result = analyze(readback)
    result["readback_sha256"] = hashlib.sha256(raw).hexdigest()
    result["analysis_source_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    encoded = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    with Path(output_path).open("x", encoding="utf-8") as stream:
        stream.write(encoded)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readback", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = write_analysis(args.readback, args.out)
        print(json.dumps({"jobs": result["counts"]["jobs"], "joint_pairs": 21,
                          "parent_cache_pairs": 6, "universal_kappa_bound_established": False}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, OverflowError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
