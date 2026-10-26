#!/usr/bin/env python3
"""Frozen descriptive analysis of finite native sibling-fork W1 resource evidence.

The externally pinned full reader must run first. This analysis never converts
local timing into a minimum-cost theorem, a physical attestation or chain growth.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))
from read_w1_cost_research import require, uint64, hx
from w1_fork_resource_reader import options_from_args, same
from contract_wire import header_decode
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1/experiments"))
from analyze_w1_adaptive_joint import exact_fraction, load_json
from w1_chain_security_envelope import required_work

PLAN = ROOT / "formal/pon-nakamoto-v1/experiments/w1_fork_resource_campaign_v1.json"
REFERENCE = "integer-paired-general"
BINARY = "pon_w1_fork_resource_research"
PHASES = ("setup", "miner", "receiver", "audit")
IDENTITY_KEYS = ("attempt_id", "task_index", "template_index", "branch", "epoch", "parent",
                 "height", "header_hex", "challenge", "proof_sha256", "semantic_id", "target_hit")


def ratio(numerator, denominator):
    uint64(numerator, "RATIO_NUMERATOR")
    uint64(denominator, "RATIO_DENOMINATOR")
    return None if denominator == 0 else exact_fraction(numerator, denominator)


def yield_rate_ratio(left_count, left_cpu, right_count, right_cpu):
    for value in (left_count, left_cpu, right_count, right_cpu):
        uint64(value, "RATE_OPERAND")
    if left_cpu == 0 or right_cpu == 0 or right_count == 0:
        return None
    return exact_fraction(left_count * right_cpu, right_count * left_cpu)


def miner_metrics(row):
    require(row["schema"] == "pon-w1-fork-resource-readback-v1" and row["status"] == "verified",
            "MINER_READBACK_SCHEMA")
    options, phases = row["options"], row["phase_cpu_ns"]
    require(set(phases) == set(PHASES), "PHASE_SET")
    for value in phases.values():
        uint64(value, "PHASE_CPU")
    require(sum(phases.values()) == uint64(row["total_process_cpu_ns"], "TOTAL_CPU"), "PHASE_SUM")
    require(type(row["setup_complete"]) is bool and row["setup_complete"] is row["setup"]["complete"],
            "SETUP_COMPLETE")
    require(not row["setup_complete"] or phases["setup"] <= options["setup_budget_ns"], "SETUP_OVER_BUDGET")
    attempts = row["attempts"]
    require([a["attempt_id"] for a in attempts] == list(range(len(attempts))), "ATTEMPT_ORDER")
    full, hits, accepted, all_ids = set(), set(), set(), set()
    weights, target_counts, parent_tasks = {}, Counter(), Counter()
    late, late_hits = 0, 0
    for a in attempts:
        identity = hx(a["semantic_id"], 32, "SEMANTIC_ID").hex()
        require(identity not in all_ids, "DUPLICATE_RESEARCH_IDENTITY")
        all_ids.add(identity)
        elapsed = uint64(a["miner_elapsed_cpu_ns"], "MINER_AVAILABILITY_CPU")
        inside = elapsed <= options["miner_budget_ns"]
        require(type(a["within_miner_budget"]) is bool and a["within_miner_budget"] is inside,
                "AVAILABILITY_FENCE")
        require(type(a["target_hit"]) is bool and a["native_accepted"] is a["target_hit"],
                "NATIVE_TARGET_OUTCOME")
        h = header_decode(bytes.fromhex(a["header_hex"]))
        require(h["parent"].hex() == a["parent"] and h["height"] == a["height"], "HEADER_PARENT")
        target = int.from_bytes(h["target"], "big")
        weights[identity] = required_work(target)
        target_counts[h["target"].hex()] += 1
        parent_tasks[(a["parent"], a["task_index"])] += 1
        if inside:
            full.add(identity)
            if a["target_hit"]:
                hits.add(identity)
            if a["native_accepted"]:
                accepted.add(identity)
        else:
            late += 1
            late_hits += a["target_hit"]
    require(accepted == hits <= full, "ACCEPTED_SUBSET")
    setup = row["setup"]
    acq, audit = row["acquisitions"], row["audit"]
    original = sum(uint64(a["original_complete_attempts"], "ORIGINAL_ATTEMPTS", 1) for a in acq)
    require(original == setup["original_search_complete_attempts"] and
            len(acq) == setup["original_acquisitions"] == setup["known_original_winning_semantics"],
            "SETUP_COUNT")
    known = {a["semantic_id"] for a in acq}
    require(len(known) == len(acq) and not known.intersection(all_ids), "PREPAID_CREDIT_REUSE")
    expected_counts = dict(
        research_proof_records=len(attempts), original_winner_records=len(acq),
        original_reconstruction_records=original, all_full_proof_records=len(attempts)+len(acq)+original,
        research_target_hits=sum(a["target_hit"] for a in attempts), research_late_proofs=late,
        research_late_target_hits=late_hits, miner_unique_complete_by_B=len(full),
        miner_unique_target_hits_by_B=len(hits), eventually_native_accepted_from_B=len(accepted))
    require(same(row["counts"], expected_counts) and type(row["retained_proof_records_replayed"]) is int and row["retained_proof_records_replayed"] ==
            expected_counts["all_full_proof_records"], "FULL_COUNT_RECONCILIATION")
    require(audit["research_full_native_audits"] == len(attempts) and
            audit["original_reconstruction_records"] == original and
            audit["original_winner_repetitions"] == len(acq) and audit["new_work_credit"] == 0,
            "AUDIT_COUNT")
    for name in ("miner_unique_complete_by_B", "miner_unique_target_hits_by_B"):
        require(row["miner"][name] == expected_counts[name], "MINER_SUMMARY_COUNT")
    require(row["receiver"]["eventually_native_accepted_from_B"] == len(accepted) and
            row["receiver"]["active_chain_growth_from_research"] == 0, "RECEIVER_SUMMARY_COUNT")
    status, cap = row["miner_status"], options["max_attempts"]
    require(len(attempts) <= cap and row["miner"]["status"] == status, "MINER_STATUS")
    censored = len(attempts) == cap
    if not row["setup_complete"]:
        require(status == "setup-incomplete" and not attempts, "MINER_WITHOUT_SETUP")
    elif status == "miner-cpu-budget-stopped":
        require(phases["miner"] >= options["miner_budget_ns"], "FALSE_BUDGET_STOP")
    else:
        require(status == "safety-cap-censored" and censored, "FALSE_CAP_STOP")
    require(row["miner"]["safety_cap_reached"] is censored, "CAP_FLAG")
    complete = (row["setup_complete"] and options["miner_budget_ns"] > 0 and
                status == "miner-cpu-budget-stopped" and not censored)
    unattributed = {}
    for phase in PHASES:
        charged = sum(uint64(value, "CHARGED_STAGE_CPU") for key, value in row["charged_stage_cpu_ns"].items()
                      if key.startswith(phase + ":"))
        require(charged <= phases[phase], "PHASE_CHARGES")
        unattributed[phase] = phases[phase] - charged
    require(same(unattributed, row["unattributed_phase_cpu_ns"]), "UNATTRIBUTED_PHASE_CPU")
    require(set(row["charged_stage_cpu_ns"]).issubset(
        {key for key in row["charged_stage_cpu_ns"] if key.split(":")[0] in PHASES}), "UNKNOWN_CHARGE_PHASE")
    setup_plus_miner = phases["setup"] + phases["miner"]
    final_stats = row["receiver"]["native_stats"]
    return dict(
        job=row["job"], options=options, setup_complete=row["setup_complete"], miner_status=status,
        complete_uncensored_miner_budget_observation=complete, safety_cap_reached=censored,
        nominal_setup_budget_ns=options["setup_budget_ns"], nominal_miner_budget_ns=options["miner_budget_ns"],
        phase_cpu_ns=phases, setup_plus_miner_cpu_ns=setup_plus_miner,
        total_process_cpu_ns=row["total_process_cpu_ns"], total_wall_ns=row["total_wall_ns"],
        setup_overshoot_cpu_ns=max(0, phases["setup"]-options["setup_budget_ns"]),
        miner_overshoot_cpu_ns=max(0, phases["miner"]-options["miner_budget_ns"]),
        counts=expected_counts, known_prepaid_winning_identities=len(known), transaction_fee_units=setup["transaction_fee_units"],
        transaction_fee_scope="committed setup candidate receipts; consult active economy separately after incomplete setup",
        paid_template_count=len(row["templates"]), selected_parent_task_counts=[
            dict(parent=parent, task_index=task, complete_proofs=n) for (parent, task), n in sorted(parent_tasks.items())],
        target_opportunities=dict(target_counts), candidate_chainwork_from_B=sum(weights[i] for i in accepted),
        candidate_chainwork_is_canonical_growth=False, canonical_chainwork_added_by_research=0,
        final_native_stats=final_stats, charged_stage_cpu_ns=row["charged_stage_cpu_ns"],
        unattributed_phase_cpu_ns=unattributed, full_proofs_per_nominal_B_ns=ratio(len(full), options["miner_budget_ns"]),
        accepted_from_B_per_actual_miner_ns=ratio(len(accepted), phases["miner"]),
        accepted_from_B_per_setup_plus_miner_ns=ratio(len(accepted), setup_plus_miner),
        whole_command_usage=row["whole_command_usage"], cpu_observer_reconciliation=row["cpu_observer_reconciliation"],
        native_state_is_reported_not_reexecuted_by_python=True, minimum_attacker_cost_established=False,
        forest=row["forest"], paid_forest_identity_sha256=row["paid_forest_identity_sha256"],
        epochs_started=len(row["epochs"]), cache_hit_records=sum(a["cache_hit"] for a in attempts),
        selected_template_counts=dict(Counter(str(a["template_index"]) for a in attempts)),
        selected_task_counts=dict(Counter(str(a["task_index"]) for a in attempts)),
        visited_leaf_parents=len({a["parent"] for a in attempts}),
        distinct_leaf_state_roots=len({a["state_root"] for a in row["forest"]["leaves"]}) if row["forest"] else 0,
        cumulative_setup_plus_miner_cpu_is_not_a_shared_budget_limit=True,
        epoch_budget_reset=False, arbitrary_strategy_covered=False)


def key_without(options, field):
    return json.dumps({k:v for k,v in options.items() if k != field}, sort_keys=True, separators=(",", ":"))


def matching_prefix(left, right):
    count = 0
    for a, b in zip(left, right):
        if any(a[key] != b[key] for key in IDENTITY_KEYS):
            return False, count
        count += 1
    return True, count


def compare(left, right, metrics, dimension):
    require(key_without(left["options"], dimension) == key_without(right["options"], dimension), "PAIR_OPTIONS")
    a, b = metrics[left["job"]], metrics[right["job"]]
    prefix, overlap = matching_prefix(left["attempts"], right["attempts"])
    same_paid = same(left["acquisitions"], right["acquisitions"])
    same_bank = same(left["templates"], right["templates"])
    complete = (a["complete_uncensored_miner_budget_observation"] and
                b["complete_uncensored_miner_budget_observation"])
    same_forest = same(left["forest"], right["forest"]) and left["paid_forest_identity_sha256"] == right["paid_forest_identity_sha256"]
    comparable = prefix and same_paid and same_bank and same_forest and complete
    yield_key = "eventually_native_accepted_from_B"
    out = dict(dimension=dimension, left_job=left["job"], right_job=right["job"],
               left_label=left["options"][dimension], right_label=right["options"][dimension],
               comparable=comparable, same_paid_acquisition_history=same_paid,
               same_complete_template_bank=same_bank, same_complete_paid_forest=same_forest, overlapping_semantic_prefix_matches=prefix,
               matched_prefix_records=overlap, both_complete_uncensored_observations=complete,
               unequal_record_counts_retained=len(left["attempts"]) != len(right["attempts"]),
               equal_B_complete_proof_ratio=None, equal_B_eventually_accepted_ratio=None,
               actual_miner_accepted_rate_ratio=None, setup_plus_miner_accepted_rate_ratio=None,
               left_metrics=a, right_metrics=b, universal_kappa_bound=False,
               canonical_chain_growth_ratio=False,
               reason=None if comparable else "incomplete-or-censored-observation-or-divergent-paid-identity")
    if comparable:
        out["equal_B_complete_proof_ratio"] = ratio(a["counts"]["miner_unique_complete_by_B"], b["counts"]["miner_unique_complete_by_B"])
        out["equal_B_eventually_accepted_ratio"] = ratio(a["counts"][yield_key], b["counts"][yield_key])
        out["actual_miner_accepted_rate_ratio"] = yield_rate_ratio(a["counts"][yield_key], a["phase_cpu_ns"]["miner"], b["counts"][yield_key], b["phase_cpu_ns"]["miner"])
        out["setup_plus_miner_accepted_rate_ratio"] = yield_rate_ratio(a["counts"][yield_key], a["setup_plus_miner_cpu_ns"], b["counts"][yield_key], b["setup_plus_miner_cpu_ns"])
    return out



def analyze(readback):
    require(readback.get("schema") == "pon-w1-fork-resource-derived-v1", "READBACK_SCHEMA")
    plan, raw = load_json(PLAN)
    require(readback["plan_sha256"] == hashlib.sha256(raw).hexdigest(), "REGISTERED_PLAN_HASH")
    for flag in ("external_identity_pins_checked", "posthoc_replay_provides_no_selection_feedback",
                 "all_retained_full_proof_records_independently_replayed", "one_total_miner_budget_across_epochs",
                 "finite_common_root_sibling_branches", "stdout_losslessly_compacted_after_measured_child"):
        require(readback[flag] is True, "REPLAY_REQUIRED:" + flag)
    for flag in ("hardware_attested", "universal_kappa_bound_established", "hardness_accepted",
                 "production_activation", "new_training_qualification", "native_execution_attested_by_reader",
                 "native_qualification_independently_reexecuted_by_python", "receiver_and_audit_feedback_to_miner",
                 "arbitrary_fork_forest", "unbounded_adaptive_strategy_or_reuse"):
        require(readback[flag] is False, "AUTHORITY_SCOPE:" + flag)
    require(readback["phase_order"] == list(PHASES), "PHASE_ORDER")
    jobs=readback["jobs"]
    require(len(jobs)==len(plan["jobs"])==42 and [r["job"] for r in jobs]==[r["name"] for r in plan["jobs"]], "REGISTERED_JOB_SET")
    metrics={};groups={field:defaultdict(dict) for field in ("arm","reuse","policy")};main=[];controls=[]
    for row,registered in zip(jobs,plan["jobs"]):
        require(row["binary"]==registered["binary"]==BINARY and same(row["options"],options_from_args(registered["args"])),"REGISTERED_JOB_OPTIONS")
        metric=miner_metrics(row);metrics[row["job"]]=metric
        if plan["cohorts"][row["job"]]=="control":
            controls.append(row["job"])
            continue
        main.append(row["job"])
        for field in groups:
            group=groups[field][key_without(row["options"],field)]
            require(row["options"][field]not in group,"DUPLICATE_COMPARISON_CELL");group[row["options"][field]]=row
    pairs={field:[] for field in groups};pairs["strassen_against_specialized"]=[]
    for field,reference in (("arm",REFERENCE),("reuse","lifetime"),("policy","round-robin")):
        for group in groups[field].values():
            if reference in group:
                for label,row in group.items():
                    if label!=reference:pairs[field].append(compare(row,group[reference],metrics,field))
    for group in groups["arm"].values():
        if "structure-strassen"in group and "structure-specialized"in group:
            pairs["strassen_against_specialized"].append(compare(group["structure-strassen"],group["structure-specialized"],metrics,"arm"))
    require(len(main)==36 and len(controls)==6 and {key:len(value) for key,value in pairs.items()}==dict(arm=20,reuse=4,policy=14,strassen_against_specialized=4),"REGISTERED_COMPARISON_COUNTS")
    for name in ("control-setup-zero","control-setup-tight"):
        require(metrics[name]["setup_complete"] is False and metrics[name]["counts"]["research_proof_records"]==0,"SETUP_CONTROL")
    require(metrics["control-miner-zero"]["setup_complete"] is True and metrics["control-miner-zero"]["counts"]["miner_unique_complete_by_B"]==0,"ZERO_MINER_CONTROL")
    for name in ("control-attempt-cap","control-cold-cap"):
        require(metrics[name]["miner_status"]=="safety-cap-censored" and metrics[name]["safety_cap_reached"] is True,"CAP_CONTROL")
    require(metrics["control-miner-tight"]["miner_status"]=="miner-cpu-budget-stopped","TIGHT_MINER_CONTROL")
    totals={name:sum(metrics[row["job"]]["counts"][name] for row in jobs) for name in metrics[jobs[0]["job"]]["counts"]}
    directions={}
    for dimension,comparisons in pairs.items():
        counts=Counter()
        for comparison in comparisons:
            if not comparison["comparable"]:counts["unpaired_or_censored"]+=1;continue
            left=comparison["left_metrics"]["counts"]["eventually_native_accepted_from_B"]
            right=comparison["right_metrics"]["counts"]["eventually_native_accepted_from_B"]
            counts["higher" if left>right else "lower" if left<right else "equal"]+=1
        directions[dimension]=dict(counts)
    return dict(schema="pon-w1-fork-resource-analysis-v1",source=readback["source"],plan_sha256=readback["plan_sha256"],
        jobs=[metrics[row["job"]] for row in jobs],counts=dict(registered_jobs=len(jobs),main_jobs=len(main),controls=len(controls),retained_records=totals,phase_cpu_ns={phase:sum(m["phase_cpu_ns"][phase] for m in metrics.values()) for phase in PHASES}),
        comparisons=pairs,comparison_directions=directions,main_jobs=main,control_jobs=controls,
        all_main_miner_budget_observations_complete=all(metrics[name]["complete_uncensored_miner_budget_observation"] for name in main),
        ordinary_receiver_feedback_to_miner=False,ratios_are_finite_descriptive_observations=True,
        sum_of_candidate_work_is_chain_growth=False,setup_plus_miner_rate_is_not_equal_total_budget_yield=True,
        setup_plus_miner_rate_numerator="new research wins available by B only; paid setup winners are reported separately",
        aggregate_count_scope="sum of per-job observations; counterfactual job identities are not globally deduplicated",
        known_bank_scope="finite disclosed paid common-root native sibling paths; no free or unbounded initial bank",
        adaptive_scope="only registered paid greedy mean-service policy; its selection divergence is retained and is not a matched stream",
        same_B_across_all_epochs=True,arbitrary_strategy_bound=False,unbounded_reuse_bound=False,
        fastest_known_global_algorithm_established=False,maximum_attacker_yield_established=False,
        universal_kappa_bound_established=False,hardness_accepted=False,production_activation=False,
        hardware_attested=False,new_training_qualification=False,energy_joules=None,network_transfer_measured=False)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readback", type=Path, required=True)
    parser.add_argument("--expected-readback-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.out.exists(), "OUTPUT_ALREADY_EXISTS")
        hx(args.expected_readback_sha256, 32, "EXTERNAL_READBACK_PIN")
        readback, raw = load_json(args.readback)
        require(hashlib.sha256(raw).hexdigest() == args.expected_readback_sha256, "READBACK_PIN_MISMATCH")
        result = analyze(readback)
        result["readback_sha256"] = args.expected_readback_sha256
        result["analysis_source_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        with args.out.open("x") as stream:
            json.dump(result, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
        print(json.dumps({"counts": result["counts"], "all_main_miner_budget_observations_complete":
                          result["all_main_miner_budget_observations_complete"], "hardness_accepted": False}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, OverflowError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
