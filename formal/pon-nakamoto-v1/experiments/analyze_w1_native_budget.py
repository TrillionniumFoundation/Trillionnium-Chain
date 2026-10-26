#!/usr/bin/env python3
"""Registered equal-budget native-admission analysis, not a hardness certificate.

Input must first pass the externally pinned full bundle reader. All native clock,
State and admission observations remain source-bound reports. Counterfactual jobs
and sibling admissions do not accumulate canonical chainwork.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
from read_w1_cost_research import require, uint64
from w1_parent_reuse_reader import options_from_args as parent_options
from w1_joint_challenge_reader import options_from_args as joint_options
from analyze_w1_adaptive_joint import (
    command_observation, exact_fraction, joint_metrics, load_json, parent_metrics,
    rate_ratio, stage_shares,
)

PLAN = Path(__file__).with_name("w1_native_budget_campaign_v1.json")
PARENT = "pon_w1_parent_reuse_research"
JOINT = "pon_w1_joint_research"
MODE = "budget-final-parent-v2"


def count_ratio(numerator, denominator):
    for value in (numerator, denominator):
        uint64(value, "COUNT_RATIO_OPERAND")
    return None if denominator == 0 else exact_fraction(numerator, denominator)


def within(record, field, budget):
    value = record.get(field)
    return value is not None and uint64(value["process_cpu_ns"], "COMPLETION_CPU") <= budget


def budget_metrics(row):
    require(row["schema"] == "pon-w1-parent-reuse-readback-v2", "V2_READBACK_SCHEMA")
    options, counts = row["options"], row["counts"]
    require(options["mode"] == MODE, "V2_MODE")
    budget = uint64(options["cpu_budget_ns"], "NOMINAL_BUDGET")
    strategy = uint64(row["strategy_cpu_ns"], "STRATEGY_CPU")
    posthoc = uint64(row["posthoc_process_cpu_ns"], "POSTHOC_CPU")
    attempts, acquisitions = row["attempts"], row["acquisitions"]
    require(type(attempts) is list and type(acquisitions) is list, "RECORD_LISTS")
    all_admitted, research_admitted, completed, final_admitted, final_completed = set(), set(), set(), set(), set()
    all_winners, research_winners, all_research = set(), set(), set()
    final_round = options["rounds"] - 1
    final_rows, prefix_rows = [], []
    for kind, records in (("research", attempts), ("auxiliary", acquisitions)):
        require([r["id"] for r in records] == list(range(len(records))), "SEQUENTIAL_RECORD_IDS")
        for record in records:
            identity = record["semantic_id"]
            require(type(identity) is str and len(identity) == 64, "SEMANTIC_ID")
            require(type(record["target_hit"]) is bool, "TARGET_BOOLEAN")
            require((record["admission_completed"] is not None) is record["target_hit"], "ADMISSION_TARGET_BINDING")
            if record["target_hit"]:
                all_winners.add(identity)
            if within(record, "admission_completed", budget):
                all_admitted.add(identity)
                if kind == "research":
                    research_admitted.add(identity)
            if kind == "research":
                require(0 <= record["round"] <= final_round, "RESEARCH_ROUND")
                all_research.add(identity)
                if record["target_hit"]:
                    research_winners.add(identity)
                if within(record, "completed", budget):
                    completed.add(identity)
                if record["round"] == final_round:
                    final_rows.append(record)
                    if within(record, "admission_completed", budget):
                        final_admitted.add(identity)
                    if within(record, "completed", budget):
                        final_completed.add(identity)
                else:
                    prefix_rows.append(record)
    original = sum(uint64(a["original_make_complete_attempts"], "ORIGINAL_ATTEMPTS", 1) for a in acquisitions)
    expected = dict(research_completed_proofs=len(attempts), acquisitions=len(acquisitions),
                    research_unique_complete_semantics=len(all_research), research_unique_winners=len(research_winners),
                    all_work_unique_winners=len(all_winners), all_work_unique_admitted_within_budget=len(all_admitted),
                    research_unique_admitted_within_budget=len(research_admitted),
                    original_make_completed_proofs=original, original_make_failed_target_proofs=original-len(acquisitions))
    for key, value in expected.items():
        require(counts[key] == value, "DERIVED_COUNT:" + key)
    replay = row["python_replayed"]
    require(replay["research_proofs"] == len(attempts) and replay["acquisition_winners"] == len(acquisitions) and
            replay["posthoc_reconstruction_records"] == original and
            row["retained_proof_records_replayed"] == replay["full_relation_records"] ==
            len(attempts) + len(acquisitions) + original, "FULL_REPLAY_COUNTS")
    envelope = row["budget_experiment"]
    cap = options["max_final_attempts"]
    require(envelope["mode"] == MODE and envelope["final_parent_attempt_cap"] == cap and
            envelope["planned_research_attempt_cap"] == final_round * options["attempts_per_parent"] + cap,
            "DECLARED_SAFETY_CAP")
    require(envelope["final_parent_research_attempts"] == len(final_rows) and
            envelope["prefix_research_attempts"] == len(prefix_rows) and len(final_rows) <= cap,
            "PHASE_COUNTS")
    require(envelope["final_parent_unique_complete_within_budget"] == len(final_completed) and
            envelope["final_parent_unique_admitted_within_budget"] == len(final_admitted), "FINAL_PHASE_CREDIT")
    require(envelope["prefix_unique_complete_within_budget"] == len(completed-final_completed) and
            envelope["prefix_unique_admitted_within_budget"] == len(research_admitted-final_admitted), "PREFIX_PHASE_CREDIT")
    reached = envelope["reached_final_parent"]
    require(type(reached) is bool and (reached or not final_rows), "FINAL_PARENT_REACHED")
    if reached:
        require(len(prefix_rows) == final_round * options["attempts_per_parent"] and
                all(a["parent"] == envelope["final_parent"] for a in final_rows), "FIXED_FINAL_PARENT")
    status = row["status"]
    exhausted = status in ("process-cpu-budget-stopped", "process-cpu-budget-stopped-before-context")
    censored = status == "safety-cap-censored"
    require(exhausted or censored, "V2_STOP_STATUS")
    if exhausted:
        require(strategy >= budget, "FALSE_BUDGET_EXHAUSTION")
    if censored:
        require(reached and len(final_rows) == cap, "FALSE_SAFETY_CAP")
    require(not row["controls_completed"], "V2_MUST_NOT_CLAIM_FINAL_REVOCATION")
    shares = stage_shares(row["charge_cpu_ns_by_stage"], strategy)
    require(shares["unattributed_cpu_ns"] == row["unattributed_strategy_cpu_ns"], "CHARGE_RESIDUAL")
    fulfilled = reached and exhausted and not censored and len(final_rows) < cap and budget > 0
    stats = row["final_stats"]
    return dict(job=row["job"], options=options, status=status, nominal_cpu_budget_ns=budget,
                strategy_cpu_ns=strategy, posthoc_process_cpu_ns=posthoc,
                budget_overshoot_cpu_ns=max(0, strategy-budget), safety_cap_censored=len(final_rows) == cap,
                stopped_on_safety_cap=censored, final_attempt_cap_reached=len(final_rows) == cap,
                complete_fixed_budget_observation=fulfilled,
                research_unique_complete_within_budget=len(completed),
                research_unique_admitted_within_budget=len(research_admitted),
                all_work_unique_admitted_within_budget=len(all_admitted),
                auxiliary_unique_admitted_within_budget=len(all_admitted-research_admitted),
                final_parent_unique_complete_within_budget=len(final_completed),
                final_parent_unique_admitted_within_budget=len(final_admitted),
                final_parent=envelope["final_parent"], budget_experiment=envelope, counts=counts,
                all_retained_full_proof_records=len(attempts)+len(acquisitions)+original,
                genuine_research_records=len(attempts), auxiliary_original_winning_records=len(acquisitions),
                posthoc_reconstructed_records=original, controls=row["controls"], controls_completed=False,
                final_native_height=None if stats is None else stats["height"],
                final_native_chainwork_hex=None if stats is None else stats["chainwork_hex"],
                final_native_state_scope="native-reported-not-independently-executed-by-Python",
                stages_over_strategy=shares, command=command_observation(row,strategy,posthoc),
                posthoc_reconstructions_add_credit=False, sibling_admissions_equal_chain_growth=False)


def key_without(options, removed):
    return json.dumps({k:v for k,v in options.items() if k != removed},sort_keys=True,separators=(",",":"))


def identity_prefix(left, right):
    keys=("id","task_index","parent","height","challenge","proof_sha256","semantic_id","block_id","target_hit")
    matched = 0
    for a,b in zip(left,right):
        if not all(a[key] == b[key] for key in keys):
            return False, matched
        matched += 1
    return True, matched


def comparison(left, right, metrics, dimension):
    require(key_without(left["options"],dimension) == key_without(right["options"],dimension), "PAIR_OPTIONS")
    a,b=metrics[left["job"]],metrics[right["job"]]
    research,overlap=identity_prefix(left["attempts"],right["attempts"])
    auxiliary,aux_overlap=identity_prefix(left["acquisitions"],right["acquisitions"])
    same_aux_len=len(left["acquisitions"]) == len(right["acquisitions"])
    same_final=a["final_parent"] is not None and a["final_parent"] == b["final_parent"]
    same_history=research and auxiliary and same_aux_len and same_final
    complete=a["complete_fixed_budget_observation"] and b["complete_fixed_budget_observation"]
    comparable=same_history and complete
    ratio=lambda name:count_ratio(a[name],b[name]) if comparable else None
    return dict(dimension=dimension,left_job=left["job"],right_job=right["job"],
                left_label=left["options"][dimension],right_label=right["options"][dimension],
                options_except_comparison={k:v for k,v in left["options"].items() if k != dimension},
                same_paid_acquisition_and_overlapping_research_history=same_history,
                matched_research_prefix_records=overlap, matched_auxiliary_records=aux_overlap,
                both_complete_fixed_budget_observations=complete,comparable=comparable,
                unequal_record_counts_are_retained=len(left["attempts"]) != len(right["attempts"]),
                equal_budget_research_admitted_ratio=ratio("research_unique_admitted_within_budget"),
                equal_budget_all_work_admitted_ratio=ratio("all_work_unique_admitted_within_budget"),
                equal_budget_final_parent_admitted_ratio=ratio("final_parent_unique_admitted_within_budget"),
                equal_budget_research_complete_opportunity_ratio=ratio("research_unique_complete_within_budget"),
                actual_strategy_cpu_admitted_rate_ratio=rate_ratio(
                    a["research_unique_admitted_within_budget"],a["strategy_cpu_ns"],
                    b["research_unique_admitted_within_budget"],b["strategy_cpu_ns"]) if comparable else None,
                reason=None if comparable else "censored-or-incomplete-budget-observation-or-divergent-paid-history",
                left=a,right=b,universal_kappa_bound=False,canonical_chain_growth_ratio=False)


def analyze(readback):
    require(readback.get("schema") == "pon-w1-next-research-derived-v1", "READBACK_SCHEMA")
    plan,raw=load_json(PLAN)
    require(readback["plan_sha256"] == hashlib.sha256(raw).hexdigest(),"REGISTERED_PLAN_HASH")
    jobs=readback["jobs"]
    require(len(jobs)==len(plan["jobs"])==38 and [r["job"] for r in jobs] ==
            [r["name"] for r in plan["jobs"]],"EXACT_REGISTERED_JOB_SET_AND_ORDER")
    for key in ("external_identity_pins_checked","posthoc_replay_provides_no_selection_feedback",
                "all_retained_full_proof_records_independently_replayed"):
        require(readback[key] is True,"READBACK_VERIFICATION:"+key)
    for key in ("hardware_attested","universal_kappa_bound_established","hardness_accepted",
                "production_activation","new_training_qualification","native_execution_attested_by_reader",
                "native_qualification_independently_reexecuted_by_python"):
        require(readback[key] is False,"READBACK_AUTHORITY:"+key)
    metrics={}; arms=defaultdict(dict); caches=defaultdict(dict); main=[]; controls=[]
    for row,registered in zip(jobs,plan["jobs"]):
        require(row["binary"] == registered["binary"],"REGISTERED_BINARY")
        option_parser=joint_options if row["binary"]==JOINT else parent_options
        require(row["options"] == option_parser(registered["args"]),"REGISTERED_EXACT_OPTIONS")
        if row["binary"]==JOINT:
            result=joint_metrics(row)
        elif row["options"].get("mode")==MODE:
            result=budget_metrics(row)
        else:
            result=parent_metrics(row)
        metrics[row["job"]]=result
        if row["job"].startswith("budget."):
            main.append(row)
            group=arms[key_without(row["options"],"arm")]
            require(row["options"]["arm"] not in group,"DUPLICATE_ARM")
            group[row["options"]["arm"]]=row
            if row["job"].startswith("budget.main."):
                group=caches[key_without(row["options"],"cache")]
                require(row["options"]["cache"] not in group,"DUPLICATE_CACHE")
                group[row["options"]["cache"]]=row
        else:
            controls.append(result)
    require(len(main)==30 and len(arms)==15 and len(caches)==12 and len(controls)==8,"REGISTERED_GROUP_COUNTS")
    producer_pairs=[];cache_pairs=[]
    for group in arms.values():
        require(set(group)=={"structure-specialized","integer-paired-general"},"PRODUCER_SET")
        producer_pairs.append(comparison(group["structure-specialized"],group["integer-paired-general"],metrics,"arm"))
    for group in caches.values():
        require(set(group)=={"hot","cold"},"CACHE_SET")
        cache_pairs.append(comparison(group["hot"],group["cold"],metrics,"cache"))
    parents=[r for r in jobs if r["binary"]==PARENT]; joints=[r for r in jobs if r["binary"]==JOINT]
    genuine=sum(len(r["attempts"]) for r in jobs)
    auxiliary=sum(len(r["acquisitions"]) for r in parents)
    reconstructed=sum(r["python_replayed"]["posthoc_reconstruction_records"] for r in parents)
    all_replayed=sum(r["retained_proof_records_replayed"] for r in parents)+sum(r["all_completed_proofs_python_replayed"] for r in joints)
    require(all_replayed==genuine+auxiliary+reconstructed,"ALL_REPLAY_ACCOUNTING")
    return dict(schema="pon-w1-native-budget-analysis-v1",source=readback["source"],
                raw_manifest_sha256=readback["raw_manifest_sha256"],plan_sha256=readback["plan_sha256"],
                reader_sha256=readback["reader_sha256"],binaries=readback["binaries"],
                counts=dict(jobs=38,parent_jobs=len(parents),joint_controls=len(joints),main_budget_jobs=30,
                            producer_pairs=15,cache_pairs=12,controls=8,
                            complete_main_fixed_budget_observations=sum(metrics[r["job"]]["complete_fixed_budget_observation"] for r in main),
                            comparable_producer_pairs=sum(r["comparable"] for r in producer_pairs),
                            comparable_cache_pairs=sum(r["comparable"] for r in cache_pairs),
                            genuine_research_proof_records=genuine,auxiliary_original_winning_proof_records=auxiliary,
                            posthoc_reconstructed_proof_records=reconstructed,all_full_proof_records_independently_replayed=all_replayed),
                all_main_fixed_budget_obligations_completed=all(metrics[r["job"]]["complete_fixed_budget_observation"] for r in main),
                producer_pairs=producer_pairs,cache_pairs=cache_pairs,controls=controls,
                all_jobs_in_registered_order=[metrics[r["job"]] for r in jobs],
                maximum_single_command_rss_kib=max(m["command"]["whole_command_maximum_rss_kib"] for m in metrics.values()),
                hardware=readback["hardware"],energy_joules=None,network_transfer_measured=False,
                hardware_attested=False,hardness_accepted=False,production_activation=False,
                universal_kappa_bound_established=False,new_training_qualification=False,
                original_internal_misses_retained_when_generated=False,
                limitations=["Equal-B admission ratios describe finite controlled policies on one nonexclusive CPU.",
                             "All policies pay the same two-task acquisition; cheaper alternative acquisition policies remain untested.",
                             "Final-parent siblings are admitted locally and do not add canonical chain growth or network TPS.",
                             "Structure-specialized is a fixed known algorithm mapping, not a proven fastest producer.",
                             "Only identity-matched prefixes under uncensored budget exhaustion permit paired ratios.",
                             "Overshoot and native observers stay charged; posthoc reconstruction adds no credited tickets.",
                             "The changed source and v2 namespace do not reinterpret the previous 32-attempt experiment."])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readback",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    try:
        require(not args.out.exists(),"OUTPUT_ALREADY_EXISTS")
        readback,raw=load_json(args.readback)
        result=analyze(readback)
        result["readback_sha256"]=hashlib.sha256(raw).hexdigest()
        result["analysis_source_sha256"]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        with args.out.open("x") as stream:
            json.dump(result,stream,indent=2,sort_keys=True,allow_nan=False);stream.write("\n")
        print(json.dumps({"counts":result["counts"],"all_main_fixed_budget_obligations_completed":result["all_main_fixed_budget_obligations_completed"],"hardness_accepted":False}))
        return 0
    except (OSError,ValueError,KeyError,TypeError,OverflowError) as error:
        print(str(error),file=sys.stderr);return 2


if __name__=="__main__":
    raise SystemExit(main())
