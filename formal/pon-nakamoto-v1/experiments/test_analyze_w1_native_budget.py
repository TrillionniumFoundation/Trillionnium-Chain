#!/usr/bin/env python3
"""Synthetic analysis controls; no fabricated native work or measured CPU claims."""
from __future__ import annotations
import copy
import hashlib
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import analyze_w1_native_budget as analysis


def h(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


def fixture():
    options=dict(rounds=2,attempts_per_parent=1,seed=7,cache="hot",strategy="maintenance-only",
                 screen_width=4,arm="integer-paired-general",cpu_budget_ns=100,
                 mode=analysis.MODE,max_final_attempts=8)
    attempts=[]
    for index,(round_,ordinal,cpu,admitted) in enumerate(((0,0,20,25),(1,0,45,None),(1,1,90,99),(1,2,101,104))):
        attempts.append(dict(id=index,task_index=0,parent=h(round_),height=round_+2,round=round_,attempt=ordinal,
                             challenge=h((index,"challenge")),proof_sha256=h((index,"proof")),
                             semantic_id=h(index),block_id=h((index,"block")),target_hit=admitted is not None,
                             completed=dict(process_cpu_ns=cpu),
                             admission_completed=None if admitted is None else dict(process_cpu_ns=admitted)))
    aux=dict(id=0,task_index=0,parent=h("genesis"),height=1,challenge=h("auxch"),proof_sha256=h("auxproof"),
             semantic_id=h("aux"),block_id=h("auxblock"),target_hit=True,original_make_complete_attempts=2,
             admission_completed=dict(process_cpu_ns=10),original_search_completed=dict(process_cpu_ns=5))
    row=dict(job="synthetic",schema="pon-w1-parent-reuse-readback-v2",options=options,
             attempts=attempts,acquisitions=[aux],status="process-cpu-budget-stopped",strategy_cpu_ns=105,
             posthoc_process_cpu_ns=7,controls=[],controls_completed=False,
             charge_cpu_ns_by_stage={"context-open-and-task-source":11,"research-complete-proof":30},
             unattributed_strategy_cpu_ns=64,final_stats=dict(height=3,chainwork_hex="06"),
             whole_waited_child_resources=dict(user_cpu_ns=112,system_cpu_ns=0),
             whole_command_usage=dict(maximum_resident_set_kib=123,user_seconds_decimal="0.00",system_seconds_decimal="0.00"))
    refresh(row)
    return row


def refresh(row):
    attempts,aux=row["attempts"],row["acquisitions"]
    budget=row["options"]["cpu_budget_ns"]
    inside=lambda r,f:r.get(f) is not None and r[f]["process_cpu_ns"]<=budget
    final=[r for r in attempts if r["round"]==row["options"]["rounds"]-1]
    prefix=[r for r in attempts if r not in final]
    row["counts"]=dict(research_completed_proofs=len(attempts),acquisitions=len(aux),
                       research_unique_complete_semantics=len(attempts),research_unique_winners=sum(a["target_hit"] for a in attempts),
                       all_work_unique_winners=sum(a["target_hit"] for a in attempts+aux),
                       all_work_unique_admitted_within_budget=sum(inside(a,"admission_completed") for a in attempts+aux),
                       research_unique_admitted_within_budget=sum(inside(a,"admission_completed") for a in attempts),
                       original_make_completed_proofs=2,original_make_failed_target_proofs=1)
    row["python_replayed"]=dict(research_proofs=len(attempts),acquisition_winners=1,
                                posthoc_reconstruction_records=2,full_relation_records=len(attempts)+3)
    row["retained_proof_records_replayed"]=len(attempts)+3
    cap=row["options"]["max_final_attempts"]
    row["budget_experiment"]=dict(mode=analysis.MODE,final_parent_attempt_cap=cap,planned_research_attempt_cap=cap+1,
                                  reached_final_parent=True,final_parent=h(1),prefix_research_attempts=len(prefix),
                                  final_parent_research_attempts=len(final),
                                  final_parent_unique_complete_within_budget=sum(inside(a,"completed") for a in final),
                                  final_parent_unique_admitted_within_budget=sum(inside(a,"admission_completed") for a in final),
                                  prefix_unique_complete_within_budget=sum(inside(a,"completed") for a in prefix),
                                  prefix_unique_admitted_within_budget=sum(inside(a,"admission_completed") for a in prefix))


class BudgetAnalysisTests(unittest.TestCase):
    def test_admission_fence_does_not_credit_late_winner_or_posthoc(self):
        row=fixture();result=analysis.budget_metrics(row)
        self.assertEqual(result["research_unique_complete_within_budget"],3)
        self.assertEqual(result["research_unique_admitted_within_budget"],2)
        self.assertEqual(result["all_work_unique_admitted_within_budget"],3)
        self.assertEqual(result["final_parent_unique_admitted_within_budget"],1)
        self.assertEqual(result["posthoc_reconstructed_records"],2)
        self.assertEqual(result["budget_overshoot_cpu_ns"],5)
        self.assertEqual(result["final_native_height"],3)
        self.assertFalse(result["sibling_admissions_equal_chain_growth"])
        self.assertTrue(result["complete_fixed_budget_observation"])

    def test_claimed_budget_credit_must_reconcile(self):
        row=fixture();row["counts"]["research_unique_admitted_within_budget"]+=1
        with self.assertRaisesRegex(ValueError,"DERIVED_COUNT"):
            analysis.budget_metrics(row)

    def test_cap_even_with_overrun_is_not_uncensored_budget_result(self):
        row=fixture();row["options"]["max_final_attempts"]=3;row["status"]="safety-cap-censored";refresh(row)
        result=analysis.budget_metrics(row)
        self.assertTrue(result["safety_cap_censored"])
        self.assertFalse(result["complete_fixed_budget_observation"])
        row["status"]="process-cpu-budget-stopped"
        result=analysis.budget_metrics(row)
        self.assertFalse(result["complete_fixed_budget_observation"])
        self.assertTrue(result["safety_cap_censored"])
        self.assertFalse(result["stopped_on_safety_cap"])

    def test_false_budget_stop_and_missing_replay_rejected(self):
        for alter,pattern in ((lambda r:r.update(strategy_cpu_ns=99),"FALSE_BUDGET_EXHAUSTION"),
                              (lambda r:r["python_replayed"].update(full_relation_records=6),"FULL_REPLAY_COUNTS"),
                              (lambda r:r.update(controls_completed=True),"V2_MUST_NOT")):
            row=fixture();alter(row)
            with self.subTest(pattern=pattern),self.assertRaisesRegex(ValueError,pattern):
                analysis.budget_metrics(row)

    def test_unequal_matching_prefixes_permit_exact_count_not_cpu_ratio(self):
        left,right=fixture(),fixture()
        left["job"]="special";left["options"]["arm"]="structure-specialized"
        right["job"]="integer";right["attempts"]=right["attempts"][:2];refresh(right)
        metrics={r["job"]:analysis.budget_metrics(r) for r in (left,right)}
        pair=analysis.comparison(left,right,metrics,"arm")
        self.assertTrue(pair["comparable"])
        self.assertTrue(pair["unequal_record_counts_are_retained"])
        self.assertEqual(pair["equal_budget_research_admitted_ratio"]["reduced_numerator"],2)
        self.assertEqual(pair["equal_budget_research_admitted_ratio"]["reduced_denominator"],1)
        self.assertEqual(pair["matched_research_prefix_records"],2)

    def test_divergent_parent_or_task_history_suppresses_pair_claim(self):
        left,right=fixture(),fixture();left["job"]="hot";right["job"]="cold";right["options"]["cache"]="cold"
        metrics={r["job"]:analysis.budget_metrics(r) for r in (left,right)}
        right["attempts"][0]["challenge"]=h("different")
        result=analysis.comparison(left,right,metrics,"cache")
        self.assertFalse(result["comparable"])
        self.assertEqual(result["matched_research_prefix_records"],0)
        self.assertIsNone(result["equal_budget_all_work_admitted_ratio"])
        self.assertIsNone(result["actual_strategy_cpu_admitted_rate_ratio"])

    def test_zero_baseline_never_invents_finite_or_infinite_ratio(self):
        self.assertIsNone(analysis.count_ratio(1,0))
        self.assertIsNone(analysis.count_ratio(0,0))
        self.assertEqual(analysis.count_ratio(0,2)["decimal"],0)
        with self.assertRaises(ValueError):analysis.count_ratio(-1,2)

    def test_registered_plan_has_predeclared_budget_grid_and_controls(self):
        from run_w1_next_research import validate_plan
        plan,_=analysis.load_json(analysis.PLAN)
        jobs=validate_plan(plan)
        self.assertEqual(len(jobs),38)
        self.assertEqual(sum(j["name"].startswith("budget.main.") for j in jobs),24)
        self.assertEqual(sum(j["name"].startswith("budget.short.") for j in jobs),6)
        self.assertEqual(sum(j["name"].startswith("control.") for j in jobs),8)
        main=[analysis.parent_options(j["args"]) for j in jobs if j["name"].startswith("budget.")]
        self.assertTrue(all(p["max_final_attempts"]==4096 for p in main))
        self.assertEqual({p["cpu_budget_ns"] for p in main},{500_000_000,1_000_000_000})
        order={}
        for p in main:
            if p["seed"] in (3101,3102):
                order.setdefault((p["strategy"],p["cache"],p["seed"]),[]).append(p["arm"])
        for strategy in ("maintenance-only","zero-only","paid-task-screen"):
            for cache in ("hot","cold"):
                self.assertEqual(order[strategy,cache,3101],order[strategy,cache,3102][::-1])


if __name__=="__main__":unittest.main()
