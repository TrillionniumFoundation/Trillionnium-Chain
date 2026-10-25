"""Control-logic fixtures, never substitutes for the separately pinned native run."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import task_family_selection as research


class Clock:
    def __init__(self, initial=0):
        self.cpu = initial

    def now(self):
        return self.cpu


class ControlledJobs:
    def __init__(self, clock, costs=None, evaluation_cost=50):
        self.clock = clock
        self.costs = costs or [10] * len(research.GRID)
        self.evaluation_cost = evaluation_cost
        self.calls = []

    def __call__(self, phase, family, arm, seed, attempts):
        self.calls.append((phase, family, arm, seed, attempts))
        self.clock.cpu += self.costs[research.GRID.index((family, arm))] if phase == "training" else self.evaluation_cost
        # Equal task/challenge across producer arms is the same semantic work.
        tickets = [{"semantic_id":f"{phase}/{family}/{ordinal}","task":family,
                    "challenge":f"{seed}/{ordinal}","ticket":str(ordinal),"target_hit":True}
                   for ordinal in range(attempts)]
        return {"complete_proofs":attempts,"tickets":tickets}


class TaskFamilySelectionTests(unittest.TestCase):
    def test_registered_nine_call_grid_includes_legal_structural_competitors(self):
        self.assertEqual(research.GRID, (
            ("full-rank-field","prepared-generic"),
            ("full-rank-field","paired-product"),
            ("full-rank-field","integer-paired-general"),
            ("zero","prepared-generic"),
            ("zero","blocked-zero-integer-paired"),
            ("zero","integer-paired-general"),
            ("continuity-maintenance-v1","prepared-generic"),
            ("continuity-maintenance-v1","maintenance-prefix"),
            ("continuity-maintenance-v1","maintenance-limb"),
        ))

    def run_case(self, budget=10000, costs=None, evaluation_cost=50, initial=0):
        clock = Clock(initial)
        jobs = ControlledJobs(clock,costs,evaluation_cost)
        events = []
        result = research.execute_strategy(jobs,clock.now,budget,events.append)
        return result,jobs,clock,events

    def test_all_training_precedes_selection_and_heldout_dispatch(self):
        result,jobs,clock,events = self.run_case()
        self.assertEqual(len(jobs.calls),len(research.GRID)+1)
        self.assertTrue(all(call[0] == "training" for call in jobs.calls[:-1]))
        self.assertEqual(jobs.calls[-1][0],"evaluation")
        self.assertTrue(all(call[3] == research.TRAINING_SEED for call in jobs.calls[:-1]))
        self.assertEqual(jobs.calls[-1][3],research.EVALUATION_SEED)
        self.assertNotEqual(research.TRAINING_SEED,research.EVALUATION_SEED)
        self.assertEqual(events[len(research.GRID)]["kind"],"selection")
        self.assertEqual(result["status"],"evaluation-complete")
        self.assertEqual(clock.cpu,140)

    def test_full_measured_cost_selects_a_family_and_arm_not_first_success(self):
        costs = [20] * len(research.GRID)
        costs[4] = 5
        result,jobs,_,_ = self.run_case(costs=costs)
        self.assertEqual((result["selected"]["family"],result["selected"]["arm"]),research.GRID[4])
        self.assertEqual(jobs.calls[-1][1:3],research.GRID[4])
        self.assertEqual(sum(row["full_call_cpu_ns"] for row in result["records"]),215)

    def test_hindsight_target_hits_do_not_enter_the_selector_and_ties_are_fixed(self):
        rows = [{"family":family,"arm":arm,"full_call_cpu_ns":10,
                 "complete_proofs":research.TRAINING_ATTEMPTS,"target_hits":100000-index}
                for index,(family,arm) in enumerate(research.GRID)]
        self.assertEqual(research.choose(rows),0)
        for index,row in enumerate(rows):
            row["target_hits"] = index * 100000
            row["tickets"] = ["arbitrary-observed-luck"] * index
        self.assertEqual(research.choose(rows),0)

    def test_training_duplicate_tickets_across_algorithms_are_counted_once(self):
        result,_,_,_ = self.run_case()
        expected = len(research.FAMILIES)*research.TRAINING_ATTEMPTS + research.EVALUATION_ATTEMPTS
        self.assertEqual(len(result["distinct_tickets"]),expected)
        self.assertEqual(result["distinct_target_hits"],expected)
        self.assertEqual(result["budget_distinct_target_hits"],expected)

    def test_startup_cpu_and_zero_budget_cannot_start_free_children(self):
        for budget,initial in ((0,0),(10,10),(10,11)):
            with self.subTest(budget=budget,initial=initial):
                result,jobs,_,_ = self.run_case(budget=budget,initial=initial)
                self.assertEqual(jobs.calls,[])
                self.assertIsNone(result["selected"])
                self.assertFalse(result["heldout_executed"])
                self.assertEqual(result["budget_distinct_target_hits"],0)

    def test_partial_training_is_retained_without_hindsight_selection(self):
        with patch.object(research,"choose",side_effect=AssertionError("must not select partial grid")):
            result,jobs,clock,_ = self.run_case(budget=15)
        self.assertEqual(len(jobs.calls),2)
        self.assertEqual(clock.cpu,20)
        self.assertEqual(result["status"],"budget-during-training")
        self.assertIsNone(result["selected"])
        self.assertFalse(result["training_grid_complete"])
        self.assertFalse(result["records"][-1]["within_cpu_budget"])

    def test_overrun_child_keeps_all_cost_and_outputs_but_receives_no_budget_credit(self):
        result,jobs,clock,_ = self.run_case(budget=120,evaluation_cost=50)
        self.assertEqual(clock.cpu,140)
        self.assertEqual(result["status"],"evaluation-overrun")
        self.assertEqual(len(jobs.calls),10)
        self.assertEqual(result["records"][-1]["full_call_cpu_ns"],50)
        self.assertFalse(result["records"][-1]["within_cpu_budget"])
        self.assertEqual(result["budget_distinct_target_hits"],12)
        self.assertEqual(result["distinct_target_hits"],76)

    def test_child_failure_never_retries_or_refunds_consumed_cpu(self):
        clock = Clock()
        calls = []
        def failure(*args):
            calls.append(args)
            clock.cpu += 13
            raise ValueError("CHILD_EXECUTION_FAILED")
        with self.assertRaisesRegex(ValueError,"CHILD_EXECUTION_FAILED"):
            research.execute_strategy(failure,clock.now,100,lambda _:None)
        self.assertEqual(len(calls),1)
        self.assertEqual(clock.cpu,13)

    def test_reversed_cpu_clock_and_incomplete_proof_batch_fail_closed(self):
        for reverse in (True,False):
            clock = Clock(5)
            def invalid(*args):
                clock.cpu = 4 if reverse else 6
                return {"complete_proofs":0,"tickets":[]}
            with self.subTest(reverse=reverse),self.assertRaisesRegex(ValueError,"CPU_CLOCK_REVERSED|CHILD_PROOF_COUNT"):
                research.execute_strategy(invalid,clock.now,100,lambda _:None)

    def test_native_command_fixes_scope_target_material_family_and_heldout_seed(self):
        family,arm = research.GRID[0]
        arguments = research.native_args(family,arm,research.EVALUATION_SEED,research.EVALUATION_ATTEMPTS)
        pairs = dict(zip(arguments[::2],arguments[1::2]))
        self.assertEqual(pairs["--scope"],"relation")
        self.assertEqual(pairs["--mode"],"hot")
        self.assertEqual(pairs["--target"],research.TARGET)
        self.assertEqual(pairs["--seed"],str(research.EVALUATION_SEED))
        self.assertNotIn("--cpu-budget-ns",pairs)

    def test_missing_end_truncated_raw_and_duplicate_json_keys_are_not_valid_work(self):
        family,arm = research.GRID[0]
        for raw in (b"",b"{}",b"{}\n",b'{"kind":"campaign","kind":"end"}\n'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                research.basic_review(raw,family,arm,research.TRAINING_SEED,research.TRAINING_ATTEMPTS)
        with self.assertRaises(ValueError):
            research.decode('{"cpu":NaN}')


if __name__ == "__main__":
    unittest.main(verbosity=2)
