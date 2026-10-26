#!/usr/bin/env python3
"""Synthetic bookkeeping controls, never native or physical execution evidence."""
from __future__ import annotations
import copy
import hashlib
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent))
import analyze_w1_miner_resource as analysis
from contract_wire import SCHEMA, header_encode


def digest(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


def header(index):
    result = {f["name"]: (bytes.fromhex(digest(f["name"])) if f["type"] == "hash32" else 1)
              for f in SCHEMA["header"]}
    result.update(parent=bytes.fromhex(digest("parent")), height=1, nonce=index,
                  target=((1 << 255)-1).to_bytes(32, "big"))
    return header_encode(result).hex()


def fixture():
    options = dict(setup_budget_ns=100, miner_budget_ns=100, parents=1, max_attempts=8,
                   acquisition="selective", policy="maintenance-only", parent_policy="newest",
                   screen_width=4, arm="integer-paired-general", cache="hot", seed=7)
    records = []
    for index, (cpu, hit) in enumerate(((20, False), (40, True), (90, True), (101, True))):
        records.append(dict(attempt_id=index, task_index=0, template_index=0, bank=0,
                            semantic_id=digest(index), parent=digest("parent"), height=1,
                            header_hex=header(index), challenge=digest(("challenge", index)),
                            proof_sha256=digest(("proof", index)), target_hit=hit,
                            available=dict(process_cpu_ns=10+cpu, wall_ns=20+cpu),
                            miner_elapsed_cpu_ns=cpu, within_miner_budget=cpu<=100,
                            native_accepted=hit, native_admission_completed=dict(process_cpu_ns=200+index),
                            native_admission_cpu_ns=5, producer_cpu_ns=8))
    row = dict(schema="pon-w1-miner-budget-readback-v1", status="verified", job="fixture", options=options,
               setup_complete=True, miner_status="miner-cpu-budget-stopped",
               phase_cpu_ns=dict(setup=10, miner=110, receiver=300, audit=400),
               total_process_cpu_ns=820, total_wall_ns=900, attempts=records,
               acquisitions=[dict(source_id=0, semantic_id=digest("known"), original_complete_attempts=2,
                                  fee_units=0, header_hex=header(99), role="bank-template")],
               templates=[dict(template_index=0, parent=digest("parent"), header_hex=header(99))],
               setup=dict(complete=True, original_search_complete_attempts=2, original_acquisitions=1,
                          known_original_winning_semantics=1, transaction_fee_units=0),
               miner={}, receiver=dict(active_chain_growth_from_research=0, native_stats={"height":0}),
               audit={}, charged_stage_cpu_ns={"setup:context-and-task-source":4, "miner:complete-proof-and-ticket":32},
               unattributed_phase_cpu_ns=dict(setup=6, miner=78, receiver=300, audit=400),
               whole_command_usage={"maximum_resident_set_kib":123},
               cpu_observer_reconciliation={"signed_residual_cpu_ns":1})
    refresh(row)
    return row


def refresh(row):
    records, acq = row["attempts"], row["acquisitions"]
    for a in records:
        a["within_miner_budget"] = a["miner_elapsed_cpu_ns"] <= row["options"]["miner_budget_ns"]
    inside = [a for a in records if a["within_miner_budget"]]
    hits = sum(a["target_hit"] for a in inside)
    original = sum(a["original_complete_attempts"] for a in acq)
    row["counts"] = dict(
        research_proof_records=len(records), original_winner_records=len(acq),
        original_reconstruction_records=original, all_full_proof_records=len(records)+len(acq)+original,
        research_target_hits=sum(a["target_hit"] for a in records),
        research_late_proofs=sum(not a["within_miner_budget"] for a in records),
        research_late_target_hits=sum(a["target_hit"] and not a["within_miner_budget"] for a in records),
        miner_unique_complete_by_B=len(inside), miner_unique_target_hits_by_B=hits,
        eventually_native_accepted_from_B=hits)
    row["retained_proof_records_replayed"] = row["counts"]["all_full_proof_records"]
    row["miner"] = dict(status=row["miner_status"], safety_cap_reached=len(records)==row["options"]["max_attempts"],
                        miner_unique_complete_by_B=len(inside), miner_unique_target_hits_by_B=hits)
    row["receiver"]["eventually_native_accepted_from_B"] = hits
    row["audit"] = dict(research_full_native_audits=len(records), original_reconstruction_records=original,
                        original_winner_repetitions=len(acq), new_work_credit=0)


class ResourceAnalysisTests(unittest.TestCase):
    def test_full_bytes_availability_and_later_admission_are_distinct(self):
        result = analysis.miner_metrics(fixture())
        self.assertEqual(result["counts"]["miner_unique_complete_by_B"], 3)
        self.assertEqual(result["counts"]["eventually_native_accepted_from_B"], 2)
        self.assertEqual(result["counts"]["research_late_target_hits"], 1)
        self.assertEqual(result["candidate_chainwork_from_B"], 4)
        self.assertEqual(result["canonical_chainwork_added_by_research"], 0)
        self.assertEqual(result["setup_plus_miner_cpu_ns"], 120)
        self.assertEqual(result["miner_overshoot_cpu_ns"], 10)
        self.assertTrue(result["complete_uncensored_miner_budget_observation"])
        self.assertFalse(result["minimum_attacker_cost_established"])

    def test_late_admission_timestamp_does_not_rewrite_producer_fence(self):
        row = fixture()
        for a in row["attempts"]:
            a["native_admission_completed"]["process_cpu_ns"] = 10**6
        self.assertEqual(analysis.miner_metrics(row)["counts"]["eventually_native_accepted_from_B"], 2)
        row["attempts"][-1]["within_miner_budget"] = True
        with self.assertRaisesRegex(ValueError, "AVAILABILITY_FENCE"):
            analysis.miner_metrics(row)

    def test_no_credit_for_duplicate_or_prepaid_semantics(self):
        row = fixture()
        row["attempts"][1]["semantic_id"] = row["attempts"][0]["semantic_id"]
        with self.assertRaisesRegex(ValueError, "DUPLICATE_RESEARCH_IDENTITY"):
            analysis.miner_metrics(row)
        row = fixture()
        row["attempts"][0]["semantic_id"] = row["acquisitions"][0]["semantic_id"]
        with self.assertRaisesRegex(ValueError, "PREPAID_CREDIT_REUSE"):
            analysis.miner_metrics(row)

    def test_cap_even_with_budget_overrun_is_censored(self):
        row = fixture()
        row["options"]["max_attempts"] = 4
        refresh(row)
        result = analysis.miner_metrics(row)
        self.assertTrue(result["safety_cap_reached"])
        self.assertFalse(result["complete_uncensored_miner_budget_observation"])

    def test_phase_budget_and_replay_corruption_are_rejected(self):
        cases = (
            (lambda r:r.update(total_process_cpu_ns=821), "PHASE_SUM"),
            (lambda r:r["options"].update(setup_budget_ns=9), "SETUP_OVER_BUDGET"),
            (lambda r:r["counts"].update(original_winner_records=True), "FULL_COUNT"),
            (lambda r:r["receiver"].update(active_chain_growth_from_research=1), "RECEIVER_SUMMARY"),
            (lambda r:r["unattributed_phase_cpu_ns"].update(miner=79), "UNATTRIBUTED"),
            (lambda r:r["counts"].update(eventually_native_accepted_from_B=3), "FULL_COUNT"))
        for alter, error in cases:
            row = fixture()
            alter(row)
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                analysis.miner_metrics(row)

    def test_matching_unequal_prefixes_give_count_ratios(self):
        left, right = fixture(), fixture()
        left["job"] = "special"
        left["options"]["arm"] = "structure-paired"
        right["job"] = "reference"
        right["attempts"] = right["attempts"][:2]
        refresh(right)
        metrics = {r["job"]:analysis.miner_metrics(r) for r in (left, right)}
        comparison = analysis.compare(left, right, metrics, "arm")
        self.assertTrue(comparison["comparable"])
        self.assertTrue(comparison["unequal_record_counts_retained"])
        self.assertEqual(comparison["equal_B_eventually_accepted_ratio"]["decimal"], 2.0)
        self.assertEqual(comparison["matched_prefix_records"], 2)

    def test_changed_paid_history_or_bank_suppresses_pair(self):
        for field in ("acquisitions", "templates", "attempts"):
            left, right = fixture(), fixture()
            left["job"], right["job"] = "shared", "selective"
            left["options"]["acquisition"] = "shared"
            if field == "acquisitions":
                left[field][0]["fee_units"] = 1
            else:
                left[field][0]["parent"] = digest("other")
                if field == "attempts":
                    # Only comparison identities are under test here; both
                    # original full readbacks have already been independently read.
                    pass
            metrics = {r["job"]:analysis.miner_metrics(fixture()) for r in (left, right)}
            result = analysis.compare(left, right, metrics, "acquisition")
            self.assertFalse(result["comparable"])
            self.assertIsNone(result["equal_B_eventually_accepted_ratio"])
            self.assertIsNone(result["setup_plus_miner_accepted_rate_ratio"])

    def test_zero_denominator_is_not_infinite_advantage(self):
        self.assertIsNone(analysis.ratio(1, 0))
        self.assertIsNone(analysis.ratio(0, 0))
        self.assertEqual(analysis.ratio(0, 2)["decimal"], 0)
        self.assertIsNone(analysis.yield_rate_ratio(1, 10, 0, 20))
        self.assertEqual(analysis.yield_rate_ratio(0, 10, 1, 20)["decimal"], 0)

    def test_preregistered_comparisons_are_fixed_before_results(self):
        plan, _ = analysis.load_json(analysis.PLAN)
        groups = {field:{} for field in ("arm", "cache", "acquisition")}
        for row in plan["jobs"]:
            if row["name"].startswith("control."):
                continue
            options = analysis.options_from_args(row["args"])
            for field in groups:
                groups[field].setdefault(analysis.key_without(options, field), set()).add(options[field])
        counts = {field:sum(len(labels)-1 for labels in cells.values() if ref in labels)
                  for field, ref in (("arm",analysis.REFERENCE),("cache","cold"),("acquisition","selective"))
                  for cells in (groups[field],)}
        self.assertEqual(counts, dict(arm=32, cache=18, acquisition=4))


if __name__ == "__main__":
    unittest.main()
