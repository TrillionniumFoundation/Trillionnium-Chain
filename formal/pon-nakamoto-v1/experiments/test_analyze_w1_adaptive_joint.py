#!/usr/bin/env python3
"""Small synthetic-readback controls; no timings or native execution are measured."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("analyze_w1_adaptive_joint.py")
SPEC = importlib.util.spec_from_file_location("adaptive_joint_analysis", SCRIPT)
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


def digest(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


def command(cpu):
    return dict(
        whole_waited_child_resources=dict(user_cpu_ns=cpu + 1000, system_cpu_ns=0),
        whole_command_usage=dict(maximum_resident_set_kib=12345,
                                 user_seconds_decimal="1.00", system_seconds_decimal="0.00"),
    )


def fixture():
    plan, raw = analysis.load_json(analysis.PLAN)
    jobs = []
    for item in plan["jobs"]:
        binary = item["binary"]
        options = (analysis.joint_options if binary == analysis.JOINT else analysis.parent_options)(item["args"])
        budget = options["cpu_budget_ns"]
        if binary == analysis.JOINT:
            count = 0 if budget == 0 else (3 if options["producer"] == "avx2-joint" else 2)
            task = digest(options["family"])
            attempts, seen = [], set()
            for index in range(count):
                nonce = index % options["nonce_space"]
                identity = digest((task, options["seed"], options["sample"], options["target"], nonce))
                hit = options["target"] != [0] * 32
                attempts.append(dict(index=index, task=task, challenge=identity, ticket=identity,
                                     semantic_id=identity, block_id=identity, target_hit=hit,
                                     unique=identity not in seen, inclusive_producer_cpu_ns=index + 1,
                                     inclusive_within_cpu_budget=True))
                seen.add(identity)
            inclusive = budget + 1000
            core = inclusive // 2
            end = dict(attempts=count, unique_opportunities=len(seen),
                       target_hits=sum(a["target_hit"] for a in attempts),
                       unique_target_hits=len(seen) if options["target"] != [0] * 32 else 0,
                       inclusive_budget_unique_opportunities=len(seen),
                       inclusive_budget_unique_target_hits=len(seen) if options["target"] != [0] * 32 else 0,
                       inclusive_producer_cpu_ns=inclusive, charged_core_cpu_ns=core,
                       observer_cpu_ns=10, elapsed_cpu_ns=inclusive + 10,
                       status="inclusive-cpu-budget-exhausted")
            row = dict(schema="pon-w1-joint-challenge-verified-v1", options=options, task=task,
                       attempts=attempts, end=end, all_completed_proofs_python_replayed=count,
                       stage_cpu_ns={"material": core // 4, "prepare": core // 4,
                                     "generate": core - 2 * (core // 4)}, **command(inclusive + 10))
        else:
            count = 0 if item["name"].startswith("control.parent.") else 1
            identity = digest((options["strategy"], options["seed"], options["screen_width"]))
            common = dict(id=0, task_index=0, parent=digest("parent"), height=1,
                          challenge=identity, proof_sha256=identity,
                          semantic_id=identity, block_id=identity, target_hit=True)
            attempts = [dict(common, round=0, attempt=0,
                             completed={"process_cpu_ns": 20},
                             admission_completed={"process_cpu_ns": 30})] if count else []
            original = dict(common, semantic_id=digest(identity + "aux"),
                            block_id=digest(identity + "block"), role="unit-original-template",
                            original_make_complete_attempts=1,
                            original_search_completed={"process_cpu_ns": 10},
                            admission_completed={"process_cpu_ns": 15})
            acquisitions = [original] if count else []
            strategy = budget + (1000 if options["cache"] == "hot" else 2000)
            counts = dict(research_completed_proofs=count, acquisitions=count,
                          original_make_completed_proofs=count, original_make_failed_target_proofs=0,
                          research_unique_complete_semantics=count, all_work_unique_winners=2 * count,
                          all_work_unique_admitted_within_budget=2 * count,
                          research_unique_admitted_within_budget=count, rounds_completed=0)
            replay = dict(research_proofs=count, acquisition_winners=count,
                          posthoc_reconstruction_records=count, full_relation_records=3 * count)
            row = dict(schema="pon-w1-parent-reuse-readback-v1", options=options,
                       counts=counts, attempts=attempts, acquisitions=acquisitions,
                       python_replayed=replay, retained_proof_records_replayed=3 * count,
                       controls=[], controls_completed=False,
                       status="process-cpu-budget-stopped" if count else "process-cpu-budget-stopped-before-context",
                       strategy_cpu_ns=strategy, posthoc_process_cpu_ns=100 * count,
                       charge_cpu_ns_by_stage={"native-context-create": strategy // 2},
                       unattributed_strategy_cpu_ns=strategy - strategy // 2,
                       **command(strategy + 100 * count))
        row.update(job=item["name"], binary=binary)
        jobs.append(row)
    return dict(
        schema=analysis.SCHEMA, plan_sha256=hashlib.sha256(raw).hexdigest(), jobs=jobs,
        external_identity_pins_checked=True, posthoc_replay_provides_no_selection_feedback=True,
        all_retained_full_proof_records_independently_replayed=True,
        native_execution_attested_by_reader=False, native_qualification_independently_reexecuted_by_python=False,
        hardware_attested=False, universal_kappa_bound_established=False, hardness_accepted=False,
        production_activation=False, new_training_qualification=False,
        source={"head": "a" * 40, "tree": "b" * 40, "status": ""},
        raw_manifest_sha256="c" * 64, reader_sha256="d" * 64, binaries={}, hardware=[],
    )


class AnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = fixture()

    def test_exact_grid_and_scope_separation_without_fabricated_lifecycle_pass(self):
        result = analysis.analyze(self.base)
        self.assertEqual(result["counts"]["jobs"], 58)
        self.assertEqual(len(result["joint_pairs"]), 21)
        self.assertEqual(len(result["parent_main_cache_pairs"]), 6)
        self.assertEqual(len(result["parent_other_or_budget_controls"]), 4)
        self.assertEqual(result["counts"]["parent_lifecycle_controls_complete"], 0)
        self.assertTrue(all(row["lifecycle_observation"] == "incomplete-no-pass-claim"
                            for row in result["all_jobs_in_registered_order"]
                            if "lifecycle_observation" in row))
        zero_pair = next(row for row in result["joint_pairs"] if row["options_except_producer"]["cpu_budget_ns"] == 0)
        self.assertIsNone(zero_pair["all_completed_inclusive_rate_ratio_avx2_over_sequential"])
        self.assertEqual(result["counts"]["all_full_proof_records_independently_replayed"],
                         sum(result["counts"][key] for key in
                             ("genuine_research_proof_records", "auxiliary_original_winning_proof_records",
                              "posthoc_reconstructed_proof_records")))

    def test_joint_actual_cost_rate_and_no_nominal_budget_denominator(self):
        result = analysis.analyze(self.base)
        pair = result["joint_pairs"][0]
        ratio = pair["all_completed_inclusive_rate_ratio_avx2_over_sequential"]
        self.assertEqual((ratio["reduced_numerator"], ratio["reduced_denominator"]), (3, 2))
        self.assertEqual(ratio["numerator"], 3 * pair["sequential"]["inclusive_cpu_ns"])
        self.assertGreater(pair["sequential"]["inclusive_cpu_ns"], pair["options_except_producer"]["cpu_budget_ns"])

    def test_mismatched_plan_options_or_overlapping_identity_is_rejected(self):
        for change, message in (
            (lambda d: d["jobs"].pop(), "EXACT_58_JOBS"),
            (lambda d: d["jobs"][0]["options"].update(cpu_budget_ns=25), "REGISTERED_EXACT_OPTIONS"),
            (lambda d: d["jobs"][0]["attempts"][0].update(challenge="e" * 64), "JOINT_OVERLAPPING_IDENTITY"),
        ):
            altered = copy.deepcopy(self.base)
            change(altered)
            with self.assertRaisesRegex(ValueError, message):
                analysis.analyze(altered)

    def test_parent_full_identity_required_and_different_strategy_not_paired(self):
        result = analysis.analyze(self.base)
        jobs = {r["job"]: r for r in self.base["jobs"]}
        metric = {r["job"]: r for r in result["all_jobs_in_registered_order"]}
        pair = result["parent_main_cache_pairs"][0]
        hot, cold = jobs[pair["hot_job"]], copy.deepcopy(jobs[pair["cold_job"]])
        cold["attempts"] = []
        censored = analysis.parent_pair(hot, cold, metric)
        self.assertFalse(censored["all_research_and_acquisition_identities_identical"])
        self.assertIsNone(censored["all_work_within_budget_strategy_rate_ratio_hot_over_cold"])
        cold = copy.deepcopy(jobs[pair["cold_job"]])
        cold["options"]["strategy"] = "zero-only"
        with self.assertRaisesRegex(ValueError, "PARENT_PAIR_SCOPE"):
            analysis.parent_pair(hot, cold, metric)
        cold = copy.deepcopy(jobs[pair["cold_job"]])
        cold["acquisitions"][0]["proof_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "PARENT_OVERLAPPING_IDENTITY"):
            analysis.parent_pair(hot, cold, metric)

    def test_zero_denominators_bad_stage_sums_and_lifecycle_promotion_reject(self):
        self.assertIsNone(analysis.rate_ratio(0, 1, 2, 1))
        with self.assertRaisesRegex(ValueError, "ZERO_CPU_DENOMINATOR"):
            analysis.rate_ratio(1, 0, 1, 1)
        with self.assertRaisesRegex(ValueError, "STAGE_SUM"):
            analysis.stage_shares({"paid": 2}, 1)
        altered = copy.deepcopy(self.base)
        row = next(r for r in altered["jobs"] if r["binary"] == analysis.PARENT)
        row["controls_completed"] = True
        with self.assertRaisesRegex(ValueError, "PARENT_CONTROL_NOT_ALL_EXECUTED"):
            analysis.analyze(altered)

    def test_whole_child_negative_residual_is_preserved_not_clamped(self):
        row = command(0)
        result = analysis.command_observation(row, 2000, 500)
        self.assertEqual(result["whole_child_minus_native_and_posthoc_cpu_ns"], -1500)
        self.assertEqual(result["whole_command_maximum_rss_kib"], 12345)

    def test_exclusive_output_and_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory(prefix="w1-adaptive-analysis-test-") as folder:
            source, out = Path(folder) / "readback.json", Path(folder) / "analysis.json"
            source.write_text(json.dumps(self.base))
            analysis.write_analysis(source, out)
            original = out.read_bytes()
            with self.assertRaisesRegex(ValueError, "OUTPUT_ALREADY_EXISTS"):
                analysis.write_analysis(source, out)
            self.assertEqual(out.read_bytes(), original)
            source.write_text('{"schema":1,"schema":2}')
            with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
                analysis.load_json(source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
