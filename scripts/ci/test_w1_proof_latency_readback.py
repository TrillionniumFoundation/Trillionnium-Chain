#!/usr/bin/env python3
"""Adversarial controls on real retained clocks, not new proof measurements."""
from __future__ import annotations

import copy
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import read_w1_full_v2_disposition as retained
import read_w1_proof_latency as latency


class HistoricalLatencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, values = retained.pinned_inputs(ROOT)
        cls.report = retained.strict_json(values[retained.PROOF + "proof-result.json"])
        cls.raw = retained.observation_files(values[retained.PROOF + "observation-3.tar.gz"],
                                             retained.strict_json(values[retained.PROOF + "raw-index.json"]))

    def mutated_stage(self, index, change):
        report = copy.deepcopy(self.report)
        raw = dict(self.raw)
        row = report["stages"][index]
        change(row["result"])
        raw[row["stage"] + "/result.json"] = json.dumps(row["result"]).encode()
        return report, raw

    def mutated_stdout(self, label, transform):
        report = copy.deepcopy(self.report)
        raw = dict(self.raw)
        rows = [retained.strict_json(line) for line in raw[label + "/stdout.log"].splitlines()]
        rows = transform(rows)
        data = ("\n".join(json.dumps(row) for row in rows) + "\n").encode()
        raw[label + "/stdout.log"] = data
        stage = next(row for row in report["stages"] if row["stage"] == label)
        stage["result"]["stdout_sha256"] = retained.sha(data)
        raw[label + "/result.json"] = json.dumps(stage["result"]).encode()
        return report, raw

    def test_actual_pinned_readback_reconciles_exclusive_phases(self):
        result = latency.analyze(ROOT)
        timing = result["timing"]
        self.assertEqual(timing["fresh_pipeline_seconds"], 6248.484106799)
        self.assertAlmostEqual(math.fsum(timing["exclusive_pipeline_ledger"].values()),
                               timing["fresh_pipeline_seconds"], places=9)
        self.assertAlmostEqual(timing["exclusive_pipeline_ledger"]["segment_stages_seconds"],
                               3958.6605462940024, places=9)
        self.assertAlmostEqual(timing["exclusive_pipeline_ledger"]["recursive_compression_stage_seconds"],
                               2257.7816068050015, places=9)
        self.assertEqual(len(timing["supervisor_spans"]), 52)
        self.assertFalse(result["cryptographic_verification_performed_by_reader"])
        self.assertFalse(result["consensus_admission"])
        self.assertFalse(result["production_activation"])

    def test_nested_recursion_and_prefix_costs_are_not_added_twice(self):
        timing = latency.decompose(self.report, self.raw)
        inner = timing["nested_clocks_not_additive_to_pipeline"]
        self.assertEqual(inner["repeated_prefix_verifications"], 903)
        self.assertEqual(inner["recursive_operations"]["lift"]["operations"], 43)
        self.assertEqual(inner["recursive_operations"]["join"]["operations"], 42)
        self.assertEqual(inner["segment_prover_seconds"], 3795.495161914)
        self.assertEqual(inner["repeated_prefix_verifier_seconds"], 21.99608082)
        self.assertEqual(inner["recursive_operations"]["lift"]["prover_seconds"], 1138.946912063)
        self.assertEqual(inner["recursive_operations"]["join"]["prover_seconds"], 1112.044486135)
        self.assertAlmostEqual(timing["fixed_other_stage_counterfactuals"]["segment_stages_zero_remaining_seconds"],
                               2289.8235605049977, places=9)

    def test_real_unknowns_and_failed_trial_remain_unknown_and_failed(self):
        result = latency.analyze(ROOT)
        self.assertEqual(result["historical_attempts"]["complete_success"], 1)
        self.assertEqual(result["historical_attempts"]["complete_deadline_failure"], 1)
        self.assertEqual(result["historical_attempts"]["interrupted_outcome"], "UNKNOWN")
        self.assertFalse(result["historical_attempts"]["attempt_population_complete"])
        for value in result["timing"]["unmeasured"].values():
            self.assertIsNone(value)
        self.assertIsNone(result["timing"]["winner_to_receiver_complete_seconds"])
        self.assertIsNone(result["timing"]["prover_p99_seconds"])
        self.assertEqual(result["gates"]["winner_to_receiver_complete_latency"],
                         "INSUFFICIENT_DIRECT_EVIDENCE")

    def test_old_pipeline_cannot_become_a_winner_or_wan_clock(self):
        for key in latency.UNMEASURED:
            report = dict(self.report, **{key: self.report["fresh_proof_pipeline_seconds"]})
            with self.subTest(key=key), self.assertRaises(ValueError):
                latency.decompose(report, self.raw)

    def test_stage_order_omission_duplication_and_raw_mutation_fail(self):
        for stages in (self.report["stages"][1:], self.report["stages"][:-1],
                       list(reversed(self.report["stages"])), self.report["stages"] * 2):
            with self.assertRaises(ValueError):
                latency.decompose(dict(self.report, stages=stages), self.raw)
        report = copy.deepcopy(self.report)
        report["stages"][0]["result"]["wall_seconds"] /= 2
        with self.assertRaisesRegex(ValueError, "differs from raw"):
            latency.decompose(report, self.raw)

    def test_overlapping_reversed_and_outside_clocks_fail(self):
        for change in (
            lambda row: row.update(started_monotonic=self.report["started_monotonic"] - 1),
            lambda row: row.update(started_monotonic=self.report["stages"][0]["result"]["started_monotonic"]),
            lambda row: row.update(wall_seconds=1e9),
        ):
            report, raw = self.mutated_stage(1, change)
            with self.assertRaises(ValueError):
                latency.decompose(report, raw)

    def test_nonfinite_boolean_negative_and_incomplete_stage_fail(self):
        for value in (float("nan"), float("inf"), True, -1):
            report, raw = self.mutated_stage(0, lambda row: row.update(wall_seconds=value))
            with self.subTest(value=value), self.assertRaises(ValueError):
                latency.decompose(report, raw)
        for change in (lambda row: row.update(returncode=True),
                       lambda row: row.update(stage_process_complete=False),
                       lambda row: row.update(completion_observed_before_deadline=False)):
            report, raw = self.mutated_stage(0, change)
            with self.assertRaises(ValueError):
                latency.decompose(report, raw)

    def test_recursive_omission_reorder_and_final_binding_are_rejected(self):
        def remove_join(rows):
            return [row for row in rows if row.get("event", {}).get("name") != "join-through-0001"]
        def change_final(rows):
            rows[-1]["event"]["receipt_sha256"] = "00" * 32
            return rows
        def swap_operations(rows):
            indexes = [i for i, row in enumerate(rows) if row.get("event", {}).get("stage") ==
                       "REAL_RECURSIVE_STARK_SAVED_VERIFIED"]
            rows[indexes[0]], rows[indexes[1]] = rows[indexes[1]], rows[indexes[0]]
            return rows
        for change in (remove_join, change_final, swap_operations):
            report, raw = self.mutated_stdout("complete-recursive-compression", change)
            with self.assertRaises(ValueError):
                latency.decompose(report, raw)

    def test_prefix_or_nested_cost_cannot_be_removed_or_exceed_process(self):
        def remove_prefix(rows):
            return [row for row in rows if row.get("event", {}).get("stage") !=
                    "CHECKPOINT_CRYPTOGRAPHICALLY_REVERIFIED"]
        def inflate_prover(rows):
            for row in rows:
                if row.get("event", {}).get("stage") == "REAL_SEGMENT_STARK_SAVED_VERIFIED":
                    row["event"]["prover_ns"] = 10**18
            return rows
        for change in (remove_prefix, inflate_prover):
            report, raw = self.mutated_stdout("prove-0002", change)
            with self.assertRaises(ValueError):
                latency.decompose(report, raw)

    def test_endpoint_shift_or_resumed_run_does_not_inherit_fresh_timing(self):
        for report in (dict(self.report, fresh_proof_pipeline_seconds=1),
                       dict(self.report, prior_runs=[{}]),
                       dict(self.report, fresh_preparation_included=False),
                       dict(self.report, prover_p99_established=True)):
            with self.assertRaises(ValueError):
                latency.decompose(report, self.raw)

    def test_cli_is_deterministic_and_cannot_overwrite_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "readback.json"
            command = [sys.executable, str(ROOT / "scripts/read_w1_proof_latency.py")]
            result = subprocess.run(command + ["--out", str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            stdout = subprocess.run(command, capture_output=True, text=True, check=True).stdout
            self.assertEqual(path.read_text(), stdout)
            repeated = subprocess.run(command + ["--out", str(path)], capture_output=True, text=True)
            self.assertEqual(repeated.returncode, 2)
            self.assertEqual(path.read_text(), stdout)
            self.assertEqual(json.loads(repeated.stdout)["disposition"], "INVALID_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
