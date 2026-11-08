#!/usr/bin/env python3
"""Synthetic budget controls; these timings are not native measurements."""
import copy
import io
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_w1_observed_economics_v1 as economics
from test_pon_w1_preparation_strategy_reader_v4 import fixture


class ObservedEconomicsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = fixture()
        cls.raw = b"".join(json.dumps(row).encode() + b"\n" for row in cls.rows)
        cls.records, cls.identity = economics.read_records(io.BytesIO(cls.raw))
        cls.strategy = economics.v4.STRATEGIES[0]

    def replay(self, budget, records=None):
        return economics.fixed_budget_replay(records or self.records, self.strategy, budget)

    def test_zero_budget_records_unpaid_setup_and_no_proof(self):
        row = self.replay(0)
        self.assertEqual(row["paid_cpu_ns"], 0)
        self.assertEqual(row["recorded_relation_valid_proofs"], 0)
        self.assertEqual(row["stopped_phase"]["phase"], "common_material_setup")

    def test_common_setup_is_paid_exactly_once_per_fixed_strategy(self):
        row = self.replay(10**9)
        expected = 1000 + sum(self.records.cohorts[s, self.strategy]["total"]["cpu_ns"]
                              for s in range(economics.v4.SAMPLES))
        self.assertEqual(row["paid_cpu_ns"], expected)
        self.assertEqual(row["complete_setups"], 8)
        self.assertEqual(row["complete_searches"], 8)

    def test_partial_search_never_acquires_attempts_or_proof(self):
        first = self.records.cohorts[0, self.strategy]
        prelude = first["total"]["cpu_ns"] - first["searches"][0]["timing"]["cpu_ns"]
        row = self.replay(1000 + prelude + 1)
        self.assertEqual(row["recorded_relation_valid_proofs"], 0)
        self.assertEqual(row["attempts_in_complete_searches"], 0)
        self.assertTrue(row["unlocated_attempts_in_partial_search"])
        self.assertEqual(row["paid_cpu_ns"], row["budget_cpu_ns"])

    def test_inclusive_exact_completion_can_credit_one_proof(self):
        first = self.records.cohorts[0, self.strategy]
        row = self.replay(1000 + first["total"]["cpu_ns"])
        self.assertEqual(row["complete_searches"], 1)
        self.assertEqual(row["recorded_relation_valid_proofs"], 1)

    def test_later_cheap_samples_cannot_skip_first_expensive_search(self):
        records = copy.deepcopy(self.records)
        first = records.cohorts[0, self.strategy]
        first["searches"][0]["timing"]["cpu_ns"] += 10**6
        first["total"]["cpu_ns"] += 10**6
        row = self.replay(100_000, records)
        self.assertEqual(row["complete_searches"], 0)
        self.assertEqual(row["stopped_phase"]["sample"], 0)

    def test_semantic_alert_suppresses_all_validity_based_credit(self):
        records = copy.deepcopy(self.records)
        records.alerts.append({"synthetic": "verifier disagreement"})
        row = self.replay(10**9, records)
        self.assertIsNone(row["recorded_relation_valid_proofs"])
        self.assertEqual(row["complete_recorded_target_hits"], 8)

    def test_no_extrapolation_beyond_retained_eight_samples(self):
        row = self.replay(10**18)
        self.assertEqual(row["complete_searches"], 8)
        self.assertEqual(row["termination"], "recorded-schedule-exhausted")
        self.assertGreater(row["unused_cpu_ns"], 0)

    def test_accounting_frontloads_cohort_residual(self):
        records = copy.deepcopy(self.records)
        first = records.cohorts[0, self.strategy]
        first["total"]["cpu_ns"] += 10_000
        row = self.replay(2000, records)
        self.assertEqual(row["stopped_phase"]["phase"], "setup_and_frontloaded_cohort_overhead")
        self.assertEqual(row["complete_searches"], 0)

    def test_negative_boolean_or_unbounded_budget_rejected(self):
        for budget in (-1, True, 1.5, 10**18 + 1):
            with self.subTest(budget=budget), self.assertRaisesRegex(ValueError, "CPU_BUDGET"):
                self.replay(budget)

    def test_original_rows_are_bound_and_missing_end_rejected(self):
        self.assertEqual(self.identity["sha256"], economics.sha(self.raw))
        with self.assertRaisesRegex(ValueError, "MISSING_COMPLETE_END"):
            economics.read_records(io.BytesIO(self.raw[:self.raw.rfind(b'\n', 0, -1) + 1]))

    def test_one_shard_cannot_claim_complete_grid_or_controls(self):
        shard = economics.summarize_records(self.records, self.identity)
        with self.assertRaisesRegex(ValueError, "COMPLETE_COST_GRID_AND_SEPARATE_CONTROLS_REQUIRED"):
            economics.assemble_report([shard], {})

    def test_duplicate_or_unknown_shard_rejected(self):
        shard = economics.summarize_records(self.records, self.identity)
        with self.assertRaisesRegex(ValueError, "SHARD_INVENTORY"):
            economics.assemble_report([shard, copy.deepcopy(shard)], {})

    def test_custom_budget_inventory_cannot_be_mislabeled_as_fixed_grid(self):
        with self.assertRaisesRegex(ValueError, "BUDGET_INVENTORY"):
            economics.summarize_records(self.records, self.identity, budgets=(7,))

    def test_trailing_decompressed_data_has_an_independent_total_limit(self):
        stream = economics.BoundedDecompression(io.BytesIO(b"valid-body" + bytes(200)), 20)
        self.assertEqual(stream.read(10), b"valid-body")
        with self.assertRaisesRegex(ValueError, "TOTAL_DECOMPRESSED_STREAM_BOUND"):
            stream.read(100_000_000)
        self.assertEqual(stream.consumed, 21)

    def test_exact_decompressed_limit_allows_eof(self):
        stream = economics.BoundedDecompression(io.BytesIO(bytes(20)), 20)
        self.assertEqual(len(stream.read(20)), 20)
        self.assertEqual(stream.read(1), b"")

    @staticmethod
    def assembly_fixture():
        """Synthetic parsed-record stand-ins solely for receipt-binding controls."""
        shards, commands = [], []
        for name in economics.v4.CLASSES:
            for target in range(4):
                for horizon in economics.v4.HORIZONS if target < 2 else (1,):
                    purpose = economics.v4.PURPOSES[target]
                    digest = f"{len(shards) + 1:064x}"
                    selected = {"class": name, "target_index": target,
                                "reuse_winners": horizon, "purpose": purpose}
                    shards.append({"selection": selected, "matched_streams": [],
                        "raw_observation": {"sha256": digest, "bytes": 1}})
                    command = {"name": f"{name}-t{target}-h{horizon}" if target < 2
                        else f"{name}-control-t{target}", "purpose": purpose,
                        "process": {"stdout_sha256": digest, "process_complete": True,
                            "returncode": 0, "timed_out": False, "observer_interrupted": False,
                            "resource_failure": None, "argv": ["/synthetic/not-executed",
                                economics.v4.SELECTOR, "--class", name, "--target-index", str(target),
                                "--reuse-winners", str(horizon)]},
                        "archives": {"stdout.jsonl": {"raw_sha256": digest, "raw_bytes": 1}}}
                    commands.append(command)
        return shards, {"declaration": {"base_commit": "synthetic", "source_sha256": {},
                "tracked_or_untracked_working_changes": True, "binary_sha256": "0" * 64},
            "manifest": {"planned": 48, "observed_commands": 48, "commands": commands,
                         "unobserved_planned_commands": []}}

    def test_one_process_cannot_stand_in_for_two_independent_raw_observations(self):
        shards, metadata = self.assembly_fixture()
        commands = metadata["manifest"]["commands"]
        commands[1]["process"]["stdout_sha256"] = commands[0]["process"]["stdout_sha256"]
        commands[1]["archives"] = copy.deepcopy(commands[0]["archives"])
        with self.assertRaisesRegex(ValueError, "DUPLICATE_PROCESS_STDOUT"):
            economics.assemble_report(shards, metadata)

    def test_process_selection_and_arguments_must_match_its_raw_rows(self):
        for field in ("name", "argv"):
            shards, metadata = self.assembly_fixture()
            command = metadata["manifest"]["commands"][0]
            if field == "name":
                command[field] = "a-different-command"
            else:
                command["process"][field][-1] = "64"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "PROCESS_.*_BINDING"):
                economics.assemble_report(shards, metadata)

    def test_failed_process_cannot_gain_numeric_qualification(self):
        shards, metadata = self.assembly_fixture()
        metadata["manifest"]["commands"][0]["process"]["timed_out"] = True
        with self.assertRaisesRegex(ValueError, "FAILED_PROCESS_REMAINS_UNQUALIFIED"):
            economics.assemble_report(shards, metadata)


if __name__ == "__main__":
    unittest.main()
