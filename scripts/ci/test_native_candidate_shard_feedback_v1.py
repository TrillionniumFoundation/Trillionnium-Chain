#!/usr/bin/env python3
"""Regression controls for complete failure accounting; these are not Rust tests."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_native_candidate_shards_v1 as runner
import test_native_candidate_shards_v1 as fixtures


class CandidateFeedbackTests(unittest.TestCase):
    def invoke(self, root: Path, case: str = "", suite: str = "native"):
        return fixtures.NativeCandidateShardTests().invoke(root, case, suite)

    def test_nonzero_and_timeout_do_not_omit_later_shards_or_erase_first_failure(self):
        original = runner.run_bounded
        for suite in runner.SUITES:
            for failures in ((17,), (124,), (17, 23), (124, 17)):
                with self.subTest(suite=suite, failures=failures), tempfile.TemporaryDirectory() as directory:
                    executions = []

                    def inject(command, **kwargs):
                        output, code = original(command, **kwargs)
                        if Path(command[0]).name == "fake-native" and "--list" not in command:
                            executions.append(command)
                            if len(executions) <= len(failures):
                                return output, failures[len(executions) - 1]
                        return output, code

                    with patch.object(runner, "run_bounded", side_effect=inject):
                        code, summary, evidence = self.invoke(Path(directory), suite=suite)
                    inventory = json.loads((evidence / "inventory.json").read_text())
                    outcomes = list(summary["shards"].values())
                    self.assertEqual(code, failures[0])
                    self.assertEqual(summary["status"], "failed")
                    self.assertTrue(summary["all_shards_executed"])
                    self.assertEqual(len(executions), len(inventory))
                    self.assertEqual(len(outcomes), len(inventory))
                    for index, outcome in enumerate(outcomes):
                        expected = failures[index] if index < len(failures) else 0
                        self.assertEqual(outcome["process_exit_code"], expected)
                        self.assertEqual(outcome["exit_code"], expected)
                        self.assertEqual(outcome["status"], "timeout" if expected == 124 else "failed" if expected else "passed")
                        self.assertGreaterEqual(outcome["elapsed_seconds"], 0)
                        self.assertEqual(outcome["planned_count"], len(outcome["names"]))
                        if expected:
                            self.assertNotIn("counts", outcome)
                        else:
                            self.assertEqual(outcome["counts"]["failed"], 0)
                    for shard in inventory:
                        self.assertTrue((evidence / f"{shard}.log").is_file())
                        self.assertGreaterEqual(float((evidence / f"{shard}.elapsed-seconds").read_text()), 0)

    def test_exit_zero_with_wrong_or_missing_result_fails_but_completes_inventory(self):
        for case in ("no-summary", "wrong-count"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                code, summary, _ = self.invoke(Path(directory), case)
                self.assertEqual(code, 2)
                self.assertEqual(summary["status"], "failed")
                self.assertTrue(summary["all_shards_executed"])
                self.assertEqual(set(summary["shards"]), set(runner.SHARD_NAMES))
                for outcome in summary["shards"].values():
                    self.assertEqual(outcome["process_exit_code"], 0)
                    self.assertEqual(outcome["exit_code"], 2)
                    self.assertEqual(outcome["status"], "invalid-result")
                    self.assertIn("error", outcome)
                    self.assertNotIn("counts", outcome)

    def test_all_filtered_inventories_are_admitted_before_first_test(self):
        original = runner.run_bounded
        executions = []

        def observe(command, **kwargs):
            if Path(command[0]).name == "fake-native" and "--list" not in command:
                executions.append(command)
            return original(command, **kwargs)

        with tempfile.TemporaryDirectory() as directory, patch.object(runner, "run_bounded", side_effect=observe):
            code, summary, _ = self.invoke(Path(directory), "filtered-mismatch")
        self.assertNotEqual(code, 0)
        self.assertFalse(summary["all_shards_executed"])
        self.assertEqual(executions, [])
        self.assertTrue(all(outcome["status"] == "not-run" for outcome in summary["shards"].values()))

    def test_source_or_binary_mutation_stops_instead_of_continuing_under_false_identity(self):
        for case in ("source-change", "binary-change"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                code, summary, _ = self.invoke(Path(directory), case)
                self.assertNotEqual(code, 0)
                self.assertEqual(summary["status"], "failed")
                self.assertFalse(summary["all_shards_executed"])
                self.assertIn("error", summary)
                outcomes = list(summary["shards"].values())
                self.assertTrue(all(outcome["status"] == "not-run" for outcome in outcomes[1:]))
                self.assertTrue(all(outcome["exit_code"] is None for outcome in outcomes[1:]))

    def test_checkpoint_on_interruption_keeps_incomplete_denominator(self):
        original = runner.run_bounded
        checkpoint = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def interrupt(command, **kwargs):
                if Path(command[0]).name == "fake-native" and "--list" not in command:
                    checkpoint.append(json.loads((root / "evidence/summary.json").read_text()))
                    raise OSError("injected process launch failure")
                return original(command, **kwargs)

            with patch.object(runner, "run_bounded", side_effect=interrupt):
                code, summary, _ = self.invoke(root)
        self.assertEqual(code, 2)
        self.assertEqual(summary["status"], "failed")
        self.assertFalse(summary["all_shards_executed"])
        self.assertEqual(len(checkpoint), 1)
        self.assertNotEqual(checkpoint[0]["status"], "passed")
        self.assertEqual(set(checkpoint[0]["shards"]), set(runner.SHARD_NAMES))
        statuses = [entry["status"] for entry in checkpoint[0]["shards"].values()]
        self.assertEqual(statuses[0], "running")
        self.assertTrue(all(status == "not-run" for status in statuses[1:]))

    def test_success_requires_complete_validated_denominator_and_unchanged_deadlines(self):
        with tempfile.TemporaryDirectory() as directory:
            code, summary, _ = self.invoke(Path(directory), suite="node-epoch")
        self.assertEqual(code, 0)
        self.assertEqual(summary["status"], "passed")
        self.assertTrue(summary["all_shards_executed"])
        for outcome in summary["shards"].values():
            self.assertEqual(outcome["status"], "passed")
            self.assertEqual(outcome["deadline_seconds"], runner.NODE_CASE_DEADLINES.get(outcome["names"][0], 30))
        v8 = runner.NODE_EPOCH_PREFIX + "actual_epoch_handoff_joint_attachment_and_exact_retry_v8"
        self.assertEqual(runner.shard_deadline("node-epoch", [v8], 300), 300)


if __name__ == "__main__":
    unittest.main()
