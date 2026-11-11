"""Preserve original command/source failures in the unified evidence reader.

The child-source-mutation case executes the existing command recorder against
a real temporary Git repository. Other cases are labelled structural controls;
none is a production, model, payment, or cryptographic acceptance run.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest

import record_pq_native_command as recorder
import test_chain_hepta_qualification as fixtures


class CommandBindingTests(unittest.TestCase):
    def setUp(self):
        self.control = fixtures.QualificationTests(methodName="runTest")
        self.control.setUp()
        self.addCleanup(self.control.doCleanups)

    def receipt(self, **changes):
        source = self.control.plan["source_pair"]["chain"]
        observation = dict(schema="trnm-ci-source-v1", kind="head",
                           tested_commit=source["sha"], tested_tree=source["tree"],
                           candidate=source["sha"], base=None, prospective_merge=None,
                           tracked_worktree_verified=True, tracked_entries=1,
                           tracked_bytes=1, tests_executed_by_identity_check=False)
        value = dict(schema="trnm-pq-native-command-v1", status="command_succeeded",
                     exit_code=0, before=observation, after=copy.deepcopy(observation))
        value.update(changes)
        return value

    def review(self, receipt):
        self.control.record("native_registry", evidence=self.control.artifact(receipt))
        return self.control.run_review()["records"][-1]

    def test_actual_zero_exit_child_source_mutation_retains_record_failure(self):
        source = self.control.root / "actual-source"
        source.mkdir()
        def git(*args):
            return subprocess.check_output(["git", "-C", str(source), *args],
                                           text=True, stderr=subprocess.PIPE).strip()
        git("init", "--quiet", "--initial-branch=candidate", "--template=")
        git("config", "user.name", "Command binding control")
        git("config", "user.email", "fixture@example.invalid")
        git("config", "commit.gpgsign", "false")
        (source / "source.rs").write_text("const VALUE: u64 = 1;\n")
        git("add", "source.rs")
        git("commit", "--quiet", "--no-gpg-sign", "-m", "original control source")
        head = git("rev-parse", "HEAD")
        args = argparse.Namespace(kind="head", candidate=head, tested=head, base=None,
                                  label="zero-exit-source-mutation", output=self.control.root / "native-records",
                                  command=[sys.executable, "-c", "from pathlib import Path; "
                                           "Path('source.rs').write_text('changed source\\n')"])
        with contextlib.redirect_stdout(io.StringIO()):
            exit_code = recorder.run(args, source)
        receipt = json.loads((args.output / (args.label + ".json")).read_text())
        self.assertNotEqual(exit_code, 0)
        self.assertEqual(receipt["exit_code"], 0)
        self.assertEqual(receipt["status"], "record_failed")
        row = self.review(receipt)
        self.assertIn("RAW_COMMAND_NOT_SUCCEEDED", row["raw_result_conflicts"])
        self.assertFalse(row["declared_result_consistent"])
        self.assertEqual(row["raw_result_summary"]["status"], "record_failed")

    def test_running_receipt_cannot_supply_a_completed_result(self):
        row = self.review(self.receipt(status="running", exit_code=None))
        self.assertIn("RAW_COMMAND_NOT_SUCCEEDED", row["raw_result_conflicts"])
        self.assertIn("RAW_NATIVE_EXIT_UNOBSERVED", row["raw_result_conflicts"])
        self.assertFalse(row["declared_result_consistent"])

    def test_failed_status_is_not_hidden_by_zero_native_exit(self):
        row = self.review(self.receipt(status="command_failed"))
        self.assertIn("RAW_COMMAND_NOT_SUCCEEDED", row["raw_result_conflicts"])
        self.assertFalse(row["declared_result_consistent"])

    def test_boolean_native_exit_is_not_integer_success(self):
        row = self.review(self.receipt(exit_code=False))
        self.assertIn("RAW_NATIVE_EXIT_UNOBSERVED", row["raw_result_conflicts"])
        self.assertFalse(row["declared_result_consistent"])

    def test_command_source_cannot_borrow_normalized_source_pair(self):
        receipt = self.receipt()
        for observation in (receipt["before"], receipt["after"]):
            observation["tested_commit"] = fixtures.pin("other-actual-source", 40)
            observation["candidate"] = observation["tested_commit"]
        row = self.review(receipt)
        self.assertIn("RAW_COMMAND_SOURCE_MISMATCH", row["raw_result_conflicts"])
        self.assertFalse(row["declared_result_consistent"])

    def test_command_requires_both_source_observations(self):
        row = self.review(self.receipt(after=None))
        self.assertIn("RAW_COMMAND_SOURCE_UNVERIFIED", row["raw_result_conflicts"])
        self.assertFalse(row["declared_result_consistent"])

    def test_command_retains_changed_source_even_if_status_claims_success(self):
        receipt = self.receipt()
        receipt["after"]["tracked_bytes"] += 1
        row = self.review(receipt)
        self.assertIn("RAW_COMMAND_SOURCE_CHANGED", row["raw_result_conflicts"])
        self.assertFalse(row["declared_result_consistent"])

    def test_consistent_command_remains_an_unverified_outcome_and_hold(self):
        row = self.review(self.receipt())
        self.assertEqual(row["raw_result_conflicts"], [])
        self.assertTrue(row["declared_result_consistent"])
        self.assertFalse(row["result_payload_verified"])
        self.assertFalse(row["current_materials_consistent"])
        self.assertIn("RAW_OUTCOME_UNVERIFIED", row["issues"])
        self.assertEqual(self.control.run_review()["qualification"], "HOLD_NO_GO")

    def test_source_kind_relations_and_complete_schema_are_required(self):
        cases = (
            {"candidate": fixtures.pin("different-candidate", 40)},
            {"base": fixtures.pin("unexpected-head-base", 40)},
            {"prospective_merge": fixtures.pin("unexpected-head-merge", 40)},
            {"kind": "prospective-merge", "base": fixtures.pin("merge-base", 40),
             "prospective_merge": fixtures.pin("different-merge", 40)},
        )
        for changed in cases:
            with self.subTest(changed=changed):
                self.control.packet["records"] = []
                receipt = self.receipt()
                for observation in (receipt["before"], receipt["after"]):
                    observation.update(changed)
                row = self.review(receipt)
                self.assertIn("RAW_COMMAND_SOURCE_UNVERIFIED", row["raw_result_conflicts"])
                self.assertFalse(row["declared_result_consistent"])
        for field in ("candidate", "base", "prospective_merge"):
            with self.subTest(missing=field):
                self.control.packet["records"] = []
                receipt = self.receipt()
                for observation in (receipt["before"], receipt["after"]):
                    del observation[field]
                self.assertIn("RAW_COMMAND_SOURCE_UNVERIFIED", self.review(receipt)["raw_result_conflicts"])

    def test_success_status_cannot_hide_original_recorder_error(self):
        row = self.review(self.receipt(error="source identity changed during command"))
        self.assertIn("RAW_COMMAND_ERROR_PRESENT", row["raw_result_conflicts"])
        self.assertFalse(row["declared_result_consistent"])

    def test_consistent_prospective_source_is_not_misread_as_candidate_head(self):
        receipt = self.receipt()
        for observation in (receipt["before"], receipt["after"]):
            observation.update(kind="prospective-merge", candidate=fixtures.pin("candidate-head", 40),
                               base=fixtures.pin("merge-base", 40), prospective_merge=observation["tested_commit"])
        row = self.review(receipt)
        self.assertEqual(row["raw_result_conflicts"], [])
        self.assertTrue(row["declared_result_consistent"])
        self.assertFalse(row["result_payload_verified"])

    def test_failed_command_cannot_resolve_unknown_external_effect(self):
        self.control.complete()
        effect = self.control.effect_unknown()
        query = self.control.row(effect["steps"][1]["record_id"])
        query["evidence"] = self.control.artifact(self.receipt(status="record_failed"))
        result = self.control.run_review()["effects"][0]
        self.assertEqual(result["reported_terminal_state"], "UNKNOWN")
        self.assertFalse(result["reported_commit_observed"])
        self.assertIn("UNRESOLVED_EXTERNAL_EFFECT", result["issues"])
        self.assertFalse(result["effects_verified"])

    def test_failed_command_cannot_complete_a_learning_stage(self):
        self.control.complete()
        training = self.control.row(self.control.packet["learning"]["stages"]["training"])
        training["evidence"] = self.control.artifact(self.receipt(status="record_failed"))
        self.assertIn("UNQUALIFIED_STAGE_RECORD:training", self.control.run_review()["learning_blockers"])


if __name__ == "__main__":
    unittest.main()
