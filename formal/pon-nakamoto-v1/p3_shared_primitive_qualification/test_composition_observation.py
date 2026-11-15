"""Real temporary Git comparisons and refusal controls; no native/PQ proof claim."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import composition_observation as observation


class CompositionObservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "source"
        self.output = Path(self.temporary.name) / "evidence"
        self.root.mkdir()
        self.output.mkdir()
        self.run_git("init", "-q")
        for relative in observation.CRYPTO_FILES:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixed cryptographic control bytes\n")
        self.runtime = self.root / "trillionnium/runtime-control.txt"
        self.runtime.parent.mkdir()
        self.runtime.write_text("baseline runtime\n")
        self.commit()
        self.base = self.head()
        # These local commits are fixtures, not replacements for production
        # pin constants or a native dependency/proof execution.
        self.pins = patch.multiple(observation, RUNTIME_BASE=self.base, CRYPTO_BASE=self.base)
        self.pins.start()
        self.addCleanup(self.pins.stop)
        self.runtime.write_text("reviewed integration runtime\n")
        self.commit()
        self.records = self.make_records()

    def run_git(self, *args):
        return subprocess.check_output(["git", "-c", "user.name=Control Fixture",
                                        "-c", "user.email=control@example.invalid", *args],
                                       cwd=self.root, stderr=subprocess.PIPE)

    def commit(self):
        self.run_git("add", "--all")
        self.run_git("commit", "-q", "-m", "synthetic refusal-control fixture")

    def head(self):
        return self.run_git("rev-parse", "HEAD").decode().strip()

    def make_records(self):
        identity = {
            "schema": "trnm-ci-source-v1", "kind": "head", "tested_commit": self.head(),
            "tested_tree": self.run_git("rev-parse", "HEAD^{tree}").decode().strip(),
            "candidate": self.head(), "base": None, "prospective_merge": None,
            "tracked_worktree_verified": True, "tracked_entries": 6,
            "tracked_bytes": 123, "tests_executed_by_identity_check": False,
        }
        raw = (json.dumps(identity, sort_keys=True) + "\n").encode()
        for name in ("source-before", "source-after"):
            (self.output / (name + ".json")).write_bytes(raw)
        records = []
        for name in observation.REQUIRED_GATES:
            row = {"name": name, "argv": ["synthetic-nonnative-control"],
                   "cwd": str(self.root), "exit_code": 0}
            stdout, stderr = b"synthetic control receipt\n", b""
            if name.startswith("source-") and name in ("source-before", "source-after"):
                row["argv"] = ["python3", "-B", "scripts/ci/verify_ci_source.py", "--kind", "head",
                               "--expected-head", self.head(), "--output",
                               str(self.output / (name + ".json"))]
                stdout = raw
            if name == "unchanged-runtime-scope":
                row["argv"] = observation.runtime_scope_command()
                result = subprocess.run(row["argv"], cwd=self.root, capture_output=True)
                row["exit_code"], stdout, stderr = result.returncode, result.stdout, result.stderr
            for stream, value in (("stdout", stdout), ("stderr", stderr)):
                (self.output / (name + "." + stream + ".txt")).write_bytes(value)
                row[stream + "_sha256"] = observation.digest(value)
            records.append(row)
        return records

    def observe(self, records=None):
        return observation.build_observation(self.root, self.head(), self.output,
                                             self.records if records is None else records)

    def test_changed_runtime_keeps_original_failure_and_real_patch(self):
        result = self.observe()
        self.assertFalse(result["original_unchanged_runtime_scope_passed"])
        self.assertEqual(result["original_unchanged_runtime_scope_exit_code"], 1)
        raw = (self.output / result["runtime_diff"]["file"]).read_bytes()
        self.assertIn(b"+reviewed integration runtime", raw)
        self.assertEqual(result["runtime_diff"]["sha256"], observation.digest(raw))
        self.assertEqual(result["current_commit"], self.head())
        self.assertEqual(result["fixed_runtime_reference"], self.base)

    def test_default_mode_still_refuses_actual_original_scope_failure(self):
        row = next(row for row in self.records if row["name"] == "unchanged-runtime-scope")
        self.assertEqual(row["exit_code"], 1)
        self.assertNotIn(row["exit_code"], observation.accepted_exit_codes(row["name"], False))
        self.assertIn(row["exit_code"], observation.accepted_exit_codes(row["name"], True))

    def test_no_other_gate_can_borrow_the_composition_exception(self):
        for name in observation.REQUIRED_GATES:
            if name != "unchanged-runtime-scope":
                with self.subTest(gate=name):
                    self.assertEqual(observation.accepted_exit_codes(name, True), (0,))

    def test_unchanged_runtime_is_observed_without_qualification(self):
        self.run_git("checkout", "--detach", self.base)
        self.records = self.make_records()
        result = self.observe()
        self.assertTrue(result["original_unchanged_runtime_scope_passed"])
        self.assertEqual(result["runtime_diff"]["bytes"], 0)
        self.assertFalse(result["runtime_changes_qualified"])

    def test_result_has_new_namespace_and_preserves_all_hold_fields(self):
        result = self.observe()
        self.assertEqual(result["schema"], "p3.shared-primitive.composition-observation.v1")
        self.assertEqual(result["qualification"], "HOLD_NO_GO")
        self.assertIsNone(result["complete_noninteractive_security_bits"])
        for field in ("runtime_changes_qualified", "cryptographic_qualification",
                      "lifetime_quantum_bound_established", "complete_repository_ci",
                      "production_activation"):
            self.assertIs(result[field], False)

    def test_every_original_gate_and_the_new_control_gate_are_required(self):
        for index, row in enumerate(self.records):
            with self.subTest(gate=row["name"]), self.assertRaises(observation.ObservationError):
                self.observe(self.records[:index] + self.records[index + 1:])

    def test_duplicate_or_reordered_gate_is_refused(self):
        for rows in (self.records + [self.records[0]], list(reversed(self.records))):
            with self.assertRaises(observation.ObservationError):
                self.observe(rows)

    def test_nonruntime_failure_and_runtime_error_are_refused(self):
        for name, code in (("rust-tests", 1), ("unchanged-runtime-scope", 2),
                           ("strict-clippy", True)):
            rows = copy.deepcopy(self.records)
            next(row for row in rows if row["name"] == name)["exit_code"] = code
            with self.subTest(gate=name, code=code), self.assertRaises(observation.ObservationError):
                self.observe(rows)

    def test_forged_current_commit_is_refused(self):
        with self.assertRaises(observation.ObservationError):
            observation.build_observation(self.root, "f" * 40, self.output, self.records)

    def test_missing_expected_source_is_refused(self):
        with self.assertRaises(observation.ObservationError):
            observation.build_observation(self.root, "", self.output, self.records)

    def test_missing_fixed_history_is_refused(self):
        with patch.object(observation, "CRYPTO_BASE", "f" * 40):
            with self.assertRaises(subprocess.CalledProcessError):
                self.observe()

    def test_dirty_current_runtime_is_refused(self):
        self.runtime.write_text("uncommitted change\n")
        with self.assertRaises(observation.ObservationError):
            self.observe()

    def test_each_frozen_crypto_file_rejects_a_committed_change(self):
        for relative in observation.CRYPTO_FILES:
            with self.subTest(path=relative):
                path = self.root / relative
                original = path.read_bytes()
                path.write_bytes(original + b"changed\n")
                self.commit()
                self.records = self.make_records()
                with self.assertRaises(observation.ObservationError):
                    self.observe()
                path.write_bytes(original)
                self.commit()

    def test_missing_frozen_crypto_source_is_refused(self):
        (self.root / observation.CRYPTO_FILES[-1]).unlink()
        self.commit()
        self.records = self.make_records()
        with self.assertRaises(observation.ObservationError):
            self.observe()

    def test_source_receipts_must_be_complete_and_equal(self):
        (self.output / "source-after.json").write_text("{}\n")
        with self.assertRaises(observation.ObservationError):
            self.observe()

    def test_forged_receipt_tree_is_checked_against_real_git(self):
        identity = json.loads((self.output / "source-before.json").read_bytes())
        identity["tested_tree"] = "f" * 40
        raw = json.dumps(identity).encode()
        for name in ("source-before", "source-after"):
            (self.output / (name + ".json")).write_bytes(raw)
            (self.output / (name + ".stdout.txt")).write_bytes(raw)
            next(row for row in self.records if row["name"] == name)["stdout_sha256"] = observation.digest(raw)
        with self.assertRaises(observation.ObservationError):
            self.observe()

    def test_source_verification_command_cannot_be_replaced(self):
        next(row for row in self.records if row["name"] == "source-before")["argv"] = ["true"]
        with self.assertRaises(observation.ObservationError):
            self.observe()

    def test_original_runtime_guard_cannot_be_replaced_or_omit_exit_code(self):
        for argv in (["true"], [part for part in observation.runtime_scope_command() if part != "--exit-code"]):
            rows = copy.deepcopy(self.records)
            next(row for row in rows if row["name"] == "unchanged-runtime-scope")["argv"] = argv
            with self.assertRaises(observation.ObservationError):
                self.observe(rows)

    def test_forged_runtime_diff_is_recomputed_even_with_updated_digest(self):
        raw = b"forged empty-scope claim\n"
        (self.output / "unchanged-runtime-scope.stdout.txt").write_bytes(raw)
        next(row for row in self.records if row["name"] == "unchanged-runtime-scope")["stdout_sha256"] = observation.digest(raw)
        with self.assertRaises(observation.ObservationError):
            self.observe()

    def test_missing_or_changed_gate_output_is_refused(self):
        path = self.output / "rust-tests.stdout.txt"
        path.write_bytes(b"replacement output")
        with self.assertRaises(observation.ObservationError):
            self.observe()
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.observe()


if __name__ == "__main__":
    unittest.main(verbosity=2)
