#!/usr/bin/env python3
"""Controls for additional source observation; never the old complete rosters."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "reviewed_current_w1_observation", ROOT / "scripts/w1_current_source_observation.py")
OBS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBS)
PROFILE_RAW = (ROOT / "config/pon/w1-qrom-current-source-observation-v1.json").read_bytes()
PROFILE = OBS.checked_profile(PROFILE_RAW)
STORE = "trillionnium/crates/trnm-pon-node/src/store.rs"


class CurrentSourceObservationTests(unittest.TestCase):
    def fixture(self):
        temp = tempfile.TemporaryDirectory(prefix="trnm-current-source-observation-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for path in set(PROFILE["current_files"]) | set(PROFILE["original_owner_files"]):
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
        return root

    def observe(self, root):
        return OBS.observe_selected_sources(root, PROFILE_RAW)

    def test_actual_reviewed_bytes_keep_both_actual_old_refusals_and_all_hold_flags(self):
        report = self.observe(ROOT)
        self.assertEqual(report["selected_paths"], 37)
        self.assertEqual(report["result"], "CURRENT_SELECTED_SOURCE_OBSERVED_HOLD")
        self.assertEqual(len(report["changed_paths"]), 3)
        for row in report["original_guard_observations"].values():
            self.assertIs(row["source_scope_passed"], False)
        for name in ("original_named_test_rosters_completed", "original_workflows_passed",
                     "saved_proof_and_upstream_checks_reached", "current_binary_executed",
                     "whole_repository_source_verified", "dependency_closure_complete",
                     "provenance_authenticated"):
            self.assertIs(report[name], False)
        for name, value in report["qualification"].items():
            self.assertIs(value, None if name == "security_bits_quantum" else False)
        for name, value in report["original_implementation_lifetime_budget"].items():
            self.assertIs(value, False if name == "policy_adopted" else None)

    def test_changed_current_source_is_rejected_before_old_guard_can_run(self):
        root = self.fixture()
        target = root / STORE
        target.write_bytes(b"!" + target.read_bytes()[1:])
        with patch.object(OBS, "original_refusals", side_effect=AssertionError("must not run")):
            with self.assertRaisesRegex(OBS.ObservationError, "reviewed current source differs"):
                self.observe(root)

    def test_missing_current_source_is_failure_not_an_expected_historical_refusal(self):
        root = self.fixture()
        (root / STORE).unlink()
        with self.assertRaises(FileNotFoundError):
            self.observe(root)

    def test_same_content_source_symlink_is_refused(self):
        root = self.fixture()
        target = root / STORE
        saved = root / "saved-store"
        target.rename(saved)
        target.symlink_to(saved)
        with self.assertRaises(OSError):
            self.observe(root)

    def test_same_content_ancestor_symlink_is_refused(self):
        root = self.fixture()
        scripts = root / "scripts"
        scripts.rename(root / "saved-scripts")
        scripts.symlink_to(root / "saved-scripts")
        with self.assertRaisesRegex(OBS.ObservationError, "non-directory selected ancestor"):
            self.observe(root)

    def test_original_ledger_owner_cannot_be_edited_to_pass(self):
        root = self.fixture()
        target = root / "scripts/w1_lifetime_ledger.py"
        target.write_bytes(b"!" + target.read_bytes()[1:])
        with self.assertRaisesRegex(OBS.ObservationError, "reviewed current source differs"):
            self.observe(root)

    def test_original_implementation_contract_cannot_be_rehashed_or_promoted(self):
        root = self.fixture()
        target = root / "config/pon/w1-qrom-implementation-v1.json"
        raw = target.read_bytes()
        self.assertIn(b"false", raw)
        target.write_bytes(raw.replace(b"false", b"true ", 1))
        with self.assertRaisesRegex(OBS.ObservationError, "reviewed current source differs"):
            self.observe(root)

    def test_unreviewed_revision_or_changed_path_profile_cannot_self_certify(self):
        for mode in ("revision", "path"):
            changed = json.loads(PROFILE_RAW)
            if mode == "revision":
                changed["reviewed_source_commit"] = "f" * 40
            else:
                del changed["current_files"][STORE]
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(OBS.ObservationError, "unreviewed current observation profile"):
                    OBS.observe_selected_sources(ROOT, json.dumps(changed).encode())

    def test_qualification_flag_cannot_be_promoted_in_profile(self):
        changed = json.loads(PROFILE_RAW)
        changed["qualification"]["lifetime_bound_established"] = True
        with self.assertRaisesRegex(OBS.ObservationError, "unreviewed current observation profile"):
            OBS.observe_selected_sources(ROOT, json.dumps(changed).encode())

    def test_original_guard_unexpected_success_is_refused(self):
        original = OBS.original_module
        def changed(*args):
            module = original(*args)
            if hasattr(module, "source_survey"):
                module.source_survey = lambda _sources: {}
            return module
        with patch.object(OBS, "original_module", side_effect=changed):
            with self.assertRaisesRegex(OBS.ObservationError, "original lifetime scope unexpectedly passed"):
                self.observe(ROOT)

    def test_unrelated_original_guard_failure_cannot_be_labelled_source_drift(self):
        original = OBS.original_module
        def changed(*args):
            module = original(*args)
            if hasattr(module, "source_survey"):
                def unrelated(_sources):
                    raise module.LedgerError("unrelated failure")
                module.source_survey = unrelated
            return module
        with patch.object(OBS, "original_module", side_effect=changed):
            with self.assertRaisesRegex(OBS.ObservationError, "unexpected original lifetime failure"):
                self.observe(ROOT)

    def test_changed_source_during_original_observation_is_refused(self):
        root = self.fixture()
        original = OBS.original_refusals
        def mutate(*args):
            result = original(*args)
            target = root / STORE
            target.write_bytes(b"!" + target.read_bytes()[1:])
            return result
        with patch.object(OBS, "original_refusals", side_effect=mutate):
            with self.assertRaisesRegex(OBS.ObservationError, "reviewed current source differs"):
                self.observe(root)

    def test_returned_qualification_does_not_mutate_next_observation(self):
        first = self.observe(ROOT)
        first["qualification"]["quantum_work_qualified"] = True
        self.assertIs(self.observe(ROOT)["qualification"]["quantum_work_qualified"], False)

    def git_fixture(self):
        root = self.fixture()
        def git(*args):
            return subprocess.check_output(["git", "-c", "user.name=Observation Fixture",
                "-c", "user.email=fixture@invalid.example", *args], cwd=root,
                stderr=subprocess.PIPE, text=True).strip()
        git("init", "-q")
        git("add", "--all")
        git("commit", "-qm", "Synthetic selected source fixture; not repository qualification")
        return root, git

    def cli(self, root, expected, output, timeout=20):
        return subprocess.run([sys.executable, "-B", str(ROOT / "scripts/w1_current_source_observation.py"),
            "--root", str(root), "--expected-head", expected,
            "--profile", str(ROOT / "config/pon/w1-qrom-current-source-observation-v1.json"),
            "--output", str(output)], capture_output=True, text=True, timeout=timeout)

    def external_output(self):
        temp = tempfile.TemporaryDirectory(prefix="trnm-current-source-output-")
        self.addCleanup(temp.cleanup)
        return Path(temp.name) / "observation.json"

    def test_real_cli_binds_selected_git_blobs_but_never_claims_whole_repository(self):
        root, git = self.git_fixture()
        output = self.external_output()
        expected = git("rev-parse", "HEAD")
        result = self.cli(root, expected, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(output.read_bytes())
        self.assertEqual(report["observed_current_commit"], expected)
        self.assertIs(report["selected_current_files_match_commit"], True)
        self.assertEqual(len(report["selected_commit_blob_ids"]), 39)
        self.assertIs(report["whole_repository_source_verified"], False)
        self.assertEqual(report["security_disposition"], "HOLD_NO_GO")

    def test_real_cli_refuses_forged_current_head_without_receipt(self):
        root, _git = self.git_fixture()
        output = self.external_output()
        result = self.cli(root, "f" * 40, output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("current head differs before observation", result.stderr)
        self.assertFalse(output.exists())

    def test_real_cli_refuses_reviewed_worktree_over_a_different_commit_blob(self):
        root, git = self.git_fixture()
        target = root / STORE
        reviewed = target.read_bytes()
        target.write_bytes(b"!" + reviewed[1:])
        git("add", STORE)
        git("commit", "-qm", "Synthetic changed selected source")
        target.write_bytes(reviewed)
        output = self.external_output()
        result = self.cli(root, git("rev-parse", "HEAD"), output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected current commit bytes differ", result.stderr)
        self.assertFalse(output.exists())

    def test_real_cli_refuses_untracked_reviewed_source_missing_from_commit(self):
        root, git = self.git_fixture()
        git("rm", "--cached", STORE)
        git("commit", "-qm", "Synthetic omitted selected source")
        output = self.external_output()
        result = self.cli(root, git("rev-parse", "HEAD"), output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected current commit blob differs", result.stderr)
        self.assertFalse(output.exists())

    def test_real_cli_does_not_overwrite_an_existing_observation(self):
        root, git = self.git_fixture()
        output = self.external_output()
        output.write_bytes(b"retained-original-evidence")
        result = self.cli(root, git("rev-parse", "HEAD"), output)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b"retained-original-evidence")

    def test_real_cli_fifo_refuses_promptly_after_regular_fixture_succeeds(self):
        root, git = self.git_fixture()
        expected = git("rev-parse", "HEAD")
        normal_output = self.external_output()
        normal = self.cli(root, expected, normal_output, timeout=3)
        self.assertEqual(normal.returncode, 0, normal.stderr)
        self.assertTrue(normal_output.exists())
        target = root / STORE
        target.unlink()
        os.mkfifo(target, 0o600)
        fifo_output = self.external_output()
        # TimeoutExpired is an uncaught test failure, never a successful refusal.
        refused = self.cli(root, expected, fifo_output, timeout=3)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("selected file type or byte bound differs", refused.stderr)
        self.assertFalse(fifo_output.exists())

    def test_duplicate_and_nonfinite_json_are_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(OBS.ObservationError):
                OBS.strict_json(raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
