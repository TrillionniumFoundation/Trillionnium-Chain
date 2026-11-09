#!/usr/bin/env python3
"""Current metadata reconstruction/refusal controls; no fresh proof trials."""
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
    "tested_current_w1_mapping", ROOT / "scripts/w1_current_source_mapping.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
ASSET = "evidence/pon-w1-full-v2-20261105/succinct.bin"
STORE = "trillionnium/crates/trnm-pon-node/src/store.rs"


class CurrentSourceMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = M.build_report(ROOT)

    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="trnm-current-w1-mapping-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative in set(self.actual["checked_input_files"]) | {M.MAPPER_PATH}:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        return root

    @staticmethod
    def mutate(path):
        original = path.read_bytes()
        path.write_bytes(bytes([original[0] ^ 1]) + original[1:])

    def test_actual_mapping_reaches_retained_artifacts_and_upstream_with_security_hold(self):
        report = self.actual
        self.assertEqual(len(report["checked_input_files"]), 48)
        self.assertEqual(len(report["upstream_selected_sources"]), 24)
        self.assertIs(report["current_saved_artifact_and_upstream_mapping_reconstructed"], True)
        self.assertIs(report["saved_v2"]["public_artifact_commitments_recomputed"], True)
        self.assertIs(report["saved_v2"]["control_inclusion_matches_reconstructed_tree"], True)
        self.assertEqual(report["parameter_digest_recomputed"], report["saved_v2"]["parameter_digest"])
        self.assertIs(report["saved_v2"]["guest_elf_to_image_recomputed"], False)
        self.assertEqual(report["new_complete_proofs_generated"], 0)
        self.assertIs(report["fresh_cryptographic_verification"], False)
        self.assertIsNone(report["original_unknown_lifetime_arithmetic"]["sum_of_group_adversary_query_envelopes"])
        for key, value in report["qualification"].items():
            self.assertIs(value, None if key == "security_bits_quantum" else False)

    def test_both_original_guard_refusals_and_unfinished_rosters_are_preserved(self):
        report = self.actual
        self.assertEqual(set(report["original_source_observation"]["original_guard_observations"]),
                         {"lifetime", "implementation"})
        for row in report["original_source_observation"]["original_guard_observations"].values():
            self.assertIs(row["source_scope_passed"], False)
        for key in ("historical_named_test_rosters_completed", "historical_workflows_passed",
                    "whole_repository_source_verified", "dependency_closure_complete",
                    "current_binary_executed", "provenance_authenticated"):
            self.assertIs(report[key], False)
        for row in report["source_delta_review"]:
            self.assertIs(row["complete_semantic_equivalence_established"], False)

    def test_current_source_mutation_refused_before_saved_artifact_read(self):
        root = self.fixture()
        self.mutate(root / STORE)
        with patch.object(M, "pinned_files", side_effect=AssertionError("must not load artifacts")):
            with self.assertRaisesRegex(ValueError, "reviewed current source differs"):
                M.build_report(root)

    def test_original_owner_and_contract_cannot_be_rebased_to_make_old_guards_pass(self):
        for relative in ("scripts/w1_lifetime_ledger.py", "config/pon/w1-qrom-implementation-v1.json"):
            root = self.fixture()
            self.mutate(root / relative)
            with self.subTest(path=relative), self.assertRaisesRegex(ValueError, "reviewed current source differs"):
                M.build_report(root)

    def test_every_retained_artifact_and_snapshot_byte_pin_is_required(self):
        paths = [path for path in self.actual["checked_input_files"] if path.startswith("evidence/")]
        self.assertEqual(len(paths), 7)
        for relative in paths:
            root = self.fixture()
            self.mutate(root / relative)
            with self.subTest(path=relative), self.assertRaisesRegex(ValueError, "pinned mapping input drift"):
                M.build_report(root)

    def test_missing_snapshot_is_failure_not_historical_source_refusal(self):
        root = self.fixture()
        path = next(path for path in self.actual["checked_input_files"] if path.endswith(".json.gz"))
        (root / path).unlink()
        with self.assertRaises(FileNotFoundError):
            M.build_report(root)

    def test_observer_bytes_are_pinned_before_helper_execution(self):
        root = self.fixture()
        self.mutate(root / M.OBSERVER_PATH)
        with self.assertRaisesRegex(M.MappingError, "unreviewed current source observer"):
            M.build_report(root)

    def test_retained_artifact_symlink_and_fifo_are_refused_without_blocking(self):
        for kind in ("symlink", "fifo"):
            root = self.fixture()
            target = root / ASSET
            target.unlink()
            if kind == "symlink":
                target.symlink_to(ROOT / ASSET)
            else:
                os.mkfifo(target)
            command = [sys.executable, "-B", "-c",
                       "import sys;sys.path.insert(0,sys.argv[1]);import w1_current_source_mapping as m;m.build_report(m.Path(sys.argv[2]))",
                       str(ROOT / "scripts"), str(root)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("Too many levels of symbolic links" if kind == "symlink" else "mapping input type or bound",
                          result.stderr)

    def test_artifact_change_during_reconstruction_is_rejected_at_final_readback(self):
        root = self.fixture()
        observer, raw = M.observer_module(root)
        original = observer.original_module
        def instrument(*args):
            module = original(*args)
            if hasattr(module, "inspect_v2"):
                inspect = module.inspect_v2
                def changed(*values):
                    result = inspect(*values)
                    self.mutate(root / ASSET)
                    return result
                module.inspect_v2 = changed
            return module
        observer.original_module = instrument
        with patch.object(M, "observer_module", return_value=(observer, raw)):
            with self.assertRaisesRegex(M.MappingError, "pinned mapping input drift"):
                M.build_report(root)

    def test_returned_qualification_cannot_mutate_next_observation(self):
        report = M.build_report(ROOT)
        report["qualification"]["post_quantum_soundness_qualified"] = True
        self.assertIs(M.build_report(ROOT)["qualification"]["post_quantum_soundness_qualified"], False)

    def git_fixture(self):
        root = self.fixture()
        def git(*args):
            return subprocess.check_output(["git", "-c", "user.name=Mapping Fixture",
                "-c", "user.email=fixture@invalid.example", *args], cwd=root,
                text=True, stderr=subprocess.PIPE, timeout=10).strip()
        git("init", "-q")
        git("add", "--all")
        git("commit", "-qm", "Synthetic mapping input fixture; no project qualification")
        return root, git

    def output(self):
        temporary = tempfile.TemporaryDirectory(prefix="trnm-current-w1-mapping-output-")
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name) / "mapping.json"

    def cli(self, root, expected, output):
        return subprocess.run([sys.executable, "-B", str(ROOT / M.MAPPER_PATH), "--root", str(root),
            "--expected-head", expected, "--output", str(output)],
            text=True, capture_output=True, timeout=10)

    def test_real_cli_binds_all_48_inputs_and_executed_mapper_to_commit(self):
        root, git = self.git_fixture()
        output = self.output()
        result = self.cli(root, git("rev-parse", "HEAD"), output)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(output.read_bytes())
        self.assertEqual(len(report["selected_commit_blob_ids"]), 49)
        self.assertIs(report["selected_checked_bytes_match_commit"], True)
        self.assertIs(report["whole_repository_source_verified"], False)
        self.assertEqual(report["security_disposition"], "HOLD_NO_GO")

    def test_real_cli_refuses_retained_artifact_restored_over_different_commit_bytes(self):
        root, git = self.git_fixture()
        target = root / ASSET
        original = target.read_bytes()
        self.mutate(target)
        git("add", ASSET)
        git("commit", "-qm", "Synthetic changed committed artifact")
        target.write_bytes(original)
        output = self.output()
        result = self.cli(root, git("rev-parse", "HEAD"), output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected current commit bytes differ", result.stderr)
        self.assertFalse(output.exists())

    def test_real_cli_refuses_untracked_artifact_and_forged_expected_head(self):
        root, git = self.git_fixture()
        output = self.output()
        result = self.cli(root, "f" * 40, output)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())
        git("rm", "--cached", ASSET)
        git("commit", "-qm", "Synthetic omitted artifact")
        result = self.cli(root, git("rev-parse", "HEAD"), output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected current commit blob differs", result.stderr)
        self.assertFalse(output.exists())

    def test_real_cli_output_is_create_only_and_cannot_change_source(self):
        root, git = self.git_fixture()
        output = self.output()
        output.write_bytes(b"preserved original observation")
        result = self.cli(root, git("rev-parse", "HEAD"), output)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b"preserved original observation")
        result = self.cli(root, git("rev-parse", "HEAD"), root / "mapping.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mapping output must be outside source", result.stderr)
        self.assertFalse((root / "mapping.json").exists())


if __name__ == "__main__":
    unittest.main()
