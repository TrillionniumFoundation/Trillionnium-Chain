#!/usr/bin/env python3
"""Component controls only; no main-repository/native/qualification assertion."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("integrate_candidate", HERE / "integrate_candidate.py")
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)


class ControllerComponentControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pon-controller-components-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.repo = self.directory / "repo"
        self.repo.mkdir()
        integration.git(self.repo, "init", "-q")
        integration.git(self.repo, "config", "user.name", "Controller component fixture")
        integration.git(self.repo, "config", "user.email", "fixture@example.invalid")
        (self.repo / ".gitignore").write_text("*.log\n")
        (self.repo / "source.txt").write_text("old\n")
        integration.git(self.repo, "add", "--", ".gitignore", "source.txt")
        integration.git(self.repo, "commit", "-qm", "Component fixture, not project source")
        self.out = self.directory / "output"
        self.out.mkdir()
        self.inputs = self.directory / "inputs"
        self.inputs.mkdir()
        self.controller = integration.Controller.__new__(integration.Controller)
        self.controller.root = self.repo
        self.controller.out = self.out
        self.controller.inputs = self.inputs
        self.controller.args = SimpleNamespace(phase="prepare")
        self.controller.c2 = integration.git_text(self.repo, "rev-parse", "HEAD")
        self.controller.commands = []
        self.controller.check_inputs = lambda: None
        self.controller.state = {
            "expected_head": self.controller.c2,
            "expected_index": integration.git_text(self.repo, "write-tree"),
            "expected_files": {},
        }

    def test_frozen_external_helper_and_patch_bytes_match_reviewed_pins(self):
        root = HERE.parent
        for relative, digest in integration.INPUT_SHA256.items():
            with self.subTest(path=relative):
                self.assertEqual(integration.sha(integration.read_regular(root / relative)[0]), digest)

    def test_fifo_is_refused_without_waiting_for_a_writer(self):
        fifo = self.directory / "fifo.json"
        os.mkfifo(fifo)
        start = time.monotonic()
        with self.assertRaisesRegex(integration.Refusal, "nonregular"):
            integration.read_regular(fifo)
        self.assertLess(time.monotonic() - start, 0.5)

    def test_ancestor_symlink_and_final_symlink_are_refused(self):
        alias = self.directory / "alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        leaf = self.directory / "leaf"
        leaf.symlink_to(self.repo / "source.txt")
        for path in (alias / "source.txt", leaf):
            with self.subTest(path=path), self.assertRaises((OSError, integration.Refusal)):
                integration.read_regular(path)

    def test_oversized_file_and_duplicate_json_keys_are_refused(self):
        with self.assertRaisesRegex(integration.Refusal, "oversized"):
            integration.read_regular(self.repo / "source.txt", limit=2)
        with self.assertRaisesRegex(integration.Refusal, "duplicate"):
            integration.strict_json(b'{"complete": false, "complete": true}')
        with self.assertRaisesRegex(integration.Refusal, "nonfinite"):
            integration.strict_json(b'{"time": NaN}')

    def test_replace_refuses_an_independent_edit_and_preserves_it(self):
        target = self.repo / "source.txt"
        target.write_bytes(b"other writer\n")
        with self.assertRaisesRegex(integration.Refusal, "independent edit"):
            integration.replace_expected(target, b"old\n", b"new\n")
        self.assertEqual(target.read_bytes(), b"other writer\n")

    def test_guard_refuses_unexpected_tracked_untracked_and_index_changes(self):
        self.controller.guard()
        target = self.repo / "source.txt"
        target.write_bytes(b"changed\n")
        with self.assertRaisesRegex(integration.Refusal, "unreviewed working-tree"):
            self.controller.guard()
        target.write_bytes(b"old\n")
        extra = self.repo / "extra.txt"
        extra.write_bytes(b"extra\n")
        with self.assertRaisesRegex(integration.Refusal, "unreviewed working-tree"):
            self.controller.guard()
        integration.git(self.repo, "add", "--", "extra.txt")
        with self.assertRaisesRegex(integration.Refusal, "index changed"):
            self.controller.guard()

    def test_guard_refuses_changed_bytes_even_in_an_owned_path(self):
        relative = "source.txt"
        self.controller.state["expected_files"][relative] = integration.fingerprint(self.repo / relative)
        (self.repo / relative).write_bytes(b"other change\n")
        with self.assertRaisesRegex(integration.Refusal, "independent file change"):
            self.controller.guard()

    def test_hidden_index_flag_is_refused_without_automatic_repair(self):
        integration.git(self.repo, "update-index", "--assume-unchanged", "--", "source.txt")
        self.assertEqual(integration.git(self.repo, "status", "--porcelain"), b"")
        with self.assertRaisesRegex(integration.Refusal, "hidden, sparse"):
            self.controller.guard()
        self.assertTrue(integration.git(self.repo, "ls-files", "-v", "--", "source.txt").startswith(b"h "))

    def test_actual_git_ignored_log_must_be_force_added_and_blob_verified(self):
        paths = ("evidence/fixture/raw.stderr.log", "evidence/fixture/manifest.json")
        for relative, data in zip(paths, (b"retained failure\n", b'{"fixture": true}\n')):
            integration.write_new(self.repo / relative, data)
        self.controller.state["evidence_paths"] = list(paths)
        self.controller.state["expected_files"] = {path: integration.fingerprint(self.repo / path) for path in paths}
        integration.git(self.repo, "add", "--", paths[1])
        omitted_tree = integration.git_text(self.repo, "write-tree")
        with self.assertRaisesRegex(integration.Refusal, "omitted/filtered"):
            self.controller.verify_evidence_tree(omitted_tree)
        integration.git(self.repo, "add", "-f", "--", *paths)
        full_tree = integration.git_text(self.repo, "write-tree")
        self.controller.verify_evidence_tree(full_tree)
        self.assertEqual(integration.git(self.repo, "show", full_tree + ":" + paths[0]), b"retained failure\n")
        self.assertFalse((self.repo / "unrelated.log").exists())

    def test_patch_prediction_uses_external_index_and_preserves_real_worktree(self):
        first = "diff --git a/source.txt b/source.txt\n--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-old\n+middle\n"
        second = "diff --git a/source.txt b/source.txt\n--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-middle\n+final\n"
        (self.inputs / "first.patch").write_text(first)
        (self.inputs / "second.patch").write_text(second)
        original_index = integration.git_text(self.repo, "write-tree")
        with mock.patch.object(integration, "PATCHES", ("first.patch", "second.patch")):
            predictions = self.controller.preview_patches()
        self.assertEqual((self.repo / "source.txt").read_bytes(), b"old\n")
        self.assertEqual(integration.git_text(self.repo, "write-tree"), original_index)
        self.assertEqual(predictions[-1]["source.txt"]["blob"], integration.blob_id(b"final\n"))
        self.assertEqual(predictions[0]["source.txt"]["blob"], integration.blob_id(b"middle\n"))
        self.assertEqual(len(self.controller.commands), 3)

    def test_raw_stream_whitespace_is_preserved_while_source_whitespace_still_fails(self):
        path = integration.EVIDENCE + "/native/retained.stdout.log"
        raw = b"test result: ok. 4 passed; 0 failed; 0 ignored;\n\n"
        integration.write_new(self.repo / path, raw)
        integration.git(self.repo, "add", "-f", "--", path)
        whole = subprocess.run(["git", "diff", "--cached", "--check"], cwd=self.repo, capture_output=True)
        self.assertEqual(whole.returncode, 2)
        scoped = ["git", "diff", "--cached", "--check", "--", *integration.whitespace_paths([path])]
        self.assertEqual(subprocess.run(scoped, cwd=self.repo, capture_output=True).returncode, 0)
        self.assertEqual((self.repo / path).read_bytes(), raw)
        (self.repo / "source.txt").write_bytes(b"bad source whitespace \n")
        integration.git(self.repo, "add", "--", "source.txt")
        bad = subprocess.run(scoped, cwd=self.repo, capture_output=True)
        self.assertEqual(bad.returncode, 2)
        self.assertIn(b"source.txt", bad.stdout)
        self.assertNotIn(path.encode(), bad.stdout)
        with self.assertRaisesRegex(integration.Refusal, "not an original"):
            integration.whitespace_paths([integration.EVIDENCE + "/native/source.json"])

    def test_malformed_or_deleted_patch_paths_are_refused(self):
        with self.assertRaisesRegex(integration.Refusal, "unsafe"):
            integration.patch_paths(b"+++ b/../escape\n")
        with self.assertRaisesRegex(integration.Refusal, "deletes"):
            integration.patch_paths(b"+++ /dev/null\n")

    def test_incomplete_native_summary_cannot_begin_integration(self):
        native = self.directory / "native"
        native.mkdir()
        for name in ("commands.json", "commands-before-v3.json", "summary-v3.json", "source.json", "source-v3.json",
                     "source-before-v3.json", "source-after-v3.json", "red-source.patch", "red-v3-source.json",
                     "fresh-profile-before-v3.json", "fresh-profile-after-v3.json"):
            (native / name).write_bytes(b"{}\n")
        (native / "summary-v3.json").write_bytes(b'{"complete": false, "production_activation": false}\n')
        with self.assertRaisesRegex(integration.Refusal, "incomplete"):
            integration.validate_native(native)
        refused_out = self.directory / "refused-output"
        argv = [str(HERE / "integrate_candidate.py"), "--phase", "prepare", "--root", str(self.repo),
                "--inputs", str(HERE.parent), "--native-validation", str(native), "--output", str(refused_out)]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(integration.main(), 2)
        self.assertEqual(json.loads((refused_out / "status.json").read_text())["phase"], "failed")
        self.assertIn("incomplete", json.loads((refused_out / "failure.json").read_text())["reason"])
        self.assertEqual(integration.git_text(self.repo, "rev-parse", "HEAD"), self.controller.c2)
        self.assertEqual(integration.git(self.repo, "status", "--porcelain"), b"")

    def test_unknown_native_binary_or_directory_is_not_copied(self):
        native = self.directory / "native"
        native.mkdir()
        (native / "target").mkdir()
        with self.assertRaisesRegex(integration.Refusal, "unreviewed native output"):
            integration.native_snapshot(native)

    def test_command_failure_has_original_streams_and_small_known_status(self):
        result = self.controller.run("component-missing-command", ["/no/such/controller-component-command"], required=False)
        self.assertEqual(result["exit_code"], 127)
        self.assertTrue(result["launch_error"])
        status = json.loads((self.out / "status.json").read_text())
        self.assertEqual(status["phase"], "failed")
        self.assertEqual(status["last_exit"], 127)
        self.assertEqual(status["current_head"], self.controller.c2)
        self.assertLess((self.out / "status.json").stat().st_size, 2048)
        self.assertEqual(integration.sha((self.out / result["stderr"]["file"]).read_bytes()), result["stderr"]["sha256"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
