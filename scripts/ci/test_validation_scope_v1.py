#!/usr/bin/env python3
"""Real Git-tree positive/negative controls for narrow Rust applicability."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from validation_scope_v1 import ScopeError, assess, output_path, parse_diff, regular_prose


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="trnm-scope-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update(GIT_AUTHOR_NAME="fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                        GIT_COMMITTER_NAME="fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        self.git("init", "-q", "-b", "main")
        self.write("README.md", "overview\n")
        self.write("src/lib.rs", "pub fn value() -> u8 { 1 }\n")
        self.base = self.commit()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, env=self.env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def write(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture", "--allow-empty")
        return self.git("rev-parse", "HEAD")

    def result(self, event="pull_request", base=None):
        return assess(self.root, self.git("rev-parse", "HEAD"), event,
                      self.base if base is None else base)

    def test_regular_prose_only_is_not_applicable_not_a_pass(self):
        self.write("README.md", "edited prose\n")
        self.write("docs/runbooks/operators.md", "bounded instructions")
        head = self.commit()
        result = self.result()
        self.assertFalse(result["run_rust"])
        self.assertEqual(result["rust_test_result"], "not-applicable-not-a-test-pass")
        self.assertEqual(result["head"], head)
        self.assertEqual(result["tree"], self.git("rev-parse", "HEAD^{tree}"))
        self.assertFalse(result["release_acceptance"])

    def test_every_unknown_or_sensitive_family_requires_full(self):
        for path in ("src/lib.rs", "Cargo.lock", ".github/workflows/gate.yml",
                     "config/policy.json", "scripts/ci/validation_scope_v1.py",
                     "docs/protocol/rule.md", "docs/modules/spec.md", "docs/development/plan.md",
                     "new-unknown-file.md"):
            with self.subTest(path=path):
                self.write(path, "changed\n")
                self.commit()
                self.assertTrue(self.result()["run_rust"])
                self.git("reset", "--hard", self.base)

    def test_mixed_source_and_prose_requires_full(self):
        self.write("README.md", "edited")
        self.write("src/lib.rs", "pub fn value() -> u8 { 2 }")
        self.commit()
        self.assertTrue(self.result()["run_rust"])

    def test_source_renamed_to_prose_is_not_hidden(self):
        self.git("mv", "src/lib.rs", "OPERATIONS.md")
        self.commit()
        result = self.result()
        self.assertTrue(result["run_rust"])
        self.assertIn("src/lib.rs", [r["path"] for r in result["changes"]])

    def test_executable_and_symlink_prose_require_full(self):
        (self.root / "README.md").chmod(0o755)
        self.commit()
        self.assertTrue(self.result()["run_rust"])
        self.git("reset", "--hard", self.base)
        (self.root / "README.md").unlink()
        (self.root / "README.md").symlink_to("src/lib.rs")
        self.commit()
        self.assertTrue(self.result()["run_rust"])

    def test_main_manual_and_empty_inventory_require_full(self):
        self.assertTrue(self.result()["run_rust"])
        self.write("README.md", "edited")
        self.commit()
        for event in ("push", "workflow_dispatch"):
            self.assertTrue(self.result(event)["run_rust"])

    def test_missing_wrong_or_unknown_source_fails(self):
        head = self.git("rev-parse", "HEAD")
        for expected, event, base in (("0" * 40, "push", None), (head, "pull_request", None),
                                      (head, "pull_request", "0" * 40), (head, "other", None)):
            with self.subTest(expected=expected, event=event, base=base), self.assertRaises(ScopeError):
                assess(self.root, expected, event, base)

    def test_dirty_checkout_cannot_get_reduced_scope(self):
        self.write("README.md", "edited")
        with self.assertRaises(ScopeError):
            self.result()

    def test_diverged_base_still_detects_branch_source_changes(self):
        self.git("checkout", "-qb", "feature")
        self.write("src/lib.rs", "pub fn value() -> u8 { 2 }")
        head = self.commit()
        self.git("checkout", "-q", "main")
        self.write("README.md", "base moved")
        new_base = self.commit()
        self.git("checkout", "-q", "feature")
        result = assess(self.root, head, "pull_request", new_base)
        self.assertTrue(result["run_rust"])
        self.assertEqual(result["merge_base"], self.base)

    def test_invalid_inventory_and_output_paths_fail(self):
        for raw in (b"bad", b":100644 100644 aaa bbb R100\0a\0", b":100644 100644 aaa bbb M\0\xff\0"):
            with self.assertRaises(ScopeError):
                parse_diff(raw)
        with self.assertRaises(ScopeError):
            output_path(self.root, str(self.root / "report.json"))
        self.assertFalse(regular_prose("docs/runbooks/../rule.md", "100644", "100644"))
        self.assertFalse(regular_prose("docs/runbooks/a\nb.md", "100644", "100644"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
