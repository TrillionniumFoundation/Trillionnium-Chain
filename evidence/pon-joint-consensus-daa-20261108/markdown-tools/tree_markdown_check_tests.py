#!/usr/bin/env python3
"""Adversarial tests for the independent committed-tree Markdown check."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import tree_markdown_check as checker


class CommittedTreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Tree checker fixture")
        self.git("config", "user.email", "tree-checker@example.invalid")
        self.write(checker.CHECKER, "# parser fixture\n# " + checker.FENCE + "\n# " + checker.INLINE + "\n")
        # The synthetic repository has its own explicitly pinned checker
        # fixture; production continues to allow only the reviewed real hash.
        approved = frozenset({checker.sha256((self.repo / checker.CHECKER).read_bytes())})
        self.approval = mock.patch.object(checker, "APPROVED_CHECKER_SHA256", approved)
        self.approval.start()
        self.addCleanup(self.approval.stop)
        self.write("docs/target.md", "# Target\n")
        self.write("assets/real.zip", "committed binary target placeholder fixture only\n")

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], stderr=subprocess.STDOUT)

    def write(self, path, body):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", "immutable fixture")
        return self.git("rev-parse", "HEAD").decode().strip()

    def run_check(self, commit=None):
        commit = commit or self.commit()
        output = self.root / "result"
        output.mkdir()
        return checker.check(self.repo, commit, output)

    def test_commit_tree_does_not_require_binary_or_markdown_worktree_files(self):
        self.write("README.md", "[doc](docs/target.md) [directory](docs) [zip](assets/real.zip)\n")
        commit = self.commit()
        shutil.rmtree(self.repo / "docs")
        shutil.rmtree(self.repo / "assets")
        (self.repo / "README.md").unlink()
        result = self.run_check(commit)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["local_links"], 3)
        self.assertEqual(result["markdown_files"], 2)
        self.assertFalse(result["canonical_check_repository_executed"])
        self.assertFalse(result["full_repository_gate_pass_claimed"])

    def test_case_sensitive_target_rejected(self):
        self.write("README.md", "[wrong case](Docs/target.md)\n")
        result = self.run_check()
        self.assertEqual((result["result"], result["link_errors"]), ("FAIL", 1))

    def test_root_escape_rejected(self):
        self.write("README.md", "[escape](../outside.md) [absolute](/docs/target.md)\n")
        result = self.run_check()
        self.assertEqual(result["link_errors"], 2)

    def test_percent_encoded_local_path_and_parent_directory(self):
        self.write("docs/space name.md", "[parent](../README.md)\n")
        self.write("README.md", "[space](docs/space%20name.md) [dot](docs/%2e%2e/assets/real.zip)\n")
        self.assertEqual(self.run_check()["result"], "PASS")

    def test_fences_external_links_and_fragment_only_follow_existing_grammar(self):
        self.write("README.md", "[web](https://example.invalid/not-local) [anchor](#nowhere)\n"
                   "```text\n[ignored](missing.md)\n```\n[good](docs/target.md#unchecked)\n")
        result = self.run_check()
        self.assertEqual((result["result"], result["local_links"]), ("PASS", 1))
        self.assertFalse(result["checks_fragment_anchors"])

    def test_actual_missing_target_is_failure(self):
        self.write("README.md", "[missing](assets/no-such.zip)\n")
        self.assertEqual(self.run_check()["result"], "FAIL")

    def test_relative_committed_symlink_is_resolved(self):
        (self.repo / "docs" / "alias.md").symlink_to("target.md")
        (self.repo / "alias-dir").symlink_to("docs", target_is_directory=True)
        self.write("README.md", "[alias](docs/alias.md) [via-dir](alias-dir/target.md)\n")
        result = self.run_check()
        self.assertEqual((result["result"], result["local_links"]), ("PASS", 2))
        self.assertEqual(result["markdown_files"], 3)

    def test_escaping_symlink_is_rejected(self):
        (self.repo / "bad-link").symlink_to("../outside")
        self.write("README.md", "[escape](bad-link/target.md)\n")
        self.assertEqual(self.run_check()["result"], "FAIL")

    def test_symlink_cycle_is_rejected(self):
        (self.repo / "a").symlink_to("b")
        (self.repo / "b").symlink_to("a")
        self.write("README.md", "[loop](a)\n")
        self.assertEqual(self.run_check()["result"], "FAIL")

    def test_non_utf8_markdown_fails_instead_of_skipping(self):
        (self.repo / "README.md").write_bytes(b"\xff\xfe")
        with self.assertRaises(UnicodeError):
            self.run_check()

    def test_changed_canonical_parser_fails_closed(self):
        self.write(checker.CHECKER, "# changed parser without the known grammar\n")
        self.write("README.md", "# Good\n")
        with self.assertRaises(checker.Invalid):
            self.run_check()

    def test_old_regex_in_comments_cannot_approve_changed_parser(self):
        original = (self.repo / checker.CHECKER).read_text()
        self.write(checker.CHECKER, original + "actual_links = re.findall('different grammar', text)\n")
        self.write("README.md", "# Good\n")
        self.assertIn(checker.FENCE, (self.repo / checker.CHECKER).read_text())
        self.assertIn(checker.INLINE, (self.repo / checker.CHECKER).read_text())
        with self.assertRaises(checker.Invalid):
            self.run_check()


if __name__ == "__main__":
    unittest.main(verbosity=2)
