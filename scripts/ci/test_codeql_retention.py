#!/usr/bin/env python3
"""Execute the real SARIF readback on control files, never a CodeQL qualification.

The workflow must retain parseable original files and exact-source receipts
without hiding analysis or source failures. These local controls do not run CodeQL or GitHub
Actions, produce a substitute SARIF, or qualify a remote security check.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/codeql-real-exact-source.yml"


def step(text, name):
    return text.split(f"      - name: {name}\n", 1)[1].split("\n      - name:", 1)[0]


def field(text, key):
    return re.search(rf"^          {re.escape(key)}: (.+)$", text, re.MULTILINE).group(1)


def shell_script(workflow, name, source="head"):
    script = step(workflow, name).split("        run: |\n", 1)[1]
    script = "\n".join(line[10:] for line in script.splitlines()) + "\n"
    return script.replace("${{ matrix.language }}", "python").replace("${{ matrix.source }}", source)


class CodeqlRetentionTests(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.verify = step(self.workflow, "Verify generated SARIF is present and parseable")
        self.script = shell_script(self.workflow, "Verify generated SARIF is present and parseable")

    def readback(self, directory):
        return subprocess.run(
            ["bash", "-c", self.script],
            env=dict(os.environ, SARIF_DIR=str(directory)),
            capture_output=True, text=True, check=False,
        )

    def test_failure_retention_does_not_hide_or_skip_real_analysis(self):
        analyze = step(self.workflow, "Generate local exact-source SARIF for exact source SHA")
        retain = step(self.workflow, "Retain exact-source local SARIF for independent review")
        self.assertIn("        id: codeql\n", analyze)
        self.assertIn("uses: github/codeql-action/analyze@1fc58d04a4d4374f921bdac573c3811c240f9c26", analyze)
        self.assertEqual(field(analyze, "upload"), "never")
        self.assertNotIn("continue-on-error", self.workflow)
        self.assertNotIn("skip-queries:", self.workflow)
        self.assertIn("        id: sarif_verify\n", self.verify)
        self.assertIn("        if: always() && steps.codeql.outcome != 'skipped'\n", self.verify)
        self.assertIn("if: ${{ always() && steps.sarif_verify.outcome == 'success' }}", retain)
        output = field(analyze, "output")
        self.assertEqual(field(self.verify, "SARIF_DIR"), output)
        self.assertEqual(field(retain, "path"), "|")
        self.assertIn("            " + output + "/*.sarif\n", retain)
        identity = "${{ runner.temp }}/codeql-identity/${{ matrix.language }}/${{ matrix.source }}/"
        self.assertIn("            " + identity + "\n", retain)
        self.assertEqual(field(retain, "if-no-files-found"), "error")
        self.assertNotIn("steps.codeql.outputs.sarif-output", self.verify + retain)
        self.assertIn("run: python3 -B scripts/ci/test_codeql_retention.py", self.workflow)

    def test_full_matrix_and_failed_source_outcomes_are_preserved(self):
        self.assertIn("language: [rust, python, actions]", self.workflow)
        self.assertIn("source: ${{ github.event_name == 'pull_request' && fromJSON('[\"head\",\"prospective-merge\"]') || fromJSON('[\"head\"]') }}", self.workflow)
        self.assertIn("if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository", self.workflow)
        before = step(self.workflow, "Refuse any other source identity")
        after = step(self.workflow, "Recheck exact source after analysis")
        record = step(self.workflow, "Record source and analysis outcomes")
        diagnostics = step(self.workflow, "Retain diagnostics when no valid SARIF was produced")
        self.assertIn("        id: source_before\n", before)
        self.assertIn("        id: source_after\n", after)
        self.assertIn("        if: always()\n", record)
        self.assertIn("SOURCE_BEFORE_OUTCOME: ${{ steps.source_before.outcome }}", record)
        self.assertIn("ANALYZE_OUTCOME: ${{ steps.codeql.outcome }}", record)
        self.assertIn("SARIF_VERIFY_OUTCOME: ${{ steps.sarif_verify.outcome }}", record)
        self.assertIn("SOURCE_AFTER_OUTCOME: ${{ steps.source_after.outcome }}", record)
        self.assertIn("if: ${{ always() && steps.sarif_verify.outcome != 'success' }}", diagnostics)
        self.assertTrue(field(diagnostics, "name").startswith("codeql-diagnostics-"))
        self.assertNotIn("codeql-results", diagnostics)
        for block in (before, after):
            self.assertIn("set -euo pipefail", block)
            self.assertNotIn("|| true", block)
            self.assertIn('--expected-base "$EXPECTED_BASE_SHA" --expected-merge "$EXPECTED_SOURCE_SHA"', block)
        self.assertIn('cmp "$identity/source-before.json" "$identity/source-after.json"', after)
        self.assertLess(self.workflow.index('      - name: Retain post-analysis worktree observations\n'),
                        self.workflow.index('      - name: Recheck exact source after analysis\n'))

    def test_existing_parseable_files_are_read_without_rewriting_or_synthesizing(self):
        with tempfile.TemporaryDirectory(prefix="trnm-sarif-readback-") as directory:
            root = Path(directory)
            for name in ("python.sarif", "second.sarif"):
                (root / name).write_text(json.dumps({
                    "version": "2.1.0",
                    "runs": [{"tool": {"driver": {"name": "fixture-only"}}, "results": []}],
                }) + "\n", encoding="utf-8")
            before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}
            result = self.readback(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CODEQL_SARIF_FILES=2", result.stdout)
            self.assertEqual(before, {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()
            })

    def test_missing_original_output_is_explicit_failure_without_a_replacement(self):
        with tempfile.TemporaryDirectory(prefix="trnm-sarif-missing-") as directory:
            root = Path(directory)
            for candidate in (root / "absent", root):
                with self.subTest(candidate=candidate.name):
                    result = self.readback(candidate)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("CODEQL_SARIF_MISSING", result.stderr)
                    self.assertEqual(list(root.iterdir()), [])

    def test_malformed_or_incomplete_file_refuses_the_whole_set(self):
        controls = [b"{", b"null", b"[]", b"{}", b'{"version":"2.1.0","runs":[]}',
                    b'{"version":"2.0.0","runs":[{}]}',
                    b'{"version":"2.1.0","runs":{}}']
        for bad in controls:
            with self.subTest(bad=bad), tempfile.TemporaryDirectory(prefix="trnm-sarif-invalid-") as directory:
                root = Path(directory)
                (root / "valid.sarif").write_text('{"version":"2.1.0","runs":[{}]}\n')
                original = root / "invalid.sarif"
                original.write_bytes(bad)
                result = self.readback(root)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn("CODEQL_SARIF_FILES=", result.stdout)
                self.assertEqual(original.read_bytes(), bad)
                self.assertEqual(sorted(p.name for p in root.iterdir()), ["invalid.sarif", "valid.sarif"])


class CodeqlSourceIdentityTests(unittest.TestCase):
    """Run the actual workflow source shell with the retained verifier and real Git."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="trnm-codeql-source-")
        self.addCleanup(temporary.cleanup)
        self.area = Path(temporary.name)
        self.checkout = self.area / "repo"
        self.output = self.area / "receipts"
        (self.checkout / "scripts/ci").mkdir(parents=True)
        self.output.mkdir()
        shutil.copyfile(ROOT / "scripts/ci/verify_ci_source.py",
                        self.checkout / "scripts/ci/verify_ci_source.py")
        self.git("init", "-q", "-b", "base")
        self.git("config", "user.name", "CodeQL source fixture")
        self.git("config", "user.email", "source-fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.source = self.checkout / "actual.py"
        self.source.write_text("value = 'base'\n")
        self.git("add", ".")
        self.git("commit", "-qm", "base fixture")
        self.base = self.git("rev-parse", "HEAD")
        self.git("checkout", "-qb", "candidate")
        self.source.write_text("value = 'candidate'\n")
        self.git("commit", "-qam", "candidate fixture")
        self.head = self.git("rev-parse", "HEAD")
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.env = dict(os.environ, RUNNER_TEMP=str(self.output),
                        PYTHONDONTWRITEBYTECODE="1", GITHUB_SHA=self.head,
                        EXPECTED_SOURCE_SHA=self.head, EXPECTED_CANDIDATE_SHA=self.head,
                        EXPECTED_BASE_SHA=self.base, SOURCE_KIND="head")

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.checkout,
                                       text=True, stderr=subprocess.DEVNULL).strip()

    def run_step(self, name):
        command = shell_script(self.workflow, name, self.env["SOURCE_KIND"])
        return subprocess.run(["bash", "-euo", "pipefail", "-c", command],
                              cwd=self.checkout, env=self.env, capture_output=True,
                              text=True, check=False)

    def identity(self, filename):
        return self.output / "codeql-identity/python" / self.env["SOURCE_KIND"] / filename

    def before(self):
        result = self.run_step("Refuse any other source identity")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unchanged_head_produces_identical_deterministic_receipts(self):
        self.before()
        result = self.run_step("Recheck exact source after analysis")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        initial = self.identity("source-before.json").read_bytes()
        self.assertEqual(initial, self.identity("source-after.json").read_bytes())
        value = json.loads(initial)
        self.assertEqual(value["tested_commit"], self.head)
        self.assertTrue(value["tracked_worktree_verified"])
        self.assertFalse(value["tests_executed_by_identity_check"])

    def test_changed_tracked_bytes_fail_after_check_and_preserve_before_record(self):
        self.before()
        initial = self.identity("source-before.json").read_bytes()
        self.source.write_text("value = 'tampered'\n")
        result = self.run_step("Recheck exact source after analysis")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(initial, self.identity("source-before.json").read_bytes())
        self.assertFalse(self.identity("source-after.json").exists())
        self.assertIn("source is not clean", self.identity("source-after.log").read_text())

    def test_changed_before_receipt_fails_cmp_even_with_unchanged_source(self):
        self.before()
        value = json.loads(self.identity("source-before.json").read_text())
        value["tested_commit"] = "0" * 40
        self.identity("source-before.json").write_text(json.dumps(value) + "\n")
        result = self.run_step("Recheck exact source after analysis")
        self.assertNotEqual(result.returncode, 0)
        actual = json.loads(self.identity("source-after.json").read_text())
        self.assertEqual(actual["tested_commit"], self.head)
        self.assertTrue(self.identity("source-comparison.log").read_text())

    def test_worktree_observations_retain_dirty_paths_without_waiving_after_check(self):
        self.before()
        initial = self.identity("source-before.json").read_bytes()
        untracked_name = "untracked file\nwith newline.py"
        (self.checkout / untracked_name).write_text("value = 'untracked'\n")
        self.source.write_text("value = 'modified'\n")
        for tracked_modified in (True, False):
            with self.subTest(tracked_modified=tracked_modified):
                if not tracked_modified:
                    self.git("checkout", "--", "actual.py")
                observation = self.run_step("Retain post-analysis worktree observations")
                self.assertEqual(observation.returncode, 0, observation.stdout + observation.stderr)
                status = self.identity("worktree-status.z").read_bytes().split(b"\0")
                self.assertEqual(status[-1], b"")
                self.assertIn(b"?? " + untracked_name.encode(), status)
                names = self.identity("worktree-diff-names.z").read_bytes()
                stats = self.identity("worktree-diff-stat.txt").read_bytes()
                if tracked_modified:
                    self.assertIn(b" M actual.py", status)
                    self.assertEqual(names, b"M\0actual.py\0")
                    self.assertIn(b"actual.py", stats)
                else:
                    self.assertEqual(status, [b"?? " + untracked_name.encode(), b""])
                    self.assertEqual(names, b"")
                    self.assertEqual(stats, b"")
                result = self.run_step("Recheck exact source after analysis")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(initial, self.identity("source-before.json").read_bytes())
                self.assertFalse(self.identity("source-after.json").exists())
                self.assertIn("source is not clean", self.identity("source-after.log").read_text())

    def select_merge(self, reverse=False):
        parents = (self.head, self.base) if reverse else (self.base, self.head)
        tree = self.git("rev-parse", self.head + "^{tree}")
        merged = self.git("commit-tree", tree, "-p", parents[0], "-p", parents[1],
                          "-m", "prospective merge fixture")
        self.git("checkout", "-q", "--detach", merged)
        self.env.update(EXPECTED_SOURCE_SHA=merged, GITHUB_SHA=merged,
                        SOURCE_KIND="prospective-merge")
        return merged

    def test_exact_ordered_prospective_merge_is_checked_before_and_after(self):
        merged = self.select_merge()
        self.before()
        result = self.run_step("Recheck exact source after analysis")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(self.identity("source-after.json").read_text())
        self.assertEqual((value["base"], value["candidate"], value["prospective_merge"]),
                         (self.base, self.head, merged))
        self.assertEqual(self.identity("source-before.json").read_bytes(),
                         self.identity("source-after.json").read_bytes())

    def test_reversed_merge_parents_refuse_before_analysis(self):
        self.select_merge(reverse=True)
        result = self.run_step("Refuse any other source identity")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.identity("source-before.json").exists())
        self.assertIn("merge parents differ", self.identity("source-before.log").read_text())

    def test_outcome_record_preserves_analysis_and_source_failure_states(self):
        stages = ("source_before", "retention_controls", "initialize", "analyze",
                  "sarif_verify", "source_after")
        for failed in ("source_before", "analyze", "sarif_verify", "source_after"):
            with self.subTest(failed=failed):
                outcomes = {stage: "failure" if stage == failed else "skipped" for stage in stages}
                self.env.update({stage.upper() + "_OUTCOME": value for stage, value in outcomes.items()})
                self.env.update(IDENTITY_DIR=str(self.identity("step-outcomes.json").parent),
                                CODEQL_LANGUAGE="python")
                result = self.run_step("Record source and analysis outcomes")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                value = json.loads(self.identity("step-outcomes.json").read_text())
                self.assertEqual(value["outcomes"], outcomes)
                self.assertEqual(value["code_scanning_upload"], "never")
                self.assertEqual(value["expected_source_commit"], self.head)


if __name__ == "__main__":
    unittest.main(verbosity=2)
