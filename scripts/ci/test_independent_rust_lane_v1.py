#!/usr/bin/env python3
"""Real subprocess/Git tests of orchestration; no Rust execution is simulated as acceptance."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("independent_lane", Path(__file__).with_name("run_independent_rust_lane_v1.py"))
lane = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lane)


class IndependentLaneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.top = Path(self.temp.name)
        self.root = self.top / "repo"
        self.root.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Lane Test")
        self.git("config", "user.email", "lane@example.invalid")
        (self.root / "input").write_text("base")
        self.git("add", "input")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")
        (self.root / "input").write_text("head")
        self.git("commit", "-qam", "head")
        self.head = self.git("rev-parse", "HEAD")
        self.tree = self.git("rev-parse", "HEAD^{tree}")
        self.merge = self.git("commit-tree", self.tree, "-p", self.base, "-p", self.head, "-m", "merge")
        self.evidence = self.top / "evidence"

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True, stderr=subprocess.DEVNULL).strip()

    def confirm(self):
        return lane.identity(self.root, "head", self.head, self.base, self.merge)

    def arguments(self):
        return ["--lane", "build", "--mode", "head", "--head", self.head, "--base", self.base,
                "--merge", self.merge, "--root", str(self.root), "--evidence-dir", str(self.evidence)]

    def run_plan(self, plan):
        with patch.object(lane, "commands", return_value=plan), contextlib.redirect_stdout(io.StringIO()):
            code = lane.main(self.arguments())
        return code, json.loads((self.evidence / "summary.json").read_text())

    def python(self, text):
        return [sys.executable, "-S", "-c", text]

    def test_exact_head_and_real_ordered_merge(self):
        self.assertEqual(self.confirm()["source"], self.head)
        self.git("checkout", "-q", "--detach", self.merge)
        result = lane.identity(self.root, "merge", self.head, self.base, self.merge)
        self.assertEqual(result["parents"], f"{self.base} {self.head}")
        self.assertEqual(result["tree"], self.tree)

    def test_swapped_merge_parents_rejected_even_with_identical_tree(self):
        swapped = self.git("commit-tree", self.tree, "-p", self.head, "-p", self.base, "-m", "wrong parents")
        self.git("checkout", "-q", "--detach", swapped)
        with self.assertRaises(lane.LaneError):
            lane.identity(self.root, "merge", self.head, self.base, swapped)

    def test_wrong_source_pin_and_malformed_pin_reject(self):
        for head in ("0" * 40, "main", "", "a" * 39):
            with self.subTest(head=head), self.assertRaises(lane.LaneError):
                lane.identity(self.root, "head", head, self.base, self.merge)

    def test_dirty_or_untracked_source_refuses_before_evidence_creation(self):
        (self.root / "untracked").write_text("change")
        with self.assertRaises(lane.LaneError):
            lane.main(self.arguments())
        self.assertFalse(self.evidence.exists())

    def test_failure_does_not_skip_lint_or_get_replaced_by_success(self):
        code, summary = self.run_plan([("test", self.python("raise SystemExit(23)"), 5),
                                       ("lint", self.python("print('lint executed')"), 5)])
        self.assertEqual(code, 23)
        self.assertEqual([row["status"] for row in summary["commands"]], ["failed", "passed"])
        self.assertEqual(summary["status"], "failed")
        self.assertIn("lint executed", (self.evidence / "lint.log").read_text())

    def test_timeout_does_not_skip_lint_or_extend_original_deadline(self):
        code, summary = self.run_plan([("test", self.python("import time; print('start', flush=True); time.sleep(30)"), 0.1),
                                       ("lint", self.python("print('lint executed')"), 5)])
        self.assertEqual(code, 124)
        self.assertEqual(summary["commands"][1]["status"], "passed")
        self.assertLess(summary["commands"][0]["elapsed_ms"], 5000)

    def test_nonzero_command_cannot_claim_success_by_printing_a_summary(self):
        code, summary = self.run_plan([("test", self.python("print('test result: ok.'); raise SystemExit(9)"), 5)])
        self.assertEqual(code, 9)
        self.assertEqual(summary["status"], "failed")

    def test_complete_plan_is_checkpointed_before_first_command(self):
        command = self.python(f"import json; d=json.load(open({str(self.evidence / 'summary.json')!r})); "
                              "assert d['status']=='failed'; assert len(d['commands'])==2; "
                              "assert d['commands'][0]['status']=='running'; assert d['commands'][1]['status']=='not-run'")
        code, summary = self.run_plan([("inspect", command, 5), ("last", self.python("pass"), 5)])
        self.assertEqual(code, 0)
        self.assertFalse(summary["acceptance_authority"])
        self.assertEqual(len(summary["commands"][0]["log_sha256"]), 64)

    def test_source_drift_aborts_remaining_commands(self):
        code, summary = self.run_plan([("mutate", self.python("open('input','w').write('changed')"), 5),
                                       ("never", self.python("pass"), 5)])
        self.assertNotEqual(code, 0)
        self.assertEqual(summary["commands"][1]["status"], "not-run")
        self.assertFalse((self.evidence / "never.log").exists())

    def test_missing_executable_fails_but_independent_command_still_runs(self):
        code, summary = self.run_plan([("missing", [str(self.top / "missing")], 5),
                                       ("lint", self.python("pass"), 5)])
        self.assertNotEqual(code, 0)
        self.assertEqual(summary["commands"][1]["status"], "passed")

    def test_previous_evidence_is_never_overwritten(self):
        self.evidence.mkdir()
        original = self.evidence / "original"
        original.write_text("retained")
        with self.assertRaises(FileExistsError):
            lane.main(self.arguments())
        self.assertEqual(original.read_text(), "retained")

    def test_evidence_inside_source_is_rejected(self):
        arguments = self.arguments()
        arguments[-1] = str(self.root / "evidence")
        with self.assertRaises(lane.LaneError):
            lane.main(arguments)
        self.assertFalse((self.root / "evidence").exists())

    def test_empty_and_duplicate_command_plans_fail(self):
        for plan in ([], [("same", self.python("pass"), 5)] * 2):
            with self.subTest(plan=plan):
                evidence = self.top / ("empty" if not plan else "duplicate")
                arguments = self.arguments()
                arguments[-1] = str(evidence)
                with patch.object(lane, "commands", return_value=plan):
                    self.assertNotEqual(lane.main(arguments), 0)
                self.assertEqual(json.loads((evidence / "summary.json").read_text())["status"], "failed")

    def test_existing_shard_suites_and_case_deadlines_are_reused(self):
        for name, seconds in (("native", "900"), ("safety-epoch", "900"), ("node-epoch", "300")):
            plan = lane.commands(name, self.evidence)
            shard = next(item for item in plan if item[0] == "shards")
            self.assertIn("scripts/ci/run_native_candidate_shards_v1.py", shard[1])
            self.assertEqual(shard[1][-1], seconds)
            self.assertEqual(shard[1][shard[1].index("--suite") + 1], name)
            self.assertEqual(plan[-1][0], "strict-clippy")
            self.assertEqual(plan[-1][1][-3:], ["--", "-D", "warnings"])

    def test_all_lanes_have_finite_unique_command_plans(self):
        for name in lane.LANES:
            plan = lane.commands(name, self.evidence)
            self.assertEqual(len(plan), len({row[0] for row in plan}))
            self.assertTrue(all(0 < row[2] <= 10800 for row in plan))
            for _, argv, _ in plan:
                self.assertNotIn("--release", argv)
                self.assertNotIn("--ignored", argv)

    def test_log_overproduction_is_failure(self):
        result = lane.run_command(self.python("print('x'*8192)"), self.root, os.environ.copy(),
                                  self.top / "limited.log", 5, max_bytes=4096)
        self.assertEqual(result, 125)

    def test_owned_descendant_is_cleaned_after_parent_exits(self):
        pid_file = self.top / "child.pid"
        program = ("import subprocess,sys; p=subprocess.Popen([sys.executable,'-S','-c','import time; time.sleep(30)'], "
                   f"stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); open({str(pid_file)!r},'w').write(str(p.pid))")
        result = lane.run_command(self.python(program), self.root, os.environ.copy(), self.top / "parent.log", 5)
        self.assertEqual(result, 0)
        pid = int(pid_file.read_text())
        stat = Path(f"/proc/{pid}/stat")
        if stat.exists():
            self.assertEqual(stat.read_text().split(")", 1)[1].split()[0], "Z")


if __name__ == "__main__":
    unittest.main()
