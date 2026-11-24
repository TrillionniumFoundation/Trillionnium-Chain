"""No workflow, generic PASS marker, or synthetic evidence may substitute for actual M15."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hia.tools import qualify_release_pq_ci as q


class ReleasePqHostedEvidence(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        h, t = subprocess.check_output(
            ["git", "show", "-s", "--format=%H %T"], cwd=q.ROOT, text=True).split()
        self.tip, self.tree = h, t
        self.enterContext(patch.dict(os.environ, {
            "TRNM_EXPECTED_SOURCE_SHA": h, "GITHUB_RUN_ID": "4201", "GITHUB_RUN_ATTEMPT": "2",
            "HIA_NATIVE_COMPILER_SHA256": q.PIN,
        }))
        self.probe = {"schema": "trnm-ci-source-v1", "kind": "head", "candidate": h,
                      "tested_commit": h, "tested_tree": t, "tracked_worktree_verified": True,
                      "tests_executed_by_identity_check": False, "tracked_bytes": 1, "tracked_entries": 1}

    def source(self):
        q.save(self.root / "source-before.json", self.probe)
        q.save(self.root / "source-after.json", self.probe)

    def test_scope_and_attempt_are_strict(self):
        self.source()
        changed = {**self.probe, "tracked_worktree_verified": 1}
        q.save(self.root / "source-before.json", changed)
        with self.assertRaisesRegex(ValueError, "full source identity"):
            q.source(self.root / "source-before.json", q.lineage())
        with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "02"}):
            with self.assertRaisesRegex(ValueError, "run/attempt"):
                q.lineage()

    def test_only_real_qualifier_is_invoked_generic_stdout_never_passes(self):
        self.source()
        fake = subprocess.CompletedProcess([], 0, b'{"status":"PASS"}\n', b"")
        with (patch.object(q.subprocess, "check_output", return_value=f"{self.tip} {self.tree}".encode()),
              patch.object(q.subprocess, "run", return_value=fake) as processes):
            with self.assertRaisesRegex(ValueError, "actual Release PQ qualifier"):
                q.run(self.root / "work", self.root)
        self.assertEqual([c.args[0][4] for c in processes.call_args_list],
                         [q.script(stage) for stage in q.STAGES])
        for stage in q.STAGES:
            record = q.obj(self.root / stage / "process.json")
            self.assertEqual(record["returncode"], 0)
            self.assertEqual(record["missing"], list(q.stage_files(stage)))
        with self.assertRaisesRegex(ValueError, "execution failed"):
            q.validate_stage(self.root / "callback", "callback", q.lineage(), self.tree, "a" * 64)
        self.assertFalse((self.root / "readback.json").exists())

    def test_later_source_disagreement_refuses_before_fixture_status(self):
        self.source()
        q.save(self.root / "source-after.json", {**self.probe, "tested_tree": "1" * 40})
        with self.assertRaisesRegex(ValueError, "source changed"):
            q.validate(self.root)

    def test_generic_readback_fixture_and_bad_roster_refuse(self):
        self.source()
        q.save(self.root / "bootstrap.json", {"status": "PASS", "compiler_sha256": q.PIN,
                                            "raw_bootstrap_sha256": "a" * 64})
        q.save(self.root / "readback.json", {"status": "PASS", "head": self.tip})
        with self.assertRaisesRegex(ValueError, "unlinked regular evidence"):
            q.validate(self.root)
        with self.assertRaisesRegex(ValueError, "incomplete actual case"):
            q.roster([{"case": "valid", "status": 0}], "case", "status", q.CASES["quorum"], ())
        with self.assertRaisesRegex(ValueError, "identity or status"):
            q.roster([{"case": "valid", "status": False}], "case", "status", (("valid", 0),), ())

    def test_link_and_size_fail_closed(self):
        outside = self.root / "tiny.json"
        outside.write_bytes(b"{}")
        alias = self.root / "alias.json"
        alias.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "unlinked"):
            q.obj(alias)
        oversized = self.root / "big"
        with oversized.open("wb") as file:
            file.truncate(q.MAX_LEAF + 1)
        with self.assertRaisesRegex(ValueError, "extent exceeded"):
            q.read(oversized)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            q.exact_json(b'{"status":"FAIL","status":"PASS"}')

    def test_workflow_has_a_separate_read_only_bounded_owner_and_real_commands(self):
        workflow = (q.ROOT / ".github/workflows/hia-native-migration.yml").read_text()
        job = workflow.split("\n  native-release-pq:\n", 1)[1].split("\n  native-components-readback:", 1)[0]
        self.assertRegex(workflow, r"permissions:\n  contents: read\n")
        self.assertNotRegex(job, r"(?m)^\s*(?:continue-on-error|permissions|strategy):")
        self.assertIn("timeout-minutes: 20", job)
        self.assertIn("ref: ${{ env.TRNM_EXPECTED_SOURCE_SHA }}", job)
        self.assertIn("ref: f33d8da316de8fdf27b504371f1a5310997ff548", job)
        self.assertEqual(job.count("persist-credentials: false"), 2)
        self.assertIn("rustup toolchain install 1.95.0 --profile minimal", job)
        self.assertIn("cargo fetch --locked", job)
        for mode in ("bootstrap", "run", "verify"):
            self.assertIn(f"python3 -I -S -B hia/tools/qualify_release_pq_ci.py {mode}", job)
        self.assertIn("source-before.json", job)
        self.assertIn("source-after.json", job)
        self.assertIn("path: ${{ runner.temp }}/hia-release-pq-artifact/", job)
        self.assertNotIn("hia-release-pq-work/", job)
        self.assertIn("test_release_pq_hosted_evidence.py", job)
        self.assertIn("if: always()", job)
        self.assertTrue(re.search(r"run_id.*run_attempt", job))


if __name__ == "__main__":
    unittest.main()
