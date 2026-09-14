#!/usr/bin/env python3
"""Exercise the preflight boundary, including its deliberately cheap edit path.

The fixture scripts record policy invocation, not actual protocol acceptance.
The real native-source/runner/offline validators remain separate CI families.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="trnm-preflight-")
        self.addCleanup(self.temp.cleanup)
        # Deliberately not the old mandatory checkout basename.
        self.root = Path(self.temp.name) / "any-checkout-name"
        self.root.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update(GIT_AUTHOR_NAME="fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                        GIT_COMMITTER_NAME="fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        self.git("init", "-q", "-b", "fix/chain-fixture")
        self.git("remote", "add", "origin", "https://github.com/TrillionniumFoundation/Trillionnium-Chain.git")
        self.write("PROJECT_ID", "trillionnium-chain\n")
        self.policy = json.loads((ROOT / "PROJECT_BOUNDARY.json").read_text())
        self.write("PROJECT_BOUNDARY.json", json.dumps(self.policy))
        self.write("scripts/project-preflight.sh", (ROOT / "scripts/project-preflight.sh").read_text())
        self.write("trillionnium/Cargo.toml", '[workspace]\nmembers = ["crates/trnm-consensus-core", "crates/trnm-poco-node"]\n')
        for name in ("trnm-consensus-core", "trnm-poco-node"):
            self.write(f"trillionnium/crates/{name}/Cargo.toml", f'[package]\nname="{name}"\nversion="0.1.0"\n')
        self.write("scripts/ci/check_native_consensus_only.py",
                   'from pathlib import Path\nPath("native-called").write_text("worktree")\n')
        self.write("scripts/check_cargo_offline_policy.sh",
                   '#!/bin/bash\nprintf "%s" "$1" > offline-called\nexit "${TEST_OFFLINE_RC:-0}"\n')
        # Invocation would prove the duplicate runner scan was reintroduced.
        self.write("scripts/check_ci_runner_policy.sh", '#!/bin/bash\nexit 99\n')
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, env=self.env,
                              check=True, capture_output=True, text=True).stdout

    def run_gate(self, mode="--dev", **env):
        return subprocess.run(["bash", "scripts/project-preflight.sh", mode],
                              cwd=self.root, env={**self.env, **env}, input="", text=True,
                              capture_output=True, timeout=45)

    def test_arbitrary_checkout_and_no_task_form(self):
        self.write("uncommitted-note.txt", "not a local authorization form")
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("full_ci_policy=not-run", result.stdout)
        self.assertFalse((self.root / "native-called").exists())
        self.assertFalse((self.root / "offline-called").exists())

    def test_audit_still_checks_native_and_offline_without_duplicate_runner(self):
        result = self.run_gate("--audit")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.root / "native-called").exists())
        self.assertEqual((self.root / "offline-called").read_text(), "--worktree")

    def test_audit_propagates_policy_failure(self):
        self.assertNotEqual(self.run_gate("--audit", TEST_OFFLINE_RC="7").returncode, 0)

    def test_staged_policy_reads_index_not_edited_worktree(self):
        self.policy["project_id"] = "other-project"
        self.write("PROJECT_BOUNDARY.json", json.dumps(self.policy))
        result = self.run_gate("--staged")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "offline-called").read_text(), "--staged")
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_remote_mismatch_still_blocks(self):
        self.git("remote", "set-url", "origin", "https://github.com/example/wrong.git")
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_protected_branch_still_blocks(self):
        self.git("branch", "-m", "main")
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_external_dependency_still_blocks(self):
        self.write("trillionnium/Cargo.toml", (self.root / "trillionnium/Cargo.toml").read_text()
                   + '\n[workspace.dependencies]\noutside = { path = "../../outside" }\n')
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_duplicate_policy_member_is_rejected(self):
        text = (self.root / "PROJECT_BOUNDARY.json").read_text()
        self.write("PROJECT_BOUNDARY.json", '{"project_id":"other",' + text[1:])
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_policy_record_separator_is_rejected(self):
        self.policy["lane"] = "chain-consensus\nother"
        self.write("PROJECT_BOUNDARY.json", json.dumps(self.policy))
        self.assertNotEqual(self.run_gate().returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
