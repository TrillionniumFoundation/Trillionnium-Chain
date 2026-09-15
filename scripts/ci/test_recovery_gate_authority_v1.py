#!/usr/bin/env python3
"""Exercise real recovery metadata checks; no Cargo or full-CI pass is implied."""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PAYLOAD = "scripts/ci/check_payload_replay_recovery_v1.sh"
CORE = "scripts/ci/check_replay_to_core_r2b_contract_v1.sh"
PLAN = "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
TRUTH = "config/consensus-mainline.json"
TRAIN = "docs/development/release-train-v1.toml"
MODULES = "docs/development/module-registry-v1.toml"
CORE_ARGS = [
    "trillionnium/crates/trnm-poco-node/src/bin/trnm-poco-replay-to-core-coordinator-v1.rs",
    "trillionnium/crates/trnm-poco-node/Cargo.toml",
    ".github/workflows/trnm-replay-to-core-coordinator-v1.yml",
    TRUTH, PLAN, MODULES, TRAIN,
]


def body(source: str) -> str:
    match = re.search(r"(?m)^python3 .*<<'PY'\n(.*?)\nPY$", source, re.S)
    if match is None:
        raise ValueError("expected one real Python recovery metadata block")
    return match[1]


class RecoveryMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="trnm-recovery-metadata-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        needed = set(CORE_ARGS + [PAYLOAD, CORE])
        for value in re.findall(r'Path\("([^"\n]+)"\)', body((ROOT / PAYLOAD).read_text())):
            needed.add(value)
        for relative in needed:
            source = ROOT / relative
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, target, dirs_exist_ok=True)
            else:
                shutil.copy2(source, target)

    def run_gate(self, script: str, source: str | None = None):
        text = source if source is not None else (ROOT / script).read_text()
        args = CORE_ARGS if script == CORE else []
        return subprocess.run(
            [sys.executable, "-c", body(text), *args], cwd=self.root,
            text=True, capture_output=True, timeout=20, check=False,
        )

    def assert_both(self, passed: bool):
        for script in [PAYLOAD, CORE]:
            result = self.run_gate(script)
            self.assertEqual(result.returncode == 0, passed,
                             f"{script}: {result.stdout}\n{result.stderr}")

    def truth(self, key: str, value):
        path = self.root / TRUTH
        data = json.loads(path.read_text())
        data[key] = value
        path.write_text(json.dumps(data))

    def test_actual_condensed_plan_passes_metadata_without_old_magic_words(self):
        self.assert_both(True)

    def test_activation_prose_cannot_override_true_machine_flag(self):
        (self.root / PLAN).write_text("payload replay; node commit ledger; exact source; "
                                     "production_candidate = false; no machine flag is promoted; whole-node replay")
        self.truth("production_candidate", True)
        self.assert_both(False)

    def test_activation_rejects(self):
        self.truth("production_consensus_activation", True)
        self.assert_both(False)

    def test_null_false_is_not_boolean_false(self):
        self.truth("production_candidate", None)
        self.assert_both(False)

    def test_string_false_is_not_boolean_false(self):
        self.truth("production_candidate", "false")
        self.assert_both(False)

    def test_missing_authority_flag_rejects(self):
        path = self.root / TRUTH; data = json.loads(path.read_text())
        del data["production_candidate"]; path.write_text(json.dumps(data))
        self.assert_both(False)

    def test_duplicate_machine_members_reject(self):
        path = self.root / TRUTH; text = path.read_text()
        path.write_text('{"production_candidate":false,' + text.lstrip()[1:])
        self.assert_both(False)

    def test_changed_stage_rejects(self):
        self.truth("stage", "accepted-production")
        self.assert_both(False)

    def test_release_projection_promotion_rejects(self):
        path = self.root / TRAIN
        path.write_text(path.read_text().replace("release_ready = false", "release_ready = true"))
        self.assert_both(False)

    def test_required_recovery_owner_is_not_optional(self):
        path = self.root / MODULES
        text = path.read_text(); self.assertIn('id = "M08"', text)
        path.write_text(text.replace('id = "M08"', 'id = "M99"'))
        self.assert_both(False)

    def test_socket_feature_fence_rejects(self):
        path = self.root / "trillionnium/crates/trnm-consensus-peer-lease/Cargo.toml"
        text = path.read_text(); self.assertIn("default = []", text)
        path.write_text(text.replace("default = []", 'default = ["candidate-recovery-socket"]'))
        self.assertNotEqual(self.run_gate(PAYLOAD).returncode, 0)

    def test_node_commit_blocker_cannot_disappear(self):
        path = self.root / TRAIN; text = path.read_text()
        self.assertIn('id = "NODE-COMMIT-001"', text)
        path.write_text(text.replace('id = "NODE-COMMIT-001"', 'id = "REMOVED"'))
        self.assertNotEqual(self.run_gate(CORE).returncode, 0)

    def test_original_baseline_reproduces_the_stale_prose_failure(self):
        for script in [PAYLOAD, CORE]:
            source = subprocess.run(
                ["git", "show", "95d0a0bd6feee6fb841263c79a8ab39d936b8153:" + script],
                cwd=ROOT, check=True, capture_output=True, text=True,
            ).stdout
            result = self.run_gate(script, source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("canonical plan missing", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
