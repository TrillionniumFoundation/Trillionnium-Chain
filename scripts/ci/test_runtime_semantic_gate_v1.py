#!/usr/bin/env python3
"""Regressions for the runtime semantic gate's non-false-pass behavior."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/check_runtime_semantic_gate_v1.py"
ENV_NAMES = (
    "TRNM_SEMANTIC_P01_COMMAND",
    "TRNM_SEMANTIC_P02_COMMAND",
    "TRNM_SEMANTIC_P03_COMMAND",
    "TRNM_SEMANTIC_P04_COMMAND",
    "TRNM_SEMANTIC_P01_EVIDENCE",
    "TRNM_SEMANTIC_P02_EVIDENCE",
    "TRNM_SEMANTIC_P03_EVIDENCE",
    "TRNM_SEMANTIC_P04_EVIDENCE",
)


class RuntimeSemanticGateTests(unittest.TestCase):
    def run_gate(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        for name in ENV_NAMES:
            merged.pop(name, None)
        if env:
            merged.update(env)
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            env=merged,
        )

    def test_report_only_is_explicitly_not_run(self) -> None:
        result = self.run_gate()
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual(report["result"], "NOT_RUN")
        self.assertTrue(report["command_success_is_not_semantic_evidence"])

    def test_require_rejects_missing_runtime_commands(self) -> None:
        result = self.run_gate("--require")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["result"], "NOT_RUN")

    def test_execution_reports_actual_command_failure(self) -> None:
        result = self.run_gate(
            "--run",
            env={"TRNM_SEMANTIC_P01_COMMAND": "python3 -c 'raise SystemExit(7)'"},
        )
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual(report["result"], "FAIL")
        self.assertEqual(report["checks"][0]["returncode"], 7)

    def test_true_commands_cannot_create_semantic_pass(self) -> None:
        env = {
            "TRNM_SEMANTIC_P01_COMMAND": "true",
            "TRNM_SEMANTIC_P02_COMMAND": "true",
            "TRNM_SEMANTIC_P03_COMMAND": "true",
            "TRNM_SEMANTIC_P04_COMMAND": "true",
        }
        result = self.run_gate("--run", "--require", env=env)
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(report["result"], "INCOMPLETE")
        self.assertEqual(report["evidence_accepted_count"], 0)
        self.assertTrue(all(check["status"] == "evidence-missing" for check in report["checks"]))

    def test_source_bound_p01_evidence_is_accepted_for_its_check_only(self) -> None:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
        ).stdout.strip()
        evidence = {
            "schema": "trnm-runtime-semantic-evidence-v1",
            "check_id": "P0.1-multinode-persistence",
            "evidence_kind": "multinode-persistence-campaign",
            "source_commit": head,
            "result": "PASS",
            "production_authority": False,
            "raw_artifact_sha256": "1" * 64,
            "validator_counts": [4, 7],
            "independent_processes": True,
            "distinct_runtime_roots": True,
            "kill_restart_completed": True,
            "partition_heal_completed": True,
            "rejoin_completed": True,
            "durable_state_replay_verified": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "p01.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            result = self.run_gate(
                "--run",
                env={
                    "TRNM_SEMANTIC_P01_COMMAND": "true",
                    "TRNM_SEMANTIC_P01_EVIDENCE": str(path),
                },
            )
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual(report["checks"][0]["status"], "passed")
        self.assertEqual(report["result"], "INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
