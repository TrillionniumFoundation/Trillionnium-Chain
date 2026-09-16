#!/usr/bin/env python3
"""Regressions for runtime semantic evidence and false-pass resistance."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/check_runtime_semantic_gate_v1.py"
COMMAND_ENVS = tuple(f"TRNM_SEMANTIC_P0{index}_COMMAND" for index in range(1, 5))
EVIDENCE_ENVS = tuple(f"TRNM_SEMANTIC_P0{index}_EVIDENCE" for index in range(1, 5))


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


class RuntimeSemanticGateTests(unittest.TestCase):
    def run_gate(
        self, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        for name in (*COMMAND_ENVS, *EVIDENCE_ENVS):
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
        self.assertTrue(report["lexical_smoke_is_not_semantic_evidence"])
        self.assertTrue(report["zero_exit_is_not_semantic_evidence"])

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
        self.assertEqual(report["checks"][0]["evidence_status"], "not-configured")

    def test_four_true_commands_cannot_create_semantic_pass(self) -> None:
        result = self.run_gate(
            "--run",
            "--require",
            env={name: "true" for name in COMMAND_ENVS},
        )
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(report["result"], "FAIL")
        self.assertEqual(report["executed_count"], 4)
        self.assertEqual(report["evidence_verified_count"], 0)
        self.assertEqual(len(report["required_missing"]), 4)
        self.assertTrue(
            all(row["status"] == "failed-evidence-missing" for row in report["checks"])
        )

    def test_valid_source_bound_p01_evidence_can_pass_only_its_check(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trnm-semantic-evidence-") as directory:
            root = Path(directory)
            artifacts: list[dict[str, object]] = []
            for role in ("process_logs", "signed_final_state", "replay_verification"):
                path = root / f"{role}.json"
                payload = json.dumps({"role": role, "fact": "fixture"}, sort_keys=True).encode()
                path.write_bytes(payload)
                artifacts.append(
                    {
                        "role": role,
                        "path": path.name,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "bytes": len(payload),
                    }
                )
            evidence = {
                "schema": "trnm-runtime-semantic-evidence-v1",
                "check_id": "P0.1-multinode-persistence",
                "status": "PASS",
                "production_authority": False,
                "source_commit": git_output("rev-parse", "HEAD"),
                "source_tree": git_output("rev-parse", "HEAD^{tree}"),
                "claims": {
                    "validator_processes": 7,
                    "independent_run_roots": 7,
                    "four_node_phase": True,
                    "seven_node_phase": True,
                    "kill_restart_rejoin": True,
                    "partition_heal": True,
                    "lost_reply_recovery": True,
                    "durable_state_replay_verified": True,
                    "finality_agreement": True,
                },
                "artifacts": artifacts,
            }
            evidence_path = root / "p01.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            result = self.run_gate(
                "--run",
                env={
                    "TRNM_SEMANTIC_P01_COMMAND": "true",
                    "TRNM_SEMANTIC_P01_EVIDENCE": str(evidence_path),
                },
            )
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual(report["result"], "INCOMPLETE")
        self.assertEqual(report["checks"][0]["status"], "passed")
        self.assertEqual(report["checks"][0]["evidence_status"], "verified")
        self.assertEqual(report["evidence_verified_count"], 1)
        self.assertEqual(len(report["required_missing"]), 3)


if __name__ == "__main__":
    unittest.main()
