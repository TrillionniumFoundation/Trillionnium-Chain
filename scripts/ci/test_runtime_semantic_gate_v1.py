#!/usr/bin/env python3
"""Small regressions for the semantic gate's non-false-pass behavior."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/check_runtime_semantic_gate_v1.py"


class RuntimeSemanticGateTests(unittest.TestCase):
    def run_gate(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        for name in ("TRNM_SEMANTIC_P01_COMMAND", "TRNM_SEMANTIC_P02_COMMAND", "TRNM_SEMANTIC_P03_COMMAND", "TRNM_SEMANTIC_P04_COMMAND"):
            merged.pop(name, None)
        if env:
            merged.update(env)
        return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=ROOT, text=True, capture_output=True, env=merged)

    def test_report_only_is_explicitly_not_run(self) -> None:
        result = self.run_gate()
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual(report["result"], "NOT_RUN")
        self.assertTrue(report["lexical_smoke_is_not_semantic_evidence"])

    def test_require_rejects_missing_runtime_commands(self) -> None:
        result = self.run_gate("--require")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["result"], "NOT_RUN")

    def test_execution_reports_actual_command_failure(self) -> None:
        result = self.run_gate("--run", env={"TRNM_SEMANTIC_P01_COMMAND": "python3 -c 'raise SystemExit(7)'"})
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual(report["result"], "FAIL")
        self.assertEqual(report["checks"][0]["returncode"], 7)


if __name__ == "__main__":
    unittest.main()
