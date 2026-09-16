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


def artifact(role: str, path: Path, base: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "role": role,
        "path": os.path.relpath(path, base),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def envelope(check_id: str, artifacts: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema": "trnm-runtime-semantic-evidence-v2",
        "check_id": check_id,
        "production_authority": False,
        "source_commit": git_output("rev-parse", "HEAD"),
        "source_tree": git_output("rev-parse", "HEAD^{tree}"),
        "artifacts": artifacts,
    }


class RuntimeSemanticGateTests(unittest.TestCase):
    def run_gate(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        for name in (*COMMAND_ENVS, *EVIDENCE_ENVS):
            merged.pop(name, None)
        if env:
            merged.update(env)
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args], cwd=ROOT, text=True,
            capture_output=True, env=merged,
        )

    def test_report_only_is_explicitly_not_run(self) -> None:
        result = self.run_gate()
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual(report["result"], "NOT_RUN")
        self.assertTrue(report["lexical_smoke_is_not_semantic_evidence"])
        self.assertTrue(report["zero_exit_is_not_semantic_evidence"])

    def test_four_true_commands_cannot_create_semantic_pass(self) -> None:
        result = self.run_gate("--run", "--require", env={name: "true" for name in COMMAND_ENVS})
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(report["result"], "FAIL")
        self.assertEqual(report["evidence_verified_count"], 0)
        self.assertEqual(len(report["required_missing"]), 4)

    def test_self_authored_claims_are_forbidden_even_with_matching_hashes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trnm-semantic-false-pass-") as directory:
            root = Path(directory)
            fake = root / "fake.json"
            fake.write_text('{"fake":true}\n', encoding="utf-8")
            evidence = envelope("P0.1-multinode-persistence", [artifact("process_logs", fake, root)])
            evidence["status"] = "PASS"
            evidence["claims"] = {"validator_processes": 7, "finality_agreement": True}
            evidence_path = root / "evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            result = self.run_gate(
                "--run",
                env={"TRNM_SEMANTIC_P01_COMMAND": "true", "TRNM_SEMANTIC_P01_EVIDENCE": str(evidence_path)},
            )
        report = json.loads(result.stdout)
        self.assertEqual(report["checks"][0]["status"], "failed-evidence-invalid")
        self.assertIn("status/claims fields are forbidden", report["checks"][0]["evidence_error"])

    def test_p02_and_p03_fail_closed_until_fixed_verifiers_exist(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trnm-semantic-closed-") as directory:
            root = Path(directory)
            dummy = root / "dummy.bin"
            dummy.write_bytes(b"not-semantic-evidence")
            env: dict[str, str] = {}
            for index, check_id in ((2, "P0.2-epoch-transition"), (3, "P0.3-signer-rollback")):
                evidence_path = root / f"p0{index}.json"
                evidence_path.write_text(
                    json.dumps(envelope(check_id, [artifact("dummy", dummy, root)])),
                    encoding="utf-8",
                )
                env[f"TRNM_SEMANTIC_P0{index}_COMMAND"] = "true"
                env[f"TRNM_SEMANTIC_P0{index}_EVIDENCE"] = str(evidence_path)
            result = self.run_gate("--run", env=env)
        report = json.loads(result.stdout)
        self.assertEqual(report["result"], "FAIL")
        self.assertEqual(report["checks"][1]["status"], "failed-evidence-invalid")
        self.assertEqual(report["checks"][2]["status"], "failed-evidence-invalid")
        self.assertIn("fail closed", report["checks"][1]["evidence_error"])
        self.assertIn("fail closed", report["checks"][2]["evidence_error"])

    def test_p04_synthetic_replay_claim_is_rejected_even_when_measurement_recomputes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trnm-semantic-p04-") as directory:
            root = Path(directory)
            manifests: dict[str, Path] = {}
            for role in ("workload_manifest", "topology_manifest", "durability_profile"):
                path = root / f"{role}.json"
                path.write_text(json.dumps({"schema": f"test-{role}-v1", "production_authority": False}), encoding="utf-8")
                manifests[role] = path
            bindings = {f"{role}_sha256": hashlib.sha256(path.read_bytes()).hexdigest() for role, path in manifests.items()}
            telemetry = root / "telemetry.jsonl"
            events = [
                {
                    "schema": "trnm_e2e_tx_event_v1", "tx_id": "tx-1", "workload": "classic",
                    "execution_path": "canonical", "submitted_at_utc": "2026-09-16T00:00:00Z",
                    "finalized_at_utc": "2026-09-16T00:00:01Z", "finality_status": "finalized",
                    "replay_verified": True, "retry_count": 0, "rollback": False,
                    "segment_latency_ms": {"consensus": 800}, **bindings,
                },
                {
                    "schema": "trnm_e2e_tx_event_v1", "tx_id": "tx-2", "workload": "classic",
                    "execution_path": "canonical", "submitted_at_utc": "2026-09-16T00:01:40Z",
                    "finalized_at_utc": None, "finality_status": "pending",
                    "replay_verified": False, "retry_count": 0, "rollback": False,
                    "segment_latency_ms": {}, **bindings,
                },
            ]
            telemetry.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in events), encoding="utf-8")
            measurement = root / "measurement.json"
            subprocess.run(
                [sys.executable, str(ROOT / "trillionnium/scripts/measure_finalized_goodput.py"), str(telemetry), "-o", str(measurement)],
                cwd=ROOT, check=True,
            )
            artifacts = [artifact("raw_tx_telemetry", telemetry, root), artifact("goodput_measurement", measurement, root)]
            artifacts.extend(artifact(role, path, root) for role, path in manifests.items())
            evidence_path = root / "p04.json"
            evidence_path.write_text(json.dumps(envelope("P0.4-finalized-goodput", artifacts)), encoding="utf-8")
            result = self.run_gate(
                "--run",
                env={"TRNM_SEMANTIC_P04_COMMAND": "true", "TRNM_SEMANTIC_P04_EVIDENCE": str(evidence_path)},
            )
        report = json.loads(result.stdout)
        self.assertEqual(report["checks"][3]["status"], "failed-evidence-invalid")
        self.assertEqual(report["evidence_verified_count"], 0)
        self.assertEqual(report["result"], "FAIL")
        self.assertIn("no fixed cryptographic business-transaction replay verifier", report["checks"][3]["evidence_error"])


if __name__ == "__main__":
    unittest.main()
