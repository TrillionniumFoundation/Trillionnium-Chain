#!/usr/bin/env python3
"""Run runtime semantic acceptance without trusting command exit status alone.

Repository lexical guards and a successful subprocess are useful diagnostics,
but neither proves distributed runtime behavior. Every configured P0 command
must additionally publish one source-bound `trnm-runtime-semantic-evidence-v1`
envelope. The gate re-hashes every referenced artifact and validates the
check-specific minimum facts before a semantic result can become PASS.

This is still engineering evidence and explicitly carries no production or
independent-audit authority.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shlex
import subprocess
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config/runtime-semantic-gate-v1.toml"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from runtime_semantic_evidence_v1 import (  # noqa: E402
    EvidenceError,
    verify_evidence,
    verify_semantics,
)


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true", help="execute configured runtime commands")
    parser.add_argument(
        "--require",
        action="store_true",
        help="fail unless every required semantic check has verified evidence",
    )
    parser.add_argument("--output", type=pathlib.Path, help="write the JSON report to this path")
    return parser.parse_args()


def load() -> dict[str, Any]:
    try:
        with CONFIG.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise GateError(f"invalid semantic gate config: {error}") from error
    require(isinstance(value, dict), "semantic gate config must be a table")
    require(value.get("schema_version") == 3, "semantic gate schema drift")
    require(value.get("gate_id") == "trnm-runtime-semantic-gate-v1", "semantic gate id drift")
    require(
        value.get("evidence_schema") == "trnm-runtime-semantic-evidence-v1",
        "semantic evidence schema drift",
    )
    require(value.get("production_authority") is False, "semantic gate cannot hold production authority")
    checks = value.get("check")
    require(isinstance(checks, list) and checks, "semantic checks missing")
    seen: set[str] = set()
    seen_envs: set[str] = set()
    for row in checks:
        require(isinstance(row, dict), "semantic check row must be a table")
        check_id = row.get("id")
        command_env = row.get("command_env")
        evidence_env = row.get("evidence_env")
        semantic_verifier = row.get("semantic_verifier")
        require(
            isinstance(check_id, str) and check_id and check_id not in seen,
            "duplicate semantic check id",
        )
        require(
            isinstance(command_env, str) and command_env.startswith("TRNM_SEMANTIC_"),
            f"{check_id}: invalid command env",
        )
        require(
            isinstance(evidence_env, str) and evidence_env.startswith("TRNM_SEMANTIC_"),
            f"{check_id}: invalid evidence env",
        )
        require(command_env != evidence_env, f"{check_id}: command/evidence env alias")
        require(command_env not in seen_envs and evidence_env not in seen_envs, f"{check_id}: reused env")
        require(
            isinstance(row.get("acceptance"), str) and row["acceptance"],
            f"{check_id}: acceptance missing",
        )
        require(isinstance(row.get("required"), bool), f"{check_id}: required flag missing")
        require(
            isinstance(semantic_verifier, str) and semantic_verifier,
            f"{check_id}: semantic verifier missing",
        )
        seen.add(check_id)
        seen_envs.update({command_env, evidence_env})
    return value


def main() -> int:
    args = parse_args()
    config = load()
    reports: list[dict[str, Any]] = []
    executed = 0
    failures = 0
    evidence_verified = 0
    semantic_verified = 0

    for row in config["check"]:
        check_id = row["id"]
        raw_command = os.environ.get(row["command_env"], "").strip()
        raw_evidence = os.environ.get(row["evidence_env"], "").strip()
        command: list[str] | None = None
        status = "not-configured"
        returncode: int | None = None
        evidence_status = "not-configured" if not raw_evidence else "configured-not-verified"
        evidence_error: str | None = None
        semantic_status = "not-configured"
        semantic_error: str | None = None

        if raw_command:
            try:
                command = shlex.split(raw_command)
            except ValueError as error:
                raise GateError(f"{check_id}: invalid command quoting: {error}") from error
            require(command, f"{check_id}: empty command")
            status = "configured-not-run"

        if args.run and command is not None:
            completed = subprocess.run(command, cwd=ROOT, check=False)
            returncode = completed.returncode
            executed += 1
            if returncode != 0:
                status = "failed"
                failures += 1
            elif not raw_evidence:
                status = "failed-evidence-missing"
                evidence_status = "missing"
                evidence_error = "command returned zero but evidence path is not configured"
                failures += 1
            else:
                try:
                    evidence = verify_evidence(pathlib.Path(raw_evidence), check_id)
                except EvidenceError as error:
                    status = "failed-evidence-invalid"
                    evidence_status = "invalid"
                    evidence_error = str(error)
                    failures += 1
                else:
                    evidence_status = "verified"
                    evidence_verified += 1
                    semantic_status = "configured-not-verified"
                    try:
                        verify_semantics(evidence, check_id, row["semantic_verifier"])
                    except EvidenceError as error:
                        status = "failed-semantic-unverified"
                        semantic_status = "unverified"
                        semantic_error = str(error)
                        failures += 1
                    else:
                        status = "passed"
                        semantic_status = "verified"
                        semantic_verified += 1

        reports.append(
            {
                "id": check_id,
                "owner": row["owner"],
                "required": row["required"],
                "acceptance": row["acceptance"],
                "command_env": row["command_env"],
                "evidence_env": row["evidence_env"],
                "status": status,
                "returncode": returncode,
                "evidence_status": evidence_status,
                "evidence_error": evidence_error,
                "semantic_verifier": row["semantic_verifier"],
                "semantic_status": semantic_status,
                "semantic_error": semantic_error,
            }
        )

    required_missing = [
        report["id"]
        for report in reports
        if report["required"] and report["status"] != "passed"
    ]
    if failures:
        result = "FAIL"
    elif executed == 0:
        result = "NOT_RUN"
    elif required_missing:
        result = "INCOMPLETE"
    else:
        result = "PASS"
    report = {
        "schema": "trnm-runtime-semantic-gate-report-v3",
        "gate_id": config["gate_id"],
        "mode": "execution" if args.run else "report-only",
        "lexical_smoke_is_not_semantic_evidence": True,
        "zero_exit_is_not_semantic_evidence": True,
        "required_missing": required_missing,
        "executed_count": executed,
        "evidence_verified_count": evidence_verified,
        "semantic_verified_count": semantic_verified,
        "checks": reports,
        "production_authority": False,
        "result": result,
    }
    encoded = json.dumps(report, indent=2, sort_keys=True)
    print(encoded)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    if args.require and result != "PASS":
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GateError, OSError) as error:
        print(f"runtime semantic gate failed: {error}", file=sys.stderr)
        raise SystemExit(2)
