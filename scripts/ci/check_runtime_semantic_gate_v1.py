#!/usr/bin/env python3
"""Run P0 runtime commands and require source-bound structured evidence.

A zero exit code is only command execution success. It is never enough to turn
one of the four runtime claims green. Every passing command must additionally
publish a bounded JSON evidence record whose source commit, check identity and
check-specific behavioral predicates are verified here.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config/runtime-semantic-gate-v1.toml"
MAX_EVIDENCE_BYTES = 256 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true", help="execute configured commands")
    parser.add_argument("--require", action="store_true", help="fail unless every required check has accepted evidence")
    parser.add_argument("--output", type=pathlib.Path, help="write the JSON report to this path")
    return parser.parse_args()


def git_head() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    value = completed.stdout.strip()
    require(re.fullmatch(r"[0-9a-f]{40}", value) is not None, "non-canonical source commit")
    return value


def load() -> dict[str, Any]:
    try:
        with CONFIG.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise GateError(f"invalid semantic gate config: {error}") from error
    require(isinstance(value, dict), "semantic gate config must be a table")
    require(value.get("schema_version") == 2, "semantic gate schema drift")
    require(value.get("gate_id") == "trnm-runtime-semantic-gate-v1", "semantic gate id drift")
    require(value.get("production_authority") is False, "semantic gate cannot hold production authority")
    checks = value.get("check")
    require(isinstance(checks, list) and checks, "semantic checks missing")
    seen: set[str] = set()
    for row in checks:
        require(isinstance(row, dict), "semantic check row must be a table")
        check_id = row.get("id")
        command_env = row.get("command_env")
        evidence_env = row.get("evidence_env")
        evidence_kind = row.get("evidence_kind")
        require(isinstance(check_id, str) and check_id and check_id not in seen, "duplicate semantic check id")
        require(isinstance(command_env, str) and command_env.startswith("TRNM_SEMANTIC_"), f"{check_id}: invalid command env")
        require(isinstance(evidence_env, str) and evidence_env.startswith("TRNM_SEMANTIC_"), f"{check_id}: invalid evidence env")
        require(isinstance(evidence_kind, str) and evidence_kind, f"{check_id}: evidence kind missing")
        require(isinstance(row.get("acceptance"), str) and row["acceptance"], f"{check_id}: acceptance missing")
        require(isinstance(row.get("required"), bool), f"{check_id}: required flag missing")
        seen.add(check_id)
    return value


def load_evidence(path_text: str, row: dict[str, Any], source_commit: str) -> dict[str, Any]:
    path = pathlib.Path(path_text)
    require(path.is_absolute(), f"{row['id']}: evidence path must be absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise GateError(f"{row['id']}: evidence unavailable: {error}") from error
    require(not path.is_symlink() and path.is_file(), f"{row['id']}: evidence must be a regular non-symlink file")
    require(0 < metadata.st_size <= MAX_EVIDENCE_BYTES, f"{row['id']}: evidence size is invalid")
    try:
        raw = path.read_bytes()
        evidence = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise GateError(f"{row['id']}: invalid evidence JSON: {error}") from error
    require(isinstance(evidence, dict), f"{row['id']}: evidence must be an object")
    require(evidence.get("schema") == "trnm-runtime-semantic-evidence-v1", f"{row['id']}: evidence schema drift")
    require(evidence.get("check_id") == row["id"], f"{row['id']}: evidence check identity mismatch")
    require(evidence.get("evidence_kind") == row["evidence_kind"], f"{row['id']}: evidence kind mismatch")
    require(evidence.get("source_commit") == source_commit, f"{row['id']}: evidence is not bound to HEAD")
    require(evidence.get("result") == "PASS", f"{row['id']}: evidence did not pass")
    require(evidence.get("production_authority") is False, f"{row['id']}: evidence cannot grant production authority")
    digest = evidence.get("raw_artifact_sha256")
    require(isinstance(digest, str) and HEX64.fullmatch(digest) is not None, f"{row['id']}: raw artifact digest missing")
    validate_behavior(row["id"], evidence)
    return evidence


def require_true(evidence: dict[str, Any], *names: str) -> None:
    for name in names:
        require(evidence.get(name) is True, f"{evidence.get('check_id')}: {name} is not proven")


def validate_behavior(check_id: str, evidence: dict[str, Any]) -> None:
    if check_id == "P0.1-multinode-persistence":
        counts = evidence.get("validator_counts")
        require(isinstance(counts, list) and 4 in counts and 7 in counts, f"{check_id}: both 4-node and 7-node runs are required")
        require_true(
            evidence,
            "independent_processes",
            "distinct_runtime_roots",
            "kill_restart_completed",
            "partition_heal_completed",
            "rejoin_completed",
            "durable_state_replay_verified",
        )
    elif check_id == "P0.2-epoch-transition":
        transitions = evidence.get("transition_count")
        require(type(transitions) is int and transitions >= 2, f"{check_id}: fewer than two transitions")
        require_true(
            evidence,
            "old_only_membership_exercised",
            "new_only_membership_exercised",
            "dual_role_membership_exercised",
            "persist_before_sign_faults_exercised",
            "cold_restart_completed",
            "proof_verification_completed",
        )
    elif check_id == "P0.3-signer-rollback":
        require_true(
            evidence,
            "device_backed_custody",
            "independently_administered",
            "monotonic_anchor",
            "rollback_rejected",
            "replacement_rejected",
        )
    elif check_id == "P0.4-finalized-goodput":
        require_true(evidence, "finalized_only", "replay_verified_only")
        successful = evidence.get("successful_finalized_transactions")
        goodput = evidence.get("goodput_tps")
        duration = evidence.get("measurement_seconds")
        require(type(successful) is int and successful > 0, f"{check_id}: no successful finalized transactions")
        require(isinstance(goodput, (int, float)) and not isinstance(goodput, bool) and goodput > 0, f"{check_id}: goodput is not positive")
        require(isinstance(duration, (int, float)) and not isinstance(duration, bool) and duration > 0, f"{check_id}: measurement window is invalid")
        latencies = evidence.get("finality_latency_ms")
        require(isinstance(latencies, dict), f"{check_id}: finality latency summary missing")
        for percentile in ("p50", "p95", "p99"):
            value = latencies.get(percentile)
            require(isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0, f"{check_id}: {percentile} finality latency missing")
        require(latencies["p50"] <= latencies["p95"] <= latencies["p99"], f"{check_id}: finality percentiles are inconsistent")
    else:
        raise GateError(f"unknown semantic check: {check_id}")


def main() -> int:
    args = parse_args()
    config = load()
    source_commit = git_head()
    reports: list[dict[str, Any]] = []
    executed = 0
    failures = 0
    evidence_accepted = 0

    for row in config["check"]:
        check_id = row["id"]
        raw = os.environ.get(row["command_env"], "").strip()
        evidence_path = os.environ.get(row["evidence_env"], "").strip()
        command: list[str] | None = None
        status = "not-configured"
        returncode: int | None = None
        evidence_error: str | None = None
        if raw:
            try:
                command = shlex.split(raw)
            except ValueError as error:
                raise GateError(f"{check_id}: invalid command quoting: {error}") from error
            require(command, f"{check_id}: empty command")
            status = "configured-not-run"
        if args.run and command is not None:
            completed = subprocess.run(command, cwd=ROOT, check=False)
            returncode = completed.returncode
            executed += 1
            if returncode != 0:
                status = "command-failed"
                failures += 1
            elif not evidence_path:
                status = "evidence-missing"
            else:
                try:
                    load_evidence(evidence_path, row, source_commit)
                except GateError as error:
                    status = "evidence-rejected"
                    evidence_error = str(error)
                else:
                    status = "passed"
                    evidence_accepted += 1
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
                "evidence_error": evidence_error,
            }
        )

    required_missing = [report["id"] for report in reports if report["required"] and report["status"] != "passed"]
    if failures:
        result = "FAIL"
    elif executed == 0:
        result = "NOT_RUN"
    elif required_missing:
        result = "INCOMPLETE"
    else:
        result = "PASS"
    report = {
        "schema": "trnm-runtime-semantic-gate-report-v2",
        "gate_id": config["gate_id"],
        "source_commit": source_commit,
        "mode": "execution" if args.run else "report-only",
        "command_success_is_not_semantic_evidence": True,
        "required_missing": required_missing,
        "executed_count": executed,
        "evidence_accepted_count": evidence_accepted,
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
    except (GateError, OSError, subprocess.SubprocessError) as error:
        print(f"runtime semantic gate failed: {error}", file=sys.stderr)
        raise SystemExit(2)
