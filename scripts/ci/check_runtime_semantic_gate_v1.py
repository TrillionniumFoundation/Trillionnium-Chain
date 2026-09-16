#!/usr/bin/env python3
"""Run (or explicitly report the absence of) runtime semantic acceptance.

The repository has many useful lexical guards.  They catch accidental feature
or promotion wiring, but cannot prove distributed behavior.  This gate is the
single execution entry point for the four P0 runtime claims.  It never treats
an absent command as evidence: report-only mode emits ``NOT_RUN`` and
``--require`` exits non-zero until every required check has executed and
returned zero.
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


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true", help="execute commands supplied by environment")
    parser.add_argument("--require", action="store_true", help="fail unless all required checks execute successfully")
    parser.add_argument("--output", type=pathlib.Path, help="write the JSON report to this path")
    return parser.parse_args()


def load() -> dict[str, Any]:
    try:
        with CONFIG.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise GateError(f"invalid semantic gate config: {error}") from error
    require(isinstance(value, dict), "semantic gate config must be a table")
    require(value.get("schema_version") == 1, "semantic gate schema drift")
    require(value.get("gate_id") == "trnm-runtime-semantic-gate-v1", "semantic gate id drift")
    require(value.get("production_authority") is False, "semantic gate cannot hold production authority")
    checks = value.get("check")
    require(isinstance(checks, list) and checks, "semantic checks missing")
    seen: set[str] = set()
    for row in checks:
        require(isinstance(row, dict), "semantic check row must be a table")
        check_id = row.get("id")
        env_name = row.get("command_env")
        require(isinstance(check_id, str) and check_id and check_id not in seen, "duplicate semantic check id")
        require(isinstance(env_name, str) and env_name.startswith("TRNM_SEMANTIC_"), f"{check_id}: invalid command env")
        require(isinstance(row.get("acceptance"), str) and row["acceptance"], f"{check_id}: acceptance missing")
        require(isinstance(row.get("required"), bool), f"{check_id}: required flag missing")
        seen.add(check_id)
    return value


def main() -> int:
    args = parse_args()
    config = load()
    reports: list[dict[str, Any]] = []
    executed = 0
    failures = 0
    for row in config["check"]:
        check_id = row["id"]
        raw = os.environ.get(row["command_env"], "").strip()
        command: list[str] | None = None
        status = "not-configured"
        returncode: int | None = None
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
            if returncode == 0:
                status = "passed"
            else:
                status = "failed"
                failures += 1
        reports.append({
            "id": check_id,
            "owner": row["owner"],
            "required": row["required"],
            "acceptance": row["acceptance"],
            "command_env": row["command_env"],
            "status": status,
            "returncode": returncode,
        })

    required_missing = [r["id"] for r in reports if r["required"] and r["status"] != "passed"]
    if failures:
        result = "FAIL"
    elif executed == 0:
        result = "NOT_RUN"
    elif required_missing:
        result = "INCOMPLETE"
    else:
        result = "PASS"
    report = {
        "schema": "trnm-runtime-semantic-gate-report-v1",
        "gate_id": config["gate_id"],
        "mode": "execution" if args.run else "report-only",
        "lexical_smoke_is_not_semantic_evidence": True,
        "required_missing": required_missing,
        "executed_count": executed,
        "checks": reports,
        "production_authority": False,
        "result": result,
    }
    encoded = json.dumps(report, indent=2, sort_keys=True)
    print(encoded)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    if args.require and (result != "PASS"):
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GateError, OSError) as error:
        print(f"runtime semantic gate failed: {error}", file=sys.stderr)
        raise SystemExit(2)
