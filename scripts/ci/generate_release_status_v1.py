#!/usr/bin/env python3
"""Generate deterministic, commit-bound repository status from machine sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]


def run_git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def load_json(path: str) -> dict[str, Any]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def load_toml(path: str) -> dict[str, Any]:
    with (ROOT / path).open("rb") as handle:
        return tomllib.load(handle)


def sha256(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def build_status() -> dict[str, Any]:
    policy = load_json("config/repository-policy-v1.json")
    truth = load_json("config/consensus-mainline.json")
    cargo = load_toml("trillionnium/Cargo.toml")
    members = sorted(cargo["workspace"]["members"])
    blockers = [
        {
            "id": row["id"],
            "severity": row["severity"],
            "status": row["status"],
        }
        for row in truth.get("blockers", [])
    ]
    branch = (
        os.environ.get("GITHUB_HEAD_REF")
        or os.environ.get("GITHUB_REF_NAME")
        or run_git("rev-parse", "--abbrev-ref", "HEAD")
    )
    return {
        "schema": "trnm-release-status-v1",
        "repository": policy["repository"],
        "source": {
            "commit": run_git("rev-parse", "HEAD"),
            "tree": run_git("rev-parse", "HEAD^{tree}"),
            "branch": branch,
        },
        "authority": {
            "plan": "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md",
            "plan_sha256": sha256("docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"),
            "plan_manifest": "docs/development/plan-manifest-v1.toml",
            "machine_truth": "config/consensus-mainline.json",
            "machine_truth_sha256": sha256("config/consensus-mainline.json"),
            "repository_policy_sha256": sha256("config/repository-policy-v1.json"),
            "cargo_lock_sha256": sha256("trillionnium/Cargo.lock"),
        },
        "consensus": {
            "mainline": truth["consensus_mainline"],
            "protocol_target": truth["protocol_target"],
            "stage": truth["stage"],
            "production_candidate": truth["production_candidate"],
            "production_consensus_activation": truth["production_consensus_activation"],
            "cometbft_role": truth["cometbft"]["role"],
        },
        "workspace": {
            "manifest": "trillionnium/Cargo.toml",
            "member_count": len(members),
            "members": members,
            "excluded": sorted(cargo["workspace"].get("exclude", [])),
        },
        "repository_blockers": blockers,
        "external_blockers": [
            {"id": blocker_id, "status": "open-no-accepted-evidence"}
            for blocker_id in policy["external_blockers"]
        ],
        "configured_required_checks": policy["required_check_names"],
        "release_truth": policy["release_truth"],
    }


def encode(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--check-deterministic", action="store_true")
    args = parser.parse_args()

    first = encode(build_status())
    if args.check_deterministic:
        second = encode(build_status())
        if first != second:
            print("release status generation is nondeterministic", file=sys.stderr)
            return 2
    if args.output:
        output = args.output
        if not output.is_absolute():
            output = ROOT / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(first)
    else:
        sys.stdout.buffer.write(first)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
