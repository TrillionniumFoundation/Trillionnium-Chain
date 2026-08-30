#!/usr/bin/env python3
"""Fail-closed repository truth checks for every pull request."""

from __future__ import annotations

import json
import pathlib
import re
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]


class TruthError(RuntimeError):
    pass


def load_json(path: str) -> dict[str, Any]:
    target = ROOT / path
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TruthError(f"{path}: unreadable JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise TruthError(f"{path}: top-level value must be an object")
    return value


def load_toml(path: str) -> dict[str, Any]:
    target = ROOT / path
    try:
        with target.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise TruthError(f"{path}: unreadable TOML: {exc}") from exc
    if not isinstance(value, dict):
        raise TruthError(f"{path}: top-level value must be a table")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TruthError(message)


def read(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as exc:
        raise TruthError(f"{path}: unreadable text: {exc}") from exc


def main() -> int:
    policy = load_json("config/repository-policy-v1.json")
    boundary = load_json("PROJECT_BOUNDARY.json")
    truth = load_json("config/consensus-mainline.json")
    cargo = load_toml("trillionnium/Cargo.toml")
    toolchain = load_toml("rust-toolchain.toml")

    required_paths = policy.get("required_paths")
    require(isinstance(required_paths, list), "policy required_paths must be a list")
    missing = [path for path in required_paths if not (ROOT / path).exists()]
    require(not missing, f"required repository paths missing: {missing}")

    require(policy.get("repository") == "TrillionniumFoundation/Trillionnium-Chain",
            "repository policy slug drift")
    require(boundary.get("canonical_repository") == policy["repository"],
            "project boundary repository drift")
    require(boundary.get("schema") == "trnm-project-boundary-v2",
            "unsupported project boundary schema")
    require(boundary.get("authoritative_status") == "config/consensus-mainline.json",
            "project boundary must point to machine truth")
    require(boundary.get("authoritative_plan") ==
            "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md",
            "project boundary must point to the canonical plan")

    repository = boundary.get("repository", {})
    require(repository.get("default_branch") == policy.get("default_branch") == "main",
            "default branch policy drift")
    require(repository.get("current_visibility") == "public",
            "repository visibility observation must match the current public repository")
    require(repository.get("required_pull_request_reviews", 0) >= 2,
            "critical repository policy requires two approvals")
    require(repository.get("require_code_owner_review") is True,
            "code-owner review must be required by policy")
    require(repository.get("require_last_push_approval") is True,
            "last-push approval must be required by policy")

    consensus = boundary.get("consensus", {})
    require(consensus.get("mainline") == truth.get("consensus_mainline") ==
            policy.get("consensus_mainline") == "native-poco-bft",
            "consensus mainline drift")
    require(consensus.get("protocol_target") == truth.get("protocol_target") ==
            policy.get("protocol_target") == "poco-bft-v0",
            "protocol target drift")
    require(consensus.get("legacy_comet_role") == "migration-residue-only",
            "legacy Comet role drift")
    require(consensus.get("legacy_comet_may_authorize_release") is False,
            "legacy Comet must not authorize release")
    require(consensus.get("production_candidate") is False,
            "boundary may not claim production candidacy")
    require(consensus.get("production_consensus_activation") is False,
            "boundary may not claim consensus activation")
    require(truth.get("production_candidate") is False,
            "machine truth production_candidate must remain false")
    require(truth.get("production_consensus_activation") is False,
            "machine truth production_consensus_activation must remain false")

    workspace = cargo.get("workspace", {})
    members = set(workspace.get("members", []))
    excluded = set(workspace.get("exclude", []))
    cargo_policy = boundary.get("cargo", {})
    require(set(cargo_policy.get("required_active_members", [])) <= members,
            "required native workspace members are missing")
    require(set(cargo_policy.get("required_excluded_members", [])) <= excluded,
            "legacy node/application crates must remain excluded")
    require("crates/trnm-consensus-app" not in members and "crates/trnm-node" not in members,
            "legacy Comet production crates re-entered active workspace")
    metadata = workspace.get("metadata", {}).get("trnm", {})
    require(metadata.get("consensus_mainline") == "native-poco-bft",
            "Cargo consensus_mainline drift")
    require(metadata.get("production_consensus_activation") is False,
            "Cargo metadata may not activate production consensus")
    require(metadata.get("cometbft_role") == "migration-residue-only",
            "Cargo Comet role drift")

    require(toolchain.get("toolchain", {}).get("channel") == "1.95.0",
            "Rust toolchain must remain exactly 1.95.0")

    readme = read("README.md")
    require(len(readme.strip()) >= 1000, "README is empty or was destructively truncated")

    boundary_md = read("PROJECT_BOUNDARY.md")
    require("/home/" not in boundary_md, "project boundary must not depend on a local absolute path")
    require("Private remote:" not in boundary_md, "project boundary contains stale private-remote claim")

    security = read("SECURITY.md")
    require("trnm-poco-node" in security and "trnm-consensus-core" in security,
            "security policy does not cover the native consensus path")
    require("migration residue" in security,
            "security policy must classify legacy Comet as migration residue")
    require("CometBFT -> trnm-consensus-app -> trnm-runtime" not in security,
            "security policy still declares the superseded Comet production path")

    codeowners = read(".github/CODEOWNERS")
    for critical in (
        "/.github/", "/config/", "/SECURITY.md",
        "/trillionnium/crates/trnm-consensus-core/",
        "/trillionnium/crates/trnm-poco-node/",
        "/docs/protocol/",
    ):
        require(critical in codeowners, f"CODEOWNERS missing critical path {critical}")
    require("@ProfHepta" in codeowners,
            "critical paths need a reviewer distinct from the current package author")

    workflow_path = policy.get("baseline_workflow")
    require(isinstance(workflow_path, str), "baseline_workflow must be a path")
    workflow = read(workflow_path)
    require(re.search(r"(?m)^\s*pull_request:\s*$", workflow) is not None,
            "baseline workflow must run for every pull request")
    require("paths:" not in workflow.split("jobs:", 1)[0],
            "baseline pull-request workflow must not use path filters")
    require("github.actor" not in workflow and "github.triggering_actor" not in workflow,
            "baseline workflow must not use actor allowlists")
    require("self-hosted" not in workflow,
            "baseline workflow must not depend on self-hosted runners")
    require("runs-on: ubuntu-latest" in workflow,
            "baseline workflow must use a GitHub-hosted runner")
    for check_name in policy.get("required_check_names", []):
        require(f"name: {check_name}" in workflow,
                f"baseline workflow missing stable check name {check_name}")

    expected_external = {
        "EXT-REVIEW-001",
        "EXT-G1-CAMPAIGN-001",
        "EXT-ANCHOR-HSM-001",
        "EXT-POWERLOSS-001",
        "EXT-AUDIT-001",
        "EXT-SOAK-ACTIVATION-001",
    }
    require(set(policy.get("external_blockers", [])) == expected_external,
            "external blocker inventory drift")

    release_truth = policy.get("release_truth", {})
    require(release_truth and all(value is False for value in release_truth.values()),
            "repository policy may not promote release truth without accepted evidence")

    summary = {
        "schema": "trnm-repository-truth-check-v1",
        "repository": policy["repository"],
        "consensus_mainline": "native-poco-bft",
        "workspace_members": len(members),
        "legacy_active_members": [],
        "external_blockers": sorted(expected_external),
        "production_candidate": False,
        "production_consensus_activation": False,
        "result": "PASS",
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TruthError as exc:
        print(f"repository truth check failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
