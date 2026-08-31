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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TruthError(message)


def read(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as exc:
        raise TruthError(f"{path}: unreadable text: {exc}") from exc


def load_json(path: str) -> dict[str, Any]:
    try:
        value = json.loads(read(path))
    except json.JSONDecodeError as exc:
        raise TruthError(f"{path}: unreadable JSON: {exc}") from exc
    require(isinstance(value, dict), f"{path}: top-level value must be an object")
    return value


def load_toml(path: str) -> dict[str, Any]:
    try:
        with (ROOT / path).open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise TruthError(f"{path}: unreadable TOML: {exc}") from exc
    require(isinstance(value, dict), f"{path}: top-level value must be a table")
    return value


def require_absent(text: str, forbidden: tuple[str, ...], label: str) -> None:
    hits = [item for item in forbidden if item in text]
    require(not hits, f"{label} contains forbidden stale claims/paths: {hits}")


def main() -> int:
    policy = load_json("config/repository-policy-v1.json")
    boundary = load_json("PROJECT_BOUNDARY.json")
    truth = load_json("config/consensus-mainline.json")
    cargo = load_toml("trillionnium/Cargo.toml")
    toolchain = load_toml("rust-toolchain.toml")
    web_package = load_json("web4-frontend/package.json")

    required_paths = policy.get("required_paths")
    require(isinstance(required_paths, list), "policy required_paths must be a list")
    missing = [path for path in required_paths if not (ROOT / path).exists()]
    require(not missing, f"required repository paths missing: {missing}")

    require(
        policy.get("repository") == "TrillionniumFoundation/Trillionnium-Chain",
        "repository policy slug drift",
    )
    require(
        boundary.get("canonical_repository") == policy["repository"],
        "project boundary repository drift",
    )
    require(boundary.get("schema") == "trnm-project-boundary-v2", "unsupported project boundary schema")
    require(
        boundary.get("authoritative_status") == "config/consensus-mainline.json",
        "project boundary must point to machine truth",
    )
    require(
        boundary.get("authoritative_plan")
        == "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md",
        "project boundary must point to the canonical plan",
    )

    repository = boundary.get("repository", {})
    require(
        repository.get("default_branch") == policy.get("default_branch") == "main",
        "default branch policy drift",
    )
    require(
        repository.get("current_visibility") == "public",
        "repository visibility observation must match the current public repository",
    )
    require(
        repository.get("required_pull_request_reviews", 0) >= 2,
        "critical repository policy requires two approvals",
    )
    require(repository.get("require_code_owner_review") is True, "code-owner review must be required by policy")
    require(repository.get("require_last_push_approval") is True, "last-push approval must be required by policy")

    consensus = boundary.get("consensus", {})
    require(
        consensus.get("mainline")
        == truth.get("consensus_mainline")
        == policy.get("consensus_mainline")
        == "native-poco-bft",
        "consensus mainline drift",
    )
    require(
        consensus.get("protocol_target")
        == truth.get("protocol_target")
        == policy.get("protocol_target")
        == "poco-bft-v0",
        "protocol target drift",
    )
    require(consensus.get("legacy_comet_role") == "migration-residue-only", "legacy Comet role drift")
    require(consensus.get("legacy_comet_may_authorize_release") is False, "legacy Comet must not authorize release")
    for label, value in {
        "boundary production candidacy": consensus.get("production_candidate"),
        "boundary consensus activation": consensus.get("production_consensus_activation"),
        "machine truth production candidacy": truth.get("production_candidate"),
        "machine truth consensus activation": truth.get("production_consensus_activation"),
    }.items():
        require(value is False, f"{label} must remain false")
    require(truth.get("as_of") == "2026-08-30", "machine truth as_of date is stale")
    require(
        truth.get("active_candidate_source") == "derived-at-verification-time-from-git-head-and-tree",
        "machine truth must not embed a self-invalidating candidate SHA",
    )
    source_binding = truth.get("source_binding_policy", {})
    require(source_binding.get("mode") == "runtime-git-commit-and-tree", "machine truth source-binding mode drift")
    require(
        source_binding.get("generator") == "scripts/ci/generate_release_status_v1.py",
        "machine truth source-binding generator drift",
    )
    require(
        source_binding.get("committed_truth_may_not_claim_its_own_future_commit") is True,
        "machine truth must forbid self-referential future commit claims",
    )
    require(source_binding.get("exact_source_required_for_evidence") is True, "external evidence must bind exact source")

    workspace = cargo.get("workspace", {})
    members = set(workspace.get("members", []))
    excluded = set(workspace.get("exclude", []))
    cargo_policy = boundary.get("cargo", {})
    require(set(cargo_policy.get("required_active_members", [])) <= members, "required native workspace members are missing")
    require(set(cargo_policy.get("required_excluded_members", [])) <= excluded, "legacy node/application crates must remain excluded")
    require(
        not ({"crates/trnm-consensus-app", "crates/trnm-node"} & members),
        "legacy Comet production crates re-entered active workspace",
    )
    metadata = workspace.get("metadata", {}).get("trnm", {})
    require(metadata.get("consensus_mainline") == "native-poco-bft", "Cargo consensus_mainline drift")
    require(metadata.get("production_consensus_activation") is False, "Cargo metadata may not activate production consensus")
    require(metadata.get("cometbft_role") == "migration-residue-only", "Cargo Comet role drift")

    require(toolchain.get("toolchain", {}).get("channel") == "1.95.0", "Rust toolchain must remain exactly 1.95.0")
    engines = web_package.get("engines", {})
    require(engines.get("node") == ">=24.18.0 <25", "web Node engine drift")
    require(engines.get("npm") == ">=11.16.0 <12", "web npm engine drift")

    readme = read("README.md")
    require(len(readme.strip()) >= 1000, "README is empty or was destructively truncated")
    require(
        "https://github.com/TrillionniumFoundation/Trillionnium-Chain.git" in readme,
        "README must use the canonical clone URL",
    )
    require("Node.js `>=24.18.0 <25`" in readme, "README Node requirement must match package.json")
    require("machine-readable authority is `config/consensus-mainline.json`" in readme, "README must defer to machine truth")
    require_absent(
        readme,
        ("https://github.com/ProfAlexQI/TrillionniumChain.git", "Node.js 20+", "CometBFT is the sole"),
        "README",
    )

    boundary_md = read("PROJECT_BOUNDARY.md")
    require_absent(boundary_md, ("/home/", "/Users/", "Private remote:"), "project boundary")

    security = read("SECURITY.md")
    require("trnm-poco-node" in security and "trnm-consensus-core" in security, "security policy does not cover native consensus")
    require("migration residue" in security, "security policy must classify legacy Comet as migration residue")
    require_absent(
        security,
        ("CometBFT -> trnm-consensus-app -> trnm-runtime", "/home/", "/Users/"),
        "security policy",
    )

    operations = read("OPERATIONS.md")
    require("candidate-only; no public-testnet, production, or activation runbook" in operations, "operations scope drift")
    require("default `trnm-poco-node` path intentionally exits with failure" in operations, "default node fail-closed text missing")
    require("check_external_evidence_v1.py --require-all" in operations, "release evidence gate is undocumented")
    require_absent(
        operations,
        (
            "Canonical Public-Testnet Candidate",
            "Run the application with `trnm-cometbft-app`",
            "CometBFT -> trnm-consensus-app -> trnm-runtime",
            "BankKeeper",
            "/home/",
            "/Users/",
        ),
        "operations manual",
    )

    readiness = read("RELEASE_READINESS.md")
    require("human-readable release projection" in readiness, "release readiness must be a projection")
    require("NO-GO: not public-testnet-ready" in readiness, "release readiness must retain NO-GO")
    require("Production consensus activation | `false`" in readiness, "release readiness must retain false activation")
    require_absent(readiness, ("active **release readiness truth source**", "/home/", "/Users/"), "release readiness")

    codeowners = read(".github/CODEOWNERS")
    for critical in (
        "/.github/",
        "/config/",
        "/SECURITY.md",
        "/trillionnium/crates/trnm-consensus-core/",
        "/trillionnium/crates/trnm-poco-node/",
        "/docs/protocol/",
    ):
        require(critical in codeowners, f"CODEOWNERS missing critical path {critical}")
    require("@ProfHepta" in codeowners, "critical paths need a reviewer distinct from current package author")

    workflow_path = policy.get("baseline_workflow")
    require(isinstance(workflow_path, str), "baseline_workflow must be a path")
    workflow = read(workflow_path)
    header = workflow.split("jobs:", 1)[0]
    require(re.search(r"(?m)^\s*pull_request:\s*$", workflow) is not None, "baseline workflow must run for every pull request")
    require("paths:" not in header, "baseline pull-request workflow must not use path filters")
    require("github.actor" not in workflow and "github.triggering_actor" not in workflow, "baseline workflow must not use actor allowlists")
    require("self-hosted" not in workflow, "baseline workflow must not depend on self-hosted runners")
    require("runs-on: ubuntu-24.04" in workflow, "baseline workflow must use the pinned GitHub-hosted Ubuntu 24.04 runner")
    require("runs-on: ubuntu-latest" not in workflow, "baseline workflow may not use the moving ubuntu-latest alias")

    required_check_names = policy.get("required_check_names")
    require(isinstance(required_check_names, list) and required_check_names, "required_check_names must be non-empty")
    require(len(set(required_check_names)) == len(required_check_names), "required check names must be unique")
    for check_name in required_check_names:
        require(f"name: {check_name}" in workflow, f"baseline workflow missing stable check name {check_name}")

    exact_source_expression = (
        "TRNM_EXPECTED_SOURCE_SHA: ${{ github.event_name == 'pull_request' && "
        "github.event.pull_request.head.sha || github.sha }}"
    )
    require(exact_source_expression in workflow, "baseline workflow must derive exact pull-request head SHA")
    expected_job_count = len(required_check_names)
    require(
        workflow.count("ref: ${{ env.TRNM_EXPECTED_SOURCE_SHA }}") == expected_job_count,
        "every stable required job must explicitly check out exact source SHA",
    )
    require(
        workflow.count("persist-credentials: false") == expected_job_count,
        "every stable required job must disable persisted checkout credentials",
    )
    require(
        workflow.count("- name: Verify exact source identity") == expected_job_count,
        "every stable required job must assert checked-out source identity",
    )
    require(
        workflow.count('run: test "$(git rev-parse HEAD)" = "${TRNM_EXPECTED_SOURCE_SHA}"')
        == expected_job_count,
        "every stable required job must compare HEAD with expected source SHA",
    )
    require(workflow.count("runs-on: ubuntu-24.04") == expected_job_count, "every required job must use pinned hosted runner")

    for package in (
        "trnm-state",
        "trnm-consensus-types",
        "trnm-consensus-crypto",
        "trnm-consensus-core",
        "trnm-consensus-safety-rules",
        "trnm-consensus-safety-store",
        "trnm-consensus-signer-journal",
        "trnm-native-application",
        "trnm-poco-node",
    ):
        require(package in workflow, f"strict safety-kernel Clippy missing {package}")
    require("TRNM_FUZZ_SMOKE_SECONDS: \"5\"" in workflow, "required fuzz smoke budget drift")
    require("scripts/ci/install_cargo_fuzz.sh" in workflow, "checksum-pinned fuzz installer missing")
    require("scripts/ci/check_canonical_fuzz_smoke.sh" in workflow, "canonical public-input fuzz targets missing")

    expected_external = {
        "EXT-REVIEW-001",
        "EXT-G1-CAMPAIGN-001",
        "EXT-ANCHOR-HSM-001",
        "EXT-POWERLOSS-001",
        "EXT-AUDIT-001",
        "EXT-SOAK-ACTIVATION-001",
    }
    require(set(policy.get("external_blockers", [])) == expected_external, "external blocker inventory drift")
    release_truth = policy.get("release_truth", {})
    require(release_truth and all(value is False for value in release_truth.values()), "release truth promoted without accepted evidence")

    summary = {
        "schema": "trnm-repository-truth-check-v1",
        "repository": policy["repository"],
        "consensus_mainline": "native-poco-bft",
        "workspace_members": len(members),
        "legacy_active_members": [],
        "required_checks": required_check_names,
        "exact_source_binding": True,
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
