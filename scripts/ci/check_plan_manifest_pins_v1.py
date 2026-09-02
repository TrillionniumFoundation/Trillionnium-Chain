#!/usr/bin/env python3
"""Validate every hash-bound Plan v2 input against the exact checked-out Git tree."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/development/plan-manifest-v1.toml"


class PinError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PinError(message)


def load_toml(path: pathlib.Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise PinError(f"{path.relative_to(ROOT)}: {error}") from error
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: table required")
    return value


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def blob(path: str) -> str:
    require(
        isinstance(path, str) and path and not path.startswith("/"),
        f"invalid repository-relative path: {path!r}",
    )
    require((ROOT / path).exists(), f"pinned path missing: {path}")
    value = git("rev-parse", f"HEAD:{path}")
    require(
        re.fullmatch(r"[0-9a-f]{40}", value) is not None,
        f"invalid Git blob for {path}: {value}",
    )
    return value


def main() -> int:
    manifest = load_toml(MANIFEST)
    require(manifest.get("manifest_version") == 2, "manifest version drift")
    require(
        manifest.get("plan_id") == "trnm-chain-development-plan-v2",
        "manifest plan ID drift",
    )
    require(
        manifest.get("document_candidate_binding") == "runtime-git-commit-and-tree",
        "manifest runtime binding drift",
    )
    require(
        manifest.get("workspace_crate_count") == 62,
        "manifest workspace crate count drift",
    )

    plan_path = manifest.get("plan_path")
    evidence_path = manifest.get("evidence_contract_path")
    require(isinstance(plan_path, str), "plan path missing")
    require(isinstance(evidence_path, str), "evidence contract path missing")
    require(
        hashlib.sha256((ROOT / plan_path).read_bytes()).hexdigest()
        == manifest.get("plan_sha256"),
        "plan SHA-256 mismatch",
    )
    require(
        hashlib.sha256((ROOT / evidence_path).read_bytes()).hexdigest()
        == manifest.get("evidence_contract_sha256"),
        "evidence-contract SHA-256 mismatch",
    )

    assessed_commit = manifest.get("assessed_commit")
    assessed_tree = manifest.get("assessed_tree")
    require(
        isinstance(assessed_commit, str)
        and re.fullmatch(r"[0-9a-f]{40}", assessed_commit) is not None,
        "assessed commit missing",
    )
    require(
        isinstance(assessed_tree, str)
        and re.fullmatch(r"[0-9a-f]{40}", assessed_tree) is not None,
        "assessed tree missing",
    )
    require(
        git("rev-parse", f"{assessed_commit}^{{tree}}") == assessed_tree,
        "assessed commit/tree mismatch",
    )
    require(
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", assessed_commit, "HEAD"],
            cwd=ROOT,
        ).returncode
        == 0,
        "assessed baseline is not an ancestor of HEAD",
    )

    overlay_commit = manifest.get("repository_core_overlay_source_commit")
    overlay_tree = manifest.get("repository_core_overlay_source_tree")
    require(
        overlay_commit
        == manifest.get("repository_core_overlay", {}).get("source_commit")
        == "a44d67181dc74ad74e64819b913972d2a49abc54",
        "repository-core overlay commit drift",
    )
    require(
        overlay_tree
        == manifest.get("repository_core_overlay", {}).get("source_tree")
        == "a4480623afae1bedee9f03fcf83ce31ec00a2bb7",
        "repository-core overlay tree drift",
    )
    require(
        git("rev-parse", f"{overlay_commit}^{{tree}}") == overlay_tree,
        "repository-core overlay commit/tree mismatch",
    )
    require(
        manifest.get("repository_core_overlay_absorbed") is True
        and manifest.get("repository_core_overlay", {}).get(
            "absorbed_into_selected_successor"
        )
        is True,
        "repository-core overlay absorption drift",
    )

    pinned = {
        "build_closure_git_blob": "build_closure_registry_path",
        "build_closure_validator_git_blob": "build_closure_validator_path",
        "workspace_manifest_git_blob": "workspace_manifest_path",
        "workspace_lock_git_blob": "workspace_lock_path",
        "codeowners_git_blob": "codeowners_path",
        "module_registry_git_blob": "module_registry_path",
        "module_coverage_git_blob": "module_coverage_path",
        "module_technical_reference_git_blob": "module_technical_reference_path",
        "current_snapshot_git_blob": "current_snapshot_path",
        "documentation_truth_git_blob": "documentation_truth_path",
        "repository_policy_git_blob": "repository_policy_path",
        "blocker_execution_git_blob": "blocker_execution_path",
        "blocker_execution_validator_git_blob": "blocker_execution_validator_path",
        "documentation_reference_gate_git_blob": "documentation_reference_gate_path",
        "module_coverage_gate_git_blob": "module_coverage_gate_path",
        "canonical_plan_gate_git_blob": "canonical_plan_gate_path",
        "node_decomposition_git_blob": "node_decomposition_path",
        "node_decomposition_gate_git_blob": "node_decomposition_gate_path",
        "required_baseline_workflow_git_blob": "required_baseline_workflow_path",
        "required_baseline_gate_git_blob": "required_baseline_gate_path",
        "plan_manifest_pin_gate_git_blob": "plan_manifest_pin_gate_path",
    }

    checked: list[dict[str, str]] = []
    for blob_field, path_field in pinned.items():
        path = manifest.get(path_field)
        expected = manifest.get(blob_field)
        require(isinstance(path, str) and path, f"{path_field} missing")
        require(
            isinstance(expected, str)
            and re.fullmatch(r"[0-9a-f]{40}", expected) is not None,
            f"{blob_field} missing",
        )
        actual = blob(path)
        require(
            actual == expected,
            f"{blob_field} mismatch for {path}: {expected} != {actual}",
        )
        checked.append(
            {"blob_field": blob_field, "path": path, "blob": actual}
        )

    cargo = load_toml(ROOT / manifest["workspace_manifest_path"])
    members = cargo.get("workspace", {}).get("members")
    require(
        isinstance(members, list)
        and len(members) == manifest["workspace_crate_count"],
        "Cargo workspace member count differs from manifest",
    )

    for claim in (
        "production_candidate",
        "production_consensus_activation",
        "public_testnet_ready",
        "release_ready",
    ):
        require(manifest.get(claim) is False, f"manifest promoted {claim}")
    require(
        manifest.get("repository_core_overlay", {}).get("production_activation")
        is False,
        "overlay promoted production activation",
    )

    report = {
        "schema": "trnm-plan-manifest-pins-v1",
        "head": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "plan_id": manifest["plan_id"],
        "workspace_crates": len(members),
        "pinned_inputs": len(checked),
        "overlay_source_commit": overlay_commit,
        "production_candidate": False,
        "production_consensus_activation": False,
        "release_ready": False,
        "result": "PASS",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PinError, OSError, subprocess.CalledProcessError) as error:
        print(f"plan manifest pin validation failed: {error}", file=sys.stderr)
        raise SystemExit(2)
