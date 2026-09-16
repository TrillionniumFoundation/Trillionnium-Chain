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

# Content pins are a release/source-binding boundary.  They are deliberately
# anchored to the last refresh commit instead of HEAD, so ordinary Rust,
# test, or tooling changes do not require rewriting this large manifest.  A
# change to one of the pinned inputs still fails closed until the refresh tool
# advances the snapshot and recomputes every digest.
PIN_REFRESH_POLICY = "change-scoped-v1"


PIN_PATH_FIELDS = {
    "build_closure_git_blob": "build_closure_registry_path",
    "build_closure_validator_git_blob": "build_closure_validator_path",
    "workspace_manifest_git_blob": "workspace_manifest_path",
    "workspace_lock_git_blob": "workspace_lock_path",
    "codeowners_git_blob": "codeowners_path",
    "module_registry_git_blob": "module_registry_path",
    "module_coverage_git_blob": "module_coverage_path",
    "module_technical_reference_git_blob": "module_technical_reference_path",
    "technical_convergence_git_blob": "technical_convergence_path",
    "technical_convergence_gate_git_blob": "technical_convergence_gate_path",
    "technical_convergence_test_git_blob": "technical_convergence_test_path",
    "detailed_module_spec_index_git_blob": "detailed_module_spec_index_path",
    "current_snapshot_git_blob": "current_snapshot_path",
    "documentation_truth_git_blob": "documentation_truth_path",
    "repository_policy_git_blob": "repository_policy_path",
    "blocker_execution_git_blob": "blocker_execution_path",
    "blocker_execution_validator_git_blob": "blocker_execution_validator_path",
    "candidate_runtime_closure_git_blob": "candidate_runtime_closure_path",
    "candidate_runtime_closure_validator_git_blob": "candidate_runtime_closure_validator_path",
    "candidate_runtime_closure_architecture_git_blob": "candidate_runtime_closure_architecture_path",
    "task_archive_closure_git_blob": "task_archive_closure_path",
    "task_archive_closure_validator_git_blob": "task_archive_closure_validator_path",
    "task_archive_closure_architecture_git_blob": "task_archive_closure_architecture_path",
    "documentation_reference_gate_git_blob": "documentation_reference_gate_path",
    "module_coverage_gate_git_blob": "module_coverage_gate_path",
    "canonical_plan_gate_git_blob": "canonical_plan_gate_path",
    "node_decomposition_git_blob": "node_decomposition_path",
    "node_decomposition_gate_git_blob": "node_decomposition_gate_path",
    "required_baseline_workflow_git_blob": "required_baseline_workflow_path",
    "required_baseline_gate_git_blob": "required_baseline_gate_path",
    "plan_manifest_pin_gate_git_blob": "plan_manifest_pin_gate_path",
    "development_metadata_git_blob": "development_metadata_path",
    "independent_gates_git_blob": "independent_gates_path",
    "manifest_refresh_git_blob": "manifest_refresh_path",
}

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


def blob_at(commit: str, path: str) -> str:
    """Return the Git blob for *path* in a declared snapshot commit."""
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
            "invalid pin snapshot commit")
    value = git("rev-parse", f"{commit}:{path}")
    require(
        re.fullmatch(r"[0-9a-f]{40}", value) is not None,
        f"invalid Git blob for {path} at {commit}: {value}",
    )
    return value


def content_at(commit: str, path: str) -> bytes:
    """Read a tracked file from the immutable pin snapshot."""
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
            "invalid pin snapshot commit")
    result = subprocess.run(
        ["git", "cat-file", "blob", f"{commit}:{path}"],
        cwd=ROOT, check=True, capture_output=True,
    )
    return result.stdout


def sha256_at(commit: str, path: str) -> str:
    return hashlib.sha256(content_at(commit, path)).hexdigest()


def changed_paths_since(commit: str) -> set[str]:
    """Return tracked paths changed after the pin snapshot.

    The snapshot is always an ancestor of the checked-out source.  Comparing
    the path set, rather than every file hash, is what makes ordinary source
    changes cheap while preserving a hard failure for stale release inputs.
    """
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
            "invalid pin snapshot commit")
    paths: set[str] = set()
    for args in (("diff", "--name-only", f"{commit}..HEAD", "--"),
                 ("diff", "--name-only", "HEAD", "--"),
                 ("diff", "--cached", "--name-only", "HEAD", "--")):
        output = git(*args)
        paths.update(line for line in output.splitlines() if line)
    return paths


def changed_pin_paths(commit: str, pin_paths: set[str]) -> set[str]:
    """Return only release/source-bound inputs changed after the snapshot."""
    return changed_paths_since(commit) & pin_paths


def verify_assessed_baseline(manifest: dict[str, Any]) -> None:
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


def verify_optional_historical_source(commit: str, tree: str) -> bool:
    """Historical Git objects are optional, not inherited source acceptance.

    A normal clone of a squash/convergence mainline need not contain the old
    topic commit. Current source pins and the assessed ancestor are mandatory.
    When history is present, a contradictory object still fails closed.
    """
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "invalid historical commit")
    require(re.fullmatch(r"[0-9a-f]{40}", tree) is not None, "invalid historical tree")
    probe = subprocess.run(
        ["git", "cat-file", "--batch-check=%(objecttype)"],
        cwd=ROOT, input=commit+"\n", text=True, capture_output=True, check=True,
    ).stdout.strip()
    if probe == commit+" missing":
        return False
    require(probe == "commit", "historical source is not a commit")
    require(git("rev-parse", f"{commit}^{{tree}}") == tree,
            "historical commit/tree mismatch")
    return True


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
        type(manifest.get("workspace_crate_count")) is int
        and manifest["workspace_crate_count"] > 0,
        "manifest workspace crate count drift",
    )
    require(
        manifest.get("pin_refresh_policy") == PIN_REFRESH_POLICY,
        "manifest pin refresh policy drift",
    )
    snapshot_commit = manifest.get("pin_snapshot_commit")
    snapshot_tree = manifest.get("pin_snapshot_tree")
    require(
        isinstance(snapshot_commit, str)
        and re.fullmatch(r"[0-9a-f]{40}", snapshot_commit) is not None,
        "pin snapshot commit missing",
    )
    require(
        isinstance(snapshot_tree, str)
        and re.fullmatch(r"[0-9a-f]{40}", snapshot_tree) is not None,
        "pin snapshot tree missing",
    )
    require(
        git("rev-parse", f"{snapshot_commit}^{{tree}}") == snapshot_tree,
        "pin snapshot commit/tree mismatch",
    )
    require(
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", snapshot_commit, "HEAD"],
            cwd=ROOT,
        ).returncode
        == 0,
        "pin snapshot is not an ancestor of HEAD",
    )

    plan_path = manifest.get("plan_path")
    evidence_path = manifest.get("evidence_contract_path")
    require(isinstance(plan_path, str), "plan path missing")
    require(isinstance(evidence_path, str), "evidence contract path missing")
    require(
        sha256_at(snapshot_commit, plan_path) == manifest.get("plan_sha256"),
        "plan SHA-256 mismatch in pin snapshot",
    )
    require(
        sha256_at(snapshot_commit, evidence_path) == manifest.get("evidence_contract_sha256"),
        "evidence-contract SHA-256 mismatch in pin snapshot",
    )

    verify_assessed_baseline(manifest)

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
        manifest.get("repository_core_overlay_scope")
        == "historical-provenance-only-not-current-acceptance",
        "repository-core historical scope missing",
    )
    overlay_history_verified = verify_optional_historical_source(overlay_commit, overlay_tree)
    require(
        manifest.get("repository_core_overlay_absorbed") is True
        and manifest.get("repository_core_overlay", {}).get(
            "absorbed_into_selected_successor"
        )
        is True,
        "repository-core overlay absorption drift",
    )

    pinned = PIN_PATH_FIELDS

    # Every declared digest is checked against the immutable snapshot.  Only
    # paths changed after that snapshot are compared with the current tree;
    # this is the change-scoped part of the policy.  A normal source change
    # therefore leaves this gate read-only, while a protocol/manifest/gate
    # edit must run refresh_plan_manifest_pins_v1.py --write.
    pin_paths = {manifest.get(path_field) for path_field in PIN_PATH_FIELDS.values()}
    pin_paths.update({plan_path, evidence_path})
    pin_paths.update(
        manifest.get(path_field)
        for path_field in (
            "documentation_authority_path",
            "module_implementation_guide_path",
            "independent_review_policy_path",
            "documentation_contract_registry_path",
            "documentation_contract_gate_path",
            "documentation_contract_test_path",
            "development_metadata_path",
        )
    )
    require(all(isinstance(path, str) and path for path in pin_paths),
            "declared pin path missing")
    changed_pins = changed_pin_paths(snapshot_commit, pin_paths)

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
        actual = blob_at(snapshot_commit, path)
        require(
            actual == expected,
            f"{blob_field} mismatch in pin snapshot for {path}: {expected} != {actual}",
        )
        if path in changed_pins:
            current = blob(path)
            require(
                current == expected,
                f"stale pin for changed input {path}: {expected} != {current}; "
                "run scripts/ci/refresh_plan_manifest_pins_v1.py --write",
            )
        checked.append(
            {"blob_field": blob_field, "path": path, "blob": actual}
        )

    if plan_path in changed_pins:
        current = hashlib.sha256((ROOT / plan_path).read_bytes()).hexdigest()
        require(current == manifest.get("plan_sha256"),
                "stale plan SHA-256; run scripts/ci/refresh_plan_manifest_pins_v1.py --write")
    if evidence_path in changed_pins:
        current = hashlib.sha256((ROOT / evidence_path).read_bytes()).hexdigest()
        require(current == manifest.get("evidence_contract_sha256"),
                "stale evidence-contract SHA-256; run scripts/ci/refresh_plan_manifest_pins_v1.py --write")

    replay = manifest.get("replay")
    require(isinstance(replay, dict), "replay table missing")
    require(
        replay.get("technical_convergence_command")
        == "python3 scripts/ci/check_technical_convergence_v1.py",
        "technical convergence replay command drift",
    )
    require(
        replay.get("technical_convergence_test_command")
        == "python3 scripts/ci/test_technical_convergence_v1.py",
        "technical convergence mutant command drift",
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
        "pin_snapshot_commit": snapshot_commit,
        "changed_pinned_inputs": len(changed_pins),
        "overlay_source_commit": overlay_commit,
        "historical_overlay_object_verified": overlay_history_verified,
        "historical_evidence_acceptance_transferred": False,
        "technical_convergence_pinned": True,
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
