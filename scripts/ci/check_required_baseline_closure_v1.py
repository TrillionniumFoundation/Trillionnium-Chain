#!/usr/bin/env python3
"""Fail-closed contract for the actor-independent required baseline."""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY = ROOT / "config/repository-policy-v1.json"


class BaselineClosureError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BaselineClosureError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BaselineClosureError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=strict_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BaselineClosureError(
            f"{path.relative_to(ROOT)}: invalid JSON: {error}"
        ) from error
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: object required")
    return value


def require_tokens(text: str, tokens: tuple[str, ...], label: str) -> None:
    missing = [token for token in tokens if token not in text]
    require(not missing, f"{label}: missing required tokens: {missing}")


def main() -> int:
    policy = load_json(POLICY)
    workflow_relative = policy.get("baseline_workflow")
    require(
        isinstance(workflow_relative, str) and workflow_relative,
        "baseline_workflow path missing",
    )
    workflow_path = ROOT / workflow_relative
    require(workflow_path.is_file(), f"baseline workflow missing: {workflow_relative}")
    workflow = workflow_path.read_text(encoding="utf-8")

    required_checks = policy.get("required_check_names")
    require(
        isinstance(required_checks, list)
        and required_checks
        and all(isinstance(item, str) and item for item in required_checks),
        "required_check_names missing",
    )
    require(len(set(required_checks)) == len(required_checks), "required check names duplicate")
    for check in required_checks:
        require(
            len(re.findall(rf"(?m)^\s+name:\s*{re.escape(check)}\s*$", workflow)) == 1,
            f"required job name missing or duplicated: {check}",
        )

    header = workflow.split("jobs:", 1)[0]
    require(
        re.search(r"(?m)^\s*pull_request:\s*$", header) is not None,
        "baseline workflow must run on every pull request",
    )
    require("paths:" not in header, "baseline pull_request trigger may not use path filters")
    require("self-hosted" not in workflow, "required baseline may not depend on self-hosted runners")
    require(
        "github.actor" not in workflow and "github.triggering_actor" not in workflow,
        "required baseline may not contain actor allowlists",
    )
    require(
        workflow.count("runs-on: ubuntu-24.04") == len(required_checks),
        "every required job must use the pinned hosted runner",
    )
    require("runs-on: ubuntu-latest" not in workflow, "moving ubuntu-latest is forbidden")

    exact_source = (
        "TRNM_EXPECTED_SOURCE_SHA: ${{ github.event_name == 'pull_request' && "
        "github.event.pull_request.head.sha || github.sha }}"
    )
    require(exact_source in workflow, "exact pull-request head binding missing")
    require(
        workflow.count("ref: ${{ env.TRNM_EXPECTED_SOURCE_SHA }}") == len(required_checks),
        "every required job must check out the exact source",
    )
    require(
        workflow.count("persist-credentials: false") == len(required_checks),
        "every required job must disable persisted checkout credentials",
    )
    require(
        workflow.count('run: test "$(git rev-parse HEAD)" = "${TRNM_EXPECTED_SOURCE_SHA}"')
        == len(required_checks),
        "every required job must assert exact source identity",
    )

    require_tokens(
        workflow,
        (
            "bash scripts/ci/check_canonical_development_plan.sh",
            "python3 scripts/ci/check_module_coverage_v1.py",
            "python3 scripts/ci/check_node_decomposition_v1.py",
            "python3 scripts/ci/check_required_baseline_closure_v1.py",
            "python3 scripts/ci/check_build_closures_v1.py",
            "cargo test --workspace --all-targets --locked",
            "cargo check --manifest-path contracts/Cargo.toml --workspace --all-targets --locked",
            "cargo test --manifest-path contracts/Cargo.toml --workspace --all-targets --locked",
            "cargo clippy --manifest-path contracts/Cargo.toml --workspace --all-targets --locked -- -D warnings",
            "-p trnm-poco-node-cli --bin trnm-poco-node-cli",
            "--locked -- status",
            "--locked -- start",
            "\"start_permitted\":false",
        ),
        "required baseline closure",
    )

    clippy_packages = (
        "trnm-state",
        "trnm-consensus-types",
        "trnm-consensus-crypto",
        "trnm-consensus-core",
        "trnm-consensus-safety-rules",
        "trnm-consensus-safety-store",
        "trnm-consensus-signer-journal",
        "trnm-native-application",
        "trnm-native-application-sqlite",
        "trnm-native-execution-v0",
        "trnm-poco-node",
        "trnm-poco-node-authority",
        "trnm-poco-node-io",
        "trnm-poco-node-host",
        "trnm-poco-node-cli",
    )
    for package in clippy_packages:
        require(package in workflow, f"strict Clippy package missing: {package}")

    rust_job = re.search(
        r"(?ms)^  rust-baseline:\n(?P<body>.*)\Z",
        workflow,
    )
    require(rust_job is not None, "rust-baseline job missing")
    timeout = re.search(r"(?m)^\s{4}timeout-minutes:\s*(\d+)\s*$", rust_job.group("body"))
    require(timeout is not None and int(timeout.group(1)) >= 120, "rust-baseline timeout too small")

    required_paths = policy.get("required_paths")
    require(isinstance(required_paths, list), "repository policy required_paths missing")
    for path in (
        ".github/workflows/trnm-required-baseline.yml",
        "config/build-closures-v1.toml",
        "config/node-decomposition-v1.toml",
        "docs/architecture/TRNM_POCO_NODE_DECOMPOSITION_V1.md",
        "scripts/ci/check_build_closures_v1.py",
        "scripts/ci/check_node_decomposition_v1.py",
        "scripts/ci/check_required_baseline_closure_v1.py",
    ):
        require(path in required_paths, f"repository policy does not require {path}")
        require((ROOT / path).exists(), f"required closure input missing: {path}")

    report = {
        "schema": "trnm-required-baseline-closure-v1",
        "required_checks": required_checks,
        "actor_independent": True,
        "hosted_runner": "ubuntu-24.04",
        "full_workspace_all_targets_test": True,
        "contract_workspace_checked": True,
        "node_decomposition_required": True,
        "node_boundary_clippy_package_count": len(clippy_packages),
        "production_candidate": False,
        "production_consensus_activation": False,
        "release_ready": False,
        "result": "PASS",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BaselineClosureError as error:
        print(f"required baseline closure failed: {error}", file=sys.stderr)
        raise SystemExit(2)
