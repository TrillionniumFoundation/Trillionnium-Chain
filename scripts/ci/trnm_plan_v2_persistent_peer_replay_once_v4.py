#!/usr/bin/env python3
"""Lease-publish the final repository-owned policy and contract lint repairs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BRANCH = os.environ.get(
    "TARGET_BRANCH", "work/plan-v2-full-gap-closure-20260902"
)
CARGO = ("cargo", "+1.95.0")
TRANSIENT_WORKFLOWS = (
    Path(".github/workflows/trnm-plan-v2-cargo-lock-canonicalize-once.yml"),
    Path(
        ".github/workflows/"
        "trnm-plan-v2-persistent-peer-replay-transaction-v3.yml"
    ),
    Path(
        ".github/workflows/"
        "trnm-plan-v2-persistent-peer-replay-transaction-v4.yml"
    ),
)
CONTRACT_FILES = (
    Path("contracts/governance-guard/src/lib.rs"),
    Path("contracts/settlement-vault/src/lib.rs"),
    Path("contracts/bridge-relay/src/lib.rs"),
)
ALLOWED = {str(path) for path in (*TRANSIENT_WORKFLOWS, *CONTRACT_FILES)}


def run(*args: str, capture: bool = False) -> str:
    print("+", " ".join(args), flush=True)
    result = subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    if result.returncode:
        if capture and result.stdout:
            print(result.stdout, flush=True)
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(args)}"
        )
    return (result.stdout or "").strip()


def replace_exact(path: Path, old: str, new: str, expected: int = 1) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != expected:
        raise RuntimeError(
            f"{path}: expected {expected} occurrences, found {count}: {old!r}"
        )
    target.write_text(text.replace(old, new), encoding="utf-8")


def patch_repository_owned_blockers() -> None:
    for path in TRANSIENT_WORKFLOWS:
        target = ROOT / path
        if not target.is_file():
            raise RuntimeError(f"transient workflow is absent: {path}")
        target.unlink()

    replace_exact(
        CONTRACT_FILES[0],
        "    pub fn propose(\n",
        "    // Retain the explicit external contract call shape; each field "
        "is independently audited.\n"
        "    #[allow(clippy::too_many_arguments)]\n"
        "    pub fn propose(\n",
    )
    replace_exact(
        CONTRACT_FILES[1],
        'assert!(vault.balances.get("ghost").is_none());',
        'assert!(!vault.balances.contains_key("ghost"));',
    )
    replace_exact(
        CONTRACT_FILES[1],
        "&event.event_type[..],",
        "event.event_type,",
    )
    replace_exact(
        CONTRACT_FILES[1],
        'assert!(vault.balances.get("alice").is_none());',
        'assert!(!vault.balances.contains_key("alice"));',
        expected=2,
    )
    replace_exact(
        CONTRACT_FILES[2],
        "&vec![replay_sig],",
        "&[replay_sig],",
    )

    run(
        *CARGO,
        "fmt",
        "--manifest-path",
        "contracts/Cargo.toml",
        "--all",
    )
    changed = {
        line[3:]
        for line in run(
            "git", "status", "--short", "--untracked-files=all", capture=True
        ).splitlines()
        if line
    }
    unexpected = changed - ALLOWED
    if unexpected:
        raise RuntimeError(f"unexpected mutations: {sorted(unexpected)}")
    if changed != ALLOWED:
        raise RuntimeError(
            f"incomplete repair set: expected={sorted(ALLOWED)} "
            f"actual={sorted(changed)}"
        )


def load_truth() -> dict[str, Any]:
    return json.loads(
        (ROOT / "config/consensus-mainline.json").read_text(encoding="utf-8")
    )


def assert_fail_closed() -> None:
    truth = load_truth()
    flags = (
        "all_gaps_closed",
        "production_candidate",
        "production_consensus_activation",
        "public_testnet_ready",
        "release_ready",
    )
    promoted = [name for name in flags if truth.get(name) is True]
    if promoted:
        raise RuntimeError(f"repair cannot promote external truth: {promoted}")
    if run(
        "git",
        "status",
        "--short",
        "--",
        "config/consensus-mainline.json",
        capture=True,
    ):
        raise RuntimeError("repair modified consensus-mainline truth")


def validate(candidate: str) -> None:
    if run("git", "rev-parse", "HEAD", capture=True) != candidate:
        raise RuntimeError("candidate moved")
    if run(
        "git", "status", "--porcelain", "--untracked-files=all", capture=True
    ):
        raise RuntimeError("candidate is dirty")

    for command in (
        ("bash", "scripts/check_ci_runner_policy.sh", "--head"),
        ("bash", "scripts/check_cargo_offline_policy.sh", "--head"),
        ("bash", "scripts/ci/check_canonical_development_plan.sh"),
        ("python3", "scripts/ci/check_plan_manifest_pins_v1.py"),
        ("python3", "scripts/ci/check_documentation_reference_closure_v1.py"),
        ("python3", "scripts/ci/check_module_coverage_v1.py"),
        ("python3", "scripts/ci/check_repository_truth_v1.py"),
        ("python3", "scripts/ci/check_required_baseline_closure_v1.py"),
        ("python3", "scripts/ci/check_blocker_execution_v1.py"),
        ("bash", "scripts/ci/check_poco_bft_mainline_truth.sh", "--pre-cutover"),
        ("bash", "scripts/project-preflight.sh", "--audit"),
    ):
        run(*command)

    run(
        *CARGO,
        "fmt",
        "--manifest-path",
        "contracts/Cargo.toml",
        "--all",
        "--",
        "--check",
    )
    for command in ("check", "test", "clippy"):
        args = [
            *CARGO,
            command,
            "--manifest-path",
            "contracts/Cargo.toml",
            "--workspace",
            "--all-targets",
            "--locked",
            "--offline",
        ]
        if command == "clippy":
            args.extend(("--", "-D", "warnings"))
        run(*args)

    assert_fail_closed()
    run("git", "diff", "--check")
    if run(
        "git", "status", "--porcelain", "--untracked-files=all", capture=True
    ):
        raise RuntimeError("validation mutated candidate")


def main() -> int:
    os.chdir(ROOT)
    start = run("git", "rev-parse", "HEAD", capture=True)
    expected = os.environ.get("GITHUB_SHA")
    if expected and expected != start:
        raise RuntimeError(f"source mismatch: {expected} != {start}")
    if run(
        "git", "status", "--porcelain", "--untracked-files=all", capture=True
    ):
        raise RuntimeError("dirty initial checkout")

    patch_repository_owned_blockers()
    assert_fail_closed()
    run("git", "add", "--all", "--", *sorted(ALLOWED))
    if subprocess.run(
        ("git", "diff", "--cached", "--quiet"), cwd=ROOT
    ).returncode != 1:
        raise RuntimeError("repair produced no staged candidate or git failed")

    run("git", "config", "user.name", "trillionnium-plan-v2-bot")
    run(
        "git",
        "config",
        "user.email",
        "trillionnium-plan-v2-bot@users.noreply.github.com",
    )
    run(
        "git",
        "commit",
        "-m",
        "ci(plan-v2): close policy and contract blockers",
    )
    candidate = run("git", "rev-parse", "HEAD", capture=True)
    validate(candidate)

    run("git", "fetch", "origin", f"refs/heads/{BRANCH}")
    remote = run("git", "rev-parse", "FETCH_HEAD", capture=True)
    if remote != start:
        raise RuntimeError(f"remote moved: {remote} != {start}")
    run(
        "git",
        "push",
        f"--force-with-lease=refs/heads/{BRANCH}:{start}",
        "origin",
        f"{candidate}:refs/heads/{BRANCH}",
    )
    print(f"qualified_candidate={candidate}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
