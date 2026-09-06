#!/usr/bin/env python3
"""Run a bounded exact-source Rust autofix and full local qualification once.

Only machine-applicable Rust source edits plus explicit known lint repairs are
permitted.  Cargo manifests, lockfiles, documentation, configuration and
machine readiness truth are immutable.  A candidate is published only after
both Rust workspaces pass format, check, test and strict Clippy at one exact
source and the remote branch lease remains unchanged.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
BRANCH = os.environ.get(
    "TARGET_BRANCH", "work/plan-v2-full-gap-closure-20260902"
)
CARGO = ("cargo", "+1.95.0")
SELF = Path("scripts/ci/trnm_plan_v2_repository_autofix_once_20260906b.py")
WORKFLOW = Path(
    ".github/workflows/trnm-plan-v2-repository-autofix-20260906b.yml"
)
CLEANUP = (
    Path("scripts/ci/trnm_plan_v2_repository_closure_once_20260906a.py"),
    Path(".github/workflows/trnm-plan-v2-repository-closure-20260906a.yml"),
    SELF,
    WORKFLOW,
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
CONTRACT_GOVERNANCE = Path("contracts/governance-guard/src/lib.rs")
CONTRACT_SETTLEMENT = Path("contracts/settlement-vault/src/lib.rs")
CONTRACT_BRIDGE = Path("contracts/bridge-relay/src/lib.rs")
MAX_CHANGED_RUST_FILES = 96
MAX_CHANGED_LINES = 6000


class ClosureError(RuntimeError):
    pass


def command_text(args: Iterable[str]) -> str:
    return " ".join(args)


def run(*args: str, capture: bool = False) -> str:
    print("+", command_text(args), flush=True)
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
        raise ClosureError(
            f"command failed ({result.returncode}): {command_text(args)}"
        )
    return (result.stdout or "").strip()


def run_autofix(*args: str) -> int:
    print("+", command_text(args), flush=True)
    result = subprocess.run(args, cwd=ROOT, text=True)
    print(f"autofix_return_code={result.returncode}", flush=True)
    return result.returncode


def replace_bounded(path: Path, old: str, new: str, maximum: int) -> int:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count > maximum:
        raise ClosureError(
            f"{path}: expected <= {maximum} occurrences, found {count}"
        )
    if count:
        target.write_text(text.replace(old, new), encoding="utf-8")
    return count


def apply_known_contract_repairs() -> None:
    target = ROOT / CONTRACT_GOVERNANCE
    text = target.read_text(encoding="utf-8")
    marker = "    #[allow(clippy::too_many_arguments)]\n    pub fn propose(\n"
    if marker not in text:
        count = replace_bounded(
            CONTRACT_GOVERNANCE,
            "    pub fn propose(\n",
            "    // Public governance ABI: every argument is independently "
            "validated and audited.\n"
            "    #[allow(clippy::too_many_arguments)]\n"
            "    pub fn propose(\n",
            1,
        )
        if count != 1:
            raise ClosureError(
                "governance propose lint is neither repaired nor uniquely patchable"
            )

    replace_bounded(
        CONTRACT_SETTLEMENT,
        'assert!(vault.balances.get("ghost").is_none());',
        'assert!(!vault.balances.contains_key("ghost"));',
        1,
    )
    replace_bounded(
        CONTRACT_SETTLEMENT,
        "&event.event_type[..],",
        "event.event_type,",
        1,
    )
    replace_bounded(
        CONTRACT_SETTLEMENT,
        'assert!(vault.balances.get("alice").is_none());',
        'assert!(!vault.balances.contains_key("alice"));',
        2,
    )
    replace_bounded(
        CONTRACT_BRIDGE,
        "&vec![replay_sig],",
        "&[replay_sig],",
        1,
    )


def remove_transient_machinery() -> None:
    for path in CLEANUP:
        target = ROOT / path
        if target.exists():
            target.unlink()


def rust_autofix(manifest: str) -> None:
    run_autofix(
        *CARGO,
        "clippy",
        "--fix",
        "--manifest-path",
        manifest,
        "--workspace",
        "--all-targets",
        "--locked",
        "--offline",
        "--allow-dirty",
        "--allow-staged",
        "--",
        "-D",
        "warnings",
    )
    run(*CARGO, "fmt", "--manifest-path", manifest, "--all")


def changed_paths() -> set[str]:
    return {
        line[3:]
        for line in run(
            "git", "status", "--short", "--untracked-files=all", capture=True
        ).splitlines()
        if line
    }


def assert_bounded_diff() -> None:
    paths = changed_paths()
    cleanup_paths = {str(path) for path in CLEANUP}
    source_paths = paths - cleanup_paths
    forbidden = [
        path
        for path in source_paths
        if not (
            path.endswith(".rs")
            and (path.startswith("contracts/") or path.startswith("trillionnium/"))
        )
    ]
    if forbidden:
        raise ClosureError(f"autofix touched forbidden paths: {sorted(forbidden)}")
    if len(source_paths) > MAX_CHANGED_RUST_FILES:
        raise ClosureError(
            f"autofix changed {len(source_paths)} Rust files; limit is "
            f"{MAX_CHANGED_RUST_FILES}"
        )

    numstat = run("git", "diff", "--numstat", capture=True)
    changed_lines = 0
    for line in numstat.splitlines():
        added, deleted, path = line.split("\t", 2)
        if added == "-" or deleted == "-":
            raise ClosureError(f"binary diff is forbidden: {path}")
        changed_lines += int(added) + int(deleted)
    if changed_lines > MAX_CHANGED_LINES:
        raise ClosureError(
            f"autofix changed {changed_lines} lines; limit is {MAX_CHANGED_LINES}"
        )
    required = {str(SELF), str(WORKFLOW)}
    if not required.issubset(paths):
        raise ClosureError(
            f"one-shot cleanup missing; required={sorted(required)} "
            f"changed={sorted(paths)}"
        )
    run("git", "diff", "--check")


def load_json(path: str) -> dict[str, Any]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def assert_fail_closed() -> None:
    truth = load_json("config/consensus-mainline.json")
    flags = (
        "all_gaps_closed",
        "production_candidate",
        "production_consensus_activation",
        "public_testnet_ready",
        "release_ready",
    )
    promoted = [name for name in flags if truth.get(name) is True]
    if promoted:
        raise ClosureError(f"autofix cannot promote external truth: {promoted}")
    immutable = (
        "config/consensus-mainline.json",
        "contracts/Cargo.toml",
        "contracts/Cargo.lock",
        "trillionnium/Cargo.toml",
        "trillionnium/Cargo.lock",
    )
    dirty = run("git", "status", "--short", "--", *immutable, capture=True)
    if dirty:
        raise ClosureError(f"autofix modified immutable authority inputs:\n{dirty}")


def run_repository_validators() -> None:
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
        ("python3", "scripts/ci/check_build_closures_v1.py", "--verify-cargo-tree"),
        ("bash", "scripts/ci/check_poco_bft_mainline_truth.sh", "--pre-cutover"),
        ("bash", "scripts/project-preflight.sh", "--audit"),
    ):
        run(*command)


def validate_workspace(manifest: str) -> None:
    run(
        *CARGO,
        "fmt",
        "--manifest-path",
        manifest,
        "--all",
        "--",
        "--check",
    )
    for command in ("check", "test", "clippy"):
        args = [
            *CARGO,
            command,
            "--manifest-path",
            manifest,
            "--workspace",
            "--all-targets",
            "--locked",
            "--offline",
        ]
        if command == "clippy":
            args.extend(("--", "-D", "warnings"))
        run(*args)


def validate(candidate: str) -> None:
    if run("git", "rev-parse", "HEAD", capture=True) != candidate:
        raise ClosureError("candidate moved during validation")
    if run(
        "git", "status", "--porcelain", "--untracked-files=all", capture=True
    ):
        raise ClosureError("candidate is dirty before validation")
    run_repository_validators()
    validate_workspace("contracts/Cargo.toml")
    validate_workspace("trillionnium/Cargo.toml")
    assert_fail_closed()
    run("git", "diff", "--check")
    if run(
        "git", "status", "--porcelain", "--untracked-files=all", capture=True
    ):
        raise ClosureError("validation mutated candidate")


def main() -> int:
    os.chdir(ROOT)
    start = run("git", "rev-parse", "HEAD", capture=True)
    expected = os.environ.get("GITHUB_SHA")
    if expected and expected != start:
        raise ClosureError(f"source mismatch: {expected} != {start}")
    if run(
        "git", "status", "--porcelain", "--untracked-files=all", capture=True
    ):
        raise ClosureError("dirty initial checkout")

    apply_known_contract_repairs()
    rust_autofix("contracts/Cargo.toml")
    rust_autofix("trillionnium/Cargo.toml")
    remove_transient_machinery()
    assert_fail_closed()
    assert_bounded_diff()

    run("git", "add", "--all")
    staged = subprocess.run(
        ("git", "diff", "--cached", "--quiet"), cwd=ROOT
    ).returncode
    if staged == 0:
        raise ClosureError("autofix transaction produced no candidate")
    if staged != 1:
        raise ClosureError(f"git diff failed with status {staged}")

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
        "fix(plan-v2): apply bounded strict Rust autofixes",
    )
    candidate = run("git", "rev-parse", "HEAD", capture=True)
    validate(candidate)

    run("git", "fetch", "origin", f"refs/heads/{BRANCH}")
    remote = run("git", "rev-parse", "FETCH_HEAD", capture=True)
    if remote != start:
        raise ClosureError(f"remote moved: {remote} != {start}")
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
