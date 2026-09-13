#!/usr/bin/env python3
"""Apply the remaining deterministic repository-owned Plan v2 repairs once.

The transaction is intentionally narrow: it may repair only the known strict
contract lints and remove transient closure machinery.  It validates the
result against the canonical repository gates and lease-pushes only when the
remote branch has not moved.
"""
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
SELF = Path("scripts/ci/trnm_plan_v2_repository_closure_once_20260906a.py")
WORKFLOW = Path(
    ".github/workflows/trnm-plan-v2-repository-closure-20260906a.yml"
)
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
    WORKFLOW,
)
CONTRACT_FILES = (
    Path("contracts/governance-guard/src/lib.rs"),
    Path("contracts/settlement-vault/src/lib.rs"),
    Path("contracts/bridge-relay/src/lib.rs"),
)
ALLOWED = {str(path) for path in (*TRANSIENT_WORKFLOWS, *CONTRACT_FILES, SELF)}


class ClosureError(RuntimeError):
    pass


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
        raise ClosureError(
            f"command failed ({result.returncode}): {' '.join(args)}"
        )
    return (result.stdout or "").strip()


def replace_if_present(path: Path, old: str, new: str, maximum: int) -> int:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count > maximum:
        raise ClosureError(
            f"{path}: expected no more than {maximum} occurrences, found {count}"
        )
    if count:
        target.write_text(text.replace(old, new), encoding="utf-8")
    return count


def patch_repository_owned_blockers() -> None:
    for path in TRANSIENT_WORKFLOWS:
        target = ROOT / path
        if target.exists():
            target.unlink()

    governance = ROOT / CONTRACT_FILES[0]
    governance_text = governance.read_text(encoding="utf-8")
    marker = "    #[allow(clippy::too_many_arguments)]\n    pub fn propose(\n"
    if marker not in governance_text:
        replaced = replace_if_present(
            CONTRACT_FILES[0],
            "    pub fn propose(\n",
            "    // Public governance ABI: every argument is independently "
            "validated and audited.\n"
            "    #[allow(clippy::too_many_arguments)]\n"
            "    pub fn propose(\n",
            1,
        )
        if replaced != 1:
            raise ClosureError(
                "governance propose lint is neither repaired nor uniquely patchable"
            )

    replace_if_present(
        CONTRACT_FILES[1],
        'assert!(vault.balances.get("ghost").is_none());',
        'assert!(!vault.balances.contains_key("ghost"));',
        1,
    )
    replace_if_present(
        CONTRACT_FILES[1],
        "&event.event_type[..],",
        "event.event_type,",
        1,
    )
    replace_if_present(
        CONTRACT_FILES[1],
        'assert!(vault.balances.get("alice").is_none());',
        'assert!(!vault.balances.contains_key("alice"));',
        2,
    )
    replace_if_present(
        CONTRACT_FILES[2],
        "&vec![replay_sig],",
        "&[replay_sig],",
        1,
    )

    self_target = ROOT / SELF
    if self_target.exists():
        self_target.unlink()

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
        raise ClosureError(f"unexpected mutations: {sorted(unexpected)}")
    required_cleanup = {str(SELF), str(WORKFLOW)}
    if not required_cleanup.issubset(changed):
        raise ClosureError(
            f"one-shot cleanup is incomplete: changed={sorted(changed)}"
        )


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
        raise ClosureError(
            f"repository repair may not promote external truth: {promoted}"
        )
    if run(
        "git",
        "status",
        "--short",
        "--",
        "config/consensus-mainline.json",
        capture=True,
    ):
        raise ClosureError("repair modified consensus-mainline truth")


def validate(candidate: str) -> None:
    if run("git", "rev-parse", "HEAD", capture=True) != candidate:
        raise ClosureError("candidate moved during validation")
    if run(
        "git", "status", "--porcelain", "--untracked-files=all", capture=True
    ):
        raise ClosureError("candidate is dirty before validation")

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

    run(
        *CARGO,
        "fmt",
        "--manifest-path",
        "trillionnium/Cargo.toml",
        "--all",
        "--",
        "--check",
    )
    run(
        *CARGO,
        "check",
        "--manifest-path",
        "trillionnium/Cargo.toml",
        "--workspace",
        "--all-targets",
        "--locked",
        "--offline",
    )
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

    patch_repository_owned_blockers()
    assert_fail_closed()
    run("git", "add", "--all")
    staged = subprocess.run(
        ("git", "diff", "--cached", "--quiet"), cwd=ROOT
    ).returncode
    if staged == 0:
        raise ClosureError("closure transaction produced no candidate")
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
        "fix(plan-v2): close deterministic repository blockers",
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
