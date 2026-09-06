#!/usr/bin/env python3
"""Validate and lease-publish the persistent replay/Core-ack Plan v2 slice."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BRANCH = os.environ.get("TARGET_BRANCH", "work/plan-v2-full-gap-closure-20260902")
CARGO = ("cargo", "+1.95.0")
MANIFEST = "trillionnium/Cargo.toml"
LOCK = Path("trillionnium/Cargo.lock")
PLAN = Path("docs/development/plan-manifest-v1.toml")
DOC_TRUTH = Path("config/documentation-truth-v1.json")
DOC = "docs/development/packages/TRNM_P2_NET_PERSISTENT_REPLAY_CORE_ACK_V0.md"
ALLOWED = {
    str(DOC_TRUTH), str(PLAN), str(LOCK),
    "trillionnium/crates/trnm-durable-file-adapters-v0/src/bin/trnm-candidate-persistent-host.rs",
    "trillionnium/crates/trnm-durable-file-adapters-v0/src/lib.rs",
    "trillionnium/crates/trnm-poco-node-io/src/authenticated_p2p.rs",
}


def run(*args: str, capture: bool = False) -> str:
    print("+", " ".join(args), flush=True)
    p = subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.STDOUT if capture else None)
    if p.returncode:
        if capture and p.stdout: print(p.stdout, flush=True)
        raise RuntimeError(f"command failed ({p.returncode}): {' '.join(args)}")
    return (p.stdout or "").strip()


def no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out: raise RuntimeError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def load_json(path: Path) -> Any:
    return json.loads((ROOT/path).read_text(encoding="utf-8"), object_pairs_hook=no_dupes)


def repair_doc_truth() -> None:
    path = ROOT/DOC_TRUTH
    data = load_json(DOC_TRUTH)
    tracked = set(run("git", "ls-files", "docs/development/*.md", "docs/development/**/*.md",
                      capture=True).splitlines())
    if DOC not in tracked: raise RuntimeError(f"required tracked document absent: {DOC}")
    matches: list[list[str]] = []
    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for child in value.values(): walk(child)
        elif isinstance(value, list) and all(isinstance(x, str) for x in value):
            values = set(value)
            if values == tracked-{DOC} or values == tracked: matches.append(value)
    walk(data)
    if not matches: raise RuntimeError("exact docs/development allowlist not found")
    if len(matches) > 1:
        exact_missing = [row for row in matches if set(row) == tracked-{DOC}]
        if len(exact_missing) == 1: matches = exact_missing
        else: raise RuntimeError(f"ambiguous exact development allowlists: {len(matches)}")
    if DOC not in matches[0]:
        matches[0].append(DOC); matches[0].sort()
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")


def pin(name: str, path: Path) -> None:
    blob = run("git", "hash-object", str(path), capture=True)
    plan = ROOT/PLAN
    text = plan.read_text(encoding="utf-8")
    updated, count = re.subn(rf'(?m)^{re.escape(name)}\s*=\s*"[0-9a-f]+"\s*$',
                             f'{name} = "{blob}"', text)
    if count != 1: raise RuntimeError(f"expected one {name}, found {count}")
    plan.write_text(updated, encoding="utf-8")


def patch_slice() -> None:
    sys.path.insert(0, str((ROOT/"scripts/ci").resolve()))
    os.environ["EXPECTED_PARENT_SHA"] = run("git", "rev-parse", "HEAD^", capture=True)
    import trnm_plan_v2_persistent_peer_replay_once as base
    patch_error: Exception | None = None
    try: base.patch_sources()
    except Exception as exc:
        patch_error = exc
        print(f"patch_sources diagnostic: {exc!r}", flush=True)
    run("git", "checkout", "HEAD", "--", ".github/workflows")
    repair_doc_truth()
    run(*CARGO, "generate-lockfile", "--manifest-path", MANIFEST, "--offline")
    pin("workspace_lock_git_blob", LOCK)
    pin("documentation_truth_git_blob", DOC_TRUTH)
    run(*CARGO, "fmt", "--manifest-path", MANIFEST, "--all")
    changed = {line[3:] for line in run("git", "status", "--short", capture=True).splitlines() if line}
    unexpected = changed-ALLOWED
    if unexpected: raise RuntimeError(f"unexpected mutations: {sorted(unexpected)}")
    if patch_error and not changed:
        raise RuntimeError("patch failed without an independently valid authority repair") from patch_error


def assert_fail_closed() -> None:
    truth = load_json(Path("config/consensus-mainline.json"))
    flags = ("all_gaps_closed", "production_candidate", "production_consensus_activation",
             "public_testnet_ready", "release_ready")
    promoted = [name for name in flags if truth.get(name) is True]
    if promoted: raise RuntimeError(f"publisher cannot promote external truth: {promoted}")
    if run("git", "status", "--short", "--", "config/consensus-mainline.json", capture=True):
        raise RuntimeError("publisher modified consensus-mainline truth")


def validate(candidate: str) -> None:
    if run("git", "rev-parse", "HEAD", capture=True) != candidate: raise RuntimeError("candidate moved")
    if run("git", "status", "--porcelain", "--untracked-files=all", capture=True):
        raise RuntimeError("candidate is dirty")
    for cmd in (
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
    ): run(*cmd)
    run(*CARGO, "fmt", "--manifest-path", MANIFEST, "--all", "--", "--check")
    run(*CARGO, "check", "--manifest-path", MANIFEST, "--workspace", "--all-targets",
        "--locked", "--offline")
    for package, features in (
        ("trnm-poco-node-io", "candidate-pacemaker,candidate-authenticated-p2p"),
        ("trnm-durable-file-adapters-v0", "candidate-peer-replay"),
        ("trnm-poco-node-host", "candidate-networked-authority"),
    ):
        run(*CARGO, "test", "--manifest-path", MANIFEST, "-p", package,
            "--features", features, "--all-targets", "--locked", "--offline")
        run(*CARGO, "clippy", "--manifest-path", MANIFEST, "-p", package,
            "--features", features, "--all-targets", "--locked", "--offline", "--",
            "-D", "warnings")
    assert_fail_closed(); run("git", "diff", "--check")
    if run("git", "status", "--porcelain", "--untracked-files=all", capture=True):
        raise RuntimeError("validation mutated candidate")


def main() -> int:
    os.chdir(ROOT)
    start = run("git", "rev-parse", "HEAD", capture=True)
    expected = os.environ.get("GITHUB_SHA")
    if expected and expected != start: raise RuntimeError(f"source mismatch: {expected} != {start}")
    if run("git", "status", "--porcelain", "--untracked-files=all", capture=True):
        raise RuntimeError("dirty initial checkout")
    patch_slice(); assert_fail_closed(); run("git", "add", "--", *sorted(ALLOWED))
    diff = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT)
    if diff.returncode == 0: candidate = start
    elif diff.returncode == 1:
        run("git", "config", "user.name", "trillionnium-plan-v2-bot")
        run("git", "config", "user.email", "trillionnium-plan-v2-bot@users.noreply.github.com")
        run("git", "commit", "-m", "feat(plan-v2): close persistent peer replay Core acknowledgement")
        candidate = run("git", "rev-parse", "HEAD", capture=True)
    else: raise RuntimeError(f"git diff return={diff.returncode}")
    validate(candidate)
    if candidate != start:
        run("git", "fetch", "origin", f"refs/heads/{BRANCH}")
        remote = run("git", "rev-parse", "FETCH_HEAD", capture=True)
        if remote != start: raise RuntimeError(f"remote moved: {remote} != {start}")
        run("git", "push", f"--force-with-lease=refs/heads/{BRANCH}:{start}", "origin",
            f"{candidate}:refs/heads/{BRANCH}")
    print(f"qualified_candidate={candidate}", flush=True)
    return 0

if __name__ == "__main__": raise SystemExit(main())
