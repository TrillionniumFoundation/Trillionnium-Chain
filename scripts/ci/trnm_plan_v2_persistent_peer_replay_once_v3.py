#!/usr/bin/env python3
"""Build, validate and fast-forward publish the persistent replay closure."""
from __future__ import annotations
import json, os, re, subprocess, sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BRANCH = os.environ.get("TARGET_BRANCH", "work/plan-v2-full-gap-closure-20260902")
PLAN = Path("docs/development/plan-manifest-v1.toml")
DOC_TRUTH = Path("config/documentation-truth-v1.json")
LOCK = Path("trillionnium/Cargo.lock")
MANIFEST = "trillionnium/Cargo.toml"
DOC = "docs/development/packages/TRNM_P2_NET_PERSISTENT_REPLAY_CORE_ACK_V0.md"
ALLOWED = {
    str(DOC_TRUTH), str(PLAN), str(LOCK),
    "trillionnium/crates/trnm-durable-file-adapters-v0/src/bin/trnm-candidate-persistent-host.rs",
    "trillionnium/crates/trnm-durable-file-adapters-v0/src/lib.rs",
    "trillionnium/crates/trnm-poco-node-io/src/authenticated_p2p.rs",
}


def run(*args: str, capture: bool = False) -> str:
    print("+", " ".join(args), flush=True)
    p = subprocess.run(args, cwd=ROOT, check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None)
    return (p.stdout or "").strip()


def load_no_dupes(path: Path) -> Any:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out: raise RuntimeError(f"duplicate JSON key: {key}")
            out[key] = value
        return out
    return json.loads((ROOT/path).read_text(), object_pairs_hook=hook)


def repair_document_truth() -> None:
    data = load_no_dupes(DOC_TRUTH)
    matches: list[list[str]] = []
    def walk(value: Any, keys: tuple[str, ...] = ()) -> None:
        if isinstance(value, dict):
            for key, child in value.items(): walk(child, keys+(key,))
        elif isinstance(value, list) and all(isinstance(x, str) for x in value):
            hint = ".".join(keys).lower()
            dev = [x for x in value if x.startswith("docs/development/")]
            if DOC not in value and len(dev) >= 2 and len(dev) == len(value) and (
                "allow" in hint or "development" in hint or "markdown" in hint):
                matches.append(value)
    walk(data)
    if DOC not in (ROOT/DOC_TRUTH).read_text():
        if len(matches) != 1: raise RuntimeError(f"development allowlist matches={len(matches)}")
        matches[0].append(DOC); matches[0].sort()
        (ROOT/DOC_TRUTH).write_text(json.dumps(data, indent=2, ensure_ascii=False)+"\n")


def pin(name: str, path: Path) -> None:
    blob = run("git", "hash-object", str(path), capture=True)
    text = (ROOT/PLAN).read_text()
    updated, count = re.subn(rf'(?m)^{re.escape(name)}\s*=\s*"[0-9a-f]+"\s*$',
                             f'{name} = "{blob}"', text)
    if count != 1: raise RuntimeError(f"manifest assignment {name}: {count}")
    (ROOT/PLAN).write_text(updated)


def patch() -> None:
    sys.path.insert(0, str((ROOT/"scripts/ci").resolve()))
    os.environ["EXPECTED_PARENT_SHA"] = run("git", "rev-parse", "HEAD^", capture=True)
    import trnm_plan_v2_persistent_peer_replay_once as base
    try:
        base.patch_sources()
    except Exception as exc:
        print(f"patch_sources diagnostic: {exc!r}", flush=True)
    run("git", "checkout", "HEAD", "--", ".github/workflows")
    repair_document_truth()
    run("cargo", "+1.95.0", "generate-lockfile", "--manifest-path", MANIFEST, "--offline")
    pin("workspace_lock_git_blob", LOCK)
    pin("documentation_truth_git_blob", DOC_TRUTH)
    run("cargo", "+1.95.0", "fmt", "--manifest-path", MANIFEST, "--all")
    changed = {line[3:] for line in run("git", "status", "--short", capture=True).splitlines() if line}
    extra = changed-ALLOWED
    if extra: raise RuntimeError(f"unexpected mutations: {sorted(extra)}")


def fail_closed() -> None:
    truth = load_no_dupes(Path("config/consensus-mainline.json"))
    names = ("all_gaps_closed", "production_candidate", "production_consensus_activation",
             "public_testnet_ready", "release_ready")
    if [n for n in names if truth.get(n) is True]:
        raise RuntimeError("publisher cannot promote external or activation truth")
    if run("git", "status", "--short", "--", "config/consensus-mainline.json", capture=True):
        raise RuntimeError("publisher modified consensus-mainline truth")


def validate(candidate: str) -> None:
    if run("git", "rev-parse", "HEAD", capture=True) != candidate: raise RuntimeError("HEAD moved")
    if run("git", "status", "--porcelain", "--untracked-files=all", capture=True):
        raise RuntimeError("candidate is not clean")
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
    run("cargo", "+1.95.0", "fmt", "--manifest-path", MANIFEST, "--all", "--", "--check")
    run("cargo", "+1.95.0", "check", "--manifest-path", MANIFEST,
        "--workspace", "--all-targets", "--locked", "--offline")
    for package, features in (
        ("trnm-poco-node-io", "candidate-pacemaker,candidate-authenticated-p2p"),
        ("trnm-durable-file-adapters-v0", "candidate-peer-replay"),
        ("trnm-poco-node-host", "candidate-networked-authority"),
    ):
        run("cargo", "+1.95.0", "test", "--manifest-path", MANIFEST, "-p", package,
            "--features", features, "--all-targets", "--locked", "--offline")
        run("cargo", "+1.95.0", "clippy", "--manifest-path", MANIFEST, "-p", package,
            "--features", features, "--all-targets", "--locked", "--offline", "--", "-D", "warnings")
    fail_closed(); run("git", "diff", "--check")
    if run("git", "status", "--porcelain", "--untracked-files=all", capture=True):
        raise RuntimeError("validation mutated candidate")


def main() -> int:
    os.chdir(ROOT)
    start = run("git", "rev-parse", "HEAD", capture=True)
    if os.environ.get("GITHUB_SHA") not in (None, start): raise RuntimeError("checkout/source mismatch")
    if run("git", "status", "--porcelain", "--untracked-files=all", capture=True):
        raise RuntimeError("dirty initial checkout")
    patch(); fail_closed(); run("git", "add", "--", *sorted(ALLOWED))
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
        run("git", "push", f"--force-with-lease=refs/heads/{BRANCH}:{start}",
            "origin", f"{candidate}:refs/heads/{BRANCH}")
    print(f"qualified_candidate={candidate}")
    return 0

if __name__ == "__main__": raise SystemExit(main())
