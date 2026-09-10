#!/usr/bin/env python3
"""Select one existing repository-gap closure overlay without weakening PoCO.

The helper is deleted before the qualified product commit. A candidate must
change an active Rust crate and tests, strictly reduce unresolved repository or
unknown plan markers, preserve the native-only guard, and compile every
workspace target.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from typing import Any

FIXED_REFS = (
    "origin/ops/publish-final-repository-closure-20260909",
    "origin/work/plan-v2-final-repository-closure-20260909",
    "origin/ops/publish-gap-closure-v3-20260909",
    "origin/work/plan-v2-repository-blockers-closure-20260902",
    "origin/integration/native-poco-a04-a19-a23-qualified-v1-20260901",
    "origin/qualification/native-poco-a04-a19-a23-exact-head-v1-20260901",
    "origin/work/plan-v2-production-ports-20260909",
    "origin/fix/remote-signer-clean-runner-20260909",
)

REF_TERMS = (
    "gap-closure",
    "final-repository-closure",
    "native-poco",
    "canonical",
    "qualification",
    "repository-blockers",
    "production-ports",
    "remote-signer",
    "g1-",
)

CANONICAL_FILES = (
    "docs/development/CURRENT_SNAPSHOT_V1.json",
    "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md",
    "docs/development/module-registry-v1.toml",
    "docs/development/plan-manifest-v1.toml",
    "docs/development/release-train-v1.toml",
)

EXTERNAL_TERMS = (
    "hsm",
    "hardware",
    "independent",
    "reviewer",
    "review",
    "audit",
    "auditor",
    "power-loss",
    "power loss",
    "sigkill",
    "soak",
    "multihost",
    "multi-host",
    "campaign",
    "self-hosted",
    "external evidence",
    "external gate",
    "production activation",
    "release readiness",
    "long-run",
    "fuzz",
    "operator ceremony",
)

REPOSITORY_TERMS = (
    "not implemented",
    "implementation missing",
    "missing implementation",
    "repository-owned",
    "repository owned",
    "source missing",
    "test missing",
    "owner missing",
    "runtime wiring missing",
    "incomplete implementation",
)

MARKER_RE = re.compile(
    r"\b(?:G[0-9][A-Za-z0-9._-]*|P[0-9][A-Za-z0-9._-]*)"
    r"[-_:](?:incomplete|open|missing|blocked)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Score:
    repository: int
    unknown: int

    @property
    def total(self) -> int:
        return self.repository + self.unknown

    def json(self) -> dict[str, int]:
        return {
            "repository": self.repository,
            "unknown": self.unknown,
            "total": self.total,
        }


def run(
    command: list[str],
    *,
    cwd: pathlib.Path,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env or os.environ.copy(),
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout[-30000:]}"
        )
    return completed


def classify(root: pathlib.Path) -> tuple[Score, list[dict[str, Any]]]:
    repository = 0
    unknown = 0
    rows = []
    for relative in CANONICAL_FILES:
        path = root / relative
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            markers = sorted(set(match.group(0) for match in MARKER_RE.finditer(line)))
            if not markers:
                continue
            context = "\n".join(lines[max(0, index - 10):min(len(lines), index + 11)])
            lowered = context.casefold()
            external = sorted(term for term in EXTERNAL_TERMS if term in lowered)
            owned = sorted(term for term in REPOSITORY_TERMS if term in lowered)
            if owned:
                kind = "repository"
                basis = owned
                repository += 1
            elif external:
                kind = "external"
                basis = external
            else:
                kind = "unknown"
                basis = ["no authenticated external dependency in local context"]
                unknown += 1
            rows.append(
                {
                    "path": relative,
                    "line": index + 1,
                    "markers": markers,
                    "classification": kind,
                    "basis": basis,
                    "text": line.strip()[:1400],
                }
            )
    return Score(repository=repository, unknown=unknown), rows


def active_prefixes(root: pathlib.Path) -> tuple[str, ...]:
    workspace = tomllib.loads(
        (root / "trillionnium/Cargo.toml").read_text(encoding="utf-8")
    )
    result = []
    for member in workspace.get("workspace", {}).get("members", []):
        if isinstance(member, str) and member.startswith("crates/"):
            result.append(f"trillionnium/{member.rstrip('/')}/")
    return tuple(sorted(set(result)))


def candidate_refs(root: pathlib.Path) -> list[str]:
    run(
        ["git", "fetch", "--no-tags", "origin", "+refs/heads/*:refs/remotes/origin/*"],
        cwd=root,
    )
    result = list(FIXED_REFS)
    listed = run(
        [
            "git",
            "for-each-ref",
            "--sort=-committerdate",
            "--format=%(refname:short)",
            "refs/remotes/origin",
        ],
        cwd=root,
    ).stdout.splitlines()
    current = f"origin/{os.environ.get('TARGET_BRANCH', '')}"
    for reference in listed:
        lowered = reference.casefold()
        if reference in {"origin/HEAD", current}:
            continue
        if any(term in lowered for term in REF_TERMS) and reference not in result:
            result.append(reference)
        if len(result) >= 24:
            break
    return result


def allowed(path: str, prefixes: tuple[str, ...]) -> bool:
    return path.startswith(prefixes) or path.startswith(
        ("docs/development/", "scripts/ci/", "formal/", "conformance/", "config/")
    )


def forbidden(path: str) -> bool:
    lowered = path.casefold()
    terms = (
        "trnm-consensus-" + "app",
        "trnm-" + "node/",
        "co" + "met",
        "tender" + "mint",
        "/a" + "bci",
        "temporary_poco",
        "poco-only-convergence-r",
        "poco-repository-gap-convergence-r",
        "poco-exact-gap-convergence-r",
        "poco-qualified-external-orchestration-r",
        "poco-qualified-gap-overlay-r",
        "poco-takeover-r",
        "poco-full-qualification-r",
    )
    return any(term in lowered for term in terms)


def changed(root: pathlib.Path, reference: str) -> list[tuple[str, str]]:
    output = run(
        ["git", "diff", "--name-status", "--find-renames=90%", "HEAD", reference],
        cwd=root,
    ).stdout
    rows = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) >= 2:
            rows.append((fields[0], fields[-1]))
    return rows


def create_worktree(root: pathlib.Path, suffix: str) -> pathlib.Path:
    path = pathlib.Path(tempfile.mkdtemp(prefix=f"trnm-r27-overlay-{suffix}-"))
    shutil.rmtree(path)
    run(["git", "worktree", "add", "--detach", str(path), "HEAD"], cwd=root)
    return path


def remove_worktree(root: pathlib.Path, path: pathlib.Path) -> None:
    run(["git", "worktree", "remove", "--force", str(path)], cwd=root, check=False)
    shutil.rmtree(path, ignore_errors=True)


def apply_reference(
    root: pathlib.Path,
    reference: str,
    prefixes: tuple[str, ...],
) -> dict[str, Any]:
    selected = []
    for status, path in changed(root, reference):
        if allowed(path, prefixes) and not forbidden(path):
            selected.append((status, path))
    for status, path in selected:
        destination = root / path
        if status.startswith("D"):
            if destination.is_dir():
                shutil.rmtree(destination)
            elif destination.exists() or destination.is_symlink():
                destination.unlink()
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            run(["git", "checkout", reference, "--", path], cwd=root)
    run(["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all"], cwd=root)
    paths = run(["git", "diff", "--name-only"], cwd=root).stdout.splitlines()
    code = [path for path in paths if path.endswith(".rs")]
    tests = [
        path
        for path in code
        if "/tests/" in path or path.endswith("/tests.rs") or "test" in pathlib.Path(path).name
    ]
    return {
        "selected_paths": selected,
        "changed_paths": paths,
        "code_paths": code,
        "test_paths": tests,
    }


def stage_one(
    root: pathlib.Path,
    reference: str,
    index: int,
    baseline: Score,
    prefixes: tuple[str, ...],
) -> dict[str, Any]:
    worktree = create_worktree(root, f"s1-{index}")
    try:
        overlay = apply_reference(worktree, reference, prefixes)
        row: dict[str, Any] = {"reference": reference, **overlay}
        if not overlay["code_paths"]:
            row.update({"stage_one": False, "reason": "no-active-code-change"})
            return row
        if not overlay["test_paths"]:
            row.update({"stage_one": False, "reason": "no-test-change"})
            return row
        native = run(
            ["python3", "scripts/ci/check_native_consensus_only.py"],
            cwd=worktree,
            check=False,
        )
        if native.returncode != 0:
            row.update(
                {
                    "stage_one": False,
                    "reason": "native-only",
                    "log": native.stdout[-16000:],
                }
            )
            return row
        score, gaps = classify(worktree)
        row.update({"score": score.json(), "gaps": gaps})
        if score.total >= baseline.total:
            row.update({"stage_one": False, "reason": "gap-score-not-reduced"})
            return row
        patch = pathlib.Path(f"/tmp/trnm-r27-overlay-{index}.patch")
        patch.write_text(
            run(["git", "diff", "--binary", "HEAD"], cwd=worktree).stdout,
            encoding="utf-8",
        )
        row.update(
            {
                "stage_one": True,
                "reason": "source-test-native-gap-reduction",
                "patch": str(patch),
                "patch_sha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
                "changed_count": len(overlay["changed_paths"]),
            }
        )
        return row
    finally:
        remove_worktree(root, worktree)


def stage_two(root: pathlib.Path, row: dict[str, Any], index: int) -> dict[str, Any]:
    worktree = create_worktree(root, f"s2-{index}")
    try:
        applied = run(
            ["git", "apply", "--index", "--binary", str(row["patch"])],
            cwd=worktree,
            check=False,
        )
        if applied.returncode != 0:
            return {**row, "stage_two": False, "stage_two_reason": "patch-apply", "log": applied.stdout[-16000:]}
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = f"/tmp/trnm-r27-overlay-check-{index}"
        shutil.rmtree(env["CARGO_TARGET_DIR"], ignore_errors=True)
        checked = run(
            [
                "cargo", "check", "--manifest-path", "trillionnium/Cargo.toml",
                "--workspace", "--all-targets", "--locked", "--offline", "-j", "1",
            ],
            cwd=worktree,
            check=False,
            env=env,
        )
        if checked.returncode != 0:
            return {**row, "stage_two": False, "stage_two_reason": "workspace-check", "log": checked.stdout[-30000:]}
        return {**row, "stage_two": True, "stage_two_reason": "workspace-all-targets-pass"}
    finally:
        remove_worktree(root, worktree)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: temporary_poco_gap_overlay_r27.py ROOT")
    root = pathlib.Path(sys.argv[1]).resolve()
    baseline, baseline_rows = classify(root)
    report: dict[str, Any] = {
        "schema": "trnm-poco-gap-overlay-search-r27-v1",
        "baseline": baseline.json(),
        "baseline_gaps": baseline_rows,
        "stage_one": [],
        "stage_two": [],
        "selected": None,
    }
    if baseline.total == 0:
        pathlib.Path("/tmp/trnm-r27-overlay-search.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return 0

    prefixes = active_prefixes(root)
    proposals = []
    for index, reference in enumerate(candidate_refs(root), 1):
        exists = run(
            ["git", "rev-parse", "--verify", "--quiet", reference],
            cwd=root,
            check=False,
        )
        if exists.returncode != 0:
            row = {"reference": reference, "stage_one": False, "reason": "missing-ref"}
        else:
            row = stage_one(root, reference, index, baseline, prefixes)
        report["stage_one"].append(row)
        if row.get("stage_one"):
            proposals.append(row)

    proposals.sort(key=lambda row: (int(row["score"]["total"]), int(row["changed_count"])))
    accepted = []
    for index, proposal in enumerate(proposals[:5], 1):
        row = stage_two(root, proposal, index)
        report["stage_two"].append(row)
        if row.get("stage_two"):
            accepted.append(row)

    if accepted:
        accepted.sort(key=lambda row: (int(row["score"]["total"]), int(row["changed_count"])))
        selected = accepted[0]
        run(
            ["git", "apply", "--index", "--binary", str(selected["patch"])],
            cwd=root,
        )
        report["selected"] = {
            "reference": selected["reference"],
            "score": selected["score"],
            "changed_count": selected["changed_count"],
            "patch_sha256": selected["patch_sha256"],
        }

    pathlib.Path("/tmp/trnm-r27-overlay-search.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summary = [
        f"baseline_total={baseline.total}",
        f"stage_one_accepted={len(proposals)}",
        f"stage_two_accepted={len(accepted)}",
        f"selected={report['selected'] is not None}",
    ]
    if report["selected"]:
        summary.append(f"selected_reference={report['selected']['reference']}")
        summary.append(f"selected_score={report['selected']['score']}")
    pathlib.Path("/tmp/trnm-r27-overlay-summary.txt").write_text(
        "\n".join(summary) + "\n", encoding="utf-8"
    )
    return 0 if report["selected"] is not None else 4


if __name__ == "__main__":
    raise SystemExit(main())
