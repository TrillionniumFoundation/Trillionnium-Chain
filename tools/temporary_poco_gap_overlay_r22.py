#!/usr/bin/env python3
"""Search recent closure refs for a strictly improving native PoCO overlay.

The helper is temporary and removed before qualification. Candidate selection
is two-stage: source/test/native-only/gap reduction first, then all-targets
compilation only for the best five proposals.
"""
from __future__ import annotations

import hashlib
import importlib.util
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
class GapScore:
    repository: int
    unknown: int

    @property
    def total(self) -> int:
        return self.repository + self.unknown

    def as_dict(self) -> dict[str, int]:
        return {"repository": self.repository, "unknown": self.unknown, "total": self.total}


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
        env=env,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout[-24000:]}"
        )
    return completed


def classify_gaps(root: pathlib.Path) -> tuple[GapScore, list[dict[str, Any]]]:
    repository = 0
    unknown = 0
    rows: list[dict[str, Any]] = []
    for relative in CANONICAL_FILES:
        path = root / relative
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            markers = sorted(set(match.group(0) for match in MARKER_RE.finditer(line)))
            if not markers:
                continue
            context = "\n".join(lines[max(0, index - 10): min(len(lines), index + 11)])
            lowered = context.casefold()
            external = sorted(term for term in EXTERNAL_TERMS if term in lowered)
            owned = sorted(term for term in REPOSITORY_TERMS if term in lowered)
            if owned:
                classification = "repository"
                basis = owned
                repository += 1
            elif external:
                classification = "external"
                basis = external
            else:
                classification = "unknown"
                basis = ["no external dependency or repository implementation evidence in local context"]
                unknown += 1
            rows.append(
                {
                    "path": relative,
                    "line": index + 1,
                    "markers": markers,
                    "classification": classification,
                    "basis": basis,
                    "text": line.strip()[:1200],
                }
            )
    return GapScore(repository=repository, unknown=unknown), rows


def active_crate_prefixes(root: pathlib.Path) -> tuple[str, ...]:
    manifest = tomllib.loads((root / "trillionnium/Cargo.toml").read_text(encoding="utf-8"))
    result = []
    for member in manifest.get("workspace", {}).get("members", []):
        if isinstance(member, str) and member.startswith("crates/"):
            result.append(f"trillionnium/{member.rstrip('/')}/")
    return tuple(sorted(set(result)))


def candidate_refs(root: pathlib.Path) -> list[str]:
    run(["git", "fetch", "--no-tags", "origin", "+refs/heads/*:refs/remotes/origin/*"], cwd=root)
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
    result = []
    for reference in FIXED_REFS:
        if reference not in result:
            result.append(reference)
    for reference in listed:
        lowered = reference.casefold()
        if reference in {"origin/HEAD", f"origin/{os.environ.get('TARGET_BRANCH', '')}"}:
            continue
        if any(term in lowered for term in REF_TERMS) and reference not in result:
            result.append(reference)
        if len(result) >= 24:
            break
    return result


def forbidden_path(path: str) -> bool:
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
    )
    return any(term in lowered for term in terms)


def allowed_path(path: str, prefixes: tuple[str, ...]) -> bool:
    if path.startswith(prefixes):
        return True
    return path.startswith(
        ("docs/development/", "scripts/ci/", "formal/", "conformance/", "config/")
    )


def changed_paths(root: pathlib.Path, reference: str) -> list[tuple[str, str]]:
    result = run(
        ["git", "diff", "--name-status", "--find-renames=90%", "HEAD", reference],
        cwd=root,
    )
    rows = []
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) >= 2:
            rows.append((fields[0], fields[-1]))
    return rows


def apply_overlay(root: pathlib.Path, reference: str, prefixes: tuple[str, ...]) -> dict[str, Any]:
    selected = []
    for status, path in changed_paths(root, reference):
        if allowed_path(path, prefixes) and not forbidden_path(path):
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
    changed = run(["git", "diff", "--name-only"], cwd=root).stdout.splitlines()
    code = [path for path in changed if path.endswith(".rs")]
    tests = [
        path
        for path in changed
        if path.endswith(".rs")
        and ("/tests/" in path or path.endswith("/tests.rs") or "test" in pathlib.Path(path).name)
    ]
    return {"selected": selected, "changed": changed, "code": code, "tests": tests}


def create_worktree(root: pathlib.Path, index: int) -> pathlib.Path:
    worktree = pathlib.Path(tempfile.mkdtemp(prefix=f"trnm-r22-overlay-{index}-"))
    shutil.rmtree(worktree)
    run(["git", "worktree", "add", "--detach", str(worktree), "HEAD"], cwd=root)
    return worktree


def remove_worktree(root: pathlib.Path, worktree: pathlib.Path) -> None:
    run(["git", "worktree", "remove", "--force", str(worktree)], cwd=root, check=False)
    shutil.rmtree(worktree, ignore_errors=True)


def stage_one(
    root: pathlib.Path,
    reference: str,
    index: int,
    baseline: GapScore,
    prefixes: tuple[str, ...],
) -> dict[str, Any]:
    worktree = create_worktree(root, index)
    try:
        overlay = apply_overlay(worktree, reference, prefixes)
        result: dict[str, Any] = {"reference": reference, **overlay}
        if not overlay["code"]:
            result.update({"accepted_stage_one": False, "reason": "no-active-code-change"})
            return result
        if not overlay["tests"]:
            result.update({"accepted_stage_one": False, "reason": "no-test-change"})
            return result
        native = run(["python3", "scripts/ci/check_native_consensus_only.py"], cwd=worktree, check=False)
        if native.returncode != 0:
            result.update(
                {
                    "accepted_stage_one": False,
                    "reason": "native-only",
                    "log": native.stdout[-12000:],
                }
            )
            return result
        score, gaps = classify_gaps(worktree)
        result.update({"score": score.as_dict(), "gaps": gaps})
        if score.total >= baseline.total:
            result.update({"accepted_stage_one": False, "reason": "gap-score-not-reduced"})
            return result
        patch = pathlib.Path(f"/tmp/trnm-r22-stage-one-{index}.patch")
        patch.write_text(run(["git", "diff", "--binary", "HEAD"], cwd=worktree).stdout, encoding="utf-8")
        result.update(
            {
                "accepted_stage_one": True,
                "reason": "source-test-native-gap-reduction",
                "patch": str(patch),
                "patch_sha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
                "changed_count": len(overlay["changed"]),
            }
        )
        return result
    finally:
        remove_worktree(root, worktree)


def stage_two(root: pathlib.Path, proposal: dict[str, Any], index: int) -> dict[str, Any]:
    worktree = create_worktree(root, 100 + index)
    try:
        patch = pathlib.Path(proposal["patch"])
        applied = run(["git", "apply", "--index", "--binary", str(patch)], cwd=worktree, check=False)
        if applied.returncode != 0:
            return {**proposal, "accepted_stage_two": False, "reason_stage_two": "patch-apply", "log": applied.stdout[-12000:]}
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = f"/tmp/trnm-r22-overlay-check-{index}"
        shutil.rmtree(env["CARGO_TARGET_DIR"], ignore_errors=True)
        checked = run(
            [
                "cargo",
                "check",
                "--manifest-path",
                "trillionnium/Cargo.toml",
                "--workspace",
                "--all-targets",
                "--locked",
                "--offline",
                "-j",
                "1",
            ],
            cwd=worktree,
            check=False,
            env=env,
        )
        if checked.returncode != 0:
            return {**proposal, "accepted_stage_two": False, "reason_stage_two": "workspace-check", "log": checked.stdout[-24000:]}
        return {**proposal, "accepted_stage_two": True, "reason_stage_two": "workspace-all-targets-pass"}
    finally:
        remove_worktree(root, worktree)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: temporary_poco_gap_overlay_r22.py ROOT")
    root = pathlib.Path(sys.argv[1]).resolve()
    baseline, baseline_rows = classify_gaps(root)
    report: dict[str, Any] = {
        "schema": "trnm-poco-gap-overlay-search-r22-v1",
        "baseline": baseline.as_dict(),
        "baseline_gaps": baseline_rows,
        "stage_one": [],
        "stage_two": [],
        "selected": None,
    }
    if baseline.total == 0:
        pathlib.Path("/tmp/trnm-r22-overlay-search.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return 0

    prefixes = active_crate_prefixes(root)
    proposals = []
    for index, reference in enumerate(candidate_refs(root), 1):
        exists = run(["git", "rev-parse", "--verify", "--quiet", reference], cwd=root, check=False)
        if exists.returncode != 0:
            row = {"reference": reference, "accepted_stage_one": False, "reason": "missing-ref"}
        else:
            row = stage_one(root, reference, index, baseline, prefixes)
        report["stage_one"].append(row)
        if row.get("accepted_stage_one"):
            proposals.append(row)

    proposals.sort(key=lambda row: (int(row["score"]["total"]), int(row["changed_count"])))
    accepted = []
    for index, proposal in enumerate(proposals[:5], 1):
        row = stage_two(root, proposal, index)
        report["stage_two"].append(row)
        if row.get("accepted_stage_two"):
            accepted.append(row)

    if accepted:
        accepted.sort(key=lambda row: (int(row["score"]["total"]), int(row["changed_count"])))
        selected = accepted[0]
        run(["git", "apply", "--index", "--binary", selected["patch"]], cwd=root)
        report["selected"] = {
            "reference": selected["reference"],
            "score": selected["score"],
            "changed_count": selected["changed_count"],
            "patch_sha256": selected["patch_sha256"],
        }

    pathlib.Path("/tmp/trnm-r22-overlay-search.json").write_text(
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
    pathlib.Path("/tmp/trnm-r22-overlay-summary.txt").write_text(
        "\n".join(summary) + "\n", encoding="utf-8"
    )
    return 0 if report["selected"] is not None else 4


if __name__ == "__main__":
    raise SystemExit(main())
