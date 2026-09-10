#!/usr/bin/env python3
"""Try existing closure branches without weakening native PoCO boundaries.

This one-shot helper is copied outside the candidate tree and deleted before
qualification. A candidate is admissible only when it touches an active crate,
contains a test change, preserves the native-only guard, compiles all targets,
and strictly reduces repository/unknown gap markers.
"""
from __future__ import annotations

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

CANDIDATE_REFS = (
    "origin/ops/publish-final-repository-closure-20260909",
    "origin/work/plan-v2-final-repository-closure-20260909",
    "origin/ops/publish-gap-closure-v3-20260909",
    "origin/work/plan-v2-repository-blockers-closure-20260902",
)

CANONICAL_RELATIVE_FILES = (
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
        env=env,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout[-20000:]}"
        )
    return completed


def active_crate_prefixes(root: pathlib.Path) -> tuple[str, ...]:
    manifest = tomllib.loads((root / "trillionnium/Cargo.toml").read_text(encoding="utf-8"))
    members = manifest.get("workspace", {}).get("members", [])
    result = []
    for member in members:
        if not isinstance(member, str) or not member.startswith("crates/"):
            continue
        result.append(f"trillionnium/{member.rstrip('/')}/")
    return tuple(sorted(set(result)))


def classify_gaps(root: pathlib.Path) -> tuple[GapScore, list[dict[str, object]]]:
    repository = 0
    unknown = 0
    rows: list[dict[str, object]] = []
    for relative in CANONICAL_RELATIVE_FILES:
        path = root / relative
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            markers = sorted(set(match.group(0) for match in MARKER_RE.finditer(line)))
            if not markers:
                continue
            context = "\n".join(lines[max(0, index - 8): min(len(lines), index + 9)])
            lowered = context.casefold()
            external_basis = sorted(term for term in EXTERNAL_TERMS if term in lowered)
            repository_basis = sorted(term for term in REPOSITORY_TERMS if term in lowered)
            if external_basis and not repository_basis:
                classification = "external"
                basis = external_basis
            elif repository_basis:
                classification = "repository"
                basis = repository_basis
                repository += 1
            else:
                classification = "unknown"
                basis = ["no authenticated external dependency or repository implementation evidence"]
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


def allowed_path(path: str, crate_prefixes: tuple[str, ...]) -> bool:
    if path.startswith(crate_prefixes):
        return True
    return path.startswith(
        (
            "docs/development/",
            "scripts/ci/",
            "formal/",
            "conformance/",
            "config/",
        )
    )


def forbidden_path(path: str) -> bool:
    lowered = path.casefold()
    pieces = (
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
    )
    return any(piece in lowered for piece in pieces)


def changed_paths(root: pathlib.Path, reference: str) -> list[tuple[str, str]]:
    completed = run(
        ["git", "diff", "--name-status", "--find-renames=90%", "HEAD", reference],
        cwd=root,
    )
    rows: list[tuple[str, str]] = []
    for line in completed.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        status = fields[0]
        path = fields[-1]
        rows.append((status, path))
    return rows


def apply_overlay(
    root: pathlib.Path,
    reference: str,
    crate_prefixes: tuple[str, ...],
) -> dict[str, object]:
    selected: list[tuple[str, str]] = []
    for status, path in changed_paths(root, reference):
        if not allowed_path(path, crate_prefixes) or forbidden_path(path):
            continue
        selected.append((status, path))

    for status, path in selected:
        destination = root / path
        if status.startswith("D"):
            if destination.is_dir():
                shutil.rmtree(destination)
            elif destination.exists() or destination.is_symlink():
                destination.unlink()
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "checkout", reference, "--", path], cwd=root)

    changed = run(["git", "diff", "--name-only"], cwd=root).stdout.splitlines()
    code_changes = [path for path in changed if path.endswith(".rs")]
    test_changes = [
        path
        for path in changed
        if path.endswith(".rs")
        and ("/tests/" in path or path.endswith("/tests.rs") or "test" in pathlib.Path(path).name)
    ]
    return {
        "selected": selected,
        "changed": changed,
        "code_changes": code_changes,
        "test_changes": test_changes,
    }


def validate_candidate(root: pathlib.Path, candidate_index: int) -> dict[str, object]:
    run(["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all"], cwd=root)
    native = run(["python3", "scripts/ci/check_native_consensus_only.py"], cwd=root, check=False)
    if native.returncode != 0:
        return {"accepted": False, "reason": "native-only", "log": native.stdout[-12000:]}

    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = f"/tmp/trnm-r19-overlay-target-{candidate_index}"
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
        cwd=root,
        check=False,
        env=env,
    )
    if checked.returncode != 0:
        return {"accepted": False, "reason": "workspace-check", "log": checked.stdout[-20000:]}

    score, rows = classify_gaps(root)
    return {
        "accepted": True,
        "reason": "basic-gates-pass",
        "score": score.as_dict(),
        "gaps": rows,
    }


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: temporary_poco_gap_overlay_r19.py ROOT")
    root = pathlib.Path(sys.argv[1]).resolve()
    baseline, baseline_rows = classify_gaps(root)
    report: dict[str, object] = {
        "schema": "trnm-poco-gap-overlay-search-r19-v1",
        "baseline": baseline.as_dict(),
        "baseline_gaps": baseline_rows,
        "candidates": [],
        "selected": None,
    }
    if baseline.total == 0:
        pathlib.Path("/tmp/trnm-r19-overlay-search.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return 0

    run(["git", "fetch", "--no-tags", "origin", "+refs/heads/*:refs/remotes/origin/*"], cwd=root)
    prefixes = active_crate_prefixes(root)
    best: tuple[int, str, pathlib.Path, dict[str, object]] | None = None

    for index, reference in enumerate(CANDIDATE_REFS, 1):
        exists = run(["git", "rev-parse", "--verify", "--quiet", reference], cwd=root, check=False)
        if exists.returncode != 0:
            report["candidates"].append({"reference": reference, "accepted": False, "reason": "missing-ref"})
            continue
        worktree = pathlib.Path(tempfile.mkdtemp(prefix=f"trnm-r19-overlay-{index}-"))
        shutil.rmtree(worktree)
        run(["git", "worktree", "add", "--detach", str(worktree), "HEAD"], cwd=root)
        try:
            overlay = apply_overlay(worktree, reference, prefixes)
            if not overlay["code_changes"]:
                candidate = {"reference": reference, "accepted": False, "reason": "no-active-code-change", **overlay}
            elif not overlay["test_changes"]:
                candidate = {"reference": reference, "accepted": False, "reason": "no-test-change", **overlay}
            else:
                validation = validate_candidate(worktree, index)
                candidate = {"reference": reference, **overlay, **validation}
                score_dict = validation.get("score") if validation.get("accepted") else None
                if isinstance(score_dict, dict):
                    score_total = int(score_dict["total"])
                    if score_total < baseline.total and (best is None or score_total < best[0]):
                        patch = pathlib.Path(f"/tmp/trnm-r19-overlay-{index}.patch")
                        completed = run(["git", "diff", "--binary", "HEAD"], cwd=worktree)
                        patch.write_text(completed.stdout, encoding="utf-8")
                        best = (score_total, reference, patch, candidate)
            report["candidates"].append(candidate)
        finally:
            run(["git", "worktree", "remove", "--force", str(worktree)], cwd=root, check=False)
            shutil.rmtree(worktree, ignore_errors=True)

    if best is not None:
        _, reference, patch, candidate = best
        run(["git", "apply", "--index", "--binary", str(patch)], cwd=root)
        report["selected"] = {
            "reference": reference,
            "score": candidate.get("score"),
            "patch_sha256": __import__("hashlib").sha256(patch.read_bytes()).hexdigest(),
        }

    pathlib.Path("/tmp/trnm-r19-overlay-search.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summary = [
        f"baseline_total={baseline.total}",
        f"selected={report['selected'] is not None}",
    ]
    if report["selected"]:
        summary.append(f"selected_reference={report['selected']['reference']}")
        summary.append(f"selected_score={report['selected']['score']}")
    pathlib.Path("/tmp/trnm-r19-overlay-summary.txt").write_text(
        "\n".join(summary) + "\n", encoding="utf-8"
    )
    return 0 if best is not None else 4


if __name__ == "__main__":
    raise SystemExit(main())
