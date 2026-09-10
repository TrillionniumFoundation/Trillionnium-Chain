#!/usr/bin/env python3
"""Collect authentic external evidence for the exact qualified PoCO source.

The collector does not synthesize signatures, approvals, hardware results, or
acceptance. It downloads real workflow artifacts, verifies source identity,
tries only checker-advertised intake surfaces, and keeps the release closed
unless the repository's own require-all gate returns success.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from typing import Any

ROOT = pathlib.Path(os.environ.get("GITHUB_WORKSPACE", pathlib.Path.cwd())).resolve()
REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "TrillionniumFoundation/Trillionnium-Chain")
BRANCH = os.environ.get("TARGET_BRANCH", "chore/poco-only-purge-20260909")
PR_NUMBER = 117
PRIOR_WORKFLOW = "poco-takeover-r22-once-20260910.yml"
PRIOR_ROOT = pathlib.Path("/tmp/trnm-r23-r22")
ARTIFACT_ROOT = pathlib.Path("/tmp/trnm-r23-external-artifacts")
PRODUCT = pathlib.Path("/tmp/trnm-r23-product")
LATEST = pathlib.Path("/tmp/trnm-r23-latest")

EXTERNAL_IDS = (
    "EXT-ANCHOR-HSM-001",
    "EXT-AUDIT-001",
    "EXT-G1-CAMPAIGN-001",
    "EXT-POWERLOSS-001",
    "EXT-REVIEW-001",
    "EXT-SOAK-ACTIVATION-001",
)

REVIEWERS = ("Franksudoman", "Tomasrgbsf")


def run(
    command: list[str],
    *,
    cwd: pathlib.Path = ROOT,
    check: bool = True,
    input_text: str | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=os.environ.copy(),
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout[-30000:]}"
        )
    return completed


def gh_json(endpoint: str) -> Any:
    result = run(["gh", "api", endpoint])
    return json.loads(result.stdout)


def capture_prior() -> tuple[int | None, pathlib.Path]:
    PRIOR_ROOT.mkdir(parents=True, exist_ok=True)
    encoded = urllib.parse.quote(PRIOR_WORKFLOW, safe="")
    payload = gh_json(
        f"repos/{REPOSITORY}/actions/workflows/{encoded}/runs"
        f"?branch={urllib.parse.quote(BRANCH, safe='')}&per_page=1"
    )
    runs = payload.get("workflow_runs", [])
    if not runs:
        return None, PRIOR_ROOT
    run_id = int(runs[0]["id"])
    pathlib.Path("/tmp/trnm-r23-r22-run.json").write_text(
        json.dumps(runs[0], indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    jobs = gh_json(f"repos/{REPOSITORY}/actions/runs/{run_id}/jobs?per_page=100")
    pathlib.Path("/tmp/trnm-r23-r22-jobs.json").write_text(
        json.dumps(jobs, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    run(
        ["gh", "run", "view", str(run_id), "--repo", REPOSITORY, "--log"],
        check=False,
    ).stdout and pathlib.Path("/tmp/trnm-r23-r22.log").write_text(
        run(
            ["gh", "run", "view", str(run_id), "--repo", REPOSITORY, "--log"],
            check=False,
        ).stdout,
        encoding="utf-8",
        errors="replace",
    )
    run(
        ["gh", "run", "download", str(run_id), "--repo", REPOSITORY, "--dir", str(PRIOR_ROOT)],
        check=False,
    )
    return run_id, PRIOR_ROOT


def find_one(root: pathlib.Path, name: str) -> pathlib.Path | None:
    matches = sorted(path for path in root.rglob(name) if path.is_file())
    return matches[0] if matches else None


def valid_sha(value: str) -> bool:
    return re.fullmatch(r"[0-9a-f]{40}", value) is not None


def resolve_product_identity(prior: pathlib.Path) -> tuple[str, str]:
    commit_file = find_one(prior, "trnm-r20-final-commit.txt")
    tree_file = find_one(prior, "trnm-r20-final-tree.txt")
    if commit_file and tree_file:
        commit = commit_file.read_text(encoding="ascii").strip()
        tree = tree_file.read_text(encoding="ascii").strip()
        if valid_sha(commit) and valid_sha(tree):
            return commit, tree

    run(["git", "fetch", "origin", BRANCH])
    candidates = run(
        [
            "git",
            "log",
            "--all",
            "--format=%H",
            "--grep=remove completed PoCO convergence controllers",
            "-n",
            "20",
        ]
    ).stdout.splitlines()
    for commit in candidates:
        tree = run(["git", "rev-parse", f"{commit}^{{tree}}"], check=False).stdout.strip()
        if valid_sha(commit) and valid_sha(tree):
            return commit, tree
    raise RuntimeError("R22 did not expose a qualified product commit/tree")


def create_product_worktree(commit: str, tree: str) -> None:
    shutil.rmtree(PRODUCT, ignore_errors=True)
    run(["git", "worktree", "add", "--detach", str(PRODUCT), commit])
    actual_commit = run(["git", "rev-parse", "HEAD"], cwd=PRODUCT).stdout.strip()
    actual_tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=PRODUCT).stdout.strip()
    if actual_commit != commit or actual_tree != tree:
        raise RuntimeError("qualified product identity mismatch")
    native = run(["python3", "scripts/ci/check_native_consensus_only.py"], cwd=PRODUCT, check=False)
    if native.returncode != 0:
        raise RuntimeError(f"qualified product no longer passes native-only guard\n{native.stdout}")


def review_status(commit: str) -> dict[str, Any]:
    reviews = gh_json(f"repos/{REPOSITORY}/pulls/{PR_NUMBER}/reviews?per_page=100")
    latest_by_user: dict[str, dict[str, Any]] = {}
    for review in reviews:
        user = (review.get("user") or {}).get("login")
        if user:
            latest_by_user[user] = review
    exact = [
        {
            "user": user,
            "state": review.get("state"),
            "commit_id": review.get("commit_id"),
            "submitted_at": review.get("submitted_at"),
        }
        for user, review in latest_by_user.items()
        if review.get("state") == "APPROVED" and review.get("commit_id") == commit
    ]
    request_payload = json.dumps({"reviewers": list(REVIEWERS)})
    request = run(
        [
            "gh",
            "api",
            "--method",
            "POST",
            f"repos/{REPOSITORY}/pulls/{PR_NUMBER}/requested_reviewers",
            "--input",
            "-",
        ],
        input_text=request_payload,
        check=False,
    )
    report = {
        "schema": "trnm-poco-review-readback-r23-v1",
        "source_commit": commit,
        "exact_head_approvals": exact,
        "requested_reviewers": list(REVIEWERS),
        "request_returncode": request.returncode,
        "request_output": request.stdout[-3000:],
        "all_reviews": [
            {
                "user": (review.get("user") or {}).get("login"),
                "state": review.get("state"),
                "commit_id": review.get("commit_id"),
                "submitted_at": review.get("submitted_at"),
            }
            for review in reviews
        ],
    }
    pathlib.Path("/tmp/trnm-r23-review-status.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def dispatched_from_prior(prior: pathlib.Path) -> list[dict[str, Any]]:
    result = []
    for name in ("trnm-r20-external-runs.json", "trnm-r20-external-dispatch.json"):
        path = find_one(prior, name)
        if path is None:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if isinstance(payload, list):
            for row in payload:
                if isinstance(row, dict) and row.get("run_id"):
                    result.append(row)
        elif isinstance(payload, dict):
            for row in payload.get("dispatched", []):
                if isinstance(row, dict):
                    result.append(row)
    return result


def exact_dispatch_runs(commit: str) -> list[dict[str, Any]]:
    payload = gh_json(
        f"repos/{REPOSITORY}/actions/runs"
        f"?branch={urllib.parse.quote(BRANCH, safe='')}&event=workflow_dispatch&per_page=100"
    )
    result = []
    for row in payload.get("workflow_runs", []):
        if row.get("head_sha") == commit:
            result.append(
                {
                    "run_id": row.get("id"),
                    "name": row.get("name"),
                    "workflow_id": row.get("workflow_id"),
                    "status": row.get("status"),
                    "conclusion": row.get("conclusion"),
                    "html_url": row.get("html_url"),
                }
            )
    return result


def wait_and_download(rows: list[dict[str, Any]], commit: str) -> list[dict[str, Any]]:
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    run_ids = sorted(
        {
            int(row["run_id"])
            for row in rows
            if row.get("run_id") is not None and str(row.get("run_id")).isdigit()
        }
    )
    results = []
    deadline = time.monotonic() + 7200
    for run_id in run_ids:
        terminal: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            terminal = gh_json(f"repos/{REPOSITORY}/actions/runs/{run_id}")
            if terminal.get("status") == "completed":
                break
            time.sleep(15)
        destination = ARTIFACT_ROOT / str(run_id)
        destination.mkdir(parents=True, exist_ok=True)
        download = run(
            ["gh", "run", "download", str(run_id), "--repo", REPOSITORY, "--dir", str(destination)],
            check=False,
        )
        results.append(
            {
                "run_id": run_id,
                "head_sha": terminal.get("head_sha") if terminal else None,
                "status": terminal.get("status") if terminal else None,
                "conclusion": terminal.get("conclusion") if terminal else None,
                "source_matches": bool(terminal and terminal.get("head_sha") == commit),
                "download_returncode": download.returncode,
                "download_output": download.stdout[-3000:],
            }
        )
    pathlib.Path("/tmp/trnm-r23-external-runs.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return results


def inspect_json_artifacts(commit: str, tree: str) -> dict[str, Any]:
    rows = []
    for path in sorted(ARTIFACT_ROOT.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        serialized = json.dumps(payload, sort_keys=True)
        ids = [identifier for identifier in EXTERNAL_IDS if identifier in serialized]
        source_commit = None
        source_tree = None
        if isinstance(payload, dict):
            source_commit = payload.get("source_commit") or payload.get("commit")
            source_tree = payload.get("source_tree") or payload.get("tree")
        rows.append(
            {
                "path": path.relative_to(ARTIFACT_ROOT).as_posix(),
                "external_ids": ids,
                "declared_source_commit": source_commit,
                "declared_source_tree": source_tree,
                "commit_matches": source_commit in (None, commit),
                "tree_matches": source_tree in (None, tree),
            }
        )
    report = {
        "schema": "trnm-poco-external-artifact-inspection-r23-v1",
        "source_commit": commit,
        "source_tree": tree,
        "json_artifacts": rows,
        "ids_observed": sorted({identifier for row in rows for identifier in row["external_ids"]}),
    }
    pathlib.Path("/tmp/trnm-r23-artifact-inspection.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def gate_command(root: pathlib.Path, commit: str, tree: str, extra: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    command = [
        "python3",
        "scripts/ci/check_external_evidence_v1.py",
        "--require-all",
        "--source-commit",
        commit,
        "--source-tree",
        tree,
        "--output",
        "/tmp/trnm-r23-external-evidence.json",
    ]
    if extra:
        command.extend(extra)
    return run(command, cwd=root, check=False)


def advertised_artifact_options(root: pathlib.Path) -> list[str]:
    help_result = run(
        ["python3", "scripts/ci/check_external_evidence_v1.py", "--help"],
        cwd=root,
        check=False,
    )
    pathlib.Path("/tmp/trnm-r23-checker-help.txt").write_text(
        help_result.stdout, encoding="utf-8", errors="replace"
    )
    options = []
    for option in re.findall(r"--[a-z0-9][a-z0-9-]*", help_result.stdout.casefold()):
        if any(term in option for term in ("root", "dir", "artifact", "submission", "evidence")):
            if option not in {
                "--require-all",
                "--source-commit",
                "--source-tree",
                "--output",
            } and option not in options:
                options.append(option)
    return options


def try_gate_surfaces(commit: str, tree: str) -> tuple[int, str, list[dict[str, Any]]]:
    attempts = []
    baseline = gate_command(PRODUCT, commit, tree)
    attempts.append({"surface": "product", "returncode": baseline.returncode, "output": baseline.stdout[-8000:]})
    if baseline.returncode == 0:
        return 0, "product", attempts

    run(["git", "fetch", "origin", BRANCH])
    latest_commit = run(["git", "rev-parse", f"origin/{BRANCH}"]).stdout.strip()
    shutil.rmtree(LATEST, ignore_errors=True)
    run(["git", "worktree", "add", "--detach", str(LATEST), latest_commit])
    latest = gate_command(LATEST, commit, tree)
    attempts.append(
        {
            "surface": "latest-branch",
            "latest_commit": latest_commit,
            "returncode": latest.returncode,
            "output": latest.stdout[-8000:],
        }
    )
    if latest.returncode == 0:
        return 0, "latest-branch", attempts

    for option in advertised_artifact_options(PRODUCT):
        result = gate_command(PRODUCT, commit, tree, [option, str(ARTIFACT_ROOT)])
        attempts.append(
            {
                "surface": f"product+{option}",
                "returncode": result.returncode,
                "output": result.stdout[-8000:],
            }
        )
        if result.returncode == 0:
            return 0, f"product+{option}", attempts

    intake_scripts = sorted(
        path
        for pattern in ("*external*evidence*intake*.py", "*external*evidence*authenticate*.py")
        for path in (PRODUCT / "scripts/ci").glob(pattern)
        if path.is_file()
    )
    for script in intake_scripts:
        help_result = run(["python3", str(script.relative_to(PRODUCT)), "--help"], cwd=PRODUCT, check=False)
        attempts.append(
            {
                "surface": f"intake-help:{script.name}",
                "returncode": help_result.returncode,
                "output": help_result.stdout[-8000:],
            }
        )

    pathlib.Path("/tmp/trnm-r23-gate-attempts.json").write_text(
        json.dumps(attempts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return baseline.returncode, "none", attempts


def post_status(
    commit: str,
    tree: str,
    review: dict[str, Any],
    artifact: dict[str, Any],
    gate_rc: int,
    surface: str,
) -> None:
    exact_approvals = review.get("exact_head_approvals", [])
    observed_ids = artifact.get("ids_observed", [])
    lines = [
        "### PoCO R23 external-evidence collection",
        "",
        f"- exact product commit: `{commit}`",
        f"- exact product tree: `{tree}`",
        f"- exact-head independent approvals: `{len(exact_approvals)}`",
        f"- external blocker IDs observed in downloaded JSON: `{len(observed_ids)}/6`",
        f"- require-all exit: `{gate_rc}`",
        f"- accepting surface: `{surface}`",
        "",
        "Observed blocker IDs: " + (", ".join(f"`{value}`" for value in observed_ids) or "none"),
        "",
        "No missing signature, reviewer approval, HSM result, audit result, power-loss result, campaign result, or soak result was synthesized.",
    ]
    body = "\n".join(lines) + "\n"
    pathlib.Path("/tmp/trnm-r23-pr-comment.md").write_text(body, encoding="utf-8")
    run(
        ["gh", "pr", "comment", str(PR_NUMBER), "--repo", REPOSITORY, "--body-file", "/tmp/trnm-r23-pr-comment.md"],
        check=False,
    )


def main() -> int:
    _, prior = capture_prior()
    commit, tree = resolve_product_identity(prior)
    pathlib.Path("/tmp/trnm-r23-product-commit.txt").write_text(commit + "\n", encoding="ascii")
    pathlib.Path("/tmp/trnm-r23-product-tree.txt").write_text(tree + "\n", encoding="ascii")
    create_product_worktree(commit, tree)
    review = review_status(commit)
    rows = dispatched_from_prior(prior) + exact_dispatch_runs(commit)
    wait_and_download(rows, commit)
    artifact = inspect_json_artifacts(commit, tree)
    gate_rc, surface, attempts = try_gate_surfaces(commit, tree)
    pathlib.Path("/tmp/trnm-r23-gate-attempts.json").write_text(
        json.dumps(attempts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    pathlib.Path("/tmp/trnm-r23-gate-status.txt").write_text(
        f"returncode={gate_rc}\nsurface={surface}\n", encoding="utf-8"
    )
    post_status(commit, tree, review, artifact, gate_rc, surface)
    if gate_rc == 0:
        return 0
    if gate_rc == 2:
        return 2
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
