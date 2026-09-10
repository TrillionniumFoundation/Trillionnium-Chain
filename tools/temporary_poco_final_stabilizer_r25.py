#!/usr/bin/env python3
"""Restore the latest actually published and qualified PoCO product ancestor.

Only temporary-controller commits may be removed. The script then dispatches
available real evidence workflows and preserves fail-closed release truth.
"""
from __future__ import annotations

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
EXPECTED_HEAD = os.environ.get("GITHUB_SHA", "")
PR_NUMBER = 117
PRODUCT = pathlib.Path("/tmp/trnm-r25-product")
ARTIFACTS = pathlib.Path("/tmp/trnm-r25-external-artifacts")

MESSAGE_TERMS = (
    "publish native-domain qualified product tree",
    "publish semantic-preserving native-only tree",
    "publish corrected qualified native-only tree",
    "remove completed poco convergence controllers",
    "publish zero-repository-gap native poco tree",
)

EXTERNAL_IDS = (
    "EXT-ANCHOR-HSM-001",
    "EXT-AUDIT-001",
    "EXT-G1-CAMPAIGN-001",
    "EXT-POWERLOSS-001",
    "EXT-REVIEW-001",
    "EXT-SOAK-ACTIVATION-001",
)

EXTERNAL_KEYWORDS = (
    "external",
    "evidence",
    "hsm",
    "audit",
    "power",
    "soak",
    "campaign",
    "multihost",
    "multi-host",
    "long-fuzz",
    "review",
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
    return json.loads(run(["gh", "api", endpoint]).stdout)


def temporary_path(path: str) -> bool:
    if path.startswith("tools/temporary_poco_"):
        return True
    if not path.startswith(".github/workflows/poco-"):
        return False
    return any(f"r{number}" in path.casefold() for number in range(14, 26))


def tree_has_temporary_paths(commit: str) -> bool:
    paths = run(["git", "ls-tree", "-r", "--name-only", commit]).stdout.splitlines()
    return any(temporary_path(path) for path in paths)


def candidate_messages() -> list[tuple[str, str]]:
    rows = []
    history = run(
        ["git", "log", "--first-parent", "--format=%H%x00%s", "-n", "250", "HEAD"]
    ).stdout.splitlines()
    for line in history:
        if "\x00" not in line:
            continue
        commit, subject = line.split("\x00", 1)
        lowered = subject.casefold()
        if any(term in lowered for term in MESSAGE_TERMS):
            rows.append((commit, subject))
    return rows


def validate_candidate(commit: str, index: int) -> dict[str, Any]:
    if tree_has_temporary_paths(commit):
        return {"commit": commit, "accepted": False, "reason": "temporary-path-present"}
    worktree = pathlib.Path(f"/tmp/trnm-r25-candidate-{index}")
    shutil.rmtree(worktree, ignore_errors=True)
    added = run(["git", "worktree", "add", "--detach", str(worktree), commit], check=False)
    if added.returncode != 0:
        return {"commit": commit, "accepted": False, "reason": "worktree-add", "log": added.stdout[-4000:]}
    try:
        required = (
            worktree / "scripts/ci/check_native_consensus_only.py",
            worktree / "scripts/ci/check_canonical_development_plan.sh",
            worktree / "scripts/ci/check_repository_truth_v1.py",
            worktree / "scripts/ci/check_required_protocol_contract_v1.py",
        )
        if not all(path.is_file() for path in required):
            return {"commit": commit, "accepted": False, "reason": "required-gate-missing"}
        commands = (
            ["python3", "scripts/ci/check_native_consensus_only.py"],
            ["bash", "scripts/ci/check_canonical_development_plan.sh"],
            ["bash", "scripts/ci/check_poco_bft_mainline_truth.sh"],
            ["python3", "scripts/ci/check_repository_truth_v1.py"],
            ["python3", "scripts/ci/check_required_protocol_contract_v1.py"],
        )
        logs = []
        for command in commands:
            result = run(command, cwd=worktree, check=False)
            logs.append({"command": command, "returncode": result.returncode, "output": result.stdout[-12000:]})
            if result.returncode != 0:
                return {"commit": commit, "accepted": False, "reason": "truth-gate", "logs": logs}
        status = run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=worktree).stdout.strip()
        if status:
            return {"commit": commit, "accepted": False, "reason": "gate-dirtied-tree", "status": status}
        tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=worktree).stdout.strip()
        return {"commit": commit, "tree": tree, "accepted": True, "reason": "all-truth-gates-pass", "logs": logs}
    finally:
        run(["git", "worktree", "remove", "--force", str(worktree)], check=False)
        shutil.rmtree(worktree, ignore_errors=True)


def select_product() -> tuple[str, str, list[dict[str, Any]]]:
    attempts = []
    for index, (commit, subject) in enumerate(candidate_messages(), 1):
        result = validate_candidate(commit, index)
        result["subject"] = subject
        attempts.append(result)
        if result.get("accepted"):
            pathlib.Path("/tmp/trnm-r25-product-selection.json").write_text(
                json.dumps(attempts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            return commit, str(result["tree"]), attempts
    pathlib.Path("/tmp/trnm-r25-product-selection.json").write_text(
        json.dumps(attempts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    raise RuntimeError("no published qualified product ancestor passed exact truth gates")


def validate_controller_only_suffix(product: str, current: str) -> list[str]:
    if run(["git", "merge-base", "--is-ancestor", product, current], check=False).returncode != 0:
        raise RuntimeError("selected product is not an ancestor of current head")
    changed = run(["git", "diff", "--name-only", product, current]).stdout.splitlines()
    rejected = [path for path in changed if not temporary_path(path)]
    pathlib.Path("/tmp/trnm-r25-controller-diff.txt").write_text(
        "\n".join(changed) + "\n", encoding="utf-8"
    )
    if rejected:
        raise RuntimeError("non-controller paths changed after product: " + ", ".join(rejected))
    return changed


def restore_product_head(product: str) -> None:
    current = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    if EXPECTED_HEAD and current != EXPECTED_HEAD:
        raise RuntimeError(f"event head mismatch: expected {EXPECTED_HEAD}, observed {current}")
    validate_controller_only_suffix(product, current)
    run(
        [
            "git",
            "push",
            f"--force-with-lease=refs/heads/{BRANCH}:{current}",
            "origin",
            f"{product}:refs/heads/{BRANCH}",
        ]
    )


def create_product_worktree(product: str, tree: str) -> None:
    shutil.rmtree(PRODUCT, ignore_errors=True)
    run(["git", "worktree", "add", "--detach", str(PRODUCT), product])
    if run(["git", "rev-parse", "HEAD"], cwd=PRODUCT).stdout.strip() != product:
        raise RuntimeError("product commit mismatch after stabilization")
    if run(["git", "rev-parse", "HEAD^{tree}"], cwd=PRODUCT).stdout.strip() != tree:
        raise RuntimeError("product tree mismatch after stabilization")
    pathlib.Path("/tmp/trnm-r25-product-commit.txt").write_text(product + "\n", encoding="ascii")
    pathlib.Path("/tmp/trnm-r25-product-tree.txt").write_text(tree + "\n", encoding="ascii")


def required_inputs(text: str) -> list[str]:
    result = []
    for match in re.finditer(r"(?m)^\s{6}([A-Za-z0-9_-]+):\s*$", text):
        name = match.group(1)
        tail = text[match.end():match.end() + 800]
        if re.search(r"(?m)^\s{8}required:\s*true\s*$", tail):
            result.append(name)
    return result


def dispatch_evidence(product: str, tree: str) -> list[dict[str, Any]]:
    values = {
        "source_commit": product,
        "source_sha": product,
        "commit": product,
        "head_sha": product,
        "source_tree": tree,
        "tree": tree,
        "tree_sha": tree,
        "branch": BRANCH,
        "ref": BRANCH,
        "target_branch": BRANCH,
    }
    rows = []
    for path in sorted((PRODUCT / ".github/workflows").glob("*.y*ml")):
        relative = path.relative_to(PRODUCT).as_posix()
        text = path.read_text(encoding="utf-8")
        lowered = (relative + "\n" + text[:6000]).casefold()
        if "workflow_dispatch" not in text:
            continue
        exact_ids = [identifier for identifier in EXTERNAL_IDS if identifier in text]
        if not exact_ids and not any(keyword in lowered for keyword in EXTERNAL_KEYWORDS):
            continue
        required = required_inputs(text)
        unknown = [name for name in required if name not in values]
        if unknown:
            rows.append({"workflow": relative, "dispatched": False, "reason": "unknown-required-input", "inputs": unknown, "external_ids": exact_ids})
            continue
        payload: dict[str, Any] = {"ref": BRANCH}
        inputs = {name: values[name] for name in required}
        if inputs:
            payload["inputs"] = inputs
        endpoint = (
            f"repos/{REPOSITORY}/actions/workflows/"
            f"{urllib.parse.quote(path.name, safe='')}/dispatches"
        )
        result = run(
            ["gh", "api", "--method", "POST", endpoint, "--input", "-"],
            input_text=json.dumps(payload),
            check=False,
        )
        rows.append(
            {
                "workflow": relative,
                "workflow_file": path.name,
                "dispatched": result.returncode == 0,
                "returncode": result.returncode,
                "output": result.stdout[-3000:],
                "inputs": inputs,
                "external_ids": exact_ids,
            }
        )
    pathlib.Path("/tmp/trnm-r25-dispatch.json").write_text(
        json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return rows


def wait_runs(rows: list[dict[str, Any]], product: str) -> list[dict[str, Any]]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    results = []
    deadline = time.monotonic() + 5400
    for row in rows:
        if not row.get("dispatched"):
            continue
        encoded = urllib.parse.quote(str(row["workflow_file"]), safe="")
        run_id = None
        while time.monotonic() < deadline:
            payload = gh_json(
                f"repos/{REPOSITORY}/actions/workflows/{encoded}/runs"
                f"?branch={urllib.parse.quote(BRANCH, safe='')}&event=workflow_dispatch&per_page=20"
            )
            for candidate in payload.get("workflow_runs", []):
                if candidate.get("head_sha") == product:
                    run_id = int(candidate["id"])
                    break
            if run_id is not None:
                break
            time.sleep(10)
        terminal = None
        if run_id is not None:
            while time.monotonic() < deadline:
                terminal = gh_json(f"repos/{REPOSITORY}/actions/runs/{run_id}")
                if terminal.get("status") == "completed":
                    break
                time.sleep(15)
            destination = ARTIFACTS / str(run_id)
            destination.mkdir(parents=True, exist_ok=True)
            download = run(
                ["gh", "run", "download", str(run_id), "--repo", REPOSITORY, "--dir", str(destination)],
                check=False,
            )
        else:
            download = None
        results.append(
            {
                "workflow": row["workflow"],
                "run_id": run_id,
                "status": terminal.get("status") if terminal else None,
                "conclusion": terminal.get("conclusion") if terminal else None,
                "head_sha": terminal.get("head_sha") if terminal else None,
                "artifact_download_returncode": download.returncode if download else None,
                "artifact_download_output": download.stdout[-3000:] if download else None,
            }
        )
    pathlib.Path("/tmp/trnm-r25-external-runs.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return results


def request_and_read_reviews(product: str) -> dict[str, Any]:
    request = run(
        [
            "gh", "api", "--method", "POST",
            f"repos/{REPOSITORY}/pulls/{PR_NUMBER}/requested_reviewers",
            "--input", "-",
        ],
        input_text=json.dumps({"reviewers": list(REVIEWERS)}),
        check=False,
    )
    reviews = gh_json(f"repos/{REPOSITORY}/pulls/{PR_NUMBER}/reviews?per_page=100")
    exact = [
        {
            "user": (review.get("user") or {}).get("login"),
            "state": review.get("state"),
            "commit_id": review.get("commit_id"),
            "submitted_at": review.get("submitted_at"),
        }
        for review in reviews
        if review.get("state") == "APPROVED" and review.get("commit_id") == product
    ]
    report = {
        "source_commit": product,
        "exact_head_approvals": exact,
        "request_returncode": request.returncode,
        "request_output": request.stdout[-3000:],
    }
    pathlib.Path("/tmp/trnm-r25-review.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def artifact_ids() -> list[str]:
    observed = set()
    for path in ARTIFACTS.rglob("*.json"):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for identifier in EXTERNAL_IDS:
            if identifier in text:
                observed.add(identifier)
    return sorted(observed)


def external_gate(product: str, tree: str) -> subprocess.CompletedProcess[str]:
    run(["python3", "scripts/ci/test_external_evidence_v1.py"], cwd=PRODUCT)
    result = run(
        [
            "python3", "scripts/ci/check_external_evidence_v1.py", "--require-all",
            "--source-commit", product,
            "--source-tree", tree,
            "--output", "/tmp/trnm-r25-external-evidence.json",
        ],
        cwd=PRODUCT,
        check=False,
    )
    pathlib.Path("/tmp/trnm-r25-external-evidence.log").write_text(
        result.stdout, encoding="utf-8", errors="replace"
    )
    pathlib.Path("/tmp/trnm-r25-external-status.txt").write_text(
        f"returncode={result.returncode}\n", encoding="ascii"
    )
    return result


def post_comment(product: str, tree: str, review: dict[str, Any], gate: subprocess.CompletedProcess[str]) -> None:
    ids = artifact_ids()
    body = "\n".join(
        [
            "### PoCO R25 stabilized product and external gate",
            "",
            f"- clean branch/product commit: `{product}`",
            f"- product tree: `{tree}`",
            f"- exact-head approvals: `{len(review['exact_head_approvals'])}`",
            f"- external IDs observed in downloaded artifacts: `{len(ids)}/6`",
            f"- require-all exit: `{gate.returncode}`",
            "- missing evidence was not synthesized or self-approved.",
            "",
            "Observed IDs: " + (", ".join(f"`{identifier}`" for identifier in ids) or "none"),
        ]
    ) + "\n"
    pathlib.Path("/tmp/trnm-r25-pr-comment.md").write_text(body, encoding="utf-8")
    run(
        ["gh", "pr", "comment", str(PR_NUMBER), "--repo", REPOSITORY, "--body-file", "/tmp/trnm-r25-pr-comment.md"],
        check=False,
    )


def main() -> int:
    run(["git", "fetch", "--no-tags", "origin", "+refs/heads/*:refs/remotes/origin/*"])
    product, tree, _ = select_product()
    create_product_worktree(product, tree)
    restore_product_head(product)
    review = request_and_read_reviews(product)
    rows = dispatch_evidence(product, tree)
    wait_runs(rows, product)
    gate = external_gate(product, tree)
    post_comment(product, tree, review, gate)
    if gate.returncode == 0:
        return 0
    if gate.returncode == 2:
        return 2
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
