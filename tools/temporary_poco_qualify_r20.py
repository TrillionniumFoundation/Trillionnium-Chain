#!/usr/bin/env python3
"""Qualify and publish one exact native PoCO tree, then launch real evidence jobs.

The controller is copied outside the candidate tree and deleted before the
candidate commit. It never converts missing external evidence into acceptance.
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
BRANCH = os.environ.get("TARGET_BRANCH", "chore/poco-only-purge-20260909")
REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "TrillionniumFoundation/Trillionnium-Chain")
FINAL = pathlib.Path("/tmp/trnm-r20-final")
EVIDENCE = pathlib.Path("/tmp/trnm-r20-evidence")
OVERLAY_HELPER = pathlib.Path("/tmp/trnm-r20-overlay.py")
TARGET_DIR = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", "/tmp/trnm-r20-target"))

TEMPORARY_PATHS = (
    ".github/workflows/poco-only-convergence-r14-once-20260910.yml",
    ".github/workflows/poco-only-convergence-r15-once-20260910.yml",
    ".github/workflows/poco-repository-gap-convergence-r16-once-20260910.yml",
    ".github/workflows/poco-exact-gap-convergence-r17-once-20260910.yml",
    ".github/workflows/poco-qualified-external-orchestration-r18-once-20260910.yml",
    ".github/workflows/poco-qualified-gap-overlay-r19-once-20260910.yml",
    ".github/workflows/poco-qualified-gap-overlay-r20-once-20260910.yml",
    "tools/temporary_poco_gap_overlay_r19.py",
    "tools/temporary_poco_productize_r19.py",
    "tools/temporary_poco_productize_r20.py",
    "tools/temporary_poco_qualify_r20.py",
    "tools/temporary_poco_r13_postfix.py",
)

BOUNDARY_PACKAGES = (
    "trnm-state",
    "trnm-consensus-types",
    "trnm-consensus-crypto",
    "trnm-consensus-core",
    "trnm-consensus-safety-rules",
    "trnm-consensus-safety-store",
    "trnm-consensus-signer-journal",
    "trnm-native-application",
    "trnm-native-application-sqlite",
    "trnm-native-execution-v0",
    "trnm-durable-file-adapters-v0",
    "trnm-tx-lifecycle-v0",
    "trnm-state-sync-v0",
    "trnm-migration-v0",
    "trnm-control-plane-v0",
    "trnm-release-bundle-v0",
    "trnm-node-boundary-v0",
    "trnm-poco-node-production-v0",
    "trnm-production-adapter-conformance-v0",
    "trnm-poco-node",
    "trnm-poco-node-authority",
    "trnm-poco-node-io",
    "trnm-poco-node-host",
    "trnm-poco-node-cli",
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


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    output: str


def run(
    command: list[str],
    *,
    cwd: pathlib.Path = ROOT,
    check: bool = True,
    log: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> CommandResult:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        timeout=timeout,
    )
    output = completed.stdout
    if log is not None:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(output, encoding="utf-8", errors="replace")
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{output[-30000:]}"
        )
    return CommandResult(command, completed.returncode, output)


def append_log(path: pathlib.Path, text: str) -> None:
    with path.open("a", encoding="utf-8") as destination:
        destination.write(text)
        if not text.endswith("\n"):
            destination.write("\n")


def remove_temporary_paths() -> None:
    for relative in TEMPORARY_PATHS:
        path = ROOT / relative
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists() or path.is_symlink():
            path.unlink()


def commit_if_dirty(message: str, *, cwd: pathlib.Path) -> bool:
    run(["git", "add", "-A"], cwd=cwd)
    run(["git", "diff", "--cached", "--check"], cwd=cwd)
    changed = run(["git", "diff", "--cached", "--name-only"], cwd=cwd).output.strip()
    if not changed:
        return False
    run(["git", "config", "user.name", "Qian QI"], cwd=cwd)
    run(
        ["git", "config", "user.email", "102159240+ProfHepta@users.noreply.github.com"],
        cwd=cwd,
    )
    run(["git", "commit", "-m", message], cwd=cwd)
    return True


def prepare_candidate() -> tuple[str, str]:
    remove_temporary_paths()
    run(["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all"])
    commit_if_dirty("ci: remove completed PoCO convergence controllers", cwd=ROOT)
    commit = run(["git", "rev-parse", "HEAD"]).output.strip()
    tree = run(["git", "rev-parse", "HEAD^{tree}"]).output.strip()
    if run(["git", "status", "--porcelain", "--untracked-files=all"]).output.strip():
        raise RuntimeError("source checkout is dirty before candidate worktree creation")
    shutil.rmtree(FINAL, ignore_errors=True)
    run(["git", "worktree", "add", "--detach", str(FINAL), commit])
    if run(["git", "-C", str(FINAL), "rev-parse", "HEAD"]).output.strip() != commit:
        raise RuntimeError("candidate commit identity mismatch")
    if run(["git", "-C", str(FINAL), "rev-parse", "HEAD^{tree}"]).output.strip() != tree:
        raise RuntimeError("candidate tree identity mismatch")
    pathlib.Path("/tmp/trnm-r20-initial-commit.txt").write_text(commit + "\n", encoding="ascii")
    pathlib.Path("/tmp/trnm-r20-initial-tree.txt").write_text(tree + "\n", encoding="ascii")
    return commit, tree


def load_overlay_module() -> Any:
    spec = importlib.util.spec_from_file_location("trnm_r20_overlay", OVERLAY_HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load overlay helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def refresh_pins(cwd: pathlib.Path) -> None:
    helper_commit = run(
        ["git", "log", "--all", "-1", "--format=%H", "--", "tools/temporary_poco_convergence_r5.py"],
        cwd=cwd,
        check=False,
    ).output.strip()
    if not helper_commit:
        return
    helper = cwd / "tools/.temporary_r20_refresh.py"
    source = run(
        ["git", "show", f"{helper_commit}:tools/temporary_poco_convergence_r5.py"],
        cwd=cwd,
    ).output
    helper.write_text(source, encoding="utf-8")
    try:
        run(["python3", str(helper.relative_to(cwd)), "refresh-pins"], cwd=cwd)
    finally:
        helper.unlink(missing_ok=True)


def run_overlay_rounds() -> int:
    log = pathlib.Path("/tmp/trnm-r20-overlay-rounds.log")
    log.write_text("", encoding="utf-8")
    applied = 0
    for round_number in range(1, 4):
        head = run(["git", "rev-parse", "HEAD"], cwd=FINAL).output.strip()
        append_log(log, f"round={round_number} head={head}")
        result = run(
            ["python3", str(OVERLAY_HELPER), str(FINAL)],
            cwd=FINAL,
            check=False,
        )
        append_log(log, result.output)
        if result.returncode == 4:
            append_log(log, f"round={round_number} admissible_improvement=false")
            break
        if result.returncode != 0:
            raise RuntimeError(f"overlay search failed in round {round_number}:\n{result.output[-30000:]}")
        staged = run(["git", "diff", "--cached", "--name-only"], cwd=FINAL).output.strip()
        unstaged = run(["git", "diff", "--name-only"], cwd=FINAL).output.strip()
        if not staged and not unstaged:
            append_log(log, f"round={round_number} baseline_zero_or_noop=true")
            break
        run(["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all"], cwd=FINAL)
        refresh_pins(FINAL)
        run(["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all"], cwd=FINAL)
        commit_if_dirty(
            f"fix(poco): integrate admissible repository gap closure round {round_number}",
            cwd=FINAL,
        )
        run(["python3", "scripts/ci/check_native_consensus_only.py"], cwd=FINAL)
        check_env = os.environ.copy()
        check_env["CARGO_TARGET_DIR"] = f"/tmp/trnm-r20-overlay-commit-{round_number}"
        shutil.rmtree(check_env["CARGO_TARGET_DIR"], ignore_errors=True)
        run(
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
            cwd=FINAL,
            env=check_env,
        )
        applied += 1
    return applied


def convergence_commands() -> list[pathlib.Path]:
    patterns = (
        "*technical*convergence*.py",
        "*technical*convergence*.sh",
        "*documentation*integrity*.py",
        "*documentation*integrity*.sh",
        "*module*coverage*.py",
        "*module*coverage*.sh",
    )
    paths: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()
    for pattern in patterns:
        for path in sorted((FINAL / "scripts/ci").glob(pattern)):
            if path.is_file() and path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


def classify_final_gaps() -> dict[str, Any]:
    overlay = load_overlay_module()
    score, rows = overlay.classify_gaps(FINAL)
    commands = []
    report_texts = []
    for path in convergence_commands():
        relative = path.relative_to(FINAL).as_posix()
        command = ["python3", relative] if path.suffix == ".py" else ["bash", relative]
        result = run(command, cwd=FINAL, check=False)
        commands.append(
            {
                "path": relative,
                "returncode": result.returncode,
                "output": result.output,
            }
        )
        report_texts.append(result.output)
    joined = "\n".join(report_texts)
    source_regressions_present = (
        '"source_regression_case_count":' in joined
        and '"source_regression_case_count": 0' not in joined
    )
    independent_vectors_absent = '"independent_golden_vector_count": 0' in joined
    catalog_incomplete = '"operation_catalog_complete": false' in joined
    catalog_repository_gap = catalog_incomplete and not (
        source_regressions_present and independent_vectors_absent
    )
    failed_commands = [row["path"] for row in commands if row["returncode"] != 0]
    repository_gap_count = score.total + int(catalog_repository_gap) + len(failed_commands)
    external_rows = [row for row in rows if row["classification"] == "external"]
    if catalog_incomplete and not catalog_repository_gap:
        external_rows.append(
            {
                "path": "convergence-reports",
                "line": 0,
                "markers": ["operation-catalog-independent-acceptance-open"],
                "classification": "external",
                "basis": ["source regression cases present", "independent golden vectors absent"],
                "text": "implementation sources exist; independent golden acceptance remains external",
            }
        )
    report = {
        "schema": "trnm-poco-final-gap-classification-r20-v1",
        "source_commit": run(["git", "rev-parse", "HEAD"], cwd=FINAL).output.strip(),
        "source_tree": run(["git", "rev-parse", "HEAD^{tree}"], cwd=FINAL).output.strip(),
        "repository_gap_count": repository_gap_count,
        "repository_marker_score": score.as_dict(),
        "catalog_repository_gap": catalog_repository_gap,
        "failed_convergence_commands": failed_commands,
        "markers": rows,
        "external_rows": external_rows,
        "external_blocker_ids": [
            "EXT-ANCHOR-HSM-001",
            "EXT-AUDIT-001",
            "EXT-G1-CAMPAIGN-001",
            "EXT-POWERLOSS-001",
            "EXT-REVIEW-001",
            "EXT-SOAK-ACTIVATION-001",
        ],
        "commands": commands,
    }
    pathlib.Path("/tmp/trnm-r20-gap-classification.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summary = [
        f"source_commit={report['source_commit']}",
        f"source_tree={report['source_tree']}",
        f"repository_gap_count={repository_gap_count}",
        f"repository_marker_total={score.total}",
        f"catalog_repository_gap={str(catalog_repository_gap).lower()}",
        f"failed_convergence_command_count={len(failed_commands)}",
        "external_blocker_count=6",
    ]
    for row in rows:
        summary.append(
            f"{row['classification'].upper()} {row['path']}:{row['line']} {row['text']}"
        )
    pathlib.Path("/tmp/trnm-r20-gap-summary.txt").write_text(
        "\n".join(summary) + "\n", encoding="utf-8"
    )
    pathlib.Path("/tmp/trnm-r20-repository-gap-count.txt").write_text(
        str(repository_gap_count) + "\n", encoding="ascii"
    )
    return report


def truth_gates() -> None:
    commands = (
        (["python3", "-m", "compileall", "-q", "scripts", "tools", "formal", "conformance"], None),
        (["python3", "scripts/ci/check_native_consensus_only.py"], "/tmp/trnm-r20-native-only.json"),
        (["bash", "scripts/ci/check_canonical_development_plan.sh"], "/tmp/trnm-r20-canonical-plan.log"),
        (["bash", "scripts/ci/check_poco_bft_mainline_truth.sh"], "/tmp/trnm-r20-mainline.log"),
        (["python3", "scripts/ci/check_repository_truth_v1.py"], "/tmp/trnm-r20-repository-truth.json"),
        (["python3", "scripts/ci/check_required_protocol_contract_v1.py"], "/tmp/trnm-r20-protocol-contract.json"),
    )
    for command, log in commands:
        run(command, cwd=FINAL, log=pathlib.Path(log) if log else None)
    run(
        ["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"],
        cwd=FINAL,
    )
    if run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=FINAL).output.strip():
        raise RuntimeError("candidate became dirty during truth gates")


def compile_all() -> None:
    shutil.rmtree(TARGET_DIR, ignore_errors=True)
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(TARGET_DIR)
    run(
        [
            "cargo", "check", "--manifest-path", "trillionnium/Cargo.toml",
            "--workspace", "--all-targets", "--locked", "--offline", "-j", "1",
        ],
        cwd=FINAL,
        env=env,
        log=pathlib.Path("/tmp/trnm-r20-workspace-check.log"),
    )
    run(
        [
            "cargo", "check", "--manifest-path", "contracts/Cargo.toml",
            "--workspace", "--all-targets", "--locked", "--offline", "-j", "1",
        ],
        cwd=FINAL,
        env=env,
        log=pathlib.Path("/tmp/trnm-r20-contract-check.log"),
    )


def test_all() -> None:
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(TARGET_DIR)
    run(
        [
            "cargo", "test", "--manifest-path", "trillionnium/Cargo.toml",
            "--workspace", "--all-targets", "--locked", "--offline",
            "--no-fail-fast", "-j", "1", "--", "--test-threads=1",
        ],
        cwd=FINAL,
        env=env,
        timeout=7200,
        log=pathlib.Path("/tmp/trnm-r20-workspace-test.log"),
    )
    run(
        [
            "cargo", "test", "--manifest-path", "contracts/Cargo.toml",
            "--workspace", "--all-targets", "--locked", "--offline", "-j", "1",
        ],
        cwd=FINAL,
        env=env,
        log=pathlib.Path("/tmp/trnm-r20-contract-test.log"),
    )
    if run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=FINAL).output.strip():
        raise RuntimeError("candidate became dirty during tests")


def clippy_all() -> None:
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(TARGET_DIR)
    run(
        [
            "cargo", "clippy", "--manifest-path", "contracts/Cargo.toml",
            "--workspace", "--all-targets", "--locked", "--offline", "-j", "1",
            "--", "-D", "warnings",
        ],
        cwd=FINAL,
        env=env,
        log=pathlib.Path("/tmp/trnm-r20-contract-clippy.log"),
    )
    log = pathlib.Path("/tmp/trnm-r20-boundary-clippy.log")
    log.write_text("", encoding="utf-8")
    for package in BOUNDARY_PACKAGES:
        result = run(
            [
                "cargo", "clippy", "-p", package, "--all-targets",
                "--locked", "--offline", "-j", "1", "--", "-D", "warnings",
            ],
            cwd=FINAL / "trillionnium",
            env=env,
            check=False,
        )
        append_log(log, f"=== package={package} rc={result.returncode} ===\n{result.output}")
        if result.returncode != 0:
            raise RuntimeError(f"strict clippy failed for {package}\n{result.output[-30000:]}")
    if run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=FINAL).output.strip():
        raise RuntimeError("candidate became dirty during clippy")


def publish() -> tuple[str, str]:
    commit = run(["git", "rev-parse", "HEAD"], cwd=FINAL).output.strip()
    tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=FINAL).output.strip()
    if pathlib.Path("/tmp/trnm-r20-repository-gap-count.txt").read_text().strip() != "0":
        raise RuntimeError("repository gap count is not zero at publication")
    truth_gates()
    run(["git", "push", "origin", f"{commit}:refs/heads/{BRANCH}"], cwd=ROOT)
    pathlib.Path("/tmp/trnm-r20-final-commit.txt").write_text(commit + "\n", encoding="ascii")
    pathlib.Path("/tmp/trnm-r20-final-tree.txt").write_text(tree + "\n", encoding="ascii")
    return commit, tree


def workflow_required_inputs(text: str) -> list[str]:
    required: list[str] = []
    for match in re.finditer(r"(?m)^\s{6}([A-Za-z0-9_-]+):\s*$", text):
        name = match.group(1)
        tail = text[match.end(): match.end() + 700]
        if re.search(r"(?m)^\s{8}required:\s*true\s*$", tail):
            required.append(name)
    return required


def dispatch_external(commit: str, tree: str) -> dict[str, Any]:
    token = os.environ.get("GH_TOKEN")
    if not token:
        return {"dispatched": [], "skipped": [{"reason": "GH_TOKEN missing"}]}
    values = {
        "source_commit": commit,
        "source_sha": commit,
        "commit": commit,
        "head_sha": commit,
        "source_tree": tree,
        "tree": tree,
        "tree_sha": tree,
        "branch": BRANCH,
        "ref": BRANCH,
        "target_branch": BRANCH,
    }
    dispatched = []
    skipped = []
    start = dt.datetime.now(dt.timezone.utc).isoformat()
    for path in sorted((FINAL / ".github/workflows").glob("*.y*ml")):
        relative = path.relative_to(FINAL).as_posix()
        text = path.read_text(encoding="utf-8")
        lowered = (relative + "\n" + text[:5000]).casefold()
        if "workflow_dispatch" not in text or not any(word in lowered for word in EXTERNAL_KEYWORDS):
            continue
        required = workflow_required_inputs(text)
        unknown = [name for name in required if name not in values]
        if unknown:
            skipped.append({"workflow": relative, "reason": "unknown-required-input", "inputs": unknown})
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
            cwd=FINAL,
            check=False,
            env=os.environ.copy(),
        ) if False else None
        completed = subprocess.run(
            ["gh", "api", "--method", "POST", endpoint, "--input", "-"],
            cwd=FINAL,
            input=json.dumps(payload),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=os.environ.copy(),
        )
        if completed.returncode == 0:
            dispatched.append({"workflow": relative, "workflow_file": path.name, "inputs": inputs})
        else:
            skipped.append(
                {
                    "workflow": relative,
                    "reason": "dispatch-failed",
                    "output": completed.stdout[-3000:],
                }
            )
    report = {
        "schema": "trnm-poco-external-dispatch-r20-v1",
        "source_commit": commit,
        "source_tree": tree,
        "dispatch_started_at": start,
        "dispatched": dispatched,
        "skipped": skipped,
    }
    pathlib.Path("/tmp/trnm-r20-external-dispatch.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def wait_for_dispatched(report: dict[str, Any], commit: str) -> list[dict[str, Any]]:
    results = []
    deadline = time.monotonic() + 7200
    for row in report.get("dispatched", []):
        workflow_file = row["workflow_file"]
        encoded = urllib.parse.quote(workflow_file, safe="")
        run_id = None
        while time.monotonic() < deadline:
            query = (
                f"repos/{REPOSITORY}/actions/workflows/{encoded}/runs"
                f"?branch={urllib.parse.quote(BRANCH, safe='')}&event=workflow_dispatch&per_page=10"
            )
            response = run(["gh", "api", query], cwd=FINAL, check=False)
            if response.returncode == 0:
                try:
                    payload = json.loads(response.output)
                except json.JSONDecodeError:
                    payload = {}
                for candidate in payload.get("workflow_runs", []):
                    if candidate.get("head_sha") == commit:
                        run_id = candidate.get("id")
                        break
            if run_id is not None:
                break
            time.sleep(10)
        if run_id is None:
            results.append({"workflow": row["workflow"], "result": "run-not-observed"})
            continue
        terminal = None
        while time.monotonic() < deadline:
            response = run(["gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}"], cwd=FINAL, check=False)
            if response.returncode == 0:
                try:
                    terminal = json.loads(response.output)
                except json.JSONDecodeError:
                    terminal = None
            if terminal and terminal.get("status") == "completed":
                break
            time.sleep(15)
        result = {
            "workflow": row["workflow"],
            "run_id": run_id,
            "status": terminal.get("status") if terminal else None,
            "conclusion": terminal.get("conclusion") if terminal else None,
        }
        artifact_dir = pathlib.Path("/tmp/trnm-r20-external-artifacts") / str(run_id)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        download = run(
            ["gh", "run", "download", str(run_id), "--repo", REPOSITORY, "--dir", str(artifact_dir)],
            cwd=FINAL,
            check=False,
        )
        result["artifact_download_returncode"] = download.returncode
        result["artifact_download_output"] = download.output[-3000:]
        results.append(result)
    pathlib.Path("/tmp/trnm-r20-external-runs.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return results


def external_evidence_gate(commit: str, tree: str) -> int:
    run(["python3", "scripts/ci/test_external_evidence_v1.py"], cwd=FINAL)
    result = run(
        [
            "python3",
            "scripts/ci/check_external_evidence_v1.py",
            "--require-all",
            "--source-commit",
            commit,
            "--source-tree",
            tree,
            "--output",
            "/tmp/trnm-r20-external-evidence.json",
        ],
        cwd=FINAL,
        check=False,
    )
    pathlib.Path("/tmp/trnm-r20-external-evidence.log").write_text(
        result.output, encoding="utf-8", errors="replace"
    )
    pathlib.Path("/tmp/trnm-r20-external-evidence-status.txt").write_text(
        f"external_evidence_exit={result.returncode}\n", encoding="ascii"
    )
    if result.returncode not in (0, 2):
        raise RuntimeError(f"unexpected external evidence gate exit {result.returncode}\n{result.output}")
    return result.returncode


def main() -> int:
    prepare_candidate()
    applied = run_overlay_rounds()
    pathlib.Path("/tmp/trnm-r20-overlay-applied-count.txt").write_text(
        str(applied) + "\n", encoding="ascii"
    )
    gap_report = classify_final_gaps()
    if gap_report["repository_gap_count"] != 0:
        raise RuntimeError(
            "repository-owned gaps remain after admissible overlay search\n"
            + pathlib.Path("/tmp/trnm-r20-gap-summary.txt").read_text(encoding="utf-8")
        )
    truth_gates()
    compile_all()
    test_all()
    clippy_all()
    commit, tree = publish()
    dispatch_report = dispatch_external(commit, tree)
    wait_for_dispatched(dispatch_report, commit)
    gate_rc = external_evidence_gate(commit, tree)
    return gate_rc


if __name__ == "__main__":
    raise SystemExit(main())
