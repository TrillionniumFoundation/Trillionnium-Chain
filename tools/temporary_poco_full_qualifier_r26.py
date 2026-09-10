#!/usr/bin/env python3
"""Close repository-owned PoCO gaps and qualify one immutable product tree.

This controller is removed before the candidate commit. It may reuse an
existing closure branch only when the overlay changes active source and tests,
preserves the native-only boundary, strictly reduces unresolved repository
markers, and compiles all workspace targets. Missing external evidence is never
converted into acceptance.
"""
from __future__ import annotations

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
from typing import Any

ROOT = pathlib.Path(os.environ.get("GITHUB_WORKSPACE", pathlib.Path.cwd())).resolve()
BRANCH = os.environ.get("TARGET_BRANCH", "chore/poco-only-purge-20260909")
REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "TrillionniumFoundation/Trillionnium-Chain")
PR_NUMBER = 117
FINAL = pathlib.Path("/tmp/trnm-r26-final")
TARGET = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", "/tmp/trnm-r26-target"))
OVERLAY = pathlib.Path("/tmp/trnm-r26-overlay.py")
ARTIFACTS = pathlib.Path("/tmp/trnm-r26-external-artifacts")

CANONICAL_FILES = (
    "docs/development/CURRENT_SNAPSHOT_V1.json",
    "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md",
    "docs/development/module-registry-v1.toml",
    "docs/development/plan-manifest-v1.toml",
    "docs/development/release-train-v1.toml",
)

EXTERNAL_IDS = (
    "EXT-ANCHOR-HSM-001",
    "EXT-AUDIT-001",
    "EXT-G1-CAMPAIGN-001",
    "EXT-POWERLOSS-001",
    "EXT-REVIEW-001",
    "EXT-SOAK-ACTIVATION-001",
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

REVIEWERS = ("Franksudoman", "Tomasrgbsf")

TEMPORARY_EXACT = (
    ".github/workflows/poco-only-convergence-r14-once-20260910.yml",
    ".github/workflows/poco-only-convergence-r15-once-20260910.yml",
    ".github/workflows/poco-repository-gap-convergence-r16-once-20260910.yml",
    ".github/workflows/poco-exact-gap-convergence-r17-once-20260910.yml",
    ".github/workflows/poco-qualified-external-orchestration-r18-once-20260910.yml",
    ".github/workflows/poco-qualified-gap-overlay-r19-once-20260910.yml",
    ".github/workflows/poco-qualified-gap-overlay-r20-once-20260910.yml",
    ".github/workflows/poco-qualified-gap-overlay-r21-once-20260910.yml",
    ".github/workflows/poco-takeover-r22-once-20260910.yml",
    ".github/workflows/poco-external-collector-r23-once-20260910.yml",
    ".github/workflows/poco-clean-product-r24-once-20260910.yml",
    ".github/workflows/poco-final-stabilizer-r25-once-20260910.yml",
    ".github/workflows/poco-full-qualification-r26-once-20260910.yml",
)

DISPATCH_INCLUDE = (
    "evidence",
    "qualification",
    "fuzz",
    "soak",
    "campaign",
    "audit",
    "powerloss",
    "power-loss",
    "hsm",
    "multihost",
    "multi-host",
    "review",
)

DISPATCH_EXCLUDE = (
    "admin",
    "cleanup",
    "delete",
    "settings",
    "secret",
    "apply-",
    "publish-",
)


def run(
    command: list[str],
    *,
    cwd: pathlib.Path = ROOT,
    check: bool = True,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
    log: pathlib.Path | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env or os.environ.copy(),
        timeout=timeout,
    )
    if log is not None:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(completed.stdout, encoding="utf-8", errors="replace")
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout[-40000:]}"
        )
    return completed


def append(path: pathlib.Path, value: str) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(value)
        if not value.endswith("\n"):
            output.write("\n")


def gh_json(endpoint: str) -> Any:
    return json.loads(run(["gh", "api", endpoint]).stdout)


def restore_history_file(relative: str, destination: pathlib.Path) -> None:
    commit = run(
        ["git", "log", "--all", "-1", "--format=%H", "--", relative],
        check=False,
    ).stdout.strip()
    if not commit:
        raise RuntimeError(f"history does not contain {relative}")
    source = run(["git", "show", f"{commit}:{relative}"]).stdout
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(source, encoding="utf-8")


def repair_raw_key_boundary() -> bool:
    path = ROOT / "trillionnium/crates/trnm-poco-node/tests/raw_key_boundary.rs"
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    compact_marker = "compact_lib.contains("
    desired_feature = "recovery-process-test-support"
    if compact_marker in text and desired_feature in text:
        return False
    begin = text.find('        if relative == "src/recovery_tests.rs" {')
    terminator = "            continue;\n        }\n"
    end = text.find(terminator, begin)
    if begin < 0 or end < 0:
        raise RuntimeError("raw-key recovery assertion block drift")
    end += len(terminator)
    replacement = '''        if relative == "src/recovery_tests.rs" {
            let compact_lib: String = lib.chars().filter(|ch| !ch.is_whitespace()).collect();
            assert!(
                compact_lib.contains(
                    "#[cfg(all(test,feature=\\\"recovery-process-test-support\\\",target_os=\\\"linux\\\"))]modrecovery_tests;"
                ),
                "recovery raw-key module lost its test/fixture gate"
            );
            continue;
        }
'''
    path.write_text(text[:begin] + replacement + text[end:], encoding="utf-8")
    return True


def repair_unused_codec_constant() -> bool:
    path = ROOT / "trillionnium/crates/trnm-native-execution-v0/src/store.rs"
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    identifier = "AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0"
    definition = f"const {identifier}: u16 = 1;\n"
    if definition in text and text.count(identifier) == 1:
        path.write_text(text.replace(definition, "", 1), encoding="utf-8")
        return True
    return False


def refresh_pins() -> None:
    relative = "tools/temporary_poco_convergence_r5.py"
    helper = ROOT / "tools/.temporary_r26_refresh.py"
    try:
        restore_history_file(relative, helper)
        run(["python3", str(helper.relative_to(ROOT)), "refresh-pins"])
    except RuntimeError as error:
        append(pathlib.Path("/tmp/trnm-r26-refresh-pins.log"), str(error))
        raise
    finally:
        helper.unlink(missing_ok=True)


def commit_if_dirty(message: str) -> bool:
    run(["git", "add", "-A"])
    run(["git", "diff", "--cached", "--check"])
    changed = run(["git", "diff", "--cached", "--name-only"]).stdout.strip()
    if not changed:
        return False
    run(["git", "config", "user.name", "Qian QI"])
    run(
        ["git", "config", "user.email", "102159240+ProfHepta@users.noreply.github.com"]
    )
    run(["git", "commit", "-m", message])
    return True


def direct_repairs() -> None:
    changed = repair_raw_key_boundary()
    changed = repair_unused_codec_constant() or changed
    if not changed:
        return
    run(["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all"])
    refresh_pins()
    run(["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all"])
    commit_if_dirty("fix(poco): close native qualification boundary blockers")


def restore_overlay() -> None:
    restore_history_file("tools/temporary_poco_gap_overlay_r22.py", OVERLAY)
    run(["python3", "-m", "py_compile", str(OVERLAY)])


def overlay_rounds() -> int:
    restore_overlay()
    log = pathlib.Path("/tmp/trnm-r26-overlay-rounds.log")
    log.write_text("", encoding="utf-8")
    applied = 0
    for round_number in range(1, 4):
        head = run(["git", "rev-parse", "HEAD"]).stdout.strip()
        append(log, f"round={round_number} head={head}")
        result = run(["python3", str(OVERLAY), str(ROOT)], check=False)
        append(log, result.stdout)
        if result.returncode == 4:
            append(log, f"round={round_number} admissible_improvement=false")
            break
        if result.returncode != 0:
            raise RuntimeError(
                f"overlay search failed in round {round_number}\n{result.stdout[-40000:]}"
            )
        staged = run(["git", "diff", "--cached", "--name-only"]).stdout.strip()
        unstaged = run(["git", "diff", "--name-only"]).stdout.strip()
        if not staged and not unstaged:
            append(log, f"round={round_number} no_changes=true")
            break
        run(["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all"])
        refresh_pins()
        run(["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all"])
        commit_if_dirty(
            f"fix(poco): integrate admissible repository closure round {round_number}"
        )
        run(["python3", "scripts/ci/check_native_consensus_only.py"])
        check_env = os.environ.copy()
        check_env["CARGO_TARGET_DIR"] = f"/tmp/trnm-r26-overlay-check-{round_number}"
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
            env=check_env,
        )
        applied += 1
    pathlib.Path("/tmp/trnm-r26-overlay-applied-count.txt").write_text(
        str(applied) + "\n", encoding="ascii"
    )
    return applied


def remove_temporary_controllers() -> None:
    for relative in TEMPORARY_EXACT:
        path = ROOT / relative
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists() or path.is_symlink():
            path.unlink()
    tools = ROOT / "tools"
    if tools.is_dir():
        for path in tools.glob("temporary_poco_*"):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()


def prepare_immutable_candidate() -> tuple[str, str]:
    direct_repairs()
    overlay_rounds()
    remove_temporary_controllers()
    run(["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all"])
    refresh_pins()
    run(["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all"])
    commit_if_dirty("chore(poco): publish fully qualified native-only product tree")
    commit = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    tree = run(["git", "rev-parse", "HEAD^{tree}"]).stdout.strip()
    status = run(["git", "status", "--porcelain", "--untracked-files=all"]).stdout.strip()
    if status:
        raise RuntimeError(f"source tree dirty before immutable qualification\n{status}")
    shutil.rmtree(FINAL, ignore_errors=True)
    run(["git", "worktree", "add", "--detach", str(FINAL), commit])
    if run(["git", "rev-parse", "HEAD"], cwd=FINAL).stdout.strip() != commit:
        raise RuntimeError("immutable candidate commit mismatch")
    if run(["git", "rev-parse", "HEAD^{tree}"], cwd=FINAL).stdout.strip() != tree:
        raise RuntimeError("immutable candidate tree mismatch")
    pathlib.Path("/tmp/trnm-r26-final-commit.txt").write_text(
        commit + "\n", encoding="ascii"
    )
    pathlib.Path("/tmp/trnm-r26-final-tree.txt").write_text(
        tree + "\n", encoding="ascii"
    )
    return commit, tree


def convergence_paths() -> list[pathlib.Path]:
    patterns = (
        "*technical*convergence*.py",
        "*technical*convergence*.sh",
        "*documentation*integrity*.py",
        "*documentation*integrity*.sh",
        "*module*coverage*.py",
        "*module*coverage*.sh",
    )
    result: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()
    for pattern in patterns:
        for path in sorted((FINAL / "scripts/ci").glob(pattern)):
            if path.is_file() and path not in seen:
                seen.add(path)
                result.append(path)
    return result


def marker_classification() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    repository: list[dict[str, Any]] = []
    external: list[dict[str, Any]] = []
    for relative in CANONICAL_FILES:
        path = FINAL / relative
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            markers = sorted(set(match.group(0) for match in MARKER_RE.finditer(line)))
            if not markers:
                continue
            context = "\n".join(lines[max(0, index - 10):min(len(lines), index + 11)])
            lowered = context.casefold()
            ids = sorted(identifier for identifier in EXTERNAL_IDS if identifier in context)
            external_basis = sorted(term for term in EXTERNAL_TERMS if term in lowered)
            repository_basis = sorted(term for term in REPOSITORY_TERMS if term in lowered)
            row = {
                "path": relative,
                "line": index + 1,
                "markers": markers,
                "text": line.strip()[:1400],
            }
            if repository_basis:
                row["classification"] = "repository"
                row["basis"] = repository_basis
                repository.append(row)
            elif ids or external_basis:
                row["classification"] = "external"
                row["basis"] = ids + external_basis
                external.append(row)
            else:
                row["classification"] = "repository-unknown"
                row["basis"] = ["no authenticated external dependency found"]
                repository.append(row)
    return repository, external


def parse_json_objects(text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    values = []
    for index, character in enumerate(text):
        if character not in "[{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            values.append(value)
    return values


def exact_gap_inventory(commit: str, tree: str) -> dict[str, Any]:
    repository_markers, external_markers = marker_classification()
    commands = []
    parsed = []
    failed = []
    for path in convergence_paths():
        relative = path.relative_to(FINAL).as_posix()
        command = ["python3", relative] if path.suffix == ".py" else ["bash", relative]
        result = run(command, cwd=FINAL, check=False)
        row = {
            "path": relative,
            "command": command,
            "returncode": result.returncode,
            "output": result.stdout,
        }
        commands.append(row)
        parsed.extend(parse_json_objects(result.stdout))
        if result.returncode != 0:
            failed.append(relative)

    source_regression_count = 0
    independent_vector_count: int | None = None
    operation_catalog_complete: bool | None = None
    operation_open_count: int | None = None
    for value in parsed:
        count = value.get("source_regression_case_count")
        if isinstance(count, int) and not isinstance(count, bool):
            source_regression_count = max(source_regression_count, count)
        catalog = value.get("operation_catalog")
        if isinstance(catalog, dict):
            count = catalog.get("source_regression_case_count")
            if isinstance(count, int) and not isinstance(count, bool):
                source_regression_count = max(source_regression_count, count)
            count = catalog.get("independent_golden_vector_count")
            if isinstance(count, int) and not isinstance(count, bool):
                independent_vector_count = count
            complete = catalog.get("operation_catalog_complete")
            if isinstance(complete, bool):
                operation_catalog_complete = complete
            opened = catalog.get("operations_with_open_requirements")
            if isinstance(opened, int) and not isinstance(opened, bool):
                operation_open_count = opened
        count = value.get("independent_golden_vector_count")
        if isinstance(count, int) and not isinstance(count, bool):
            independent_vector_count = count

    catalog_external_only = (
        operation_catalog_complete is False
        and source_regression_count > 0
        and independent_vector_count == 0
    )
    catalog_repository_gap = operation_catalog_complete is False and not catalog_external_only
    if catalog_external_only:
        external_markers.append(
            {
                "path": "convergence-reports",
                "line": 0,
                "markers": ["independent-golden-acceptance-open"],
                "text": "source regression cases exist; independent golden acceptance is absent",
                "classification": "external",
                "basis": [
                    f"source_regression_case_count={source_regression_count}",
                    "independent_golden_vector_count=0",
                ],
            }
        )

    repository_gap_count = (
        len(repository_markers) + len(failed) + int(catalog_repository_gap)
    )
    report = {
        "schema": "trnm-poco-exact-gap-inventory-r26-v1",
        "source_commit": commit,
        "source_tree": tree,
        "repository_gap_count": repository_gap_count,
        "repository_markers": repository_markers,
        "external_markers": external_markers,
        "external_blocker_ids": list(EXTERNAL_IDS),
        "failed_convergence_commands": failed,
        "source_regression_case_count": source_regression_count,
        "independent_golden_vector_count": independent_vector_count,
        "operation_catalog_complete": operation_catalog_complete,
        "operations_with_open_requirements": operation_open_count,
        "operation_catalog_external_only": catalog_external_only,
        "operation_catalog_repository_gap": catalog_repository_gap,
        "commands": commands,
    }
    pathlib.Path("/tmp/trnm-r26-gap-inventory.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summary = [
        f"source_commit={commit}",
        f"source_tree={tree}",
        f"repository_gap_count={repository_gap_count}",
        f"repository_marker_count={len(repository_markers)}",
        f"failed_convergence_command_count={len(failed)}",
        f"operation_catalog_repository_gap={str(catalog_repository_gap).lower()}",
        f"external_blocker_count={len(EXTERNAL_IDS)}",
    ]
    for row in repository_markers:
        summary.append(f"REPOSITORY {row['path']}:{row['line']} {row['text']}")
    for row in external_markers:
        summary.append(f"EXTERNAL {row['path']}:{row['line']} {row['text']}")
    pathlib.Path("/tmp/trnm-r26-gap-summary.txt").write_text(
        "\n".join(summary) + "\n", encoding="utf-8"
    )
    if repository_gap_count != 0:
        raise RuntimeError(
            "repository-owned gap inventory is nonzero\n"
            + pathlib.Path("/tmp/trnm-r26-gap-summary.txt").read_text(encoding="utf-8")
        )
    return report


def truth_gates() -> None:
    commands = (
        (["python3", "-m", "compileall", "-q", "scripts", "tools", "formal", "conformance"], None),
        (["python3", "scripts/ci/check_native_consensus_only.py"], "/tmp/trnm-r26-native-only.json"),
        (["bash", "scripts/ci/check_canonical_development_plan.sh"], "/tmp/trnm-r26-canonical-plan.log"),
        (["bash", "scripts/ci/check_poco_bft_mainline_truth.sh"], "/tmp/trnm-r26-mainline.log"),
        (["python3", "scripts/ci/check_repository_truth_v1.py"], "/tmp/trnm-r26-repository-truth.json"),
        (["python3", "scripts/ci/check_required_protocol_contract_v1.py"], "/tmp/trnm-r26-protocol-contract.json"),
    )
    for command, log in commands:
        run(command, cwd=FINAL, log=pathlib.Path(log) if log else None)
    run(
        ["cargo", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"],
        cwd=FINAL,
    )
    if run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=FINAL).stdout.strip():
        raise RuntimeError("truth gates dirtied immutable candidate")


def compile_all() -> None:
    shutil.rmtree(TARGET, ignore_errors=True)
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(TARGET)
    run(
        [
            "cargo", "check", "--manifest-path", "trillionnium/Cargo.toml",
            "--workspace", "--all-targets", "--locked", "--offline", "-j", "1",
        ],
        cwd=FINAL,
        env=env,
        log=pathlib.Path("/tmp/trnm-r26-workspace-check.log"),
    )
    run(
        [
            "cargo", "check", "--manifest-path", "contracts/Cargo.toml",
            "--workspace", "--all-targets", "--locked", "--offline", "-j", "1",
        ],
        cwd=FINAL,
        env=env,
        log=pathlib.Path("/tmp/trnm-r26-contract-check.log"),
    )


def targeted_tests() -> None:
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(TARGET)
    run(
        [
            "cargo", "test", "--manifest-path", "trillionnium/Cargo.toml",
            "-p", "trnm-native-execution-v0", "--lib", "--locked", "--offline", "-j", "1",
        ],
        cwd=FINAL,
        env=env,
        log=pathlib.Path("/tmp/trnm-r26-native-execution-test.log"),
    )
    run(
        [
            "cargo", "test", "--manifest-path", "trillionnium/Cargo.toml",
            "-p", "trnm-poco-node", "--test", "raw_key_boundary",
            "--locked", "--offline", "-j", "1",
        ],
        cwd=FINAL,
        env=env,
        log=pathlib.Path("/tmp/trnm-r26-raw-key-test.log"),
    )


def test_all() -> None:
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(TARGET)
    run(
        [
            "cargo", "test", "--manifest-path", "trillionnium/Cargo.toml",
            "--workspace", "--all-targets", "--locked", "--offline",
            "--no-fail-fast", "-j", "1", "--", "--test-threads=1",
        ],
        cwd=FINAL,
        env=env,
        timeout=7200,
        log=pathlib.Path("/tmp/trnm-r26-workspace-test.log"),
    )
    run(
        [
            "cargo", "test", "--manifest-path", "contracts/Cargo.toml",
            "--workspace", "--all-targets", "--locked", "--offline", "-j", "1",
        ],
        cwd=FINAL,
        env=env,
        log=pathlib.Path("/tmp/trnm-r26-contract-test.log"),
    )
    if run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=FINAL).stdout.strip():
        raise RuntimeError("tests dirtied immutable candidate")


def clippy_all() -> None:
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(TARGET)
    run(
        [
            "cargo", "clippy", "--manifest-path", "contracts/Cargo.toml",
            "--workspace", "--all-targets", "--locked", "--offline", "-j", "1",
            "--", "-D", "warnings",
        ],
        cwd=FINAL,
        env=env,
        log=pathlib.Path("/tmp/trnm-r26-contract-clippy.log"),
    )
    log = pathlib.Path("/tmp/trnm-r26-boundary-clippy.log")
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
        append(log, f"=== package={package} rc={result.returncode} ===\n{result.stdout}")
        if result.returncode != 0:
            raise RuntimeError(
                f"strict clippy failed for {package}\n{result.stdout[-40000:]}"
            )
    if run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=FINAL).stdout.strip():
        raise RuntimeError("clippy dirtied immutable candidate")


def publish(commit: str, tree: str) -> None:
    if run(["git", "rev-parse", "HEAD"], cwd=FINAL).stdout.strip() != commit:
        raise RuntimeError("candidate commit changed before publication")
    if run(["git", "rev-parse", "HEAD^{tree}"], cwd=FINAL).stdout.strip() != tree:
        raise RuntimeError("candidate tree changed before publication")
    truth_gates()
    run(["git", "push", "origin", f"{commit}:refs/heads/{BRANCH}"])


def required_inputs(text: str) -> list[str]:
    result = []
    for match in re.finditer(r"(?m)^\s{6}([A-Za-z0-9_-]+):\s*$", text):
        name = match.group(1)
        tail = text[match.end():match.end() + 800]
        if re.search(r"(?m)^\s{8}required:\s*true\s*$", tail):
            result.append(name)
    return result


def request_reviews(commit: str) -> dict[str, Any]:
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
        if review.get("state") == "APPROVED" and review.get("commit_id") == commit
    ]
    report = {
        "source_commit": commit,
        "exact_head_approvals": exact,
        "request_returncode": request.returncode,
        "request_output": request.stdout[-4000:],
    }
    pathlib.Path("/tmp/trnm-r26-review.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def dispatch_external(commit: str, tree: str) -> list[dict[str, Any]]:
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
    rows = []
    for path in sorted((FINAL / ".github/workflows").glob("*.y*ml")):
        relative = path.relative_to(FINAL).as_posix()
        text = path.read_text(encoding="utf-8")
        lowered = (relative + "\n" + text[:7000]).casefold()
        if "workflow_dispatch" not in text:
            continue
        ids = [identifier for identifier in EXTERNAL_IDS if identifier in text]
        if not ids and not any(term in lowered for term in DISPATCH_INCLUDE):
            continue
        if any(term in lowered for term in DISPATCH_EXCLUDE):
            rows.append(
                {
                    "workflow": relative,
                    "dispatched": False,
                    "reason": "excluded-mutating-or-admin-workflow",
                    "external_ids": ids,
                }
            )
            continue
        required = required_inputs(text)
        unknown = [name for name in required if name not in values]
        if unknown:
            rows.append(
                {
                    "workflow": relative,
                    "dispatched": False,
                    "reason": "unknown-required-input",
                    "inputs": unknown,
                    "external_ids": ids,
                }
            )
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
                "output": result.stdout[-4000:],
                "inputs": inputs,
                "external_ids": ids,
            }
        )
    pathlib.Path("/tmp/trnm-r26-dispatch.json").write_text(
        json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return rows


def wait_external(rows: list[dict[str, Any]], commit: str) -> list[dict[str, Any]]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    results = []
    global_deadline = time.monotonic() + 5400
    for row in rows:
        if not row.get("dispatched"):
            continue
        encoded = urllib.parse.quote(str(row["workflow_file"]), safe="")
        run_id = None
        while time.monotonic() < global_deadline:
            payload = gh_json(
                f"repos/{REPOSITORY}/actions/workflows/{encoded}/runs"
                f"?branch={urllib.parse.quote(BRANCH, safe='')}&event=workflow_dispatch&per_page=20"
            )
            for candidate in payload.get("workflow_runs", []):
                if candidate.get("head_sha") == commit:
                    run_id = int(candidate["id"])
                    break
            if run_id is not None:
                break
            time.sleep(10)
        terminal = None
        if run_id is not None:
            while time.monotonic() < global_deadline:
                terminal = gh_json(f"repos/{REPOSITORY}/actions/runs/{run_id}")
                if terminal.get("status") == "completed":
                    break
                time.sleep(15)
            destination = ARTIFACTS / str(run_id)
            destination.mkdir(parents=True, exist_ok=True)
            download = run(
                ["gh", "run", "download", str(run_id), "--repo", REPOSITORY,
                 "--dir", str(destination)],
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
                "download_returncode": download.returncode if download else None,
                "download_output": download.stdout[-4000:] if download else None,
            }
        )
    pathlib.Path("/tmp/trnm-r26-external-runs.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return results


def external_gate(commit: str, tree: str) -> subprocess.CompletedProcess[str]:
    run(["python3", "scripts/ci/test_external_evidence_v1.py"], cwd=FINAL)
    result = run(
        [
            "python3", "scripts/ci/check_external_evidence_v1.py", "--require-all",
            "--source-commit", commit,
            "--source-tree", tree,
            "--output", "/tmp/trnm-r26-external-evidence.json",
        ],
        cwd=FINAL,
        check=False,
    )
    pathlib.Path("/tmp/trnm-r26-external-evidence.log").write_text(
        result.stdout, encoding="utf-8", errors="replace"
    )
    pathlib.Path("/tmp/trnm-r26-external-status.txt").write_text(
        f"returncode={result.returncode}\n", encoding="ascii"
    )
    if result.returncode == 2 and "external evidence gate remains open" not in result.stdout:
        raise RuntimeError(
            "external evidence checker returned 2 without the expected fail-closed message"
        )
    if result.returncode not in (0, 2):
        raise RuntimeError(
            f"unexpected external evidence checker exit {result.returncode}\n{result.stdout}"
        )
    return result


def post_comment(
    commit: str,
    tree: str,
    gaps: dict[str, Any],
    reviews: dict[str, Any],
    gate: subprocess.CompletedProcess[str],
) -> None:
    dispatch = json.loads(pathlib.Path("/tmp/trnm-r26-dispatch.json").read_text(encoding="utf-8"))
    runs = json.loads(pathlib.Path("/tmp/trnm-r26-external-runs.json").read_text(encoding="utf-8"))
    lines = [
        "### PoCO R26 immutable full qualification",
        "",
        f"- qualified product commit: `{commit}`",
        f"- qualified product tree: `{tree}`",
        f"- repository-owned gap count: `{gaps['repository_gap_count']}`",
        f"- exact-head independent approvals: `{len(reviews['exact_head_approvals'])}`",
        f"- external workflows dispatched: `{sum(1 for row in dispatch if row.get('dispatched'))}`",
        f"- completed exact-head external runs: `{sum(1 for row in runs if row.get('status') == 'completed')}`",
        f"- external require-all exit: `{gate.returncode}`",
        "",
        "The same immutable commit passed native-only truth, canonical plan, repository truth, protocol contract, all-target compilation, targeted native/raw-key tests, full workspace/contracts regression, and strict production-boundary Clippy before publication.",
        "",
        "No approval, signature, HSM result, audit result, power-loss result, multihost result, campaign result, fuzz result, or soak result was synthesized.",
    ]
    body = "\n".join(lines) + "\n"
    pathlib.Path("/tmp/trnm-r26-pr-comment.md").write_text(body, encoding="utf-8")
    run(
        ["gh", "pr", "comment", str(PR_NUMBER), "--repo", REPOSITORY,
         "--body-file", "/tmp/trnm-r26-pr-comment.md"],
        check=False,
    )


def main() -> int:
    event_head = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    if os.environ.get("GITHUB_SHA") and event_head != os.environ["GITHUB_SHA"]:
        raise RuntimeError("event/source identity mismatch before qualification")
    commit, tree = prepare_immutable_candidate()
    truth_gates()
    gaps = exact_gap_inventory(commit, tree)
    compile_all()
    targeted_tests()
    test_all()
    clippy_all()
    publish(commit, tree)
    reviews = request_reviews(commit)
    dispatched = dispatch_external(commit, tree)
    wait_external(dispatched, commit)
    gate = external_gate(commit, tree)
    post_comment(commit, tree, gaps, reviews, gate)
    return gate.returncode


if __name__ == "__main__":
    raise SystemExit(main())
