#!/usr/bin/env python3
"""Narrow Rust-test applicability, not a successful test or release attestation.

All code, contracts, policy, build, unknown, executable and symlink changes run
full Rust validation. Only regular operator/overview prose may be inapplicable.
The other four required baseline jobs are not filtered. No contributor label,
PR title, actor identity or user-provided file list controls this decision.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any

MAX_CHANGED_PATHS = 4096
MAX_DIFF_BYTES = 2 * 1024 * 1024
PROSE_FILES = frozenset({"README.md", "OPERATIONS.md", "SECURITY.md", "PROJECT_BOUNDARY.md"})
SHA = re.compile(r"[0-9a-f]{40}\Z")


class ScopeError(RuntimeError):
    pass


def git(root: Path, *args: str) -> bytes:
    env = {**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"}
    result = subprocess.run(["git", *args], cwd=root, env=env, capture_output=True, timeout=30)
    if result.returncode:
        raise ScopeError(f"git {args[0]} failed; no reduced validation is authorized")
    return result.stdout


def regular_prose(path: str, old_mode: str, new_mode: str) -> bool:
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        return False
    if old_mode not in {"000000", "100644"} or new_mode not in {"000000", "100644"}:
        return False
    parts = PurePosixPath(path).parts
    if ".." in parts or path.startswith("/"):
        return False
    return path in PROSE_FILES or (
        len(parts) >= 3 and parts[:2] == ("docs", "runbooks") and path.endswith(".md")
    )


def parse_diff(raw: bytes) -> list[dict[str, str]]:
    if len(raw) > MAX_DIFF_BYTES:
        raise ScopeError("change inventory exceeds its bound; full validation required")
    fields = raw.split(b"\0")
    if not fields or fields[-1] != b"" or len(fields[:-1]) % 2:
        raise ScopeError("invalid raw Git change inventory")
    if (len(fields) - 1) // 2 > MAX_CHANGED_PATHS:
        raise ScopeError("too many changed paths; full validation required")
    rows = []
    for offset in range(0, len(fields) - 1, 2):
        try:
            header = fields[offset].decode("ascii").split()
            path = fields[offset + 1].decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise ScopeError("undecodable Git change inventory; no reduced validation") from error
        if len(header) != 5 or not header[0].startswith(":") or header[4] not in {"A", "D", "M", "T"}:
            raise ScopeError("unexpected change kind; no reduced validation")
        rows.append({"path": path, "old_mode": header[0][1:], "new_mode": header[1], "status": header[4]})
    return rows


def assess(root: Path, expected_head: str, event: str, base: str | None) -> dict[str, Any]:
    if not SHA.fullmatch(expected_head):
        raise ScopeError("expected head must be an exact commit SHA")
    actual = git(root, "rev-parse", "HEAD").decode().strip()
    if actual != expected_head:
        raise ScopeError("checked-out head differs from requested source")
    if git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ScopeError("reviewed checkout is not clean")
    tree = git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    report: dict[str, Any] = {
        "schema": "trnm-validation-scope-v1", "head": actual, "tree": tree,
        "event": event, "base": base, "merge_base": None,
        "run_rust": True, "scope": "full", "reason": "non-pull-request-requires-full-validation",
        "changes": [], "rust_test_result": "not-run-by-selector", "release_acceptance": False,
    }
    if event not in {"pull_request", "push", "workflow_dispatch"}:
        raise ScopeError("unknown event; no reduced validation")
    if event != "pull_request":
        return report
    if base is None or not SHA.fullmatch(base):
        raise ScopeError("pull request requires an exact base commit")
    resolved = git(root, "rev-parse", f"{base}^{{commit}}").decode().strip()
    if resolved != base:
        raise ScopeError("base is not a commit")
    merge_bases = git(root, "merge-base", "--all", base, actual).decode().splitlines()
    if len(merge_bases) != 1:
        raise ScopeError("ambiguous merge base; no reduced validation")
    # No rename collapsing: moving a source file to *.md retains the source deletion.
    raw = git(root, "diff", "--raw", "--no-abbrev", "--no-renames", "--no-ext-diff", "-z", merge_bases[0], actual, "--")
    changes = parse_diff(raw) if raw else []
    report.update(merge_base=merge_bases[0], changes=changes, reason="code-contract-policy-or-unknown-change")
    if changes and all(regular_prose(row["path"], row["old_mode"], row["new_mode"]) for row in changes):
        report.update(run_rust=False, scope="documentation-only", reason="regular-overview-or-operator-prose-only",
                      rust_test_result="not-applicable-not-a-test-pass")
    elif not changes:
        report["reason"] = "empty-change-inventory-requires-full-validation"
    return report


def output_path(root: Path, raw: str) -> Path:
    path = Path(raw).resolve()
    if path == root or root in path.parents:
        raise ScopeError("reports must not mutate the reviewed checkout")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--base")
    parser.add_argument("--output")
    parser.add_argument("--github-output")
    args = parser.parse_args()
    root = args.root.resolve()
    report = assess(root, args.expected_head, args.event, args.base)
    text = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        output_path(root, args.output).write_text(text, encoding="utf-8")
    if args.github_output:
        with output_path(root, args.github_output).open("a", encoding="utf-8") as stream:
            stream.write(f"run_rust={'true' if report['run_rust'] else 'false'}\n")
    print(text, end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ScopeError, OSError, subprocess.TimeoutExpired) as error:
        print(f"validation scope failed: {error}", file=sys.stderr)
        raise SystemExit(2)
