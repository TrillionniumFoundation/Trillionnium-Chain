#!/usr/bin/env python3
"""Regression guard: retired consensus/node packages must stay outside active Cargo paths.

This compatibility filename remains only because required workflows invoke it by
path; the test itself is a native-only anti-regression boundary. The former
legacy node, foreign-consensus adapter, and helper must be absent rather than
buildable in an isolated workspace.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SELF = Path(__file__).resolve()
WORKSPACE = ROOT / "trillionnium/Cargo.toml"
NATIVE_ONLY_CHECK = ROOT / "scripts/ci/check_native_consensus_only.py"

RETIRED_PATHS = (
    ROOT / "trillionnium/crates/trnm-node",
    ROOT / "trillionnium/crates/trnm-consensus-app",
    ROOT / "trillionnium/scripts/legacy_node_cargo.sh",
)
SEARCH_ROOTS = (
    ROOT / ".github/workflows",
    ROOT / "scripts",
    ROOT / "trillionnium/scripts",
)
SCRIPT_SUFFIXES = {".sh", ".yml", ".yaml", ".py"}

# Build retired package names from fragments so this guard does not flag its own
# source merely for naming what it protects against.
RETIRED_NODE = "trnm-" + "node"
RETIRED_ADAPTER = "trnm-" + "consensus-app"
FORBIDDEN_CARGO = re.compile(
    rf"\bcargo\s+(?:run|build|test|check|clippy)\b[^\n]*?"
    rf"(?:-p(?:=|\s+)|--package(?:=|\s+))(?:{re.escape(RETIRED_NODE)}|{re.escape(RETIRED_ADAPTER)})\b"
)


def fail(message: str) -> None:
    raise SystemExit(f"native-only cargo boundary failed: {message}")


def main() -> int:
    for retired in RETIRED_PATHS:
        if retired.exists():
            fail(f"retired path reappeared: {retired.relative_to(ROOT)}")

    if not WORKSPACE.is_file():
        fail("workspace manifest is missing")
    if not NATIVE_ONLY_CHECK.is_file():
        fail("native-consensus-only checker is missing")

    workspace_text = WORKSPACE.read_text(encoding="utf-8")
    for package in (RETIRED_NODE, RETIRED_ADAPTER):
        if package in workspace_text:
            fail(f"retired package remains in active workspace: {package}")

    violations: list[str] = []
    for manifest in sorted((ROOT / "trillionnium").rglob("Cargo.toml")):
        if not manifest.is_file():
            continue
        text = manifest.read_text(encoding="utf-8", errors="strict")
        for package in (RETIRED_NODE, RETIRED_ADAPTER):
            if package in text:
                violations.append(
                    f"{manifest.relative_to(ROOT)}: retired Cargo package/path reference {package}"
                )

    for search_root in SEARCH_ROOTS:
        if not search_root.exists():
            continue
        for path in sorted(search_root.rglob("*")):
            if not path.is_file() or path.suffix not in SCRIPT_SUFFIXES:
                continue
            if path.resolve() == SELF:
                continue
            text = path.read_text(encoding="utf-8", errors="strict")
            for match in FORBIDDEN_CARGO.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                violations.append(
                    f"{path.relative_to(ROOT)}:{line}: {match.group(0).strip()}"
                )

    if violations:
        fail("retired active Cargo reference(s):\n" + "\n".join(violations))

    result = subprocess.run(
        [sys.executable, str(NATIVE_ONLY_CHECK)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        fail(f"native-consensus-only checker rejected the tree: {detail}")

    print("native_only_cargo_boundary=ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
