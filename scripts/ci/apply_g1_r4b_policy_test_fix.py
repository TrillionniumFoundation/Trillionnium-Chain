#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

EXPECTED_HEAD = "3a4e2fa066de74025866da94cfe8a9efbfca03aa"
TARGET = "scripts/check_cargo_offline_policy_test.sh"
EXPECTED_BLOB = "a81abe7b19d2fbf75a738f70ea4d2d06c26ac487"


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True, encoding="utf-8"
    ).strip()


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    if git(root, "rev-parse", "HEAD") != EXPECTED_HEAD:
        raise SystemExit("G1-R4B policy-test fix requires the exact R4A base")
    if git(root, "rev-parse", f"HEAD:{TARGET}") != EXPECTED_BLOB:
        raise SystemExit("Cargo offline policy test base blob changed")
    path = root / TARGET
    text = path.read_text(encoding="utf-8")
    old = "jobs=18 cargo_jobs=16 no_cargo_jobs=2"
    new = "jobs=20 cargo_jobs=18 no_cargo_jobs=2"
    if text.count(old) != 1 or new in text:
        raise SystemExit("Cargo offline policy test summary preimage is not exact")
    path.write_text(text.replace(old, new), encoding="utf-8")
    print("g1_r4b_offline_policy_test_expectation=passed")


if __name__ == "__main__":
    main()
