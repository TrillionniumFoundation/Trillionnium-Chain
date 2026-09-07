#!/usr/bin/env python3
"""Reject every tracked reference to retired consensus engines and adapters."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
FORBIDDEN = {
    "retired-engine-brand": "co" + "met",
    "retired-engine-family": "tender" + "mint",
    "retired-adapter-protocol": "a" + "bci",
    "retired-adapter-package": "trnm-consensus-" + "app",
    "retired-adapter-module": "trnm_consensus_" + "app",
    "retired-adapter-feature": "legacy-consensus-" + "app",
}
RETIRED_DIRS = (
    ROOT / "trillionnium" / "crates" / ("trnm-consensus-" + "app"),
    ROOT / "trillionnium" / "crates" / "trnm-node",
)


def tracked_paths() -> list[pathlib.Path]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [ROOT / item.decode("utf-8") for item in raw.split(b"\0") if item]


def main() -> int:
    findings: list[dict[str, object]] = []
    for directory in RETIRED_DIRS:
        if directory.exists():
            findings.append({"path": str(directory.relative_to(ROOT)), "reason": "retired-directory-present"})
    for path in tracked_paths():
        relative = path.relative_to(ROOT).as_posix()
        lowered_path = relative.casefold()
        for label, token in FORBIDDEN.items():
            if token.casefold() in lowered_path:
                findings.append({"path": relative, "reason": label, "location": "path"})
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        lowered = text.casefold()
        for label, token in FORBIDDEN.items():
            needle = token.casefold()
            start = 0
            while True:
                offset = lowered.find(needle, start)
                if offset < 0:
                    break
                line = text.count("\n", 0, offset) + 1
                findings.append({"path": relative, "reason": label, "line": line})
                start = offset + len(needle)
    result = {
        "schema": "trnm-native-consensus-only-check-v1",
        "tracked_files": len(tracked_paths()),
        "findings": findings,
        "result": "PASS" if not findings else "FAIL",
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if not findings else 2


if __name__ == "__main__":
    raise SystemExit(main())
