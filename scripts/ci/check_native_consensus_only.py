#!/usr/bin/env python3
"""Reject retired consensus routes and euphemised aliases in the tracked tree."""
from __future__ import annotations
import json
import pathlib
import stat
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
FORBIDDEN = {
    "retired-engine-brand": "co" + "met",
    "retired-engine-family": "tender" + "mint",
    "retired-adapter-protocol": "a" + "bci",
    "retired-adapter-package": "trnm-consensus-" + "app",
    "retired-adapter-module": "trnm_consensus_" + "app",
    "euphemised-engine": "external_" + "bft_engine",
    "euphemised-adapter": "external_" + "application_adapter",
    "retired-feature": "retired-" + "application-path",
}
RETIRED_DIRS = (
    ROOT / "trillionnium" / "crates" / ("trnm-consensus-" + "app"),
    ROOT / "trillionnium" / "crates" / ("trnm-" + "node"),
)


def tracked_paths() -> list[pathlib.Path]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [ROOT / value.decode("utf-8") for value in raw.split(b"\0") if value]


def scan(root: pathlib.Path, paths: list[pathlib.Path]) -> dict[str, object]:
    """Inspect every tracked object; unavailable input is a failed scan.

    Byte matching also covers non-UTF-8 payloads. Symlinks must resolve to a
    tracked regular file inside the checkout; never read an external target.
    This is a source hygiene check, not protection from concurrent same-UID
    filesystem changes or a proof of runtime dependency isolation.
    """
    root = root.resolve(strict=True)
    findings: list[dict[str, object]] = []
    if not paths:
        findings.append({"reason": "empty-tracked-inventory"})
    # Validate the lexical inventory before any content read. Resolving an
    # entry here would silently turn a directory replacement into a new source.
    tracked: set[pathlib.Path] = set()
    admitted_paths: list[pathlib.Path] = []
    for path in paths:
        if (not path.is_absolute() or not path.is_relative_to(root)
                or path == root or ".." in path.parts):
            findings.append({"path": path.as_posix(), "reason": "invalid-tracked-path"})
            continue
        relative = path.relative_to(root).as_posix()
        if path in tracked:
            findings.append({"path": relative, "reason": "duplicate-tracked-path"})
            continue
        tracked.add(path)
        admitted_paths.append(path)
    for directory in RETIRED_DIRS:
        relative = directory.relative_to(ROOT)
        candidate = root / relative
        if candidate.exists() or candidate.is_symlink():
            findings.append({"path": relative.as_posix(), "reason": "retired-directory-present"})
    for path in admitted_paths:
        relative = path.relative_to(root).as_posix()
        for label, token in FORBIDDEN.items():
            if token.casefold() in relative.casefold():
                findings.append({"path": relative, "reason": label, "location": "path"})
        try:
            # A permitted file symlink is different from a replaced parent.
            # Reject both internal aliases and external directory redirection
            # before opening the content. Concurrent replacement stays outside
            # this hygiene check's stated trust boundary.
            if path.parent.resolve(strict=True) != path.parent:
                findings.append({"path": relative, "reason": "noncanonical-tracked-parent"})
                continue
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                # Inspect link bytes too: a safe resolved path must not hide
                # a retired identity in the stored link expression.
                link = path.readlink()
                for label, token in FORBIDDEN.items():
                    if token.casefold() in str(link).casefold():
                        findings.append({"path": relative, "reason": label, "location": "symlink"})
                target = path.resolve(strict=True)
                if not target.is_relative_to(root) or target not in tracked:
                    findings.append({"path": relative, "reason": "untracked-or-external-symlink"})
                    continue
                if not stat.S_ISREG(target.stat().st_mode):
                    findings.append({"path": relative, "reason": "non-regular-symlink-target"})
                    continue
            elif not stat.S_ISREG(metadata.st_mode):
                findings.append({"path": relative, "reason": "non-regular-tracked-file"})
                continue
            data = path.read_bytes()
        except (OSError, RuntimeError) as error:
            findings.append({"path": relative, "reason": "unreadable-tracked-file",
                             "error_type": type(error).__name__})
            continue
        lowered = data.lower()
        for label, token in FORBIDDEN.items():
            needle = token.encode("ascii").lower()
            start = 0
            while True:
                offset = lowered.find(needle, start)
                if offset < 0:
                    break
                findings.append({"path": relative, "reason": label,
                                 "line": data.count(b"\n", 0, offset) + 1})
                start = offset + len(needle)
    return {
        "schema": "trnm-native-consensus-only-check-v2",
        "tracked_files": len(paths),
        "findings": findings,
        "result": "PASS" if not findings else "FAIL",
    }


def main() -> int:
    try:
        result = scan(ROOT, tracked_paths())
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        result = {"schema": "trnm-native-consensus-only-check-v2", "tracked_files": 0,
                  "findings": [{"reason": "tracked-inventory-unavailable",
                                "error_type": type(error).__name__}], "result": "FAIL"}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["result"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
