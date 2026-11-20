#!/usr/bin/env python3
"""Verify removed preparation records against their reachable Git snapshot.

This command reads local Git objects only. It does not fetch, restore files,
execute archived helpers, or turn historical observations into current tests.
Use --cat with one exact indexed path to retrieve its original bytes on stdout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


class Invalid(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Invalid(message)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key: " + key)
        value[key] = item
    return value


def canonical(path):
    require(isinstance(path, str) and path and path != "." and "\\" not in path
            and not any(ord(c) < 32 for c in path), "invalid archive path")
    parts = PurePosixPath(path)
    require(not parts.is_absolute() and ".." not in parts.parts
            and str(parts) == path and ".git" not in parts.parts,
            "noncanonical archive path: " + path)
    return path


def local_file(root, path):
    path = canonical(path)
    target = root / path
    for part in [target, *target.parents]:
        if part == root:
            break
        require(not part.is_symlink(), "symlink in retained path: " + path)
    require(target.is_file(), "missing retained file: " + path)
    return target


def git(root, *args):
    env = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0",
               GIT_NO_REPLACE_OBJECTS="1")
    result = subprocess.run(["git", "--no-replace-objects", *args], cwd=root,
                            env=env, capture_output=True, check=False)
    require(result.returncode == 0,
            "local Git snapshot unavailable: " + " ".join(args[:3]))
    return result.stdout


def tree_rows(root, commit, paths):
    result = {}
    for raw in git(root, "ls-tree", "-rlz", commit, "--", *paths).split(b"\0"):
        if not raw:
            continue
        metadata, name = raw.split(b"\t", 1)
        mode, kind, oid, size = metadata.decode("ascii").split()
        path = canonical(name.decode("utf-8"))
        require(kind == "blob" and mode in {"100644", "100755"},
                "unsupported archived Git entry: " + path)
        require(path not in result, "duplicate Git tree path")
        result[path] = {"path": path, "mode": mode, "blob": oid, "bytes": int(size)}
    return result


def validate_row(row):
    require(isinstance(row, dict)
            and set(row) == {"path", "mode", "blob", "bytes", "sha256"},
            "invalid archive row fields")
    canonical(row["path"])
    require(row["mode"] in {"100644", "100755"}
            and isinstance(row["blob"], str)
            and re.fullmatch(r"[0-9a-f]{40}", row["blob"])
            and type(row["bytes"]) is int and row["bytes"] >= 0
            and isinstance(row["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]),
            "invalid archive row identity")


def validate(root: Path, index: Path, selected: str | None = None):
    root = root.resolve()
    require(not index.is_symlink(), "symlink archive index")
    data = json.loads(index.read_text(), object_pairs_hook=unique)
    fields = {"schema", "source_commit", "source_tree", "scopes", "file_count",
              "total_bytes", "files", "historical_manifests", "retained_copies",
              "preserved_files", "qualification_changed", "production_activation"}
    require(isinstance(data, dict) and set(data) == fields, "invalid archive index fields")
    require(data["schema"] == "trnm-historical-source-archive-v1", "wrong archive schema")
    require(data["qualification_changed"] is False
            and data["production_activation"] is False, "archive promotes qualification")
    for name in ("source_commit", "source_tree"):
        require(isinstance(data[name], str)
                and re.fullmatch(r"[0-9a-f]{40}", data[name]), "invalid snapshot identity")
    commit = data["source_commit"]
    git(root, "merge-base", "--is-ancestor", commit, "HEAD")
    require(git(root, "rev-parse", commit + "^{tree}").decode().strip()
            == data["source_tree"], "snapshot tree differs")
    scopes = data["scopes"]
    require(isinstance(scopes, list) and scopes
            and scopes == sorted(set(scopes)), "duplicate or unsorted archive scopes")
    for scope in scopes:
        canonical(scope)
        require(not any(scope.startswith(other + "/") for other in scopes if other != scope),
                "overlapping archive scopes")
    require(isinstance(data["files"], list) and data["files"], "empty archive roster")
    actual = tree_rows(root, commit, scopes)
    indexed = {}
    for row in data["files"]:
        validate_row(row)
        name = row["path"]
        require(name not in indexed, "duplicate archive member: " + name)
        require(any(name.startswith(scope + "/") for scope in scopes),
                "member outside declared scopes")
        require(actual.get(name) == {key: row[key] for key in ("path", "mode", "blob", "bytes")},
                "archive member differs from pinned tree: " + name)
        require(not (root / name).exists() and not (root / name).is_symlink(),
                "archived preparation file still in active tree: " + name)
        indexed[name] = row
    require(list(indexed) == sorted(actual), "archive roster omits or reorders pinned files")
    require(type(data["file_count"]) is int and data["file_count"] == len(indexed)
            and type(data["total_bytes"]) is int
            and data["total_bytes"] == sum(row["bytes"] for row in indexed.values()),
            "archive totals differ")
    manifests = data["historical_manifests"]
    require(isinstance(manifests, list) and manifests, "missing historical inventory")
    for row in manifests:
        validate_row(row)
        name = row["path"]
        require(name not in indexed, "duplicate historical inventory path")
        require(tree_rows(root, commit, [name]).get(name)
                == {key: row[key] for key in ("path", "mode", "blob", "bytes")},
                "historical inventory differs from pinned tree")
        indexed[name] = row
    require(selected is None or canonical(selected) in indexed, "path is not indexed")
    payload = None
    cache = {}
    for name, row in indexed.items():
        if row["blob"] not in cache:
            raw = git(root, "cat-file", "blob", row["blob"])
            cache[row["blob"]] = (len(raw), hashlib.sha256(raw).hexdigest())
            if name == selected:
                payload = raw
        elif name == selected:
            payload = git(root, "cat-file", "blob", row["blob"])
        require(cache[row["blob"]] == (row["bytes"], row["sha256"]),
                "archived bytes or SHA-256 differ: " + name)
    require(isinstance(data["retained_copies"], list)
            and isinstance(data["preserved_files"], list), "invalid retained roster")
    seen = set()
    for row in data["retained_copies"]:
        require(isinstance(row, dict) and set(row) == {"path", "archive_path"},
                "invalid retained copy fields")
        name = canonical(row["path"])
        require(name not in seen and row["archive_path"] in indexed,
                "duplicate or unbound retained copy")
        seen.add(name)
        raw = local_file(root, name).read_bytes()
        original = indexed[row["archive_path"]]
        require((len(raw), hashlib.sha256(raw).hexdigest())
                == (original["bytes"], original["sha256"]), "retained summary changed: " + name)
    for row in data["preserved_files"]:
        validate_row(row)
        name = row["path"]
        require(name not in seen, "duplicate preserved path")
        seen.add(name)
        require(tree_rows(root, commit, [name]).get(name)
                == {key: row[key] for key in ("path", "mode", "blob", "bytes")},
                "preserved file differs from pinned tree")
        raw = local_file(root, name).read_bytes()
        require((len(raw), hashlib.sha256(raw).hexdigest()) == (row["bytes"], row["sha256"]),
                "preserved failure or qualification changed: " + name)
        require(raw == git(root, "cat-file", "blob", row["blob"]),
                "preserved bytes differ from original snapshot: " + name)
    report = {"result": "PASS", "archive_files": data["file_count"],
              "archive_bytes": data["total_bytes"], "source_commit": commit,
              "retained_summaries": len(data["retained_copies"]),
              "preserved_files": len(data["preserved_files"]),
              "historical_observations_only": True, "current_native_tests_executed": 0,
              "production_activation": False}
    return report, payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cat", metavar="EXACT_ARCHIVED_PATH")
    args = parser.parse_args()
    try:
        report, payload = validate(args.root, args.manifest, args.cat)
        if args.cat is not None:
            sys.stdout.buffer.write(payload)
        else:
            print(json.dumps(report, sort_keys=True))
        return 0
    except (Invalid, KeyError, TypeError, OSError, UnicodeError, ValueError) as error:
        print("Historical archive check failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
