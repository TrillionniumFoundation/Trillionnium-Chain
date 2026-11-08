#!/usr/bin/env python3
"""Verify native evidence using only objects in one exact Git commit.

Working-tree files, including ignored logs, cannot satisfy this check. Both the
index and every referenced storage object must be ordinary committed blobs.
This checks evidence preservation, not the truth or security of observations.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

PREFIX = "formal/pon-nakamoto-v1/p3_shared_primitive_qualification/evidence/"
STORES = ("native-v1", "native-v2-base-sync")
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_STORED_BYTES = MAX_FILE_BYTES + 65536


def safe_path(value: str) -> str:
    if not isinstance(value, str) or "\0" in value:
        raise ValueError("invalid evidence path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts or str(path) != value:
        raise ValueError("noncanonical evidence path: " + value)
    return value


def bounded_count(value: int, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid evidence byte/count bound")
    return value


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_commit(root: Path, commit: str, stores=STORES) -> dict:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("expected a full commit SHA")

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=root)

    if git("cat-file", "-t", commit).strip() != b"commit":
        raise ValueError("object is not a commit")
    entries = {}
    for row in git("ls-tree", "-r", "-l", "-z", "--full-tree", commit, "--", PREFIX).split(b"\0"):
        if not row:
            continue
        header, path = row.split(b"\t", 1)
        mode, kind, oid, size = header.decode("ascii").split()
        entries[path.decode("utf-8")] = (mode, kind, oid, size)
    blobs = {}

    def read_blob(path: str) -> bytes:
        if path not in entries:
            raise ValueError("missing committed evidence blob: " + path)
        mode, kind, oid, size_text = entries[path]
        if mode not in ("100644", "100755") or kind != "blob":
            raise ValueError("nonordinary committed evidence blob: " + path)
        size = bounded_count(int(size_text), MAX_STORED_BYTES)
        if oid not in blobs:
            data = git("cat-file", "blob", oid)
            if len(data) != size:
                raise ValueError("Git blob size mismatch: " + path)
            blobs[oid] = data
        return blobs[oid]

    reports = []
    for store in stores:
        base = PREFIX + safe_path(store) + "/"
        index_bytes = read_blob(base + "file-index.json")
        index = json.loads(index_bytes)
        if index["schema"] != "p3-native-observation-file-store-v1":
            raise ValueError("unknown evidence index schema")
        seen, storage_paths, compressed = set(), set(), {}
        total = 0
        for item in index["files"]:
            relative = safe_path(item["path"])
            if relative in seen:
                raise ValueError("duplicate logical evidence path")
            seen.add(relative)
            expected = bounded_count(item["bytes"], MAX_FILE_BYTES)
            storage = item["storage"]
            stored_path = safe_path(storage["path"])
            storage_paths.add(stored_path)
            packed = read_blob(base + stored_path)
            if storage["kind"] == "gzip_object":
                packed_size = bounded_count(storage["bytes"], MAX_STORED_BYTES)
                if len(packed) != packed_size or digest(packed) != storage["sha256"]:
                    raise ValueError("compressed evidence size/hash mismatch: " + stored_path)
                compressed[stored_path] = packed_size
                with gzip.GzipFile(fileobj=io.BytesIO(packed)) as handle:
                    data = handle.read(expected + 1)
                    if len(data) != expected or handle.read(1):
                        raise ValueError("compressed evidence expansion mismatch: " + stored_path)
            elif storage["kind"] == "plain":
                data = packed
            else:
                raise ValueError("unknown evidence storage kind")
            if len(data) != expected or digest(data) != item["sha256"]:
                raise ValueError("original evidence size/hash mismatch: " + relative)
            total += len(data)
        actual = {
            "file_count": len(seen),
            "total_uncompressed_bytes": total,
            "binary_object_count": len(compressed),
            "compressed_binary_bytes": sum(compressed.values()),
        }
        for field, value in actual.items():
            if type(index[field]) is not int or index[field] != value:
                raise ValueError("evidence index aggregate mismatch: " + field)
        reports.append({"store": store, **actual, "distinct_storage_files": len(storage_paths),
                        "index_sha256": digest(index_bytes)})
    return {"schema": "p3.evidence-git-closure.v1", "result": "PASS", "commit": commit,
            "tree": git("rev-parse", commit + "^{tree}").decode().strip(), "stores": reports,
            "evidence_read_from": "committed_git_blobs", "working_tree_evidence_used": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    print(json.dumps(verify_commit(root, args.expected_head), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
