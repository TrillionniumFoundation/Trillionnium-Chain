#!/usr/bin/env python3
"""Create-only retention of the actual six pressure-campaign executables.

This is a bounded evidence copy after the original native observations, not a
build, executable loader, native qualification or runtime resource owner.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time

SCHEMA = "pon-pure-binary-archive-v1"
NAMES = frozenset({"trnm_crypto_primitives", "trnm_pon_node", "pure_pon_cli",
                   "pon_confirmation_risk_v1", "pure_pon_pressure_v2", "trnm-pon-node"})
TOTAL_LIMIT = 192 * 1024 * 1024
FILE_LIMIT = 64 * 1024 * 1024
MANIFEST_LIMIT = 128 * 1024
READ_SECONDS = 30


def require(value, message):
    if not value:
        raise ValueError(message)


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "ARCHIVE_DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def finite(text):
        value = float(text)
        require(math.isfinite(value), "ARCHIVE_NONFINITE_JSON")
        return value

    def invalid(_):
        raise ValueError("ARCHIVE_NONFINITE_JSON")

    return json.loads(raw, object_pairs_hook=unique, parse_float=finite, parse_constant=invalid)


def directory(path):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.abspath(path), "ARCHIVE_ABSOLUTE_PATH")
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            require(part not in ("", ".", ".."), "ARCHIVE_PATH_COMPONENT")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def identity(value):
    return {"device": value.st_dev, "inode": value.st_ino, "bytes": value.st_size,
            "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns}


def held_file(root, parts):
    require(parts and all(p not in ("", ".", "..") and "/" not in p for p in parts),
            "ARCHIVE_RELATIVE_PATH")
    held = os.dup(root)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=held)
            os.close(held)
            held = child
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                       dir_fd=held)
    finally:
        os.close(held)


def hash_held(descriptor, expected_bytes, deadline, destination=None):
    before = os.fstat(descriptor)
    require(stat.S_ISREG(before.st_mode) and before.st_size == expected_bytes
            and 0 < expected_bytes <= FILE_LIMIT, "ARCHIVE_SOURCE_TYPE_OR_SIZE")
    digest, count = hashlib.sha256(), 0
    while True:
        require(time.monotonic() < deadline, "ARCHIVE_READ_DEADLINE")
        chunk = os.read(descriptor, min(65536, expected_bytes + 1 - count))
        if not chunk:
            break
        count += len(chunk)
        require(count <= expected_bytes, "ARCHIVE_SOURCE_GREW")
        digest.update(chunk)
        if destination is not None:
            view = memoryview(chunk)
            while view:
                written = os.write(destination, view)
                require(written > 0, "ARCHIVE_SHORT_WRITE")
                view = view[written:]
    after = os.fstat(descriptor)
    require(time.monotonic() < deadline and count == expected_bytes
            and identity(before) == identity(after), "ARCHIVE_SOURCE_CHANGED_OR_DEADLINE")
    return digest.hexdigest(), identity(before)


def _write_manifest(held, result):
    raw = (json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    require(len(raw) <= MANIFEST_LIMIT, "ARCHIVE_MANIFEST_BOUND")
    fd = os.open("binary-archive-v1.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=held)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def retain(output, target, binaries, expected_head, expected_tree):
    """Archive once; retain failed partial bytes and never substitute a retry."""
    output, target = Path(output), Path(target)
    started, deadline = time.monotonic_ns(), time.monotonic() + READ_SECONDS
    out_fd = directory(output)
    target_fd = archive_fd = None
    result = {"schema": SCHEMA, "expected_head": expected_head, "expected_tree": expected_tree,
              "expected_names": sorted(NAMES), "declared_names": sorted(binaries),
              "file_limit_bytes": FILE_LIMIT, "total_limit_bytes": TOTAL_LIMIT,
              "manifest_limit_bytes": MANIFEST_LIMIT, "read_budget_seconds": READ_SECONDS,
              "started_monotonic_ns": started, "ended_monotonic_ns": None,
              "files": [], "errors": [], "complete": False,
              "physical_authentication": False, "native_execution": False}
    try:
        os.mkdir("retained-binaries", mode=0o700, dir_fd=out_fd)
        archive_fd = os.open("retained-binaries", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                             | os.O_CLOEXEC, dir_fd=out_fd)
        target_fd = directory(target)
        declared_names = set(binaries)
        if declared_names != NAMES:
            result["errors"].append("ValueError: ARCHIVE_EXACT_SIX_EXECUTABLES_REQUIRED")
        # A failed build can still supply useful original bytes. Retain only
        # fixed-name members; missing or unknown names keep the archive failed.
        retained_names = declared_names & NAMES
        require(all(type(binaries[name]["bytes"]) is int
                    and 0 < binaries[name]["bytes"] <= FILE_LIMIT for name in retained_names)
                and sum(binaries[name]["bytes"] for name in retained_names) <= TOTAL_LIMIT,
                "ARCHIVE_DECLARED_BYTE_BOUND")
        for name in sorted(retained_names):
            item = binaries[name]
            row = {"name": name, "source_path": item["path"], "expected_bytes": item["bytes"],
                   "expected_sha256": item["sha256"], "retained_path": "retained-binaries/" + name,
                   "copied_bytes": None, "sha256": None, "source_identity": None,
                   "complete": False, "error": None}
            source = destination = None
            try:
                source_path = Path(item["path"])
                require(source_path.is_absolute() and str(source_path) == os.path.abspath(source_path),
                        "ARCHIVE_SOURCE_PATH")
                parts = source_path.relative_to(target).parts
                source = held_file(target_fd, parts)
                destination = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                                      | os.O_CLOEXEC, 0o600, dir_fd=archive_fd)
                digest, before = hash_held(source, item["bytes"], deadline, destination)
                row.update(copied_bytes=os.fstat(destination).st_size, sha256=digest,
                           source_identity=before)
                require(digest == item["sha256"] and row["copied_bytes"] == item["bytes"],
                        "ARCHIVE_SOURCE_DIGEST_MISMATCH")
                # Verify actual retained bytes through a separate descriptor.
                retained = held_file(archive_fd, (name,))
                try:
                    actual, _ = hash_held(retained, item["bytes"], deadline)
                finally:
                    os.close(retained)
                require(actual == digest, "ARCHIVE_RETAINED_DIGEST_MISMATCH")
                row["complete"] = True
            except (OSError, ValueError, KeyError, TypeError) as error:
                row["error"] = type(error).__name__ + ": " + str(error)
                if destination is not None:
                    row["copied_bytes"] = os.fstat(destination).st_size
            finally:
                for fd in (source, destination):
                    if fd is not None:
                        os.close(fd)
            result["files"].append(row)
        result["complete"] = (declared_names == NAMES and not result["errors"]
                              and len(result["files"]) == len(NAMES)
                              and all(r["complete"] for r in result["files"]))
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        result["ended_monotonic_ns"] = time.monotonic_ns()
        for fd in (target_fd, archive_fd):
            if fd is not None:
                os.close(fd)
        try:
            _write_manifest(out_fd, result)
        finally:
            os.close(out_fd)
    return result


def verify(output, binaries, expected_head, expected_tree):
    """Independent bounded readback, usable after artifact extraction."""
    held = directory(output)
    try:
        fd = held_file(held, ("binary-archive-v1.json",))
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_size <= MANIFEST_LIMIT,
                    "ARCHIVE_MANIFEST_TYPE_OR_BOUND")
            raw = os.read(fd, MANIFEST_LIMIT + 1)
            require(len(raw) == before.st_size and raw.endswith(b"\n")
                    and identity(before) == identity(os.fstat(fd)), "ARCHIVE_MANIFEST_INCOMPLETE")
        finally:
            os.close(fd)
        result = strict_json(raw)
        require(result["schema"] == SCHEMA and result["complete"] is True and not result["errors"]
                and result["expected_head"] == expected_head and result["expected_tree"] == expected_tree
                and result["expected_names"] == result["declared_names"] == sorted(NAMES)
                and set(binaries) == NAMES, "ARCHIVE_BINDING_OR_COMPLETION")
        require(result["physical_authentication"] is False and result["native_execution"] is False,
                "ARCHIVE_OBSERVATION_ONLY_AUTHORITY")
        require(all(type(result[k]) is int for k in ("file_limit_bytes", "total_limit_bytes",
                    "manifest_limit_bytes", "read_budget_seconds", "started_monotonic_ns", "ended_monotonic_ns"))
                and 0 <= result["started_monotonic_ns"], "ARCHIVE_INTEGER_BOUNDS")
        require(result["file_limit_bytes"] == FILE_LIMIT and result["total_limit_bytes"] == TOTAL_LIMIT
                and result["manifest_limit_bytes"] == MANIFEST_LIMIT
                and result["read_budget_seconds"] == READ_SECONDS
                and type(result["started_monotonic_ns"]) is int
                and result["started_monotonic_ns"] <= result["ended_monotonic_ns"]
                <= result["started_monotonic_ns"] + READ_SECONDS * 1_000_000_000,
                "ARCHIVE_ORIGINAL_BOUNDS")
        require([r["name"] for r in result["files"]] == sorted(NAMES), "ARCHIVE_COVERAGE")
        require(all(type(b["bytes"]) is int and 0 < b["bytes"] <= FILE_LIMIT for b in binaries.values())
                and sum(b["bytes"] for b in binaries.values()) <= TOTAL_LIMIT, "ARCHIVE_TOTAL_BYTES")
        deadline = time.monotonic() + READ_SECONDS
        for row in result["files"]:
            name, item = row["name"], binaries[row["name"]]
            require(type(row["expected_bytes"]) is int and type(row["copied_bytes"]) is int,
                    "ARCHIVE_INTEGER_BYTE_COUNTS")
            require(row["complete"] is True and row["error"] is None
                    and row["retained_path"] == "retained-binaries/" + name
                    and row["source_path"] == item["path"]
                    and row["expected_bytes"] == row["copied_bytes"] == item["bytes"]
                    and row["expected_sha256"] == row["sha256"] == item["sha256"],
                    "ARCHIVE_BINARY_ASSOCIATION")
            fd = held_file(held, ("retained-binaries", name))
            try:
                digest, _ = hash_held(fd, item["bytes"], deadline)
            finally:
                os.close(fd)
            require(digest == item["sha256"], "ARCHIVE_RETAINED_DIGEST_MISMATCH")
        return result
    finally:
        os.close(held)
