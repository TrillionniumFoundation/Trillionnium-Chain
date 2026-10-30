#!/usr/bin/env python3
"""Retain bounded diagnostics separately from the original CodeQL artifact.

This collector copies observations; it neither decides scan success nor changes
the original query, phase budget, source gate or security verdict. Log samples
are tails of retained files, not a claim to contain a complete process stream.
"""
from __future__ import annotations

import argparse
import collections
import errno
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

SCHEMA = "pon-pinned-codeql-bounded-metadata-v1"
SARIF_SCHEMA = "pon-pinned-codeql-bounded-sarif-v1"
FULL_FILE_LIMIT = 2 * 1024 * 1024
SARIF_FILE_LIMIT = 128 * 1024 * 1024
SARIF_ARTIFACT_LIMIT = 136 * 1024 * 1024
JSON_TOTAL_LIMIT = 16 * 1024 * 1024
TAIL_LIMIT = 128 * 1024
TAIL_TOTAL_LIMIT = 8 * 1024 * 1024
MANIFEST_LIMIT = 1024 * 1024
ARTIFACT_LIMIT = 32 * 1024 * 1024
READ_SECONDS = 30
PHASES = ("version", "packs", "queries", "project-toolchain", "extractor-options",
          "extractor-toolchain", "create", "analyze")
JSON_FILES = (
    "source-checkout.json", "source-final.json", "analysis/result.json",
    "analysis/source-before.json", "analysis/source-after.json",
    *(f"analysis/{phase}.execution.json" for phase in PHASES),
    "analysis/queries-before.json", "analysis/queries-after.json",
    "analysis/semantic-extraction.json",
    "analysis/cpp-scope/build/context.json",
    "analysis/cpp-source-copy-before.json", "analysis/cpp-source-copy-after.json",
)
SARIF_FILES = ("analysis/analysis.sarif", "analysis/result.json",
               "analysis/source-before.json", "analysis/source-after.json")
LOG_FILES = (
    "runner.log", "reader-controls.log", "metadata-reader-controls.log",
    "rust-toolchain.log", "rust-extractor-toolchain.log",
    *(f"analysis/{phase}.{stream}.log" for phase in PHASES for stream in ("stdout", "stderr")),
    *(f"analysis/cpp-scope/build/{phase}.{stream}.log"
      for phase in ("compiler-version", "cargo-metadata", "kernel", "sqlite")
      for stream in ("stdout", "stderr")),
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def fingerprint(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
            metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def directory(path):
    """Open each absolute directory component without following links."""
    require(path.is_absolute() and ".." not in path.parts, "absolute directory without traversal required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def child_file(root, relative):
    parts = PurePosixPath(relative).parts
    require(parts and not PurePosixPath(relative).is_absolute() and ".." not in parts,
            "fixed relative diagnostic path required")
    descriptor = os.dup(root)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=descriptor)
    finally:
        os.close(descriptor)


def write_file(root, relative, data):
    parts = PurePosixPath(relative).parts
    descriptor = os.dup(root)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        file = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=descriptor)
        with os.fdopen(file, "wb") as stream:
            stream.write(data)
    finally:
        os.close(descriptor)


def strict_json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON member")
            value[key] = item
        return value

    def number(text):
        value = float(text)
        require(math.isfinite(value), "nonfinite JSON number")
        return value

    json.loads(data, object_pairs_hook=pairs, parse_float=number,
               parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def observe(root, relative, *, tail, remaining, deadline, full_file_limit=None):
    full_file_limit = FULL_FILE_LIMIT if full_file_limit is None else full_file_limit
    row = {"source_path": relative, "representation": "tail_of_retained_file" if tail else "original_json_bytes"}
    if time.monotonic() >= deadline:
        return {**row, "status": "read_deadline_exceeded"}, None
    try:
        descriptor = child_file(root, relative)
    except OSError as error:
        return {**row, "status": "missing" if error.errno == errno.ENOENT else "unsafe_or_unreadable",
                "errno": error.errno}, None
    try:
        before = os.fstat(descriptor)
        row["retained_file_bytes_observed"] = before.st_size
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            return {**row, "status": "not_single_link_regular_file"}, None
        if not tail and before.st_size > full_file_limit:
            return {**row, "status": "file_size_limit", "file_size_limit": full_file_limit}, None
        count = min(before.st_size, TAIL_LIMIT) if tail else before.st_size
        if count > remaining:
            return {**row, "status": "aggregate_size_limit", "remaining_category_bytes": remaining}, None
        start = before.st_size - count if tail else 0
        data = bytearray()
        while len(data) < count:
            if time.monotonic() >= deadline:
                return {**row, "status": "read_deadline_exceeded"}, None
            block = os.pread(descriptor, min(65536, count - len(data)), start + len(data))
            if not block:
                return {**row, "status": "changed_or_short_read"}, None
            data.extend(block)
        after = os.fstat(descriptor)
        if identity(before) != identity(after):
            return {**row, "status": "changed_during_read"}, None
        data = bytes(data)
        row.update(status="copied", byte_start=start, byte_end_exclusive=start + len(data),
                   sampled_bytes=fingerprint(data), covers_retained_file=(start == 0),
                   complete_process_stream_claim=False)
        if not tail:
            try:
                strict_json(data)
                row["json_syntax_valid"] = True
            except (ValueError, TypeError, RecursionError, UnicodeError):
                row["json_syntax_valid"] = False
        return row, data
    except OSError as error:
        return {**row, "status": "file_read_error", "errno": error.errno}, None
    finally:
        os.close(descriptor)


def collect(source, output, expected_head, language, run_id, run_attempt, *, sarif_only=False):
    require(re.fullmatch(r"[0-9a-f]{40}", expected_head) is not None, "full expected source SHA required")
    require(language in ("actions", "python", "rust", "cpp"), "known analysis language required")
    require(type(run_id) is int and type(run_attempt) is int and 0 < run_id < 2**64
            and 0 < run_attempt < 2**64, "positive bounded run identity required")
    require(source.is_absolute() and output.is_absolute() and ".." not in source.parts
            and ".." not in output.parts and not output.is_relative_to(source)
            and not source.is_relative_to(output), "separate absolute diagnostic directories required")
    require(type(sarif_only) is bool, "explicit artifact profile required")
    json_files = SARIF_FILES if sarif_only else JSON_FILES
    log_files = () if sarif_only else LOG_FILES
    schema = SARIF_SCHEMA if sarif_only else SCHEMA
    json_budget = SARIF_FILE_LIMIT + 3 * FULL_FILE_LIMIT if sarif_only else JSON_TOTAL_LIMIT
    artifact_limit = SARIF_ARTIFACT_LIMIT if sarif_only else ARTIFACT_LIMIT
    require(len(set(json_files + log_files)) == len(json_files + log_files), "unique fixed diagnostic inventory")
    parent = directory(output.parent)
    try:
        os.mkdir(output.name, 0o700, dir_fd=parent)
        destination = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=parent)
    finally:
        os.close(parent)
    root = None
    root_error = None
    try:
        try:
            root = directory(source)
        except OSError as error:
            root_error = {"status": "input_root_unavailable", "errno": error.errno}
        deadline = time.monotonic() + READ_SECONDS
        rows = []
        totals = {"json": 0, "tails": 0}
        for tail, names, budget, category in ((False, json_files, json_budget, "json"),
                                             (True, log_files, TAIL_TOTAL_LIMIT, "tails")):
            for relative in names:
                if root is None:
                    row, data = {"source_path": relative, "representation": "tail_of_retained_file" if tail else "original_json_bytes",
                                 **root_error}, None
                else:
                    limit = SARIF_FILE_LIMIT if relative == "analysis/analysis.sarif" else FULL_FILE_LIMIT
                    row, data = observe(root, relative, tail=tail, remaining=budget - totals[category],
                                        deadline=deadline, full_file_limit=limit)
                if data is not None:
                    member = ("tails/" + relative + ".tail") if tail else ("raw/" + relative)
                    write_file(destination, member, data)
                    row["artifact_member"] = member
                    totals[category] += len(data)
                rows.append(row)
        result = {"schema": schema, "requested_source": {"expected_head": expected_head, "language": language,
                  "run_id": run_id, "run_attempt": run_attempt}, "input_root": str(source),
                  "inventory_collected": True, "analysis_outcome_inferred": False,
                  "official_security_gate_qualified": False, "production_qualified": False,
                  "scope": "Fixed raw diagnostic inventory only. Missing, refused or oversized files remain explicit. Tails describe retained file bytes; phase JSON retains any upstream stream truncation. No complete process stream, scan coverage, finding count or security verdict is inferred.",
                  "limits": {"json_file_bytes": FULL_FILE_LIMIT, "json_total_bytes": json_budget,
                             "sarif_file_bytes": SARIF_FILE_LIMIT if sarif_only else None,
                             "log_tail_bytes": TAIL_LIMIT, "log_tail_total_bytes": TAIL_TOTAL_LIMIT,
                             "manifest_bytes": MANIFEST_LIMIT, "artifact_bytes": artifact_limit,
                             "cooperative_read_seconds": READ_SECONDS},
                  "payload_bytes": totals, "statuses": dict(collections.Counter(row["status"] for row in rows)),
                  "files": rows}
        encoded = (json.dumps(result, indent=2, allow_nan=False) + "\n").encode()
        require(len(encoded) <= MANIFEST_LIMIT and sum(totals.values()) + len(encoded) < artifact_limit,
                "bounded metadata artifact limit exceeded")
        write_file(destination, "manifest.json", encoded)
        return {"schema": schema, "manifest": fingerprint(encoded), "payload_bytes": totals,
                "statuses": result["statuses"], "analysis_outcome_inferred": False,
                "official_security_gate_qualified": False}
    finally:
        if root is not None:
            os.close(root)
        os.close(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--language", choices=("actions", "python", "rust", "cpp"), required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--sarif-only", action="store_true",
                        help="Retain original bounded SARIF and source observations in a separate artifact; no verdict inference")
    args = parser.parse_args()
    print(json.dumps(collect(args.input, args.output, args.expected_head, args.language, args.run_id,
                             args.run_attempt, sarif_only=args.sarif_only), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
