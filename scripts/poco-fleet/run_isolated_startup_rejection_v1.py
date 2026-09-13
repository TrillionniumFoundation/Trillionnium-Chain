#!/usr/bin/env python3
"""Prepare and execute one fail-closed isolated startup rejection attempt.

The primary process-1 authority tree is never modified.  This runner copies it
into a fresh private tree without following links, preserves the exact
path/type/mode/length inventory, mutates one or two file contents in place, and
invokes the Rust typed Node-reopen seam.  A successful Node reopen is a hard
failure.  The Rust binary signs and atomically publishes the only accepted
evidence artifact.

This is a standalone authority seam, not permission to enable the complete
eight-fault fleet campaign.  The full campaign must call it only from a typed
stable process-1 RestartCut and must independently prove that the surviving
fleet continued making progress.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
from typing import Any


FAULT_KINDS = frozenset({"stale_snapshot", "rollback_attempt"})
PRIMARY_AUTHORITY_RELATIVE = pathlib.PurePosixPath("runtime-authority-v1")
SAFETY_MUTATION_RELATIVE = pathlib.PurePosixPath(
    "target-safety/safety.sqlite3"
)
MAX_ENTRIES = 4_096
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TREE_BYTES = 2 * 1024 * 1024 * 1024
MAX_CONFIG_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_PROCESS_OUTPUT_BYTES = 256 * 1024
COPY_BUFFER_BYTES = 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(f"PoCO isolated startup rejection failed: {message}")


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def strict_json_bytes(raw: bytes, field: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError(f"{field} contains duplicate key {key!r}")
            value[key] = child
        return value

    try:
        return json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        fail(f"cannot decode {field}: {error}")


def sha256_file(path: pathlib.Path, maximum: int) -> str:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > maximum
    ):
        fail(f"{path} is not one bounded single-link regular file")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if not same_file_identity(metadata, opened, include_times=True):
            fail(f"{path} changed before its pinned read")
        while chunk := os.read(descriptor, COPY_BUFFER_BYTES):
            digest.update(chunk)
        after = os.fstat(descriptor)
        path_after = path.lstat()
        if not same_file_identity(opened, after, include_times=True) or not same_file_identity(
            opened, path_after, include_times=True
        ):
            fail(f"{path} changed during its pinned read")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def same_file_identity(
    left: os.stat_result,
    right: os.stat_result,
    *,
    include_times: bool,
) -> bool:
    same = (
        stat.S_ISREG(left.st_mode)
        and stat.S_ISREG(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and stat.S_IMODE(left.st_mode) == stat.S_IMODE(right.st_mode)
        and left.st_nlink == 1
        and right.st_nlink == 1
    )
    if include_times:
        same = same and left.st_mtime_ns == right.st_mtime_ns and left.st_ctime_ns == right.st_ctime_ns
    return same


def require_canonical_directory(
    path: pathlib.Path,
    field: str,
    *,
    exact_mode: int | None = None,
) -> pathlib.Path:
    unresolved = path.absolute()
    metadata = unresolved.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail(f"{field} is not one real directory")
    resolved = unresolved.resolve(strict=True)
    if resolved != unresolved:
        fail(f"{field} traverses a symbolic link")
    if exact_mode is not None and stat.S_IMODE(metadata.st_mode) != exact_mode:
        fail(f"{field} mode is not {exact_mode:04o}")
    return resolved


def require_regular_file(
    path: pathlib.Path,
    field: str,
    *,
    maximum: int,
    executable: bool = False,
) -> pathlib.Path:
    unresolved = path.absolute()
    metadata = unresolved.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > maximum
        or (executable and not os.access(unresolved, os.X_OK))
    ):
        fail(f"{field} is not one bounded single-link regular file")
    resolved = unresolved.resolve(strict=True)
    if resolved != unresolved:
        fail(f"{field} traverses a symbolic link")
    return resolved


def fsync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclasses.dataclass(frozen=True)
class CopiedFileV1:
    relative: pathlib.PurePosixPath
    source_sha256: str
    target_sha256: str
    bytes: int
    mode: int
    source_device: int
    source_inode: int
    target_device: int
    target_inode: int


def copy_regular_file(
    source: pathlib.Path,
    target: pathlib.Path,
    relative: pathlib.PurePosixPath,
) -> CopiedFileV1:
    source_before = source.lstat()
    if (
        stat.S_ISLNK(source_before.st_mode)
        or not stat.S_ISREG(source_before.st_mode)
        or source_before.st_nlink != 1
        or source_before.st_size <= 0
        or source_before.st_size > MAX_FILE_BYTES
    ):
        fail(f"authority file {relative} is not a bounded single-link regular file")
    source_fd = os.open(
        source,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    target_fd: int | None = None
    try:
        source_opened = os.fstat(source_fd)
        if not same_file_identity(source_before, source_opened, include_times=True):
            fail(f"authority file {relative} changed before copy")
        target_fd = os.open(
            target,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            stat.S_IMODE(source_opened.st_mode),
        )
        os.fchmod(target_fd, stat.S_IMODE(source_opened.st_mode))
        source_digest = hashlib.sha256()
        target_digest = hashlib.sha256()
        copied = 0
        while chunk := os.read(source_fd, COPY_BUFFER_BYTES):
            source_digest.update(chunk)
            view = memoryview(chunk)
            while view:
                count = os.write(target_fd, view)
                if count <= 0:
                    fail(f"short write while copying authority file {relative}")
                target_digest.update(view[:count])
                copied += count
                view = view[count:]
        os.fsync(target_fd)
        source_after = os.fstat(source_fd)
        source_path_after = source.lstat()
        if not same_file_identity(source_opened, source_after, include_times=True) or not same_file_identity(
            source_opened, source_path_after, include_times=True
        ):
            fail(f"authority file {relative} changed during copy")
        target_opened = os.fstat(target_fd)
        if (
            not stat.S_ISREG(target_opened.st_mode)
            or target_opened.st_nlink != 1
            or copied != source_opened.st_size
            or target_opened.st_size != source_opened.st_size
            or stat.S_IMODE(target_opened.st_mode) != stat.S_IMODE(source_opened.st_mode)
            or source_digest.digest() != target_digest.digest()
        ):
            fail(f"authority copy differs at {relative}")
        return CopiedFileV1(
            relative=relative,
            source_sha256=source_digest.hexdigest(),
            target_sha256=target_digest.hexdigest(),
            bytes=copied,
            mode=stat.S_IMODE(source_opened.st_mode),
            source_device=source_opened.st_dev,
            source_inode=source_opened.st_ino,
            target_device=target_opened.st_dev,
            target_inode=target_opened.st_ino,
        )
    finally:
        os.close(source_fd)
        if target_fd is not None:
            os.close(target_fd)


def copy_authority_tree(
    source: pathlib.Path,
    target: pathlib.Path,
) -> list[CopiedFileV1]:
    source = require_canonical_directory(source, "primary authority root", exact_mode=0o700)
    if target.exists() or target.is_symlink():
        fail("isolated authority root already exists")
    os.mkdir(target, 0o700)
    os.chmod(target, 0o700)
    copied: list[CopiedFileV1] = []
    entry_count = 0
    total_bytes = 0

    def recurse(
        source_directory: pathlib.Path,
        target_directory: pathlib.Path,
        relative_directory: pathlib.PurePosixPath,
    ) -> None:
        nonlocal entry_count, total_bytes
        directory_before = source_directory.lstat()
        if stat.S_ISLNK(directory_before.st_mode) or not stat.S_ISDIR(directory_before.st_mode):
            fail(f"authority directory {relative_directory} changed type")
        children = sorted(os.scandir(source_directory), key=lambda entry: os.fsencode(entry.name))
        for child in children:
            entry_count += 1
            if entry_count > MAX_ENTRIES:
                fail("authority tree crosses its entry bound")
            source_child = pathlib.Path(child.path)
            target_child = target_directory / child.name
            child_relative = relative_directory / child.name
            metadata = source_child.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                fail(f"authority tree contains symlink {child_relative}")
            if stat.S_ISDIR(metadata.st_mode):
                mode = stat.S_IMODE(metadata.st_mode)
                os.mkdir(target_child, mode)
                os.chmod(target_child, mode)
                recurse(source_child, target_child, child_relative)
                fsync_directory(target_child)
            elif stat.S_ISREG(metadata.st_mode):
                fact = copy_regular_file(source_child, target_child, child_relative)
                copied.append(fact)
                total_bytes += fact.bytes
                if total_bytes > MAX_TREE_BYTES:
                    fail("authority tree crosses its byte bound")
            else:
                fail(f"authority tree contains unsupported entry {child_relative}")
        directory_after = source_directory.lstat()
        if (
            directory_before.st_dev != directory_after.st_dev
            or directory_before.st_ino != directory_after.st_ino
            or stat.S_IMODE(directory_before.st_mode) != stat.S_IMODE(directory_after.st_mode)
        ):
            fail(f"authority directory {relative_directory} changed during copy")

    recurse(source, target, pathlib.PurePosixPath())
    if not copied:
        fail("authority tree contains no regular file")
    fsync_directory(target)
    return copied


def flip_first_byte(path: pathlib.Path) -> None:
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_FILE_BYTES
    ):
        fail(f"mutation target {path} is not one bounded single-link file")
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if not same_file_identity(before, opened, include_times=True):
            fail(f"mutation target {path} changed before mutation")
        first = os.pread(descriptor, 1, 0)
        if len(first) != 1 or os.pwrite(descriptor, bytes((first[0] ^ 0xFF,)), 0) != 1:
            fail(f"cannot perform exact mutation at {path}")
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_nlink != 1
            or stat.S_IMODE(after.st_mode) != stat.S_IMODE(opened.st_mode)
        ):
            fail(f"mutation changed file shape at {path}")
    finally:
        os.close(descriptor)


def prepare_isolated_mutation(
    primary: pathlib.Path,
    isolated: pathlib.Path,
    fault_kind: str,
) -> tuple[list[CopiedFileV1], tuple[pathlib.PurePosixPath, ...]]:
    if fault_kind not in FAULT_KINDS:
        fail("fault kind is not stale_snapshot or rollback_attempt")
    copied = copy_authority_tree(primary, isolated)
    by_relative = {item.relative: item for item in copied}
    if SAFETY_MUTATION_RELATIVE not in by_relative:
        fail(f"authority tree lacks {SAFETY_MUTATION_RELATIVE}")
    selected = [SAFETY_MUTATION_RELATIVE]
    if fault_kind == "stale_snapshot":
        second = next(
            (
                relative
                for relative in sorted(by_relative, key=lambda value: value.as_posix().encode())
                if relative != SAFETY_MUTATION_RELATIVE
            ),
            None,
        )
        if second is None:
            fail("stale snapshot requires a second independent regular file")
        selected.append(second)
    for relative in selected:
        flip_first_byte(isolated / relative)
    fsync_directory(isolated)
    return copied, tuple(selected)


EXPECTED_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "run_id",
        "validator_id",
        "target_config_sha256",
        "fleet_start_certificate_sha256",
        "fault_kind",
        "changed_file_count",
        "attempt_nonce",
        "node_error_class",
        "node_error_stage",
        "primary_cut_sha256",
        "isolated_snapshot_sha256",
        "isolated_snapshot_inventory_sha256",
        "runtime_journal_sha256",
        "runtime_journal_bytes",
        "process_instance",
        "primary_unchanged",
        "runtime_journal_unchanged",
        "network_started",
        "evidence_sha256",
        "artifact_sha256",
        "artifact_path",
        "fault_campaign_observed",
        "g3_evidence_complete",
        "geo_wan_evidence",
        "production_activation",
    }
)


def validate_result(
    value: Any,
    *,
    fault_kind: str,
    attempt_nonce: str,
    evidence_path: pathlib.Path,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != EXPECTED_RESULT_KEYS:
        fail("Rust attempt result has a non-canonical field set")
    expected_changed = 1 if fault_kind == "rollback_attempt" else 2
    if (
        not isinstance(value["schema_version"], int)
        or isinstance(value["schema_version"], bool)
        or value["schema_version"] != 1
        or value["status"] != "isolated-startup-rejection-authenticated-and-persisted"
        or not isinstance(value["run_id"], str)
        or not value["run_id"].startswith("poco-g3-")
        or len(value["run_id"].encode("utf-8")) > 128
        or value["fault_kind"] != fault_kind
        or not isinstance(value["changed_file_count"], int)
        or isinstance(value["changed_file_count"], bool)
        or value["changed_file_count"] != expected_changed
        or value["attempt_nonce"] != attempt_nonce
        or value["node_error_class"] != "deployed_ordinary_reopen_v0"
        or not isinstance(value["node_error_stage"], str)
        or not value["node_error_stage"]
        or len(value["node_error_stage"].encode("utf-8")) > 128
        or not isinstance(value["process_instance"], int)
        or isinstance(value["process_instance"], bool)
        or value["process_instance"] != 1
        or value["primary_unchanged"] is not True
        or value["runtime_journal_unchanged"] is not True
        or value["network_started"] is not False
        or value["fault_campaign_observed"] is not False
        or value["g3_evidence_complete"] is not False
        or value["geo_wan_evidence"] is not False
        or value["production_activation"] is not False
        or value["artifact_path"] != str(evidence_path)
    ):
        fail("Rust attempt result differs from isolated rejection semantics")
    for field in (
        "validator_id",
        "target_config_sha256",
        "fleet_start_certificate_sha256",
        "primary_cut_sha256",
        "isolated_snapshot_sha256",
        "isolated_snapshot_inventory_sha256",
        "runtime_journal_sha256",
        "evidence_sha256",
        "artifact_sha256",
    ):
        child = value[field]
        if not isinstance(child, str) or len(child) != 64 or any(
            byte not in "0123456789abcdef" for byte in child
        ):
            fail(f"Rust attempt result has invalid {field}")
    if not isinstance(value["runtime_journal_bytes"], int) or isinstance(
        value["runtime_journal_bytes"], bool
    ) or value["runtime_journal_bytes"] <= 0:
        fail("Rust attempt result has invalid runtime journal length")
    if sha256_file(evidence_path, MAX_EVIDENCE_BYTES) != value["artifact_sha256"]:
        fail("published rejection evidence differs from its content address")
    if stat.S_IMODE(evidence_path.lstat().st_mode) != 0o600:
        fail("published rejection evidence mode is not 0600")
    return value


def write_new(path: pathlib.Path, payload: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--private-run-root", type=pathlib.Path, required=True)
    parser.add_argument("--validator-config", type=pathlib.Path, required=True)
    parser.add_argument("--fault-kind", choices=sorted(FAULT_KINDS), required=True)
    parser.add_argument("--attempt-nonce", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if (
        len(args.attempt_nonce) != 64
        or any(byte not in "0123456789abcdef" for byte in args.attempt_nonce)
        or args.attempt_nonce == "0" * 64
    ):
        fail("attempt nonce must be one nonzero lowercase 32-byte hex value")
    if args.timeout_seconds < 1 or args.timeout_seconds > 3_600:
        fail("timeout seconds must be in 1..=3600")
    binary = require_regular_file(
        args.binary, "lab-validator binary", maximum=512 * 1024 * 1024, executable=True
    )
    run_root = require_canonical_directory(
        args.private_run_root, "private run root", exact_mode=0o700
    )
    config = require_regular_file(
        args.validator_config, "validator config", maximum=MAX_CONFIG_BYTES
    )
    try:
        config.relative_to(run_root)
    except ValueError:
        fail("validator config is outside the private run root")
    primary = require_canonical_directory(
        run_root / PRIMARY_AUTHORITY_RELATIVE,
        "primary authority root",
        exact_mode=0o700,
    )
    output = args.output.absolute()
    parent = require_canonical_directory(output.parent, "output parent", exact_mode=0o700)
    if output.parent != parent or output.exists() or output.is_symlink():
        fail("output must be one fresh child of its canonical private parent")
    os.mkdir(output, 0o700)
    os.chmod(output, 0o700)
    fsync_directory(parent)
    isolated = output / "isolated-authority-v1"
    copied, mutated = prepare_isolated_mutation(primary, isolated, args.fault_kind)
    evidence = output / "isolated-startup-rejection.bin"
    command = [
        str(binary),
        "attempt-isolated-startup-rejection",
        str(run_root),
        str(config),
        args.fault_kind,
        str(isolated),
        args.attempt_nonce,
        str(evidence),
    ]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=args.timeout_seconds,
        check=False,
    )
    if len(completed.stdout) > MAX_PROCESS_OUTPUT_BYTES or len(completed.stderr) > MAX_PROCESS_OUTPUT_BYTES:
        fail("lab-validator output crosses its bound")
    write_new(output / "validator.stdout", completed.stdout)
    write_new(output / "validator.stderr", completed.stderr or b"\n")
    if completed.returncode != 0:
        fail(f"typed isolated attempt exited {completed.returncode}")
    result = validate_result(
        strict_json_bytes(completed.stdout, "lab-validator stdout"),
        fault_kind=args.fault_kind,
        attempt_nonce=args.attempt_nonce,
        evidence_path=evidence,
    )
    summary = {
        "schema_version": 1,
        "status": "isolated-startup-rejection-runner-complete",
        "fault_kind": args.fault_kind,
        "attempt_nonce": args.attempt_nonce,
        "copied_file_count": len(copied),
        "copied_file_bytes": sum(item.bytes for item in copied),
        "mutated_files": [value.as_posix() for value in mutated],
        "artifact_sha256": result["artifact_sha256"],
        "node_error_stage": result["node_error_stage"],
        "primary_unchanged": True,
        "runtime_journal_unchanged": True,
        "network_started": False,
        "standalone_runner_wired": True,
        "active_eight_fault_campaign_supported": False,
        "fault_campaign_observed": False,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    write_new(output / "summary.json", canonical_json(summary))
    fsync_directory(output)
    sys.stdout.buffer.write(canonical_json(summary))


if __name__ == "__main__":
    main()
