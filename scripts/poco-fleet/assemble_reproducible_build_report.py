#!/usr/bin/env python3
"""Join two architecture-local reproducible builds into one G3 build report."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import tarfile
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_source_candidate  # noqa: E402


HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 1024 * 1024 * 1024
EMPTY_STATUS_SHA256 = hashlib.sha256(b"").hexdigest()
CARGO_LOCK_PATH = "trillionnium/Cargo.lock"
CANDIDATE_REPORT_KEYS = {
    "source_candidate_sha256",
    "archive_bytes",
    "file_count",
    "source_bytes",
    "source_profile",
    "base_commit",
    "git_object_format",
    "git_tree_oid",
    "git_status_sha256",
    "cargo_lock_path",
    "cargo_lock_sha256",
    "cargo_lock_bytes",
    "production_activation",
    "geo_wan_evidence",
}


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 build-report assembly failed: {message}")


def fsync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as error:
        if sys.platform == "darwin" and error.errno in {errno.EINVAL, errno.ENOTSUP}:
            return
        raise


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            fail(f"duplicate JSON object name {key!r}")
        value[key] = child
    return value


def read_regular_bytes(
    path: pathlib.Path,
    field: str,
    maximum: int,
    *,
    executable: bool = False,
) -> bytes:
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > maximum
        or (executable and metadata.st_mode & 0o111 == 0)
    ):
        fail(f"{field} must be one regular non-symlink file")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
            or opened.st_mtime_ns != metadata.st_mtime_ns
            or opened.st_ctime_ns != metadata.st_ctime_ns
            or opened.st_mode != metadata.st_mode
            or (executable and opened.st_mode & 0o111 == 0)
        ):
            fail(f"{field} changed identity while opening")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{field} truncated during pinned read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"{field} grew during pinned read")
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or after.st_mode != opened.st_mode
        ):
            fail(f"{field} changed during pinned read")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def read_json(path: pathlib.Path, field: str) -> dict[str, Any]:
    raw = read_regular_bytes(path, field, MAX_JSON_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode {field}: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must be one JSON object")
    if (json.dumps(value, sort_keys=True) + "\n").encode("utf-8") != raw:
        fail(f"{field} is not canonical builder JSON")
    return value


def sha256_file(path: pathlib.Path, field: str) -> tuple[str, int]:
    payload = read_regular_bytes(path, field, MAX_BINARY_BYTES, executable=True)
    return hashlib.sha256(payload).hexdigest(), len(payload)


def validated_candidate_sha256(path: pathlib.Path) -> dict[str, Any]:
    try:
        report = check_source_candidate.validate(path, require_clean=True)
    except (SystemExit, OSError, tarfile.TarError, ValueError) as error:
        fail(f"source candidate failed independent validation: {error}")
    if set(report) != CANDIDATE_REPORT_KEYS:
        fail("source-candidate verifier returned fields outside the strict contract")
    object_format = report.get("git_object_format")
    oid_length = 40 if object_format == "sha1" else 64 if object_format == "sha256" else 0
    digest = report.get("source_candidate_sha256")
    base_commit = report.get("base_commit")
    tree_oid = report.get("git_tree_oid")
    if (
        not isinstance(digest, str)
        or not HEX64.fullmatch(digest)
        or type(report.get("archive_bytes")) is not int
        or report["archive_bytes"] <= 0
        or type(report.get("file_count")) is not int
        or report["file_count"] <= 0
        or type(report.get("source_bytes")) is not int
        or report["source_bytes"] < 0
        or report.get("source_profile") != "clean-commit-v1"
        or not isinstance(base_commit, str)
        or len(base_commit) != oid_length
        or re.fullmatch(r"[0-9a-f]+", base_commit) is None
        or not isinstance(tree_oid, str)
        or len(tree_oid) != oid_length
        or re.fullmatch(r"[0-9a-f]+", tree_oid) is None
        or report.get("git_status_sha256") != EMPTY_STATUS_SHA256
        or report.get("cargo_lock_path") != CARGO_LOCK_PATH
        or not isinstance(report.get("cargo_lock_sha256"), str)
        or not HEX64.fullmatch(report["cargo_lock_sha256"])
        or type(report.get("cargo_lock_bytes")) is not int
        or report["cargo_lock_bytes"] <= 0
        or report.get("production_activation") is not False
        or report.get("geo_wan_evidence") is not False
    ):
        fail("source-candidate verifier returned a non-canonical result")
    return report


REPORT_KEYS = {
    "schema_version",
    "source_candidate_sha256",
    "source_candidate_profile",
    "source_base_commit",
    "source_git_object_format",
    "source_git_tree_oid",
    "source_git_status_sha256",
    "cargo_lock_path",
    "cargo_lock_sha256",
    "cargo_lock_bytes",
    "validator_binary_sha256",
    "validator_binary_bytes",
    "material_builder_binary_sha256",
    "material_builder_binary_bytes",
    "host_triple",
    "rustc_vv_sha256",
    "reproducible_build",
    "independent_build_count",
    "output_validator_binary",
    "output_material_builder_binary",
    "production_activation",
    "geo_wan_evidence",
}


def validate_local_report(
    report: dict[str, Any],
    validator_binary: pathlib.Path,
    material_builder_binary: pathlib.Path,
    candidate_report: dict[str, Any],
    architecture: str,
) -> tuple[str, str]:
    if set(report) != REPORT_KEYS:
        fail(f"{architecture} report fields differ from the frozen schema")
    validator_hash, validator_bytes = sha256_file(
        validator_binary, f"{architecture} validator binary"
    )
    material_builder_hash, material_builder_bytes = sha256_file(
        material_builder_binary, f"{architecture} material-builder binary"
    )
    triple = report.get("host_triple")
    if architecture == "linux-x86_64":
        triple_ok = isinstance(triple, str) and triple.startswith("x86_64-") and triple.endswith(
            "-linux-gnu"
        )
    else:
        triple_ok = triple in {"aarch64-apple-darwin", "arm64-apple-darwin"}
    if (
        type(report.get("schema_version")) is not int
        or report.get("schema_version") != 3
        or report.get("source_candidate_sha256")
        != candidate_report["source_candidate_sha256"]
        or report.get("source_candidate_profile")
        != candidate_report["source_profile"]
        or report.get("source_base_commit") != candidate_report["base_commit"]
        or report.get("source_git_object_format")
        != candidate_report["git_object_format"]
        or report.get("source_git_tree_oid") != candidate_report["git_tree_oid"]
        or report.get("source_git_status_sha256")
        != candidate_report["git_status_sha256"]
        or report.get("cargo_lock_path") != candidate_report["cargo_lock_path"]
        or report.get("cargo_lock_sha256") != candidate_report["cargo_lock_sha256"]
        or type(report.get("cargo_lock_bytes")) is not int
        or report.get("cargo_lock_bytes") != candidate_report["cargo_lock_bytes"]
        or report.get("validator_binary_sha256") != validator_hash
        or type(report.get("validator_binary_bytes")) is not int
        or report.get("validator_binary_bytes") != validator_bytes
        or report.get("material_builder_binary_sha256") != material_builder_hash
        or type(report.get("material_builder_binary_bytes")) is not int
        or report.get("material_builder_binary_bytes") != material_builder_bytes
        or validator_hash == material_builder_hash
        or not triple_ok
        or not isinstance(report.get("rustc_vv_sha256"), str)
        or not HEX64.fullmatch(report["rustc_vv_sha256"])
        or report.get("reproducible_build") is not True
        or type(report.get("independent_build_count")) is not int
        or report.get("independent_build_count") != 2
        or not isinstance(report.get("output_validator_binary"), str)
        or not report["output_validator_binary"]
        or not isinstance(report.get("output_material_builder_binary"), str)
        or not report["output_material_builder_binary"]
        or report.get("production_activation") is not False
        or report.get("geo_wan_evidence") is not False
    ):
        fail(f"{architecture} report differs from its exact reproducible-build contract")
    return validator_hash, material_builder_hash


def assemble(
    candidate: pathlib.Path,
    linux_report_path: pathlib.Path,
    linux_binary: pathlib.Path,
    linux_material_builder: pathlib.Path,
    macos_report_path: pathlib.Path,
    macos_binary: pathlib.Path,
    macos_material_builder: pathlib.Path,
) -> dict[str, Any]:
    candidate_report = validated_candidate_sha256(candidate)
    linux = read_json(linux_report_path, "Linux build report")
    macos = read_json(macos_report_path, "macOS build report")
    linux_hash, linux_material_builder_hash = validate_local_report(
        linux,
        linux_binary,
        linux_material_builder,
        candidate_report,
        "linux-x86_64",
    )
    macos_hash, macos_material_builder_hash = validate_local_report(
        macos,
        macos_binary,
        macos_material_builder,
        candidate_report,
        "macos-arm64",
    )
    return {
        "schema_version": 3,
        # Historical field name: this remains the canonical candidate tar hash.
        "source_tree_sha256": candidate_report["source_candidate_sha256"],
        "source_candidate_profile": candidate_report["source_profile"],
        "source_base_commit": candidate_report["base_commit"],
        "source_git_object_format": candidate_report["git_object_format"],
        "source_git_tree_oid": candidate_report["git_tree_oid"],
        "source_git_status_sha256": candidate_report["git_status_sha256"],
        "cargo_lock_path": candidate_report["cargo_lock_path"],
        "cargo_lock_sha256": candidate_report["cargo_lock_sha256"],
        "cargo_lock_bytes": candidate_report["cargo_lock_bytes"],
        "linux_first_sha256": linux_hash,
        "linux_second_sha256": linux_hash,
        "linux_material_builder_first_sha256": linux_material_builder_hash,
        "linux_material_builder_second_sha256": linux_material_builder_hash,
        "macos_first_sha256": macos_hash,
        "macos_second_sha256": macos_hash,
        "macos_material_builder_first_sha256": macos_material_builder_hash,
        "macos_material_builder_second_sha256": macos_material_builder_hash,
        "independent_build_roots": True,
        "production_activation": False,
    }


def write_new(path: pathlib.Path, value: dict[str, Any]) -> None:
    if not path.is_absolute():
        path = pathlib.Path.cwd() / path
    unresolved_parent = path.parent.absolute()
    try:
        parent_metadata = unresolved_parent.lstat()
        parent = unresolved_parent.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve output parent: {error}")
    if (
        unresolved_parent != parent
        or unresolved_parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or path.name in {"", ".", ".."}
    ):
        fail("output parent must be one real non-symlink directory")
    parent_descriptor = os.open(
        parent,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    created_identity: tuple[int, int] | None = None
    content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        try:
            opened_parent = os.fstat(parent_descriptor)
            if (
                opened_parent.st_dev != parent_metadata.st_dev
                or opened_parent.st_ino != parent_metadata.st_ino
            ):
                fail("output parent changed identity while opening")
            os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail("output already exists; build reports are immutable")
        descriptor = os.open(
            path.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_descriptor,
        )
        created = os.fstat(descriptor)
        created_identity = (created.st_dev, created.st_ino)
        try:
            with os.fdopen(descriptor, "wb") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            if created_identity is not None:
                try:
                    named = os.stat(
                        path.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    if (named.st_dev, named.st_ino) == created_identity:
                        os.unlink(path.name, dir_fd=parent_descriptor)
                except FileNotFoundError:
                    pass
            raise

        read_descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent_descriptor,
        )
        try:
            opened = os.fstat(read_descriptor)
            if created_identity is None or (opened.st_dev, opened.st_ino) != created_identity:
                fail("emitted aggregate build report changed identity after creation")
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(read_descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    fail("emitted aggregate build report truncated during readback")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(read_descriptor, 1):
                fail("emitted aggregate build report grew during readback")
            after = os.fstat(read_descriptor)
            if (
                (after.st_dev, after.st_ino) != created_identity
                or after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns
                or after.st_mode != opened.st_mode
            ):
                fail("emitted aggregate build report changed during readback")
            readback = b"".join(chunks)
        finally:
            os.close(read_descriptor)
        named = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        current_parent = parent.lstat()
        if (
            (named.st_dev, named.st_ino) != created_identity
            or (current_parent.st_dev, current_parent.st_ino)
            != (opened_parent.st_dev, opened_parent.st_ino)
            or readback != content
        ):
            fail("emitted aggregate build report changed after creation")
        fsync_directory(parent_descriptor)
    except BaseException:
        if created_identity is not None:
            try:
                named = os.stat(
                    path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (named.st_dev, named.st_ino) == created_identity:
                    os.unlink(path.name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(parent_descriptor)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_candidate", type=pathlib.Path)
    parser.add_argument("--linux-report", required=True, type=pathlib.Path)
    parser.add_argument("--linux-binary", required=True, type=pathlib.Path)
    parser.add_argument("--linux-material-builder", required=True, type=pathlib.Path)
    parser.add_argument("--macos-report", required=True, type=pathlib.Path)
    parser.add_argument("--macos-binary", required=True, type=pathlib.Path)
    parser.add_argument("--macos-material-builder", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    try:
        result = assemble(
            args.source_candidate,
            args.linux_report,
            args.linux_binary,
            args.linux_material_builder,
            args.macos_report,
            args.macos_binary,
            args.macos_material_builder,
        )
        write_new(args.output, result)
    except OSError as error:
        fail(str(error))
    print(
        "poco_g3_reproducible_build_report=assembled "
        f"source={result['source_tree_sha256']} "
        f"linux={result['linux_first_sha256']} macos={result['macos_first_sha256']} "
        f"linux_material_builder={result['linux_material_builder_first_sha256']} "
        f"macos_material_builder={result['macos_material_builder_first_sha256']} "
        "builds_per_architecture=2 production_activation=false geo_wan=false"
    )


if __name__ == "__main__":
    main()
