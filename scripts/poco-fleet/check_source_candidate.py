#!/usr/bin/env python3
"""Strictly verify one deterministic PoCO G3 source-candidate tar."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import tarfile
import tempfile
from typing import Any


HEX64 = re.compile(r"^[0-9a-f]{64}$")
EMPTY_STATUS_SHA256 = hashlib.sha256(b"").hexdigest()
CARGO_LOCK_PATH = "trillionnium/Cargo.lock"
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_COMMIT_BYTES = 16 * 1024 * 1024
MAX_FILE_COUNT = 200_000

V1_INVENTORY_KEYS = {
    "schema_version",
    "profile",
    "base_commit",
    "git_status_sha256",
    "file_count",
    "source_bytes",
    "files",
    "production_activation",
    "geo_wan_evidence",
}
V2_INVENTORY_KEYS = V1_INVENTORY_KEYS | {
    "git_object_format",
    "git_tree_oid",
    "git_commit_payload_base64",
    "cargo_lock",
}


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 source candidate invalid: {message}")


def exact(value: object, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{field} keys differ from the source-candidate contract")
    return value


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON object name {key!r}")
        result[key] = value
    return result


def sha256_stream(source) -> str:
    digest = hashlib.sha256()
    while chunk := source.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def safe_source_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        fail("source file path is not one canonical POSIX path")
    path = pathlib.PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", "..", ".git", "target"} for part in path.parts)
        or value == "SOURCE-CANDIDATE.json"
    ):
        fail("source file path escapes the candidate root")
    return value


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def canonical_tar_info(name: str, data: bytes, mode: int) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.size = len(data)
    member.mode = mode
    member.uid = 0
    member.gid = 0
    member.uname = ""
    member.gname = ""
    member.mtime = 0
    member.type = tarfile.REGTYPE
    return member


def oid_hex_length(object_format: object) -> int:
    if object_format == "sha1":
        return 40
    if object_format == "sha256":
        return 64
    fail("candidate git_object_format is unsupported")


def exact_oid(value: object, object_format: object, field: str) -> str:
    length = oid_hex_length(object_format)
    if (
        not isinstance(value, str)
        or len(value) != length
        or re.fullmatch(r"[0-9a-f]+", value) is None
    ):
        fail(f"{field} is not one exact {object_format} object ID")
    return value


def git_object_oid(object_format: str, kind: str, payload: bytes) -> str:
    header = f"{kind} {len(payload)}\0".encode("ascii")
    if object_format == "sha1":
        digest = hashlib.sha1()  # noqa: S324 - Git's repository object format.
    elif object_format == "sha256":
        digest = hashlib.sha256()
    else:
        fail("candidate git_object_format is unsupported")
    digest.update(header)
    digest.update(payload)
    return digest.hexdigest()


def compute_git_tree_oid(records: list[dict[str, Any]], object_format: str) -> str:
    """Rebuild the exact Git root-tree object from flat canonical file records."""

    def new_node() -> dict[str, dict[str, Any]]:
        return {"files": {}, "dirs": {}}

    root = new_node()
    for record in records:
        parts = record["path"].split("/")
        node = root
        for part in parts[:-1]:
            if part in node["files"]:
                fail("candidate tree contains a file/directory prefix collision")
            node = node["dirs"].setdefault(part, new_node())
        leaf = parts[-1]
        if leaf in node["files"] or leaf in node["dirs"]:
            fail("candidate tree contains a duplicate or prefix-colliding path")
        node["files"][leaf] = record

    def encode(node: dict[str, dict[str, Any]]) -> str:
        entries: list[tuple[bytes, bytes]] = []
        for name, record in node["files"].items():
            encoded_name = name.encode("utf-8")
            mode = b"100755" if record["mode"] == "0755" else b"100644"
            oid = bytes.fromhex(record["git_blob_oid"])
            entries.append((encoded_name, mode + b" " + encoded_name + b"\0" + oid))
        for name, child in node["dirs"].items():
            encoded_name = name.encode("utf-8")
            oid = bytes.fromhex(encode(child))
            entries.append(
                (
                    encoded_name + b"/",
                    b"40000 " + encoded_name + b"\0" + oid,
                )
            )
        entries.sort(key=lambda item: item[0])
        return git_object_oid(
            object_format,
            "tree",
            b"".join(payload for _, payload in entries),
        )

    return encode(root)


def validate(path: pathlib.Path, *, require_clean: bool = False) -> dict[str, object]:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        fail("candidate archive must be one regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_ARCHIVE_BYTES:
        fail("candidate archive size crosses its bound")
    with tempfile.TemporaryFile(prefix="poco-g3-frozen-candidate-") as frozen_archive:
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
            ):
                fail("candidate archive changed identity while opening")
            digest = hashlib.sha256()
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    fail("candidate archive truncated during pinned copy")
                frozen_archive.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                fail("candidate archive grew during pinned copy")
            after = os.fstat(descriptor)
            if (
                after.st_dev != opened.st_dev
                or after.st_ino != opened.st_ino
                or after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns
                or after.st_mode != opened.st_mode
            ):
                fail("candidate archive changed during pinned copy")
            archive_sha256 = digest.hexdigest()
        finally:
            os.close(descriptor)

        frozen_archive.flush()
        frozen_archive.seek(0)
        with tarfile.open(fileobj=frozen_archive, mode="r:") as archive:
            members: list[tarfile.TarInfo] = []
            for member in archive:
                if len(members) >= MAX_FILE_COUNT + 1:
                    fail("candidate tar member count crosses its bound")
                members.append(member)
            if not members or members[0].name != "source/SOURCE-CANDIDATE.json":
                fail("candidate inventory is not the first tar member")
            names: list[str] = []
            seen_names: set[str] = set()
            contents: dict[str, bytes] = {}
            member_modes: dict[str, int] = {}
            for member in members:
                if (
                    not member.isfile()
                    or member.issym()
                    or member.islnk()
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname
                    or member.gname
                    or member.mtime != 0
                    or member.mode not in {0o644, 0o755}
                    or not member.name.startswith("source/")
                    or member.name in seen_names
                    or member.size > MAX_FILE_BYTES
                ):
                    fail("candidate tar member metadata is non-canonical")
                relative = member.name.removeprefix("source/")
                if relative != "SOURCE-CANDIDATE.json":
                    safe_source_path(relative)
                stream = archive.extractfile(member)
                if stream is None:
                    fail("candidate tar regular member has no byte stream")
                data = stream.read(MAX_FILE_BYTES + 1)
                if len(data) != member.size:
                    fail("candidate tar member length differs from header")
                names.append(member.name)
                seen_names.add(member.name)
                contents[relative] = data
                member_modes[relative] = member.mode

    try:
        inventory_value = json.loads(
            contents["SOURCE-CANDIDATE.json"].decode("utf-8"),
            object_pairs_hook=unique_object,
        )
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"candidate inventory is not exact UTF-8 JSON: {error}")
    if not isinstance(inventory_value, dict):
        fail("candidate inventory must be one JSON object")
    if canonical_json(inventory_value) != contents["SOURCE-CANDIDATE.json"]:
        fail("candidate inventory JSON is not canonical")
    if type(inventory_value.get("schema_version")) is not int:
        fail("candidate schema_version must be one exact integer")
    schema_version = inventory_value["schema_version"]
    if schema_version == 1:
        inventory = exact(inventory_value, V1_INVENTORY_KEYS, "inventory")
        if require_clean:
            fail("strict source candidate must use clean-commit-v1")
        profile = "exact-git-visible-worktree-v1"
        record_keys = {"path", "sha256", "bytes", "mode"}
        object_format: str | None = None
    elif schema_version == 2:
        inventory = exact(inventory_value, V2_INVENTORY_KEYS, "inventory")
        profile = "clean-commit-v1"
        record_keys = {"path", "sha256", "bytes", "mode", "git_blob_oid"}
        object_format = inventory.get("git_object_format")
    else:
        fail("candidate schema_version is unsupported")

    if (
        inventory.get("profile") != profile
        or not isinstance(inventory.get("base_commit"), str)
        or not isinstance(inventory.get("git_status_sha256"), str)
        or not HEX64.fullmatch(inventory["git_status_sha256"])
        or inventory.get("production_activation") is not False
        or inventory.get("geo_wan_evidence") is not False
    ):
        fail("candidate inventory crosses its exact non-production profile")
    if schema_version == 1:
        if len(inventory["base_commit"]) not in {40, 64} or re.fullmatch(
            r"[0-9a-f]+", inventory["base_commit"]
        ) is None:
            fail("legacy candidate base_commit is not one Git object ID")
    else:
        assert object_format is not None
        base_commit = exact_oid(inventory["base_commit"], object_format, "base_commit")
        git_tree_oid = exact_oid(inventory.get("git_tree_oid"), object_format, "git_tree_oid")
        if inventory["git_status_sha256"] != EMPTY_STATUS_SHA256:
            fail("clean-commit-v1 must bind the empty Git status")
        encoded_commit = inventory.get("git_commit_payload_base64")
        if not isinstance(encoded_commit, str) or len(encoded_commit) > MAX_COMMIT_BYTES * 2:
            fail("clean candidate commit payload is not bounded canonical base64")
        try:
            commit_payload = base64.b64decode(encoded_commit, validate=True)
        except (ValueError, binascii.Error) as error:
            fail(f"clean candidate commit payload is not canonical base64: {error}")
        if (
            len(commit_payload) > MAX_COMMIT_BYTES
            or base64.b64encode(commit_payload).decode("ascii") != encoded_commit
            or git_object_oid(object_format, "commit", commit_payload) != base_commit
        ):
            fail("clean candidate commit payload does not match base_commit")
        if commit_payload.partition(b"\n")[0] != b"tree " + git_tree_oid.encode("ascii"):
            fail("clean candidate base_commit does not bind git_tree_oid")

    records_value = inventory.get("files")
    if (
        not isinstance(records_value, list)
        or not records_value
        or len(records_value) > MAX_FILE_COUNT
    ):
        fail("candidate file inventory is empty or not a list")
    records: list[dict[str, Any]] = []
    expected_names = ["source/SOURCE-CANDIDATE.json"]
    previous: bytes | None = None
    total = 0
    for index, value in enumerate(records_value):
        record = exact(value, record_keys, f"files[{index}]")
        relative = safe_source_path(record["path"])
        key = relative.encode("utf-8")
        if previous is not None and previous >= key:
            fail("candidate file records are not strictly byte-sorted")
        previous = key
        if (
            not isinstance(record.get("sha256"), str)
            or not HEX64.fullmatch(record["sha256"])
            or isinstance(record.get("bytes"), bool)
            or not isinstance(record.get("bytes"), int)
            or record["bytes"] < 0
            or record["bytes"] > MAX_FILE_BYTES
            or record.get("mode") not in {"0644", "0755"}
        ):
            fail("candidate file record is non-canonical")
        data = contents.get(relative)
        if data is None:
            fail("candidate inventory names a missing tar member")
        if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            fail("candidate file bytes differ from inventory")
        if member_modes.get(relative) != int(record["mode"], 8):
            fail("candidate file mode differs from inventory")
        if schema_version == 2:
            assert object_format is not None
            blob_oid = exact_oid(record.get("git_blob_oid"), object_format, "git_blob_oid")
            if git_object_oid(object_format, "blob", data) != blob_oid:
                fail("candidate file bytes differ from git_blob_oid")
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            fail("candidate source total exceeds its bound")
        expected_names.append(f"source/{relative}")
        records.append(record)
    if names != expected_names or set(contents) != {
        "SOURCE-CANDIDATE.json",
        *(record["path"] for record in records),
    }:
        fail("candidate tar member inventory has extra, missing, or reordered files")
    if type(inventory.get("file_count")) is not int or type(inventory.get("source_bytes")) is not int:
        fail("candidate inventory totals must be exact integers")
    if inventory["file_count"] != len(records) or inventory["source_bytes"] != total:
        fail("candidate inventory totals differ from tar contents")

    result: dict[str, object] = {
        "source_candidate_sha256": archive_sha256,
        "archive_bytes": opened.st_size,
        "file_count": len(records),
        "source_bytes": total,
        "base_commit": inventory["base_commit"],
        "production_activation": False,
        "geo_wan_evidence": False,
    }
    if schema_version == 2:
        assert object_format is not None
        cargo_lock = exact(
            inventory.get("cargo_lock"),
            {"path", "sha256", "bytes"},
            "cargo_lock",
        )
        if cargo_lock.get("path") != CARGO_LOCK_PATH:
            fail("clean candidate does not bind the active workspace Cargo.lock")
        lock_records = [record for record in records if record["path"] == CARGO_LOCK_PATH]
        if len(lock_records) != 1:
            fail("clean candidate must contain exactly one active workspace Cargo.lock")
        lock_record = lock_records[0]
        if lock_record["mode"] != "0644":
            fail("active workspace Cargo.lock must not be executable")
        if (
            cargo_lock.get("sha256") != lock_record["sha256"]
            or cargo_lock.get("bytes") != lock_record["bytes"]
            or not isinstance(cargo_lock.get("sha256"), str)
            or not HEX64.fullmatch(cargo_lock["sha256"])
            or isinstance(cargo_lock.get("bytes"), bool)
            or not isinstance(cargo_lock.get("bytes"), int)
            or cargo_lock["bytes"] <= 0
        ):
            fail("cargo_lock binding differs from its exact file record")
        rebuilt_tree = compute_git_tree_oid(records, object_format)
        if rebuilt_tree != inventory["git_tree_oid"]:
            fail("candidate file records do not reconstruct git_tree_oid")
        result.update(
            {
                "source_profile": profile,
                "git_status_sha256": inventory["git_status_sha256"],
                "git_object_format": object_format,
                "git_tree_oid": inventory["git_tree_oid"],
                "cargo_lock_path": cargo_lock["path"],
                "cargo_lock_sha256": cargo_lock["sha256"],
                "cargo_lock_bytes": cargo_lock["bytes"],
            }
        )

    with tempfile.TemporaryFile(prefix="poco-g3-canonical-tar-") as canonical:
        with tarfile.open(fileobj=canonical, mode="w", format=tarfile.GNU_FORMAT) as archive:
            inventory_bytes = contents["SOURCE-CANDIDATE.json"]
            archive.addfile(
                canonical_tar_info("source/SOURCE-CANDIDATE.json", inventory_bytes, 0o644),
                io.BytesIO(inventory_bytes),
            )
            for record in records:
                relative = record["path"]
                data = contents[relative]
                archive.addfile(
                    canonical_tar_info(
                        f"source/{relative}", data, int(record["mode"], 8)
                    ),
                    io.BytesIO(data),
                )
        canonical_size = canonical.tell()
        canonical.seek(0)
        if canonical_size != opened.st_size or sha256_stream(canonical) != archive_sha256:
            fail("candidate tar bytes are not the unique canonical GNU encoding")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=pathlib.Path)
    parser.add_argument("--require-clean", action="store_true")
    args = parser.parse_args()
    try:
        candidate = args.candidate
        if not candidate.is_absolute():
            candidate = pathlib.Path.cwd() / candidate
        result = validate(candidate, require_clean=args.require_clean)
    except (OSError, tarfile.TarError, ValueError) as error:
        fail(str(error))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
