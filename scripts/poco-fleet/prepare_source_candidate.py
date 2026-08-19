#!/usr/bin/env python3
"""Create a deterministic source candidate.

The default profile preserves the historical exact-worktree v1 format for
audit compatibility.  ``--require-clean`` emits clean-commit-v1: membership,
modes, and bytes come only from the committed Git tree/blob objects, while the
worktree status must be empty.  Formal builders accept only that strict v2
profile.
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tarfile
from typing import Any


LEGACY_SCHEMA_VERSION = 1
STRICT_SCHEMA_VERSION = 2
EMPTY_STATUS_SHA256 = hashlib.sha256(b"").hexdigest()
CARGO_LOCK_PATH = "trillionnium/Cargo.lock"
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_COMMIT_BYTES = 16 * 1024 * 1024
MAX_FILE_COUNT = 200_000
GIT_OVERRIDE_EXACT = {
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_EXTERNAL_DIFF",
    "GIT_NAMESPACE",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_NO_LAZY_FETCH",
    "GIT_QUARANTINE_PATH",
}


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 source candidate preparation failed: {message}")


def fsync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as error:
        if sys.platform == "darwin" and error.errno in {errno.EINVAL, errno.ENOTSUP}:
            return
        raise


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def ambient_git_override_names(environment: dict[str, str]) -> list[str]:
    return sorted(
        name
        for name in environment
        if name in GIT_OVERRIDE_EXACT
        or name == "GIT_CONFIG_PARAMETERS"
        or name.startswith("GIT_CONFIG_KEY_")
        or name.startswith("GIT_CONFIG_VALUE_")
        or name == "GIT_CONFIG_COUNT"
    )


def git_environment() -> dict[str, str]:
    overrides = ambient_git_override_names(os.environ)
    if overrides:
        fail(f"ambient Git authority override is forbidden: {overrides[0]}")
    environment = os.environ.copy()
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    return environment


def git(root: pathlib.Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            f"core.excludesFile={os.devnull}",
            *arguments,
        ],
        input=input_bytes,
        check=True,
        capture_output=True,
        env=git_environment(),
    ).stdout


def safe_tree_path(raw: bytes) -> pathlib.PurePosixPath:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"Git tree path is not UTF-8: {error}")
    if not text or "\\" in text:
        fail("Git returned a non-canonical tree path")
    path = pathlib.PurePosixPath(text)
    if (
        path.is_absolute()
        or path.as_posix() != text
        or any(part in {"", ".", "..", ".git", "target"} for part in path.parts)
        or text == "SOURCE-CANDIDATE.json"
    ):
        fail(f"Git returned a forbidden or non-canonical tree path: {text!r}")
    return path


def candidate_paths(root: pathlib.Path) -> list[pathlib.PurePosixPath]:
    """Historical v1 membership: tracked plus non-ignored untracked files."""

    raw = git(root, "ls-files", "-co", "--exclude-per-directory=.gitignore", "-z")
    values: list[pathlib.PurePosixPath] = []
    seen: set[pathlib.PurePosixPath] = set()
    for item in raw.split(b"\0"):
        if not item:
            continue
        if len(values) >= MAX_FILE_COUNT:
            fail("candidate worktree entry count crosses its bound")
        path = safe_tree_path(item)
        if path in seen:
            fail(f"Git returned a duplicate path: {path}")
        seen.add(path)
        absolute = root.joinpath(*path.parts)
        if not absolute.exists() and not absolute.is_symlink():
            continue
        values.append(path)
    values.sort(key=lambda value: value.as_posix().encode("utf-8"))
    if not values:
        fail("candidate inventory is empty")
    return values


def freeze_file(root: pathlib.Path, relative: pathlib.PurePosixPath) -> tuple[bytes, int]:
    path = root.joinpath(*relative.parts)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"candidate path is not one regular non-symlink file: {relative}")
    if metadata.st_size > MAX_FILE_BYTES:
        fail(f"candidate file size crosses its bound: {relative}")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
            or opened.st_mtime_ns != metadata.st_mtime_ns
        ):
            fail(f"candidate file changed identity while opening: {relative}")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"candidate file truncated during pinned read: {relative}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"candidate file grew during pinned read: {relative}")
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
        ):
            fail(f"candidate file changed during pinned read: {relative}")
    finally:
        os.close(descriptor)
    mode = 0o755 if metadata.st_mode & 0o111 else 0o644
    return data, mode


def oid_length(object_format: str) -> int:
    if object_format == "sha1":
        return 40
    if object_format == "sha256":
        return 64
    fail(f"unsupported Git object format: {object_format!r}")


def git_object_oid(object_format: str, kind: str, payload: bytes) -> str:
    header = f"{kind} {len(payload)}\0".encode("ascii")
    if object_format == "sha1":
        digest = hashlib.sha1()  # noqa: S324 - Git's repository object format.
    elif object_format == "sha256":
        digest = hashlib.sha256()
    else:
        fail(f"unsupported Git object format: {object_format!r}")
    digest.update(header)
    digest.update(payload)
    return digest.hexdigest()


def parse_tree(
    raw: bytes, object_format: str
) -> list[tuple[pathlib.PurePosixPath, str, str]]:
    entries: list[tuple[pathlib.PurePosixPath, str, str]] = []
    seen: set[pathlib.PurePosixPath] = set()
    expected_oid_length = oid_length(object_format)
    for item in raw.split(b"\0"):
        if not item:
            continue
        if len(entries) >= MAX_FILE_COUNT:
            fail("candidate Git tree entry count crosses its bound")
        try:
            header, raw_path = item.split(b"\t", 1)
            mode_raw, kind_raw, oid_raw = header.split(b" ")
            mode = mode_raw.decode("ascii")
            kind = kind_raw.decode("ascii")
            oid = oid_raw.decode("ascii")
        except (ValueError, UnicodeDecodeError) as error:
            fail(f"cannot parse exact Git tree record: {error}")
        path = safe_tree_path(raw_path)
        if path in seen:
            fail(f"Git tree contains a duplicate path: {path}")
        seen.add(path)
        if mode not in {"100644", "100755"} or kind != "blob":
            fail(f"Git tree contains unsupported mode/type {mode} {kind}: {path}")
        if len(oid) != expected_oid_length or re.fullmatch(r"[0-9a-f]+", oid) is None:
            fail(f"Git tree contains a non-canonical object ID: {path}")
        entries.append((path, mode, oid))
    entries.sort(key=lambda entry: entry[0].as_posix().encode("utf-8"))
    if not entries:
        fail("candidate Git tree is empty")
    return entries


def read_blobs(
    root: pathlib.Path,
    entries: list[tuple[pathlib.PurePosixPath, str, str]],
    object_format: str,
) -> dict[str, bytes]:
    requested = list(dict.fromkeys(oid for _, _, oid in entries))
    process = subprocess.Popen(
        [
            "git",
            "-C",
            str(root),
            "-c",
            f"core.excludesFile={os.devnull}",
            "cat-file",
            "--batch",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_environment(),
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        fail("cannot open exact git cat-file pipes")
    blobs: dict[str, bytes] = {}
    unique_total = 0
    try:
        for requested_oid in requested:
            process.stdin.write(requested_oid.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline()
            if not header.endswith(b"\n"):
                fail("git cat-file returned a truncated object header")
            try:
                observed_oid_raw, kind, size_raw = header[:-1].split(b" ")
                observed_oid = observed_oid_raw.decode("ascii")
                size = int(size_raw.decode("ascii"), 10)
            except (ValueError, UnicodeDecodeError) as error:
                fail(f"git cat-file returned a malformed object header: {error}")
            if (
                observed_oid != requested_oid
                or kind != b"blob"
                or size < 0
                or size > MAX_FILE_BYTES
            ):
                fail("git cat-file returned an unexpected blob identity/type/size")
            unique_total += size
            if unique_total > MAX_TOTAL_BYTES:
                fail("candidate unique Git blob bytes exceed the total bound")
            chunks: list[bytes] = []
            remaining = size
            while remaining:
                chunk = process.stdout.read(min(1024 * 1024, remaining))
                if not chunk:
                    fail("git cat-file returned a truncated blob payload")
                chunks.append(chunk)
                remaining -= len(chunk)
            if process.stdout.read(1) != b"\n":
                fail("git cat-file omitted the blob record delimiter")
            payload = b"".join(chunks)
            if git_object_oid(object_format, "blob", payload) != requested_oid:
                fail("Git blob bytes do not match their declared object ID")
            blobs[requested_oid] = payload
        process.stdin.close()
        if process.stdout.read(1):
            fail("git cat-file returned trailing undeclared bytes")
        stderr = process.stderr.read()
        return_code = process.wait()
        if return_code != 0 or stderr:
            fail("git cat-file did not complete silently and successfully")
    except BaseException:
        process.kill()
        process.wait()
        raise
    return blobs


def compute_git_tree_oid(records: list[dict[str, Any]], object_format: str) -> str:
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
        entries_to_encode: list[tuple[bytes, bytes]] = []
        for name, record in node["files"].items():
            encoded_name = name.encode("utf-8")
            mode = b"100755" if record["mode"] == "0755" else b"100644"
            entries_to_encode.append(
                (
                    encoded_name,
                    mode
                    + b" "
                    + encoded_name
                    + b"\0"
                    + bytes.fromhex(record["git_blob_oid"]),
                )
            )
        for name, child in node["dirs"].items():
            encoded_name = name.encode("utf-8")
            entries_to_encode.append(
                (
                    encoded_name + b"/",
                    b"40000 "
                    + encoded_name
                    + b"\0"
                    + bytes.fromhex(encode(child)),
                )
            )
        entries_to_encode.sort(key=lambda item: item[0])
        return git_object_oid(
            object_format,
            "tree",
            b"".join(payload for _, payload in entries_to_encode),
        )

    return encode(root)


def strict_snapshot(root: pathlib.Path) -> dict[str, bytes | str]:
    commit = git(root, "rev-parse", "HEAD^{commit}").decode("ascii").strip()
    tree = git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    object_format = git(root, "rev-parse", "--show-object-format").decode("ascii").strip()
    expected = oid_length(object_format)
    for field, value in (("HEAD", commit), ("HEAD tree", tree)):
        if len(value) != expected or re.fullmatch(r"[0-9a-f]+", value) is None:
            fail(f"{field} is not one exact {object_format} object ID")
    status = git(
        root,
        "status",
        "--porcelain=v2",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    tree_records = git(root, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
    commit_payload = git(root, "cat-file", "commit", commit)
    if len(commit_payload) > MAX_COMMIT_BYTES:
        fail("HEAD commit object crosses its size bound")
    if git_object_oid(object_format, "commit", commit_payload) != commit:
        fail("HEAD commit object bytes do not match HEAD")
    first_line = commit_payload.partition(b"\n")[0]
    if first_line != b"tree " + tree.encode("ascii"):
        fail("HEAD commit object does not bind HEAD^{tree}")
    return {
        "commit": commit,
        "tree": tree,
        "object_format": object_format,
        "status": status,
        "tree_records": tree_records,
        "commit_payload": commit_payload,
    }


def prepare_legacy_worktree(
    root: pathlib.Path,
) -> tuple[dict[str, Any], list[tuple[pathlib.PurePosixPath, bytes, int]]]:
    records: list[dict[str, Any]] = []
    frozen: list[tuple[pathlib.PurePosixPath, bytes, int]] = []
    total = 0
    for relative in candidate_paths(root):
        data, mode = freeze_file(root, relative)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            fail("candidate source bytes exceed the total bound")
        records.append(
            {
                "path": relative.as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "mode": format(mode, "04o"),
            }
        )
        frozen.append((relative, data, mode))

    head = git(root, "rev-parse", "HEAD").decode("ascii").strip()
    status = git(root, "status", "--porcelain=v2", "-z", "--untracked-files=all")
    if candidate_paths(root) != [relative for relative, _, _ in frozen]:
        fail("candidate path inventory changed during preparation")
    for (relative, expected, expected_mode), record in zip(frozen, records, strict=True):
        observed, observed_mode = freeze_file(root, relative)
        if (
            observed != expected
            or observed_mode != expected_mode
            or hashlib.sha256(observed).hexdigest() != record["sha256"]
        ):
            fail(f"candidate file changed during preparation: {relative}")
    final_head = git(root, "rev-parse", "HEAD").decode("ascii").strip()
    final_status = git(root, "status", "--porcelain=v2", "-z", "--untracked-files=all")
    if final_head != head or final_status != status:
        fail("Git provenance changed during candidate preparation")
    inventory = {
        "schema_version": LEGACY_SCHEMA_VERSION,
        "profile": "exact-git-visible-worktree-v1",
        "base_commit": head,
        "git_status_sha256": hashlib.sha256(status).hexdigest(),
        "file_count": len(records),
        "source_bytes": total,
        "files": records,
        "production_activation": False,
        "geo_wan_evidence": False,
    }
    return inventory, frozen


def prepare_clean_commit(
    root: pathlib.Path,
) -> tuple[dict[str, Any], list[tuple[pathlib.PurePosixPath, bytes, int]]]:
    before = strict_snapshot(root)
    status = before["status"]
    assert isinstance(status, bytes)
    if status != b"":
        fail("clean-commit-v1 requires an empty Git status")
    object_format = before["object_format"]
    tree_records = before["tree_records"]
    assert isinstance(object_format, str)
    assert isinstance(tree_records, bytes)
    entries = parse_tree(tree_records, object_format)
    blobs = read_blobs(root, entries, object_format)

    records: list[dict[str, Any]] = []
    frozen: list[tuple[pathlib.PurePosixPath, bytes, int]] = []
    total = 0
    for relative, tree_mode, blob_oid in entries:
        data = blobs[blob_oid]
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            fail("candidate source bytes exceed the total bound")
        mode = 0o755 if tree_mode == "100755" else 0o644
        records.append(
            {
                "path": relative.as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "mode": format(mode, "04o"),
                "git_blob_oid": blob_oid,
            }
        )
        frozen.append((relative, data, mode))

    lock_records = [record for record in records if record["path"] == CARGO_LOCK_PATH]
    if len(lock_records) != 1:
        fail("clean-commit-v1 requires exactly one active workspace Cargo.lock")
    lock_record = lock_records[0]
    if lock_record["mode"] != "0644":
        fail("active workspace Cargo.lock must not be executable")
    if lock_record["bytes"] <= 0:
        fail("active workspace Cargo.lock must not be empty")
    tree = before["tree"]
    assert isinstance(tree, str)
    if compute_git_tree_oid(records, object_format) != tree:
        fail("Git tree contains unsupported entries or does not match flat records")

    after = strict_snapshot(root)
    if after != before:
        fail("Git commit/tree/status changed during strict candidate preparation")
    commit = before["commit"]
    commit_payload = before["commit_payload"]
    assert isinstance(commit, str)
    assert isinstance(tree, str)
    assert isinstance(commit_payload, bytes)
    inventory = {
        "schema_version": STRICT_SCHEMA_VERSION,
        "profile": "clean-commit-v1",
        "base_commit": commit,
        "git_object_format": object_format,
        "git_tree_oid": tree,
        "git_commit_payload_base64": base64.b64encode(commit_payload).decode("ascii"),
        "git_status_sha256": EMPTY_STATUS_SHA256,
        "file_count": len(records),
        "source_bytes": total,
        "files": records,
        "cargo_lock": {
            "path": CARGO_LOCK_PATH,
            "sha256": lock_record["sha256"],
            "bytes": lock_record["bytes"],
        },
        "production_activation": False,
        "geo_wan_evidence": False,
    }
    return inventory, frozen


def tar_entry(name: str, data: bytes, mode: int) -> tuple[tarfile.TarInfo, io.BytesIO]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.type = tarfile.REGTYPE
    return info, io.BytesIO(data)


def prepare(
    root: pathlib.Path,
    output: pathlib.Path,
    *,
    require_clean: bool = False,
) -> dict[str, Any]:
    if not root.is_absolute():
        root = pathlib.Path.cwd() / root
    root_metadata = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        fail("source root must be one real non-symlink directory")
    root = root.resolve(strict=True)
    if not (root / ".git").exists() and not git(root, "rev-parse", "--git-dir").strip():
        fail("source root is not a Git worktree")
    if not output.is_absolute():
        output = pathlib.Path.cwd() / output
    unresolved_output_parent = output.parent.absolute()
    try:
        output_parent_metadata = unresolved_output_parent.lstat()
        output_parent = unresolved_output_parent.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve candidate output parent: {error}")
    if (
        unresolved_output_parent != output_parent
        or unresolved_output_parent.is_symlink()
        or not stat.S_ISDIR(output_parent_metadata.st_mode)
        or output.name in {"", ".", ".."}
    ):
        fail("candidate output parent must be one real non-symlink directory")
    output = output_parent / output.name
    try:
        output.relative_to(root)
    except ValueError:
        pass
    else:
        fail("candidate archive must be outside the source tree")

    output_parent_descriptor = os.open(
        output_parent,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    opened_output_parent = os.fstat(output_parent_descriptor)
    if (
        opened_output_parent.st_dev != output_parent_metadata.st_dev
        or opened_output_parent.st_ino != output_parent_metadata.st_ino
    ):
        os.close(output_parent_descriptor)
        fail("candidate output parent changed identity while opening")
    try:
        os.stat(output.name, dir_fd=output_parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except BaseException:
        os.close(output_parent_descriptor)
        raise
    else:
        os.close(output_parent_descriptor)
        fail("candidate archive already exists; candidates are immutable")
    os.close(output_parent_descriptor)

    if require_clean:
        inventory, frozen = prepare_clean_commit(root)
    else:
        inventory, frozen = prepare_legacy_worktree(root)
    inventory_bytes = canonical_json(inventory)

    descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    archive_sha256 = ""
    archive_bytes = 0
    output_parent_descriptor = os.open(
        output_parent,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    opened_output_parent = os.fstat(output_parent_descriptor)
    current_parent = output_parent.lstat()
    if (
        opened_output_parent.st_dev != output_parent_metadata.st_dev
        or opened_output_parent.st_ino != output_parent_metadata.st_ino
        or current_parent.st_dev != opened_output_parent.st_dev
        or current_parent.st_ino != opened_output_parent.st_ino
    ):
        os.close(output_parent_descriptor)
        fail("candidate output parent changed during preparation")
    try:
        os.stat(output.name, dir_fd=output_parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except BaseException:
        os.close(output_parent_descriptor)
        raise
    else:
        os.close(output_parent_descriptor)
        fail("candidate archive appeared during preparation")
    try:
        descriptor = os.open(
            output.name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=output_parent_descriptor,
        )
        created = os.fstat(descriptor)
        created_identity = (created.st_dev, created.st_ino)
        with os.fdopen(descriptor, "w+b") as raw:
            descriptor = None
            os.fchmod(raw.fileno(), 0o600)
            with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
                info, stream = tar_entry("source/SOURCE-CANDIDATE.json", inventory_bytes, 0o644)
                archive.addfile(info, stream)
                for relative, data, mode in frozen:
                    info, stream = tar_entry(f"source/{relative.as_posix()}", data, mode)
                    archive.addfile(info, stream)
            raw.flush()
            os.fsync(raw.fileno())
            written = os.fstat(raw.fileno())
            archive_bytes = written.st_size
            raw.seek(0)
            digest = hashlib.sha256()
            while chunk := raw.read(1024 * 1024):
                digest.update(chunk)
            archive_sha256 = digest.hexdigest()
            after = os.fstat(raw.fileno())
            if (
                (after.st_dev, after.st_ino) != created_identity
                or after.st_size != archive_bytes
                or after.st_mtime_ns != written.st_mtime_ns
                or after.st_ctime_ns != written.st_ctime_ns
                or after.st_mode != written.st_mode
            ):
                fail("candidate archive changed during pinned write/readback")
        named = os.stat(output.name, dir_fd=output_parent_descriptor, follow_symlinks=False)
        current_parent = output_parent.lstat()
        if (
            created_identity is None
            or (named.st_dev, named.st_ino) != created_identity
            or (current_parent.st_dev, current_parent.st_ino)
            != (opened_output_parent.st_dev, opened_output_parent.st_ino)
        ):
            fail("candidate archive output path changed after creation")
        fsync_directory(output_parent_descriptor)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        if created_identity is not None:
            try:
                named = os.stat(
                    output.name,
                    dir_fd=output_parent_descriptor,
                    follow_symlinks=False,
                )
                if (named.st_dev, named.st_ino) == created_identity:
                    os.unlink(output.name, dir_fd=output_parent_descriptor)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(output_parent_descriptor)
    result = {
        "archive": str(output),
        "sha256": archive_sha256,
        "bytes": archive_bytes,
        "file_count": inventory["file_count"],
        "source_bytes": inventory["source_bytes"],
        "base_commit": inventory["base_commit"],
        "production_activation": False,
        "geo_wan_evidence": False,
    }
    if require_clean:
        result["source_profile"] = inventory["profile"]
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_root", type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--require-clean", action="store_true")
    args = parser.parse_args()
    try:
        result = prepare(
            args.source_root,
            args.output,
            require_clean=args.require_clean,
        )
    except (OSError, subprocess.SubprocessError, tarfile.TarError, ValueError) as error:
        fail(str(error))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
