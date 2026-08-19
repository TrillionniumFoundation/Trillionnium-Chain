#!/usr/bin/env python3
"""Fail-closed transport for already sealed PoCO evidence artifacts.

The caller supplies every source and destination path.  This module never
discovers evidence, follows links, replaces an existing destination, or treats
transport metadata as runtime authority.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import pathlib
import re
import shlex
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from typing import Any, BinaryIO


MAX_SEALED_ARTIFACT_BYTES_V1 = 512 * 1024 * 1024
_COPY_BUFFER_BYTES_V1 = 1024 * 1024
_MAX_FRAME_LINE_BYTES_V1 = 4096
_HEX_SHA256_V1 = re.compile(r"^[0-9a-f]{64}$")
_MANAGEMENT_V1 = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@%+\-]{0,254}$")
_REMOTE_NAME_V1 = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,254}$")
_EXPORT_HEADER_V1 = b"TRNM_SEALED_ARTIFACT_EXPORT_V1"
_EXPORT_TRAILER_V1 = b"TRNM_SEALED_ARTIFACT_EXPORT_END_V1"
_STAGE_HEADER_V1 = b"TRNM_SEALED_ARTIFACT_STAGE_V1"
_STAGE_TRAILER_V1 = b"TRNM_SEALED_ARTIFACT_STAGE_END_V1"
_STAGE_RECEIPT_V1 = b"TRNM_SEALED_ARTIFACT_RECEIPT_V1"


class SealedArtifactTransportError(RuntimeError):
    """A sealed artifact did not satisfy the closed transport contract."""


@dataclasses.dataclass(frozen=True)
class SealedArtifactFactsV1:
    """Stable facts revalidated by the transport boundary."""

    path: str
    sha256: str
    bytes: int
    mode: int
    device: int
    inode: int
    modified_ns: int
    changed_ns: int
    uid: int
    nlink: int

    def as_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class _IdentityV1:
    device: int
    inode: int
    bytes: int
    mode: int
    uid: int
    gid: int
    nlink: int
    modified_ns: int
    changed_ns: int


@dataclasses.dataclass
class _PinnedSourceV1:
    path: str
    name: str
    parent_fd: int
    fd: int
    identity: _IdentityV1

    def close(self) -> None:
        os.close(self.fd)
        os.close(self.parent_fd)


# Tests may replace only these two narrow process/mutation seams.  Production
# callers never receive an owner, descriptor, or mutable record through them.
_SSH_PROCESS_FACTORY_V1: Callable[..., Any] = subprocess.Popen
_TEST_AFTER_FIRST_SOURCE_PASS_V1: Callable[[str], None] | None = None


def _fail(message: str) -> None:
    raise SealedArtifactTransportError(message)


def _maximum_bytes(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > MAX_SEALED_ARTIFACT_BYTES_V1
    ):
        _fail("maximum_bytes is outside the sealed-artifact bound")
    return value


def _absolute_path(value: str | os.PathLike[str], field: str) -> str:
    try:
        raw = os.fspath(value)
    except TypeError as error:
        raise SealedArtifactTransportError(f"{field} is not a path") from error
    if isinstance(raw, bytes) or not raw or "\x00" in raw or not os.path.isabs(raw):
        _fail(f"{field} must be an absolute text path")
    components = pathlib.PurePosixPath(raw).parts
    if any(component in ("", ".", "..") for component in components[1:]):
        _fail(f"{field} is not lexically canonical")
    normalized = os.path.normpath(raw)
    if normalized != raw or normalized == "/":
        _fail(f"{field} is not a file path in canonical form")
    return raw


def _management(value: object) -> str:
    if not isinstance(value, str) or _MANAGEMENT_V1.fullmatch(value) is None:
        _fail("management is not a closed SSH destination")
    return value


def _remote_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or _REMOTE_NAME_V1.fullmatch(value) is None
        or value in (".", "..")
    ):
        _fail("remote_name is not a safe single file name")
    return value


def _identity(metadata: os.stat_result) -> _IdentityV1:
    return _IdentityV1(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        bytes=metadata.st_size,
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        nlink=metadata.st_nlink,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _require_private_regular(
    metadata: os.stat_result, maximum_bytes: int, field: str
) -> _IdentityV1:
    if not stat.S_ISREG(metadata.st_mode):
        _fail(f"{field} is not a regular file")
    identity = _identity(metadata)
    if identity.uid != os.geteuid():
        _fail(f"{field} is not owned by the effective user")
    if identity.mode != 0o600:
        _fail(f"{field} mode is not 0600")
    if identity.nlink != 1:
        _fail(f"{field} link count is not one")
    if identity.bytes < 0 or identity.bytes > maximum_bytes:
        _fail(f"{field} exceeds its byte bound")
    return identity


def _open_directory_nofollow(path: str, field: str) -> int:
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        _fail(f"{field} is not an absolute canonical directory")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    current = os.open("/", flags)
    try:
        for component in pathlib.PurePosixPath(path).parts[1:]:
            if component in ("", ".", ".."):
                _fail(f"{field} contains an unsafe component")
            following = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


def _open_parent_nofollow(path: str, field: str) -> tuple[int, str]:
    parent, name = os.path.split(path)
    if not name or name in (".", ".."):
        _fail(f"{field} has no safe file name")
    return _open_directory_nofollow(parent, f"{field} parent"), name


def _open_source(path: str, maximum_bytes: int, field: str) -> _PinnedSourceV1:
    parent_fd, name = _open_parent_nofollow(path, field)
    fd = -1
    try:
        lexical = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        expected = _require_private_regular(lexical, maximum_bytes, field)
        fd = os.open(
            name,
            os.O_RDONLY
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_fd,
        )
        actual_metadata = os.fstat(fd)
        actual = _require_private_regular(actual_metadata, maximum_bytes, field)
        if actual != expected:
            _fail(f"{field} changed while it was opened")
        return _PinnedSourceV1(path, name, parent_fd, fd, actual)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)
        raise


def _named_identity(source: _PinnedSourceV1, maximum_bytes: int, field: str) -> _IdentityV1:
    metadata = os.stat(source.name, dir_fd=source.parent_fd, follow_symlinks=False)
    return _require_private_regular(metadata, maximum_bytes, field)


def _write_all(fd: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            _fail("sealed-artifact destination stopped accepting bytes")
        view = view[written:]


def _hash_fd(fd: int, maximum_bytes: int, expected_bytes: int) -> tuple[str, int]:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    while True:
        chunk = os.read(fd, _COPY_BUFFER_BYTES_V1)
        if not chunk:
            break
        count += len(chunk)
        if count > maximum_bytes:
            _fail("sealed-artifact source grew beyond its byte bound")
        digest.update(chunk)
    if count != expected_bytes:
        _fail("sealed-artifact source size changed during hashing")
    return digest.hexdigest(), count


def _stream_fd_to_fd(
    source_fd: int, target_fd: int, maximum_bytes: int, expected_bytes: int
) -> tuple[str, int]:
    os.lseek(source_fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    while True:
        chunk = os.read(source_fd, _COPY_BUFFER_BYTES_V1)
        if not chunk:
            break
        count += len(chunk)
        if count > maximum_bytes:
            _fail("sealed-artifact source grew beyond its byte bound")
        digest.update(chunk)
        _write_all(target_fd, chunk)
    if count != expected_bytes:
        _fail("sealed-artifact source size changed while it was copied")
    return digest.hexdigest(), count


def _facts(path: str, digest: str, identity: _IdentityV1) -> SealedArtifactFactsV1:
    if _HEX_SHA256_V1.fullmatch(digest) is None:
        _fail("sealed-artifact digest is not canonical SHA-256")
    return SealedArtifactFactsV1(
        path=path,
        sha256=digest,
        bytes=identity.bytes,
        mode=identity.mode,
        device=identity.device,
        inode=identity.inode,
        modified_ns=identity.modified_ns,
        changed_ns=identity.changed_ns,
        uid=identity.uid,
        nlink=identity.nlink,
    )


def _expected(expected: object, field: str) -> object:
    if isinstance(expected, Mapping):
        if field not in expected:
            _fail(f"expected sealed-artifact facts omit {field}")
        return expected[field]
    if not hasattr(expected, field):
        _fail(f"expected sealed-artifact facts omit {field}")
    return getattr(expected, field)


def _revalidate_open_source(
    path: str, maximum_bytes: int, expected_identity: _IdentityV1, expected_digest: str
) -> SealedArtifactFactsV1:
    reopened = _open_source(path, maximum_bytes, "sealed artifact")
    try:
        if reopened.identity != expected_identity:
            _fail("sealed-artifact source identity changed before its second pass")
        digest, _ = _hash_fd(reopened.fd, maximum_bytes, reopened.identity.bytes)
        if digest != expected_digest:
            _fail("sealed-artifact source digest changed before its second pass")
        if os.fstat(reopened.fd) and _identity(os.fstat(reopened.fd)) != expected_identity:
            _fail("sealed-artifact source identity changed during its second pass")
        if _named_identity(reopened, maximum_bytes, "sealed artifact") != expected_identity:
            _fail("sealed-artifact source path changed during its second pass")
        return _facts(path, digest, expected_identity)
    finally:
        reopened.close()


def _invoke_first_pass_hook(path: str) -> None:
    hook = _TEST_AFTER_FIRST_SOURCE_PASS_V1
    if hook is not None:
        hook(path)


def _private_target_parent(path: str) -> tuple[int, str, tuple[int, int]]:
    parent_fd, name = _open_parent_nofollow(path, "sealed-artifact target")
    try:
        metadata = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            _fail("sealed-artifact target parent is not effective-user-owned 0700")
        return parent_fd, name, (metadata.st_dev, metadata.st_ino)
    except BaseException:
        os.close(parent_fd)
        raise


def _fresh_target_identity(
    path: str,
    parent_identity: tuple[int, int],
    created_identity: tuple[int, int],
    maximum_bytes: int,
) -> _IdentityV1:
    fresh_parent, name = _open_parent_nofollow(path, "sealed-artifact target")
    try:
        parent_metadata = os.fstat(fresh_parent)
        if (parent_metadata.st_dev, parent_metadata.st_ino) != parent_identity:
            _fail("sealed-artifact target parent identity changed")
        metadata = os.stat(name, dir_fd=fresh_parent, follow_symlinks=False)
        identity = _require_private_regular(metadata, maximum_bytes, "sealed-artifact target")
        if (identity.device, identity.inode) != created_identity:
            _fail("sealed-artifact target path no longer names the created file")
        os.fsync(fresh_parent)
        return identity
    finally:
        os.close(fresh_parent)


def _cleanup_created_target(
    parent_fd: int, name: str, created_identity: tuple[int, int] | None
) -> None:
    if created_identity is None:
        return
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) == created_identity:
            os.unlink(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
    except FileNotFoundError:
        return
    except OSError:
        return


def _cleanup_facts_target(facts: SealedArtifactFactsV1) -> None:
    """Remove only the still-named inode created by this transport attempt."""

    parent_fd = -1
    try:
        parent_fd, name = _open_parent_nofollow(
            facts.path, "sealed-artifact failed target"
        )
        _cleanup_created_target(parent_fd, name, (facts.device, facts.inode))
    except (OSError, SealedArtifactTransportError):
        return
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def _copy_local_v1(source: str, target: str, maximum_bytes: int) -> SealedArtifactFactsV1:
    pinned = _open_source(source, maximum_bytes, "sealed-artifact source")
    parent_fd = -1
    target_fd = -1
    created_identity: tuple[int, int] | None = None
    try:
        parent_fd, target_name, parent_identity = _private_target_parent(target)
        target_fd = os.open(
            target_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        os.fchmod(target_fd, 0o600)
        created_metadata = os.fstat(target_fd)
        created_identity = (created_metadata.st_dev, created_metadata.st_ino)
        first_digest, first_bytes = _stream_fd_to_fd(
            pinned.fd, target_fd, maximum_bytes, pinned.identity.bytes
        )
        os.fsync(target_fd)
        _invoke_first_pass_hook(source)
        if _identity(os.fstat(pinned.fd)) != pinned.identity:
            _fail("sealed-artifact source changed after its first pass")
        if _named_identity(pinned, maximum_bytes, "sealed-artifact source") != pinned.identity:
            _fail("sealed-artifact source path changed after its first pass")
        _revalidate_open_source(source, maximum_bytes, pinned.identity, first_digest)

        target_identity = _require_private_regular(
            os.fstat(target_fd), maximum_bytes, "sealed-artifact target"
        )
        if target_identity.bytes != first_bytes:
            _fail("sealed-artifact target size differs from the copied bytes")
        os.close(target_fd)
        target_fd = -1
        target_identity = _fresh_target_identity(
            target, parent_identity, created_identity, maximum_bytes
        )
        facts = _facts(target, first_digest, target_identity)
        return revalidate_local_sealed_artifact_v1(target, facts)
    except BaseException:
        if target_fd >= 0:
            os.close(target_fd)
        if parent_fd >= 0:
            _cleanup_created_target(parent_fd, target_name, created_identity)
        raise
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
        pinned.close()


def _read_bounded_line(stream: BinaryIO, field: str) -> bytes:
    value = stream.readline(_MAX_FRAME_LINE_BYTES_V1 + 1)
    if len(value) > _MAX_FRAME_LINE_BYTES_V1 or not value.endswith(b"\n"):
        _fail(f"{field} is missing or oversized")
    return value[:-1]


def _parse_decimal(value: bytes, field: str, maximum: int | None = None) -> int:
    if not value or not value.isdigit() or (len(value) > 1 and value.startswith(b"0")):
        _fail(f"{field} is not canonical decimal")
    result = int(value)
    if maximum is not None and result > maximum:
        _fail(f"{field} exceeds its bound")
    return result


def _parse_hex(value: bytes, field: str) -> str:
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise SealedArtifactTransportError(f"{field} is not ASCII") from error
    if _HEX_SHA256_V1.fullmatch(decoded) is None:
        _fail(f"{field} is not canonical SHA-256")
    return decoded


def _process_stderr(error_file: BinaryIO) -> str:
    try:
        error_file.seek(0)
        value = error_file.read(8192)
    except (OSError, AttributeError):
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").strip()
    return str(value).strip()


def _stop_process(process: Any) -> None:
    try:
        process.kill()
    except (OSError, AttributeError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=10)
    except (OSError, AttributeError, subprocess.TimeoutExpired):
        pass


def _ssh_arguments(management: str, remote_arguments: tuple[str, ...]) -> list[str]:
    command = " ".join(shlex.quote(value) for value in remote_arguments)
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
        management,
        command,
    ]


def _copy_export_frame_v1(
    stream: BinaryIO,
    target: str,
    maximum_bytes: int,
) -> tuple[SealedArtifactFactsV1, tuple[str, str]]:
    header = _read_bounded_line(stream, "sealed-artifact export header").split(b" ")
    if len(header) != 2 or header[0] != _EXPORT_HEADER_V1:
        _fail("sealed-artifact export header differs")
    expected_bytes = _parse_decimal(header[1], "sealed-artifact export size", maximum_bytes)
    parent_fd = -1
    target_fd = -1
    created_identity: tuple[int, int] | None = None
    try:
        parent_fd, target_name, parent_identity = _private_target_parent(target)
        target_fd = os.open(
            target_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        os.fchmod(target_fd, 0o600)
        created = os.fstat(target_fd)
        created_identity = (created.st_dev, created.st_ino)
        digest = hashlib.sha256()
        remaining = expected_bytes
        while remaining:
            chunk = stream.read(min(_COPY_BUFFER_BYTES_V1, remaining))
            if not chunk:
                _fail("sealed-artifact export frame is truncated")
            if not isinstance(chunk, bytes):
                _fail("sealed-artifact export stream is not binary")
            remaining -= len(chunk)
            digest.update(chunk)
            _write_all(target_fd, chunk)
        trailer = _read_bounded_line(stream, "sealed-artifact export trailer").split(b" ")
        if len(trailer) != 4 or trailer[0] != _EXPORT_TRAILER_V1:
            _fail("sealed-artifact export trailer differs")
        trailer_bytes = _parse_decimal(trailer[1], "sealed-artifact trailer size", maximum_bytes)
        first_digest = _parse_hex(trailer[2], "sealed-artifact first remote digest")
        second_digest = _parse_hex(trailer[3], "sealed-artifact second remote digest")
        if stream.read(1) != b"":
            _fail("sealed-artifact export has trailing bytes")
        local_digest = digest.hexdigest()
        if (
            trailer_bytes != expected_bytes
            or first_digest != second_digest
            or first_digest != local_digest
        ):
            _fail("sealed-artifact export digest or size differs")
        os.fsync(target_fd)
        target_identity = _require_private_regular(
            os.fstat(target_fd), maximum_bytes, "sealed-artifact target"
        )
        if target_identity.bytes != expected_bytes:
            _fail("sealed-artifact export target size differs")
        os.close(target_fd)
        target_fd = -1
        target_identity = _fresh_target_identity(
            target, parent_identity, created_identity, maximum_bytes
        )
        facts = _facts(target, local_digest, target_identity)
        facts = revalidate_local_sealed_artifact_v1(target, facts)
        return facts, (first_digest, second_digest)
    except BaseException:
        if target_fd >= 0:
            os.close(target_fd)
        if parent_fd >= 0:
            _cleanup_created_target(parent_fd, target_name, created_identity)
        raise
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def _copy_remote_v1(
    management: str, source: str, target: str, maximum_bytes: int
) -> SealedArtifactFactsV1:
    arguments = _ssh_arguments(
        management,
        ("python3", "-c", _REMOTE_EXPORT_HELPER_V1, source, str(maximum_bytes)),
    )
    with tempfile.TemporaryFile() as error_file:
        process = _SSH_PROCESS_FACTORY_V1(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=error_file,
            close_fds=True,
        )
        if process.stdout is None:
            _stop_process(process)
            _fail("sealed-artifact exporter has no binary output")
        facts: SealedArtifactFactsV1 | None = None
        try:
            facts, _ = _copy_export_frame_v1(process.stdout, target, maximum_bytes)
            return_code = process.wait(timeout=300)
            if return_code != 0:
                detail = _process_stderr(error_file)
                _fail(f"sealed-artifact exporter failed{': ' + detail if detail else ''}")
            return facts
        except BaseException:
            _stop_process(process)
            if facts is not None:
                _cleanup_facts_target(facts)
            raise
        finally:
            try:
                process.stdout.close()
            except (OSError, AttributeError):
                pass


def copy_sealed_stage_artifact_v1(
    management: str,
    remote: bool,
    source: str | os.PathLike[str],
    target: str | os.PathLike[str],
    maximum_bytes: int,
) -> SealedArtifactFactsV1:
    """Copy one sealed artifact into a new coordinator-owned file."""

    bound = _maximum_bytes(maximum_bytes)
    source_path = _absolute_path(source, "sealed-artifact source")
    target_path = _absolute_path(target, "sealed-artifact target")
    if not isinstance(remote, bool):
        _fail("remote is not boolean")
    if remote:
        return _copy_remote_v1(_management(management), source_path, target_path, bound)
    return _copy_local_v1(source_path, target_path, bound)


def revalidate_local_sealed_artifact_v1(
    path: str | os.PathLike[str], expected_facts: object
) -> SealedArtifactFactsV1:
    """Freshly reopen and authenticate a coordinator-local sealed artifact."""

    local_path = _absolute_path(path, "sealed-artifact path")
    expected_path = _absolute_path(
        _expected(expected_facts, "path"), "expected sealed-artifact path"  # type: ignore[arg-type]
    )
    if local_path != expected_path:
        _fail("sealed-artifact path differs from its expected facts")
    expected_bytes = _expected(expected_facts, "bytes")
    if (
        isinstance(expected_bytes, bool)
        or not isinstance(expected_bytes, int)
        or expected_bytes < 0
        or expected_bytes > MAX_SEALED_ARTIFACT_BYTES_V1
    ):
        _fail("expected sealed-artifact byte count is invalid")
    expected_digest = _expected(expected_facts, "sha256")
    if not isinstance(expected_digest, str) or _HEX_SHA256_V1.fullmatch(expected_digest) is None:
        _fail("expected sealed-artifact digest is invalid")
    opened = _open_source(
        local_path,
        max(1, expected_bytes),
        "sealed artifact",
    )
    try:
        digest, count = _hash_fd(opened.fd, max(1, expected_bytes), opened.identity.bytes)
        if count != expected_bytes or digest != expected_digest:
            _fail("sealed-artifact content differs from its expected facts")
        if _identity(os.fstat(opened.fd)) != opened.identity:
            _fail("sealed-artifact identity changed while it was revalidated")
        if _named_identity(opened, max(1, expected_bytes), "sealed artifact") != opened.identity:
            _fail("sealed-artifact path changed while it was revalidated")
        current = _facts(local_path, digest, opened.identity)
        for field in (
            "mode",
            "device",
            "inode",
            "modified_ns",
            "changed_ns",
            "uid",
            "nlink",
        ):
            if getattr(current, field) != _expected(expected_facts, field):
                _fail(f"sealed-artifact {field} differs from its expected facts")
        return current
    finally:
        opened.close()


def _binary_write(stream: BinaryIO, value: bytes) -> None:
    written = stream.write(value)
    if written is not None and written != len(value):
        _fail("sealed-artifact SSH input accepted a partial write")


def _parse_receipt_v1(
    stream: BinaryIO, remote_path: str, maximum_bytes: int
) -> SealedArtifactFactsV1:
    fields = _read_bounded_line(stream, "sealed-artifact receipt").split(b" ")
    if len(fields) != 11 or fields[0] != _STAGE_RECEIPT_V1:
        _fail("sealed-artifact receipt differs")
    size = _parse_decimal(fields[1], "sealed-artifact receipt size", maximum_bytes)
    first_digest = _parse_hex(fields[2], "sealed-artifact receipt first digest")
    second_digest = _parse_hex(fields[3], "sealed-artifact receipt second digest")
    numeric = [
        _parse_decimal(value, f"sealed-artifact receipt field {index}")
        for index, value in enumerate(fields[4:], start=4)
    ]
    if stream.read(1) != b"":
        _fail("sealed-artifact receipt has trailing bytes")
    if first_digest != second_digest:
        _fail("sealed-artifact receipt digests differ")
    device, inode, modified_ns, changed_ns, uid, nlink, mode = numeric
    if mode != 0o600 or nlink != 1:
        _fail("sealed-artifact receipt mode or link count differs")
    return SealedArtifactFactsV1(
        path=remote_path,
        sha256=first_digest,
        bytes=size,
        mode=mode,
        device=device,
        inode=inode,
        modified_ns=modified_ns,
        changed_ns=changed_ns,
        uid=uid,
        nlink=nlink,
    )


def stage_sealed_artifact_on_observer_v1(
    management: str,
    source: str | os.PathLike[str],
    remote_reports_root: str | os.PathLike[str],
    remote_name: str,
    maximum_bytes: int,
) -> SealedArtifactFactsV1:
    """Stage one coordinator artifact into a new private observer file."""

    bound = _maximum_bytes(maximum_bytes)
    management_value = _management(management)
    source_path = _absolute_path(source, "sealed-artifact source")
    reports_root = _absolute_path(remote_reports_root, "observer reports root")
    name = _remote_name(remote_name)
    remote_path = f"{reports_root}/{name}"

    initial = _open_source(source_path, bound, "sealed-artifact source")
    try:
        first_digest, _ = _hash_fd(initial.fd, bound, initial.identity.bytes)
        if _identity(os.fstat(initial.fd)) != initial.identity:
            _fail("sealed-artifact source changed during its first staging pass")
        if _named_identity(initial, bound, "sealed-artifact source") != initial.identity:
            _fail("sealed-artifact source path changed during its first staging pass")
        initial_facts = _facts(source_path, first_digest, initial.identity)
    finally:
        initial.close()
    _invoke_first_pass_hook(source_path)

    arguments = _ssh_arguments(
        management_value,
        (
            "python3",
            "-c",
            _REMOTE_RECEIVER_HELPER_V1,
            reports_root,
            name,
            str(bound),
            str(initial_facts.bytes),
            initial_facts.sha256,
        ),
    )
    with tempfile.TemporaryFile() as error_file:
        process = _SSH_PROCESS_FACTORY_V1(
            arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=error_file,
            close_fds=True,
        )
        if process.stdin is None or process.stdout is None:
            _stop_process(process)
            _fail("sealed-artifact observer receiver has no binary pipes")
        reopened: _PinnedSourceV1 | None = None
        try:
            reopened = _open_source(source_path, bound, "sealed-artifact source")
            if reopened.identity != initial.identity:
                _fail("sealed-artifact source identity changed before observer staging")
            header = b" ".join(
                (
                    _STAGE_HEADER_V1,
                    str(initial_facts.bytes).encode("ascii"),
                    initial_facts.sha256.encode("ascii"),
                )
            ) + b"\n"
            _binary_write(process.stdin, header)
            os.lseek(reopened.fd, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            count = 0
            while True:
                chunk = os.read(reopened.fd, _COPY_BUFFER_BYTES_V1)
                if not chunk:
                    break
                count += len(chunk)
                if count > bound:
                    _fail("sealed-artifact source grew during observer staging")
                digest.update(chunk)
                _binary_write(process.stdin, chunk)
            second_digest = digest.hexdigest()
            trailer = b" ".join(
                (
                    _STAGE_TRAILER_V1,
                    str(count).encode("ascii"),
                    second_digest.encode("ascii"),
                )
            ) + b"\n"
            _binary_write(process.stdin, trailer)
            try:
                process.stdin.flush()
            except AttributeError:
                pass
            process.stdin.close()
            if (
                count != initial_facts.bytes
                or second_digest != initial_facts.sha256
                or _identity(os.fstat(reopened.fd)) != initial.identity
                or _named_identity(reopened, bound, "sealed-artifact source")
                != initial.identity
            ):
                _fail("sealed-artifact source changed during observer staging")
            receipt = _parse_receipt_v1(process.stdout, remote_path, bound)
            return_code = process.wait(timeout=300)
            if return_code != 0:
                detail = _process_stderr(error_file)
                _fail(f"sealed-artifact observer receiver failed{': ' + detail if detail else ''}")
            if receipt.bytes != initial_facts.bytes or receipt.sha256 != initial_facts.sha256:
                _fail("sealed-artifact observer receipt differs from its source")
            revalidate_local_sealed_artifact_v1(source_path, initial_facts)
            return receipt
        except BaseException:
            _stop_process(process)
            raise
        finally:
            if reopened is not None:
                reopened.close()
            for stream in (process.stdin, process.stdout):
                try:
                    stream.close()
                except (OSError, AttributeError):
                    pass


# These helpers execute under a fixed ``python3 -c`` command.  They accept only
# a preselected absolute source/root, one safe name, and numeric/hash bounds.
# They deliberately contain no artifact discovery or authority reconstruction.
_REMOTE_EXPORT_HELPER_V1 = r'''
import hashlib, os, pathlib, stat, sys

def die(message):
    raise RuntimeError(message)

def directory(path):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        for part in pathlib.PurePosixPath(path).parts[1:]:
            if part in ('', '.', '..'):
                die('unsafe path')
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise

def identity(value):
    return (value.st_dev, value.st_ino, value.st_size, stat.S_IMODE(value.st_mode), value.st_uid, value.st_gid, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)

def open_source(path, maximum):
    parent, name = os.path.split(path)
    if not os.path.isabs(path) or os.path.normpath(path) != path or not name:
        die('unsafe source')
    parent_fd = directory(parent)
    fd = -1
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size < 0 or before.st_size > maximum:
            die('source contract')
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0), dir_fd=parent_fd)
        after = os.fstat(fd)
        if identity(before) != identity(after):
            die('source changed at open')
        return parent_fd, fd, name, identity(after)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)
        raise

def named(parent_fd, name):
    return identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))

def digest_file(fd, expected, maximum, emit):
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        count += len(chunk)
        if count > maximum:
            die('source exceeds bound')
        digest.update(chunk)
        if emit:
            sys.stdout.buffer.write(chunk)
    if count != expected:
        die('source size changed')
    return digest.hexdigest(), count

try:
    source = sys.argv[1]
    maximum = int(sys.argv[2])
    if maximum < 1 or maximum > 512 * 1024 * 1024:
        die('invalid maximum')
    parent_fd, fd, name, original = open_source(source, maximum)
    try:
        sys.stdout.buffer.write(('TRNM_SEALED_ARTIFACT_EXPORT_V1 %d\n' % original[2]).encode('ascii'))
        first, count = digest_file(fd, original[2], maximum, True)
        sys.stdout.buffer.flush()
        if identity(os.fstat(fd)) != original or named(parent_fd, name) != original:
            die('source changed after first pass')
    finally:
        os.close(fd)
        os.close(parent_fd)
    parent_fd, fd, name, reopened = open_source(source, maximum)
    try:
        if reopened != original:
            die('source changed before second pass')
        second, second_count = digest_file(fd, original[2], maximum, False)
        if identity(os.fstat(fd)) != original or named(parent_fd, name) != original:
            die('source changed after second pass')
    finally:
        os.close(fd)
        os.close(parent_fd)
    if count != second_count or first != second:
        die('source passes differ')
    sys.stdout.buffer.write(('TRNM_SEALED_ARTIFACT_EXPORT_END_V1 %d %s %s\n' % (count, first, second)).encode('ascii'))
    sys.stdout.buffer.flush()
except BaseException as error:
    sys.stderr.write('sealed artifact export failed: %s\n' % error)
    sys.exit(71)
'''


_REMOTE_RECEIVER_HELPER_V1 = r'''
import hashlib, os, pathlib, re, stat, sys

HEX = re.compile(r'^[0-9a-f]{64}$')

def die(message):
    raise RuntimeError(message)

def directory(path):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        for part in pathlib.PurePosixPath(path).parts[1:]:
            if part in ('', '.', '..'):
                die('unsafe path')
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise

def identity(value):
    return (value.st_dev, value.st_ino, value.st_size, stat.S_IMODE(value.st_mode), value.st_uid, value.st_gid, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)

def read_line(stream):
    value = stream.readline(4097)
    if len(value) > 4096 or not value.endswith(b'\n'):
        die('invalid frame line')
    return value[:-1]

parent_fd = -1
target_fd = -1
created = None
name = ''
try:
    root, name, maximum_raw, expected_raw, expected_hash = sys.argv[1:6]
    maximum = int(maximum_raw)
    expected = int(expected_raw)
    if maximum < 1 or maximum > 512 * 1024 * 1024 or expected < 0 or expected > maximum or HEX.fullmatch(expected_hash) is None:
        die('invalid bounds')
    if not os.path.isabs(root) or os.path.normpath(root) != root or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}', name) or name in ('.', '..'):
        die('unsafe target')
    parent_fd = directory(root)
    root_stat = os.fstat(parent_fd)
    if not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != os.geteuid() or stat.S_IMODE(root_stat.st_mode) != 0o700:
        die('reports root contract')
    header = read_line(sys.stdin.buffer).split(b' ')
    if len(header) != 3 or header[0] != b'TRNM_SEALED_ARTIFACT_STAGE_V1' or int(header[1]) != expected or header[2].decode('ascii') != expected_hash:
        die('header differs')
    target_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
    os.fchmod(target_fd, 0o600)
    target_start = os.fstat(target_fd)
    created = (target_start.st_dev, target_start.st_ino)
    digest = hashlib.sha256()
    remaining = expected
    while remaining:
        chunk = sys.stdin.buffer.read(min(1024 * 1024, remaining))
        if not chunk:
            die('truncated body')
        remaining -= len(chunk)
        digest.update(chunk)
        view = memoryview(chunk)
        while view:
            written = os.write(target_fd, view)
            if written <= 0:
                die('short target write')
            view = view[written:]
    trailer = read_line(sys.stdin.buffer).split(b' ')
    if len(trailer) != 3 or trailer[0] != b'TRNM_SEALED_ARTIFACT_STAGE_END_V1' or int(trailer[1]) != expected or trailer[2].decode('ascii') != expected_hash:
        die('trailer differs')
    if sys.stdin.buffer.read(1) != b'':
        die('trailing bytes')
    first = digest.hexdigest()
    if first != expected_hash:
        die('body digest differs')
    os.fsync(target_fd)
    written_stat = os.fstat(target_fd)
    written_identity = identity(written_stat)
    if not stat.S_ISREG(written_stat.st_mode) or written_stat.st_uid != os.geteuid() or stat.S_IMODE(written_stat.st_mode) != 0o600 or written_stat.st_nlink != 1 or written_stat.st_size != expected:
        die('written target contract')
    os.close(target_fd)
    target_fd = -1
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if identity(named) != written_identity:
        die('target path changed')
    os.fsync(parent_fd)
    reopened = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0), dir_fd=parent_fd)
    try:
        if identity(os.fstat(reopened)) != written_identity:
            die('target changed before second pass')
        second_hash = hashlib.sha256()
        count = 0
        while True:
            chunk = os.read(reopened, 1024 * 1024)
            if not chunk:
                break
            count += len(chunk)
            if count > maximum:
                die('target exceeds bound')
            second_hash.update(chunk)
        second = second_hash.hexdigest()
        if count != expected or second != first or identity(os.fstat(reopened)) != written_identity or identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != written_identity:
            die('target second pass differs')
    finally:
        os.close(reopened)
    values = (expected, first, second, written_identity[0], written_identity[1], written_identity[7], written_identity[8], written_identity[4], written_identity[6], written_identity[3])
    sys.stdout.write('TRNM_SEALED_ARTIFACT_RECEIPT_V1 %d %s %s %d %d %d %d %d %d %d\n' % values)
    sys.stdout.flush()
except BaseException as error:
    if target_fd >= 0:
        os.close(target_fd)
    if parent_fd >= 0 and created is not None:
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == created:
                os.unlink(name, dir_fd=parent_fd)
                os.fsync(parent_fd)
        except OSError:
            pass
    sys.stderr.write('sealed artifact receive failed: %s\n' % error)
    sys.exit(72)
finally:
    if target_fd >= 0:
        os.close(target_fd)
    if parent_fd >= 0:
        os.close(parent_fd)
'''


__all__ = (
    "MAX_SEALED_ARTIFACT_BYTES_V1",
    "SealedArtifactFactsV1",
    "SealedArtifactTransportError",
    "copy_sealed_stage_artifact_v1",
    "revalidate_local_sealed_artifact_v1",
    "stage_sealed_artifact_on_observer_v1",
)
