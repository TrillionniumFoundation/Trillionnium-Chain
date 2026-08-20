#!/usr/bin/env python3
"""Build one source candidate twice and emit both architecture-local lab binaries."""

from __future__ import annotations

import argparse
import dataclasses
import errno
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
CHECK = HERE / "check_source_candidate.py"
PACKAGE = "trnm-poco-lab-validator"
VALIDATOR_BINARY = "trnm-poco-lab-validator"
MATERIAL_BUILDER_BINARY = "trnm-poco-lab-material-builder"
MAX_CANDIDATE_BYTES = 4 * 1024 * 1024 * 1024
MAX_BINARY_BYTES = 1024 * 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EMPTY_STATUS_SHA256 = hashlib.sha256(b"").hexdigest()
CARGO_LOCK_PATH = "trillionnium/Cargo.lock"
STRICT_CANDIDATE_REPORT_KEYS = {
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


@dataclasses.dataclass(frozen=True)
class FrozenBinaryV1:
    payload: bytes
    sha256: str
    size: int


@dataclasses.dataclass(frozen=True)
class BuildResultV1:
    binaries: dict[str, pathlib.Path]
    rustc_vv: bytes


@dataclasses.dataclass
class OutputSlotV1:
    path: pathlib.Path
    parent_fd: int
    parent_dev: int
    parent_ino: int
    name: str
    created_dev: int | None = None
    created_ino: int | None = None


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 reproducible lab build failed: {message}")


def fsync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as error:
        if sys.platform == "darwin" and error.errno in {errno.EINVAL, errno.ENOTSUP}:
            return
        raise


def ambient_override_names(environment: dict[str, str]) -> list[str]:
    exact = {
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "RUSTC",
        "RUSTDOC",
        "RUSTC_BOOTSTRAP",
        "RUSTUP_TOOLCHAIN",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "CARGO_BUILD_TARGET_DIR",
        "CARGO_TARGET_DIR",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CC",
        "CXX",
        "AR",
        "LD",
        "RANLIB",
        "CFLAGS",
        "CXXFLAGS",
        "CPPFLAGS",
        "LDFLAGS",
        "SDKROOT",
        "DEVELOPER_DIR",
        "MACOSX_DEPLOYMENT_TARGET",
    }
    return sorted(
        key
        for key in environment
        if key in exact
        or (key.startswith("CARGO_") and key != "CARGO_HOME")
        or (key.startswith("RUST") and key != "RUSTUP_HOME")
        or key.startswith("CARGO_PROFILE_")
        or key.startswith("CARGO_TARGET_")
        or key.startswith("CARGO_BUILD_")
        or (key.startswith("RUSTC_") and key.endswith("WRAPPER"))
        or key.startswith("PKG_CONFIG_")
        or key.startswith("BINDGEN_")
        or key.startswith("LIBCLANG_")
        or key.startswith("OPENSSL_")
        or key in {"CLANG_PATH", "CMAKE", "MAKEFLAGS", "NUM_JOBS"}
    )


def reject_config_path(path: pathlib.Path, field: str) -> None:
    if not path.exists() and not path.is_symlink():
        return
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        fail(f"{field} is not one regular non-symlink file: {path}")
    fail(f"{field} is forbidden: {path}")


def resolved_cargo_home() -> pathlib.Path:
    raw = pathlib.Path(os.environ.get("CARGO_HOME", str(pathlib.Path.home() / ".cargo")))
    if not raw.is_absolute():
        raw = pathlib.Path.cwd() / raw
    unresolved = raw.absolute()
    try:
        metadata = unresolved.lstat()
        resolved = unresolved.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve Cargo home: {error}")
    if unresolved != resolved or unresolved.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        fail("Cargo home must be one real non-symlink directory")
    return resolved


def reject_cargo_home_configs(cargo_home: pathlib.Path) -> None:
    for name in ("config.toml", "config"):
        reject_config_path(cargo_home / name, "ambient Cargo config")


def reject_ambient_build_overrides() -> pathlib.Path:
    overrides = ambient_override_names(os.environ)
    if overrides:
        fail(f"ambient build override is forbidden: {overrides[0]}")
    cargo_home = resolved_cargo_home()
    reject_cargo_home_configs(cargo_home)
    return cargo_home


def reject_ambient_ancestor_configs(source: pathlib.Path) -> None:
    current = source
    while True:
        for name in ("config.toml", "config"):
            reject_config_path(
                current / ".cargo" / name,
                "ambient ancestor Cargo config",
            )
        if current.parent == current:
            break
        current = current.parent


def freeze_candidate(source: pathlib.Path, target: pathlib.Path) -> None:
    metadata = source.lstat()
    if source.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        fail("candidate input must be one regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_CANDIDATE_BYTES:
        fail("candidate input size crosses its bound")
    source_descriptor = os.open(
        source,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    target_descriptor: int | None = None
    try:
        opened = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
        ):
            fail("candidate input changed identity while opening")
        target_descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        with os.fdopen(source_descriptor, "rb", closefd=False) as input_file, os.fdopen(
            target_descriptor, "wb", closefd=False
        ) as output_file:
            os.fchmod(output_file.fileno(), 0o600)
            remaining = opened.st_size
            while remaining:
                chunk = input_file.read(min(1024 * 1024, remaining))
                if not chunk:
                    fail("candidate input truncated during pinned copy")
                output_file.write(chunk)
                remaining -= len(chunk)
            if input_file.read(1):
                fail("candidate input grew during pinned copy")
            after = os.fstat(input_file.fileno())
            if (
                after.st_dev != opened.st_dev
                or after.st_ino != opened.st_ino
                or after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
            ):
                fail("candidate input changed during pinned copy")
            output_file.flush()
            os.fsync(output_file.fileno())
    except BaseException:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(source_descriptor)
        if target_descriptor is not None:
            os.close(target_descriptor)


def unique_json_object(pairs):
    value = {}
    for key, child in pairs:
        if key in value:
            fail(f"source-candidate verifier returned duplicate JSON key {key!r}")
        value[key] = child
    return value


def validate_strict_candidate_report(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != STRICT_CANDIDATE_REPORT_KEYS:
        fail("source-candidate verifier returned fields outside the strict contract")
    object_format = value.get("git_object_format")
    oid_length = 40 if object_format == "sha1" else 64 if object_format == "sha256" else 0
    base_commit = value.get("base_commit")
    tree_oid = value.get("git_tree_oid")
    if (
        value.get("source_profile") != "clean-commit-v1"
        or not isinstance(value.get("source_candidate_sha256"), str)
        or not HEX64.fullmatch(value["source_candidate_sha256"])
        or type(value.get("archive_bytes")) is not int
        or value["archive_bytes"] <= 0
        or type(value.get("file_count")) is not int
        or value["file_count"] <= 0
        or type(value.get("source_bytes")) is not int
        or value["source_bytes"] < 0
        or not isinstance(base_commit, str)
        or len(base_commit) != oid_length
        or re.fullmatch(r"[0-9a-f]+", base_commit) is None
        or not isinstance(tree_oid, str)
        or len(tree_oid) != oid_length
        or re.fullmatch(r"[0-9a-f]+", tree_oid) is None
        or value.get("git_status_sha256") != EMPTY_STATUS_SHA256
        or value.get("cargo_lock_path") != CARGO_LOCK_PATH
        or not isinstance(value.get("cargo_lock_sha256"), str)
        or not HEX64.fullmatch(value["cargo_lock_sha256"])
        or type(value.get("cargo_lock_bytes")) is not int
        or value["cargo_lock_bytes"] <= 0
        or value.get("production_activation") is not False
        or value.get("geo_wan_evidence") is not False
    ):
        fail("source-candidate verifier returned a non-canonical strict result")
    return value


def run_candidate_checker(candidate: pathlib.Path) -> dict[str, object]:
    checked = subprocess.run(
        [sys.executable, str(CHECK), str(candidate), "--require-clean"],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        value = json.loads(checked.stdout, object_pairs_hook=unique_json_object)
    except json.JSONDecodeError as error:
        fail(f"source-candidate verifier returned invalid JSON: {error}")
    return validate_strict_candidate_report(value)


def verify_cargo_lock(source: pathlib.Path, candidate_report: dict[str, object]) -> None:
    lock = source / CARGO_LOCK_PATH
    metadata = lock.lstat()
    if (
        lock.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > MAX_CANDIDATE_BYTES
    ):
        fail("extracted active workspace Cargo.lock is not one bounded regular file")
    descriptor = os.open(lock, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
            or opened.st_mtime_ns != metadata.st_mtime_ns
        ):
            fail("extracted active workspace Cargo.lock changed identity while opening")
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail("extracted active workspace Cargo.lock truncated during read")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail("extracted active workspace Cargo.lock grew during read")
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
        ):
            fail("extracted active workspace Cargo.lock changed during read")
    finally:
        os.close(descriptor)
    if (
        opened.st_size != candidate_report["cargo_lock_bytes"]
        or digest.hexdigest() != candidate_report["cargo_lock_sha256"]
    ):
        fail("extracted active workspace Cargo.lock differs from strict candidate report")


def extract(candidate: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    destination.mkdir(mode=0o700)
    with tarfile.open(candidate, "r:") as archive:
        for member in archive.getmembers():
            if not member.isfile() or not member.name.startswith("source/"):
                fail("verified candidate unexpectedly contains a non-regular member")
            relative = pathlib.PurePosixPath(member.name)
            if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
                fail("verified candidate member escapes extraction root")
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                fail("verified candidate member lacks a byte stream")
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, member.mode)
            try:
                with os.fdopen(descriptor, "wb") as output:
                    shutil.copyfileobj(stream, output, length=1024 * 1024)
            except BaseException:
                try:
                    target.unlink()
                except FileNotFoundError:
                    pass
                raise
            if target.stat().st_size != member.size:
                fail("candidate member changed length while extracting")
    return destination / "source"


def isolated_build_environment(
    source: pathlib.Path,
    target: pathlib.Path,
    cargo_home: pathlib.Path,
) -> dict[str, str]:
    path_value = os.environ.get("PATH")
    if not path_value:
        fail("PATH must name the native build tools")
    for entry in path_value.split(os.pathsep):
        if not entry or not pathlib.Path(entry).is_absolute():
            fail("PATH may contain only absolute non-empty entries")
    environment_root = target.parent / f"environment-{target.name}"
    environment_root.mkdir(mode=0o700)
    temporary = environment_root / "tmp"
    temporary.mkdir(mode=0o700)
    environment = {
        "PATH": path_value,
        "HOME": str(environment_root),
        "TMPDIR": str(temporary),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TERM_COLOR": "never",
        "CARGO_TARGET_DIR": str(target),
        "CARGO_HOME": str(cargo_home),
        "SOURCE_DATE_EPOCH": "0",
        "TZ": "UTC",
        "LC_ALL": "C",
        "LANG": "C",
        "RUSTFLAGS": (
            f"--remap-path-prefix={source}=/trnm-source "
            f"--remap-path-prefix={target}=/trnm-target "
            f"--remap-path-prefix={cargo_home}=/trnm-cargo-home "
            f"--remap-path-prefix={environment_root}=/trnm-environment"
        ),
    }
    rustup_home_value = os.environ.get("RUSTUP_HOME")
    if rustup_home_value is None:
        default_rustup_home = pathlib.Path.home() / ".rustup"
        if default_rustup_home.exists() or default_rustup_home.is_symlink():
            rustup_home_value = str(default_rustup_home)
    if rustup_home_value is not None:
        rustup_home = pathlib.Path(rustup_home_value)
        if not rustup_home.is_absolute():
            rustup_home = pathlib.Path.cwd() / rustup_home
        unresolved = rustup_home.absolute()
        try:
            metadata = unresolved.lstat()
            resolved = unresolved.resolve(strict=True)
        except OSError as error:
            fail(f"cannot resolve Rustup home: {error}")
        if (
            unresolved != resolved
            or unresolved.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            fail("Rustup home must be one real non-symlink directory")
        environment["RUSTUP_HOME"] = str(resolved)
    return environment


def rustc_version(source: pathlib.Path, environment: dict[str, str]) -> bytes:
    result = subprocess.run(
        ["rustc", "-vV"],
        check=True,
        cwd=source,
        env=environment,
        capture_output=True,
    )
    if not result.stdout or len(result.stdout) > 64 * 1024 or result.stderr:
        fail("candidate-selected rustc -vV output crosses its exact bound")
    try:
        result.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"candidate-selected rustc -vV is not UTF-8: {error}")
    return result.stdout


def build(
    source: pathlib.Path,
    target: pathlib.Path,
    cargo_home: pathlib.Path,
) -> BuildResultV1:
    manifest = source / "trillionnium/Cargo.toml"
    if not manifest.is_file() or manifest.is_symlink():
        fail("candidate lacks the active Trillionnium Cargo workspace")
    reject_cargo_home_configs(cargo_home)
    reject_ambient_ancestor_configs(source)
    environment = isolated_build_environment(source, target, cargo_home)
    rustc_before = rustc_version(source, environment)
    subprocess.run(
        [
            "cargo",
            "build",
            "--manifest-path",
            str(manifest),
            "--locked",
            "--offline",
            "--release",
            "-p",
            PACKAGE,
            "--bin",
            VALIDATOR_BINARY,
            "--bin",
            MATERIAL_BUILDER_BINARY,
        ],
        check=True,
        cwd=source,
        env=environment,
        stdout=sys.stderr,
    )
    reject_cargo_home_configs(cargo_home)
    reject_ambient_ancestor_configs(source)
    rustc_after = rustc_version(source, environment)
    if rustc_before != rustc_after:
        fail("candidate-selected rustc changed across the native build")
    binaries = {
        "validator": target / "release" / VALIDATOR_BINARY,
        "material_builder": target / "release" / MATERIAL_BUILDER_BINARY,
    }
    for role, binary in binaries.items():
        if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
            fail(f"Cargo did not emit one executable regular {role} binary")
    return BuildResultV1(binaries=binaries, rustc_vv=rustc_after)


def build_verified_pair(
    left_source: pathlib.Path,
    right_source: pathlib.Path,
    left_target: pathlib.Path,
    right_target: pathlib.Path,
    cargo_home: pathlib.Path,
    candidate_report: dict[str, object],
) -> tuple[BuildResultV1, BuildResultV1]:
    # Both extracted locks must pass before the first rustc/Cargo subprocess.
    verify_cargo_lock(left_source, candidate_report)
    verify_cargo_lock(right_source, candidate_report)
    verify_cargo_lock(left_source, candidate_report)
    left = build(left_source, left_target, cargo_home)
    verify_cargo_lock(right_source, candidate_report)
    right = build(right_source, right_target, cargo_home)
    return left, right


def make_build_report(
    candidate_report: dict[str, object],
    hashes: dict[str, str],
    sizes: dict[str, int],
    rustc_vv: bytes,
    slots: dict[str, OutputSlotV1],
) -> dict[str, object]:
    rustc = rustc_vv.decode("utf-8")
    host = next(
        (
            line.removeprefix("host: ")
            for line in rustc.splitlines()
            if line.startswith("host: ")
        ),
        None,
    )
    if host is None:
        fail("rustc -vV omitted host triple")
    return {
        "schema_version": 3,
        "source_candidate_sha256": candidate_report["source_candidate_sha256"],
        "source_candidate_profile": candidate_report["source_profile"],
        "source_base_commit": candidate_report["base_commit"],
        "source_git_object_format": candidate_report["git_object_format"],
        "source_git_tree_oid": candidate_report["git_tree_oid"],
        "source_git_status_sha256": candidate_report["git_status_sha256"],
        "cargo_lock_path": candidate_report["cargo_lock_path"],
        "cargo_lock_sha256": candidate_report["cargo_lock_sha256"],
        "cargo_lock_bytes": candidate_report["cargo_lock_bytes"],
        "validator_binary_sha256": hashes["validator"],
        "validator_binary_bytes": sizes["validator"],
        "material_builder_binary_sha256": hashes["material_builder"],
        "material_builder_binary_bytes": sizes["material_builder"],
        "host_triple": host,
        "rustc_vv_sha256": hashlib.sha256(rustc_vv).hexdigest(),
        "reproducible_build": True,
        "independent_build_count": 2,
        "output_validator_binary": str(slots["validator"].path),
        "output_material_builder_binary": str(slots["material_builder"].path),
        "production_activation": False,
        "geo_wan_evidence": False,
    }


def freeze_binary(path: pathlib.Path, field: str) -> FrozenBinaryV1:
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_BINARY_BYTES
        or metadata.st_mode & 0o111 == 0
    ):
        fail(f"{field} must be one bounded executable regular non-symlink file")
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
            or opened.st_mode & 0o111 == 0
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
    payload = b"".join(chunks)
    return FrozenBinaryV1(payload, hashlib.sha256(payload).hexdigest(), len(payload))


def prepare_output_slot(path: pathlib.Path, role: str) -> OutputSlotV1:
    if not path.is_absolute():
        path = pathlib.Path.cwd() / path
    unresolved_parent = path.parent.absolute()
    try:
        metadata = unresolved_parent.lstat()
        resolved_parent = unresolved_parent.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve output {role} parent: {error}")
    if (
        unresolved_parent != resolved_parent
        or unresolved_parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or path.name in {"", ".", ".."}
    ):
        fail(f"output {role} parent must be one real non-symlink directory")
    parent_fd = os.open(
        resolved_parent,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    opened = os.fstat(parent_fd)
    if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
        os.close(parent_fd)
        fail(f"output {role} parent changed identity while opening")
    try:
        os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except BaseException:
        os.close(parent_fd)
        raise
    else:
        os.close(parent_fd)
        fail(f"output {role} binary already exists; candidate artifacts are immutable")
    return OutputSlotV1(
        resolved_parent / path.name,
        parent_fd,
        opened.st_dev,
        opened.st_ino,
        path.name,
    )


def emit_binary(payload: bytes, slot: OutputSlotV1) -> None:
    descriptor = os.open(
        slot.name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | os.O_NOFOLLOW,
        0o755,
        dir_fd=slot.parent_fd,
    )
    created = os.fstat(descriptor)
    slot.created_dev = created.st_dev
    slot.created_ino = created.st_ino
    try:
        with os.fdopen(descriptor, "wb") as destination:
            os.fchmod(destination.fileno(), 0o755)
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
        fsync_directory(slot.parent_fd)
    except BaseException:
        unlink_owned_output(slot)
        raise


def freeze_emitted_binary(slot: OutputSlotV1, field: str) -> FrozenBinaryV1:
    descriptor = os.open(
        slot.name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=slot.parent_fd,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            slot.created_dev is None
            or slot.created_ino is None
            or opened.st_dev != slot.created_dev
            or opened.st_ino != slot.created_ino
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_size <= 0
            or opened.st_size > MAX_BINARY_BYTES
            or opened.st_mode & 0o111 == 0
        ):
            fail(f"{field} changed identity after emission")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{field} truncated during emitted readback")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"{field} grew during emitted readback")
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or after.st_mode != opened.st_mode
        ):
            fail(f"{field} changed during emitted readback")
    finally:
        os.close(descriptor)
    try:
        named = slot.path.lstat()
        current_parent = slot.path.parent.lstat()
    except OSError as error:
        fail(f"{field} output path is no longer reachable: {error}")
    if (
        named.st_dev != opened.st_dev
        or named.st_ino != opened.st_ino
        or current_parent.st_dev != slot.parent_dev
        or current_parent.st_ino != slot.parent_ino
    ):
        fail(f"{field} output path changed after emission")
    payload = b"".join(chunks)
    return FrozenBinaryV1(payload, hashlib.sha256(payload).hexdigest(), len(payload))


def unlink_owned_output(slot: OutputSlotV1) -> None:
    if slot.created_dev is None or slot.created_ino is None:
        return
    try:
        metadata = os.stat(slot.name, dir_fd=slot.parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if metadata.st_dev == slot.created_dev and metadata.st_ino == slot.created_ino:
        os.unlink(slot.name, dir_fd=slot.parent_fd)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=pathlib.Path)
    parser.add_argument("--output-validator-binary", required=True, type=pathlib.Path)
    parser.add_argument("--output-material-builder", required=True, type=pathlib.Path)
    args = parser.parse_args()
    cargo_home = reject_ambient_build_overrides()
    candidate = args.candidate
    if not candidate.is_absolute():
        candidate = pathlib.Path.cwd() / candidate
    requested_outputs = {
        "validator": args.output_validator_binary,
        "material_builder": args.output_material_builder,
    }
    slots: dict[str, OutputSlotV1] = {}
    try:
        for role, output in requested_outputs.items():
            slots[role] = prepare_output_slot(output, role)
        if slots["validator"].path == slots["material_builder"].path:
            fail("validator and material-builder outputs must be distinct paths")

        completed = False
        try:
            with tempfile.TemporaryDirectory(prefix="poco-g3-repro-build-") as temporary:
                root = pathlib.Path(temporary)
                frozen_candidate = root / "source-candidate.tar"
                freeze_candidate(candidate, frozen_candidate)
                candidate_report = run_candidate_checker(frozen_candidate)
                left_source = extract(frozen_candidate, root / "left")
                right_source = extract(frozen_candidate, root / "right")
                left, right = build_verified_pair(
                    left_source,
                    right_source,
                    root / "target-left",
                    root / "target-right",
                    cargo_home,
                    candidate_report,
                )
                if left.rustc_vv != right.rustc_vv:
                    fail("candidate-selected rustc differs between independent builds")
                hashes: dict[str, str] = {}
                sizes: dict[str, int] = {}
                frozen_left: dict[str, FrozenBinaryV1] = {}
                for role in ("validator", "material_builder"):
                    left_binary = freeze_binary(
                        left.binaries[role], f"left {role} binary"
                    )
                    right_binary = freeze_binary(
                        right.binaries[role], f"right {role} binary"
                    )
                    if (
                        left_binary.sha256 != right_binary.sha256
                        or left_binary.payload != right_binary.payload
                    ):
                        fail(
                            f"two independent candidate builds produced different {role} binaries"
                        )
                    frozen_left[role] = left_binary
                    hashes[role] = left_binary.sha256
                    sizes[role] = left_binary.size
                if hashes["validator"] == hashes["material_builder"]:
                    fail(
                        "validator and material-builder binaries must have distinct SHA-256 values"
                    )
                emit_binary(frozen_left["validator"].payload, slots["validator"])
                emit_binary(
                    frozen_left["material_builder"].payload,
                    slots["material_builder"],
                )
            for role, slot in slots.items():
                emitted = freeze_emitted_binary(slot, f"emitted {role} binary")
                if emitted.sha256 != hashes[role] or emitted.size != sizes[role]:
                    fail(f"emitted {role} binary differs from reproducible build")
            report = make_build_report(
                candidate_report,
                hashes,
                sizes,
                left.rustc_vv,
                slots,
            )
            completed = True
        finally:
            if not completed:
                for slot in slots.values():
                    unlink_owned_output(slot)
    finally:
        for slot in slots.values():
            os.close(slot.parent_fd)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.SubprocessError, tarfile.TarError, ValueError) as error:
        fail(str(error))
