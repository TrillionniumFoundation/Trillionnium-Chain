#!/usr/bin/env python3
"""Build and verify the signed, local-only TRNM Chain devnet v1 distribution."""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


PACKAGE_ID = "trnm_chain_devnet_v1"
PACKAGE_SCHEMA = "trnm_chain_package_manifest_v1"
PACKAGE_SCOPE = "loopback-local-devnet"
REQUIRED_BINARIES = (
    "trnm-chain-node",
    "trnm-chain-validator",
    "trnm-chain-cli",
)
REQUIRED_INIT_PUBLIC_FILES = (
    "genesis/devnet-genesis.json",
    "config/node.json",
    "config/validator-1.json",
    "config/validator-2.json",
    "config/validator-3.json",
    "config/validator-4.json",
)
REQUIRED_INIT_SECRET_FILES = tuple(
    f"secrets/validator-{index}.key" for index in range(1, 5)
)
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
HEX_PRIVATE_KEY = re.compile(r"^[0-9a-f]{64}\n?$")


class PackageError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise PackageError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=True,
            stdin=subprocess.DEVNULL,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
    except FileNotFoundError:
        fail(f"required command is unavailable: {command[0]}")
    except subprocess.CalledProcessError as error:
        detail = ""
        if capture:
            detail = f": {(error.stderr or error.stdout or '').strip()}"
        fail(f"command failed ({error.returncode}): {' '.join(command)}{detail}")


def workspace_root() -> Path:
    return Path(__file__).resolve().parents[2]


def repository_root(workspace: Path) -> Path:
    root = workspace.parent
    resolved = run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=root,
        capture=True,
    ).stdout.strip()
    if Path(resolved).resolve() != root.resolve():
        fail(f"canonical repository root mismatch: expected {root}, got {resolved}")
    return root


def git_output(root: Path, *arguments: str) -> str:
    return run(["git", *arguments], cwd=root, capture=True).stdout.strip()


def source_fingerprint(root: Path) -> tuple[str, str, list[str]]:
    head = git_output(root, "rev-parse", "HEAD")
    status = run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
        capture=True,
    ).stdout
    status_lines = sorted(line for line in status.splitlines() if line)
    digest = hashlib.sha256()
    digest.update(b"trnm.source.fingerprint.v1\0")
    digest.update(head.encode("ascii"))
    digest.update(b"\0")
    tracked_diff = run(
        ["git", "diff", "--binary", "--no-ext-diff", "HEAD", "--"],
        cwd=root,
        capture=True,
    ).stdout.encode("utf-8")
    digest.update(tracked_diff)
    untracked = run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=root,
        capture=True,
    ).stdout.split("\0")
    for relative in sorted(item for item in untracked if item):
        path = root / relative
        if not path.is_file() or path.is_symlink():
            fail(f"untracked source is not a regular file: {relative}")
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(bytes.fromhex(sha256_file(path)))
    return head, digest.hexdigest(), status_lines


def require_safe_signing_key(path: Path) -> Path:
    if not path.is_absolute():
        fail("release signing key path must be absolute")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"release signing key does not exist: {path}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail("release signing key must be a non-symlink regular file")
    if os.name == "posix" and metadata.st_mode & 0o077:
        fail("release signing key permissions must be owner-only (0600 or stricter)")
    run(["openssl", "pkey", "-in", str(path), "-noout"], capture=True)
    return path


def canonical_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o644)


def parse_json_file(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON file {path}: {error}")


def walk_json(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key in sorted(value):
            next_prefix = f"{prefix}.{key}" if prefix else key
            yield from walk_json(value[key], next_prefix)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_json(item, f"{prefix}[{index}]")
    else:
        yield prefix, value


def assert_loopback_value(label: str, value: str) -> None:
    lowered = value.lower()
    if "://" in lowered:
        if not (
            lowered.startswith("http://127.0.0.1:")
            or lowered.startswith("http://[::1]:")
        ):
            fail(f"generated devnet {label} is not explicit loopback HTTP: {value}")
        return
    host = lowered.rsplit(":", 1)[0].strip("[]")
    if host not in {"127.0.0.1", "::1", "localhost"}:
        fail(f"generated devnet {label} is not loopback: {value}")


def validate_init_devnet_output(output: Path) -> dict[str, Any]:
    if output.is_symlink() or not output.is_dir():
        fail("operator init-devnet output must be a real directory")
    expected = set(REQUIRED_INIT_PUBLIC_FILES + REQUIRED_INIT_SECRET_FILES)
    actual = {
        path.relative_to(output).as_posix()
        for path in output.rglob("*")
        if path.is_file()
    }
    missing = sorted(expected - actual)
    if missing:
        fail(f"operator init-devnet omitted required files: {', '.join(missing)}")

    public_files: list[str] = []
    for relative in REQUIRED_INIT_PUBLIC_FILES:
        path = output / relative
        if path.is_symlink() or not path.is_file():
            fail(f"generated public devnet material is unsafe: {relative}")
        payload = parse_json_file(path)
        public_files.append(relative)
        for label, value in walk_json(payload):
            lowered = label.lower()
            if isinstance(value, str) and (
                lowered.endswith("listen_addr")
                or lowered.endswith("listen_address")
                or lowered.endswith("vote_endpoint")
                or lowered.endswith("rpc_endpoint")
            ):
                assert_loopback_value(label, value)

    genesis = parse_json_file(output / "genesis/devnet-genesis.json")
    if not isinstance(genesis, dict):
        fail("generated genesis must be a JSON object")
    if genesis.get("scope") != PACKAGE_SCOPE:
        fail(f"generated genesis scope must be {PACKAGE_SCOPE}")
    if genesis.get("development_only") is not True:
        fail("generated genesis must set development_only=true")

    for relative in REQUIRED_INIT_SECRET_FILES:
        path = output / relative
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            fail(f"generated validator secret is not a regular file: {relative}")
        if os.name == "posix" and metadata.st_mode & 0o077:
            fail(f"generated validator secret is not owner-only: {relative}")
        try:
            text = path.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as error:
            fail(f"generated validator secret is unreadable: {relative}: {error}")
        if not HEX_PRIVATE_KEY.fullmatch(text):
            fail(f"generated validator secret is not canonical 32-byte lowercase hex: {relative}")

    return {
        "schema": "trnm_init_devnet_smoke_v1",
        "scope": PACKAGE_SCOPE,
        "development_only": True,
        "validator_count": 4,
        "public_files_validated": public_files,
        "secret_files_validated": len(REQUIRED_INIT_SECRET_FILES),
        "secret_material_packaged": False,
    }


def sanitize_spdx_id(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-.")
    return sanitized or "unknown"


def build_spdx_sbom(
    metadata: dict[str, Any],
    *,
    head: str,
    target: str,
    created_at: str,
) -> dict[str, Any]:
    packages = sorted(
        metadata.get("packages", []),
        key=lambda package: (package.get("name", ""), package.get("version", ""), package.get("id", "")),
    )
    ids: dict[str, str] = {}
    spdx_packages: list[dict[str, Any]] = []
    for index, package in enumerate(packages, start=1):
        spdx_id = (
            f"SPDXRef-Cargo-{index}-"
            f"{sanitize_spdx_id(package.get('name', 'unknown'))}-"
            f"{sanitize_spdx_id(package.get('version', 'unknown'))}"
        )
        ids[str(package.get("id", ""))] = spdx_id
        license_expression = package.get("license") or "NOASSERTION"
        spdx_packages.append(
            {
                "SPDXID": spdx_id,
                "name": package.get("name", "unknown"),
                "versionInfo": package.get("version", "unknown"),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": license_expression,
                "copyrightText": "NOASSERTION",
            }
        )

    distribution_id = "SPDXRef-Package-trnm-chain-devnet-v1"
    spdx_packages.insert(
        0,
        {
            "SPDXID": distribution_id,
            "name": PACKAGE_ID,
            "versionInfo": "1",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "MIT",
            "copyrightText": "NOASSERTION",
            "comment": "Local-loopback devnet distribution; not public-mainnet release evidence.",
        },
    )
    relationships: list[dict[str, str]] = []
    resolve = metadata.get("resolve") or {}
    for node in sorted(resolve.get("nodes", []), key=lambda item: str(item.get("id", ""))):
        source_id = ids.get(str(node.get("id", "")))
        if not source_id:
            continue
        dependency_ids = {
            str(dependency.get("pkg", ""))
            for dependency in node.get("deps", [])
            if isinstance(dependency, dict) and dependency.get("pkg")
        }
        dependency_ids.update(
            str(dependency)
            for dependency in node.get("dependencies", [])
            if isinstance(dependency, str) and dependency
        )
        for dependency_id in sorted(dependency_ids):
            target_id = ids.get(dependency_id)
            if target_id:
                relationships.append(
                    {
                        "spdxElementId": source_id,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": target_id,
                    }
                )
    root_names = {"trnm-node", "trnm-cli", "trnm-research-protocol"}
    for package in packages:
        if package.get("name") in root_names:
            related = ids.get(str(package.get("id", "")))
            if related:
                relationships.append(
                    {
                        "spdxElementId": distribution_id,
                        "relationshipType": "CONTAINS",
                        "relatedSpdxElement": related,
                    }
                )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{PACKAGE_ID}-{head[:12]}-{target}",
        "documentNamespace": (
            "https://trillionnium.invalid/spdx/"
            f"{PACKAGE_ID}/{head}/{sanitize_spdx_id(target)}"
        ),
        "creationInfo": {
            "created": created_at,
            "creators": ["Tool: trnm_chain_devnet_v1.py"],
        },
        "documentDescribes": [distribution_id],
        "packages": spdx_packages,
        "relationships": relationships,
    }


def copy_regular(source: Path, destination: Path, mode: int = 0o644) -> None:
    if source.is_symlink() or not source.is_file():
        fail(f"required package input is not a regular file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def iter_payload_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            fail(f"package staging tree contains a symlink: {path}")
        if path.is_file():
            yield path


def write_payload_checksums(package_root: Path) -> Path:
    checksums = package_root / "checksums/SHA256SUMS"
    checksums.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for path in iter_payload_files(package_root):
        relative = path.relative_to(package_root).as_posix()
        if relative == "checksums/SHA256SUMS" or relative.startswith("signatures/"):
            continue
        lines.append(f"{sha256_file(path)}  {relative}")
    checksums.write_text("\n".join(lines) + "\n", encoding="ascii")
    checksums.chmod(0o644)
    return checksums


def openssl_public_key(private_key: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(destination),
        ],
        capture=True,
    )
    destination.chmod(0o644)


def openssl_sign(private_key: Path, payload: Path, signature: Path) -> None:
    signature.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(private_key),
            "-rawin",
            "-in",
            str(payload),
            "-out",
            str(signature),
        ],
        capture=True,
    )
    signature.chmod(0o644)


def openssl_public_der(path: Path) -> bytes:
    completed = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(path), "-outform", "DER"],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        fail(f"invalid trusted Ed25519 public key: {path}")
    return completed.stdout


def openssl_verify(public_key: Path, payload: Path, signature: Path) -> None:
    run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(public_key),
            "-rawin",
            "-in",
            str(payload),
            "-sigfile",
            str(signature),
        ],
        capture=True,
    )


def deterministic_archive(source: Path, archive: Path, epoch: int) -> None:
    with tempfile.NamedTemporaryFile(prefix="trnm-devnet-", suffix=".tar", delete=False) as temp:
        tar_path = Path(temp.name)
    try:
        with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as tar:
            paths = [source, *sorted(source.rglob("*"), key=lambda p: p.relative_to(source).as_posix())]
            for path in paths:
                if path.is_symlink():
                    fail(f"refusing to archive symlink: {path}")
                relative = Path(source.name)
                if path != source:
                    relative /= path.relative_to(source)
                info = tar.gettarinfo(str(path), arcname=relative.as_posix())
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = epoch
                if info.isdir():
                    info.mode = 0o755
                    tar.addfile(info)
                elif info.isfile():
                    info.mode = path.stat().st_mode & 0o777
                    with path.open("rb") as handle:
                        tar.addfile(info, handle)
                else:
                    fail(f"unsupported package entry type: {path}")
        with tar_path.open("rb") as source_handle, archive.open("xb") as output_handle:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=output_handle,
                mtime=epoch,
                compresslevel=9,
            ) as gzip_handle:
                shutil.copyfileobj(source_handle, gzip_handle)
    finally:
        tar_path.unlink(missing_ok=True)


def safe_extract(archive: Path, destination: Path) -> Path:
    try:
        handle = tarfile.open(archive, "r:gz")
    except (tarfile.TarError, OSError) as error:
        fail(f"invalid package archive: {error}")
    with handle:
        members = handle.getmembers()
        if not members:
            fail("package archive is empty")
        roots: set[str] = set()
        for member in members:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts:
                fail(f"unsafe archive member path: {member.name}")
            roots.add(pure.parts[0])
            if member.issym() or member.islnk() or member.isdev():
                fail(f"archive contains forbidden link/device entry: {member.name}")
            if not (member.isdir() or member.isfile()):
                fail(f"archive contains unsupported entry: {member.name}")
        if roots != {PACKAGE_ID}:
            fail(f"archive root must be exactly {PACKAGE_ID}")
        for member in members:
            target = destination / PurePosixPath(member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(0o755)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = handle.extractfile(member)
            if extracted is None:
                fail(f"unable to extract archive member: {member.name}")
            with target.open("xb") as output:
                shutil.copyfileobj(extracted, output)
            target.chmod(member.mode & 0o777)
    return destination / PACKAGE_ID


def verify_checksum_manifest(package_root: Path) -> None:
    checksum_path = package_root / "checksums/SHA256SUMS"
    if checksum_path.is_symlink() or not checksum_path.is_file():
        fail("package is missing checksums/SHA256SUMS")
    lines = checksum_path.read_text(encoding="ascii").splitlines()
    listed: set[str] = set()
    listed_order: list[str] = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if not match:
            fail(f"malformed checksum line: {line!r}")
        expected, relative = match.groups()
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or relative in listed:
            fail(f"unsafe or duplicate checksum path: {relative}")
        listed.add(relative)
        listed_order.append(relative)
        path = package_root / pure
        if path.is_symlink() or not path.is_file():
            fail(f"checksummed payload is missing or unsafe: {relative}")
        if sha256_file(path) != expected:
            fail(f"checksum mismatch: {relative}")
    if listed_order != sorted(listed_order):
        fail("SHA256SUMS must use deterministic path ordering")
    actual = {
        path.relative_to(package_root).as_posix()
        for path in iter_payload_files(package_root)
        if path.relative_to(package_root).as_posix() != "checksums/SHA256SUMS"
        and not path.relative_to(package_root).as_posix().startswith("signatures/")
    }
    if listed != actual:
        missing = sorted(actual - listed)
        extra = sorted(listed - actual)
        fail(f"checksum coverage mismatch; missing={missing}, extra={extra}")


def verify_package_tree(package_root: Path, trusted_public_key: Path) -> dict[str, Any]:
    manifest_path = package_root / "manifest/package.json"
    manifest = parse_json_file(manifest_path)
    if not isinstance(manifest, dict):
        fail("package manifest must be a JSON object")
    expected_fields = {
        "schema": PACKAGE_SCHEMA,
        "package_id": PACKAGE_ID,
        "scope": PACKAGE_SCOPE,
        "public_mainnet_ready": False,
        "private_keys_packaged": False,
    }
    for key, expected in expected_fields.items():
        if manifest.get(key) != expected:
            fail(f"manifest field {key} must equal {expected!r}")
    if tuple(manifest.get("required_binaries", [])) != REQUIRED_BINARIES:
        fail("manifest required_binaries does not match the live binary contract")
    for binary in REQUIRED_BINARIES:
        path = package_root / "bin" / binary
        if path.is_symlink() or not path.is_file():
            fail(f"missing required live binary: {binary}")
        if os.name == "posix" and not path.stat().st_mode & stat.S_IXUSR:
            fail(f"live binary is not executable: {binary}")
    if (package_root / "secrets").exists():
        fail("release archive must not contain a secrets directory")
    for path in iter_payload_files(package_root):
        lowered = path.name.lower()
        if lowered.endswith((".key", ".pem", ".p12", ".pfx")) and not path.relative_to(
            package_root
        ).as_posix().startswith("signatures/"):
            fail(f"release archive contains forbidden key-like payload: {path.name}")
        if b"-----BEGIN PRIVATE KEY-----" in path.read_bytes():
            fail(f"release archive contains PEM private-key material: {path.name}")
    for schema_path in sorted((package_root / "schemas").glob("*.json")):
        parse_json_file(schema_path)
    if not list((package_root / "schemas").glob("*.json")):
        fail("release archive contains no JSON schemas")

    packaged_public_key = package_root / "signatures/release-public-key.pem"
    internal_signature = package_root / "signatures/SHA256SUMS.ed25519"
    if not packaged_public_key.is_file() or not internal_signature.is_file():
        fail("package is missing its signed checksum contract")
    if hashlib.sha256(openssl_public_der(packaged_public_key)).digest() != hashlib.sha256(
        openssl_public_der(trusted_public_key)
    ).digest():
        fail("packaged signing public key does not match the external trust anchor")
    openssl_verify(
        trusted_public_key,
        package_root / "checksums/SHA256SUMS",
        internal_signature,
    )
    verify_checksum_manifest(package_root)
    return manifest


def verify_archive_bundle(
    archive: Path,
    trusted_public_key: Path,
    checksum_file: Path,
    signature_file: Path,
) -> dict[str, Any]:
    for path, label in (
        (archive, "archive"),
        (trusted_public_key, "trusted public key"),
        (checksum_file, "archive checksum"),
        (signature_file, "archive signature"),
    ):
        if path.is_symlink() or not path.is_file():
            fail(f"{label} must be a non-symlink regular file: {path}")
    checksum_text = checksum_file.read_text(encoding="ascii")
    match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)\n", checksum_text)
    if not match:
        fail("archive checksum file is malformed")
    expected, filename = match.groups()
    if filename != archive.name:
        fail("archive checksum filename does not bind the selected archive")
    if sha256_file(archive) != expected:
        fail("archive SHA-256 does not match the signed checksum file")
    openssl_verify(trusted_public_key, checksum_file, signature_file)
    with tempfile.TemporaryDirectory(prefix="trnm-devnet-verify-") as directory:
        package_root = safe_extract(archive, Path(directory))
        manifest = verify_package_tree(package_root, trusted_public_key)
    return {
        "schema": "trnm_chain_package_verification_v1",
        "verified": True,
        "archive": str(archive.resolve()),
        "archive_sha256": expected,
        "package_id": manifest["package_id"],
        "scope": manifest["scope"],
        "git_head": manifest["git_head"],
        "source_state": manifest["source_state"],
        "public_mainnet_ready": False,
    }


def build(args: argparse.Namespace) -> None:
    workspace = workspace_root()
    root = repository_root(workspace)
    static_root = workspace / "packaging/trnm_chain_devnet_v1"
    if static_root.is_symlink() or not static_root.is_dir():
        fail(f"missing release source directory: {static_root}")
    signing_key = require_safe_signing_key(Path(args.signing_key).resolve())
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    target_dir = Path(args.target_dir).resolve()

    head_before, source_digest_before, status_before = source_fingerprint(root)
    if status_before and not args.allow_dirty:
        fail(
            "worktree is dirty; official package assembly is fail-closed. "
            "Use --allow-dirty only for an explicitly non-release local rehearsal."
        )
    source_state = "dirty-local-rehearsal" if status_before else "clean"
    epoch = args.source_date_epoch
    if epoch is None:
        epoch = int(git_output(root, "show", "-s", "--format=%ct", "HEAD"))
    if epoch < 0:
        fail("SOURCE_DATE_EPOCH must be non-negative")
    created_at = (
        dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    rustc_info = run(["rustc", "-vV"], capture=True).stdout
    target_match = re.search(r"^host: (.+)$", rustc_info, re.MULTILINE)
    if not target_match:
        fail("unable to determine Rust host target")
    target = target_match.group(1)

    build_env = os.environ.copy()
    build_env.update(
        {
            "TZ": "UTC",
            "LC_ALL": "C",
            "LANG": "C",
            "SOURCE_DATE_EPOCH": str(epoch),
            "CARGO_TERM_COLOR": "never",
            "CARGO_BUILD_JOBS": build_env.get("CARGO_BUILD_JOBS", "1"),
            "CARGO_TARGET_DIR": str(target_dir),
        }
    )
    cargo_command = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "-p",
        "trnm-node",
    ]
    for binary in REQUIRED_BINARIES:
        cargo_command.extend(["--bin", binary])
    run(cargo_command, cwd=workspace, env=build_env)
    binary_dir = target_dir / "release"
    for binary in REQUIRED_BINARIES:
        path = binary_dir / binary
        if path.is_symlink() or not path.is_file():
            fail(f"cargo build did not produce required live binary: {binary}")
        run([str(path), "--help"], capture=True)

    with tempfile.TemporaryDirectory(prefix="trnm-init-devnet-") as init_directory:
        init_output = Path(init_directory) / "material"
        run(
            [
                str(binary_dir / "trnm-chain-cli"),
                "operator",
                "init-devnet",
                "--output-dir",
                str(init_output),
            ],
            capture=True,
        )
        init_evidence = validate_init_devnet_output(init_output)

    metadata = json.loads(
        run(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            cwd=workspace,
            env=build_env,
            capture=True,
        ).stdout
    )
    head_after, source_digest_after, status_after = source_fingerprint(root)
    if (
        head_after != head_before
        or source_digest_after != source_digest_before
        or status_after != status_before
    ):
        fail("source tree changed during package build; refusing mixed-source artifact")

    dirty_suffix = f"-dirty-{source_digest_before[:12]}" if status_before else ""
    archive_stem = (
        f"{PACKAGE_ID}-{sanitize_spdx_id(target)}-{head_before[:12]}{dirty_suffix}"
    )
    archive_path = output_dir / f"{archive_stem}.tar.gz"
    checksum_path = output_dir / f"{archive_stem}.tar.gz.sha256"
    signature_path = output_dir / f"{archive_stem}.tar.gz.ed25519"
    public_key_path = output_dir / f"{archive_stem}.release-public-key.pem"
    for path in (archive_path, checksum_path, signature_path, public_key_path):
        if path.exists() or path.is_symlink():
            fail(f"refusing to overwrite existing release artifact: {path}")

    with tempfile.TemporaryDirectory(prefix="trnm-devnet-stage-") as stage_directory:
        package_root = Path(stage_directory) / PACKAGE_ID
        (package_root / "bin").mkdir(parents=True)
        for binary in REQUIRED_BINARIES:
            copy_regular(binary_dir / binary, package_root / "bin" / binary, 0o755)
        for relative in (
            "README.md",
            "ROLLBACK.md",
            "LEGAL-NOTICE.md",
        ):
            copy_regular(static_root / relative, package_root / "docs" / relative)
        for source in sorted((static_root / "schemas").glob("*.json")):
            copy_regular(source, package_root / "schemas" / source.name)
        for source in sorted((static_root / "config").glob("*")):
            if source.is_file():
                copy_regular(source, package_root / "config" / source.name)
        for source in sorted((static_root / "genesis").glob("*")):
            if source.is_file():
                copy_regular(source, package_root / "genesis" / source.name)
        copy_regular(workspace / "Cargo.lock", package_root / "sbom/Cargo.lock")
        copy_regular(root / "RELEASE_READINESS.md", package_root / "docs/RELEASE_READINESS.md")
        research_fixture = (
            workspace
            / "crates/trnm-research-protocol/fixtures/protocol-v1-golden.json"
        )
        if research_fixture.is_file():
            copy_regular(
                research_fixture,
                package_root / "schemas/trnm-research-protocol-v1-golden.json",
            )
        canonical_json(package_root / "evidence/init-devnet-smoke.json", init_evidence)
        canonical_json(
            package_root / "sbom/trnm-chain-devnet-v1.spdx.json",
            build_spdx_sbom(
                metadata,
                head=head_before,
                target=target,
                created_at=created_at,
            ),
        )
        manifest = {
            "schema": PACKAGE_SCHEMA,
            "package_id": PACKAGE_ID,
            "package_version": 1,
            "scope": PACKAGE_SCOPE,
            "development_only": True,
            "public_mainnet_ready": False,
            "release_readiness_truth": "docs/RELEASE_READINESS.md",
            "required_binaries": list(REQUIRED_BINARIES),
            "node_entrypoint": "bin/trnm-chain-node",
            "validator_entrypoint": "bin/trnm-chain-validator",
            "operator_entrypoint": "bin/trnm-chain-cli operator",
            "genesis_entrypoint": "bin/trnm-chain-cli operator init-devnet",
            "private_keys_packaged": False,
            "package_signing": "Ed25519 via OpenSSL pkeyutl over canonical SHA256SUMS and archive checksum",
            "git_head": head_before,
            "source_state": source_state,
            "source_fingerprint_sha256": source_digest_before,
            "source_status_entry_count": len(status_before),
            "source_date_epoch": epoch,
            "generated_at": created_at,
            "rust_target": target,
            "rustc": rustc_info.splitlines()[0],
            "reproducible_archive_contract": (
                "sorted paths, uid/gid 0, fixed mtime, fixed modes, gzip mtime"
            ),
            "rollback": "docs/ROLLBACK.md",
        }
        canonical_json(package_root / "manifest/package.json", manifest)
        checksum_manifest = write_payload_checksums(package_root)
        packaged_public = package_root / "signatures/release-public-key.pem"
        openssl_public_key(signing_key, packaged_public)
        openssl_sign(
            signing_key,
            checksum_manifest,
            package_root / "signatures/SHA256SUMS.ed25519",
        )
        deterministic_archive(package_root, archive_path, epoch)

    archive_digest = sha256_file(archive_path)
    checksum_path.write_text(
        f"{archive_digest}  {archive_path.name}\n",
        encoding="ascii",
    )
    checksum_path.chmod(0o644)
    openssl_sign(signing_key, checksum_path, signature_path)
    openssl_public_key(signing_key, public_key_path)
    verification = verify_archive_bundle(
        archive_path,
        public_key_path,
        checksum_path,
        signature_path,
    )
    print(json.dumps(verification, sort_keys=True))


def verify(args: argparse.Namespace) -> None:
    result = verify_archive_bundle(
        Path(args.archive).resolve(),
        Path(args.trusted_public_key).resolve(),
        Path(args.checksum).resolve(),
        Path(args.signature).resolve(),
    )
    print(json.dumps(result, sort_keys=True))


def validate_init(args: argparse.Namespace) -> None:
    result = validate_init_devnet_output(Path(args.output_dir).resolve())
    print(json.dumps(result, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    root = workspace_root()
    command = argparse.ArgumentParser(
        description="Build or independently verify trnm_chain_devnet_v1.",
    )
    subcommands = command.add_subparsers(dest="command", required=True)

    build_parser = subcommands.add_parser("build", help="build and sign the package")
    build_parser.add_argument("--signing-key", required=True)
    build_parser.add_argument(
        "--output-dir",
        default=str(root / "run/releases/trnm-chain-devnet-v1"),
    )
    build_parser.add_argument(
        "--target-dir",
        default=str(root / "target/trnm-chain-devnet-v1"),
    )
    build_parser.add_argument("--source-date-epoch", type=int)
    build_parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="produce an explicitly non-release dirty local-rehearsal package",
    )
    build_parser.set_defaults(handler=build)

    verify_parser = subcommands.add_parser("verify", help="verify archive and signatures")
    verify_parser.add_argument("--archive", required=True)
    verify_parser.add_argument("--trusted-public-key", required=True)
    verify_parser.add_argument("--checksum", required=True)
    verify_parser.add_argument("--signature", required=True)
    verify_parser.set_defaults(handler=verify)

    init_parser = subcommands.add_parser(
        "validate-init",
        help="validate an operator init-devnet output tree without exposing secrets",
    )
    init_parser.add_argument("--output-dir", required=True)
    init_parser.set_defaults(handler=validate_init)
    return command


def main() -> int:
    try:
        arguments = parser().parse_args()
        arguments.handler(arguments)
        return 0
    except PackageError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
