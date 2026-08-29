#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath

MISSING_RE = re.compile(
    r"failed to download `(?P<name>[A-Za-z0-9_-]+) v(?P<version>[A-Za-z0-9.+-]+)`"
)
STAMP_RE = re.compile(r"^(?P<sha>[0-9a-f]{64})  (?P<path>[A-Za-z0-9_./-]+)$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9.+-]+$")


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )


def require_success(result: subprocess.CompletedProcess[str], operation: str) -> None:
    if result.returncode == 0:
        return
    if result.stdout:
        print(result.stdout, file=sys.stderr, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    raise SystemExit(f"{operation} failed with exit code {result.returncode}")


def load_registry_packages(lock_path: Path) -> dict[tuple[str, str], str]:
    with lock_path.open("rb") as handle:
        data = tomllib.load(handle)
    packages: dict[tuple[str, str], str] = {}
    for package in data.get("package", []):
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        checksum = package.get("checksum")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        if source != "registry+https://github.com/rust-lang/crates.io-index":
            continue
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise SystemExit(f"registry package lacks an exact checksum: {name} {version}")
        key = (name, version)
        if key in packages:
            raise SystemExit(f"duplicate registry package in lock: {name} {version}")
        packages[key] = checksum
    if not packages:
        raise SystemExit("lock contains no checksummed crates.io packages")
    return packages


def cargo_binary(toolchain: str) -> Path:
    rustup = Path.home() / ".cargo/bin/rustup"
    result = run([str(rustup), "which", "--toolchain", toolchain, "cargo"], capture=True)
    require_success(result, "resolve pinned Cargo")
    cargo = Path(result.stdout.strip())
    if not cargo.is_absolute() or not cargo.is_file():
        raise SystemExit(f"pinned Cargo path is invalid: {cargo}")
    return cargo


def registry_roots(cargo_home: Path) -> tuple[Path, Path]:
    matches = sorted((cargo_home / "registry/cache").glob("*/fs2-0.4.3.crate"))
    if len(matches) != 1:
        raise SystemExit(
            "expected exactly one hardened crates.io cache containing fs2-0.4.3.crate; "
            f"found {len(matches)}"
        )
    cache_dir = matches[0].parent.resolve()
    src_dir = (cargo_home / "registry/src" / cache_dir.name).resolve()
    if not cache_dir.is_dir() or cache_dir.is_symlink():
        raise SystemExit(f"registry cache is not a real directory: {cache_dir}")
    if not src_dir.is_dir() or src_dir.is_symlink():
        raise SystemExit(f"registry source root is not a real directory: {src_dir}")
    return cache_dir, src_dir


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_exact(name: str, version: str, checksum: str, destination: Path) -> None:
    if not SAFE_NAME_RE.fullmatch(name) or not SAFE_VERSION_RE.fullmatch(version):
        raise SystemExit(f"unsafe locked package coordinate: {name} {version}")
    url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    result = run(
        [
            "curl",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--retry",
            "5",
            "--output",
            str(destination),
            url,
        ]
    )
    require_success(result, f"download exact crate {name} {version}")
    observed = sha256(destination)
    if observed != checksum:
        destination.unlink(missing_ok=True)
        raise SystemExit(
            f"crate checksum mismatch for {name} {version}: "
            f"expected={checksum} actual={observed}"
        )


def extract_exact_archive(archive: Path, name: str, version: str, destination: Path) -> Path:
    expected_top = f"{name}-{version}"
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members:
            raise SystemExit(f"empty crate archive: {name} {version}")
        for member in members:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts:
                raise SystemExit(f"unsafe archive path in {name} {version}: {member.name}")
            if pure.parts[0] != expected_top:
                raise SystemExit(
                    f"unexpected archive root in {name} {version}: {member.name}"
                )
            if not (member.isdir() or member.isfile()):
                raise SystemExit(
                    f"unsupported archive entry in {name} {version}: {member.name}"
                )
        bundle.extractall(destination, filter="data")
    extracted = destination / expected_top
    if not extracted.is_dir() or extracted.is_symlink():
        raise SystemExit(f"crate did not extract to one real directory: {expected_top}")
    for entry in extracted.rglob("*"):
        mode = entry.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise SystemExit(f"unsafe extracted entry: {entry}")
    return extracted


def install_root_owned(crate_file: Path, extracted: Path, cache_dir: Path, src_dir: Path) -> None:
    require_success(run(["sudo", "-n", "true"]), "obtain noninteractive runner provisioning authority")
    cache_target = cache_dir / crate_file.name
    require_success(
        run(
            [
                "sudo",
                "-n",
                "install",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0444",
                str(crate_file),
                str(cache_target),
            ]
        ),
        f"install hardened crate cache file {crate_file.name}",
    )
    source_target = src_dir / extracted.name
    if source_target.exists() or source_target.is_symlink():
        if source_target.is_symlink() or not source_target.is_dir():
            raise SystemExit(f"existing crate source target is unsafe: {source_target}")
    else:
        require_success(
            run(["sudo", "-n", "cp", "-a", str(extracted), str(src_dir)]),
            f"install extracted crate source {extracted.name}",
        )
    require_success(
        run(["sudo", "-n", "chown", "-R", "root:root", str(source_target)]),
        f"harden source ownership {source_target.name}",
    )
    require_success(
        run(
            [
                "sudo",
                "-n",
                "find",
                str(source_target),
                "-type",
                "d",
                "-exec",
                "chmod",
                "0555",
                "{}",
                "+",
            ]
        ),
        f"harden source directories {source_target.name}",
    )
    require_success(
        run(
            [
                "sudo",
                "-n",
                "find",
                str(source_target),
                "-type",
                "f",
                "-exec",
                "chmod",
                "0444",
                "{}",
                "+",
            ]
        ),
        f"harden source files {source_target.name}",
    )
    if sha256(cache_target) != sha256(crate_file):
        raise SystemExit(f"installed crate cache checksum changed: {cache_target}")


def refresh_stamp(stamp: Path, lock_relative: str, lock_path: Path, work: Path) -> None:
    if not stamp.is_file() or stamp.is_symlink():
        raise SystemExit(f"offline stamp is not a regular file: {stamp}")
    lines = stamp.read_text(encoding="utf-8").splitlines()
    replacement = sha256(lock_path)
    seen = 0
    output: list[str] = []
    for line in lines:
        match = STAMP_RE.fullmatch(line)
        if match is None:
            raise SystemExit("offline stamp contains a malformed line")
        if match.group("path") == lock_relative:
            seen += 1
            line = f"{replacement}  {lock_relative}"
        output.append(line)
    if seen != 1:
        raise SystemExit(
            f"offline stamp must contain exactly one {lock_relative} line; found {seen}"
        )
    staged = work / "offline-stamp"
    staged.write_text("\n".join(output) + "\n", encoding="utf-8")
    require_success(
        run(
            [
                "sudo",
                "-n",
                "install",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0444",
                str(staged),
                str(stamp),
            ]
        ),
        "publish exact offline cache stamp",
    )
    observed = [
        match.group("sha")
        for line in stamp.read_text(encoding="utf-8").splitlines()
        if (match := STAMP_RE.fullmatch(line)) is not None
        and match.group("path") == lock_relative
    ]
    if observed != [replacement]:
        raise SystemExit("published offline stamp did not retain the exact lock digest")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--stamp", required=True)
    parser.add_argument("--max-packages", type=int, default=64)
    args = parser.parse_args()

    root = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()).resolve()
    manifest = (root / args.manifest).resolve()
    lock_path = (root / args.lock).resolve()
    for path, label in ((manifest, "manifest"), (lock_path, "lock")):
        if not path.is_file() or path.is_symlink() or root not in path.parents:
            raise SystemExit(f"{label} must be a regular file below the repository root")
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", args.lock):
        raise SystemExit("lock argument is not a safe repository-relative path")
    if args.max_packages < 1 or args.max_packages > 256:
        raise SystemExit("max-packages must be in 1..=256")

    packages = load_registry_packages(lock_path)
    cargo = cargo_binary(args.toolchain)
    cargo_home = (Path.home() / ".cargo").resolve()
    cache_dir, src_dir = registry_roots(cargo_home)
    stamp = Path(args.stamp).resolve()
    attempted: set[tuple[str, str]] = set()
    provisioned: list[tuple[str, str]] = []
    environment = os.environ.copy()
    environment["CARGO_HOME"] = str(cargo_home)
    environment["CARGO_NET_OFFLINE"] = "true"

    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    with tempfile.TemporaryDirectory(prefix="trnm-locked-crates-", dir=runner_temp) as temporary:
        work = Path(temporary)
        for _ in range(args.max_packages + 1):
            result = run(
                [
                    str(cargo),
                    "fetch",
                    "--manifest-path",
                    str(manifest),
                    "--locked",
                    "--offline",
                ],
                cwd=root,
                env=environment,
                capture=True,
            )
            if result.returncode == 0:
                refresh_stamp(stamp, args.lock, lock_path, work)
                print(
                    "exact_locked_crate_provisioning=passed "
                    f"packages={len(provisioned)} cache={cache_dir.name}"
                )
                for name, version in provisioned:
                    print(f"provisioned={name}@{version}")
                return
            combined = (result.stdout or "") + (result.stderr or "")
            match = MISSING_RE.search(combined)
            if match is None:
                print(combined, file=sys.stderr, end="")
                raise SystemExit("offline Cargo failure was not one exact missing crate")
            coordinate = (match.group("name"), match.group("version"))
            if coordinate in attempted:
                print(combined, file=sys.stderr, end="")
                raise SystemExit(f"crate remained missing after exact provisioning: {coordinate}")
            attempted.add(coordinate)
            checksum = packages.get(coordinate)
            if checksum is None:
                raise SystemExit(
                    f"Cargo requested a crate not bound by Cargo.lock: {coordinate[0]} {coordinate[1]}"
                )
            name, version = coordinate
            crate_file = work / f"{name}-{version}.crate"
            extraction = work / f"extract-{len(provisioned)}"
            extraction.mkdir(mode=0o700)
            download_exact(name, version, checksum, crate_file)
            extracted = extract_exact_archive(crate_file, name, version, extraction)
            install_root_owned(crate_file, extracted, cache_dir, src_dir)
            provisioned.append(coordinate)

    raise SystemExit(f"exact crate provisioning exceeded {args.max_packages} packages")


if __name__ == "__main__":
    main()
