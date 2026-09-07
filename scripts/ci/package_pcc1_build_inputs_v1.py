#!/usr/bin/env python3
"""M17: temporary read-only export of public offline compilation inputs.

No home directory, registry index, Cargo credentials, environment, private key,
production data, or runner state is exported. This is not acceptance evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tomllib


def output(*args: str) -> str:
    return subprocess.check_output(args, text=True, timeout=180).strip()


def main() -> None:
    root = Path(output("git", "rev-parse", "--show-toplevel")).resolve()
    os.chdir(root)
    head = output("git", "rev-parse", "HEAD")
    compiler = output("rustc", "-vV")
    if "release: 1.95.0" not in compiler or "59807616e1fa2540724bfbac14d7976d7e4a3860" not in compiler:
        raise RuntimeError("compiler does not match the repository's frozen toolchain")
    sysroot = Path(output("rustc", "--print", "sysroot")).resolve(strict=True)
    target = "x86_64-unknown-linux-gnu"
    if f"host: {target}" not in compiler:
        raise RuntimeError("unexpected compiler host")
    metadata = json.loads(output("cargo", "metadata", "--manifest-path", "trillionnium/Cargo.toml", "--format-version", "1", "--locked", "--offline", "--filter-platform", target))
    lock = tomllib.loads((root / "trillionnium/Cargo.lock").read_text())
    checksums = {(p["name"], p["version"]): p["checksum"] for p in lock["package"] if "checksum" in p}
    destination = Path(os.environ["RUNNER_TEMP"]) / "pcc1-offline-build-inputs"
    destination.mkdir(exist_ok=False)
    packages = []
    with tarfile.open(destination / "vendor.tar.gz", "w:gz") as archive:
        for package in metadata["packages"]:
            source = package.get("source")
            if source is None:
                continue
            if source != "registry+https://github.com/rust-lang/crates.io-index":
                raise RuntimeError("non-public registry input cannot be exported")
            name = f'{package["name"]}-{package["version"]}'
            directory = Path(package["manifest_path"]).resolve(strict=True).parent
            if directory.name != name or directory.parent.parent.name != "src" or directory.parent.parent.parent.name != "registry":
                raise RuntimeError("package is not a canonical registry source directory")
            checksum = checksums[(package["name"], package["version"])]
            record = json.loads((directory / ".cargo-checksum.json").read_text())
            if record.get("package") != checksum:
                raise RuntimeError("package checksum differs from exact Cargo.lock")
            for item in directory.rglob("*"):
                if item.is_symlink():
                    raise RuntimeError("registry export refuses symlinks")
            archive.add(directory, arcname=f"vendor/{name}", recursive=True)
            packages.append({"name": package["name"], "version": package["version"], "checksum": checksum})
    with tarfile.open(destination / "toolchain.tar.gz", "w:gz") as archive:
        for part in ("bin", "lib", "libexec"):
            path = sysroot / part
            if path.exists():
                archive.add(path, arcname=f"toolchain/{part}", recursive=True)
    manifest = {
        "schema": "pcc1-offline-development-inputs-v1",
        "source_commit": head,
        "source_tree": output("git", "rev-parse", "HEAD^{tree}"),
        "compiler": compiler,
        "cargo": output("cargo", "-V"),
        "lock_sha256": hashlib.sha256((root / "trillionnium/Cargo.lock").read_bytes()).hexdigest(),
        "public_registry_packages": packages,
        "production_evidence": False,
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    lines = []
    for path in sorted(destination.iterdir()):
        with path.open("rb") as handle:
            lines.append(f"{hashlib.file_digest(handle, 'sha256').hexdigest()}  {path.name}")
    (destination / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    print(json.dumps({"source": head, "package_count": len(packages), "scope": "offline-development-only"}))


if __name__ == "__main__":
    main()
