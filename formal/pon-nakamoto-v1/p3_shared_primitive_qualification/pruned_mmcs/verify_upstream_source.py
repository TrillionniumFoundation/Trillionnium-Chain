#!/usr/bin/env python3
"""Read-only provenance for the native pruned-MMCS reduction check.

Requires the locked offline Cargo metadata JSON. Every retained crate archive
must match Cargo.lock and every ordinary archived file must match the cache.
This checks bytes, not the cryptographic correctness of those bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tomllib


BASE = "1fe2f31c70977a030aec73b63fe0617f34d15a77"
CRATE = "formal/pon-nakamoto-v1/w1_public_stark_research"
PACKAGES = (
    "p3-merkle-tree", "p3-commit", "p3-field", "p3-symmetric",
    "p3-challenger", "sha3", "keccak",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(repository: Path, metadata: Path) -> dict:
    repository = repository.resolve(strict=True)
    graph = json.loads(metadata.read_text())
    lock = tomllib.loads((repository / CRATE / "Cargo.lock").read_text())
    locked = {(p["name"], p["version"]): p for p in lock["package"]}
    packages = {name: [p for p in graph["packages"] if p["name"] == name]
                for name in PACKAGES}
    if any(len(values) != 1 for values in packages.values()):
        raise ValueError("missing or ambiguous dependency in the locked graph")
    baseline = {}
    for relative in ("Cargo.lock", "Cargo.toml", "src/tagged_sha3.rs", "src/tagged_sha3_wire.rs"):
        path = f"{CRATE}/{relative}"
        expected = subprocess.check_output(["git", "--no-replace-objects", "show", f"{BASE}:{path}"], cwd=repository)
        actual = (repository / path).read_bytes()
        if actual != expected:
            raise ValueError(f"frozen R1 baseline changed: {path}")
        baseline[path] = digest(actual)
    receipts = []
    for name in PACKAGES:
        package = packages[name][0]
        version = package["version"]
        expected_version = "0.8.0" if name.startswith("p3-") else {
            "sha3": "0.10.9", "keccak": "0.1.6"
        }[name]
        if version != expected_version:
            raise ValueError(f"unexpected version: {name} {version}")
        if not package["source"].startswith("registry+"):
            raise ValueError(f"dependency is not the locked registry package: {name}")
        source = Path(package["manifest_path"]).parent
        archive = source.parents[2] / "cache" / source.parent.name / f"{name}-{version}.crate"
        archive_bytes = archive.read_bytes()
        expected_checksum = locked[(name, version)]["checksum"]
        if digest(archive_bytes) != expected_checksum:
            raise ValueError(f"archive differs from Cargo.lock: {name}")
        files = {}
        with tarfile.open(archive, "r:gz") as tar:
            for item in tar:
                if item.isdir():
                    continue
                member = PurePosixPath(item.name)
                if (not item.isfile() or member.is_absolute() or ".." in member.parts
                        or not member.parts or member.parts[0] != f"{name}-{version}"):
                    raise ValueError(f"non-ordinary archive member: {item.name}")
                relative = Path(*member.parts[1:])
                cached = source / relative
                if cached.is_symlink() or not cached.is_file():
                    raise ValueError(f"non-ordinary cached dependency file: {cached}")
                archived = tar.extractfile(item).read()
                if cached.read_bytes() != archived:
                    raise ValueError(f"cached dependency differs from its locked archive: {name}/{relative}")
                key = relative.as_posix()
                if key in files:
                    raise ValueError(f"duplicate archived path: {name}/{key}")
                files[key] = digest(archived)
        receipts.append({
            "package": name, "version": version,
            "archive_sha256": expected_checksum,
            "archived_file_count": len(files),
            "all_archived_files_equal_cached_files": True,
            "source_sha256": {key: value for key, value in sorted(files.items()) if key.endswith(".rs")},
        })
    return {
        "schema": "p3.pruned-mmcs.native-source-identity.v1",
        "baseline_commit": BASE,
        "frozen_profile_files": baseline,
        "locked_packages": receipts,
        "cryptographic_qualification": False,
        "production_activation": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--cargo-metadata", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.repository, args.cargo_metadata), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
