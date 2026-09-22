#!/usr/bin/env python3
"""Export cached public crates matched to Cargo.lock for offline diagnosis.

No downloads, toolchain substitution, code execution or qualification claims.
Only checksum-matching crates.io .crate files are copied; Cargo credentials,
configuration, private registry archives and unpacked sources are excluded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import tomllib

from check_cargo_source_inventory_v1 import ROOT, validate_clean_source

MAX_ARCHIVES = 2048
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
PUBLIC_REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def collect(root: Path, cache: Path, output: Path, expected: str) -> dict:
    root = root.resolve(strict=True)
    source = validate_clean_source(root, expected)
    output = output.absolute()
    if output.exists() or output.is_symlink() or output.resolve().is_relative_to(root):
        raise ValueError("output must be a new directory outside the source")
    lock_path = root / "trillionnium/Cargo.lock"
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    public = [p for p in lock["package"] if p.get("source") == PUBLIC_REGISTRY]
    if not public or len(public) > MAX_ARCHIVES:
        raise ValueError("empty or oversized public registry inventory")
    candidates = []
    missing = []
    names = set()
    total = 0
    for package in public:
        name, version, checksum = (package[k] for k in ("name", "version", "checksum"))
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]*", version):
            raise ValueError("noncanonical registry package identity")
        if not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError("invalid locked checksum")
        filename = f"{name}-{version}.crate"
        if filename in names:
            raise ValueError("duplicate locked archive")
        names.add(filename)
        matches = sorted(cache.glob(f"*/{filename}"))
        if not matches:
            missing.append(filename)
            continue
        selected = None
        for path in matches:
            if cache.is_symlink() or path.parent.is_symlink() or path.is_symlink() or not path.is_file():
                raise ValueError("archive or cache path is not a regular non-symlink input")
            size = path.stat().st_size
            if size > MAX_ARCHIVE_BYTES:
                raise ValueError("archive byte limit exceeded")
            data = path.read_bytes()
            if len(data) != size or hashlib.sha256(data).hexdigest() != checksum:
                raise ValueError(f"locked archive checksum mismatch: {filename}")
            selected = (path, filename, checksum, size)
        assert selected is not None
        total += selected[3]
        if total > MAX_TOTAL_BYTES:
            raise ValueError("aggregate archive byte limit exceeded")
        candidates.append(selected)
    output.parent.mkdir(parents=True, exist_ok=True)
    # A partial output cannot masquerade as a complete diagnostic bundle.
    with tempfile.TemporaryDirectory(prefix=".cargo-archives-", dir=output.parent) as tmp:
        stage = Path(tmp) / "bundle"
        stage.mkdir()
        captured = []
        for path, filename, checksum, size in candidates:
            target = stage / filename
            shutil.copyfile(path, target, follow_symlinks=False)
            if target.is_symlink() or not target.is_file() or target.stat().st_size != size or hashlib.sha256(target.read_bytes()).hexdigest() != checksum:
                raise ValueError("archive changed while copying")
            captured.append({"file": filename, "sha256": checksum, "size_bytes": size})
        (stage / "Cargo.lock").write_bytes(lock_bytes)
        if validate_clean_source(root, expected) != source or lock_path.read_bytes() != lock_bytes:
            raise ValueError("source changed during collection")
        report = {
            "schema": "trnm-cached-public-cargo-archives-v1", "source": source,
            "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
            "archives": captured, "missing": sorted(missing),
            "all_locked_public_archives_captured": not missing,
            "scope": "cached-public-inputs-only-not-build-or-test-acceptance",
        }
        (stage / "manifest.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        # Destination is an isolated runner-temporary path, never a user store.
        if output.exists() or output.is_symlink():
            raise ValueError("output appeared during collection")
        stage.rename(output)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cache", type=Path, default=Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))) / "registry/cache")
    args = parser.parse_args()
    try:
        result = collect(ROOT, args.cache, args.output, args.expected_commit)
        print(json.dumps({"captured": len(result["archives"]), "missing": len(result["missing"]), "scope": result["scope"]}))
        return 0
    except (OSError, ValueError, KeyError) as error:
        parser.exit(2, f"public Cargo archive collection failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
