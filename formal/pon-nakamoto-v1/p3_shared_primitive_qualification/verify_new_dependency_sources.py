#!/usr/bin/env python3
"""Check newly added registry sources against Cargo.lock and cached archives.

Offline, read-only source-identity check. It does not audit the algorithms or
grant implementation/security qualification. The baseline is intentionally fixed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tomllib

BASELINE = "cc836dfc13ef0006eb0878abd8cb5eca9a76bec0"
MANIFEST = "formal/pon-nakamoto-v1/w1_public_stark_research/Cargo.lock"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--registry", type=Path,
                        default=Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")) / "registry")
    args = parser.parse_args()
    root = args.repository.resolve()
    old = tomllib.loads(subprocess.check_output(
        ["git", "show", BASELINE + ":" + MANIFEST], cwd=root, text=True))
    new = tomllib.loads((root / MANIFEST).read_text())
    before = {(p["name"], p["version"]) for p in old["package"]}
    added = [p for p in new["package"] if (p["name"], p["version"]) not in before]
    if {(p["name"], p["version"]) for p in added} != {("keccak", "0.1.6"), ("sha3", "0.10.9")}:
        raise SystemExit("Unexpected new dependency set")
    records = []
    for package in added:
        name = package["name"] + "-" + package["version"]
        archives = list((args.registry / "cache").glob("*/" + name + ".crate"))
        sources = list((args.registry / "src").glob("*/" + name))
        if len(archives) != 1 or len(sources) != 1:
            raise SystemExit("Expected one cached archive and source directory: " + name)
        archive_digest = hashlib.sha256(archives[0].read_bytes()).hexdigest()
        if archive_digest != package["checksum"]:
            raise SystemExit("Locked archive checksum mismatch: " + name)
        files = []
        with tarfile.open(archives[0], mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                rel = PurePosixPath(member.name).relative_to(name)
                if ".." in rel.parts:
                    raise SystemExit("Invalid archive member path")
                expected = archive.extractfile(member).read()
                if expected != (sources[0] / str(rel)).read_bytes():
                    raise SystemExit("Registry source mismatch: " + name + "/" + str(rel))
                files.append({"path": str(rel), "sha256": hashlib.sha256(expected).hexdigest()})
        records.append({"package": name, "archive_sha256": archive_digest,
                        "locked_checksum_matches": True, "registry_files_match_archive": True,
                        "file_count": len(files), "files": files})
    print(json.dumps({"schema": "p3.shared.sha3.new-dependency-integrity.v1",
                      "baseline": BASELINE,
                      "new_packages": [(p["name"], p["version"]) for p in added],
                      "records": records}, indent=2))


if __name__ == "__main__":
    main()
