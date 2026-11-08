#!/usr/bin/env python3
"""Verify the exact selected CI archive; hashes are identity, not qualification."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_name(name):
    if not isinstance(name, str) or not name or "\\" in name:
        raise ValueError("unsafe archive name")
    p = PurePosixPath(name)
    if p.is_absolute() or any(x in ("", ".", "..") for x in name.split("/")):
        raise ValueError("unsafe archive name")
    return p

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extract", type=Path)
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    manifest = json.loads((base / "raw-manifest.json").read_text())
    if manifest["schema"] != "trnm-responsive-CI-archive-v1":
        raise ValueError("manifest schema")
    archive_meta = manifest["archive"]
    archive = base / safe_name(archive_meta["path"])
    if archive.stat().st_size != archive_meta["size"] or digest(archive) != archive_meta["sha256"]:
        raise ValueError("archive size/hash")
    expected = {}
    for row in manifest["files"]:
        name = str(safe_name(row["path"]))
        if name in expected or type(row["size"]) is not int or row["size"] < 0:
            raise ValueError("duplicate or invalid manifest member")
        expected[name] = row
    seen = set()
    with tarfile.open(archive, "r:gz") as packed:
        for member in packed:
            name = str(safe_name(member.name))
            if not member.isfile() or name in seen or name not in expected:
                raise ValueError("nonregular, duplicate or unexpected member")
            row = expected[name]
            if member.size != row["size"]:
                raise ValueError("member size: " + name)
            stream = packed.extractfile(member)
            if stream is None:
                raise ValueError("missing member stream")
            h = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(chunk)
            if h.hexdigest() != row["sha256"]:
                raise ValueError("member hash: " + name)
            seen.add(name)
    if seen != set(expected):
        raise ValueError("missing members")
    if digest(archive) != archive_meta["sha256"]:
        raise ValueError("archive changed during verification")
    if args.extract is not None:
        destination = args.extract.absolute()
        if destination.exists() or destination.is_symlink():
            raise ValueError("extraction destination must be absent")
        destination.mkdir(mode=0o700)
        extracted_seen = set()
        with tarfile.open(archive, "r:gz") as packed:
            for member in packed:
                name = str(safe_name(member.name))
                if not member.isfile() or name not in expected or name in extracted_seen:
                    raise ValueError("archive changed before extraction")
                if member.size != expected[name]["size"]:
                    raise ValueError("member size changed before extraction")
                stream = packed.extractfile(member)
                if stream is None:
                    raise ValueError("missing member stream")
                data = stream.read()
                row = expected[name]
                if len(data) != row["size"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
                    raise ValueError("member changed before extraction")
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as result:
                    result.write(data)
                extracted_seen.add(name)
        if extracted_seen != set(expected):
            raise ValueError("incomplete extraction")
        if digest(archive) != archive_meta["sha256"]:
            raise ValueError("archive changed during extraction")
    print(json.dumps({"status": "VERIFIED", "members": len(seen),
                      "member_bytes": sum(x["size"] for x in expected.values()),
                      "archive_sha256": archive_meta["sha256"]}, sort_keys=True))

if __name__ == "__main__":
    main()
