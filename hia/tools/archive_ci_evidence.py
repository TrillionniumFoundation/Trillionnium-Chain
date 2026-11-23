#!/usr/bin/env python3
"""Package CI evidence whose original names cannot be sent as Actions paths."""
import argparse
import hashlib
from pathlib import Path
import tarfile
import tempfile


def inventory(root):
    result = {}
    for path in root.rglob("*"):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError(f"unsupported evidence entry: {path.relative_to(root)!r}")
        result[path.relative_to(root).as_posix()] = path
    return result


def archive_evidence(root, output):
    root, output = root.resolve(strict=True), output.resolve()
    if not root.is_dir() or output.is_relative_to(root):
        raise ValueError("evidence must be a directory and output must be outside it")
    entries = inventory(root)
    if not any(path.is_file() for path in entries.values()):
        raise ValueError("no evidence files")
    output.parent.mkdir(parents=True, exist_ok=True)
    # PAX with surrogateescape round-trips Linux filename bytes, including CR.
    options = dict(encoding="utf-8", errors="surrogateescape")
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        candidate = Path(temporary) / "evidence.tar"
        with tarfile.open(candidate, "w:", format=tarfile.PAX_FORMAT, dereference=True, **options) as archive:
            for name, path in sorted(entries.items()):
                archive.add(path, arcname=name, recursive=False)
        if set(inventory(root)) != set(entries):
            raise ValueError("evidence paths changed while packaging")
        seen = set()
        with tarfile.open(candidate, "r:", **options) as archive:
            for member in archive:
                path = entries.get(member.name)
                if path is None or member.name in seen:
                    raise ValueError(f"unexpected archive member: {member.name!r}")
                seen.add(member.name)
                if member.isdir() and path.is_dir():
                    continue
                if not (member.isfile() and path.is_file()):
                    raise ValueError(f"archive member type changed: {member.name!r}")
                with archive.extractfile(member) as archived, path.open("rb") as original:
                    if (member.size != path.stat().st_size or
                        hashlib.file_digest(archived, "sha256").digest()
                        != hashlib.file_digest(original, "sha256").digest()):
                        raise ValueError(f"archive member bytes changed: {member.name!r}")
        if seen != set(entries):
            raise ValueError("archive member roster differs from evidence")
        candidate.replace(output)
    return len(entries)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(f"Verified archive members: {archive_evidence(args.source, args.destination)}")
