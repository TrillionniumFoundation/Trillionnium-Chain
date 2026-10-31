#!/usr/bin/env python3
"""Verify ordered native-binary gzip fragments using only the standard library."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import tempfile
from pathlib import Path


def verify(manifest_path: Path, output: Path | None = None) -> dict:
    manifest = json.loads(manifest_path.read_text())
    if manifest["schema"] != "pon-history-native-binary-fragments-v1":
        raise ValueError("archive manifest schema")
    if manifest["archive"]["format"] != "gzip":
        raise ValueError("archive format")
    if output is not None and output.exists():
        raise FileExistsError(output)
    pieces = manifest["pieces"]
    if not pieces or len({part["name"] for part in pieces}) != len(pieces):
        raise ValueError("empty or repeated pieces")
    archive_hash = hashlib.sha256()
    archive_bytes = 0
    with tempfile.TemporaryFile() as archive:
        for part in pieces:
            name = part["name"]
            if Path(name).name != name or name in {".", ".."}:
                raise ValueError("nonlocal piece name")
            if not 0 < part["bytes"] <= 7_000_000:
                raise ValueError("piece byte limit")
            piece_hash = hashlib.sha256()
            piece_bytes = 0
            with (manifest_path.parent / name).open("rb") as incoming:
                for chunk in iter(lambda: incoming.read(1024 * 1024), b""):
                    piece_bytes += len(chunk)
                    if piece_bytes > part["bytes"]:
                        raise ValueError("piece longer than manifest")
                    piece_hash.update(chunk)
                    archive_hash.update(chunk)
                    archive.write(chunk)
            if piece_bytes != part["bytes"] or piece_hash.hexdigest() != part["sha256"]:
                raise ValueError("piece bytes or hash mismatch")
            archive_bytes += piece_bytes
        if (
            archive_bytes != manifest["archive"]["bytes"]
            or archive_hash.hexdigest() != manifest["archive"]["sha256"]
        ):
            raise ValueError("whole archive bytes or hash mismatch")
        archive.seek(0)
        native_hash = hashlib.sha256()
        native_bytes = 0
        with tempfile.TemporaryFile() as native:
            with gzip.GzipFile(fileobj=archive, mode="rb") as incoming:
                for chunk in iter(lambda: incoming.read(1024 * 1024), b""):
                    native_bytes += len(chunk)
                    if native_bytes > manifest["native"]["bytes"]:
                        raise ValueError("native binary longer than manifest")
                    native_hash.update(chunk)
                    if output is not None:
                        native.write(chunk)
            if (
                native_bytes != manifest["native"]["bytes"]
                or native_hash.hexdigest() != manifest["native"]["sha256"]
            ):
                raise ValueError("native binary bytes or hash mismatch")
            if output is not None:
                native.seek(0)
                # Creation is exclusive. Never overwrite an existing artifact.
                with output.open("xb") as destination:
                    shutil.copyfileobj(native, destination, 1024 * 1024)
                output.chmod(0o755)
    return {
        "schema": "pon-history-native-binary-readback-v1",
        "manifest": str(manifest_path),
        "pieces": len(pieces),
        "archive_bytes": archive_bytes,
        "archive_sha256": archive_hash.hexdigest(),
        "native_bytes": native_bytes,
        "native_sha256": native_hash.hexdigest(),
        "compiled_host_source_sha256": manifest["compiled_host_source_sha256"],
        "output": str(output) if output is not None else None,
        "native_execution_performed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.manifest, args.output), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
