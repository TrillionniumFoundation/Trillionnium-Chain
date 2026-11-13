#!/usr/bin/env python3
"""Verify this evidence archive and losslessly encoded original streams."""
from pathlib import Path
import gzip
import hashlib
import json

root = Path(__file__).resolve().parent
manifest = json.loads((root / "artifact-manifest.json").read_text())
def digest(data):
    return hashlib.sha256(data).hexdigest()
def local(name):
    path = Path(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe archive path")
    result = root / path
    if result.is_symlink() or not result.is_file():
        raise ValueError("missing or nonregular archive member: " + name)
    return result
for item in manifest["files"]:
    data = local(item["path"]).read_bytes()
    assert len(data) == item["bytes"], item["path"]
    assert digest(data) == item["sha256"], item["path"]
mapping = json.loads((root / "copy-map.json").read_text())
for item in mapping["files"]:
    data = local(item["package_path"]).read_bytes()
    assert len(data) == item["archive_bytes"], item["package_path"]
    assert digest(data) == item["archive_sha256"], item["package_path"]
    decoded = gzip.decompress(data) if item["encoding"] == "gzip" else data
    assert len(decoded) == item["source_bytes"], item["source_path"]
    assert digest(decoded) == item["source_sha256"], item["source_path"]
print(json.dumps({"status": "ARCHIVE_BYTES_VERIFIED", "files": len(manifest["files"]),
                  "decoded_original_files": len(mapping["files"]),
                  "semantic_or_production_qualification": False}, sort_keys=True))
