#!/usr/bin/env python3
"""Verify exact contents of a portable evidence directory."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent).resolve()
manifest = json.loads((root / "manifest.json").read_text())
expected = {row["path"]: row for row in manifest["files"]}
if len(expected) != len(manifest["files"]):
    raise SystemExit("FAIL: duplicate manifest paths")
actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
if actual != set(expected) | {"manifest.json"}:
    raise SystemExit("FAIL: file set differs from manifest")
for name, row in expected.items():
    path = root / name
    if name == "manifest.json" or path.is_symlink() or not path.resolve().is_relative_to(root):
        raise SystemExit("FAIL: unsafe manifest path")
    raw = path.read_bytes()
    if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
        raise SystemExit("FAIL: content differs: " + name)
if len(expected) != manifest["file_count_excluding_manifest"]:
    raise SystemExit("FAIL: manifest count differs")
if sum(row["bytes"] for row in expected.values()) != manifest["total_bytes_excluding_manifest"]:
    raise SystemExit("FAIL: manifest byte total differs")
print(json.dumps({"status": "PASS", "verified_files_excluding_manifest": len(expected),
                  "total_files": len(actual),
                  "total_bytes": sum((root / name).stat().st_size for name in actual)}, sort_keys=True))
