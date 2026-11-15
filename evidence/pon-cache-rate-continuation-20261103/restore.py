#!/usr/bin/env python3
"""Restore the bounded validation log archive into a new directory."""
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

root = Path(__file__).resolve().parent
if len(sys.argv) != 2:
    raise SystemExit("usage: restore.py NEW_DIRECTORY")
target = Path(sys.argv[1])
if target.exists():
    raise SystemExit("destination must not exist")
manifest = json.loads((root / "raw-manifest.json").read_text())
raw = base64.b64decode((root / "raw-validation.tar.gz.base64").read_bytes(), validate=True)
if hashlib.sha256(raw).hexdigest() != manifest["archive_sha256"]:
    raise SystemExit("archive digest mismatch")
expected = {row["path"]: row for row in manifest["files"]}
contents = {}
with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
    for member in archive:
        name = member.name
        if (not member.isfile() or name not in expected or name in contents
                or Path(name).name != name or member.size != expected[name]["bytes"]
                or member.size > 4_000_000):
            raise SystemExit("unexpected archive member")
        stream = archive.extractfile(member)
        data = stream.read(member.size + 1)
        if len(data) != member.size or hashlib.sha256(data).hexdigest() != expected[name]["sha256"]:
            raise SystemExit("member digest mismatch")
        contents[name] = data
if set(contents) != set(expected):
    raise SystemExit("incomplete archive")
target.mkdir()
for name, data in contents.items():
    with (target / name).open("xb") as stream:
        stream.write(data)
print(json.dumps({"files": len(contents), "destination": str(target), "digests_checked": True}))
