#!/usr/bin/env python3
"""Restore the exact native records into a new directory, checking every byte."""
import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('output', type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent
manifest = json.loads((root / 'manifest.json').read_text())
encoded = (root / manifest['encoded_file']).read_bytes()
assert hashlib.sha256(encoded).hexdigest() == manifest['encoded_sha256']
compressed = base64.b64decode(b''.join(encoded.split()), validate=True)
assert hashlib.sha256(compressed).hexdigest() == manifest['gzip_sha256']
with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
    raw = stream.read(manifest['tar_bytes'] + 1)
assert len(raw) == manifest['tar_bytes']
assert hashlib.sha256(raw).hexdigest() == manifest['tar_sha256']
expected = {row['path']: row for row in manifest['files']}
assert len(expected) == len(manifest['files'])
restored = {}
with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
    members = archive.getmembers()
    assert len(members) == len(expected)
    for member in members:
        assert member.isfile() and re.fullmatch(r'[A-Za-z0-9_.-]+', member.name)
        assert member.name in expected and member.name not in restored
        row = expected[member.name]
        assert member.size == row['bytes']
        data = archive.extractfile(member).read()
        assert len(data) == row['bytes']
        assert hashlib.sha256(data).hexdigest() == row['sha256']
        restored[member.name] = data
args.output.mkdir(parents=True, exist_ok=False)
for name, data in restored.items():
    (args.output / name).write_bytes(data)
print(json.dumps({'restored_files': len(restored), 'passed': manifest['passed'],
                  'failed': manifest['failed'], 'whole_chain_pq_qualified': False}, sort_keys=True))
