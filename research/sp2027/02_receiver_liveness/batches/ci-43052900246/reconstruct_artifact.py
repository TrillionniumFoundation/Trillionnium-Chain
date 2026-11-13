#!/usr/bin/env python3
"""Reassemble the unchanged GitHub artifact; never overwrite an output."""
import argparse
import hashlib
import json
import os
from pathlib import Path

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
manifest = json.loads((root / 'ARTIFACT_PARTS.json').read_text())
digest = hashlib.sha256()
total = 0
with args.out.open('xb') as output:
    for part in manifest['parts']:
        raw = (root / part['path']).read_bytes()
        assert part['offset'] == total and len(raw) == part['size_bytes']
        assert hashlib.sha256(raw).hexdigest() == part['sha256']
        output.write(raw)
        digest.update(raw)
        total += len(raw)
    output.flush()
    os.fsync(output.fileno())
assert total == manifest['original_size_bytes']
assert digest.hexdigest() == manifest['original_sha256']
print(json.dumps({'size_bytes': total, 'sha256': digest.hexdigest(), 'raw_bytes_modified': False}))
