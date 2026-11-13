#!/usr/bin/env python3
"""Offline byte-preservation check; not a claim of functional correctness."""
import hashlib, json, sys
from pathlib import Path
root=Path(__file__).resolve().parent
manifest=json.loads((root/'MANIFEST.json').read_text(encoding='utf-8'))
errors=[]
for entry in manifest['files']:
    path=root/'files'/entry['name']
    try: buf=path.read_bytes()
    except OSError as exc: errors.append(f"{entry['name']}: {exc}");continue
    sha256=hashlib.sha256(buf).hexdigest()
    git_blob=hashlib.sha1(b'blob '+str(len(buf)).encode('ascii')+b'\x00'+buf).hexdigest()
    if (len(buf),sha256,git_blob)!=(entry['bytes'],entry['sha256'],entry['git_blob_sha']):
        errors.append(f"{entry['name']}: size or hash mismatch")
if errors:
    print('\n'.join('FAIL: '+e for e in errors));sys.exit(1)
print('PASS: %d preserved source files (SHA-256 and Git Blob SHA)' % len(manifest['files']))
