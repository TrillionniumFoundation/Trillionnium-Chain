#!/usr/bin/env python3
"""Verify preserved validation bytes; this does not rerun native experiments."""
import hashlib,json,zipfile
from pathlib import Path
root=Path(__file__).resolve().parent
manifest=json.loads((root/'MANIFEST.json').read_bytes())
archive=root/manifest['archive']['path']
raw=archive.read_bytes()
assert len(raw)==manifest['archive']['bytes']
assert hashlib.sha256(raw).hexdigest()==manifest['archive']['sha256']
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    assert sorted(z.namelist())==sorted(manifest['members'])
    for name,expected in manifest['members'].items():
        payload=z.read(name)
        assert len(payload)==expected['bytes'],name
        assert hashlib.sha256(payload).hexdigest()==expected['sha256'],name
print(json.dumps({'verified_archive':str(archive),'members':len(manifest['members']),
                  'sha256':manifest['archive']['sha256'],'native_experiments':0}))
