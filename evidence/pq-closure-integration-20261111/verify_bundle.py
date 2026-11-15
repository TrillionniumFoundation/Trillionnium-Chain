#!/usr/bin/env python3
"""Verify packaged bytes and optional external archives; execute no workloads."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--archives', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parent
manifest = json.loads((root / 'package-manifest.json').read_bytes())
expected = set(manifest['files']) | {'package-manifest.json', 'SHA256SUMS'}
actual = {str(path.relative_to(root)) for path in root.rglob('*') if path.is_file()}
assert actual == expected, 'missing or extra package file'
for name, record in manifest['files'].items():
    relative = PurePosixPath(name)
    assert not relative.is_absolute() and all(part not in ('', '.', '..') for part in relative.parts)
    path = root / name
    assert not path.is_symlink()
    raw = path.read_bytes()
    assert len(raw) == record['bytes'], name
    assert hashlib.sha256(raw).hexdigest() == record['sha256'], name
for line in (root / 'SHA256SUMS').read_text().splitlines():
    digest, name = line.split('  ', 1)
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
archive_count = 0
if args.archives:
    for archive in json.loads((root / 'archive-references.json').read_bytes()):
        path = Path(archive['original_local_path'])
        assert path.stat().st_size == archive['bytes'], str(path)
        with path.open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == archive['sha256'], str(path)
        archive_count += 1
print(json.dumps({'package_files_verified': len(actual), 'original_archives_verified': archive_count,
                  'workload_execution_performed': False, 'security_qualified': False}, sort_keys=True))
