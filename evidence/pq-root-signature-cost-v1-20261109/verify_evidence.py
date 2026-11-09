#!/usr/bin/env python3
"""Check retained bytes and archive membership; this is not an execution attestation."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile


def checked_path(value):
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or str(path) != value:
        raise ValueError('noncanonical evidence path: ' + value)
    return path


def check(data, record):
    if len(data) != record['bytes'] or hashlib.sha256(data).hexdigest() != record['sha256']:
        raise ValueError('evidence digest mismatch: ' + record['path'])


def main():
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / 'manifest.json').read_text())
    expected = {entry['path']: entry for entry in manifest['files']}
    if len(expected) != len(manifest['files']):
        raise ValueError('duplicate manifest entries')
    observed = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and str(p.relative_to(root)) != 'manifest.json'}
    if observed != set(expected):
        raise ValueError('unexpected or missing evidence files')
    for name, entry in expected.items():
        checked_path(name)
        path = root / name
        if path.is_symlink():
            raise ValueError('evidence symlink')
        check(path.read_bytes(), entry)
    member_count = 0
    for archive in manifest['archives']:
        checked_path(archive['path'])
        wanted = {entry['path']: entry for entry in archive['members']}
        if len(wanted) != len(archive['members']):
            raise ValueError('duplicate archive manifest entries')
        with tarfile.open(root / archive['path'], 'r:gz') as tar:
            members = tar.getmembers()
            if len(members) != len(wanted) or {m.name for m in members} != set(wanted):
                raise ValueError('archive membership mismatch')
            for member in members:
                checked_path(member.name)
                if not member.isfile():
                    raise ValueError('unexpected archive entry type')
                with tar.extractfile(member) as stream:
                    check(stream.read(), wanted[member.name])
                member_count += 1
    print(json.dumps({'status': 'BYTE_INTEGRITY_VERIFIED', 'files': len(expected), 'archive_members': member_count, 'independent_execution_authentication': False}))


if __name__ == '__main__':
    main()
