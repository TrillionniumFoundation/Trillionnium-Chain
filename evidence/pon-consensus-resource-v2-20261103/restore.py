#!/usr/bin/env python3
"""Restore retained text observations into a new directory; never execute them."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    manifest = json.loads((here / 'native-records-manifest.json').read_text())
    encoded = (here / 'native-records.tar.gz.base64').read_bytes()
    if hashlib.sha256(encoded).hexdigest() != manifest['encoded_sha256']:
        raise ValueError('encoded observation archive changed')
    raw = base64.b64decode(encoded, validate=True)
    if hashlib.sha256(raw).hexdigest() != manifest['archive_sha256']:
        raise ValueError('observation archive changed')
    members = {entry['path']: entry for entry in manifest['members']}
    if len(members) != len(manifest['members']):
        raise ValueError('duplicate manifest paths')
    args.out.mkdir(parents=True, exist_ok=False)
    seen = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if (not member.isfile() or path.is_absolute() or '..' in path.parts
                    or member.name not in members or member.name in seen):
                raise ValueError('unexpected observation member')
            expected = members[member.name]
            total += member.size
            if (member.size != expected['bytes'] or member.size > 16 * 1024 * 1024
                    or total > 128 * 1024 * 1024):
                raise ValueError('observation member size changed')
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError('missing regular observation member')
            data = stream.read(member.size + 1)
            if len(data) != member.size or hashlib.sha256(data).hexdigest() != expected['sha256']:
                raise ValueError('observation bytes changed')
            destination = args.out.joinpath(*path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as output:
                output.write(data)
            seen.add(member.name)
    if seen != set(members):
        raise ValueError('incomplete observation archive')
    print(json.dumps({'record_restore': 'PASS', 'members': len(seen),
                      'native_execution': False, 'qualification_status': 'HOLD'}))


if __name__ == '__main__':
    main()
