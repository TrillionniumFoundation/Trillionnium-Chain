#!/usr/bin/env python3
"""Verify every retained archive part and member without extracting or running it."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify(index_path):
    index_path = Path(index_path).resolve(strict=True)
    raw_index = index_path.read_bytes()
    index = json.loads(raw_index)
    require(index['schema'] == 'trnm-curated-evidence-archive-v1', 'archive schema')
    require(index['part_max_bytes'] == 1_572_864, 'part bound')
    expected = {}
    for row in index['members']:
        name = row['path']
        parts = PurePosixPath(name).parts
        require(name and not name.startswith('/') and '..' not in parts and '.' not in parts,
                'unsafe member path')
        require(name not in expected, 'duplicate declared member')
        expected[name] = row
    require(expected and index['parts'], 'empty archive')
    with tempfile.TemporaryFile() as combined:
        digest = hashlib.sha256()
        total = 0
        for number, part in enumerate(index['parts']):
            require(part['number'] == number, 'part order')
            require(re.fullmatch(r'raw-evidence\.tar\.zst\.part-[0-9]{3,}', part['file'])
                    and part['file'] == f'raw-evidence.tar.zst.part-{number:03d}', 'part path/number')
            require(0 < part['bytes'] <= index['part_max_bytes'], 'part size bound')
            if number < len(index['parts']) - 1:
                require(part['bytes'] == index['part_max_bytes'], 'short nonfinal part')
            path = index_path.parent / part['file']
            require(path.is_file() and not path.is_symlink(), 'missing/nonregular part')
            require(path.stat().st_size == part['bytes'] and sha(path) == part['sha256'],
                    'part content mismatch')
            with path.open('rb') as source:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    combined.write(block)
                    digest.update(block)
                    total += len(block)
        require(total == index['archive_bytes'] and digest.hexdigest() == index['archive_sha256'],
                'assembled archive mismatch')
        combined.seek(0)
        process = subprocess.Popen(['zstd', '-d', '-q', '-c'], stdin=combined,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        seen = set()
        try:
            with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                for member in archive:
                    require(member.isfile() and member.name in expected and member.name not in seen,
                            'unknown/nonregular/duplicate archive member')
                    row = expected[member.name]
                    require(member.size == row['bytes'] and member.mode == row['mode'],
                            'member size/mode mismatch')
                    require(member.mtime == 0 and member.uid == 0 and member.gid == 0,
                            'nondeterministic archive metadata')
                    member_hash = hashlib.sha256()
                    size = 0
                    reader = archive.extractfile(member)
                    for block in iter(lambda: reader.read(1024 * 1024), b''):
                        member_hash.update(block)
                        size += len(block)
                    require(size == row['bytes'] and member_hash.hexdigest() == row['sha256'],
                            'raw member mismatch')
                    seen.add(member.name)
            while process.stdout.read(1024 * 1024):
                pass
            stderr = process.stderr.read()
            require(process.wait() == 0, 'zstd failed: ' + stderr.decode(errors='replace'))
            require(seen == set(expected), 'missing archive members')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    require(index_path.read_bytes() == raw_index, 'index changed during verification')
    return {
        'schema': 'trnm-curated-evidence-archive-verification-v1',
        'result': 'PASS_ARCHIVE_CONTENT_ONLY',
        'index_sha256': hashlib.sha256(raw_index).hexdigest(),
        'verified_parts': len(index['parts']), 'verified_members': len(seen),
        'raw_member_bytes': sum(row['bytes'] for row in expected.values()),
        'archive_bytes': total, 'archive_sha256': digest.hexdigest(),
        'native_tests_executed': 0, 'whole_chain_pq_qualified': False,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('index', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.index), sort_keys=True, indent=2))
