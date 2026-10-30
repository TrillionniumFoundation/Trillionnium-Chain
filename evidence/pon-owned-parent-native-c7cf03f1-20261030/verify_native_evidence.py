#!/usr/bin/env python3
"""Verify raw evidence bytes and optionally extract them into a new directory.

Integrity of archived bytes does not itself establish test or security acceptance.
"""
from pathlib import Path, PurePosixPath
import argparse
import base64
import hashlib
import json
import re

PREFIXES = {'observations', 'runners', 'metadata', 'probe', 'summaries', 'root-source-controls'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read_regular(path):
    require(not path.is_symlink() and path.is_file(), 'regular evidence file required')
    return path.read_bytes()


def safe_relative(name):
    require(isinstance(name, str) and '\\' not in name and '\x00' not in name,
            'invalid logical path')
    p = PurePosixPath(name)
    require(not p.is_absolute() and name == p.as_posix() and
            all(x not in ('', '.', '..') for x in p.parts) and p.parts[0] in PREFIXES,
            'logical path outside fixed evidence prefixes')
    return p


def verify(root):
    index = json.loads(read_regular(root / 'index.json'))
    require(index['schema'] == 'pon-owned-parent-raw-evidence-index-v1', 'wrong index schema')
    require(len(index['files']) <= 10000, 'too many evidence files')
    chunks = {}
    for expected in index['packs']:
        name = expected['path']
        require(re.fullmatch(r'pack-[0-9]{4}\.json', name), 'invalid pack path')
        data = read_regular(root / name)
        require(len(data) == expected['bytes'] and hashlib.sha256(data).hexdigest() == expected['sha256'],
                'pack hash or size mismatch')
        pack = json.loads(data)
        require(pack['schema'] == 'pon-owned-parent-raw-evidence-pack-v1', 'wrong pack schema')
        for item in pack['parts']:
            key = (item['file_id'], item['part'])
            require(key not in chunks, 'duplicate raw part')
            raw = base64.b64decode(item['data_base64'], validate=True)
            require(len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256'],
                    'raw part hash or size mismatch')
            chunks[key] = (name, item, raw)
    decoded = []
    paths = set()
    used = set()
    for file_id, item in enumerate(index['files']):
        require(item['id'] == file_id, 'noncanonical file id')
        path = safe_relative(item['path'])
        require(path not in paths, 'duplicate logical path')
        paths.add(path)
        require(0 <= item['bytes'] <= 64 * 1024 * 1024, 'raw file exceeds archive limit')
        assembled = bytearray()
        for part, expected in enumerate(item['parts']):
            key = (file_id, part)
            require(key in chunks, 'missing raw part')
            pack_name, actual, raw = chunks[key]
            require(key not in used and pack_name == expected['pack'] and actual['offset'] == len(assembled)
                    and actual['bytes'] == expected['bytes'] and actual['sha256'] == expected['sha256'],
                    'part mapping or offset mismatch')
            used.add(key)
            assembled.extend(raw)
        data = bytes(assembled)
        require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'],
                'original raw file hash or size mismatch')
        decoded.append((path, data))
    require(used == set(chunks), 'unreferenced raw part')
    require(len(decoded) == index['raw_file_count'] and sum(len(b) for _, b in decoded) == index['raw_bytes'],
            'archive total mismatch')
    return index, decoded


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    p.add_argument('--extract', type=Path)
    args = p.parse_args()
    index, decoded = verify(args.root.resolve())
    if args.extract is not None:
        dest = args.extract.absolute()
        require(not dest.exists() and not dest.is_symlink(), 'extraction directory must not exist')
        require(all(not part.is_symlink() for part in [dest, *dest.parents]), 'symlink in extraction destination')
        dest.mkdir(parents=True, exist_ok=False)
        for rel, data in decoded:
            path = dest.joinpath(*rel.parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            require(all(not part.is_symlink() for part in [path, *path.parents]), 'symlink in extraction path')
            with path.open('xb') as stream:
                stream.write(data)
    print(json.dumps({'schema': 'pon-owned-parent-raw-evidence-integrity-result-v1',
                      'verified_files': len(decoded), 'verified_bytes': index['raw_bytes'],
                      'extracted': args.extract is not None, 'integrity_only_not_test_acceptance': True}))


if __name__ == '__main__':
    main()
