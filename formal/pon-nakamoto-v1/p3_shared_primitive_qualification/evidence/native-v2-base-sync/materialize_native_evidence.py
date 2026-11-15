#!/usr/bin/env python3
"""Materialize exact native observation bytes from the retained deduplicated store.

This is an offline evidence utility. It validates relative names, bounded object
sizes, SHA-256 and the complete byte count before publishing each file into a new
output directory. It does not run a proof, reconstruct a lost observation or
change the historical source/binary paths embedded in raw reports.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil

MAX_FILE_BYTES = 16 * 1024 * 1024


def safe_path(text):
    p = PurePosixPath(text)
    if p.is_absolute() or '..' in p.parts or not p.parts or str(p) != text:
        raise ValueError('noncanonical evidence path: ' + text)
    return p


def materialize(evidence, output):
    index = json.loads((evidence / 'file-index.json').read_text())
    if index['schema'] != 'p3-native-observation-file-store-v1':
        raise ValueError('unknown evidence store schema')
    output.mkdir(parents=True, exist_ok=False)
    seen = set()
    total = 0
    for item in index['files']:
        rel = safe_path(item['path'])
        if str(rel) in seen:
            raise ValueError('duplicate evidence path')
        seen.add(str(rel))
        expected_bytes = item['bytes']
        if not isinstance(expected_bytes, int) or not 0 <= expected_bytes <= MAX_FILE_BYTES:
            raise ValueError('evidence file exceeds fixed bound')
        storage = item['storage']
        source = evidence / safe_path(storage['path'])
        if source.is_symlink() or not source.is_file():
            raise ValueError('nonordinary evidence input')
        if storage['kind'] == 'gzip_object':
            packed = source.read_bytes()
            if hashlib.sha256(packed).hexdigest() != storage['sha256']:
                raise ValueError('compressed object hash mismatch')
            with gzip.open(source, 'rb') as f:
                data = f.read(expected_bytes + 1)
                if len(data) != expected_bytes or f.read(1):
                    raise ValueError('object expands beyond expected byte count')
        elif storage['kind'] == 'plain':
            data = source.read_bytes()
        else:
            raise ValueError('unknown evidence storage kind')
        if len(data) != expected_bytes or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('retained native file hash mismatch: ' + str(rel))
        target = output / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        total += len(data)
    return {'schema':'p3-native-evidence-materialization-v1','result':'PASS','files':len(seen),'bytes':total,'output':str(output)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output', type=Path, required=True)
    a = parser.parse_args()
    print(json.dumps(materialize(a.evidence, a.output)))


if __name__ == '__main__':
    main()
