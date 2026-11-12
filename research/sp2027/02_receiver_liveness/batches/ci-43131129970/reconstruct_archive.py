#!/usr/bin/env python3
"""Concatenate exact original ZIP bytes; refuse any missing/changed part."""
import argparse
import hashlib
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / 'ARTIFACT_PARTS.json').read_text())
    assert manifest['schema'] == 'sp27-original-artifact-parts-v1'
    assert not args.out.exists(), 'output must be absent'
    temporary = args.out.with_name(args.out.name + '.unpublished')
    assert not temporary.exists(), 'temporary output must be absent'
    args.out.parent.mkdir(parents=True, exist_ok=True)
    digest, total = hashlib.sha256(), 0
    try:
        with temporary.open('xb') as output:
            for part in manifest['parts']:
                name = Path(part['path'])
                assert not name.is_absolute() and '..' not in name.parts
                assert part['offset'] == total
                raw = (root / name).read_bytes()
                assert len(raw) == part['size_bytes']
                assert hashlib.sha256(raw).hexdigest() == part['sha256']
                output.write(raw)
                digest.update(raw)
                total += len(raw)
        assert total == manifest['original_size_bytes']
        assert digest.hexdigest() == manifest['original_sha256']
        assert not args.out.exists(), 'output appeared during reconstruction'
        temporary.chmod(0o444)
        os.rename(temporary, args.out)
        print(json.dumps({'archive': str(args.out), 'bytes': total,
                          'sha256': digest.hexdigest(), 'rewrapped': False}, sort_keys=True))
    finally:
        if temporary.exists():
            temporary.unlink()


if __name__ == '__main__':
    main()
