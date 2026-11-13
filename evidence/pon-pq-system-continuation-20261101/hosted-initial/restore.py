#!/usr/bin/env python3
"""Restore exact retained evidence bytes from a compact text publication."""
import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe(base, name):
    relative = Path(name)
    assert not relative.is_absolute() and '..' not in relative.parts
    path = base/relative
    assert path.resolve().is_relative_to(base.resolve())
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    manifest = json.loads((root/'manifest.json').read_text())
    assert manifest['schema'] == 'lossless-ci-evidence-text-storage-v1'
    assert 0 < len(manifest['files']) <= 512
    assert manifest['raw_total_bytes'] <= 64*1024*1024
    assert not args.output.exists() and not args.output.is_symlink()
    args.output.mkdir()
    total = 0
    for entry in manifest['files']:
        assert 0 <= entry['bytes'] <= 16*1024*1024
        assert 0 <= entry['storage_bytes'] <= 16*1024*1024
        source = safe(root,entry['storage_path'])
        assert source.is_file() and not source.is_symlink()
        with source.open('rb') as stream:
            stored = stream.read(entry['storage_bytes']+1)
        assert len(stored) == entry['storage_bytes']
        assert sha(stored) == entry['storage_sha256']
        if entry['encoding'] == 'gzip+base64':
            zipped = base64.b64decode(stored.strip(),validate=True)
            with gzip.GzipFile(fileobj=io.BytesIO(zipped)) as stream:
                raw = stream.read(entry['bytes']+1)
        else:
            assert entry['encoding'] == 'identity'
            raw = stored
        assert len(raw) == entry['bytes'] and sha(raw) == entry['sha256']
        output = safe(args.output,entry['path'])
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open('xb') as stream:
            stream.write(raw)
        total += len(raw)
    assert total == manifest['raw_total_bytes']
    assert sha((args.output/'manifest.json').read_bytes()) == manifest['raw_manifest_sha256']
    print(json.dumps({'restored_files':len(manifest['files']),'restored_bytes':total,
                      'raw_manifest_sha256':manifest['raw_manifest_sha256'],
                      'native_tests_executed':False},sort_keys=True))


if __name__ == '__main__':
    main()
