#!/usr/bin/env python3
"""Verify and restore this evidence package without executing its recorded code."""
import argparse
import base64
import binascii
import gzip
import hashlib
import json
import os
import pathlib
import re
import stat
import tarfile
import tempfile

MAX_TAR = 512 * 1024 * 1024
MAX_GZIP = 128 * 1024 * 1024
MAX_MANIFEST = 4 * 1024 * 1024
MAX_FILES = 10000
MAX_PARTS = 5000
MAX_PART_BYTES = 160000

def require(ok, message):
    if not ok:
        raise ValueError(message)

def unique_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON constant')))

def safe_relative(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9._/-]+', value) is not None, 'noncanonical relative path')
    path = pathlib.PurePosixPath(value)
    require(not path.is_absolute() and all(part not in ('', '.', '..') for part in value.split('/')) and path.as_posix() == value, 'unsafe relative path: ' + value)
    return path

def integer(value, limit, label):
    require(type(value) is int and 0 <= value <= limit, 'invalid bounded integer: ' + label)
    return value

def digest(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None, 'invalid SHA256')
    return value

def sha(data):
    return hashlib.sha256(data).hexdigest()

def bounded_file(root, name, maximum, expected_size=None, expected_sha=None):
    parts = safe_relative(name).parts
    path = root
    for part in parts:
        path = path / part
        require(not path.is_symlink(), 'symlink package component')
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= maximum, 'nonregular/oversized package file')
    if expected_size is not None:
        require(metadata.st_size == expected_size, 'package size mismatch: ' + name)
    with path.open('rb') as stream:
        data = stream.read(maximum + 1)
    require(len(data) == metadata.st_size, 'package file changed while reading')
    if expected_sha is not None:
        require(sha(data) == digest(expected_sha), 'package SHA256 mismatch: ' + name)
    return data

def stream_hash(stream, size, output=None):
    result = hashlib.sha256()
    remaining = size
    while remaining:
        data = stream.read(min(1024 * 1024, remaining))
        require(bool(data), 'truncated archive member')
        result.update(data)
        if output is not None:
            output.write(data)
        remaining -= len(data)
    require(stream.read(1) == b'', 'oversized archive member')
    return result.hexdigest()

def restore(bundle, output):
    manifest_bytes = bounded_file(bundle, 'manifest.json', MAX_MANIFEST)
    manifest = unique_json(manifest_bytes)
    require(manifest.get('schema') == 'trnm-pq-evidence-archive-v1', 'unknown package schema')
    require(manifest.get('status') == 'HOLD' and manifest.get('whole_chain_pq_qualified') is False, 'unexpected qualification promotion')
    count = integer(manifest['file_count'], MAX_FILES, 'file count')
    raw_total = integer(manifest['raw_total_bytes'], MAX_TAR, 'raw byte total')
    tar_size = integer(manifest['tar']['bytes'], MAX_TAR, 'tar bytes')
    gzip_size = integer(manifest['gzip']['bytes'], MAX_GZIP, 'gzip bytes')
    require(manifest['max_encoded_part_bytes'] == MAX_PART_BYTES, 'unknown chunk bound')
    parts = manifest['parts']
    require(isinstance(parts, list) and 0 < len(parts) <= MAX_PARTS, 'invalid chunk list')
    for support in manifest['support_files']:
        require(support['path'] in ('README.md', 'restore.py', 'build_archive.py'), 'unexpected support file')
        bounded_file(bundle, support['path'], MAX_PART_BYTES, integer(support['bytes'], MAX_PART_BYTES, 'support bytes'), support['sha256'])
    require(len(manifest['support_files']) == 3 and len({s['path'] for s in manifest['support_files']}) == 3, 'missing/duplicate support file')
    require(not output.exists() and not output.is_symlink(), 'output must not already exist')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='pq-evidence-restore-', dir=output.parent) as temp:
        temp = pathlib.Path(temp)
        gz_path = temp / 'payload.gz'
        gz_hash = hashlib.sha256()
        decoded_total = 0
        names = set()
        with gz_path.open('xb') as dst:
            for index, part in enumerate(parts):
                require(part['path'] == 'chunks/part-' + str(index).zfill(5) + '.b64', 'out-of-order chunk path')
                require(part['path'] not in names, 'duplicate chunk')
                names.add(part['path'])
                size = integer(part['bytes'], MAX_PART_BYTES, 'encoded part bytes')
                encoded = bounded_file(bundle, part['path'], MAX_PART_BYTES, size, part['sha256'])
                require(encoded.endswith(b'\n') and b'\n' not in encoded[:-1] and b'\r' not in encoded, 'noncanonical base64 framing')
                data = base64.b64decode(encoded[:-1], validate=True)
                require(len(data) == integer(part['decoded_bytes'], MAX_PART_BYTES, 'decoded part bytes'), 'decoded size mismatch')
                require(sha(data) == digest(part['decoded_sha256']), 'decoded SHA256 mismatch')
                require(part['gzip_offset'] == decoded_total, 'noncontiguous gzip offsets')
                decoded_total += len(data)
                require(decoded_total <= gzip_size, 'gzip body exceeds declared bound')
                gz_hash.update(data)
                dst.write(data)
        require(decoded_total == gzip_size and gz_hash.hexdigest() == digest(manifest['gzip']['sha256']), 'gzip aggregate mismatch')
        tar_path = temp / 'payload.tar'
        tar_hash = hashlib.sha256()
        unpacked = 0
        with gzip.open(gz_path, 'rb') as src, tar_path.open('xb') as dst:
            while True:
                data = src.read(1024 * 1024)
                if not data:
                    break
                unpacked += len(data)
                require(unpacked <= tar_size, 'decompressed archive exceeds declared bound')
                tar_hash.update(data)
                dst.write(data)
        require(unpacked == tar_size and tar_hash.hexdigest() == digest(manifest['tar']['sha256']), 'tar aggregate mismatch')
        raw_record = manifest['raw_manifest']
        require(raw_record['path'] == 'RAW_FILES.json', 'unknown raw manifest path')
        raw_manifest_size = integer(raw_record['bytes'], MAX_MANIFEST, 'raw manifest bytes')
        with tarfile.open(tar_path, 'r:') as tar:
            members = []
            seen = set()
            for member in tar:
                require(len(members) <= count, 'too many tar members')
                safe_relative(member.name)
                require(member.name not in seen, 'duplicate tar member')
                require(member.isfile() and member.sparse is None and set(member.pax_headers).issubset({'path'}), 'nonregular/unsupported tar member')
                require(member.uid == member.gid == member.mtime == 0 and member.mode == 0o644, 'noncanonical tar metadata')
                integer(member.size, MAX_TAR, 'member bytes')
                seen.add(member.name)
                members.append(member)
            require(len(members) == count + 1 and members[0].name == 'RAW_FILES.json', 'incomplete raw member set')
            first = members[0]
            require(first.size == raw_manifest_size, 'raw manifest size mismatch')
            with tar.extractfile(first) as stream:
                raw_manifest_bytes = stream.read(raw_manifest_size + 1)
            require(len(raw_manifest_bytes) == raw_manifest_size and sha(raw_manifest_bytes) == digest(raw_record['sha256']), 'raw manifest SHA256 mismatch')
            raw = unique_json(raw_manifest_bytes)
            require(raw.get('schema') == 'trnm-pq-evidence-raw-files-v1' and raw['file_count'] == count and raw['raw_total_bytes'] == raw_total, 'raw manifest totals mismatch')
            expected = {}
            for row in raw['files']:
                path = safe_relative(row['path'])
                require(row['path'] != 'RAW_FILES.json' and row['path'] not in expected, 'duplicate/reserved raw path')
                expected[row['path']] = (integer(row['bytes'], raw_total, 'raw file bytes'), digest(row['sha256']))
            require(len(expected) == count and sum(v[0] for v in expected.values()) == raw_total, 'raw file accounting mismatch')
            require([m.name for m in members[1:]] == sorted(expected), 'unexpected/unsorted archive files')
            for name in expected:
                for parent in pathlib.PurePosixPath(name).parents:
                    require(str(parent) not in expected, 'file/directory path collision')
            stage = temp / 'restored'
            stage.mkdir()
            (stage / 'RAW_FILES.json').write_bytes(raw_manifest_bytes)
            for member in members[1:]:
                size, expected_sha = expected[member.name]
                require(member.size == size, 'member size differs from manifest')
                target = stage / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as src, target.open('xb') as dst:
                    actual_sha = stream_hash(src, size, dst)
                require(actual_sha == expected_sha, 'restored file SHA256 mismatch: ' + member.name)
                os.chmod(target, 0o644)
            require(not output.exists() and not output.is_symlink(), 'output appeared during verification')
            stage.rename(output)
    return {'schema': 'trnm-pq-evidence-restore-result-v1', 'result': 'PASS', 'restored_files': count, 'restored_raw_bytes': raw_total, 'raw_manifest_sha256': raw_record['sha256'], 'manifest_sha256': sha(manifest_bytes), 'output': str(output), 'native_code_executed': False, 'whole_chain_pq_qualified': False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--bundle', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent)
    args = parser.parse_args()
    try:
        result = restore(args.bundle.resolve(strict=True), args.output.absolute())
    except (OSError, ValueError, KeyError, TypeError, binascii.Error, tarfile.TarError) as error:
        print(json.dumps({'result': 'REFUSE', 'error': str(error), 'whole_chain_pq_qualified': False}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
