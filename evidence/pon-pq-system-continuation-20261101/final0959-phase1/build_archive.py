#!/usr/bin/env python3
"""Build a deterministic evidence archive from a frozen, explicit file plan."""
import argparse
import base64
import gzip
import hashlib
import io
import json
import pathlib
import re
import shutil
import stat
import tarfile
import zlib

CHUNK_RAW_BYTES = 117000
MAX_CHUNK_BYTES = 160000

def encode_json(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()

def safe_relative(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9._/-]+', value):
        raise ValueError('noncanonical relative path')
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in ('', '.', '..') for part in value.split('/')) or path.as_posix() != value:
        raise ValueError('unsafe relative path: ' + value)
    return path

def hash_file(path):
    digest = hashlib.sha256()
    count = 0
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(data)
            count += len(data)
    return count, digest.hexdigest()

def info(name, size):
    result = tarfile.TarInfo(name)
    result.size = size
    result.mode = 0o644
    result.uid = result.gid = result.mtime = 0
    result.uname = result.gname = ''
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--source-root', type=pathlib.Path)
    parser.add_argument('--work', type=pathlib.Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_bytes())
    args.output.mkdir(parents=True, exist_ok=True)
    args.work.mkdir(parents=True, exist_ok=True)
    chunks = args.output / 'chunks'
    chunks.mkdir(exist_ok=True)
    if list(chunks.iterdir()):
        raise ValueError('output chunks directory must be empty')
    files = []
    sources = {}
    for original in plan['files']:
        name = original.get('archive', original.get('path'))
        safe_relative(name)
        if name == 'RAW_FILES.json' or name in sources:
            raise ValueError('reserved/duplicate archive path')
        source = args.source_root / name if args.source_root else pathlib.Path(original['source'])
        metadata = source.lstat()
        if source.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError('source must be a regular file: ' + str(source))
        size, digest = hash_file(source)
        if size != original['bytes'] or ('sha256' in original and digest != original['sha256']):
            raise ValueError('source differs from frozen plan: ' + name)
        with source.open('rb') as stream:
            if stream.read(4) == b'\x7fELF' or source.suffix.lower() == '.zip':
                raise ValueError('ELF/ZIP body excluded: ' + name)
        files.append({'path': name, 'source': original['source'], 'bytes': size, 'sha256': digest})
        sources[name] = source
    files.sort(key=lambda item: item['path'])
    raw_manifest = {
        'schema': 'trnm-pq-evidence-raw-files-v1',
        'metadata': plan.get('metadata', {}),
        'file_count': len(files),
        'raw_total_bytes': sum(item['bytes'] for item in files),
        'files': files,
    }
    raw_manifest_bytes = encode_json(raw_manifest)
    raw_manifest_sha = hashlib.sha256(raw_manifest_bytes).hexdigest()
    (args.work / 'RAW_FILES.json').write_bytes(raw_manifest_bytes)
    archive = args.work / 'payload.tar'
    with tarfile.open(archive, mode='w', format=tarfile.PAX_FORMAT) as tar:
        tar.addfile(info('RAW_FILES.json', len(raw_manifest_bytes)), io.BytesIO(raw_manifest_bytes))
        for item in files:
            source = sources[item['path']]
            with source.open('rb') as stream:
                tar.addfile(info(item['path'], item['bytes']), stream)
                if stream.read(1):
                    raise ValueError('source grew during archive read')
            if hash_file(source) != (item['bytes'], item['sha256']):
                raise ValueError('source changed during archive read: ' + item['path'])
    tar_bytes, tar_sha = hash_file(archive)
    compressed = args.work / 'payload.tar.gz'
    with archive.open('rb') as src, compressed.open('wb') as dst:
        with gzip.GzipFile(fileobj=dst, mode='wb', filename='', mtime=0, compresslevel=9) as encoded:
            shutil.copyfileobj(src, encoded, length=1024 * 1024)
    gzip_bytes, gzip_sha = hash_file(compressed)
    parts = []
    offset = 0
    with compressed.open('rb') as stream:
        while True:
            data = stream.read(CHUNK_RAW_BYTES)
            if not data:
                break
            encoded = base64.b64encode(data) + b'\n'
            assert len(encoded) <= MAX_CHUNK_BYTES
            name = 'chunks/part-' + str(len(parts)).zfill(5) + '.b64'
            (args.output / name).write_bytes(encoded)
            parts.append({'path': name, 'bytes': len(encoded), 'sha256': hashlib.sha256(encoded).hexdigest(), 'decoded_bytes': len(data), 'decoded_sha256': hashlib.sha256(data).hexdigest(), 'gzip_offset': offset})
            offset += len(data)
    supports = []
    for name in ['README.md', 'restore.py', 'build_archive.py']:
        source = pathlib.Path(__file__).resolve().parent / name
        target = args.output / name
        if source.resolve() != target.resolve():
            shutil.copyfile(source, target)
        size, digest = hash_file(target)
        supports.append({'path': name, 'bytes': size, 'sha256': digest})
    manifest = {
        'schema': 'trnm-pq-evidence-archive-v1',
        'status': 'HOLD',
        'whole_chain_pq_qualified': False,
        'metadata': plan.get('metadata', {}),
        'file_count': len(files),
        'raw_total_bytes': raw_manifest['raw_total_bytes'],
        'raw_manifest': {'path': 'RAW_FILES.json', 'bytes': len(raw_manifest_bytes), 'sha256': raw_manifest_sha},
        'tar': {'format': 'PAX', 'bytes': tar_bytes, 'sha256': tar_sha, 'mtime': 0, 'uid': 0, 'gid': 0, 'mode': '0644'},
        'gzip': {'bytes': gzip_bytes, 'sha256': gzip_sha, 'mtime': 0, 'filename': '', 'compresslevel': 9, 'zlib_version': zlib.ZLIB_VERSION},
        'encoding': 'independently base64-encoded consecutive gzip byte segments; one final LF per part',
        'max_encoded_part_bytes': MAX_CHUNK_BYTES,
        'parts': parts,
        'support_files': supports,
    }
    encoded_manifest = encode_json(manifest)
    (args.output / 'manifest.json').write_bytes(encoded_manifest)
    print(json.dumps({'output': str(args.output), 'file_count': len(files), 'raw_total_bytes': raw_manifest['raw_total_bytes'], 'tar_sha256': tar_sha, 'gzip_bytes': gzip_bytes, 'gzip_sha256': gzip_sha, 'parts': len(parts), 'manifest_sha256': hashlib.sha256(encoded_manifest).hexdigest()}, sort_keys=True), flush=True)

if __name__ == '__main__':
    main()
