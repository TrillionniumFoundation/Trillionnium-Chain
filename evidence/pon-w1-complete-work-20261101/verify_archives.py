#!/usr/bin/env python3
"""Verify the retained bytes; no native execution or security qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

def digest_file(path):
    with path.open('rb') as source:
        return digest_stream(source)

def digest_stream(source):
    digest = hashlib.sha256()
    for block in iter(lambda: source.read(1024 * 1024), b''):
        digest.update(block)
    return digest.hexdigest()

def child(root, name):
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError(f'noncanonical path: {name}')
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise ValueError(f'missing or nonregular file: {name}')
    return path

def archive(root, filename, expected_sha, expected_bytes, members):
    path = child(root, filename)
    if path.stat().st_size != expected_bytes or digest_file(path) != expected_sha:
        raise ValueError(f'archive identity mismatch: {filename}')
    expected = {row['path']: row for row in members}
    if len(expected) != len(members):
        raise ValueError(f'duplicate manifest member: {filename}')
    with tarfile.open(path, 'r:xz') as tar:
        actual = tar.getmembers()
        if len(actual) != len(expected) or {m.name for m in actual} != set(expected):
            raise ValueError(f'archive member set mismatch: {filename}')
        for member in actual:
            row = expected[member.name]
            if not member.isfile() or member.size != row['bytes']:
                raise ValueError(f'nonregular or wrong-size member: {member.name}')
            with tar.extractfile(member) as stream:
                if digest_stream(stream) != row['sha256']:
                    raise ValueError(f'member identity mismatch: {member.name}')
    return len(members), sum(row['bytes'] for row in members)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, nargs='?', default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    root = args.directory.resolve()
    index = json.loads(child(root, 'FILE_INDEX.json').read_text())
    indexed_names = {row['path'] for row in index['files']}
    if len(indexed_names) != len(index['files']):
        raise ValueError('duplicate FILE_INDEX entry')
    actual_names = {path.relative_to(root).as_posix() for path in root.rglob('*')
                    if path.is_file() or path.is_symlink()}
    if actual_names != indexed_names | {'FILE_INDEX.json', 'SHA256SUMS'}:
        raise ValueError('published file set does not match FILE_INDEX')
    for row in index['files']:
        path = child(root, row['path'])
        if path.stat().st_size != row['bytes'] or digest_file(path) != row['sha256']:
            raise ValueError(f'file identity mismatch: {row["path"]}')
    sums = child(root, 'SHA256SUMS').read_text().splitlines()
    expected_names = {row['path'] for row in index['files']} | {'FILE_INDEX.json'}
    observed_names = set()
    for line in sums:
        expected_sha, separator, name = line.partition('  ')
        if not separator or name in observed_names or name not in expected_names:
            raise ValueError('invalid SHA256SUMS entry')
        observed_names.add(name)
        if digest_file(child(root, name)) != expected_sha:
            raise ValueError(f'SHA256SUMS mismatch: {name}')
    if observed_names != expected_names:
        raise ValueError('incomplete SHA256SUMS')
    total_archives = total_members = total_bytes = 0
    for run in index['runs']:
        directory = root / f'run-{run}'
        capture = json.loads(child(directory, 'CAPTURE_INDEX.json').read_text())
        for row in capture['artifacts']:
            count, size = archive(directory, row['capture_archive'], row['capture_archive_sha256'],
                                  row['capture_archive_bytes'], row['members'])
            total_archives += 1
            total_members += count
            total_bytes += size
        readbacks = json.loads(child(directory, 'READBACK_INDEX.json').read_text())
        for row in readbacks['archives']:
            count, size = archive(directory, row['archive'], row['sha256'], row['bytes'], row['members'])
            total_archives += 1
            total_members += count
            total_bytes += size
    for name in ('other-ci-8327719', 'codeql-export'):
        extra = root / name
        additional = json.loads(child(extra, 'RETAINED_CAPTURE_INDEX.json').read_text())
        for row in additional['captures']:
            count, size = archive(extra, row['retained_archive'], row['retained_archive_sha256'],
                                  row['retained_archive_bytes'], row['members'])
            total_archives += 1
            total_members += count
            total_bytes += size
    recent = root / 'recent-ci-repair'
    repair = json.loads(child(recent, 'READBACK_INDEX.json').read_text())
    for row in repair['archives']:
        count, size = archive(recent, row['archive'], row['sha256'], row['bytes'], row['members'])
        total_archives += 1
        total_members += count
        total_bytes += size
    validation = json.loads(child(root, 'VALIDATION_INDEX.json').read_text())
    count, size = archive(root, validation['archive'], validation['sha256'],
                          validation['bytes'], validation['members'])
    print(json.dumps({'result': 'PASS_RETAINED_BYTES', 'runs': index['runs'],
                      'archives_reopened': total_archives + 1,
                      'members_verified': total_members + count,
                      'member_bytes_verified': total_bytes + size,
                      'original_zip_containers_included': False,
                      'new_native_execution': False,
                      'work_hardness_or_service_qualification': False}, sort_keys=True))

if __name__ == '__main__':
    main()
