"""Retain actual runtime files and inode metadata without following special objects.

Fixture hard links and Cargo hard links are valid observations. Every pathname's
regular bytes are copied into an independent regular archive member; original
device/inode/link-count metadata remains explicit. This does not weaken source
admission or the stricter executable-bundle object_inventory contract.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile


SCHEMA = 'trnm.hia.runtime-observation-archive.v1'
FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


def fingerprint(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_nlink, value.st_uid, value.st_gid, value.st_mtime_ns, value.st_ctime_ns)


def identity(path):
    digest = hashlib.sha256()
    count = 0
    with Path(path).open('rb') as stream:
        while block := stream.read(1 << 20):
            count += len(block)
            digest.update(block)
    return {'bytes': count, 'sha256': digest.hexdigest()}


class HashedReader:
    def __init__(self, fd):
        self.fd = fd
        self.count = 0
        self.digest = hashlib.sha256()

    def read(self, size):
        # TarFile requires a complete requested block, including across EINTR.
        result = bytearray()
        while len(result) < size:
            block = os.read(self.fd, size - len(result))
            if not block:
                break
            result.extend(block)
        raw = bytes(result)
        self.count += len(raw)
        self.digest.update(raw)
        return raw


def verify_archive(path):
    with tarfile.open(path, 'r:gz') as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)) or not all(member.isfile() for member in members):
            raise ValueError('Archive has duplicate or nonregular members')
        if names.count('manifest.json') != 1:
            raise ValueError('Missing unique archive manifest')
        manifest_bytes = archive.extractfile('manifest.json').read()
        manifest = json.loads(manifest_bytes)
        if manifest.get('schema') != SCHEMA:
            raise ValueError('Unknown observation archive schema')
        regular = [row for row in manifest['entries'] if row['kind'] == 'regular']
        if names != [row['member'] for row in regular] + ['manifest.json']:
            raise ValueError('Archive member roster differs from captured paths')
        paths = [row['path'] for row in manifest['entries']]
        if len(paths) != len(set(paths)):
            raise ValueError('Repeated original observation path')
        total = 0
        for row in regular:
            member = archive.getmember(row['member'])
            if member.size != row['bytes'] or member.mode != 0o600:
                raise ValueError('Archive regular extent or mode differs')
            digest = hashlib.sha256()
            count = 0
            with archive.extractfile(member) as stream:
                while block := stream.read(1 << 20):
                    count += len(block)
                    digest.update(block)
            if count != row['bytes'] or digest.hexdigest() != row['sha256']:
                raise ValueError('Archived regular bytes differ: ' + row['path'])
            total += count
    return {'status': 'ARCHIVE_AND_ALL_MEMBERS_READBACK_PASS',
            'archive': identity(path), 'regular_content_members': len(regular),
            'archive_members_including_manifest': len(regular) + 1,
            'regular_logical_bytes': total, 'metadata_entries': len(manifest['entries']),
            'original_hardlinked_paths': sum(row['kind'] == 'regular' and row['links'] > 1 for row in manifest['entries']),
            'special_objects_are_metadata_only': True,
            'runtime_qualification_inferred_from_packaging': False,
            'manifest': {'bytes': len(manifest_bytes), 'sha256': hashlib.sha256(manifest_bytes).hexdigest()}}


def archive_observations(roots, output, metadata=None):
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.is_symlink() or output.resolve(strict=True) != output:
        raise ValueError('Noncanonical archive output directory')
    declared = {}
    for label, value in roots.items():
        if not re.fullmatch('[a-z][a-z0-9_-]*', label):
            raise ValueError('Noncanonical observation label')
        root = Path(value).absolute()
        if root.is_symlink() or root.resolve(strict=True) != root or not root.is_dir():
            raise ValueError('Noncanonical observation root: ' + label)
        if root == output or root in output.parents:
            raise ValueError('Archive output must be outside every captured root')
        declared[label] = root
    if not declared:
        raise ValueError('No actual observation root')
    rows, expected, root_fds, aliases = [], [], {}, {}
    path = output / 'complete-observations.tar.gz'
    regular_count = 0

    def capture_row(label, parts, value, kind):
        relative = '/'.join((label, *parts))
        row = {'path': relative, 'kind': kind, 'mode': value.st_mode,
               'bytes': value.st_size, 'device': value.st_dev, 'inode': value.st_ino,
               'links': value.st_nlink, 'uid': value.st_uid, 'gid': value.st_gid,
               'mtime_ns': value.st_mtime_ns, 'ctime_ns': value.st_ctime_ns}
        expected.append((label, parts, fingerprint(value)))
        return row

    def walk(directory, label, parts, archive):
        nonlocal regular_count
        before = os.fstat(directory)
        for name in sorted(os.listdir(directory), key=os.fsencode):
            value = os.stat(name, dir_fd=directory, follow_symlinks=False)
            child_parts = (*parts, name)
            if stat.S_ISDIR(value.st_mode):
                row = capture_row(label, child_parts, value, 'directory')
                fd = os.open(name, FLAGS | os.O_DIRECTORY, dir_fd=directory)
                try:
                    if fingerprint(os.fstat(fd)) != fingerprint(value):
                        raise ValueError('Directory replaced while opening')
                    walk(fd, label, child_parts, archive)
                finally:
                    os.close(fd)
            elif stat.S_ISREG(value.st_mode):
                row = capture_row(label, child_parts, value, 'regular')
                fd = os.open(name, FLAGS, dir_fd=directory)
                try:
                    if fingerprint(os.fstat(fd)) != fingerprint(value):
                        raise ValueError('Regular file replaced while opening')
                    reader = HashedReader(fd)
                    member = f'files/{regular_count:08d}.bin'
                    info = tarfile.TarInfo(member)
                    info.size, info.mode = value.st_size, 0o600
                    archive.addfile(info, reader)
                    if (reader.count != value.st_size or os.read(fd, 1)
                            or fingerprint(os.fstat(fd)) != fingerprint(value)):
                        raise ValueError('Regular file changed while copying')
                    row.update(member=member, sha256=reader.digest.hexdigest())
                    alias = (value.st_dev, value.st_ino)
                    signature = (fingerprint(value), row['sha256'])
                    if alias in aliases and aliases[alias] != signature:
                        raise ValueError('Hard-link aliases changed between observations')
                    aliases[alias] = signature
                    regular_count += 1
                finally:
                    os.close(fd)
            elif stat.S_ISLNK(value.st_mode):
                row = capture_row(label, child_parts, value, 'symlink-metadata')
                row['target'] = os.readlink(name, dir_fd=directory)
            else:
                row = capture_row(label, child_parts, value, 'special-metadata')
                row['rdev'] = value.st_rdev
            if fingerprint(os.stat(name, dir_fd=directory, follow_symlinks=False)) != fingerprint(value):
                raise ValueError('Named observation changed during capture')
            rows.append(row)
        if fingerprint(os.fstat(directory)) != fingerprint(before):
            raise ValueError('Directory changed during capture')

    def recheck():
        for label, parts, before in expected:
            fd = os.dup(root_fds[label])
            try:
                for name in parts[:-1]:
                    next_fd = os.open(name, FLAGS | os.O_DIRECTORY, dir_fd=fd)
                    os.close(fd)
                    fd = next_fd
                now = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False) if parts else os.fstat(fd)
                if fingerprint(now) != before:
                    raise ValueError('Observation changed before the archive was complete')
            finally:
                os.close(fd)
        for label, root in declared.items():
            if fingerprint(root.lstat()) != fingerprint(os.fstat(root_fds[label])):
                raise ValueError('Observation root pathname was replaced')

    try:
        with tarfile.open(path, mode='x:gz', compresslevel=1) as archive:
            for label, root in declared.items():
                fd = os.open(root, FLAGS | os.O_DIRECTORY)
                root_fds[label] = fd
                value = os.fstat(fd)
                if fingerprint(root.lstat()) != fingerprint(value):
                    raise ValueError('Observation root replaced while opening')
                rows.append(capture_row(label, (), value, 'directory'))
                walk(fd, label, (), archive)
            recheck()
            manifest = {'schema': SCHEMA, 'metadata': metadata or {}, 'entries': rows,
                        'runtime_qualification_inferred_from_packaging': False,
                        'special_objects_are_metadata_only': True}
            raw = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
            info = tarfile.TarInfo('manifest.json')
            info.size, info.mode = len(raw), 0o600
            archive.addfile(info, io.BytesIO(raw))
        recheck()
        report = verify_archive(path)
        (output / 'archive.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        return report
    except BaseException as error:
        failure = {'status': 'ARCHIVE_FAILED', 'error_type': type(error).__name__,
                   'error': str(error), 'runtime_qualification_inferred_from_packaging': False}
        if path.is_file() and not path.is_symlink():
            failure['partial_archive'] = identity(path)
        (output / 'archive-failure.json').write_text(json.dumps(failure, sort_keys=True, indent=2) + '\n')
        raise
    finally:
        for fd in root_fds.values():
            os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', action='append', default=[])
    parser.add_argument('--optional-root', action='append', default=[])
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify', type=Path)
    parser.add_argument('--metadata', type=Path)
    args = parser.parse_args()
    if args.verify:
        if args.output or args.root or args.optional_root or args.metadata:
            parser.error('--verify cannot be combined with capture arguments')
        print(json.dumps(verify_archive(args.verify), sort_keys=True))
        return
    if args.output is None:
        parser.error('--output is required for capture')
    roots, absent = {}, []
    for optional, values in ((False, args.root), (True, args.optional_root)):
        for value in values:
            label, path = value.split('=', 1)
            if label in roots or label in absent:
                raise ValueError('Duplicate observation label')
            if optional and not os.path.lexists(path):
                absent.append(label)
            else:
                roots[label] = path
    metadata = json.loads(args.metadata.read_bytes()) if args.metadata else {}
    metadata['absent_optional_roots'] = absent
    print(json.dumps(archive_observations(roots, args.output, metadata), sort_keys=True))


if __name__ == '__main__':
    main()
