#!/usr/bin/env python3
"""Offline, fail-closed recovery of the unchanged source-development cache."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import uuid

HERE = Path(__file__).absolute().parent
MANIFEST_SHA256 = 'e18c233981cd7a9747902d4baf7ae7b0c86c12866b11f35722bd6d3fa39522c3'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
BASE = '6cdbf9551aae1754e489773bac29bc0598e20a9b'


class RecoveryError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise RecoveryError(message)


def oid(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value), 'invalid object ID')
    return value


def safe_relative(value):
    p = PurePosixPath(value)
    require(value and not p.is_absolute() and all(x not in ('', '.', '..') for x in value.split('/'))
            and '\\' not in value and '\x00' not in value, 'unsafe relative path')
    return value


def open_directory(path, create=False):
    """Walk from / using dirfds: never follow a symlink, including ancestors."""
    require('..' not in Path(path).parts, 'unsafe directory traversal')
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_at(fd, name):
    safe_relative(name)
    require('/' not in name, 'nested file name')
    f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        require(stat.S_ISREG(os.fstat(f).st_mode), 'not a regular file: ' + name)
        with os.fdopen(f, 'rb', closefd=False) as stream:
            return stream.read()
    finally:
        os.close(f)


def read_file(path):
    fd = open_directory(Path(path).parent)
    try:
        return read_at(fd, Path(path).name)
    finally:
        os.close(fd)


def atomic_file(fd, name, data):
    """Link a complete fsynced temporary inode, never replace an existing name."""
    safe_relative(name)
    require('/' not in name, 'nested file name')
    try:
        require(read_at(fd, name) == data, 'conflicting existing cache file: ' + name)
        return False
    except FileNotFoundError:
        pass
    temporary = '.recover-' + uuid.uuid4().hex
    f = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(f, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        except FileExistsError:
            require(read_at(fd, name) == data, 'concurrent conflicting cache file: ' + name)
        os.fsync(fd)
    finally:
        os.unlink(temporary, dir_fd=fd)
    return True


class Git:
    def __init__(self, repo):
        fd = open_directory(repo)
        os.close(fd)
        self.repo = str(Path(repo).absolute())
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        self.env.update(GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1',
                        GIT_CONFIG_GLOBAL=os.devnull, GIT_ALLOW_PROTOCOL='')

    def run(self, *args, optional=False):
        p = subprocess.run(['git', '-c', 'protocol.allow=never', '-c', 'core.fsmonitor=false',
                            '-c', 'core.hooksPath=/dev/null', *args], cwd=self.repo, env=self.env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if p.returncode:
            if optional:
                return None
            raise RecoveryError('offline Git command failed: ' + ' '.join(args) + ': ' + p.stderr.decode(errors='replace'))
        return p.stdout

    def identity(self):
        require(self.run('config', '--get-all', 'remote.origin.url').decode().strip() == ORIGIN,
                'wrong repository origin identity')
        require(self.run('rev-parse', '--show-object-format').strip() == b'sha1', 'unsupported Git object format')

    def object(self, kind, object_id):
        oid(object_id)
        data = self.run('cat-file', kind, object_id, optional=True)
        if data is None:
            return None
        require(hashlib.sha1(kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data).hexdigest() == object_id,
                'corrupt Git object: ' + object_id)
        return data


def load_inputs(package):
    raw = read_file(HERE / 'required-objects.json')
    require(hashlib.sha256(raw).hexdigest() == MANIFEST_SHA256, 'required manifest hash mismatch')
    manifest = json.loads(raw)
    require(manifest['baseline'] == BASE, 'wrong baseline')
    for name, expected in manifest['package_sha256'].items():
        require(hashlib.sha256(read_file(package / name)).hexdigest() == expected, 'frozen package hash mismatch: ' + name)
    decoded = {}
    hashes = json.loads(read_file(package / 'decoded-hashes.json'))
    for name in ('owner-discovery.json', 'history-filter.json'):
        decoded[name] = gzip.decompress(read_file(package / (name + '.gz')))
        require(hashlib.sha256(decoded[name]).hexdigest() == hashes[name], 'decoded hash mismatch: ' + name)
    owners = json.loads(decoded['owner-discovery.json'])
    history = json.loads(decoded['history-filter.json'])
    candidates = {oid(v['blob']) for v in owners['variants']}
    require(len(candidates) == len(owners['variants']) == 161, 'candidate cardinality mismatch')
    require(candidates == {oid(v['oid']) for v in manifest['candidates']}, 'candidate manifest mismatch')
    require(candidates == set(history['historical_blobs']) | set(history['novel_blobs']), 'history partition mismatch')
    for entry in manifest['baseline_entries']:
        oid(entry['oid'])
        safe_relative(entry['path'])
        require(entry['type'] in ('tree', 'blob') and entry['mode'] in ('040000', '100644', '100755'), 'unsafe tree entry')
    return manifest, decoded


def requirements(manifest):
    objects = {manifest['baseline']: 'commit', manifest['baseline_root_tree']: 'tree', manifest['inventory_blob']: 'blob'}
    for entry in manifest['baseline_entries']:
        objects[entry['oid']] = entry['type']
    for entry in manifest['candidates']:
        objects[entry['oid']] = 'blob'
    return objects


def recover(repo, cache, package, check_only=False):
    manifest, decoded = load_inputs(package)
    git = Git(repo)
    git.identity()
    objects = requirements(manifest)
    available = {}
    missing = []
    # Read only pinned commit/tree/source/inventory objects, never historical tasks.
    for object_id, kind in sorted(objects.items()):
        data = git.object(kind, object_id)
        if data is None:
            missing.append({'oid': object_id, 'type': kind})
        else:
            available[object_id] = data
    report = {'schema': 'chain-source-cache-recovery-report-v1', 'result': 'MISSING' if missing else 'PASS',
              'candidate_blobs': 161, 'baseline_rust_paths': 332, 'required_objects': len(objects),
              'required_blobs': sum(k == 'blob' for k in objects.values()), 'missing_objects': missing,
              'network_used': False, 'training_run': False, 'cache_written': False}
    if missing or check_only:
        return report
    inventory = json.loads(available[manifest['inventory_blob']])
    paths = [p['path'] for p in inventory['packages'] if p['module'] in ('M00', 'M04', 'M10')]
    require(paths == manifest['package_paths'], 'baseline inventory scope mismatch')
    # Validate the exact historical source-tree binding before materialization.
    listing = git.run('ls-tree', '-r', '-t', BASE, '--', *paths, 'config/portability-inventory-v1.json').decode()
    actual = []
    for line in listing.splitlines():
        meta, path = line.split('\t')
        mode, kind, object_id = meta.split()
        if kind == 'tree' or path.endswith('.rs') or path == 'config/portability-inventory-v1.json':
            actual.append(dict(path=path, mode=mode, type=kind, oid=object_id))
    require(actual == manifest['baseline_entries'], 'baseline tree mismatch')
    fd = open_directory(cache, create=True)
    try:
        try:
            os.mkdir('blobs', mode=0o700, dir_fd=fd)
        except FileExistsError:
            pass
        blobfd = os.open('blobs', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            # Prevalidate every existing destination before adding anything.
            destinations = [(fd, name, data) for name, data in decoded.items()]
            destinations += [(blobfd, key, available[key]) for key, kind in sorted(objects.items()) if kind == 'blob']
            for directory, name, data in destinations:
                try:
                    require(read_at(directory, name) == data, 'conflicting existing cache file: ' + name)
                except FileNotFoundError:
                    pass
            written = sum(atomic_file(directory, name, data) for directory, name, data in destinations)
        finally:
            os.close(blobfd)
    finally:
        os.close(fd)
    report.update(cache_written=True, new_files=written)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--package', type=Path, default=HERE.parent / 'source-development-freeze-20261103')
    parser.add_argument('--check-only', action='store_true', help='verify local required objects and print exact missing IDs without writing cache')
    args = parser.parse_args()
    try:
        report = recover(args.repo, args.cache, args.package, args.check_only)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report['result'] == 'PASS' else 2
    except (RecoveryError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({'result': 'FAIL', 'error': str(exc)}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
