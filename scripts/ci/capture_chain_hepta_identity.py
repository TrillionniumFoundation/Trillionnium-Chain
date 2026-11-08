#!/usr/bin/env python3
"""Read two explicitly pinned worktrees; source identity never proves build/load.

Raw regular-file bytes and Git executable modes are checked through no-follow
descriptors. This is an observation interval, not an atomic filesystem snapshot.
No subprocess builds, executes repository code, fetches, or touches a service.
An explicit --manifest-dir writes new gzip evidence files outside both repos;
without it, the complete tracked manifest stays embedded in the JSON output.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

MAX_ENTRIES = 50000
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_GIT_OUTPUT = 16 * 1024 * 1024
LOCK_NAMES = frozenset({
    'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'go.sum',
    'packages.lock.json', 'yarn.lock', 'bun.lockb',
})
BUILD_FIELDS = ('build_sha256', 'load_sha256', 'interpreter_sha256',
                'libraries_sha256', 'environment_sha256', 'configuration_sha256')


class IdentityError(ValueError):
    pass


def canonical_root(value: Path) -> Path:
    root = Path(value)
    if (not root.is_absolute() or '..' in root.parts
            or root.resolve(strict=True) != root or not root.is_dir()):
        raise IdentityError('repository root must be an absolute directory without symlink aliases')
    return root


def relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or '..' in path.parts
            or str(path) != value or '\x00' in value or '.git' in path.parts):
        raise IdentityError('noncanonical or escaping repository-relative path')
    return value


def git(root: Path, *arguments: str) -> bytes:
    # Remove injected repository/index/object/config/namespace selection. Git's
    # protocol denial also prevents fetching on versions without the env switch.
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1',
               GIT_ALLOW_PROTOCOL='',
               GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_SYSTEM=os.devnull,
               GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM='1',
               GIT_GRAFT_FILE=os.devnull, LC_ALL='C')
    command = ['git', '--no-replace-objects', '-c', 'protocol.allow=never',
               '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false',
               '-c', 'core.hooksPath=' + os.devnull, '-C', str(root), *arguments]
    try:
        run = subprocess.run(command, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise IdentityError('Git observation did not complete') from error
    if run.returncode or len(run.stdout) > MAX_GIT_OUTPUT:
        raise IdentityError('Git observation failed or exceeded its output bound: ' + arguments[0])
    return run.stdout


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def raw_file(root_fd: int, path: str, expected_size: int, expected_mode: str) -> dict:
    """Keep every parent held and recheck its pathname binding after the read."""
    parts = relative_path(path).split('/')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    directories = [os.dup(root_fd)]
    links = []
    try:
        for part in parts[:-1]:
            parent = directories[-1]
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
            directories.append(child)
            links.append((parent, part, child, fingerprint(os.fstat(child))))
        parent, name = directories[-1], parts[-1]
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if expected_mode == '120000' and not stat.S_ISLNK(before.st_mode):
            raise IdentityError('expected tracked symlink was replaced by another type')
        if expected_mode != '120000' and not stat.S_ISREG(before.st_mode):
            raise IdentityError('tracked path is not a regular file; links are not followed')
        if before.st_size != expected_size or expected_size > MAX_FILE_BYTES:
            raise IdentityError('tracked size differs or exceeds the file bound')
        blob = hashlib.sha1(b'blob ' + str(expected_size).encode() + b'\0',
                            usedforsecurity=False)
        sha256 = hashlib.sha256()
        if expected_mode == '120000':
            target = os.readlink(os.fsencode(name), dir_fd=parent)
            if len(target) != expected_size:
                raise IdentityError('tracked symlink target size changed')
            blob.update(target)
            sha256.update(target)
            actual_mode = '120000'
        else:
            with os.fdopen(os.open(name, flags | os.O_NONBLOCK, dir_fd=parent), 'rb') as stream:
                if fingerprint(os.fstat(stream.fileno())) != fingerprint(before):
                    raise IdentityError('tracked file changed before reading')
                remaining = expected_size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise IdentityError('tracked file truncated during reading')
                    remaining -= len(chunk)
                    blob.update(chunk)
                    sha256.update(chunk)
                if stream.read(1) or fingerprint(os.fstat(stream.fileno())) != fingerprint(before):
                    raise IdentityError('tracked file changed during reading')
            actual_mode = '100755' if before.st_mode & 0o111 else '100644'
        if fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)) != fingerprint(before):
            raise IdentityError('tracked path changed during reading')
        for ancestor, part, child, observed in reversed(links):
            if (fingerprint(os.fstat(child)) != observed
                    or fingerprint(os.stat(part, dir_fd=ancestor, follow_symlinks=False)) != observed):
                raise IdentityError('tracked parent changed during reading')
        return {'blob': blob.hexdigest(), 'sha256': sha256.hexdigest(),
                'bytes': expected_size, 'mode': actual_mode,
                'observed_posix_mode': oct(stat.S_IMODE(before.st_mode))}
    finally:
        for descriptor in reversed(directories):
            os.close(descriptor)


def tree_entries(raw: bytes) -> dict:
    entries = {}
    for entry in raw.split(b'\0'):
        if not entry:
            continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, oid, size = metadata.decode('ascii').split()
        path = relative_path(name.decode('utf-8'))
        if path in entries or not re.fullmatch('[0-9a-f]{40}', oid):
            raise IdentityError('duplicate path or invalid Git object ID')
        entries[path] = {'mode': mode, 'kind': kind, 'blob': oid,
                         'bytes': int(size) if size.isdigit() else None}
        if len(entries) > MAX_ENTRIES:
            raise IdentityError('tracked entry bound exceeded')
    if not entries:
        raise IdentityError('empty tracked source cannot qualify this pair')
    return entries


def is_lock(path: str) -> bool:
    name = PurePosixPath(path).name
    return name.endswith(('.lock', '.lockb')) or name in LOCK_NAMES


def retain_manifest(rows: list, root: Path, destination: Path | None) -> tuple[str, dict]:
    raw = json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()
    digest = hashlib.sha256(raw).hexdigest()
    if destination is None:
        return digest, {'storage': 'embedded', 'sha256': digest, 'bytes': len(raw)}
    destination = Path(destination)
    directory = canonical_root(destination.parent)
    relative_path(destination.name)
    if directory.is_relative_to(root):
        raise IdentityError('manifest output must be outside the observed repository')
    compressed = gzip.compress(raw, compresslevel=6, mtime=0)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=descriptor)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(compressed)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    return digest, {'storage': 'gzip', 'path': destination.name,
                    'sha256': hashlib.sha256(compressed).hexdigest(), 'bytes': len(compressed),
                    'uncompressed_sha256': digest, 'uncompressed_bytes': len(raw)}


def capture_repository(root: Path, expected: str, explicit_locks=(),
                       manifest_path: Path | None = None) -> tuple[dict, dict]:
    root = canonical_root(root)
    if type(expected) is not str or re.fullmatch('[0-9a-f]{40}', expected) is None:
        raise IdentityError('expected commit must be a full lowercase 40-hex SHA')
    explicit_locks = {relative_path(path) for path in explicit_locks}
    if git(root, 'rev-parse', '--show-object-format').strip() != b'sha1':
        raise IdentityError('unsupported Git object format')
    top = git(root, 'rev-parse', '--show-toplevel').decode().rstrip('\n')
    if Path(top) != root:
        raise IdentityError('Git repository root differs from the requested worktree')
    head = git(root, 'rev-parse', '--verify', 'HEAD^{commit}').decode().strip()
    tree = git(root, 'rev-parse', '--verify', head + '^{tree}').decode().strip()
    pinned = git(root, 'rev-parse', '--verify', expected + '^{commit}').decode().strip()
    if pinned != expected:
        raise IdentityError('expected object is not exactly the pinned commit')
    source = {'sha': head, 'tree': tree, 'locks': {}}
    errors = []
    if head != expected:
        errors.append({'reason': 'HEAD_MISMATCH', 'expected': expected, 'actual': head})
    replacements = git(root, 'for-each-ref', '--format=%(refname)', 'refs/replace/').decode().splitlines()
    if replacements:
        errors.append({'reason': 'REPLACEMENT_REFS_PRESENT', 'refs': replacements})
    entries = tree_entries(git(root, 'ls-tree', '-r', '-l', '-z', '--full-tree', expected))
    lock_paths = explicit_locks | {path for path in entries if is_lock(path)}
    before_index = git(root, 'ls-files', '--stage', '-z')
    before_untracked = git(root, 'ls-files', '--others', '-z')
    wanted_index = b''.join((item['mode'] + ' ' + item['blob'] + ' 0\t' + path).encode() + b'\0'
                            for path, item in entries.items())
    index_matches = before_index == wanted_index
    if not index_matches:
        errors.append({'reason': 'INDEX_DIFFERS_FROM_PINNED_TREE'})
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    root_identity = fingerprint(os.fstat(root_fd))
    rows, byte_count = [], 0
    try:
        for path, item in entries.items():
            row = {'path': path, 'expected': item}
            try:
                if item['kind'] != 'blob' or item['mode'] not in ('100644', '100755', '120000') or item['bytes'] is None:
                    row['observation_status'] = 'UNKNOWN'
                    raise IdentityError('unsupported tracked mode/type; gitlinks need a separate recursive-source contract')
                byte_count += item['bytes']
                if byte_count > MAX_TOTAL_BYTES:
                    raise IdentityError('total tracked byte bound exceeded')
                observed = raw_file(root_fd, path, item['bytes'], item['mode'])
                row['observed'] = observed
                if observed['blob'] != item['blob'] or observed['mode'] != item['mode']:
                    raise IdentityError('raw tracked bytes or executable mode differ from the pinned blob')
                row['matches'] = True
            except (OSError, ValueError) as error:
                row.update(matches=False, error=str(error))
                errors.append({'reason': 'TRACKED_ENTRY_MISMATCH', 'path': path, 'detail': str(error)})
            rows.append(row)
        if fingerprint(os.fstat(root_fd)) != root_identity:
            errors.append({'reason': 'ROOT_CHANGED_DURING_CAPTURE'})
    finally:
        os.close(root_fd)
    row_map = {row['path']: row for row in rows}
    for path in sorted(lock_paths):
        row = row_map.get(path)
        regular = row is not None and row.get('observed', {}).get('mode') in ('100644', '100755')
        source['locks'][path] = row['observed']['sha256'] if regular else None
        if not row or not row['matches'] or not regular:
            errors.append({'reason': 'LOCK_NOT_VERIFIED', 'path': path})
    after_untracked = git(root, 'ls-files', '--others', '-z')
    untracked = sorted(set(part.decode('utf-8') for part in before_untracked.split(b'\0') + after_untracked.split(b'\0') if part))
    if untracked:
        errors.append({'reason': 'UNTRACKED_PATHS_PRESENT', 'count': len(untracked)})
    if (before_index != git(root, 'ls-files', '--stage', '-z')
            or before_untracked != after_untracked
            or git(root, 'rev-parse', '--verify', 'HEAD^{commit}').decode().strip() != head
            or fingerprint(os.stat(canonical_root(root), follow_symlinks=False)) != root_identity):
        errors.append({'reason': 'SOURCE_METADATA_CHANGED_DURING_CAPTURE'})
    raw_matches = all(row['matches'] for row in rows)
    source_status = ('UNKNOWN' if any(row.get('observation_status') == 'UNKNOWN' for row in rows)
                     else 'VERIFIED' if not errors else 'MISMATCH')
    manifest_digest, manifest = retain_manifest(rows, root, manifest_path)
    detail = {'root': str(root), 'expected_sha': expected,
              'source_status': source_status,
              'tracked_worktree_verified': not errors, 'raw_tracked_entries_match': raw_matches,
              'dirty': bool(errors), 'index_matches': index_matches,
              'tracked_entries': len(rows), 'tracked_bytes': byte_count,
              'tracked_manifest_sha256': manifest_digest, 'tracked_manifest': manifest,
              'untracked_paths_including_ignored': untracked, 'errors': errors,
              'lock_discovery': 'All tracked *.lock/*.lockb and enumerated ecosystem lock basenames, plus explicit paths',
              'symlink_scope': 'Git 120000 target bytes/mode only, never target contents or dependency/load closure; lock contents require a regular file',
              'lock_paths': sorted(lock_paths),
              'mismatched_entries': [row for row in rows if not row['matches']]}
    if manifest_path is None:
        detail['entries'] = rows
    return source, detail


def capture_pair(chain_root: Path, chain_sha: str, hepta_root: Path, hepta_sha: str,
                 chain_locks=(), hepta_locks=(), manifest_directory: Path | None = None) -> dict:
    sources, observations, blockers = {}, {}, []
    if manifest_directory is not None:
        manifest_directory = canonical_root(manifest_directory)
        if any(manifest_directory.is_relative_to(Path(root).resolve()) for root in (chain_root, hepta_root)):
            raise IdentityError('manifest directory must be outside both repositories')
    for role, root, expected, locks in (
        ('chain', chain_root, chain_sha, chain_locks),
        ('hepta', hepta_root, hepta_sha, hepta_locks),
    ):
        try:
            manifest_path = (manifest_directory / (role + '-tracked-manifest-v1.json.gz')
                             if manifest_directory is not None else None)
            sources[role], observations[role] = capture_repository(root, expected, locks, manifest_path)
        except (OSError, ValueError) as error:
            sources[role] = {'sha': None, 'tree': None, 'locks': {}}
            observations[role] = {'source_status': 'UNKNOWN', 'tracked_worktree_verified': False,
                                  'dirty': None, 'errors': [{'reason': 'CAPTURE_FAILED', 'detail': str(error)}]}
        if observations[role]['tracked_worktree_verified'] is not True:
            blockers.append(role + ':SOURCE_NOT_VERIFIED')
        blockers.extend((role + ':BUILD_NOT_OBSERVED', role + ':LOAD_NOT_OBSERVED'))
    build_load = {role: {key: None for key in BUILD_FIELDS} for role in ('chain', 'hepta')}
    build_load['hepta']['model_closure_sha256'] = None
    return {'schema': 'trnm-chain-hepta-identity-observation-v1',
            'observed_utc': datetime.now(timezone.utc).isoformat(),
            'status': 'HOLD_NO_GO', 'source_pair': sources,
            'source_observations': observations, 'build_load': build_load,
            'build_load_status': 'NOT_OBSERVED', 'toolchain_status': 'NOT_OBSERVED',
            'blockers': blockers, 'production_qualified': False,
            'actual_model_execution_proved': False, 'tests_executed_by_identity_check': False,
            'limits': {'maximum_entries_per_repository': MAX_ENTRIES,
                       'maximum_file_bytes': MAX_FILE_BYTES, 'maximum_total_bytes': MAX_TOTAL_BYTES},
            'scope': 'Source and tracked lock observations only. No executable was built or loaded; disk paths are never treated as live processes. No atomic snapshot or full dependency-resolution attestation.'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest-dir', type=Path,
                        help='existing absolute directory outside both repos; create new gzip manifests, never overwrite')
    for role in ('chain', 'hepta'):
        parser.add_argument('--' + role + '-root', type=Path, required=True)
        parser.add_argument('--' + role + '-sha', required=True)
        parser.add_argument('--' + role + '-lock', action='append', default=[])
    args = parser.parse_args()
    try:
        result = capture_pair(args.chain_root, args.chain_sha, args.hepta_root, args.hepta_sha,
                              args.chain_lock, args.hepta_lock, args.manifest_dir)
    except (OSError, ValueError) as error:
        print(json.dumps({'schema': 'trnm-chain-hepta-identity-observation-v1',
                          'status': 'HOLD_NO_GO', 'input_refused': str(error),
                          'production_qualified': False}))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    # Zero means only both source observations completed cleanly. It is never
    # build, load, integration, application, or production acceptance.
    return 0 if all(value['tracked_worktree_verified'] for value in result['source_observations'].values()) else 2


if __name__ == '__main__':
    raise SystemExit(main())
