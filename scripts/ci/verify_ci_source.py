#!/usr/bin/env python3
"""Record exact Git objects and tracked worktree bytes, not just cached Git status."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _canonical_merge_tree(root: Path, base: str, candidate: str) -> str:
    """Use reviewed objects with default Git merge semantics, never local drivers.

    Merge configuration and info/attributes are not tracked source. A temporary
    bare repository isolates them, templates, and global/environment injection.
    Tracked attributes still belong to the selected input objects. This uses the
    installed trusted Git; it does not certify Git itself or support custom
    external merge drivers as part of a prospective-source identity.
    """
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_SYSTEM=os.devnull,
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM='1',
                       GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0')

    def command(directory: Path, *args: str) -> list[str]:
        return ['git', '--no-replace-objects', '-C', str(directory), *args]

    ancestor = subprocess.run(command(root, 'merge-base', '--is-ancestor', base, candidate),
                              env=environment, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, check=False)
    if ancestor.returncode == 0:
        return subprocess.check_output(command(root, 'rev-parse', candidate + '^{tree}'),
                                       env=environment, text=True).strip()
    if ancestor.returncode != 1:
        raise ValueError('prospective merge cannot be reproduced from available history')
    objects = subprocess.check_output(
        command(root, 'rev-parse', '--path-format=absolute', '--git-path', 'objects'),
        env=environment, text=True).rstrip('\n')
    if not Path(objects).is_absolute() or '\n' in objects or '\r' in objects:
        raise ValueError('noncanonical merge object directory')
    with tempfile.TemporaryDirectory(prefix='trnm-canonical-merge-') as temporary:
        isolated = Path(temporary) / 'objects-only.git'
        subprocess.run(['git', 'init', '--bare', '--quiet', '--object-format=sha1',
                        '--template=', str(isolated)], env=environment, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (isolated / 'objects/info/alternates').write_text(objects + '\n')
        return subprocess.check_output(
            command(isolated, '-c', 'core.attributesFile=' + os.devnull,
                    'merge-tree', '--write-tree', '--no-messages', base, candidate),
            env=environment, text=True, stderr=subprocess.PIPE).strip()


def _fingerprint(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _tracked_blob(root_fd: int, path: bytes, mode: bytes, size: int) -> str:
    """Hash one raw blob through no-follow directory/file descriptors on CI Unix."""
    parts = path.split(b'/')
    if not parts or any(part in (b'', b'.', b'..') for part in parts):
        raise ValueError('noncanonical tracked path')
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=parent)
            os.close(parent)
            parent = next_parent
        name = parts[-1]
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        value = hashlib.sha1(b'blob ' + str(size).encode('ascii') + b'\0',
                             usedforsecurity=False)
        if mode == b'120000':
            if not stat.S_ISLNK(before.st_mode):
                raise ValueError('tracked symlink type changed')
            target = os.readlink(name, dir_fd=parent)
            if len(target) != size:
                raise ValueError('tracked symlink size changed')
            value.update(target)
        elif mode in (b'100644', b'100755'):
            if not stat.S_ISREG(before.st_mode) or before.st_size != size:
                raise ValueError('tracked regular file type or size changed')
            if bool(before.st_mode & 0o111) != (mode == b'100755'):
                raise ValueError('tracked executable mode changed')
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            with os.fdopen(os.open(name, flags, dir_fd=parent), 'rb') as stream:
                if _fingerprint(os.fstat(stream.fileno())) != _fingerprint(before):
                    raise ValueError('tracked file changed before hashing')
                remaining = size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError('tracked file truncated during hashing')
                    value.update(chunk)
                    remaining -= len(chunk)
                if stream.read(1) or _fingerprint(os.fstat(stream.fileno())) != _fingerprint(before):
                    raise ValueError('tracked file changed during hashing')
        else:
            # Gitlinks require a separate recursive-source contract; never skip them.
            raise ValueError('unsupported tracked entry mode')
        if _fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)) != _fingerprint(before):
            raise ValueError('tracked path changed during hashing')
        return value.hexdigest()
    finally:
        os.close(parent)


def verify(kind: str, expected_head: str, expected_base: str | None = None,
           expected_merge: str | None = None, root: Path = ROOT) -> dict:
    root = root.resolve(strict=True)

    def git_bytes(*args: str) -> bytes:
        # Object replacement must not change the meaning of an event's immutable SHA.
        return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=root)

    def git(*args: str) -> str:
        return git_bytes(*args).decode('utf-8').strip()

    def clean() -> None:
        if git('for-each-ref', '--format=%(refname)', 'refs/replace/'):
            raise ValueError('replacement refs are not source identity')
        if (root / git('rev-parse', '--git-path', 'info/grafts')).exists():
            raise ValueError('grafted history is not source identity')
        entries = git_bytes('ls-files', '-v', '-z').split(b'\0')
        if any(entry and (entry[:1].islower() or entry[:1] == b'S') for entry in entries):
            raise ValueError('index hides tracked worktree entries')
        if git('status', '--porcelain', '--untracked-files=all', '--ignore-submodules=none'):
            raise ValueError('source is not clean')

    for name, value in [('head', expected_head), ('base', expected_base), ('merge', expected_merge)]:
        if value is not None and re.fullmatch(r'[0-9a-f]{40}', value) is None:
            raise ValueError('noncanonical expected ' + name)
    if Path(git('rev-parse', '--show-toplevel')).resolve() != root:
        raise ValueError('Git worktree does not match the checked source root')
    actual = git('rev-parse', 'HEAD')
    if kind == 'head':
        if actual != expected_head or expected_base is not None or expected_merge is not None:
            raise ValueError('head identity mismatch')
    elif kind == 'prospective-merge':
        if expected_base is None or expected_merge is None or actual != expected_merge:
            raise ValueError('merge identity mismatch')
        parents = git('show', '-s', '--format=%P', actual).split()
        if parents != [expected_base, expected_head]:
            raise ValueError('merge parents differ from the event base and candidate')
    else:
        raise ValueError('unknown source kind')
    clean()
    tree = git('rev-parse', actual + '^{tree}')
    if kind == 'prospective-merge':
        # Ordered parents do not bind a commit's tree: commit-tree can attach
        # any source to those same parents. Reproduce the actual combination
        # before allowing a command to borrow the candidate/base identities.
        # A conflict needs a new reviewed candidate, not an unreviewed manual
        # resolution hidden inside a prospective-merge receipt.
        try:
            combined_tree = _canonical_merge_tree(root, expected_base, expected_head)
        except (OSError, subprocess.CalledProcessError) as error:
            raise ValueError('prospective merge cannot be reproduced without conflicts') from error
        if re.fullmatch(r'[0-9a-f]{40}', combined_tree) is None or tree != combined_tree:
            raise ValueError('prospective merge tree differs from the event base and candidate')
    entries = git_bytes('ls-tree', '-r', '-l', '-z', '--full-tree', actual).split(b'\0')
    count = total = 0
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for entry in entries:
            if not entry:
                continue
            metadata, path = entry.split(b'\t', 1)
            mode, kind_name, object_id, size_text = metadata.split()
            if kind_name != b'blob' or not size_text.isdigit():
                raise ValueError('unsupported tracked entry: ' + repr(path))
            size = int(size_text)
            try:
                actual_blob = _tracked_blob(root_fd, path, mode, size)
            except (OSError, ValueError) as error:
                raise ValueError('tracked source verification failed: ' + repr(path)) from error
            if actual_blob != object_id.decode('ascii'):
                raise ValueError('tracked source bytes differ from commit: ' + repr(path))
            count += 1
            total += size
    finally:
        os.close(root_fd)
    clean()
    if git('rev-parse', 'HEAD') != actual:
        raise ValueError('HEAD changed during source verification')
    return {'schema': 'trnm-ci-source-v1', 'kind': kind, 'tested_commit': actual,
            'tested_tree': tree, 'candidate': expected_head,
            'base': expected_base, 'prospective_merge': expected_merge,
            'tracked_worktree_verified': True, 'tracked_entries': count,
            'tracked_bytes': total, 'tests_executed_by_identity_check': False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', required=True, choices=['head', 'prospective-merge'])
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-base')
    parser.add_argument('--expected-merge')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = verify(args.kind, args.expected_head, args.expected_base, args.expected_merge)
    text = json.dumps(result, sort_keys=True, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
