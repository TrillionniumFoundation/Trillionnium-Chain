#!/usr/bin/env python3
"""Read-only CI observations of the original public Host parent, never authority."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path


PARENT = Path('/sys/fs/cgroup/trnmponpublic.slice')
UNIT = 'trnmponpublic.slice'
RUNTIME_UNIT = Path('/run/systemd/system') / UNIT
UNIT_SHA256 = '74eb36a63559bf8603c15ddd3753a1db143684a2cefd84cce5aff10a76bbd622'
LIMITS = {
    'cpu.max': '25000 100000',
    'cpu.max.burst': '0',
    'memory.max': '2147483648',
    'memory.swap.max': '0',
    'pids.max': '256',
}


def write_new(path: Path, value: dict) -> None:
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def capture(phase: str, service: str) -> dict:
    """Failures remain null/error observations; never substitute a valid fixture."""
    errors = {}

    def read(path: Path, limit=2048):
        try:
            with path.open('rb') as stream:
                raw = stream.read(limit + 1)
            if len(raw) > limit:
                raise ValueError('READ_LIMIT')
            return raw.decode('utf-8').strip()
        except (OSError, UnicodeError, ValueError) as error:
            errors[str(path)] = str(error)
            return None

    parent = None
    try:
        metadata = PARENT.lstat()
        parent = {
            'canonical_path': str(PARENT.resolve(strict=True)),
            'device': metadata.st_dev, 'inode': metadata.st_ino,
            'uid': metadata.st_uid, 'gid': metadata.st_gid,
            'mode': stat.S_IMODE(metadata.st_mode),
            'directory': stat.S_ISDIR(metadata.st_mode),
            'symlink': stat.S_ISLNK(metadata.st_mode),
        }
    except OSError as error:
        errors[str(PARENT)] = str(error)
    unit_sha = None
    try:
        unit_sha = hashlib.sha256(RUNTIME_UNIT.read_bytes()).hexdigest()
    except OSError as error:
        errors[str(RUNTIME_UNIT)] = str(error)
    status = read(Path('/proc/thread-self/status'), 16384)
    privileges = {}
    if status is not None:
        for line in status.splitlines():
            key, separator, value = line.partition(':')
            if separator and key in ('NoNewPrivs', 'CapBnd'):
                privileges[key] = value.strip()
    return {
        'schema': 'trnm-ci-original-public-host-observation-v1',
        'phase': phase, 'observed_utc': datetime.now(timezone.utc).isoformat(),
        'service': service, 'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
        'cwd': str(Path.cwd()), 'parent_path': str(PARENT), 'parent': parent,
        'boot_id': read(Path('/proc/sys/kernel/random/boot_id'), 128),
        'thread_cgroup': read(Path('/proc/thread-self/cgroup')),
        'thread_privileges': privileges,
        'cgroup_controllers': read(Path('/sys/fs/cgroup/cgroup.controllers')),
        'limits': {name: read(PARENT / name, 128) for name in LIMITS},
        'counters': {name: read(PARENT / name) for name in (
            'cpu.stat', 'memory.current', 'memory.events', 'pids.current', 'cgroup.events')},
        'installed_unit_sha256': unit_sha, 'read_errors': errors,
        'host_readiness_only': True, 'consensus_or_model_authority': False,
    }


def validate(sample: dict, *, inside: bool, uid: int, gid: int, cwd: str,
             reference: dict | None = None) -> list[str]:
    errors = []
    parent = sample.get('parent') or {}
    if (sample.get('parent_path') != str(PARENT)
            or parent.get('canonical_path') != str(PARENT)
            or parent.get('directory') is not True or parent.get('symlink') is not False
            or parent.get('uid') != 0 or type(parent.get('mode')) is not int
            or parent.get('mode', 0) & 0o022):
        errors.append('FIXED_PARENT_IDENTITY')
    if sample.get('limits') != LIMITS:
        errors.append('ORIGINAL_FINITE_LIMITS')
    if sample.get('installed_unit_sha256') != UNIT_SHA256:
        errors.append('REVIEWED_UNIT_BYTES')
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',
                        sample.get('boot_id') or ''):
        errors.append('BOOT_ID_REQUIRED')
    if sample.get('read_errors'):
        errors.append('KERNEL_OBSERVATION_UNAVAILABLE')
    if (sample.get('uid'), sample.get('gid'), sample.get('cwd')) != (uid, gid, cwd):
        errors.append('ORIGINAL_CALLER_CONTEXT')
    if inside:
        if sample.get('thread_privileges') != {'NoNewPrivs': '1', 'CapBnd': '0000000000000000'}:
            errors.append('UNPRIVILEGED_SERVICE_REQUIRED')
        expected = '0::/trnmponpublic.slice/' + sample['service']
        actual = sample.get('thread_cgroup') or ''
        if actual != expected and not actual.startswith(expected + '/'):
            errors.append('ACTUAL_SERVICE_MEMBERSHIP')
        if '\n' in actual or any(piece in ('.', '..', '')
                                 for piece in actual.removeprefix('0::/').split('/')):
            errors.append('ACTUAL_SERVICE_MEMBERSHIP')
    if reference is not None:
        if sample.get('service') != reference.get('service'):
            errors.append('OWNED_SERVICE_CHANGED')
        for key in ('parent', 'boot_id', 'limits', 'installed_unit_sha256'):
            if sample.get(key) != reference.get(key):
                errors.append('HOST_CONTEXT_CHANGED:' + key)
    return sorted(set(errors))


# Diagnostic snapshots share this existing read-only observation owner. They are
# not a Host capability, a live-budget check, or proof of a child's placement.
_CGROUP_PROC_LIMIT = 16 * 1024
_CGROUP_MOUNT_LIMIT = 256 * 1024
_CGROUP_PATH_LIMIT = 4096
_CGROUP_DEPTH_LIMIT = 64
_CURRENT_LIMITS = (
    'cpu.max', 'cpu.max.burst', 'memory.max', 'memory.swap.max',
    'pids.max', 'cpuset.cpus.effective',
)


def _current_cgroup_text(path, limit, errors, device=None):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError('REGULAR_KERNEL_FILE_REQUIRED')
            if device is not None and metadata.st_dev != device:
                raise ValueError('CGROUP_FILE_DEVICE_CHANGED')
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('BOUNDED_KERNEL_OBSERVATION_REQUIRED')
        return raw.decode('utf-8')
    except (OSError, UnicodeError, ValueError) as error:
        errors[str(path)] = type(error).__name__ + ':' + str(error)
        return None


def _current_cgroup_path(value):
    if (not isinstance(value, str) or not value.startswith('/')
            or len(value.encode('utf-8')) > _CGROUP_PATH_LIMIT
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError('CANONICAL_BOUNDED_CGROUP_PATH_REQUIRED')
    parts = [] if value == '/' else value[1:].split('/')
    if (len(parts) > _CGROUP_DEPTH_LIMIT
            or any(part in ('', '.', '..') for part in parts)):
        raise ValueError('CANONICAL_BOUNDED_CGROUP_PATH_REQUIRED')
    return Path(value)


def _current_mount_path(value):
    escapes = {'040': ' ', '011': '\t', '012': '\n', '134': '\\'}
    def replace(match):
        if match.group(1) not in escapes:
            raise ValueError('MOUNT_ESCAPE_UNSUPPORTED')
        return escapes[match.group(1)]
    decoded = re.sub(r'\\([0-9]{3})', replace, value)
    if re.search(r'\\(?![0-9]{3})', value):
        raise ValueError('MOUNT_ESCAPE_UNSUPPORTED')
    return _current_cgroup_path(decoded)


def _current_cgroup_mapping(membership, mountinfo):
    memberships = [line.split(':', 2) for line in membership.splitlines()]
    if any(len(row) != 3 or re.fullmatch(r'[0-9]+', row[0]) is None
           or (row[0] == '0' and row[1] != '') for row in memberships):
        raise ValueError('CURRENT_CGROUP_MEMBERSHIP_SHAPE')
    unified = [row[2] for row in memberships if row[:2] == ['0', '']]
    if len(unified) != 1:
        raise ValueError('ONE_CURRENT_UNIFIED_CGROUP_REQUIRED')
    member = _current_cgroup_path(unified[0])
    rows = mountinfo.splitlines()
    if not rows or len(rows) > 4096:
        raise ValueError('BOUNDED_MOUNT_TABLE_REQUIRED')
    mounts = []
    for line in rows:
        before, separator, after = line.partition(' - ')
        fields, filesystem = before.split(), after.split()
        if (not separator or len(fields) < 6 or len(filesystem) != 3
                or re.fullmatch(r'[0-9]+:[0-9]+', fields[2]) is None):
            raise ValueError('MOUNTINFO_SHAPE_REQUIRED')
        mounts.append({
            'mount_id': fields[0], 'device': fields[2],
            'root': _current_mount_path(fields[3]),
            'mount_point': _current_mount_path(fields[4]),
            'filesystem': filesystem[0], 'raw': line,
        })
    covering = [row for row in mounts if row['filesystem'] == 'cgroup2'
                and member.is_relative_to(row['root'])]
    if len(covering) != 1:
        raise ValueError('ONE_COVERING_CGROUP2_MOUNT_REQUIRED')
    selected = covering[0]
    leaf = selected['mount_point'] / member.relative_to(selected['root'])
    _current_cgroup_path(str(leaf))
    if any(row is not selected and row['mount_point'].is_relative_to(selected['mount_point'])
           and leaf.is_relative_to(row['mount_point']) for row in mounts):
        raise ValueError('CGROUP_PATH_SHADOW_MOUNT')
    return member, selected, leaf, mounts


def _current_cgroup_directory(path, device):
    metadata = path.lstat()
    if (not stat.S_ISDIR(metadata.st_mode)
            or path.resolve(strict=True) != path or metadata.st_dev != device):
        raise ValueError('CURRENT_CGROUP_DIRECTORY_IDENTITY')
    return {'device': metadata.st_dev, 'inode': metadata.st_ino,
            'uid': metadata.st_uid, 'gid': metadata.st_gid,
            'mode': stat.S_IMODE(metadata.st_mode)}


def current_cgroup_observation():
    """Bounded, non-atomic runner snapshot; unseen ancestors remain unknown."""
    errors = {}
    result = {
        'schema': 'trnm-ci-current-cgroup-observation-v1',
        'status': 'UNRESOLVED', 'pid': os.getpid(),
        'subject': 'calling-runner-process-at-capture',
        'membership_resolved': False, 'visible_limits_complete': False,
        'atomic_snapshot': False, 'effective_quota_established': False,
        'namespace_external_ancestors_observed': False,
        'native_child_membership_verified': False,
        'consensus_or_model_authority': False,
        'scope': 'current visible cgroup2 hierarchy only; namespace-external '
                 'ancestors, concurrent changes and later child placement are not proved',
        'read_errors': errors, 'visible_ancestors': [],
    }
    membership = _current_cgroup_text(Path('/proc/self/cgroup'), _CGROUP_PROC_LIMIT, errors)
    mountinfo = _current_cgroup_text(Path('/proc/self/mountinfo'), _CGROUP_MOUNT_LIMIT, errors)
    result.update(membership_raw=membership, mountinfo_raw=mountinfo)
    try:
        if membership is None or mountinfo is None:
            raise ValueError('CURRENT_PROC_OBSERVATION_UNAVAILABLE')
        member, selected, leaf, mounts = _current_cgroup_mapping(membership, mountinfo)
        major, minor = map(int, selected['device'].split(':'))
        if major > 2**32 - 1 or minor > 2**32 - 1:
            raise ValueError('CGROUP_DEVICE_BOUND')
        device = os.makedev(major, minor)
        result.update(membership_path=str(member), resolved_path=str(leaf),
                      mount={key: str(value) for key, value in selected.items()})
        path, group = leaf, member
        while True:
            identity = _current_cgroup_directory(path, device)
            values = {}
            for name in _CURRENT_LIMITS:
                target = path / name
                if any(row['mount_point'] == target for row in mounts):
                    raise ValueError('CGROUP_LIMIT_SHADOW_MOUNT')
                values[name] = _current_cgroup_text(target, 128, errors, device)
            if _current_cgroup_directory(path, device) != identity:
                raise ValueError('CURRENT_CGROUP_DIRECTORY_CHANGED')
            result['visible_ancestors'].append({
                'path': str(path), 'cgroup_path': str(group),
                'identity': identity, 'limits': values,
            })
            if path == selected['mount_point']:
                break
            path, group = path.parent, group.parent
        after_member = _current_cgroup_text(
            Path('/proc/self/cgroup'), _CGROUP_PROC_LIMIT, errors)
        after_mount = _current_cgroup_text(
            Path('/proc/self/mountinfo'), _CGROUP_MOUNT_LIMIT, errors)
        result['membership_after_raw'] = after_member
        result['mountinfo_after_sha256'] = (
            hashlib.sha256(after_mount.encode()).hexdigest()
            if after_mount is not None else None)
        if after_member != membership or after_mount != mountinfo:
            result['mountinfo_after_raw'] = after_mount
            raise ValueError('CURRENT_CGROUP_CONTEXT_CHANGED')
        result['membership_resolved'] = True
        result['visible_limits_complete'] = not errors
        result['status'] = 'VISIBLE_HIERARCHY_OBSERVED' if not errors else 'PARTIAL_OBSERVATION'
    except (OSError, OverflowError, UnicodeError, ValueError) as error:
        result['mapping_error'] = type(error).__name__ + ':' + str(error)
    return result
