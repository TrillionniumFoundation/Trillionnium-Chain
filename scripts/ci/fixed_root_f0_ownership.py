#!/usr/bin/env python3
"""Exact F0 service identities; no implicit service or cgroup authority.

Callers must retain the returned observations. A missing receipt is unknown,
even if a process group was reaped or a stop command returned zero.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

CGROUP_ROOT = Path('/sys/fs/cgroup')
MANAGER_PROPERTIES = (
    'Id', 'LoadState', 'ActiveState', 'SubState', 'ControlGroup', 'MainPID',
    'User', 'Group', 'Slice', 'Transient', 'KillMode', 'Restart',
    'WorkingDirectory', 'InvocationID', 'Description',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity_environment():
    run, attempt, job = (os.environ.get(name, '') for name in
                         ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB'))
    require(re.fullmatch(r'[0-9]{1,30}', run) is not None
            and re.fullmatch(r'[0-9]{1,10}', attempt) is not None
            and re.fullmatch(r'[A-Za-z0-9_-]{1,80}', job) is not None,
            'EXACT_F0_RUN_ATTEMPT_JOB_REQUIRED')
    return {'run_id': run, 'run_attempt': attempt, 'job_id': job}


def controller_unit(identity):
    return 'trnm-fixed-root-f0-{run_id}-{run_attempt}-{job_id}.service'.format(**identity)


def controller_intent(identity, root, out, head, tree, prepared_sha, binary):
    unit = controller_unit(identity)
    return {'schema': 'fixed-root-owned-controller-v1', **identity,
            'service': unit, 'phase': 'controller', 'job_sha256': prepared_sha,
            'head': head, 'tree': tree, 'binary_sha256': binary['sha256'],
            'binary_path': binary['path'], 'source_root': str(root),
            'uid': os.getuid(), 'gid': os.getgid(), 'prior_load_state': 'not-found',
            'prepared_path': str(out / 'prepared/prepared.json'),
            'execution_path': str(out / 'execution'),
            'expected_cgroup': '/system.slice/' + unit,
            'description': 'Trillionnium F0 controller head ' + head + ' prepared ' + prepared_sha}


def phase_unit_matches(unit, identity, phase):
    require(phase in ('baseline', 'valid-work-root'), 'EXACT_F0_PHASE_REQUIRED')
    prefix = 'trnm-fixed-root-{run_id}-{run_attempt}-{job_id}-'.format(**identity) + phase
    return re.fullmatch(re.escape(prefix) + r'-[1-9][0-9]*\.service', unit) is not None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_OWNERSHIP_FIELD')
        result[key] = value
    return result


def regular_bytes(path, limit):
    """No symlink components, special files, unbounded reads or changed reads."""
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'EXACT_REGULAR_PATH')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'BOUNDED_REGULAR_RECEIPT')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(raw) <= limit and
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            'STABLE_BOUNDED_RECEIPT_REQUIRED')
    return raw


def receipt(path, limit=4 * 1024 * 1024):
    return json.loads(regular_bytes(path, limit), object_pairs_hook=unique_object)


def digest_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def group_identity(path):
    metadata = path.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
            and path.resolve(strict=True) == path and metadata.st_uid == 0
            and metadata.st_mode & 0o022 == 0, 'EXACT_ROOT_OWNED_CGROUP_REQUIRED')
    return {'device': metadata.st_dev, 'inode': metadata.st_ino, 'uid': metadata.st_uid,
            'gid': metadata.st_gid, 'mode': stat.S_IMODE(metadata.st_mode)}


def group_path(value):
    require(isinstance(value, str) and value.startswith('/') and value != '/'
            and all(part not in ('', '.', '..') for part in value[1:].split('/')),
            'EXACT_NONROOT_CGROUP_REQUIRED')
    return CGROUP_ROOT / value[1:]


def kernel_text(path, limit=16384):
    # Kernel pseudo-files report size zero; their bounded content is read directly.
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'BOUNDED_KERNEL_OBSERVATION_REQUIRED')
    return raw.decode('utf-8').strip()


def process_start(raw, pid):
    first = raw.split(' ', 1)[0]
    require(first == str(pid) and ') ' in raw, 'EXACT_SERVICE_PID_REQUIRED')
    fields = raw.rsplit(') ', 1)[1].split()
    require(len(fields) >= 20 and fields[1].isdigit() and fields[19].isdigit(),
            'EXACT_SERVICE_START_REQUIRED')
    return int(fields[1]), int(fields[19])


def live_identity(unit, cgroup, manager):
    """Observed in the service before any native workload is invoked."""
    pid = os.getpid()
    parent, start = process_start(kernel_text(Path('/proc/self/stat')), pid)
    require(kernel_text(Path('/proc/self/cgroup')) == '0::' + cgroup,
            'ACTUAL_SERVICE_CGROUP_REQUIRED')
    require(manager['Id'] == unit and manager['ControlGroup'] == cgroup
            and manager['MainPID'] == str(pid)
            and re.fullmatch('[0-9a-f]{32}', manager['InvocationID']) is not None,
            'ACTUAL_MANAGER_SERVICE_IDENTITY_REQUIRED')
    boot = kernel_text(Path('/proc/sys/kernel/random/boot_id'), 128)
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot) is not None,
            'ACTUAL_BOOT_ID_REQUIRED')
    return {'service': unit, 'pid': pid, 'parent_pid': parent, 'process_start_ticks': start,
            'boot_id': boot, 'uid': os.getuid(), 'gid': os.getgid(),
            'cgroup': cgroup, 'cgroup_identity': group_identity(group_path(cgroup)),
            'invocation_id': manager['InvocationID'],
            'observation_stage': 'before any native phase invocation'}


def parse_manager(raw):
    result = {}
    for line in raw.splitlines():
        key, equal, value = line.partition('=')
        require(equal and key in MANAGER_PROPERTIES and key not in result,
                'EXACT_MANAGER_PROPERTIES_REQUIRED')
        result[key] = value
    require(set(result) == set(MANAGER_PROPERTIES), 'COMPLETE_MANAGER_PROPERTIES_REQUIRED')
    return result


def manager_matches(manager, owned, live):
    """Existing unit must be the same invocation, not just the same unit name."""
    expected = {
        'Id': owned['service'], 'LoadState': 'loaded',
        'User': str(owned['uid']), 'Group': str(owned['gid']), 'Transient': 'yes',
        'Slice': 'system.slice' if owned['phase'] == 'controller' else 'trnmponpublic.slice',
        'KillMode': 'control-group', 'Restart': 'no', 'WorkingDirectory': owned['source_root'],
        'InvocationID': live['invocation_id'], 'Description': owned['description'],
    }
    require(all(manager.get(key) == value for key, value in expected.items()),
            'OWNED_SERVICE_MANAGER_IDENTITY_CHANGED')
    require(manager['ControlGroup'] == live['cgroup'] or
            (manager['ControlGroup'] == '' and manager['MainPID'] == '0'
             and manager['ActiveState'] in ('inactive', 'failed')),
            'OWNED_SERVICE_CONTROL_GROUP_CHANGED')
    require(manager['MainPID'] in ('0', str(live['pid'])), 'OWNED_SERVICE_MAIN_PID_CHANGED')
    require(manager['ActiveState'] in ('active', 'activating', 'deactivating', 'inactive', 'failed'),
            'OWNED_SERVICE_STATE_UNOBSERVABLE')


def observe_group(live):
    path = group_path(live['cgroup'])
    try:
        identity = group_identity(path)
    except FileNotFoundError:
        require(not os.path.lexists(path), 'CGROUP_DISAPPEARANCE_UNCERTAIN')
        return {'path': str(path), 'exists': False, 'empty': True,
                'evidence': 'exact cgroup path absent after same-boot ownership validation'}
    require(identity == live['cgroup_identity'], 'OWNED_CGROUP_IDENTITY_CHANGED')
    # cgroup.events populated covers descendant cgroups, unlike cgroup.procs alone.
    events, processes = kernel_text(path / 'cgroup.events'), kernel_text(path / 'cgroup.procs')
    pairs = [line.split() for line in events.splitlines()]
    require(all(len(pair) == 2 for pair in pairs), 'CGROUP_EVENTS_SHAPE')
    values = dict(pairs)
    require(len(values) == len(pairs) and values.get('populated') in ('0', '1'),
            'CGROUP_POPULATED_OBSERVATION_REQUIRED')
    pids = [int(value) for value in processes.split()]
    require(all(pid > 0 for pid in pids), 'CGROUP_PROCS_OBSERVATION_REQUIRED')
    return {'path': str(path), 'exists': True, 'identity': identity,
            'events_raw': events, 'procs_raw': processes,
            'empty': values['populated'] == '0' and not pids}


def validate_live(owned, live):
    for key in ('service', 'phase', 'job_sha256', 'binary_sha256', 'uid', 'gid'):
        require(live.get(key) == owned[key], 'OWNED_LIVE_RECEIPT_MISMATCH:' + key)
    require(live['cgroup'] == owned['expected_cgroup']
            and live['boot_id'] == kernel_text(Path('/proc/sys/kernel/random/boot_id'), 128)
            and re.fullmatch('[0-9a-f]{32}', live['invocation_id']) is not None,
            'OWNED_LIVE_BOOT_OR_CGROUP_CHANGED')
    require(type(live['pid']) is int and live['pid'] > 1
            and type(live['process_start_ticks']) is int and live['process_start_ticks'] > 0,
            'OWNED_LIVE_PROCESS_ID_REQUIRED')
    group = live['cgroup_identity']
    require(set(group) == {'device', 'inode', 'uid', 'gid', 'mode'}
            and all(type(number) is int and number >= 0 for number in group.values())
            and group['inode'] > 0 and group['uid'] == 0 and group['mode'] & 0o022 == 0,
            'OWNED_LIVE_CGROUP_IDENTITY_REQUIRED')
