"""Bounded post-gap observations of an already held child; never RSS success.

These diagnostic snapshots occur after a missing RSS sample. They cannot explain
an earlier sample by themselves, provide memory-budget credit, reap, or signal.
"""
import itertools
import os
from pathlib import Path
import select
import time


def _fields(path):
    with path.open() as handle:
        raw = handle.read(65537)
    if len(raw) > 65536:
        raise ValueError('diagnostic-proc-bound')
    result = {}
    for line in raw.splitlines():
        name, separator, value = line.partition(':')
        if separator and name in ('Pid', 'PPid', 'Tgid', 'NSpid', 'NStgid', 'VmRSS', 'State', 'Threads'):
            if name in result:
                raise ValueError('diagnostic-proc-duplicate')
            result[name] = value.split()
    return result


def _number(fields, key):
    value, = fields[key]
    return int(value)


def _task_stat(path):
    with path.open() as handle:
        raw = handle.read(65537)
    if len(raw) > 65536 or ') ' not in raw:
        raise ValueError('diagnostic-stat-bound-or-syntax')
    prefix, suffix = raw.rsplit(') ', 1)
    pid, separator, _ = prefix.partition(' (')
    fields = suffix.split()
    if not separator or len(fields) < 22 or len(fields[0]) != 1:
        raise ValueError('diagnostic-stat-fields')
    flags = int(fields[6])
    return dict(pid=int(pid), state=fields[0], ppid=int(fields[1]), flags=flags,
        pf_exiting=bool(flags & 0x00000004), pf_kthread=bool(flags & 0x00200000), starttime_ticks=int(fields[19]),
        vsize_bytes=int(fields[20]), rss_pages=int(fields[21]))


def owned_child_rss_gap(pid, held_pidfd):
    """Inspect only the held child and up to 32 tasks in its verified group."""
    result = dict(schema='llm-owned-child-post-rss-gap-v1',
        scope='post-gap diagnostic snapshot; not the missing sample or resource qualification',
        monotonic_ns=time.monotonic_ns(), identity_verified=False, diagnostic_status='unavailable')
    try:
        if type(pid) is not int or pid <= 0 or type(held_pidfd) is not int or held_pidfd < 0:
            raise ValueError('diagnostic-owned-handle')
        parent = _fields(Path('/proc/self/status'))
        parent_pid = _number(parent, 'Pid')
        parent_ns = list(map(int, parent['NSpid']))
        if not parent_ns or parent_ns[0] != parent_pid or parent_ns[-1] != os.getpid():
            raise ValueError('diagnostic-parent-namespace')
        identity_path = Path(f'/proc/self/fdinfo/{held_pidfd}')
        identity = _fields(identity_path)
        visible = _number(identity, 'Pid')
        namespace = list(map(int, identity['NSpid']))
        coordinate = len(parent_ns) - 1
        if (visible <= 0 or len(namespace) <= coordinate or namespace[0] != visible or
                namespace[coordinate] != pid):
            raise ValueError('diagnostic-held-pidfd-namespace')
        path = Path(f'/proc/{visible}')
        leader = _fields(path / 'status')
        if (_number(leader, 'Pid') != visible or _number(leader, 'Tgid') != visible or
                _number(leader, 'PPid') != parent_pid or list(map(int, leader['NSpid'])) != namespace):
            raise ValueError('diagnostic-owned-leader')
        result.update(identity_verified=True, leader_state=leader['State'][0],
            leader_rss_fields=leader.get('VmRSS'), reported_threads=_number(leader, 'Threads'))
        poll = select.poll()
        poll.register(held_pidfd, select.POLLIN)
        events = poll.poll(0)
        result['held_pidfd_poll_events'] = [event for descriptor, event in events if descriptor == held_pidfd]
        samples = []
        tasks = list(itertools.islice((path / 'task').iterdir(), 33))
        result['task_list_truncated'] = len(tasks) > 32
        result['task_list_before'] = sorted(task.name for task in tasks)
        for task in tasks[:32]:
            if not task.name.isdigit():
                raise ValueError('diagnostic-task-path')
            fields = _fields(task / 'status')
            if (_number(fields, 'Pid') != int(task.name) or _number(fields, 'Tgid') != visible or
                    _number(fields, 'PPid') != parent_pid or list(map(int, fields['NStgid'])) != namespace):
                raise ValueError('diagnostic-owned-task')
            observed_stat = _task_stat(task / 'stat')
            if observed_stat['pid'] != int(task.name) or observed_stat['ppid'] != parent_pid:
                raise ValueError('diagnostic-task-stat-identity')
            samples.append(dict(state=fields['State'][0], rss_fields=fields.get('VmRSS'),
                leader=int(task.name) == visible, stat=observed_stat,
                identity={name: fields.get(name) for name in ('Pid', 'PPid', 'Tgid', 'NSpid', 'NStgid')}))
        result['task_samples'] = samples
        after_tasks = list(itertools.islice((path / 'task').iterdir(), 33))
        result['task_list_after'] = sorted(task.name for task in after_tasks)
        result['task_list_stable'] = result['task_list_before'] == result['task_list_after']
        leader_after = _fields(path / 'status')
        if (_number(leader_after, 'Pid') != visible or _number(leader_after, 'Tgid') != visible or
                _number(leader_after, 'PPid') != parent_pid or list(map(int, leader_after['NSpid'])) != namespace):
            raise ValueError('diagnostic-owned-leader-after')
        result['reported_threads_after'] = _number(leader_after, 'Threads')
        result['leader_state_after'] = leader_after['State'][0]
        after_samples = []
        for task in after_tasks[:32]:
            fields = _fields(task / 'status')
            observed_stat = _task_stat(task / 'stat')
            if (_number(fields, 'Pid') != int(task.name) or _number(fields, 'Tgid') != visible or
                    _number(fields, 'PPid') != parent_pid or list(map(int, fields['NStgid'])) != namespace or
                    observed_stat['pid'] != int(task.name) or observed_stat['ppid'] != parent_pid):
                raise ValueError('diagnostic-owned-task-after')
            after_samples.append(dict(state=fields['State'][0], rss_fields=fields.get('VmRSS'),
                leader=int(task.name) == visible, stat=observed_stat,
                identity={name: fields.get(name) for name in ('Pid', 'PPid', 'Tgid', 'NSpid', 'NStgid')}))
        result['task_samples_after'] = after_samples
        result.update(diagnostic_status='observed',
            held_pidfd_identity_unchanged_after=_fields(identity_path) == identity)
    except (OSError, AttributeError, KeyError, ValueError, TypeError, IndexError) as error:
        result.update(error_type=type(error).__name__, error_errno=getattr(error, 'errno', None))
        if isinstance(error, ValueError) and str(error).startswith('diagnostic-'):
            result['diagnostic_reason'] = str(error)
    return result
