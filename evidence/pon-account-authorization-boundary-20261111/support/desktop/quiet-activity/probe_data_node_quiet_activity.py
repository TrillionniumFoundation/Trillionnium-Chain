#!/usr/bin/env python3
"""One read-only two-second activity observation of the existing native job."""
from pathlib import Path
import datetime
import json
import os
import time

JOB = '1a1c8ba754b-135c4-1d3'
MAIN_PID = 2987481
STDOUT = Path('/home/qian-qi/chain-pq-a418-final-records/validation/cdd984808a088e6c2e13b1e1ae6630a94d500c89/node-retained-data-all-targets/stdout.log')


def integer_pairs(path):
    return {line.split()[0].rstrip(':'): int(line.split()[1]) for line in path.read_text().splitlines()}


def sample():
    result = {'captured_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'monotonic_ns': time.monotonic_ns(), 'job_id': JOB, 'main_pid': MAIN_PID}
    try:
        cgroup_text = (Path('/proc') / str(MAIN_PID) / 'cgroup').read_text()
        result['main_cgroup_text'] = cgroup_text
        matches = [line.split(':', 2)[2] for line in cgroup_text.splitlines() if JOB in line]
        if len(matches) != 1:
            raise RuntimeError('exact existing job cgroup not uniquely established')
        relative = Path(matches[0].lstrip('/'))
        if '..' in relative.parts:
            raise RuntimeError('unexpected cgroup path')
        directory = Path('/sys/fs/cgroup') / relative
        members = sorted(set(int(value) for value in (directory / 'cgroup.procs').read_text().split()))
        hz, page = os.sysconf('SC_CLK_TCK'), os.sysconf('SC_PAGE_SIZE')
        uptime = float(Path('/proc/uptime').read_text().split()[0])
        processes = []
        for pid in members:
            entry = Path('/proc') / str(pid)
            try:
                text = (entry / 'stat').read_text()
                fields = text.rsplit(') ', 1)[1].split()
                observed = {'pid': pid, 'state': fields[0], 'ppid': int(fields[1]),
                            'start_ticks': int(fields[19]),
                            'user_cpu_seconds': int(fields[11]) / hz,
                            'system_cpu_seconds': int(fields[12]) / hz,
                            'elapsed_seconds': uptime - int(fields[19]) / hz,
                            'rss_bytes': int(fields[21]) * page,
                            'exe': os.readlink(entry / 'exe')}
                try:
                    observed['io'] = integer_pairs(entry / 'io')
                except OSError as error:
                    observed['io_unavailable'] = str(error)
                processes.append(observed)
            except (OSError, ValueError, IndexError) as error:
                processes.append({'pid': pid, 'unavailable_during_observation': str(error)})
        result['processes'] = processes
        for name in ('cpu.stat', 'memory.events'):
            path = directory / name
            if path.is_file():
                result[name] = integer_pairs(path)
        result['memory.current'] = int((directory / 'memory.current').read_text())
    except (OSError, ValueError, RuntimeError) as error:
        result['probe_error'] = str(error)
    result['filesystems'] = {}
    for value in ('/data', '/tmp', '/home/qian-qi'):
        try:
            fs = os.statvfs(value)
            result['filesystems'][value] = {'device': os.stat(value).st_dev,
                'available_bytes': fs.f_bavail * fs.f_frsize,
                'free_bytes_including_reserved': fs.f_bfree * fs.f_frsize,
                'block_size': fs.f_frsize}
        except OSError as error:
            result['filesystems'][value] = {'error': str(error)}
    try:
        st = STDOUT.stat()
        result['stdout_stat_only'] = {'path': str(STDOUT), 'device': st.st_dev, 'inode': st.st_ino,
                                      'bytes': st.st_size, 'mtime_ns': st.st_mtime_ns}
    except OSError as error:
        result['stdout_stat_error'] = str(error)
    return result


first = sample()
time.sleep(2)
second = sample()
left = {p['pid']: p for p in first.get('processes', []) if 'start_ticks' in p}
deltas = []
for after in second.get('processes', []):
    before = left.get(after['pid'])
    if not before or before['start_ticks'] != after.get('start_ticks'):
        continue
    delta = {'pid': after['pid'], 'same_process_start_ticks': after['start_ticks'],
             'exe': after['exe'],
             'user_cpu_seconds_delta': after['user_cpu_seconds'] - before['user_cpu_seconds'],
             'system_cpu_seconds_delta': after['system_cpu_seconds'] - before['system_cpu_seconds']}
    if 'io' in before and 'io' in after:
        delta['io_deltas'] = {key: after['io'][key] - before['io'][key] for key in before['io'] if key in after['io']}
    deltas.append(delta)
print(json.dumps({'schema': 'read-only-existing-native-job-activity-v1', 'job_id': JOB,
    'read_only': True, 'original_job_not_started_cancelled_or_modified': True,
    'elapsed_observation_seconds': (second['monotonic_ns'] - first['monotonic_ns']) / 1e9,
    'first': first, 'second': second, 'stable_process_deltas': deltas,
    'qualification_granted': False,
    'interpretation_limit': 'One activity/capacity observation only; no hang, OOM, storage-incident cause, or test result is inferred.'}, sort_keys=True))
