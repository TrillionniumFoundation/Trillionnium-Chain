#!/usr/bin/env python3
"""One exact native confirmation test in the original, run-owned Host parent.

The runner owns the same unprivileged PID/process group and wait4 observation as
before. A gated child holds the actual ELF; the privileged helper only attaches
that child to a new inode-bound leaf. It never executes caller commands as root,
installs sudo policy, provisions a parent, selects budgets, or grants fallback.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from decimal import Decimal
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import stat
import subprocess
import sys
import time

# -I excludes both caller PYTHONPATH and this script directory. This is the
# explicit source-owned import, never an environment-selected helper.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from history_fixed_parent_v2 import Manager, FIXED_UNIT, CGROUP_ROOT, owner, validate_copy

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).resolve()
PARENT = CGROUP_ROOT / FIXED_UNIT
HOST_TEST = 'from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline'
LIMITS = {'cpu.max': '25000 100000', 'cpu.max.burst': '0',
          'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '256'}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fd_sha(fd):
    h, offset = hashlib.sha256(), 0
    while True:
        raw = os.pread(fd, 65536, offset)
        if not raw:
            return h.hexdigest()
        h.update(raw)
        offset += len(raw)


def names(run_owner, nonce):
    owner(run_owner)
    require(re.fullmatch('[0-9a-f]{24}', nonce) is not None, 'HOST_NONCE')
    return f'trnmfromzero-{run_owner.replace(".", "-")}-{nonce}', f'from-zero-{nonce}.json'


def process_identity(pid):
    require(type(pid) is int and pid > 1, 'HOST_PID')
    path = Path('/proc') / str(pid)
    raw = (path / 'stat').read_text()
    values = raw[raw.rindex(')') + 2:].split()
    fields = dict(line.split(':', 1) for line in (path / 'status').read_text().splitlines() if ':' in line)
    group = (path / 'cgroup').read_text().splitlines()
    require(len(group) == 1 and group[0].startswith('0::/'), 'HOST_UNIFIED_CGROUP')
    return {'pid': pid, 'parent': int(values[1]), 'group': int(values[2]),
            'start_ticks': int(values[19]), 'uids': [int(x) for x in fields['Uid'].split()],
            'gids': [int(x) for x in fields['Gid'].split()], 'cgroup': group[0][3:],
            'cwd': str((path / 'cwd').resolve(strict=True))}


def validate_child(child, parent, uid, gid, pid, parent_pid, start_ticks):
    require(uid > 0 and gid >= 0 and child['pid'] == pid and parent['pid'] == parent_pid
            and child['parent'] == parent_pid and child['group'] == pid
            and child['start_ticks'] == start_ticks
            and child['uids'] == parent['uids'] == [uid] * 4
            and child['gids'] == parent['gids'] == [gid] * 4
            and child['cwd'] == parent['cwd'] == str(ROOT), 'HOST_CHILD_BINDING')
    require(not parent['cgroup'].startswith('/' + FIXED_UNIT)
            and child['cgroup'] == parent['cgroup'], 'HOST_ADMISSION_OUTSIDE_PARENT')


def native_command(command, timeout):
    require(type(timeout) in (int, float) and timeout == 90
            and len(command) == 5 and command[1:] == [HOST_TEST, '--exact', '--nocapture', '--test-threads=1'],
            'HOST_EXACT_NATIVE_COMMAND')
    binary = Path(command[0])
    require(binary.is_absolute() and not binary.is_symlink()
            and binary.resolve(strict=True) == binary, 'HOST_BINARY_PATH')
    return binary


def validate_gate_arguments(command, args, leaf):
    require(len(command) == 20
            and command[:5] == ['/usr/bin/python3', '-I', '-B', str(SCRIPT), 'exec-native']
            and command[5:15:2] == ['--gate-fd', '--elf-fd', '--sha256', '--membership', '--deadline-ns']
            and command[6].isdigit() and int(command[6]) >= 3
            and command[8] == str(args.elf_fd) and int(command[6]) != args.elf_fd
            and command[10] == args.sha256
            and command[12] == '/' + FIXED_UNIT + '/' + leaf
            and command[14] == str(args.deadline_ns), 'HOST_EXACT_GATE_COMMAND')
    return native_command(command[15:], 90)


def read_at(fd, name, limit=4096):
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    try:
        raw = os.read(handle, limit + 1)
        require(len(raw) <= limit and not os.read(handle, 1), 'HOST_KERNEL_READ_BOUND')
        return raw.decode('ascii').strip()
    finally:
        os.close(handle)


def write_at(fd, name, text):
    handle = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    try:
        raw = text.encode('ascii')
        require(os.write(handle, raw) == len(raw), 'HOST_KERNEL_SHORT_WRITE')
    finally:
        os.close(handle)


@contextmanager
def authority(args):
    require(os.geteuid() == 0, 'HOST_ROOT_HELPER_REQUIRED')
    uid, gid = int(os.environ.get('SUDO_UID', '-1')), int(os.environ.get('SUDO_GID', '-1'))
    require(uid > 0 and gid >= 0, 'HOST_UNPRIVILEGED_CALLER_REQUIRED')
    events = []
    manager = Manager(args.owner, events, lifetime=10)
    directory = manager.lease_directory(FIXED_UNIT, False)
    lease_fd = os.open(directory / 'lease.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    parent_fd = None
    try:
        # Serialise attach/release with the actual root-only existing lease.
        # No persistent additional lock file or caller-written cleanup authority.
        end = time.monotonic() + 10
        while True:
            try:
                fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < end, 'HOST_LEASE_BUSY')
                time.sleep(.005)
        lease = manager.root_lease(FIXED_UNIT)
        require(os.fstat(lease_fd).st_ino == (directory / 'lease.json').stat().st_ino, 'HOST_LEASE_REPLACED')
        validate_copy(lease, lease, args.owner, FIXED_UNIT)
        state = manager.loaded_matches(lease)
        require(state['ActiveState'] == state['SubState'] == 'active'
                and state['ControlGroup'] == '/' + FIXED_UNIT, 'HOST_PARENT_INACTIVE')
        parent_fd = os.open(PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        metadata = os.fstat(parent_fd)
        require(metadata.st_uid == 0 and not metadata.st_mode & 0o022, 'HOST_PARENT_OWNER')
        require({key: read_at(parent_fd, key, 128) for key in LIMITS} == LIMITS, 'HOST_ORIGINAL_LIMITS')
        yield manager, lease, directory, parent_fd, uid, gid
        require(manager.root_lease(FIXED_UNIT) == lease, 'HOST_LEASE_CHANGED')
        manager.loaded_matches(lease)
        current = PARENT.stat(follow_symlinks=False)
        require((current.st_dev, current.st_ino) == (metadata.st_dev, metadata.st_ino)
                and {key: read_at(parent_fd, key, 128) for key in LIMITS} == LIMITS, 'HOST_PARENT_CHANGED')
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        os.close(lease_fd)


def attach(args):
    leaf, record_name = names(args.owner, args.nonce)
    require(re.fullmatch('[0-9a-f]{64}', args.sha256) is not None
            and re.fullmatch('[0-9a-f]{40}', args.source) is not None, 'HOST_EXACT_SOURCE')
    require(time.monotonic_ns() < args.deadline_ns <= time.monotonic_ns() + 90_000_000_000, 'HOST_ABSOLUTE_DEADLINE')
    with authority(args) as (manager, lease, directory, parent_fd, uid, gid):
        child, parent = process_identity(args.pid), process_identity(args.parent_pid)
        validate_child(child, parent, uid, gid, args.pid, args.parent_pid, args.start_ticks)
        source = subprocess.run(['/usr/bin/git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                                user=uid, group=gid, extra_groups=[], capture_output=True, text=True,
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, timeout=5, check=True)
        require(source.stdout.strip() == args.source, 'HOST_SOURCE_CHANGED')
        pidfd = os.pidfd_open(args.pid, 0)
        binary_fd = os.open(f'/proc/{args.pid}/fd/{args.elf_fd}', os.O_RDONLY | os.O_CLOEXEC)
        leaf_fd = None
        try:
            info = os.fstat(binary_fd)
            command_raw = Path(f'/proc/{args.pid}/cmdline').read_bytes()
            require(len(command_raw) <= 8192 and command_raw.endswith(b'\0'), 'HOST_GATE_COMMAND_BOUND')
            binary = validate_gate_arguments(command_raw[:-1].decode().split('\0'), args, leaf)
            named = binary.stat(follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == uid
                    and info.st_mode & 0o111 and os.pread(binary_fd, 4, 0) == b'\x7fELF'
                    and (info.st_dev, info.st_ino) == (named.st_dev, named.st_ino)
                    and Path(f'/proc/{args.pid}/exe').resolve() == Path('/usr/bin/python3').resolve()
                    and fd_sha(binary_fd) == args.sha256, 'HOST_HELD_NATIVE_ELF')
            require(not select.select([pidfd], [], [], 0)[0]
                    and process_identity(args.pid) == child, 'HOST_CHILD_MOVED_BEFORE_ATTACH')
            require(read_at(parent_fd, 'pids.current', 128) == '0'
                    and read_at(parent_fd, 'cgroup.procs') == ''
                    and read_at(parent_fd, 'cgroup.type', 128) == 'domain'
                    and not any(entry.is_dir(follow_symlinks=False) for entry in os.scandir(parent_fd)),
                    'HOST_PARENT_NOT_EMPTY')
            # Same child-controller setup as the existing owned fixed-parent
            # fixture. Only this exclusively owned empty parent is changed;
            # no ancestor, quota, memory, swap, PID limit or permission is reset.
            require({'cpu', 'memory', 'pids'} <= set(read_at(parent_fd, 'cgroup.controllers').split()),
                    'HOST_CONTROLLERS_REQUIRED')
            require(time.monotonic_ns() < args.deadline_ns, 'HOST_ABSOLUTE_DEADLINE')
            write_at(parent_fd, 'cgroup.subtree_control', '+cpu +memory +pids')
            os.mkdir(leaf, 0o700, dir_fd=parent_fd)
            leaf_fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
            write_at(leaf_fd, 'cgroup.max.descendants', '0')
            meta = os.fstat(leaf_fd)
            parent_meta = os.fstat(parent_fd)
            record = {'schema': 'from-zero-native-root-leaf-v1', 'owner': args.owner, 'nonce': args.nonce,
                      'leaf': leaf, 'device': meta.st_dev, 'inode': meta.st_ino,
                      'parent_device': parent_meta.st_dev, 'parent_inode': parent_meta.st_ino,
                      'lease_token': lease['token'], 'uid': uid, 'gid': gid,
                      'pid': args.pid, 'start_ticks': args.start_ticks, 'parent_pid': args.parent_pid,
                      'source': args.source, 'binary_sha256': args.sha256}
            record_fd = os.open(directory / record_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(record_fd, 'w') as stream:
                json.dump(record, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            require(time.monotonic_ns() < args.deadline_ns
                    and not select.select([pidfd], [], [], 0)[0]
                    and process_identity(args.pid) == child, 'HOST_ATTACH_EXPIRED_OR_CHANGED')
            write_at(leaf_fd, 'cgroup.procs', str(args.pid))
            after = process_identity(args.pid)
            require(after == {**child, 'cgroup': '/' + FIXED_UNIT + '/' + leaf}, 'HOST_MEMBERSHIP_NOT_ESTABLISHED')
            return {'attached': True, 'owner': args.owner, 'leaf': leaf, 'pid': args.pid,
                    'start_ticks': args.start_ticks, 'uid': uid, 'gid': gid,
                    'source': args.source, 'binary_sha256': args.sha256, 'membership': after['cgroup']}
        finally:
            if leaf_fd is not None:
                os.close(leaf_fd)
            os.close(binary_fd)
            os.close(pidfd)


def release(args):
    leaf, record_name = names(args.owner, args.nonce)
    with authority(args) as (_, lease, directory, parent_fd, uid, gid):
        path = directory / record_name
        if not path.exists():
            # Absence is not successful native attachment and grants no credit.
            require(not (PARENT / leaf).exists(), 'HOST_UNRECORDED_LEAF')
            return {'closed': False, 'no_owned_leaf': True, 'forced_cleanup': False}
        handle = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(handle, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                    and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size <= 8192, 'HOST_ROOT_RECORD')
            record = json.load(stream)
        parent_meta = os.fstat(parent_fd)
        require(record['schema'] == 'from-zero-native-root-leaf-v1'
                and (record['owner'], record['nonce'], record['leaf'], record['uid'], record['gid'])
                == (args.owner, args.nonce, leaf, uid, gid)
                and record['lease_token'] == lease['token']
                and (record['parent_device'], record['parent_inode']) == (parent_meta.st_dev, parent_meta.st_ino),
                'HOST_RELEASE_AUTHORITY')
        fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            meta = os.fstat(fd)
            require(meta.st_uid == 0 and (meta.st_dev, meta.st_ino) == (record['device'], record['inode']), 'HOST_LEAF_REPLACED')
            forced = read_at(fd, 'cgroup.procs') != '' or 'populated 1' in read_at(fd, 'cgroup.events')
            if forced:
                write_at(fd, 'cgroup.kill', '1')
            end = time.monotonic() + 5
            while read_at(fd, 'cgroup.procs') or 'populated 1' in read_at(fd, 'cgroup.events'):
                require(time.monotonic() < end, 'HOST_DESCENDANTS_NOT_CLOSED')
                time.sleep(.005)
            counters = {key: read_at(fd, key) for key in ('cpu.stat', 'memory.current', 'cgroup.events')}
            current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            require((current.st_dev, current.st_ino) == (meta.st_dev, meta.st_ino), 'HOST_LEAF_REPLACED')
            os.rmdir(leaf, dir_fd=parent_fd)
            path.unlink()
            return {'closed': True, 'forced_cleanup': forced, 'leaf': leaf, 'kernel_after': counters}
        finally:
            os.close(fd)


def root_call(action, run_owner, nonce, extra, remaining, *, log_directory):
    require(remaining > 0, 'HOST_HELPER_DEADLINE')
    command = ['/usr/bin/sudo', '-n', '--', '/usr/bin/python3', '-I', '-B', str(SCRIPT),
               action, '--owner', run_owner, '--nonce', nonce, *extra]
    result, failure = None, None
    try:
        result = subprocess.run(command, capture_output=True,
                                timeout=min(remaining, 20), check=False)
    except (OSError, subprocess.SubprocessError) as error:
        failure = error
    streams = {name: (getattr(result if result is not None else failure, name, None) or b'')
               for name in ('stdout', 'stderr')}
    receipt = {'command': command, 'returncode': result.returncode if result else None,
               'error': str(failure) if failure else None, 'helper_completion_unknown': failure is not None}
    for name, raw in streams.items():
        if isinstance(raw, str):
            raw = raw.encode()
        receipt[name + '_bytes'] = len(raw)
        receipt[name + '_truncated'] = len(raw) > 65536
        with (log_directory / f'host-{action}.{name}').open('xb') as stream:
            stream.write(raw[:65536])
    with (log_directory / f'host-{action}.json').open('x') as stream:
        json.dump(receipt, stream, indent=2)
        stream.write('\n')
    if failure is not None:
        raise failure
    require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536, 'HOST_HELPER_OUTPUT')
    require(result.returncode == 0, 'HOST_HELPER_FAILED: ' + result.stderr[-2048:].decode(errors='replace'))
    value = json.loads(result.stdout)
    require(type(value) is dict, 'HOST_HELPER_RECEIPT')
    return value


def run_host_child(command, folder, timeout, *, run_owner, source, binary_sha256):
    """The original 90 seconds include gate creation, sudo attachment and exec.

    Cleanup may finish after a timeout, as original kill/wait4 cleanup did; it
    never renews the native deadline or converts unknown cleanup to a pass.
    """
    started = time.monotonic_ns()
    deadline = started + 90_000_000_000
    binary = native_command(command, timeout)
    owner(run_owner)
    nonce = secrets.token_hex(12)
    leaf, _ = names(run_owner, nonce)
    folder.mkdir()
    fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
    process = usage = attached = closed = None
    error = cleanup_error = None
    timed_out = False
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and os.pread(fd, 4, 0) == b'\x7fELF' and fd_sha(fd) == binary_sha256, 'HOST_BINARY_CHANGED')
        shim = ['/usr/bin/python3', '-I', '-B', str(SCRIPT), 'exec-native',
                '--gate-fd', str(gate_read), '--elf-fd', str(fd), '--sha256', binary_sha256,
                '--membership', '/' + FIXED_UNIT + '/' + leaf, '--deadline-ns', str(deadline), *command]
        with (folder / 'stdout').open('xb') as stdout, (folder / 'stderr').open('xb') as stderr:
            process = subprocess.Popen(shim, stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL,
                                       start_new_session=True, pass_fds=(gate_read, fd), cwd=ROOT)
            os.close(gate_read)
            gate_read = None
            try:
                child = process_identity(process.pid)
                attached = root_call('attach', run_owner, nonce,
                    ['--pid', str(process.pid), '--parent-pid', str(os.getpid()),
                     '--start-ticks', str(child['start_ticks']), '--elf-fd', str(fd),
                     '--sha256', binary_sha256, '--source', source, '--deadline-ns', str(deadline)],
                    (deadline - time.monotonic_ns()) / 1e9, log_directory=folder)
                require(attached == {'attached': True, 'owner': run_owner, 'leaf': leaf,
                        'pid': process.pid, 'start_ticks': child['start_ticks'], 'uid': os.getuid(),
                        'gid': os.getgid(), 'source': source, 'binary_sha256': binary_sha256,
                        'membership': '/' + FIXED_UNIT + '/' + leaf}, 'HOST_ATTACH_RECEIPT')
                require(time.monotonic_ns() < deadline, 'HOST_ABSOLUTE_DEADLINE')
                require(os.write(gate_write, b'1') == 1, 'HOST_GATE_WRITE')
                os.close(gate_write)
                gate_write = None
                while True:
                    pid, status, observed = os.wait4(process.pid, os.WNOHANG)
                    if pid:
                        usage = observed
                        process.returncode = os.waitstatus_to_exitcode(status)
                        timed_out = time.monotonic_ns() >= deadline
                        break
                    if time.monotonic_ns() >= deadline:
                        timed_out = True
                        break
                    time.sleep(.005)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as failure:
                error = str(failure)
                timed_out = time.monotonic_ns() >= deadline
            finally:
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    _, status, usage = os.wait4(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as failure:
        error = str(failure)
    finally:
        for descriptor in (fd, gate_read, gate_write):
            if descriptor is not None:
                os.close(descriptor)
        try:
            closed = root_call('release', run_owner, nonce, [], 20, log_directory=folder)
            require(closed.get('closed') is True and closed.get('forced_cleanup') is False,
                    'HOST_SCOPE_DID_NOT_CLOSE_NATURALLY')
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as failure:
            cleanup_error = str(failure)
    for name in ('stdout', 'stderr'):
        (folder / name).touch(exist_ok=True)
    cpu = lambda value: int((Decimal(str(value)) * 1_000_000).to_integral_value()) * 1000
    result = {'command': command, 'exit_code': process.returncode if process else None,
              'timed_out': timed_out, 'wall_ns': time.monotonic_ns() - started,
              'cpu_ns': cpu(usage.ru_utime) + cpu(usage.ru_stime) if usage else None,
              'user_cpu_ns': cpu(usage.ru_utime) if usage else None,
              'system_cpu_ns': cpu(usage.ru_stime) if usage else None,
              'max_rss_kib': usage.ru_maxrss if usage else None,
              'minor_faults': usage.ru_minflt if usage else None,
              'major_faults': usage.ru_majflt if usage else None,
              'voluntary_switches': usage.ru_nvcsw if usage else None,
              'involuntary_switches': usage.ru_nivcsw if usage else None,
              'wait4_cpu_resolution_ns': 1000,
              'cpu_scope': 'same waited native PID including pre-exec gate; root attach/cleanup excluded',
              'rss_scope': 'whole waited child including pre-exec image; no Rust-only attribution',
              'host_scope': {'owner': run_owner, 'attachment': attached, 'closure': closed,
                             'error': error, 'cleanup_error': cleanup_error,
                             'native_deadline_ns': deadline, 'native_budget_seconds': 90,
                             'complete': attached is not None and error is None and cleanup_error is None
                                         and not timed_out and process is not None and process.returncode == 0,
                             'scope': 'entire same-process finite confirmation fixture; not independent receiver fairness'},
              'stdout_sha256': sha((folder / 'stdout').read_bytes()),
              'stderr_sha256': sha((folder / 'stderr').read_bytes())}
    (folder / 'process.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest='action', required=True)
    for name in ('attach', 'release'):
        p = sub.add_parser(name, allow_abbrev=False)
        p.add_argument('--owner', required=True)
        p.add_argument('--nonce', required=True)
        if name == 'attach':
            for field in ('pid', 'parent-pid', 'start-ticks', 'elf-fd', 'deadline-ns'):
                p.add_argument('--' + field, type=int, required=True)
            p.add_argument('--sha256', required=True)
            p.add_argument('--source', required=True)
    p = sub.add_parser('exec-native', allow_abbrev=False)
    for field in ('gate-fd', 'elf-fd', 'deadline-ns'):
        p.add_argument('--' + field, type=int, required=True)
    p.add_argument('--sha256', required=True)
    p.add_argument('--membership', required=True)
    p.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action == 'exec-native':
        native_command(args.command, 90)
        ready, _, _ = select.select([args.gate_fd], [], [], max(0, (args.deadline_ns - time.monotonic_ns()) / 1e9))
        require(ready and os.read(args.gate_fd, 2) == b'1', 'HOST_EXEC_GATE')
        os.close(args.gate_fd)
        require(time.monotonic_ns() < args.deadline_ns
                and process_identity(os.getpid())['cgroup'] == args.membership
                and args.membership.startswith('/' + FIXED_UNIT + '/trnmfromzero-')
                and fd_sha(args.elf_fd) == args.sha256
                and os.pread(args.elf_fd, 4, 0) == b'\x7fELF', 'HOST_EXEC_BINDING')
        require(time.monotonic_ns() < args.deadline_ns, 'HOST_ABSOLUTE_DEADLINE')
        os.set_inheritable(args.elf_fd, False)
        os.execve(args.elf_fd, args.command, os.environ)
        raise AssertionError('exec returned')
    print(json.dumps(attach(args) if args.action == 'attach' else release(args), sort_keys=True))


if __name__ == '__main__':
    main()
