#!/usr/bin/env python3
"""Mutate only this run's root-leased parent and its pidfd-pinned native child.

The actual verifier stays unprivileged. JSON and executable hashes are evidence,
never authority to change a foreign parent or process. Every failure is retained.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import time

from history_fixed_parent_v2 import Manager, FIXED_UNIT, validate_copy
from read_native_history_verifier import LIMITS, PARENT, require

HELPER = 'ingress::history_graph_resource_v1::native_tests::graph_resource_v1_native_owned_parent_case'
PROFILE = 'history-account-graph-resource-fence-v1'
CASE_SECONDS = 60
CASES = [
    *({'case': f'cpu-window-{offset}', 'trigger': 'after-node', 'offset': offset, 'action': 'cpu'} for offset in range(8)),
    {'case': 'strict-cpu-next-node', 'trigger': 'strict-after-node0', 'action': 'cpu'},
    {'case': 'cpu-before-enter', 'trigger': 'enter', 'action': 'cpu'},
    {'case': 'cpu-before-final-relation', 'trigger': 'final-relation', 'action': 'cpu'},
    {'case': 'cpu-before-exit', 'trigger': 'exit', 'action': 'cpu'},
    {'case': 'cpu-before-admission-commit', 'trigger': 'admission-commit', 'action': 'cpu'},
    {'case': 'cpu-before-activation-commit', 'trigger': 'activation-commit', 'action': 'cpu'},
    {'case': 'cpu-before-settlement-commit', 'trigger': 'settlement', 'action': 'cpu'},
    {'case': 'burst-window-1', 'trigger': 'after-node', 'offset': 1, 'action': 'burst'},
    {'case': 'memory-window-3', 'trigger': 'after-node', 'offset': 3, 'action': 'memory'},
    {'case': 'swap-window-4', 'trigger': 'after-node', 'offset': 4, 'action': 'swap'},
    {'case': 'pids-window-5', 'trigger': 'after-node', 'offset': 5, 'action': 'pids'},
    {'case': 'unreadable-window-2', 'trigger': 'after-node', 'offset': 2, 'action': 'unreadable-cpu'},
    {'case': 'nonleader-process-migration-window-3', 'trigger': 'after-node', 'offset': 3, 'action': 'migrate-process'},
    {'case': 'full-import-equivalence', 'trigger': 'full-import-equivalence', 'action': 'none'},
    {'case': 'public-import-known-close', 'trigger': 'public-import-known-close', 'action': 'cpu'},
]
MUTATIONS = {'cpu': ('cpu.max', '20000 100000'), 'burst': ('cpu.max.burst', '1000'),
             'memory': ('memory.max', '1073741824'), 'swap': ('memory.swap.max', '1048576'),
             'pids': ('pids.max', '128')}


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def current_membership(pid, tid=None):
    path = Path(f'/proc/{pid}/cgroup' if tid is None else f'/proc/{pid}/task/{tid}/cgroup')
    raw = path.read_text()
    require(len(raw) <= 4096 and len(raw.splitlines()) == 1 and raw.startswith('0::/'),
            'one real unified cgroup membership required')
    relative = raw.strip()[3:]
    require('..' not in Path(relative).parts, 'unexpected cgroup path')
    return relative


def parent():
    root = Path(PARENT)
    require(root.resolve(strict=True) == root, 'fixed parent symlink refused')
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0,
            'original root-owned parent required')
    return {'path': PARENT, 'device': info.st_dev, 'inode': info.st_ino,
            'uid': info.st_uid, 'mode': info.st_mode,
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'limits': {name: (root / name).read_text().strip() for name in LIMITS},
            'cpu_file_mode': stat.S_IMODE((root / 'cpu.max').stat().st_mode),
            'pids_current': int((root / 'pids.current').read_text()),
            'cpu_stat': (root / 'cpu.stat').read_text()}


class PinnedCase:
    """All privileged case I/O stays relative to one opened directory inode."""
    def __init__(self, path, uid):
        self.path = path
        require(path.is_absolute() and path.parts[0] == '/' and len(path.parts) > 1
                and all(part not in ('.', '..') for part in path.parts[1:]), 'absolute component-safe case required')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        current = os.open('/', flags)
        try:
            for part in path.parts[1:]:
                child = os.open(part, flags, dir_fd=current)
                os.close(current)
                current = child
            self.fd = current
            self.info = os.fstat(current)
            self.uid = uid
            require(stat.S_ISDIR(self.info.st_mode) and stat.S_IMODE(self.info.st_mode) == 0o700
                    and self.info.st_uid == uid, 'private original-user control directory required')
        except BaseException:
            os.close(current)
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.fd)

    @staticmethod
    def name(name):
        require(type(name) is str and re.fullmatch('[a-z0-9-]+[.](?:json|log|guardian-pending)', name),
                'one exact direct case member required')
        return name

    def present(self, name):
        try:
            info = os.stat(self.name(name), dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        require(stat.S_ISREG(info.st_mode) and info.st_uid == self.uid, 'original-user regular handshake required')
        return True

    def read(self, name):
        fd = os.open(self.name(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == self.uid and 0 <= before.st_size <= 65536,
                    'bounded original-user regular handshake required')
            chunks = []
            remaining = 65537
            while remaining:
                raw = os.read(fd, min(65536, remaining))
                if not raw:
                    break
                chunks.append(raw); remaining -= len(raw)
            raw = b''.join(chunks)
            after = os.fstat(fd)
            require(len(raw) <= 65536 and all(getattr(before, key) == getattr(after, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
                    and len(raw) == before.st_size,
                    'stable bounded actual handshake bytes required')
        finally:
            os.close(fd)
        def unique(pairs):
            value = {}
            for key, item in pairs:
                require(key not in value, 'duplicate handshake key refused')
                value[key] = item
            return value
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite handshake')))

    def put(self, name, value, uid, gid):
        name = self.name(name)
        raw = json.dumps(value, sort_keys=True, indent=2).encode() + b'\n'
        require(len(raw) <= 256 * 1024, 'bounded fresh guardian record')
        pending = self.name(name.rsplit('.', 1)[0] + '.guardian-pending')
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        published = False
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchown(stream.fileno(), uid, gid)
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            # linkat gives a no-replace publication within the pinned inode.
            # A pre-existing final member, including a symlink, is never replaced.
            os.link(pending, name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
            published = True
            os.unlink(pending, dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            if not published:
                try:os.unlink(pending, dir_fd=self.fd)
                except FileNotFoundError:pass

    def log(self, gid):
        fd = os.open('native.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        os.fchown(fd, self.uid, gid)
        return os.fdopen(fd, 'wb')


def write_kernel(path, value):
    raw = (value + '\n').encode('ascii')
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    try:
        require(os.write(fd, raw) == len(raw), 'complete real kernel write required')
    finally:
        os.close(fd)


def run(args):
    require(os.geteuid() == 0, 'only the administrative guardian is privileged')
    require(args.uid > 0 and args.gid > 0, 'native executable must be unprivileged')
    with PinnedCase(args.directory, args.uid) as files:
        return run_pinned(args, files)


def run_pinned(args, files):
    case = args.directory
    directory = files.info
    spec = files.read('job.json')
    selected = [row for row in CASES if row['case'] == spec.get('case')]
    require(len(selected) == 1 and all(spec.get(key) == value for key, value in selected[0].items()),
            'exact finite physical-control roster required')
    require(set(spec) == set(selected[0]) | {'schema', 'parent', 'profile', 'binary_sha256'}
            and ('offset' not in spec or type(spec['offset']) is int), 'unknown case fields refused')
    require(spec['schema'] == 'history-graph-resource-physical-job-v1'
            and spec['parent'] == PARENT and spec['profile'] == PROFILE, 'explicit fixed parent and v1 case')
    binary = args.binary
    require(binary.is_absolute() and binary.resolve(strict=True) == binary and binary.is_file()
            and not binary.is_symlink() and binary.stat().st_uid == args.uid
            and sha(binary) == spec['binary_sha256'], 'actual retained user-owned ELF required')
    with binary.open('rb') as stream:
        require(stream.read(4) == b'\x7fELF', 'retained native ELF required')
    outer = current_membership(os.getpid())
    require(not outer.startswith('/trnmponpublic.slice'), 'guardian stays outside verifier parent')
    outer_path = Path('/sys/fs/cgroup') / outer.lstrip('/')
    require((outer_path / 'cpu.max').read_text().strip() == '400000 100000'
            and (outer_path / 'memory.max').read_text().strip() == '17179869184'
            and os.getpriority(os.PRIO_PROCESS, 0) == 10, 'original finite outer budget required')
    events = []
    manager = Manager(args.owner, events, lifetime=CASE_SECONDS + 20)
    lease = manager.root_lease(FIXED_UNIT)
    validate_copy(lease, lease, args.owner, FIXED_UNIT)
    manager.loaded_matches(lease)
    before = parent()
    require(before['limits'] == LIMITS and before['pids_current'] == 0, 'fresh sole original verifier parent')
    unit = f'trnm-graph-{args.owner.replace(".", "-")}-{spec["case"]}.service'
    require(re.fullmatch(r'trnm-graph-[0-9]+-[0-9]+-[a-z0-9-]+\.service', unit), 'owned unique unit name')
    group = '/trnmponpublic.slice/' + unit
    unused = manager.state(unit)
    require(unused['LoadState'] == 'not-found' and unused['ActiveState'] == 'inactive'
            and unused['FragmentPath'] == unused['ControlGroup'] == '', 'existing native unit refused')
    command = ['systemd-run', '--wait', '--pipe', '--collect', '--service-type=exec',
               '--expand-environment=no', '--slice=trnmponpublic.slice', '--unit=' + unit,
               f'--uid={args.uid}', f'--gid={args.gid}', '--property=KillMode=control-group',
               '--property=TimeoutStopSec=5s', '--property=RuntimeMaxSec=65s',
               '--property=NoNewPrivileges=yes', '--property=ProtectControlGroups=yes',
               '--property=CPUAccounting=yes', '--property=MemoryAccounting=yes',
               '--setenv=RUST_TEST_THREADS=1', '--setenv=TRNM_HISTORY_GRAPH_RESOURCE_NATIVE_CASE=' + str(case),
               str(binary), HELPER, '--exact', '--ignored', '--nocapture', '--test-threads=1']
    result = {'schema': 'history-graph-resource-physical-guardian-v1', 'case': spec['case'],
              'action': spec['action'], 'profile': PROFILE, 'unit': unit, 'native_cgroup': group,
              'outer_cgroup': outer, 'binary_sha256': spec['binary_sha256'], 'original_parent': before,
              'root_lease_verified': True, 'actual_child_unprivileged': True, 'pidfd_pinned': False,
              'passed': False, 'production_qualified': False, 'whole_history_p0_closed': False,
              'case_budget_seconds': CASE_SECONDS, 'events': events}
    started = time.monotonic(); deadline = started + CASE_SECONDS
    child = None; pidfd = None; original_identity = None; changed = False; restored = False
    def unchanged_authority():
        require(manager.root_lease(FIXED_UNIT) == lease, 'root lease changed')
        manager.loaded_matches(lease)
        current = parent()
        require(all(current[key] == before[key] for key in ('path', 'device', 'inode', 'boot_id')),
                'original physical parent replaced')
        info = case.lstat()
        pinned = os.fstat(files.fd)
        require((info.st_dev, info.st_ino) == (pinned.st_dev, pinned.st_ino)
                == (directory.st_dev, directory.st_ino), 'control directory replaced')
        return current
    def live():
        return pidfd is not None and not select.select([pidfd], [], [], 0)[0]
    def wait_file(name):
        while not files.present(name):
            require(time.monotonic() < deadline and child.poll() is None, 'finite actual native handshake')
            time.sleep(0.002)
        return files.read(name)
    def actual_identity(expected, membership):
        require(live(), 'original pinned child already exited')
        pid, tid = expected['pid'], expected['tid']
        require(type(pid) is int and type(tid) is int and pid > 1 and tid > 1 and tid != pid,
                'actual nonleader verifier thread required')
        require(expected['uid'] == args.uid and expected['gid'] == args.gid, 'original unprivileged credentials')
        require(current_membership(pid) == current_membership(pid, tid) == membership, 'actual whole process/thread membership')
        require(sha(Path(f'/proc/{pid}/exe')) == spec['binary_sha256'], 'same live original executable')
        status = Path(f'/proc/{pid}/status').read_text().splitlines()
        uids = next(line.split()[1:] for line in status if line.startswith('Uid:'))
        gids = next(line.split()[1:] for line in status if line.startswith('Gid:'))
        require(all(int(value) == args.uid for value in uids) and all(int(value) == args.gid for value in gids),
                'actual original process credentials required')
    def restore():
        nonlocal restored
        unchanged_authority()
        action = spec['action']
        if action in MUTATIONS:
            name, _ = MUTATIONS[action];write_kernel(Path(PARENT) / name, LIMITS[name])
        elif action == 'unreadable-cpu':
            os.chmod(Path(PARENT) / 'cpu.max', before['cpu_file_mode'])
        elif action == 'migrate-process' and live():
            actual_identity(original_identity, outer)
            write_kernel(Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.procs', str(original_identity['pid']))
            actual_identity(original_identity, group)
        observed = unchanged_authority()
        require(observed['limits'] == LIMITS and observed['cpu_file_mode'] == before['cpu_file_mode'],
                'actual original limits and permissions restored')
        restored = True
        return observed
    try:
        with files.log(args.gid) as log:
            child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            ready = wait_file('ready.json');identity = ready['identity'];original_identity = identity
            require(ready['case'] == spec['case'] and ready['binary_sha256'] == spec['binary_sha256'], 'ready case/source binding')
            actual_pid = int(manager.command('systemctl', 'show', unit, '--property=MainPID', '--value'))
            require(actual_pid == identity['pid'], 'JSON PID must equal actual owned service MainPID')
            pidfd = os.pidfd_open(actual_pid, 0);actual_identity(identity, group)
            result.update(pidfd_pinned=True, original_identity=identity, actual_systemd_main_pid=actual_pid)
            unchanged_authority()
            if spec['action'] != 'none':
                request = wait_file('mutation-request.json')
                require(request['schema'] == 'history-graph-resource-physical-request-v1'
                        and request['case'] == spec['case'] and request['action'] == spec['action']
                        and request['identity'] == identity and request['binary_sha256'] == spec['binary_sha256'],
                        'original pinned native mutation request required')
                actual_identity(identity, group);current = unchanged_authority();action = spec['action']
                changed = True
                if action in MUTATIONS:
                    name, value = MUTATIONS[action];write_kernel(Path(PARENT) / name, value)
                elif action == 'unreadable-cpu':
                    os.chmod(Path(PARENT) / 'cpu.max', 0)
                elif action == 'migrate-process':
                    write_kernel(outer_path / 'cgroup.procs', str(actual_pid));actual_identity(identity, outer)
                else:
                    raise ValueError('unknown physical action')
                after = unchanged_authority()
                if action in MUTATIONS:
                    name, value = MUTATIONS[action];require(after['limits'][name] == value, 'exact actual mutation readback')
                if action == 'unreadable-cpu':require(after['cpu_file_mode'] == 0, 'actual unreadable quota file')
                applied = {'case': spec['case'], 'action': action, 'actual_mutation_applied': True,
                           'before': current, 'after': after, 'identity': identity,
                           'membership_before': group, 'membership_after': current_membership(actual_pid, identity['tid']),
                           'pidfd_pinned': True, 'process_wide_migration': action == 'migrate-process'}
                result['mutation'] = applied;files.put('mutation-applied.json', applied, args.uid, args.gid)
                wait_file('native-result-before-restore.json')
                actual_identity(identity, outer if action == 'migrate-process' else group)
                after_restore = restore()
                restored_record = {'case': spec['case'], 'actual_restored': True, 'parent': after_restore,
                                   'membership': current_membership(actual_pid, identity['tid']), 'pidfd_pinned': True}
                result['restoration'] = restored_record
                files.put('mutation-restored.json', restored_record, args.uid, args.gid)
            complete = wait_file('complete.json')
            require(complete['case'] == spec['case'] and complete['passed'] is True, 'actual complete native result')
            remaining = deadline - time.monotonic();require(remaining > 0, 'case deadline exhausted')
            result['native_exit_code'] = child.wait(timeout=remaining)
            require(result['native_exit_code'] == 0 and not live(), 'actual child and pinned process cleanly exited')
            after = unchanged_authority()
            require(after['limits'] == LIMITS and after['cpu_file_mode'] == before['cpu_file_mode']
                    and after['pids_current'] == 0, 'original empty parent after native reap')
            result.update(final_parent=after, passed=True)
    except BaseException as error:
        result.update(passed=False, error=f'{type(error).__name__}: {error}')
    finally:
        try:
            if changed and not restored:result['emergency_restore'] = restore()
            if child is not None and child.poll() is None:
                # Ownership comes from our created service and pinned process,
                # never from a caller's report or a newly looked-up numeric PID.
                stop = subprocess.run(['systemctl', 'stop', unit], capture_output=True, text=True, timeout=10)
                result['cleanup_stop'] = {'exit_code': stop.returncode, 'stdout': stop.stdout, 'stderr': stop.stderr}
                if live():signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                child.wait(timeout=5)
            after = unchanged_authority();result['cleanup_parent'] = after
            require(after['limits'] == LIMITS and after['cpu_file_mode'] == before['cpu_file_mode']
                    and after['pids_current'] == 0, 'owned physical fixture cleanup must close')
        except BaseException as error:
            result.update(passed=False, cleanup_error=f'{type(error).__name__}: {error}')
        if pidfd is not None:os.close(pidfd)
        result['elapsed_seconds'] = time.monotonic() - started
        result['passed'] = result['passed'] and result['elapsed_seconds'] <= CASE_SECONDS
        files.put('guardian.json', result, args.uid, args.gid)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', required=True);parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--uid', type=int, required=True);parser.add_argument('--gid', type=int, required=True)
    result = run(parser.parse_args());print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    def cancelled(signum, _frame):
        raise InterruptedError(f'physical guardian signalled {signum}')
    signal.signal(signal.SIGTERM, cancelled)
    raise SystemExit(main())
