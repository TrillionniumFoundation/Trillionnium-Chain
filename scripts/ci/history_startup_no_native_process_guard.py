#!/usr/bin/env python3
"""Observe a real FIRST Startup in an exclusively prepared empty container.

Preparation precedes the outside signed Startup. The guardian holds the dedicated
parent/child descriptors and lease flock through actual pidfd/SIGKILL/wait4. This
does not classify an arbitrary missing database or repair partial initialization.
"""
from __future__ import annotations
import argparse
from decimal import Decimal, ROUND_HALF_EVEN
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

from history_effect_v6_process_guard import (
    SELECTOR, stable_parent_observation, stop_owned_group, write,
)
from history_native_process_guard import identity, owned_child_proc_path, sha

NATIVE = 'native'
LEASE = 'startup-namespace.lock'
SOURCE_ENV = 'TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT'


def strict(raw: bytes):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def stamp(value):
    return dict(device=value.st_dev, inode=value.st_ino, mode=value.st_mode,
                uid=value.st_uid, gid=value.st_gid, links=value.st_nlink, bytes=value.st_size,
                modified_seconds=value.st_mtime_ns // 1_000_000_000,
                modified_nanoseconds=value.st_mtime_ns % 1_000_000_000,
                changed_seconds=value.st_ctime_ns // 1_000_000_000,
                changed_nanoseconds=value.st_ctime_ns % 1_000_000_000)


def descriptor_path(fd):
    return Path(f'/proc/self/fd/{fd}')


def visible(fd, path):
    held, named = os.fstat(fd), os.lstat(path)
    assert not stat.S_ISLNK(named.st_mode) and stamp(held) == stamp(named)
    return stamp(held)


def snapshot(parent, native, lease, path, uid):
    parent_id = visible(parent, path)
    native_id = visible(native, descriptor_path(parent) / NATIVE)
    lease_id = visible(lease, descriptor_path(parent) / LEASE)
    for value, kind, links in [(parent_id, stat.S_IFDIR, 3),
                               (native_id, stat.S_IFDIR, 2), (lease_id, stat.S_IFREG, 1)]:
        assert stat.S_IFMT(value['mode']) == kind and value['uid'] == uid
        assert value['mode'] & 0o7777 == (0o700 if kind == stat.S_IFDIR else 0o600)
        assert value['links'] == links
    parent_names = sorted(os.listdir(parent))
    native_names = sorted(os.listdir(native))
    assert parent_names == [NATIVE, LEASE] and native_names == []
    assert 0 < lease_id['bytes'] <= 4096
    raw = os.pread(lease, 4097, 0)
    assert len(raw) == lease_id['bytes']
    return dict(parent=parent_id, native=native_id, lease=lease_id,
                parent_entries=parent_names, native_entries=native_names,
                lease_sha256=hashlib.sha256(raw).hexdigest())


def prepare(path, uid, identity_sha256, configuration_sha256, journal_path):
    # mkdir and O_EXCL are the creation facts. Existing paths are never adopted,
    # truncated, removed, chmod'ed, or reinterpreted as a fresh reservation.
    os.mkdir(path, 0o700)
    parent = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    lease = native = None
    try:
        lease = os.open(LEASE, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                        | os.O_CLOEXEC, 0o600, dir_fd=parent)
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        record = dict(schema='actual-history-first-startup-namespace-lease-v1',
                      namespace_parent=str(path), identity_sha256=identity_sha256,
                      journal_path=str(journal_path),
                      preparation_sha256=configuration_sha256, reservation_id=os.urandom(32).hex())
        raw = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
        with os.fdopen(os.dup(lease), 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.mkdir(NATIVE, 0o700, dir_fd=parent)
        native = os.open(NATIVE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent)
        os.fsync(native)
        os.fsync(parent)
        outer = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(outer)
        finally:
            os.close(outer)
        observed = snapshot(parent, native, lease, path, uid)
        return parent, native, lease, observed
    except BaseException:
        for fd in [native, lease, parent]:
            if fd is not None:
                os.close(fd)
        raise


def transcript(path, identity_sha256, signed_startup):
    previous = '00' * 32
    sequence = 0
    intent = None
    settlement = None
    names = sorted(p.name for p in path.iterdir() if p.name != 'owner.lock')
    assert 2 < len(names) <= 4096
    for name in names:
        raw = (path / name).read_bytes()
        assert 0 < len(raw) <= 2 * 1024 ** 2
        digest = hashlib.sha256(raw).hexdigest()
        frame = strict(raw)
        sequence += 1
        assert name == f'{sequence:020d}-{digest}.json'
        assert frame['schema'] == 'restricted-history-effect-record-v6'
        assert frame['sequence'] == sequence and frame['previous'] == previous
        assert frame['identity_sha256'] == identity_sha256
        event = frame['event']
        if event['kind'] == 'budget':
            assert intent is None and settlement is None
        elif event['kind'] == 'intent':
            assert intent is None and settlement is None
            assert bytes(event['signed']) == signed_startup
            intent = frame
        elif event['kind'] == 'settlement':
            assert intent is not None and settlement is None
            settlement = frame
        else:
            raise ValueError('not a sole first Startup with one original known settlement')
        previous = digest
    assert intent is not None and settlement is not None and settlement['sequence'] == sequence
    op = strict(signed_startup)['body']
    event = settlement['event']
    assert op['purpose'] == 'startup' and event['operation'] == op['operation_id']
    assert event['marker'] is None and event['native_id'] is None
    assert isinstance(event['native_error'], str) and event['native_error']
    assert event['effect_readback_known'] is True
    cpu = event['cpu']
    assert cpu['accounting_unavailable'] is False and cpu['live_refused'] is False
    assert cpu['total_cpu_ns'] == cpu['owner_cpu_ns'] and cpu['scoped_worker_cpu_ns'] == 0
    assert cpu['live_paid_cpu_ns'] + cpu['residual_cpu_ns'] == cpu['total_cpu_ns']
    assert 0 < cpu['total_cpu_ns'] <= op['allowance']['cpu_ns']
    for field in ['spawned_workers', 'started_workers', 'finished_workers', 'known_workers']:
        assert cpu[field] == 0
    body_raw = json.dumps(op, separators=(',', ':'), ensure_ascii=False).encode()
    intent_sha256 = hashlib.sha256(b'TRNM-HISTORY-EFFECT-RECOVERY-V6' + b'I\0'
                                  + len(body_raw).to_bytes(4, 'little') + body_raw).hexdigest()
    return dict(anchor=dict(sequence=sequence, digest=previous), intent_at_ns=intent['at_ns'],
                intent_sha256=intent_sha256, original_cpu=cpu, original_operation=op)


def wait_file(path, deadline, child=None):
    while not path.exists():
        if child is not None and child.poll() is not None:
            raise RuntimeError('owned native child exited before its actual barrier')
        if time.monotonic() >= deadline:
            raise TimeoutError('bounded first Startup preparation/barrier expired')
        time.sleep(0.01)
    return strict(path.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--configuration', type=Path, required=True)
    parser.add_argument('--configuration-sha256', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    assert args.binary.is_absolute() and args.configuration.is_absolute()
    assert sha(args.binary) == args.binary_sha256
    assert sha(args.configuration) == args.configuration_sha256
    config = strict(args.configuration.read_bytes())
    assert config['schema'] == 'actual-history-startup-no-native-preparation-v1'
    pins = dict(config['source_pins'], preparation_sha256=args.configuration_sha256)
    assert pins['source_commit'] == os.environ[SOURCE_ENV]
    assert pins['executable_sha256'] == args.binary_sha256
    assert pins['guardian_sha256'] == sha(Path(__file__).resolve())
    assert pins['observer_sha256'] == sha(Path(__file__).with_name('history_effect_v6_process_guard.py'))
    assert pins['process_guard_sha256'] == sha(Path(__file__).with_name('history_native_process_guard.py'))
    parent_path = Path(config['namespace_parent'])
    journal = Path(config['journal_path'])
    assert parent_path.is_absolute() and journal.is_absolute() and args.directory.is_absolute()
    assert not journal.is_relative_to(parent_path) and not args.directory.is_relative_to(parent_path)
    assert config['expected_uid'] == os.geteuid()
    parent = native = lease = pidfd = child = None
    reaped = False
    record = dict(schema='actual-history-startup-no-native-guardian-v1', passed=False,
                  configuration_sha256=args.configuration_sha256, pins=pins,
                  physical_power_loss_qualified=False, historical_process_tree_observed=False)
    try:
        parent, native, lease, before = prepare(parent_path, os.geteuid(),
                                              config['identity_sha256'], args.configuration_sha256,
                                              journal)
        prepared_ns = time.time_ns()
        write(args.directory / 'namespace-ready.json', dict(before=before,
              namespace_prepared_ns=prepared_ns, namespace_parent=str(parent_path)))
        launch = wait_file(args.directory / 'outside-child.json', time.monotonic() + 50)
        child_path = Path(launch['path'])
        assert sha(child_path) == launch['sha256']
        child_config = strict(child_path.read_bytes())
        assert child_config['mode'] == 'startup-no-native'
        assert child_config['store'] == str(parent_path / NATIVE)
        assert child_config['control'] == str(args.directory)
        startup_path = Path(child_config['launch'])
        assert sha(startup_path) == child_config['launch_sha256']
        startup_config = strict(startup_path.read_bytes())
        assert startup_config['identity'] == config['identity']
        assert startup_config['journal_path'] == str(journal)
        signed_startup = bytes(startup_config['signed_startup'])
        op = strict(signed_startup)['body']
        assert op['identity']['source_commit'] == pins['source_commit']
        assert prepared_ns <= op['issued_ns']
        assert snapshot(parent, native, lease, parent_path, os.geteuid()) == before
        env = os.environ.copy()
        env.update(TRNM_HISTORY_V6_CHILD_CONFIG=str(child_path),
                   TRNM_HISTORY_V6_CHILD_CONFIG_SHA256=launch['sha256'])
        spawn_before = time.time_ns()
        with (args.directory / 'killed-native-process.log').open('xb') as output:
            child = subprocess.Popen([str(args.binary), SELECTOR, '--exact', '--ignored',
                                      '--test-threads=1', '--nocapture'], env=env,
                                     stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        pidfd = os.pidfd_open(child.pid, 0)
        deadline = time.monotonic() + 80
        barrier = wait_file(args.directory / 'crash-ready.json', deadline, child)
        assert barrier['schema'] == 'actual-history-first-startup-known-failure-barrier-v1'
        assert barrier['pid'] == child.pid and barrier['actual_compiled_source'] == pins['source_commit']
        assert barrier['fixture_sha256'] == pins['fixture_sha256']
        original = transcript(journal, config['identity_sha256'], signed_startup)
        assert original['anchor'] == barrier['anchor']
        assert original['intent_sha256'] == barrier['intent_sha256']
        proc, pinned, threads = stop_owned_group(child, pidfd, args.binary_sha256, deadline, record)
        descendants = stable_parent_observation(proc, pinned, deadline, record)
        assert identity(proc) == pinned and owned_child_proc_path(child.pid, pidfd) == (proc, pinned)
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        pid, status, usage = os.wait4(child.pid, 0)
        reaped = True
        child.returncode = os.waitstatus_to_exitcode(status)
        reaped_ns = time.time_ns()
        assert pid == child.pid and os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
        fdinfo = dict(line.split(':', 1) for line in Path(f'/proc/self/fdinfo/{pidfd}').read_text().splitlines())
        assert int(fdinfo['Pid'].strip()) == -1
        assert transcript(journal, config['identity_sha256'], signed_startup) == original
        after = snapshot(parent, native, lease, parent_path, os.geteuid())
        assert after == before
        def micros(raw):
            value = Decimal(raw) * 1_000_000
            integer = value.to_integral_value(rounding=ROUND_HALF_EVEN)
            assert abs(value - integer) <= Decimal('0.001')
            return int(integer)
        raw_user, raw_system = str(usage.ru_utime), str(usage.ru_stime)
        user, system = micros(raw_user), micros(raw_system)
        upper = (user + system + 2) * 1000
        assert original['original_cpu']['total_cpu_ns'] <= upper
        closed = dict(schema='actual-history-startup-no-native-closed-process-v1', pins=pins,
                      namespace_parent=str(parent_path), journal_path=str(journal),
                      expected_uid=os.geteuid(), before=before,
                      after=after, namespace_created_exclusively=True,
                      lease_held_from_preparation_through_reap=True, namespace_prepared_ns=prepared_ns,
                      signed_startup=list(signed_startup), startup_intent_at_ns=original['intent_at_ns'],
                      intent_sha256=original['intent_sha256'], original_journal=original['anchor'],
                      child_configuration_sha256=launch['sha256'],
                      startup_configuration_sha256=child_config['launch_sha256'],
                      process_spawn_before_ns=spawn_before, process_reaped_after_ns=reaped_ns,
                      owned_namespace_pid=child.pid, observed_visible_pid=pinned['visible_pid'],
                      observed_starttime_ticks=pinned['starttime_ticks'], pidfd_identity_verified=True,
                      actual_wait4=True, signal=9, all_descendants_closed=True, descendants=descendants,
                      descendant_accounting_profile='source-bound-first-startup-empty-namespace-thread-only-v1',
                      fixture_selector=SELECTOR, historical_process_tree_observed=False,
                      cpu_counter_profile='linux-wait4-timeval-quantized-v1',
                      user_cpu_microseconds=user, system_cpu_microseconds=system,
                      reported_user_seconds=raw_user, reported_system_seconds=raw_system,
                      reported_cpu_upper_bound_ns=upper, physical_cost_qualified=False)
        write(args.directory / 'closed-process.json', closed)
        record.update(passed=True, actual_wait4=True, wait_status=status, closed_process=closed,
                      closed_process_sha256=sha(args.directory / 'closed-process.json'),
                      original_journal_transcript=original, threads_before_kill=threads,
                      exact_empty_namespace_unchanged=True)
    except BaseException as error:
        record['error'] = f'{type(error).__name__}: {error}'
        if child is not None and child.returncode is not None:
            reaped = True
        if child is not None and not reaped:
            try:
                if pidfd is not None:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                else:
                    # The unreaped direct Popen child still owns this namespace
                    # PID. No /proc observation or unrelated PID is signalled.
                    os.kill(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            pid, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
            record['cleanup_wait4'] = dict(pid=pid, status=status, user_seconds=str(usage.ru_utime),
                                          system_seconds=str(usage.ru_stime))
    finally:
        for fd in [pidfd, native, lease, parent]:
            if fd is not None:
                os.close(fd)
    write(args.directory / 'guardian-result.json', record)
    print(json.dumps(record, sort_keys=True))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
