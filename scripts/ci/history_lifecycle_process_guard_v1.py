#!/usr/bin/env python3
"""Observe actual owned Startup/Close death; never invent a Native frontier.

The new record distinguishes absent/empty SQLite from an observed committed
frontier.  It uses the original source-bound thread-only process observation
profile and does not qualify arbitrary descendants or physical power loss.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
from decimal import Decimal, ROUND_HALF_EVEN
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import time

from history_startup_no_native_process_guard import (
    NATIVE, LEASE, snapshot as empty_snapshot, strict,
)

from history_effect_v6_process_guard import (
    DESCENDANT_PROFILE, SELECTOR, identity, owned_child_proc_path, sha,
    stable_parent_observation, stop_owned_group, write,
)


def actual_snapshot(store: Path) -> dict:
    """Read a dead owner's committed view; absence never becomes genesis."""
    initializing = store / 'initializing.json'
    marker = sha(initializing) if initializing.exists() else None
    database = store / 'native.sqlite'
    if not database.exists():
        return {'database': 'absent', 'actual_frontier': None,
                'initializing_sha256': marker}
    with sqlite3.connect(f'file:{database}?mode=ro', uri=True) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        names = [r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        if not names:
            assert marker is not None
            return {'database': 'empty', 'actual_frontier': None,
                    'initializing_sha256': marker}
        tip, root, generation = db.execute(
            'SELECT hex(a.tip),hex(b.state_root),a.generation FROM active a '
            'JOIN blocks b ON b.id=a.tip WHERE a.singleton=1').fetchone()
        assert db.execute('SELECT COUNT(*) FROM reorg WHERE done!=1').fetchone()[0] == 0
        return {'database': 'genesis' if marker else 'ready',
                'actual_frontier': {'block': tip.lower(), 'root': root.lower(),
                                    'generation': generation},
                'initializing_sha256': marker}



def prepare_birth(path, uid, identity_sha256, preparation_sha256, journal):
    # Same exclusive mkdir/O_EXCL/fsync contract as the retained first-Startup
    # prepare helper, with a timestamp immediately after the actual flock.
    os.mkdir(path, 0o700)
    parent = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    lease = native = None
    try:
        lease = os.open(LEASE, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                        | os.O_CLOEXEC, 0o600, dir_fd=parent)
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        acquired_ns = time.time_ns()
        record = dict(schema='actual-history-first-startup-namespace-lease-v1',
                      namespace_parent=str(path), identity_sha256=identity_sha256,
                      journal_path=str(journal), preparation_sha256=preparation_sha256,
                      reservation_id=os.urandom(32).hex())
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
        birth = empty_snapshot(parent, native, lease, path, uid)
        return parent, native, lease, birth, time.time_ns(), acquired_ns
    except BaseException:
        for fd in (native, lease, parent):
            if fd is not None:
                os.close(fd)
        raise


def begin_birth(args, config):
    parent_path = Path(config['namespace_parent'])
    journal = Path(config['journal_path'])
    assert parent_path.is_absolute() and journal.is_absolute()
    assert not journal.is_relative_to(parent_path) and not args.directory.is_relative_to(parent_path)
    assert config['expected_uid'] == os.geteuid()
    pins = dict(config['source_pins'])
    assert pins['source_commit'] == os.environ['TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT']
    assert pins['executable_sha256'] == args.binary_sha256
    assert pins['guardian_sha256'] == sha(Path(__file__).resolve())
    assert pins['observer_sha256'] == sha(Path(__file__).with_name('history_effect_v6_process_guard.py'))
    assert pins['process_guard_sha256'] == sha(Path(__file__).with_name('history_native_process_guard.py'))
    prior = config['previous_proof']
    if prior is None:
        pins['preparation_sha256'] = args.configuration_sha256
        parent, native, lease, birth, prepared_ns, acquired_ns = prepare_birth(
            parent_path, os.geteuid(), config['identity_sha256'], pins['preparation_sha256'], journal)
    else:
        # Reacquire the same witnessed birth. No mkdir, truncation, deletion or
        # adoption of a different path is allowed for a repeated failed Startup.
        pins['preparation_sha256'] = prior['pins']['preparation_sha256']
        assert pins == prior['pins']
        assert prior['namespace_created_exclusively'] is True
        assert prior['namespace_parent'] == str(parent_path) and prior['journal_path'] == str(journal)
        assert prior['expected_uid'] == os.geteuid()
        assert prior['birth'] == prior['before'] == prior['after']
        birth, prepared_ns = prior['birth'], prior['namespace_prepared_ns']
        parent = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        lease = native = None
        try:
            lease = os.open(LEASE, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired_ns = time.time_ns()
            native = os.open(NATIVE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
            assert empty_snapshot(parent, native, lease, parent_path, os.geteuid()) == birth
            lease_body = strict(os.pread(lease, 4097, 0))
            assert lease_body['schema'] == 'actual-history-first-startup-namespace-lease-v1'
            assert lease_body['identity_sha256'] == config['identity_sha256']
            assert lease_body['namespace_parent'] == str(parent_path)
            assert lease_body['journal_path'] == str(journal)
            assert lease_body['preparation_sha256'] == pins['preparation_sha256']
        except BaseException:
            for fd in (native, lease, parent):
                if fd is not None:
                    os.close(fd)
            raise
    return dict(parent=parent, native=native, lease=lease, path=parent_path,
                journal=journal, pins=pins, birth=birth, before=birth,
                prepared_ns=prepared_ns, acquired_ns=acquired_ns,
                new_namespace_created=prior is None, identity=config['identity'],
                identity_sha256=config['identity_sha256'])


def startup_transcript(path, identity_sha256, signed_startup, closure):
    previous, sequence, intent, settlement = '00' * 32, 0, None, None
    names = sorted(p.name for p in path.iterdir() if p.name != 'owner.lock')
    assert 1 < len(names) <= 4096
    for name in names:
        raw = (path / name).read_bytes()
        assert 0 < len(raw) <= 2 * 1024 ** 2
        digest = hashlib.sha256(raw).hexdigest()
        frame = strict(raw)
        sequence += 1
        assert name == f'{sequence:020d}-{digest}.json'
        assert frame['sequence'] == sequence and frame['previous'] == previous
        assert frame['identity_sha256'] == identity_sha256
        event = frame['event']
        if event['kind'] == 'intent' and bytes(event['signed']) == signed_startup:
            assert intent is None
            intent = frame
        elif intent is not None:
            assert event['kind'] == 'settlement' and settlement is None
            settlement = frame
        previous = digest
    assert intent is not None
    operation = strict(signed_startup)['body']
    assert operation['purpose'] == 'startup'
    if closure == 'pending-startup':
        assert settlement is None and intent['sequence'] == sequence
    else:
        assert closure == 'settled-startup' and settlement is not None
        event = settlement['event']
        assert event['operation'] == operation['operation_id']
        assert event['native_id'] is None and event['marker'] is None
        assert event['native_error'] == 'HISTORY_V6_CANCELLED' and event['effect_readback_known'] is True
        cpu = event['cpu']
        assert cpu['accounting_unavailable'] is False and cpu['live_refused'] is False
        assert cpu['total_cpu_ns'] == cpu['owner_cpu_ns'] and cpu['scoped_worker_cpu_ns'] == 0
        assert 0 < cpu['total_cpu_ns'] <= operation['allowance']['cpu_ns']
        for field in ('spawned_workers', 'started_workers', 'finished_workers', 'known_workers'):
            assert cpu[field] == 0
    body_raw = json.dumps(operation, separators=(',', ':'), ensure_ascii=False).encode()
    digest = hashlib.sha256(b'TRNM-HISTORY-EFFECT-RECOVERY-V6' + b'I\0'
                            + len(body_raw).to_bytes(4, 'little') + body_raw).hexdigest()
    return dict(anchor=dict(sequence=sequence, digest=previous), intent_at_ns=intent['at_ns'],
                intent_sha256=digest, signed_startup=list(signed_startup))

def main() -> None:
    parser = argparse.ArgumentParser()
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
    birth_config = config if config.get('schema') == 'actual-history-lifecycle-no-native-preparation-v1' else None
    modes = {
        'lifecycle-init-intent', 'lifecycle-init-before-commit',
        'lifecycle-init-committed', 'lifecycle-init-published',
        'lifecycle-startup-settled-cancel', 'lifecycle-startup-pending-ready',
        'lifecycle-close-pending', 'lifecycle-close-wrong-frontier',
        'lifecycle-no-native-waiting-credit', 'lifecycle-no-native-before-node',
        'lifecycle-no-native-settled-cancel',
        *(f'lifecycle-publish-{stage}' for stage in
          ('file-synced', 'linked', 'final-synced', 'unlinked', 'published')),
    }
    mode = config['cutpoint'] if birth_config is not None else config['mode']
    assert mode in modes and args.directory.is_dir()
    administrative = mode.startswith('lifecycle-publish-')
    record = {'schema': 'actual-history-lifecycle-guardian-v1', 'passed': False,
              'configuration_sha256': args.configuration_sha256,
              'binary_sha256': args.binary_sha256, 'cutpoint': mode,
              'fixture_selector': SELECTOR, 'descendant_accounting_profile': DESCENDANT_PROFILE,
              'historical_process_tree_observed': False, 'physical_power_loss_qualified': False}
    env = os.environ.copy()
    child_path, child_sha = args.configuration, args.configuration_sha256
    child, pidfd, reaped, birth = None, None, False, None
    try:
        if birth_config is not None:
            birth = begin_birth(args, birth_config)
            write(args.directory / 'namespace-ready.json', dict(
                birth=birth['birth'], before=birth['before'], pins=birth['pins'],
                namespace_prepared_ns=birth['prepared_ns'], lease_acquired_ns=birth['acquired_ns'],
                new_namespace_created=birth['new_namespace_created']))
            launch_path = args.directory / 'outside-child.json'
            end = time.monotonic() + 50
            while not launch_path.exists():
                if time.monotonic() >= end:
                    raise TimeoutError('outside signed Startup did not arrive after actual lease')
                time.sleep(0.01)
            launch = strict(launch_path.read_bytes())
            child_path, child_sha = Path(launch['path']), launch['sha256']
            assert child_path.is_absolute() and sha(child_path) == child_sha
            config = strict(child_path.read_bytes())
            assert config['mode'] == mode and config['store'] == str(birth['path'] / NATIVE)
            assert config['control'] == str(args.directory)
            startup_path = Path(config['launch'])
            assert sha(startup_path) == config['launch_sha256']
            startup_config = strict(startup_path.read_bytes())
            assert startup_config['identity'] == birth['identity']
            assert startup_config['journal_path'] == str(birth['journal'])
            signed_startup = bytes(startup_config['signed_startup'])
            operation = strict(signed_startup)['body']
            assert birth['prepared_ns'] <= operation['issued_ns']
            assert empty_snapshot(birth['parent'], birth['native'], birth['lease'],
                                  birth['path'], os.geteuid()) == birth['birth']
        env.update(TRNM_HISTORY_V6_CHILD_CONFIG=str(child_path),
                   TRNM_HISTORY_V6_CHILD_CONFIG_SHA256=child_sha)
        spawn_before_ns = time.time_ns()
        with (args.directory / 'killed-native-process.log').open('xb') as log:
            child = subprocess.Popen([str(args.binary), SELECTOR, '--exact', '--ignored',
                                      '--test-threads=1', '--nocapture'], env=env,
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            pidfd = os.pidfd_open(child.pid, 0)
            deadline = time.monotonic() + 80
            ready = args.directory / 'crash-ready.json'
            while not ready.exists():
                pid, wait_status, usage = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    reaped = True
                    child.returncode = os.waitstatus_to_exitcode(wait_status)
                    record.update(early_status=wait_status, early_user_seconds=str(usage.ru_utime),
                                  early_system_seconds=str(usage.ru_stime))
                    raise RuntimeError('Native lifecycle child exited before selected barrier')
                if time.monotonic() >= deadline:
                    raise TimeoutError('Native lifecycle barrier exceeded 80 seconds')
                time.sleep(0.01)
            barrier = json.loads(ready.read_bytes())
            assert barrier['pid'] == child.pid and barrier['cutpoint'] == mode
            assert barrier['schema'] == 'actual-history-lifecycle-barrier-v1'
            if birth is not None:
                assert barrier['actual_compiled_source'] == birth['pins']['source_commit']
                assert barrier['fixture_sha256'] == birth['pins']['fixture_sha256']
            if administrative:
                assert barrier['native_operation_started'] is False
                assert barrier['cpu_epoch_created'] is False
            else:
                assert barrier['closure'] in ('pending-startup', 'pending-close', 'settled-startup')
                assert barrier['operation_id'] and barrier['intent_sha256']
            proc, pinned, threads = stop_owned_group(child, pidfd, args.binary_sha256, deadline, record)
            descendants = stable_parent_observation(proc, pinned, deadline, record)
            assert identity(proc) == pinned
            assert owned_child_proc_path(child.pid, pidfd) == (proc, pinned)
            os.kill(child.pid, signal.SIGKILL)
            pid, wait_status, usage = os.wait4(child.pid, 0)
            reaped = True
            child.returncode = os.waitstatus_to_exitcode(wait_status)
            reaped_after_ns = time.time_ns()
            assert pid == child.pid and os.WIFSIGNALED(wait_status)
            assert os.WTERMSIG(wait_status) == signal.SIGKILL
            fdinfo = dict(line.split(':', 1) for line in
                          Path(f'/proc/self/fdinfo/{pidfd}').read_text().splitlines())
            assert int(fdinfo['Pid'].strip()) == -1
            raw_user, raw_system = str(usage.ru_utime), str(usage.ru_stime)

            def micros(raw: str) -> int:
                value = Decimal(raw) * 1_000_000
                rounded = value.to_integral_value(rounding=ROUND_HALF_EVEN)
                assert abs(value - rounded) <= Decimal('0.001')
                return int(rounded)

            user, system = micros(raw_user), micros(raw_system)
            record.update(owned_child_pid=child.pid, child_identity=pinned,
                          actual_wait4=True, wait_status=wait_status, threads_before_kill=threads,
                          descendants_before_kill=descendants, barrier_sha256=sha(ready),
                          reported_user_seconds=raw_user, reported_system_seconds=raw_system,
                          reported_cpu_upper_bound_ns=(user + system + 2) * 1000)
            if administrative:
                record.update(new_cpu_epoch_created=False, closed_process_receipt_created=False)
            else:
                snapshot = actual_snapshot(Path(config['store']))
                if snapshot['database'] in ('absent', 'empty'):
                    assert snapshot['actual_frontier'] is None
                else:
                    with sqlite3.connect(f"file:{Path(config['store']) / 'native.sqlite'}?mode=ro", uri=True) as db:
                        db.execute('PRAGMA query_only=ON')
                        marker = db.execute('SELECT marker FROM history_effect_v6 WHERE operation=?',
                                            (barrier['operation_id'],)).fetchone()
                        assert marker is None
                closed = {'schema': 'actual-history-lifecycle-closed-process-v1',
                          'epoch': barrier['epoch'], 'executable_sha256': args.binary_sha256,
                          'intent_sha256': barrier['intent_sha256'], 'original_journal': barrier['anchor'],
                          'owned_namespace_pid': child.pid, 'observed_visible_pid': pinned['visible_pid'],
                          'observed_starttime_ticks': pinned['starttime_ticks'],
                          'pidfd_identity_verified': True, 'actual_wait4': True, 'signal': signal.SIGKILL,
                          'all_descendants_closed': True, 'descendants': [],
                          'descendant_accounting_profile': DESCENDANT_PROFILE, 'fixture_selector': SELECTOR,
                          'historical_process_tree_observed': False,
                          'cpu_counter_profile': 'linux-wait4-timeval-quantized-v1',
                          'reported_user_seconds': raw_user, 'reported_system_seconds': raw_system,
                          'user_cpu_microseconds': user, 'system_cpu_microseconds': system,
                          'reported_cpu_upper_bound_ns': (user + system + 2) * 1000, 'marker': None,
                          'declared_frontier': barrier['declared_frontier'], **snapshot,
                           'no_native': None, 'physical_cost_qualified': False}
                if birth is not None:
                    assert snapshot == {'database': 'absent', 'actual_frontier': None,
                                        'initializing_sha256': None}
                    transcript = startup_transcript(birth['journal'], birth['identity_sha256'],
                                                    signed_startup, barrier['closure'])
                    assert transcript['anchor'] == barrier['anchor']
                    assert transcript['intent_sha256'] == barrier['intent_sha256']
                    after = empty_snapshot(birth['parent'], birth['native'], birth['lease'],
                                           birth['path'], os.geteuid())
                    assert after == birth['before'] == birth['birth']
                    closed['no_native'] = dict(
                        schema='actual-history-lifecycle-no-native-proof-v1', pins=birth['pins'],
                        namespace_parent=str(birth['path']), journal_path=str(birth['journal']),
                        expected_uid=os.geteuid(), birth=birth['birth'], before=birth['before'], after=after,
                        namespace_created_exclusively=True, namespace_prepared_ns=birth['prepared_ns'],
                        lease_acquired_ns=birth['acquired_ns'], lease_held_from_process_spawn_through_reap=True,
                        signed_startup=list(signed_startup), startup_intent_at_ns=transcript['intent_at_ns'],
                        child_configuration_sha256=child_sha, startup_configuration_sha256=config['launch_sha256'],
                        process_spawn_before_ns=spawn_before_ns, process_reaped_after_ns=reaped_after_ns)
                    record.update(exact_empty_namespace_unchanged=True,
                                  new_namespace_created=birth['new_namespace_created'],
                                  same_namespace_reacquired=not birth['new_namespace_created'],
                                  original_journal_transcript=transcript)
                write(args.directory / 'closed-process.json', closed)
                record.update(closed_process=closed, closed_process_sha256=sha(args.directory / 'closed-process.json'),
                              observed_native_snapshot=snapshot, clean_close_created=False,
                              absent_frontier_fabricated=False)
            record['passed'] = True
    except BaseException as error:
        record.update(error_type=type(error).__name__, error=str(error))
        raise
    finally:
        if child is not None and not reaped:
            try:
                os.kill(child.pid, signal.SIGKILL)
                _, wait_status, _ = os.wait4(child.pid, 0)
                child.returncode = os.waitstatus_to_exitcode(wait_status)
            except ProcessLookupError:
                pass
        if pidfd is not None:
            os.close(pidfd)
        if birth is not None:
            for fd in (birth['native'], birth['lease'], birth['parent']):
                os.close(fd)
        write(args.directory / 'guardian-result.json', record)


if __name__ == '__main__':
    main()
