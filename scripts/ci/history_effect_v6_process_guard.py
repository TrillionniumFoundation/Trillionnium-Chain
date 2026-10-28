#!/usr/bin/env python3
"""Real owned-child SIGKILL/wait4 at V6 native and publication cutpoints.

The observer creates no recovery signature or budget. Test authorities separately
sign these exact raw observations. No physical-power-loss qualification.
This closed-process profile applies only to the source/binary-bound native
thread-only helper. Current parent graphs cannot prove that arbitrary earlier
descendants never became orphans or reparented; subprocess accounting is absent.
"""
from __future__ import annotations
import argparse
from decimal import Decimal, ROUND_HALF_EVEN
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import time

from history_native_process_guard import identity, owned_child_proc_path, sha, status

SELECTOR = 'store::history_effect_v6::tests::history_effect_v6_process_child_helper'
DESCENDANT_PROFILE = 'source-bound-native-thread-only-fixture-v1'


def stop_owned_group(child: subprocess.Popen, pidfd: int, executable_sha256: str,
                     deadline: float, record: dict) -> tuple[Path, dict, list[int]]:
    """Stop only the pidfd-pinned direct child TG leader; stop is not closure."""
    proc, pinned = owned_child_proc_path(child.pid, pidfd)
    observed = status(proc)
    assert int(observed['Tgid']) == int(observed['Pid']) == pinned['visible_pid']
    assert sha(proc / 'exe') == executable_sha256
    assert identity(proc) == pinned
    signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
    stop_deadline = min(deadline, time.monotonic() + 5)
    while True:
        pid, wait_status, usage = os.wait4(child.pid, os.WNOHANG | os.WUNTRACED)
        if pid:
            assert pid == child.pid
            if not os.WIFSTOPPED(wait_status):
                child.returncode = os.waitstatus_to_exitcode(wait_status)
                record['unexpected_terminal_before_stop'] = wait_status
                raise RuntimeError('owned child terminated instead of stopping')
            assert os.WSTOPSIG(wait_status) == signal.SIGSTOP
            break
        if time.monotonic() >= stop_deadline:
            raise TimeoutError('owned group did not report stopped within the original deadline')
        time.sleep(0.01)
    assert owned_child_proc_path(child.pid, pidfd) == (proc, pinned)
    threads = []
    for task in (proc / 'task').iterdir():
        assert task.name.isdigit() and len(threads) < 256
        row = status(task)
        assert int(row['Tgid']) == pinned['visible_pid']
        assert int(row['Pid']) == int(task.name) and row['State'].split()[0] == 'T'
        threads.append(int(task.name))
    threads.sort()
    assert threads and pinned['visible_pid'] in threads
    record['stopped_group'] = {
        'pidfd_signal': int(signal.SIGSTOP), 'actual_wait4_stopped': True,
        'wait_status': wait_status, 'all_observed_threads_stopped': threads,
        'stop_is_not_termination': True, 'closed_cpu_claim_created': False,
        'reported_user_seconds_at_stop': str(usage.ru_utime),
        'reported_system_seconds_at_stop': str(usage.ru_stime),
    }
    return proc, pinned, threads


def complete_parent_graph(deadline: float) -> dict[int, int]:
    """Every enumerated public status must be read; never skip a missing PID."""
    parents = {}
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        if time.monotonic() >= deadline or len(parents) >= 4096:
            raise RuntimeError('bounded complete parent snapshot unavailable')
        row = status(proc)
        assert int(row['Pid']) == int(proc.name)
        parents[int(row['Pid'])] = int(row['PPid'])
    return parents


def descendants_of(parents: dict[int, int], visible_pid: int) -> list[int]:
    assert visible_pid in parents
    found = []
    frontier = [visible_pid]
    seen = {visible_pid}
    while frontier:
        parent = frontier.pop()
        for pid, ppid in parents.items():
            if ppid == parent:
                assert pid not in seen, 'process parent graph is cyclic'
                seen.add(pid)
                found.append(pid)
                frontier.append(pid)
    return sorted(found)


def stable_parent_observation(proc: Path, pinned: dict, deadline: float,
                              record: dict, reader=complete_parent_graph) -> list[int]:
    """At most four entire observations; require two consecutive equal graphs.

    A disappearing unrelated /proc entry does not create an empty-child fact.
    That whole observation is recorded as incomplete and discarded. Only two
    fresh, fully read equal graphs can establish the stopped fixture's result.
    Any observed descendant is immediately UNKNOWN here; this pure native
    thread-only fixture has no subprocess owner/CPU/adoption contract.
    """
    observations = record.setdefault('complete_parent_observations', [])
    previous = None
    for attempt in range(1, 5):
        try:
            assert time.monotonic() < deadline
            assert identity(proc) == pinned
            assert status(proc)['State'].split()[0] == 'T'
            parents = reader(deadline)
            assert identity(proc) == pinned
            assert status(proc)['State'].split()[0] == 'T'
            descendants = descendants_of(parents, pinned['visible_pid'])
        except (FileNotFoundError, ProcessLookupError) as error:
            observations.append({'attempt': attempt, 'complete': False,
                                 'error': f'{type(error).__name__}: {error}'})
            previous = None
            continue
        except BaseException as error:
            observations.append({'attempt': attempt, 'complete': False,
                                 'error': f'{type(error).__name__}: {error}'})
            raise
        digest = hashlib.sha256(json.dumps(sorted(parents.items()),
                                          separators=(',', ':')).encode()).hexdigest()
        observations.append({'attempt': attempt, 'complete': True,
                             'process_count': len(parents), 'parent_graph_sha256': digest,
                             'descendants': descendants, 'matches_previous_complete': parents == previous})
        if descendants:
            record['unmanaged_descendants_unknown'] = descendants
            raise RuntimeError('unexpected process descendants have no closed CPU/adoption proof')
        if parents == previous:
            record['complete_matching_parent_snapshots'] = 2
            return descendants
        previous = parents
    raise RuntimeError('four complete-snapshot attempts did not establish a stable graph')


def write(path: Path, value: dict) -> None:
    # Readers use final-name visibility as their completion signal. A complete
    # wait4 record must never appear as an empty or partially written JSON file.
    pending = path.with_name(path.name + '.pending')
    with pending.open('x') as output:
        os.chmod(pending, 0o600)
        json.dump(value, output, sort_keys=True, separators=(',', ':'))
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    # Linking is atomic and cannot replace an earlier observation. Preserve the
    # pending evidence on failure instead of overwriting or hiding the conflict.
    os.link(pending, path, follow_symlinks=False)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
        pending.unlink()
        os.fsync(directory)
    finally:
        os.close(directory)


def main() -> int:
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
    config = json.loads(args.configuration.read_bytes())
    publication_modes = (
        'publication-intent-file-synced', 'publication-intent-linked',
        'publication-intent-final-synced', 'publication-intent-unlinked',
        'publication-intent-published',
    )
    repair_modes = ('publication-repair-linked', 'publication-repair-unlinked')
    assert config['mode'] in ('validation-worker', 'activation-committed', *publication_modes, *repair_modes)
    publication_cut = config['mode'] in publication_modes
    repair_cut = config['mode'] in repair_modes
    assert args.directory.is_dir()
    ready = args.directory / 'crash-ready.json'
    env = os.environ.copy()
    env.update(TRNM_HISTORY_V6_CHILD_CONFIG=str(args.configuration),
               TRNM_HISTORY_V6_CHILD_CONFIG_SHA256=args.configuration_sha256)
    record = {'schema': 'actual-history-effect-guardian-v6', 'passed': False,
              'configuration_sha256': args.configuration_sha256,
              'binary_sha256': args.binary_sha256, 'cutpoint': config['mode'],
              'descendant_accounting_profile': DESCENDANT_PROFILE,
              'fixture_selector': SELECTOR,
              'historical_process_tree_observed': False,
              'physical_power_loss_qualified': False, 'public_host_path_executed': False}
    child = None
    pidfd = None
    reaped = False
    started = time.monotonic_ns()
    try:
        with (args.directory / 'killed-native-process.log').open('xb') as log:
            child = subprocess.Popen([str(args.binary), SELECTOR, '--exact', '--ignored',
                                      '--test-threads=1', '--nocapture'], env=env,
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            pidfd = os.pidfd_open(child.pid, 0)
            deadline = time.monotonic() + 80
            while not ready.exists():
                pid, wait_status, usage = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    reaped = True
                    child.returncode = os.waitstatus_to_exitcode(wait_status)
                    record.update(early_status=wait_status, early_user_seconds=str(usage.ru_utime),
                                  early_system_seconds=str(usage.ru_stime))
                    raise RuntimeError('native child exited before the requested actual cutpoint')
                if time.monotonic() >= deadline:
                    raise TimeoutError('V6 native crash barrier exceeded 80 seconds')
                time.sleep(0.01)
            barrier = json.loads(ready.read_bytes())
            assert barrier['pid'] == child.pid and barrier['cutpoint'] == config['mode']
            if repair_cut:
                assert barrier['schema'] == 'actual-history-publication-repair-crash-barrier-v1'
                repair_config = json.loads(Path(config['publication']).read_bytes())
                assert sha(Path(config['publication'])) == config['publication_sha256']
                assert barrier['signed_publication_sha256'] == hashlib.sha256(
                    bytes(repair_config['signed_publication'])).hexdigest()
                assert barrier['native_operation_started'] is False
                assert barrier['cpu_epoch_created'] is False
                assert barrier['recovery_receipt_created'] is False
            else:
                assert barrier['pending_operation'] is not None
            proc, pinned, threads = stop_owned_group(
                child, pidfd, args.binary_sha256, deadline, record)
            before_descendants = stable_parent_observation(proc, pinned, deadline, record)
            if config['mode'] == 'validation-worker':
                assert barrier['actual_worker_thread'] is True and len(threads) >= 3
            assert identity(proc) == pinned
            assert owned_child_proc_path(child.pid, pidfd) == (proc, pinned)
            # Only the actually owned namespace PID is ever signalled/waited.
            # The outer /proc PID remains an observation, never a kill target.
            os.kill(child.pid, signal.SIGKILL)
            pid, wait_status, usage = os.wait4(child.pid, 0)
            reaped = True
            child.returncode = os.waitstatus_to_exitcode(wait_status)
            assert pid == child.pid and os.WIFSIGNALED(wait_status)
            assert os.WTERMSIG(wait_status) == signal.SIGKILL
            fdinfo = dict(line.split(':', 1) for line in
                          Path(f'/proc/self/fdinfo/{pidfd}').read_text().splitlines())
            assert int(fdinfo['Pid'].strip()) == -1
            raw_user, raw_system = str(usage.ru_utime), str(usage.ru_stime)
            # wait4 timeval has microsecond units. Retain the original strings;
            # map their binary-float spelling back to that documented unit.
            def micros(raw: str) -> int:
                value = Decimal(raw) * 1_000_000
                integer = value.to_integral_value(rounding=ROUND_HALF_EVEN)
                assert abs(value - integer) <= Decimal('0.001')
                return int(integer)
            user, system = micros(raw_user), micros(raw_system)
            if repair_cut:
                # This administrative process is not the crashed Native epoch.
                # Never export its observation as a V6 recovery CPU receipt.
                record.update(
                    passed=True, owned_child_pid=child.pid, child_identity=pinned,
                    threads_before_kill=threads, descendants_before_kill=before_descendants,
                    actual_wait4=True, wait_status=wait_status,
                    reported_user_seconds=raw_user, reported_system_seconds=raw_system,
                    reported_cpu_upper_bound_ns=(user + system + 2) * 1000,
                    barrier_sha256=sha(ready), native_operation_started=False,
                    new_cpu_epoch_created=False, v6_closed_process_receipt_created=False,
                    publication_authorized_by_observer=False)
            else:
                database = Path(config['store']) / 'native.sqlite'
                with sqlite3.connect(f'file:{database}?mode=ro', uri=True) as db:
                    db.execute('PRAGMA query_only=ON')
                    tip, root, generation = db.execute(
                        'SELECT hex(a.tip),hex(b.state_root),a.generation FROM active a '
                        'JOIN blocks b ON b.id=a.tip WHERE a.singleton=1').fetchone()
                    marker_row = db.execute('SELECT marker FROM history_effect_v6 WHERE operation=?',
                                            (barrier['pending_operation'],)).fetchone()
                    marker = json.loads(marker_row[0]) if marker_row else None
                if config['mode'] == 'validation-worker' or publication_cut:
                    assert marker is None
                else:
                    assert marker is not None and marker['purpose'] == 'activation'
                    assert marker['target'] == tip.lower() and marker['after']['generation'] == generation
                closed = {'schema': 'actual-history-effect-closed-process-v6',
                          'epoch': barrier['epoch'], 'executable_sha256': args.binary_sha256,
                          'intent_sha256': barrier['intent_sha256'], 'original_journal': barrier['anchor'],
                          'owned_namespace_pid': child.pid, 'observed_visible_pid': pinned['visible_pid'],
                          'observed_starttime_ticks': pinned['starttime_ticks'],
                          'pidfd_identity_verified': True, 'actual_wait4': True,
                          'signal': signal.SIGKILL, 'all_descendants_closed': True, 'descendants': [],
                          'descendant_accounting_profile': DESCENDANT_PROFILE,
                          'fixture_selector': SELECTOR,
                          'historical_process_tree_observed': False,
                          'cpu_counter_profile': 'linux-wait4-timeval-quantized-v1',
                          'reported_user_seconds': raw_user, 'reported_system_seconds': raw_system,
                          'user_cpu_microseconds': user, 'system_cpu_microseconds': system,
                          'reported_cpu_upper_bound_ns': (user + system + 2) * 1000,
                          'marker': marker,
                          'actual_frontier': {'block': tip.lower(), 'root': root.lower(), 'generation': generation},
                          'physical_cost_qualified': False}
                write(args.directory / 'closed-process.json', closed)
                record.update(passed=True, owned_child_pid=child.pid, child_identity=pinned,
                              threads_before_kill=threads, descendants_before_kill=before_descendants,
                              actual_wait4=True, wait_status=wait_status, closed_process=closed,
                              closed_process_sha256=sha(args.directory / 'closed-process.json'),
                              barrier_sha256=sha(ready), clean_close_created=False,
                              publication_repair_required=publication_cut,
                              publication_authorized_by_observer=False)
    except BaseException as error:
        record['error'] = f'{type(error).__name__}: {error}'
        if child is not None and child.returncode is not None:
            reaped = True
        if child is not None and not reaped:
            try:
                os.kill(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            pid, wait_status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(wait_status)
            record['cleanup_wait4'] = {'pid': pid, 'status': wait_status,
                                      'user_seconds': str(usage.ru_utime), 'system_seconds': str(usage.ru_stime)}
    finally:
        if pidfd is not None:
            os.close(pidfd)
    record['elapsed_wall_ns'] = time.monotonic_ns() - started
    write(args.directory / 'guardian-result.json', record)
    print(json.dumps(record, sort_keys=True))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
