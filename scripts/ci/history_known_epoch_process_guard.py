#!/usr/bin/env python3
"""Owned one-epoch native SIGKILL/wait4; this observer grants no authority.

The fixed source/binary-pinned helper starts exactly one epoch after spawn. Its
actual journal interval must contain one Startup and no epoch terminal. All
scope receipts must already be known under their individual original ceilings.
This is not a receipt for an unknown scope, an arbitrary descendant tree, or
the administrative process that publishes a retirement record.
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

from history_effect_v6_process_guard import (
    identity, owned_child_proc_path, sha, stable_parent_observation,
    stop_owned_group, write,
)

SELECTOR = 'store::history_effect_v6::tests::history_known_epoch_process_child_helper'
PROFILE = 'source-bound-single-epoch-native-thread-only-fixture-v1'
NATIVE_CUTS = ('known-validation', 'known-activation', 'known-close')
PUBLICATION_CUTS = ('retirement-publication-linked', 'retirement-publication-unlinked')


def encoded(value) -> bytes:
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def observe_single_epoch(config: dict, barrier: dict, spawned: int) -> tuple[dict, dict]:
    """Recompute actual on-disk scope totals/transcript; no barrier-only verdict."""
    launch_path = Path(config['launch'])
    assert sha(launch_path) == config['launch_sha256']
    launch = json.loads(launch_path.read_bytes())
    startup_raw = bytes(launch['signed_startup'])
    startup = json.loads(startup_raw)['body']
    assert startup['purpose'] == 'startup'
    assert startup['outside_spent_anchor'] == launch['outside_latest_anchor']
    epoch = startup['epoch']
    # Preserve the original typed Anchor serialization, not the alphabetically
    # ordered Value object in the outer fixture configuration.
    before = startup['outside_spent_anchor']
    head = barrier['anchor']
    expected = before['sequence'] + 1
    previous = before['digest']
    pending = None
    observed = None
    starts = terminals = 0
    rows = sorted(Path(launch['journal_path']).iterdir())
    assert len(rows) <= 4097
    for path in rows:
        if path.name == 'owner.lock':
            continue
        assert len(path.name) == 90 and path.name[20] == '-' and path.suffix == '.json'
        sequence = int(path.name[:20])
        if sequence <= before['sequence']:
            continue
        metadata = path.lstat()
        assert path.is_file() and not path.is_symlink()
        assert metadata.st_uid == os.geteuid() and metadata.st_mode & 0o077 == 0
        assert metadata.st_nlink == 1 and 0 < metadata.st_size <= 256 * 1024
        raw = path.read_bytes()
        frame = json.loads(raw)
        assert raw == encoded(frame)
        assert path.name == f'{sequence:020}-{digest(raw)}.json'
        assert sequence == frame['sequence'] == expected and frame['previous'] == previous
        assert sequence <= head['sequence'] and frame['schema'] == 'restricted-history-effect-record-v6'
        event = frame['event']
        kind = event['kind']
        if kind == 'intent':
            assert pending is None
            signed = bytes(event['signed'])
            operation = json.loads(signed)['body']
            assert operation['epoch'] == epoch
            body = encoded(operation)
            intent = digest(b'TRNM-HISTORY-EFFECT-RECOVERY-V6' + b'I\x00'
                            + len(body).to_bytes(4, 'little') + body)
            if operation['purpose'] == 'startup':
                starts += 1
                assert starts == 1 and signed == startup_raw and sequence == expected == before['sequence'] + 1
                assert spawned <= frame['at_ns'] <= time.time_ns()
                observed = {
                    'schema': 'restricted-history-known-epoch-snapshot-v1', 'epoch': epoch,
                    'startup_operation_id': operation['operation_id'], 'startup_intent_sha256': intent,
                    'startup_envelope_sha256': digest(signed), 'before_startup': before,
                    'startup_at_ns': frame['at_ns'], 'known_operations': 0, 'not_started_operations': 0,
                    'known_cpu_ns': 0, 'known_allowance_cpu_ns': 0,
                    'terminal_transcript_sha256': digest(encoded([
                        'restricted-history-known-epoch-start-v1', operation, intent, frame['at_ns']])),
                    'frontier': operation['owner_frontier'],
                }
            assert observed is not None
            pending = (operation, intent)
        elif kind in ('settlement', 'not-started'):
            assert pending is not None and observed is not None
            operation, intent = pending
            assert event['operation'] == operation['operation_id']
            if kind == 'not-started':
                assert operation['purpose'] != 'startup'
                observed['not_started_operations'] += 1
            else:
                cpu = event['cpu']
                assert cpu['schema'] == 'service-owner-scoped-thread-cpu-settlement-v1'
                assert not cpu['accounting_unavailable'] and not cpu['live_refused']
                assert cpu['owner_cpu_ns'] is not None and cpu['scoped_worker_cpu_ns'] is not None
                assert cpu['live_paid_cpu_ns'] is not None and cpu['residual_cpu_ns'] is not None
                assert cpu['owner_cpu_ns'] + cpu['scoped_worker_cpu_ns'] == cpu['total_cpu_ns']
                assert cpu['live_paid_cpu_ns'] + cpu['residual_cpu_ns'] == cpu['total_cpu_ns']
                assert cpu['spawned_workers'] == cpu['started_workers'] == cpu['finished_workers'] == cpu['known_workers']
                assert cpu['total_cpu_ns'] <= operation['allowance']['cpu_ns']
                assert event['effect_readback_known']
                if operation['purpose'] in ('validation', 'activation') and event['native_id'] == operation['target']:
                    assert event['marker'] is not None
                observed['known_operations'] += 1
                observed['known_cpu_ns'] += cpu['total_cpu_ns']
                observed['known_allowance_cpu_ns'] += operation['allowance']['cpu_ns']
                if event['marker']:
                    observed['frontier'] = event['marker']['after']
            observed['terminal_transcript_sha256'] = digest(encoded([
                'restricted-history-known-epoch-terminal-v1', observed['terminal_transcript_sha256'],
                operation, intent, event]))
            pending = None
        elif kind in ('clean-close', 'unknown-prepaid-reconciled', 'known-epoch-retired-v1'):
            terminals += 1
            raise AssertionError('the owned process interval is not exactly one unclosed known epoch')
        else:
            assert kind == 'budget' and pending is None and observed is not None
        previous = digest(raw)
        expected += 1
    assert expected == head['sequence'] + 1 and previous == head['digest']
    assert starts == 1 and terminals == 0 and pending is None and observed is not None
    assert observed == barrier['known_epoch']
    assert encoded(observed) == bytes(barrier['known_epoch_raw'])
    assert digest(encoded(observed)) == barrier['known_epoch_sha256']
    return launch, observed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--configuration', type=Path, required=True)
    parser.add_argument('--configuration-sha256', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    assert args.binary.is_absolute() and args.configuration.is_absolute()
    assert sha(args.binary) == args.binary_sha256 and sha(args.configuration) == args.configuration_sha256
    config = json.loads(args.configuration.read_bytes())
    assert config['schema'] == 'actual-history-known-epoch-child-fixture-v1'
    assert config['mode'] in (*NATIVE_CUTS, *PUBLICATION_CUTS)
    administrative = config['mode'] in PUBLICATION_CUTS
    fixture = Path(__file__).resolve().parents[2] / 'trillionnium/crates/trnm-pon-node/src/store/history_effect_v6/tests/retirement.rs'
    fixture_sha, guardian_sha = sha(fixture), sha(Path(__file__))
    # This Git subprocess is fully awaited before the owned native process is
    # born. The pinned native-thread-only helper itself never spawns it.
    source_commit = os.environ['TRNM_HISTORY_KNOWN_EPOCH_SOURCE_COMMIT']
    actual_commit = subprocess.check_output(
        ['git', '--no-replace-objects', 'rev-parse', 'HEAD'],
        cwd=Path(__file__).resolve().parents[2], text=True).strip()
    assert source_commit == actual_commit
    assert len(source_commit) == 40 and all(c in '0123456789abcdef' for c in source_commit)
    ready = args.directory / 'crash-ready.json'
    env = os.environ.copy()
    env.update(TRNM_HISTORY_KNOWN_EPOCH_CHILD_CONFIG=str(args.configuration),
               TRNM_HISTORY_KNOWN_EPOCH_CHILD_CONFIG_SHA256=args.configuration_sha256)
    record = {'schema': 'actual-history-known-epoch-guardian-v1', 'passed': False,
              'configuration_sha256': args.configuration_sha256, 'binary_sha256': args.binary_sha256,
              'fixture_source_sha256': fixture_sha, 'guardian_source_sha256': guardian_sha,
              'source_commit': source_commit,
              'cutpoint': config['mode'], 'fixture_selector': SELECTOR,
              'descendant_accounting_profile': PROFILE, 'physical_power_loss_qualified': False}
    child = None
    pidfd = None
    reaped = False
    started = time.monotonic_ns()
    try:
        with (args.directory / 'killed-native-process.log').open('xb') as log:
            spawned = time.time_ns()
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
                    record['early_status'] = wait_status
                    raise RuntimeError('owned child terminated before the selected actual cutpoint')
                if time.monotonic() >= deadline:
                    raise TimeoutError('known-epoch native crash barrier exceeded 80 seconds')
                time.sleep(0.01)
            barrier = json.loads(ready.read_bytes())
            assert barrier['pid'] == child.pid and barrier['cutpoint'] == config['mode']
            assert barrier['fixture_source_sha256'] == fixture_sha
            assert barrier['guardian_source_sha256'] == guardian_sha
            assert barrier['source_commit'] == source_commit
            proc, pinned, threads = stop_owned_group(child, pidfd, args.binary_sha256, deadline, record)
            descendants = stable_parent_observation(proc, pinned, deadline, record)
            assert identity(proc) == pinned and owned_child_proc_path(child.pid, pidfd) == (proc, pinned)
            os.kill(child.pid, signal.SIGKILL)
            pid, wait_status, usage = os.wait4(child.pid, 0)
            reaped = True
            reaped_at = time.time_ns()
            child.returncode = os.waitstatus_to_exitcode(wait_status)
            assert pid == child.pid and os.WIFSIGNALED(wait_status) and os.WTERMSIG(wait_status) == signal.SIGKILL
            fdinfo = dict(line.split(':', 1) for line in Path(f'/proc/self/fdinfo/{pidfd}').read_text().splitlines())
            assert int(fdinfo['Pid'].strip()) == -1
            def micros(raw: str) -> int:
                value = Decimal(raw) * 1_000_000
                integer = value.to_integral_value(rounding=ROUND_HALF_EVEN)
                assert abs(value - integer) <= Decimal('0.001')
                return int(integer)
            raw_user, raw_system = str(usage.ru_utime), str(usage.ru_stime)
            user, system = micros(raw_user), micros(raw_system)
            record.update(owned_child_pid=child.pid, child_identity=pinned, actual_wait4=True,
                          wait_status=wait_status, threads_before_kill=threads, descendants_before_kill=descendants,
                          reported_user_seconds=raw_user, reported_system_seconds=raw_system,
                          barrier_sha256=sha(ready))
            if administrative:
                assert barrier['schema'] == 'actual-history-known-epoch-publication-barrier-v1'
                assert not barrier['native_operation_started'] and not barrier['new_cpu_epoch_created']
                record.update(closed_process_receipt_created=False, native_operation_started=False,
                              new_cpu_epoch_created=False, retirement_authorized_by_observer=False)
            else:
                assert barrier['schema'] == 'actual-history-known-epoch-crash-barrier-v1'
                assert barrier['journal']['pending'] is None and barrier['journal']['epoch'] is not None
                launch, epoch = observe_single_epoch(config, barrier, spawned)
                assert launch['identity']['source_commit'] == source_commit
                with sqlite3.connect(f"file:{Path(config['store']) / 'native.sqlite'}?mode=ro", uri=True) as db:
                    db.execute('PRAGMA query_only=ON')
                    assert db.execute('SELECT COUNT(*) FROM reorg WHERE done!=1').fetchone()[0] == 0
                    tip, root, generation = db.execute(
                        'SELECT hex(a.tip),hex(b.state_root),a.generation FROM active a '
                        'JOIN blocks b ON b.id=a.tip WHERE a.singleton=1').fetchone()
                frontier = {'block': tip.lower(), 'root': root.lower(), 'generation': generation}
                assert frontier == epoch['frontier']
                assert epoch['known_cpu_ns'] <= (user + system + 2) * 1000 <= epoch['known_allowance_cpu_ns']
                closed = {
                    'schema': 'actual-history-known-epoch-closed-process-v1', 'epoch': epoch['epoch'],
                    'source_commit': launch['identity']['source_commit'], 'executable_sha256': args.binary_sha256,
                    'fixture_source_sha256': fixture_sha, 'guardian_source_sha256': guardian_sha,
                    'launch_configuration_sha256': config['launch_sha256'], 'signed_startup': launch['signed_startup'],
                    'original_journal': barrier['anchor'], 'known_epoch_sha256': barrier['known_epoch_sha256'],
                    'process_spawn_before_ns': spawned, 'process_reaped_after_ns': reaped_at,
                    'observed_epoch_start_count': 1, 'observed_epoch_terminal_count': 0,
                    'owned_namespace_pid': child.pid, 'observed_visible_pid': pinned['visible_pid'],
                    'observed_starttime_ticks': pinned['starttime_ticks'], 'pidfd_identity_verified': True,
                    'actual_wait4': True, 'signal': signal.SIGKILL, 'all_descendants_closed': True, 'descendants': [],
                    'descendant_accounting_profile': PROFILE, 'fixture_selector': SELECTOR,
                    'historical_process_tree_observed': False, 'cpu_counter_profile': 'linux-wait4-timeval-quantized-v1',
                    'reported_user_seconds': raw_user, 'reported_system_seconds': raw_system,
                    'user_cpu_microseconds': user, 'system_cpu_microseconds': system,
                    'reported_cpu_upper_bound_ns': (user + system + 2) * 1000,
                    'actual_frontier': frontier, 'physical_cost_qualified': False,
                }
                write(args.directory / 'closed-process.json', closed)
                record.update(closed_process=closed, closed_process_sha256=sha(args.directory / 'closed-process.json'),
                              original_known_epoch=epoch, closed_process_receipt_created=True,
                              clean_close_created=False, per_scope_receipt_created=False,
                              retirement_authorized_by_observer=False)
            record['passed'] = True
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
