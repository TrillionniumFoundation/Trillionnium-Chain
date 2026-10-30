#!/usr/bin/env python3
"""Observe an owned, pinned Native reorg fixture; create no signature or credit.

Retain the source-bound thread-only profile and actual SIGKILL/wait4 receipts.
This does not qualify arbitrary subprocess accounting or physical power loss.
"""
from __future__ import annotations
import argparse
from decimal import Decimal, ROUND_HALF_EVEN
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import time
from history_effect_v6_process_guard import (
    DESCENDANT_PROFILE, SELECTOR, identity, owned_child_proc_path, sha,
    stable_parent_observation, stop_owned_group, write,
)


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
    config = json.loads(args.configuration.read_bytes())
    modes = {
        *(f'reorg-cursor-{i}' for i in range(4)), 'reorg-cancel-cursor-1',
        'reorg-startup-pending', 'reorg-startup-not-started',
        'reorg-validation-pending', 'reorg-final-commit',
        'reorg-repair-linked', 'reorg-repair-unlinked',
        *(f'reorg-publish-{stage}' for stage in
          ('file-synced', 'linked', 'final-synced', 'unlinked', 'published')),
    }
    mode = config['mode']
    assert mode in modes and args.directory.is_dir()
    administrative = mode.startswith(('reorg-publish-', 'reorg-repair-'))
    record = {'schema': 'actual-history-reorg-continuation-guardian-v1', 'passed': False,
              'configuration_sha256': args.configuration_sha256,
              'binary_sha256': args.binary_sha256, 'cutpoint': mode,
              'fixture_selector': SELECTOR, 'descendant_accounting_profile': DESCENDANT_PROFILE,
              'historical_process_tree_observed': False, 'physical_power_loss_qualified': False}
    env = os.environ.copy()
    env.update(TRNM_HISTORY_V6_CHILD_CONFIG=str(args.configuration),
               TRNM_HISTORY_V6_CHILD_CONFIG_SHA256=args.configuration_sha256)
    child, pidfd, reaped = None, None, False
    try:
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
                    raise RuntimeError('Native reorg child exited before selected barrier')
                if time.monotonic() >= deadline:
                    raise TimeoutError('Native reorg barrier exceeded 80 seconds')
                time.sleep(0.01)
            barrier = json.loads(ready.read_bytes())
            assert barrier['pid'] == child.pid and barrier['cutpoint'] == mode
            assert barrier['schema'] == 'actual-history-reorg-continuation-barrier-v1'
            if administrative:
                assert barrier['native_operation_started'] is False
                assert barrier['cpu_epoch_created'] is False
            else:
                assert barrier['closure'] in ('pending-unknown', 'settled-known', 'not-started')
                assert barrier['operation_id'] and barrier['intent_sha256']
            proc, pinned, threads = stop_owned_group(child, pidfd, args.binary_sha256, deadline, record)
            descendants = stable_parent_observation(proc, pinned, deadline, record)
            assert identity(proc) == pinned
            assert owned_child_proc_path(child.pid, pidfd) == (proc, pinned)
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
                record.update(new_cpu_epoch_created=False, v6_closed_process_receipt_created=False)
            else:
                with sqlite3.connect(f"file:{Path(config['store']) / 'native.sqlite'}?mode=ro", uri=True) as db:
                    db.execute('PRAGMA query_only=ON')
                    tip, root, generation = db.execute(
                        'SELECT hex(a.tip),hex(b.state_root),a.generation FROM active a '
                        'JOIN blocks b ON b.id=a.tip WHERE a.singleton=1').fetchone()
                    reorg = db.execute('SELECT hex(old_tip),hex(new_tip),generation,cursor,done '
                                       'FROM reorg WHERE singleton=1').fetchone()
                    marker_row = db.execute('SELECT marker FROM history_effect_v6 WHERE operation=?',
                                            (barrier['operation_id'],)).fetchone()
                    marker = json.loads(marker_row[0]) if marker_row else None
                assert reorg is not None
                if mode == 'reorg-final-commit':
                    assert reorg[4] == 1 and marker is not None and marker['purpose'] == 'activation'
                    assert marker['after']['block'] == tip.lower()
                else:
                    assert reorg[4] == 0 and reorg[0].lower() == tip.lower()
                    assert reorg[2] == generation + 1
                    if mode == 'reorg-validation-pending':
                        assert marker is not None and marker['purpose'] == 'validation'
                    else:
                        assert marker is None
                closed = {'schema': 'actual-history-effect-closed-process-v6',
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
                          'reported_cpu_upper_bound_ns': (user + system + 2) * 1000, 'marker': marker,
                          'actual_frontier': {'block': tip.lower(), 'root': root.lower(), 'generation': generation},
                          'physical_cost_qualified': False}
                write(args.directory / 'closed-process.json', closed)
                record.update(closed_process=closed, closed_process_sha256=sha(args.directory / 'closed-process.json'),
                              reorg_after_death=reorg, clean_close_created=False)
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
        write(args.directory / 'guardian-result.json', record)


if __name__ == '__main__':
    main()
