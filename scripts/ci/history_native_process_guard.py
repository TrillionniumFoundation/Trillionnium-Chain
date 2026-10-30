#!/usr/bin/env python3
"""Bounded real SIGKILL/wait4 observation for the local native History fixture.

This creates no production recovery authority. The Rust test separately signs
the observed exact known prefix with disclosed test keys and uses the original
protected recovery loader. Only this guardian's own verified child is killed.
"""
from __future__ import annotations
import argparse
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

SELECTOR = 'store::operator_continuous_owner::history_import::tests::history_process_child_helper'

def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def status(path: Path) -> dict[str, str]:
    return {key: value.strip() for key, value in
            (line.split(':', 1) for line in (path / 'status').read_text().splitlines())}

def identity(path: Path) -> dict:
    observed = status(path)
    # Fields after the final comm ')' start at field 3; starttime is field 22.
    starttime = int((path / 'stat').read_text().rpartition(')')[2].split()[19])
    return {'visible_pid': int(observed['Pid']), 'visible_parent_pid': int(observed['PPid']),
            'namespace_pids': [int(value) for value in observed['NSpid'].split()],
            'pid_namespace_inode': (path / 'ns/pid').stat().st_ino,
            'starttime_ticks': starttime}

def owned_child_proc_path(child_pid: int, pidfd: int) -> tuple[Path, dict]:
    # The retained pidfd was opened using Popen's actual owned namespace PID.
    # Its fdinfo exposes the kernel-pinned process in /proc's PID namespace.
    # This also works on kernels without CONFIG_PROC_CHILDREN; a missing
    # observation is never interpreted as an empty list of children.
    parent = identity(Path('/proc/self'))
    assert parent['namespace_pids'][-1] == os.getpid()
    info = {key: value.strip() for key, value in
            (line.split(':', 1) for line in Path(f'/proc/self/fdinfo/{pidfd}').read_text().splitlines())}
    visible_pid = int(info['Pid'])
    assert visible_pid > 0
    path = Path(f'/proc/{visible_pid}')
    observed = identity(path)
    assert observed['visible_parent_pid'] == parent['visible_pid']
    assert observed['namespace_pids'] == [int(value) for value in info['NSpid'].split()]
    assert observed['namespace_pids'][-1] == child_pid
    assert observed['pid_namespace_inode'] == parent['pid_namespace_inode']
    return path, observed

def observed_descendants(visible_pid: int) -> list[int]:
    # Read only the public process identity/parent fields. Namespace handles of
    # unrelated processes may be inaccessible and are not needed for a parent
    # chain rooted in our already verified child. Every enumerated status must
    # be readable; a disappearing or denied entry makes this observation fail.
    parents = {}
    for path in Path('/proc').iterdir():
        if path.name.isdigit():
            value = status(path)
            assert int(value['Pid']) == int(path.name)
            parents[int(value['Pid'])] = int(value['PPid'])
    assert visible_pid in parents
    result = []
    frontier = [visible_pid]
    seen = {visible_pid}
    while frontier:
        parent = frontier.pop()
        for pid, ppid in parents.items():
            if ppid == parent:
                assert pid not in seen, 'process parent graph is cyclic'
                seen.add(pid)
                result.append(pid)
                frontier.append(pid)
    return sorted(result)

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
    args.directory.mkdir(mode=0o700, exist_ok=False)
    ready = args.directory / 'known-prefix-ready.json'
    log = args.directory / 'killed-native-process.log'
    env = os.environ.copy()
    env.update(TRNM_HISTORY_PROCESS_MODE='crash',
               TRNM_HISTORY_PROCESS_CONFIG=str(args.configuration),
               TRNM_HISTORY_PROCESS_CONFIG_SHA256=args.configuration_sha256,
               TRNM_HISTORY_PROCESS_OUTPUT=str(ready))
    started = time.monotonic_ns()
    record = {'schema': 'actual-history-known-prefix-sigkill-wait4-v1',
              'binary_sha256': args.binary_sha256,
              'configuration_sha256': args.configuration_sha256,
              'passed': False, 'actual_wait4': False,
              'physical_power_loss_qualified': False, 'public_host_path_executed': False,
              'external_registry2_admission': False}
    child = None
    pidfd = None
    reaped = False
    try:
        with log.open('xb') as output:
            child = subprocess.Popen([str(args.binary), SELECTOR, '--exact', '--ignored',
                                      '--nocapture', '--test-threads=1'],
                                     env=env, stdin=subprocess.DEVNULL,
                                     stdout=output, stderr=subprocess.STDOUT)
            record['owned_child_pid'] = child.pid
            pidfd = os.pidfd_open(child.pid, 0)
            deadline = time.monotonic() + 50
            while not ready.exists():
                pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    reaped = True
                    child.returncode = os.waitstatus_to_exitcode(status)
                    record.update(unexpected_exit_status=status, actual_wait4=True,
                                  early_user_seconds=str(usage.ru_utime),
                                  early_system_seconds=str(usage.ru_stime))
                    raise RuntimeError('native child ended before the known-prefix barrier')
                if time.monotonic() >= deadline:
                    raise TimeoutError('native known-prefix barrier exceeded 50 seconds')
                time.sleep(0.01)
            prefix = json.loads(ready.read_bytes())
            assert prefix['pid'] == child.pid
            snapshot = prefix['process_snapshot']
            assert snapshot['pending_scopes'] == 0
            assert snapshot['claims'] == snapshot['started_operations'] == 4
            assert prefix['validation_receipt']['spawned'] == 2
            assert prefix['validation_receipt']['started'] == 2
            assert prefix['validation_receipt']['finished'] == 2
            assert prefix['validation_receipt']['known'] == 2
            child_proc, child_identity = owned_child_proc_path(child.pid, pidfd)
            assert sha(child_proc / 'exe') == args.binary_sha256
            descendants = observed_descendants(child_identity['visible_pid'])
            assert not descendants
            record['observed_process_children_before_kill'] = descendants
            record['child_identity_source'] = 'owned pidfd with PPid/NSpid/namespace/starttime cross-check'
            record['descendant_observation_source'] = 'complete public proc status parent-chain snapshot at parked barrier'
            record['observed_owned_child_proc_identity'] = child_identity
            record['known_prefix_sha256'] = sha(ready)
            # All native scoped work has joined at the explicit barrier. The
            # child now parks; there is no background listener or subprocess.
            assert identity(child_proc) == child_identity
            assert owned_child_proc_path(child.pid, pidfd) == (child_proc, child_identity)
            # Signals/wait4 always use Popen's owned namespace PID. The outer
            # proc mapping above is exclusively a read/identity observation.
            os.kill(child.pid, signal.SIGKILL)
            pid, status, usage = os.wait4(child.pid, 0)
            reaped = True
            child.returncode = os.waitstatus_to_exitcode(status)
            assert pid == child.pid and os.WIFSIGNALED(status)
            assert os.WTERMSIG(status) == signal.SIGKILL
            user_ns = int(Decimal(str(usage.ru_utime)) * 1_000_000_000)
            system_ns = int(Decimal(str(usage.ru_stime)) * 1_000_000_000)
            total = user_ns + system_ns
            known = snapshot['known_scope_total_cpu_ns']
            assert total >= known > 0
            record.update(passed=True, actual_wait4=True, signal=os.WTERMSIG(status),
                          wait_status=status, user_cpu_ns=user_ns, system_cpu_ns=system_ns,
                          reported_user_seconds=str(usage.ru_utime), reported_system_seconds=str(usage.ru_stime),
                          rusage_granularity='reported wait4 timeval, converted to nanosecond units',
                          known_scope_total_cpu_ns=known, closed_process_total_cpu_ns=total,
                          residual_cpu_ns=total-known, all_owned_children_reaped=True,
                          adopted_descendants=[], clean_close_created=False)
    except BaseException as error:
        record['error'] = f'{type(error).__name__}: {error}'
        if child is not None and not reaped:
            try:
                os.kill(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            pid, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
            record['cleanup_wait4'] = {'pid': pid, 'status': status,
                                      'user_seconds': str(usage.ru_utime),
                                      'system_seconds': str(usage.ru_stime)}
    finally:
        if pidfd is not None:
            os.close(pidfd)
    record['elapsed_wall_ns'] = time.monotonic_ns() - started
    record['log_sha256'] = sha(log) if log.exists() else None
    path = args.directory / 'actual-wait4.json'
    with path.open('x') as output:
        json.dump(record, output, sort_keys=True, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps(record, sort_keys=True))
    return 0 if record['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
