#!/usr/bin/env python3
"""Execute all 15 History V6 tests from one exact release binary, retaining failures."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

from verify_ci_source import verify

ROOT = Path(__file__).resolve().parents[2]
PREFIX = 'store::history_effect_v6::tests::'
HELPER = PREFIX + 'history_effect_v6_process_child_helper'
ROSTER = sorted(PREFIX + name for name in [
    'history_effect_v6_process_child_helper',
    'history_publication_durable_unacknowledged_crash_repairs_and_resumes',
    'history_publication_final_directory_fsync_crash_repairs_and_resumes',
    'history_publication_pending_file_fsync_crash_repairs_and_resumes',
    'history_publication_pending_unlink_crash_repairs_and_resumes',
    'history_publication_two_hardlinks_crash_repairs_and_resumes',
    'publication::original_frame_and_physical_tail_refusals_preserve_every_byte',
    'settled_epoch::expired_old_budget_needs_fresh_close_authorization_then_separate_renewal',
    'settled_epoch::settled_activation_epoch_sigkill_requires_fresh_charge_then_resumes',
    'settled_epoch::settled_epoch_recovery_record_survives_every_publication_cut_and_retry',
    'v6_actual_sigkill_after_activation_commit_recovers_and_advances_again',
    'v6_actual_sigkill_during_registered_worker_recovers_with_fresh_claims',
    'v6_actual_two_worker_cancel_retry_close_and_cold_reopen_keep_predebits',
    'v6_late_journal_lock_failure_keeps_actual_native_and_original_cpu',
    'v6_unmarked_existing_bad_product_is_not_validated_by_sql_syntax',
    'v6_unsigned_worker_host_and_delegated_nonce_refuse_without_new_authority',
])


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def roster(text):
    selected = sorted(line.removesuffix(': test') for line in text.splitlines()
                      if line.startswith(PREFIX) and line.endswith(': test'))
    if selected != ROSTER:
        raise ValueError('exact History roster differs; missing, duplicate or substituted test')
    return selected


def suite_passed(text):
    summaries = re.findall(r'^test result: .+$', text, re.M)
    executed = sorted(re.findall(r'^test (' + re.escape(PREFIX) + r'\S+) \.\.\. ', text, re.M))
    return (text.splitlines().count('running 16 tests') == 1 and executed == ROSTER
            and f'test {HELPER} ... ignored' in text
            and len(summaries) == 1
            and re.fullmatch(r'test result: ok\. 15 passed; 0 failed; 1 ignored; '
                             r'\d+ measured; \d+ filtered out; finished in .+s', summaries[0]) is not None)


def bounded(command, directory, seconds, env):
    directory.mkdir()
    started = time.monotonic()
    receipt = {'command': command, 'budget_seconds': seconds, 'started_unix': time.time(),
               'passed': False, 'termination_reason': None, 'native_returncode': None,
               'available_disk_floor_bytes': 1024 ** 3, 'log_limit_bytes': 64 * 1024 ** 2,
               'child_ownership': 'only the newly spawned owned process group may be signalled',
               'cleanup_contract': 'signal the owned group before reaping its pinned leader; '
                                   'does not attest every descendant has terminated',
               'descendant_quiescence_qualified': False}
    write(directory / 'started.json', receipt)
    log_path = directory / 'native.log'
    child = None
    stopped = None
    def observed(status, usage):
        child.returncode = os.waitstatus_to_exitcode(status)
        receipt.update(native_returncode=child.returncode, actual_wait4_status=status,
                       reported_user_seconds=usage.ru_utime, reported_system_seconds=usage.ru_stime,
                       max_rss_kib=usage.ru_maxrss,
                       terminal_observed_elapsed_seconds=time.monotonic() - started)

    try:
        with log_path.open('wb', buffering=0) as log, (directory / 'resources.jsonl').open('w') as samples:
            disk = os.statvfs(directory)
            if disk.f_bavail * disk.f_frsize < receipt['available_disk_floor_bytes']:
                receipt['termination_reason'] = 'RESOURCE_ABORT_BEFORE_START'
            else:
                child = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                         stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                receipt['owned_namespace_pid'] = child.pid
                write(directory / 'started.json', receipt)
                while True:
                    # Keep the leader unreaped until the final group signal, so
                    # its PID cannot be reused while we still own the group.
                    exit_info = os.waitid(os.P_PID, child.pid,
                                          os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    now = time.monotonic()
                    elapsed = now - started
                    if exit_info is not None:
                        receipt['unreaped_terminal_observed_elapsed_seconds'] = elapsed
                        if elapsed > seconds and receipt['termination_reason'] is None:
                            receipt['termination_reason'] = 'LATE_TERMINAL_OBSERVATION'
                        break
                    disk = os.statvfs(directory)
                    available = disk.f_bavail * disk.f_frsize
                    samples.write(json.dumps({'elapsed_seconds': elapsed, 'available_bytes': available,
                                              'log_bytes': log_path.stat().st_size}) + '\n')
                    samples.flush()
                    reason = ('TIMEOUT' if elapsed >= seconds else
                              'RESOURCE_ABORT_DISK' if available < receipt['available_disk_floor_bytes'] else
                              'RESOURCE_ABORT_LOG' if log_path.stat().st_size > receipt['log_limit_bytes'] else None)
                    if stopped is None and reason:
                        receipt['termination_reason'] = reason
                        stopped = now
                        try:
                            os.killpg(child.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                    elif stopped is not None and now - stopped >= 10:
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    time.sleep(0.1 if stopped else 0.25)
    except BaseException as error:
        receipt.update(termination_reason='RUNNER_EXCEPTION', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        if child is not None and child.returncode is None:
            # Stop the owned group even on successful leader exit: a descendant
            # may still be writing logs. The unreaped leader pins group identity
            # through this LAST signal. Escaped sessions are outside this owner
            # contract; this bounded command owner is not a process sandbox.
            try:
                os.killpg(child.pid, signal.SIGKILL)
                receipt['final_owned_group_sigkill_sent'] = True
            except ProcessLookupError:
                receipt['owned_group_already_absent'] = True
            cleanup_until = time.monotonic() + 10
            while time.monotonic() < cleanup_until:
                pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    observed(status, usage)
                    break
                time.sleep(0.1)
            receipt['cleanup_leader_terminal_observed'] = child.returncode is not None
        receipt.update(elapsed_seconds=time.monotonic() - started, finished_unix=time.time(),
                       log_sha256=sha(log_path) if log_path.is_file() else None)
        if (receipt['native_returncode'] == 0 and receipt['termination_reason'] is None
                and receipt['elapsed_seconds'] > seconds):
            receipt['termination_reason'] = 'LATE_CLEANUP_TERMINAL_OBSERVATION'
        receipt['passed'] = (receipt['native_returncode'] == 0
                             and receipt['termination_reason'] is None
                             and receipt.get('cleanup_leader_terminal_observed', False))
        write(directory / 'terminal.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-source', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    output = args.out.resolve()
    if output.is_relative_to(ROOT) or not output.is_absolute():
        raise ValueError('execution output must be outside the exact source tree')
    output.mkdir(parents=True, exist_ok=False)
    terminal = {'schema': 'history-effect-v6-hosted-native-terminal-v1', 'passed': False,
                'expected_source': args.expected_source, 'full_suite_required': True,
                'native_test_budget_seconds': 600, 'original_local_full_suite_budget_seconds': 600,
                'runtime_burst_ns': 2_000_000_000, 'fixture_operation_allowance_ns': 4_000_000_000,
                'complete_parent_snapshot_attempts': 4, 'production_qualified': False,
                'whole_history_p0_closed': False}
    source_ok = False
    try:
        before = verify('head', args.expected_source)
        source_ok = True
        write(output / 'source-before.json', before)
        env = os.environ.copy()
        target = Path(env['CARGO_TARGET_DIR']).resolve()
        if target.is_relative_to(ROOT):
            raise ValueError('Cargo output must not mutate the source tree')
        env.update(CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1', RUST_TEST_THREADS='1',
                   PYTHONDONTWRITEBYTECODE='1')
        build = bounded(['cargo', '+1.95.0', 'test', '--release', '--locked', '--manifest-path',
                         'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--lib', '--no-run',
                         '--message-format=json-render-diagnostics'], output / 'build', 2400, env)
        terminal['build'] = build
        if not build['passed']:
            raise RuntimeError('actual same-source release build did not pass')
        executable = None
        for line in (output / 'build/native.log').read_text().splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (row.get('reason') == 'compiler-artifact'
                    and row.get('manifest_path') == str(ROOT / 'trillionnium/crates/trnm-pon-node/Cargo.toml')
                    and row.get('target', {}).get('name') == 'trnm_pon_node'
                    and row.get('profile', {}).get('test') and row.get('executable')):
                executable = Path(row['executable']).resolve()
        if executable is None or not executable.is_file() or not executable.is_relative_to(target):
            raise ValueError('actual test binary missing or outside isolated target')
        digest = sha(executable)
        terminal.update(binary=str(executable), binary_sha256=digest)
        listing = bounded([str(executable), '--list'], output / 'inventory', 30, env)
        if not listing['passed']:
            raise RuntimeError('actual binary test inventory failed')
        terminal['roster'] = roster((output / 'inventory/native.log').read_text())
        observer = bounded([sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts/ci',
                            '-p', 'test_history_effect_v6_guard.py'], output / 'observer', 60, env)
        observer_text = (output / 'observer/native.log').read_text()
        observer['expected_four_tests_passed'] = (observer['passed']
            and re.search(r'^Ran 4 tests in ', observer_text, re.M) is not None
            and re.search(r'^OK$', observer_text, re.M) is not None)
        terminal['observer'] = observer
        # Run every retained test even when the standalone observer group failed.
        # The ignored helper is invoked by the process tests with --exact
        # --ignored, protected fixture inputs and an independently owning guardian.
        env['TRNM_HISTORY_V6_ARTIFACT_DIR'] = str(output / 'native/artifacts')
        native = bounded([str(executable), PREFIX, '--test-threads=1', '--nocapture'],
                         output / 'native', 600, env)
        native['exact_fifteen_pass_one_ignored'] = suite_passed((output / 'native/native.log').read_text())
        terminal.update(native=native, binary_stable=sha(executable) == digest)
        terminal['passed'] = (native['passed'] and native['exact_fifteen_pass_one_ignored']
                              and observer['expected_four_tests_passed'] and terminal['binary_stable'])
    except BaseException as error:
        terminal['error'] = f'{type(error).__name__}: {error}'
        terminal['passed'] = False
    finally:
        if source_ok:
            try:
                after = verify('head', args.expected_source)
                write(output / 'source-after.json', after)
                terminal['source_stable'] = before == after
                terminal['passed'] = terminal['passed'] and before == after
            except BaseException as error:
                terminal.update(passed=False, source_after_error=f'{type(error).__name__}: {error}')
        write(output / 'terminal.json', terminal)
        print(json.dumps(terminal, sort_keys=True))
    return 0 if terminal['passed'] else 1


if __name__ == '__main__':
    def cancelled(signum, _frame):
        raise InterruptedError(f'workflow signalled {signum}')

    signal.signal(signal.SIGTERM, cancelled)
    raise SystemExit(main())
