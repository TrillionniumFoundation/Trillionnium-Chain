#!/usr/bin/env python3
"""Exact-source component controls, not a service campaign or TPS qualification.

Each old production group and current source execute identical group test bytes.
Build once per source; the fixed arm also builds pool_mining and its actual CLI.
Retain executable identities, actual lists and every named native outcome.
An arbitrary nonzero exit is never a negative control.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import tomllib

sys.dont_write_bytecode = True
from check_required_native_test import validate as validate_pass
from replay_pinned_native import json_load, require
from verify_ci_source import verify as verify_source

ROOT = Path(__file__).resolve().parents[2]
BUDGET_BEFORE_SHA = '89fb2269b0dd306fbd32c36f464842c3d7daee2b'
BUDGET_BEFORE_TREE = 'c4cd82ed0004709192eff1563d90423bd5641e99'
POOL_BEFORE_SHA = 'db93026b9314bfd8bc4350945036998f1b7d34aa'
POOL_BEFORE_TREE = '379f05bda52b20130e5d895788f0613aa680472c'
POOL_SCAN_BEFORE_SHA = 'ae657e262278ae4a058220f66a6a0495721eb9ad'
POOL_SCAN_BEFORE_TREE = 'def5ae894d06b787222b6b2b2b2d97bf8be59366'
BEFORE_SOURCES = {
    'budget-before-v2': (BUDGET_BEFORE_SHA, BUDGET_BEFORE_TREE),
    'pool-before': (POOL_BEFORE_SHA, POOL_BEFORE_TREE),
    'pool-scan-before': (POOL_SCAN_BEFORE_SHA, POOL_SCAN_BEFORE_TREE),
}
HISTORY_PREFIX = 'ingress::history_import::tests::detached_budget_controls::'
MINING_PREFIX = 'mining::prepare_control_tests::'
HISTORY = {
    HISTORY_PREFIX + 'shared_detached_history_continues_from_real_deficit_without_new_credit': 'Continue',
    HISTORY_PREFIX + 'shared_detached_history_refill_keeps_original_resource_cancellation': 'Cancel',
    HISTORY_PREFIX + 'shared_detached_history_refill_cannot_renew_original_deadline': 'Expire',
}
MINING_FAILURES = (
    MINING_PREFIX + 'registered_prepare_pre_cancel_keeps_error_before_material_or_parent_io',
    MINING_PREFIX + 'registered_prepare_cancels_inside_active_row_scan_before_execution',
    MINING_PREFIX + 'registered_prepare_cancels_during_inactive_ancestry_read_and_retries',
)
EQUIVALENCE = MINING_PREFIX + 'registered_prepare_control_preserves_packets_errors_and_cold_commit'
BUDGET_CONTROLS = (*HISTORY, *MINING_FAILURES, EQUIVALENCE)
# These are the assertion sites in the identical, committed test-only input.
# A setup unwrap or an unrelated assertion cannot establish this counterexample.
PANIC_LINES = {**dict.fromkeys(HISTORY, 221),
               **dict(zip(MINING_FAILURES, (82, 124, 176)))}
GROUP_INPUTS = {
    'budget': (
        'trillionnium/crates/trnm-pon-node/src/ingress/history_import_detached_budget_tests.rs',
        'trillionnium/crates/trnm-pon-node/src/mining_prepare_control_tests.rs',
    ),
    'pool': ('trillionnium/crates/trnm-pon-node/src/pool_run_control_tests.rs',),
    'pool-scan': ('trillionnium/crates/trnm-pon-node/src/pool_reconcile_control_tests.rs',),
}
COMMON_INPUTS = (
    'trillionnium/Cargo.toml',
    'trillionnium/Cargo.lock',
    'trillionnium/crates/trnm-pon-node/Cargo.toml',
    'rust-toolchain.toml',
)
RELEASE_PROFILE = dict(debug_assertions=False, debuginfo=0, opt_level='3',
                       overflow_checks=False, test=True)
RELEASE_CLI_PROFILE = dict(RELEASE_PROFILE, test=False)
FALSE_FLAGS = ('native_campaign_executed', 'whole_business_liveness_qualified',
               'throughput_measured', 'production_activation')
SCHEMA = 'pon-original-budget-component-controls-v2'

POOL_PREFIX = 'mining::pool_run_control_tests::'
POOL_FAILURES = {
    POOL_PREFIX + 'pool_run_stop_interrupts_batch_parent_scan': ('POOL_RUN_PARENT_SCAN_IGNORED_STOP: pool-batch', 283, 256),
    POOL_PREFIX + 'pool_run_stop_interrupts_registered_and_legacy_prepare': ('POOL_RUN_PARENT_SCAN_IGNORED_STOP: prepare', 283, 256),
    POOL_PREFIX + 'pool_run_stop_interrupts_post_search_revalidation': ('POOL_RUN_PARENT_SCAN_IGNORED_STOP: batch-revalidation', 283, 256),
    POOL_PREFIX + 'pool_run_original_deadline_interrupts_parent_scan': ('POOL_RUN_PARENT_SCAN_IGNORED_STOP: pool-batch', 283, 256),
    POOL_PREFIX + 'pool_run_cancelled_preview_keeps_queue_without_completed_m06': ('POOL_RUN_PREVIEW_IGNORED_STOP', 278, 0),
}
POOL_POSITIVES = (
    POOL_PREFIX + 'pool_run_native_and_sql_failures_survive_concurrent_stop',
    POOL_PREFIX + 'pool_run_completed_packet_and_reconcile_failure_remain_durable',
)
POOL_CONTROLS = (*POOL_FAILURES, *POOL_POSITIVES)
POOL_SCAN_PREFIX = 'mining::pool_reconcile_control_tests::'
POOL_SCAN_CONTROLS = tuple(POOL_SCAN_PREFIX + suffix for suffix in (
    'pool_run_stop_interrupts_reconciliation_pool_rows',
    'pool_run_deadline_interrupts_reconciliation_pool_rows',
))
# This is the same assertion in both exact native inputs. The first actual
# pool-batch scan decodes all six retained rows on the old production source.
POOL_SCAN_PANIC_LINE = 181
POOL_SCAN_MARKER = 'POOL_RUN_RECONCILIATION_ROWS_IGNORED_ORIGINAL_CONTROL: pool-batch'
POOL_INTEGRATION = (
    'wall_clock_loop_executes_funding_dependencies_then_reopens_exact_queue_and_chain',
    'reconciliation_failure_reports_the_already_activated_durable_block',
    'next_block_uses_current_authenticated_statement_after_atomic_renewal',
    'bounded_stop_runtime_and_invalid_material_do_not_mine_or_consume_pending_transactions',
    'completed_sqlite_blocked_batch_observes_stop_before_revalidation_or_preparation',
    'actual_cli_retains_signed_group_then_mines_with_wall_clock_and_refuses_logical_clock',
    'failed_pool_batch_retains_elapsed_before_any_search_or_admission',
    'failed_post_search_revalidation_retains_elapsed_without_admission',
    'wall_clock_miner_extends_admissible_future_tip_without_advancing_its_clock',
    'wall_clock_miner_waits_when_native_median_itself_is_still_in_the_future',
)


HANDOFF_PREFIX = 'ingress::public_v3::scalar_cpu::history_handoff_tests::'
HANDOFF_CONTROLS = tuple(HANDOFF_PREFIX + suffix for suffix in (
    'history_writer_handoff_waits_for_original_free_credit_and_preserves_other_reserve',
    'history_writer_handoff_preserves_original_resource_and_deadline',
    'history_writer_handoff_denies_wait_to_unqualified_and_replayed_work',
    'history_writer_handoff_never_revives_refused_or_unknown_operation',
    'history_writer_handoff_keeps_funded_unqualified_path_without_wait',
))
CONTROL_GROUPS = {'budget': BUDGET_CONTROLS, 'pool': POOL_CONTROLS,
                  'history-handoff': HANDOFF_CONTROLS, 'pool-scan': POOL_SCAN_CONTROLS}
MODE_GROUPS = {'budget-before-v2': ('budget',), 'pool-before': ('pool',),
              'pool-scan-before': ('pool-scan',),
              'fixed': ('budget', 'pool', 'history-handoff', 'pool-scan')}
FIXED_ONLY_INPUTS = (
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu_history_handoff_tests.rs',
    'trillionnium/crates/trnm-pon-node/tests/pool_mining.rs',
)


def controls_for_mode(mode: str) -> tuple[str, ...]:
    require(mode in MODE_GROUPS, 'EXACT_CONTROL_MODE_REQUIRED')
    return tuple(name for group in MODE_GROUPS[mode] for name in CONTROL_GROUPS[group])


def same_input_groups(mode: str) -> dict[str, tuple[str, ...]]:
    require(mode in MODE_GROUPS, 'EXACT_CONTROL_MODE_REQUIRED')
    return {'common': COMMON_INPUTS, **{group: GROUP_INPUTS[group]
            for group in MODE_GROUPS[mode] if group in GROUP_INPUTS}}


def write(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    temporary.replace(path)


def file_record(path: Path) -> dict:
    require(path.is_absolute() and path.resolve(strict=True) == path,
            'CANONICAL_REGULAR_FILE_REQUIRED')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), 'REGULAR_FILE_REQUIRED')
        stamp = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(stamp(path.lstat()) == stamp(before), 'FILE_CHANGED')
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
        require(stamp(os.fstat(stream.fileno())) == stamp(before)
                and stamp(path.lstat()) == stamp(before), 'FILE_CHANGED')
    return {'path': str(path), 'bytes': before.st_size, 'sha256': digest.hexdigest()}


def capture(command: list[str], cwd: Path, out: Path, label: str, env: dict) -> dict:
    """No replacement runtime deadline; the native controls retain their own."""
    record = {'command': command, 'cwd': str(cwd), 'started': False,
              'exit_code': None, 'failure': None, 'cleanup_errors': []}
    status = out / (label + '.process.json')
    write(status, record)
    child = None
    started = time.monotonic_ns()
    try:
        with (out / (label + '.stdout')).open('xb') as stdout, \
                (out / (label + '.stderr')).open('xb') as stderr:
            child = subprocess.Popen(command, cwd=cwd, env=env, stdout=stdout,
                                     stderr=stderr, start_new_session=True)
            record.update(started=True, pid=child.pid)
            write(status, record)
            record['exit_code'] = child.wait()
    except BaseException as error:
        record['failure'] = type(error).__name__ + ': ' + str(error)
        if child is not None:
            try:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                record['exit_code'] = child.wait(timeout=5)
            except BaseException as cleanup:
                record['cleanup_errors'].append(type(cleanup).__name__ + ': ' + str(cleanup))
    finally:
        record['elapsed_wall_ns'] = time.monotonic_ns() - started
        for stream in ('stdout', 'stderr'):
            path = out / (label + '.' + stream)
            if path.exists():
                record[stream] = file_record(path)
        write(status, record)
    return record


def successful(record: dict) -> bool:
    return (record.get('started') is True and type(record.get('exit_code')) is int
            and record['exit_code'] == 0
            and record.get('failure') is None and record.get('cleanup_errors') == [])


def build_command(mode: str) -> list[str]:
    require(mode in MODE_GROUPS, 'EXACT_CONTROL_MODE_REQUIRED')
    selected = ['--lib', '--test', 'pool_mining'] if mode == 'fixed' else ['--lib']
    return ['cargo', '+1.95.0', 'test', '--locked', '--release', '--manifest-path',
            'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', *selected,
            '--no-run', '--message-format=json']


def select_binaries(raw: str, source: Path, target_dir: Path,
                    mode: str) -> dict[str, tuple[Path, dict]]:
    require(mode in MODE_GROUPS, 'EXACT_CONTROL_MODE_REQUIRED')
    expected = {'trnm_pon_node': ('libtest', 'lib', 'lib', 'src/lib.rs', RELEASE_PROFILE)}
    if mode == 'fixed':
        expected.update({
            'pool_mining': ('pool-integration', 'test', 'bin', 'tests/pool_mining.rs', RELEASE_PROFILE),
            'trnm-pon-node': ('cli', 'bin', 'bin', 'src/main.rs', RELEASE_CLI_PROFILE),
        })
    artifacts, finished = {}, False
    package = source / 'trillionnium/crates/trnm-pon-node'
    for line in raw.splitlines():
        row = json_load(line)
        require(type(row) is dict and not finished, 'BUILD_RECORD_ORDER')
        if row.get('reason') == 'build-finished':
            require(row.get('success') is True, 'BUILD_FINISH_REQUIRED')
            finished = True
        elif row.get('reason') == 'compiler-artifact' and row.get('executable') is not None:
            target, profile = row.get('target'), row.get('profile')
            require(type(target) is dict and type(profile) is dict, 'BUILD_ARTIFACT_OBJECT')
            if target.get('name') not in expected:
                require(row.get('manifest_path') != str(package / 'Cargo.toml'),
                        'UNASSIGNED_COMPONENT_EXECUTABLE')
                continue
            role, kind, crate_type, relative, original_profile = expected[target['name']]
            require(target.get('kind') == [kind] and target.get('crate_types') == [crate_type]
                    and target.get('test') is True
                    and target.get('src_path') == str(package / relative)
                    and row.get('manifest_path') == str(package / 'Cargo.toml'),
                    'COMPONENT_TARGET_SOURCE')
            require(profile == original_profile and all(type(profile[key]) is type(value)
                    for key, value in original_profile.items()), 'ORIGINAL_RELEASE_PROFILE_REQUIRED')
            require(type(row.get('filenames')) is list and row['executable'] in row['filenames'],
                    'BUILD_EXECUTABLE_BINDING')
            binary = Path(row['executable'])
            require(binary.is_absolute() and binary.is_relative_to(target_dir)
                    and os.access(binary, os.X_OK), 'FRESH_TARGET_EXECUTABLE_REQUIRED')
            if role == 'cli':
                # Cargo embeds this original path into CARGO_BIN_EXE_trnm-pon-node.
                require(binary == target_dir / 'release/trnm-pon-node', 'ACTUAL_EMBEDDED_CLI_PATH_REQUIRED')
            file_record(binary)
            require(role not in artifacts, 'DUPLICATE_COMPONENT_EXECUTABLE')
            artifacts[role] = (binary, row)
    require(finished and set(artifacts) == {item[0] for item in expected.values()},
            'ALL_ASSIGNED_COMPONENT_EXECUTABLES_REQUIRED')
    return artifacts


def validate_list(raw: str, required: tuple[str, ...], exact: bool = False) -> dict:
    names, totals = [], []
    for line in raw.splitlines():
        if not line:
            continue
        named = re.fullmatch(r'([A-Za-z0-9_:]+): test', line)
        total = re.fullmatch(r'([0-9]+) tests?, 0 benchmarks?', line)
        if named is not None and not totals:
            names.append(named[1])
        elif total is not None and not totals:
            totals.append(int(total[1]))
        else:
            raise ValueError('UNEXPECTED_LIBTEST_LIST_RECORD')
    require(len(names) == len(set(names)) and totals == [len(names)], 'LIBTEST_LIST_COUNT')
    require(set(required).issubset(names) and (not exact or set(required) == set(names)),
            'ASSIGNED_EXACT_CONTROLS_REQUIRED')
    return {'listed_tests': len(names), 'required_tests': list(required), 'exact_roster': exact}


def validate_failed_transcript(raw: str, name: str) -> None:
    state = 'before'
    for line in raw.splitlines():
        if line.startswith('running '):
            require(state == 'before' and line in ('running 1 test', 'running 1 tests'),
                    'ONE_FAILED_INVOCATION_REQUIRED')
            state = 'running'
        elif line.startswith('test result:'):
            require(state == 'named' and re.fullmatch(
                r'test result: FAILED\. 0 passed; 1 failed; 0 ignored; 0 measured; '
                r'[0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s', line) is not None,
                'ONE_NAMED_FAILURE_REQUIRED')
            state = 'finished'
        else:
            match = re.fullmatch(r'test ([A-Za-z0-9_:]+) \.\.\.(?: .*)?', line)
            if match is not None:
                require(state == 'running' and match[1] == name, 'FAILED_TEST_IDENTITY')
                state = 'named'
    require(state == 'finished', 'COMPLETE_FAILED_TRANSCRIPT_REQUIRED')


def history_phase_map(phases: object) -> dict:
    require(type(phases) is list
            and all(type(phase) is dict and type(phase.get('phase')) is str for phase in phases),
            'HISTORY_PHASES_REQUIRED')
    by_phase = {phase['phase']: phase for phase in phases}
    require(len(by_phase) == len(phases), 'DUPLICATE_HISTORY_PHASE')
    return by_phase


def completed_phase(phase: dict, accepted: bool, error: str | None = None) -> bool:
    return (phase.get('started') is True and phase.get('completed') is True
            and phase.get('accepted') is accepted and phase.get('error_code') == error)


def unstarted_phase(phase: dict) -> bool:
    return (phase.get('started') is False and phase.get('completed') is False
            and phase.get('accepted') is None and phase.get('error_code') is None)


def settled_history_flow(flow: object, measured_cpu: int) -> dict:
    require(type(flow) is dict and flow.get('schema') == 'public-v3-local-actual-cpu-flow-v1',
            'ORIGINAL_CPU_ACCOUNT_REQUIRED')
    nonnegative = ('credited_refill_ns', 'discarded_refill_ns', 'live_debited_cpu_ns',
                   'settlement_residual_cpu_ns', 'settled_full_cpu_ns', 'settlement_discard_ns',
                   'paid_cpu_debit_ns')
    zero = ('initial_credit_ns', 'booked_reservation_ns', 'unsettled_known_live_cpu_ns', 'live_owners')
    require(all(type(flow.get(key)) is int and flow[key] >= 0 for key in nonnegative)
            and all(type(flow.get(key)) is int and flow[key] == 0 for key in zero)
            and type(flow.get('termination_reserved_ns', 0)) is int
            and flow.get('termination_reserved_ns', 0) == 0
            and type(flow.get('stored_credit_ns')) is int
            and type(flow.get('remaining_paid_credit_ns')) is int
            and flow.get('balance_identity_verified') is True,
            'ORIGINAL_SETTLED_CPU_FLOW_REQUIRED')
    require(flow['paid_cpu_debit_ns'] >= measured_cpu
            and flow['paid_cpu_debit_ns'] == flow['settled_full_cpu_ns']
            and flow['paid_cpu_debit_ns'] == flow['live_debited_cpu_ns'] + flow['settlement_residual_cpu_ns']
            and flow['stored_credit_ns'] == flow['remaining_paid_credit_ns']
            == flow['credited_refill_ns'] - flow['paid_cpu_debit_ns'] - flow['settlement_discard_ns'],
            'EXACT_ORIGINAL_SETTLED_CPU_IDENTITY_REQUIRED')
    return flow


def history_cpu_observation(cpu: object, balance: int, unavailable: bool) -> None:
    require(type(cpu) is dict and cpu.get('schema') == 'public-v3-local-stored-cpu-budget-v1'
            and cpu.get('accounting_unavailable') is unavailable,
            'ORIGINAL_CPU_OBSERVATION_REQUIRED')
    expected = dict(stored_credit_ns=balance, in_flight=0, burst_ns=2_000_000_000,
                    refill_ns_per_second=250_000_000, start_reserve_ns=100_000_000, worker_limit=2)
    require(all(type(cpu.get(key)) is int and cpu[key] == value for key, value in expected.items()),
            'ORIGINAL_CPU_BUDGET_AND_BALANCE_REQUIRED')


def history_evidence(raw: str, name: str, mode: str) -> dict:
    records = []
    for line in raw.splitlines():
        if '"schema":"history-detached-original-refill-control-v2"' in line:
            records.append(json_load(line[line.index('{'):]))
    require(len(records) == 1, 'ONE_ACTUAL_HISTORY_RECORD_REQUIRED')
    record = records[0]
    require(record.get('schema') == 'history-detached-original-refill-control-v2'
            and record.get('mode') == HISTORY[name]
            and record.get('native_campaign_executed') is False, 'HISTORY_SCOPE_AND_MODE')
    replay = record.get('replay')
    require(type(replay) is dict, 'M06_REPLAY_WAS_NOT_REACHED')
    count, cpu, credit = (replay.get(key) for key in (
        'completed_native_replays', 'actual_thread_cpu_ns', 'projected_paid_credit_ns'))
    require(type(count) is int and count > 0 and type(cpu) is int and cpu > 0
            and type(credit) is int and cpu > credit + 25_000_000,
            'ACTUAL_REPLAY_CPU_DEFICIT_REQUIRED')
    before_close = record.get('before_epoch_close')
    require(type(before_close) is dict, 'PRE_CLOSE_SETTLEMENT_REQUIRED')
    flow = settled_history_flow(before_close.get('flow'), cpu)
    balance = flow['stored_credit_ns']
    history_cpu_observation(before_close.get('cpu'), balance, False)
    history = record.get('history')
    require(type(history) is dict and type(history.get('measurement_failures')) is int
            and history['measurement_failures'] == 0
            and type(history.get('packets')) is list and len(history['packets']) == 1,
            'ACTUAL_HISTORY_PACKET_REQUIRED')
    by_phase = history_phase_map(history['packets'][0].get('phases'))
    page = history_phase_map(history.get('phases'))
    work, execution, commit = (by_phase.get(key, {}) for key in ('work', 'execution', 'commit'))
    require(completed_phase(work, True) and execution.get('started') is True
            and execution.get('completed') is True, 'REAL_W1_AND_M06_REQUIRED')
    require(completed_phase(by_phase.get('cpu_settle', {}), True)
            and completed_phase(page.get('cpu_settle', {}), True),
            'BOTH_ORIGINAL_CPU_SCOPES_SETTLED_REQUIRED')
    dirty = balance < 0
    history_cpu_observation(record.get('after_epoch_close_cpu'), balance, dirty)
    close = page.get('history_epoch_close', {})
    if dirty:
        require(completed_phase(close, False, 'PUBLIC_MUTATION_CPU_UNAVAILABLE')
                and record.get('flow') is None
                and record.get('epoch_marker') == b'active-v1'.hex()
                and record.get('outcome') == {'Err': 'PUBLIC_MUTATION_CPU_UNAVAILABLE'}
                and completed_phase(page.get('history_import', {}), False,
                                    'PUBLIC_MUTATION_CPU_UNAVAILABLE'),
                'KNOWN_DEBT_ORIGINAL_CRASH_FENCE_REQUIRED')
    else:
        final_flow = settled_history_flow(record.get('flow'), cpu)
        require(completed_phase(close, True) and final_flow == flow
                and record.get('epoch_marker') is None, 'CLEAN_ORIGINAL_EPOCH_CLOSE_REQUIRED')
    checks = record.get('refill_resource_checks')
    require(type(checks) is int and checks >= 0, 'REFILL_CHECK_COUNT')
    if mode == 'budget-before-v2':
        require(checks == 0 and completed_phase(execution, False, 'PUBLIC_MUTATION_CPU_BUDGET')
                and unstarted_phase(commit),
                'ORIGINAL_DETACHED_REFUSAL_REQUIRED')
        if not dirty:
            require(record.get('outcome') == {'Err': 'PUBLIC_MUTATION_CPU_BUDGET'}
                    and completed_phase(page.get('history_import', {}), False,
                                        'PUBLIC_MUTATION_CPU_BUDGET'),
                    'ORIGINAL_REFUSAL_OUTCOME_REQUIRED')
    else:
        require(checks > 0, 'ORIGINAL_REFILL_CONTROL_REQUIRED')
        if HISTORY[name] == 'Continue':
            packet_id = history['packets'][0].get('packet_id')
            require(type(packet_id) is list and len(packet_id) == 32
                    and all(type(byte) is int and 0 <= byte <= 255 for byte in packet_id),
                    'ACTUAL_PACKET_ID_REQUIRED')
            require(not dirty and completed_phase(execution, True) and completed_phase(commit, True)
                    and completed_phase(by_phase.get('submit_result', {}), True)
                    and completed_phase(page.get('history_import', {}), True)
                    and record.get('outcome') == {'Ok': bytes(packet_id).hex()},
                    'CONTINUED_IMPORT_REQUIRED')
        else:
            expected = 'PUBLIC_REQUEST_CANCELLED' if HISTORY[name] == 'Cancel' else 'PUBLIC_REQUEST_DEADLINE'
            require(completed_phase(execution, False, expected)
                    and unstarted_phase(commit),
                    'ORIGINAL_CANCELLATION_REQUIRED')
            if not dirty:
                require(record.get('outcome') == {'Err': expected}
                        and completed_phase(page.get('history_import', {}), False, expected),
                        'ORIGINAL_CANCELLATION_OUTCOME_REQUIRED')
    return record


def validate_case(name: str, mode: str, process: dict, stdout: str, stderr: str) -> dict:
    require(name in BUDGET_CONTROLS and mode in ('budget-before-v2', 'fixed'), 'EXACT_CASE_REQUIRED')
    failed = mode == 'budget-before-v2' and name != EQUIVALENCE
    require(process.get('started') is True and process.get('failure') is None
            and process.get('cleanup_errors') == []
            and type(process.get('exit_code')) is int
            and process.get('exit_code') == (101 if failed else 0), 'NATIVE_PROCESS_OUTCOME')
    if failed:
        validate_failed_transcript(stdout, name)
        source = ('ingress/history_import_detached_budget_tests.rs'
                  if name in HISTORY else 'mining_prepare_control_tests.rs')
        panics = re.findall(
            r"thread '([^'\n]+)'(?: \([0-9]+\))? panicked at ([^\n]+):", stderr)
        require(len(panics) == 1 and panics[0][0] == name
                and re.fullmatch(r'[^\n]*crates/trnm-pon-node/src/' + re.escape(source)
                                 + ':' + str(PANIC_LINES[name]) + r':[0-9]+',
                                 panics[0][1]) is not None,
                'EXPECTED_CONTROL_PANIC_SOURCE')
        if name in HISTORY:
            marker = 'detached execution refused actual debt before its original refill control:'
            require(marker in stderr, 'EXPECTED_DETACHED_REFUSAL_ASSERTION')
        elif name == MINING_FAILURES[0]:
            require('assertion failed: error.is(code)' in stderr, 'EXPECTED_PRE_CANCEL_ASSERTION')
        else:
            require('assertion ' + chr(96) + 'left == right' + chr(96) + ' failed' in stderr
                    and re.search(r'\bleft:\s*BeforeStateClone\b', stderr) is not None
                    and re.search(r'\bright:\s*BeforeParentBinding\b', stderr) is not None,
                    'EXPECTED_PARENT_SCAN_ASSERTION')
    else:
        validate_pass(stdout.splitlines(), name)
    record = {'test': name, 'group': 'budget', 'expected': 'fail' if failed else 'pass',
              'expected_outcome_observed': True}
    if name in HISTORY:
        record['history'] = history_evidence(stdout, name, mode)
    return record



def validate_pool_case(name: str, mode: str, process: dict,
                       stdout: str, stderr: str) -> dict:
    require(name in POOL_CONTROLS and mode in ('pool-before', 'fixed'),
            'EXACT_POOL_CASE_REQUIRED')
    failed = mode == 'pool-before' and name in POOL_FAILURES
    require(process.get('started') is True and process.get('failure') is None
            and process.get('cleanup_errors') == []
            and type(process.get('exit_code')) is int
            and process['exit_code'] == (101 if failed else 0),
            'POOL_NATIVE_PROCESS_OUTCOME')
    if failed:
        validate_failed_transcript(stdout, name)
        marker, line, expected_right = POOL_FAILURES[name]
        panics = re.findall(
            r"thread '([^'\n]+)'(?: \([0-9]+\))? panicked at ([^\n]+):",
            stderr)
        require(len(panics) == 1 and panics[0][0] == name
                and re.fullmatch(
                    r'[^\n]*crates/trnm-pon-node/src/pool_run_control_tests\.rs:'
                    + str(line) + r':[0-9]+', panics[0][1]) is not None,
                'EXPECTED_POOL_PANIC_SOURCE')
        require('assertion ' + chr(96) + 'left == right' + chr(96) + ' failed: '
                + marker in stderr, 'EXPECTED_POOL_SIGNAL_ASSERTION')
        left = re.findall(r'^\s*left:\s*([0-9]+)\s*$', stderr, re.M)
        right = re.findall(r'^\s*right:\s*([0-9]+)\s*$', stderr, re.M)
        require(len(left) == len(right) == 1 and int(right[0]) == expected_right,
                'POOL_ASSERTION_VALUES')
        actual = int(left[0])
        require((expected_right == 0 and actual == 2)
                or (expected_right == 256 and actual >= 512 and actual % 256 == 0),
                'ACTUAL_OLD_POOL_WORK_AFTER_SIGNAL_REQUIRED')
    else:
        validate_pass(stdout.splitlines(), name)
    return {'test': name, 'group': 'pool',
            'expected': 'fail' if failed else 'pass',
            'expected_outcome_observed': True}


def validate_pool_scan_case(name: str, mode: str, process: dict,
                            stdout: str, stderr: str) -> dict:
    require(name in POOL_SCAN_CONTROLS and mode in ('pool-scan-before', 'fixed'),
            'EXACT_POOL_SCAN_CASE_REQUIRED')
    failed = mode == 'pool-scan-before'
    require(process.get('started') is True and process.get('failure') is None
            and process.get('cleanup_errors') == []
            and type(process.get('exit_code')) is int
            and process['exit_code'] == (101 if failed else 0),
            'POOL_SCAN_NATIVE_PROCESS_OUTCOME')
    if failed:
        validate_failed_transcript(stdout, name)
        panics = re.findall(
            r"thread '([^'\n]+)'(?: \([0-9]+\))? panicked at ([^\n]+):", stderr)
        require(len(panics) == 1 and panics[0][0] == name
                and re.fullmatch(
                    r'[^\n]*crates/trnm-pon-node/src/pool_reconcile_control_tests\.rs:'
                    + str(POOL_SCAN_PANIC_LINE) + r':[0-9]+', panics[0][1]) is not None,
                'EXPECTED_POOL_SCAN_PANIC_SOURCE')
        marker = 'assertion ' + chr(96) + 'left == right' + chr(96) + ' failed: ' + POOL_SCAN_MARKER
        require(stderr.splitlines().count(marker) == 1, 'EXPECTED_POOL_SCAN_SIGNAL_ASSERTION')
        left = re.findall(r'^\s*left:\s*([0-9]+)\s*$', stderr, re.M)
        right = re.findall(r'^\s*right:\s*([0-9]+)\s*$', stderr, re.M)
        require(left == ['6'] and right == ['2'], 'EXACT_OLD_POOL_SCAN_ROWS_REQUIRED')
    else:
        validate_pass(stdout.splitlines(), name)
    return {'test': name, 'group': 'pool-scan',
            'expected': 'fail' if failed else 'pass',
            'expected_outcome_observed': True}


def validate_pool_integration(raw: str) -> dict:
    state, names = 'before', []
    for line in raw.splitlines():
        if line.startswith('running '):
            require(state == 'before' and line == f'running {len(POOL_INTEGRATION)} tests',
                    'ONE_COMPLETE_POOL_INVOCATION_REQUIRED')
            state = 'running'
        elif line.startswith('test result:'):
            require(state == 'running' and re.fullmatch(
                r'test result: ok\. ' + str(len(POOL_INTEGRATION))
                + r' passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; '
                r'finished in [0-9]+(?:\.[0-9]+)?s', line) is not None,
                'COMPLETE_POOL_INTEGRATION_REQUIRED')
            state = 'finished'
        elif line.startswith('test '):
            match = re.fullmatch(r'test ([A-Za-z0-9_:]+) \.\.\. ok', line)
            require(state == 'running' and match is not None, 'POOL_INTEGRATION_NAMED_PASS_REQUIRED')
            names.append(match[1])
    require(state == 'finished' and len(names) == len(POOL_INTEGRATION)
            and set(names) == set(POOL_INTEGRATION), 'COMPLETE_POOL_INTEGRATION_REQUIRED')
    return {'required_tests': list(POOL_INTEGRATION),
            'passed': len(POOL_INTEGRATION), 'failed': 0, 'ignored': 0}


def validate_source_pair(mode: str, driver_sha: str, source_sha: str) -> None:
    require(all(re.fullmatch(r'[0-9a-f]{40}', value) for value in (driver_sha, source_sha)),
            'EXACT_EXPECTED_SHA_REQUIRED')
    old_shas = {sha for sha, _ in BEFORE_SOURCES.values()}
    require(driver_sha not in old_shas and (
        (mode in BEFORE_SOURCES and source_sha == BEFORE_SOURCES[mode][0])
        or (mode == 'fixed' and source_sha == driver_sha)),
        'GROUP_BEFORE_OR_CURRENT_HEAD_REQUIRED')


def validate_control(name: str, mode: str, process: dict,
                     stdout: str, stderr: str) -> dict:
    require(name in controls_for_mode(mode), 'ASSIGNED_CONTROL_REQUIRED')
    if name in BUDGET_CONTROLS:
        return validate_case(name, mode, process, stdout, stderr)
    if name in POOL_CONTROLS:
        return validate_pool_case(name, mode, process, stdout, stderr)
    if name in POOL_SCAN_CONTROLS:
        return validate_pool_scan_case(name, mode, process, stdout, stderr)
    require(mode == 'fixed' and name in HANDOFF_CONTROLS and successful(process),
            'FIXED_NATIVE_HANDOFF_REQUIRED')
    validate_pass(stdout.splitlines(), name)
    return {'test': name, 'group': 'history-handoff', 'expected': 'pass',
            'expected_outcome_observed': True}


def run(args: argparse.Namespace) -> dict:
    source, out = args.source.resolve(strict=True), args.out.absolute()
    require(out.resolve() == out and not out.is_relative_to(source)
            and not out.is_relative_to(ROOT), 'OUTPUT_OUTSIDE_BOTH_CHECKOUTS')
    out.mkdir(exist_ok=False)
    selected = controls_for_mode(args.mode)
    failures = {'budget-before-v2': 6, 'pool-before': 5, 'pool-scan-before': 2, 'fixed': 0}[args.mode]
    report = {'schema': SCHEMA, 'result': 'FAIL', 'scope': 'assigned-native-component-controls-only',
              'mode': args.mode, 'expected_driver': args.driver_sha, 'expected_source': args.source_sha,
              'groups': list(MODE_GROUPS[args.mode]), 'required_lib_tests': list(selected),
              'commands': [], 'cases': [], 'errors': [], 'source_before': {}, 'source_after': {},
              'executables': {}, 'pool_integration': None,
              'old_source_current_corpus_qualification': False,
              'expected_passes': len(selected) - failures, 'expected_failures': failures,
              'expected_integration_passes': len(POOL_INTEGRATION) if args.mode == 'fixed' else 0,
              **dict.fromkeys(FALSE_FLAGS, False)}
    env, executable_paths = dict(os.environ), {}

    def checked(command: list[str], label: str, cwd: Path = source) -> str:
        result = capture(command, cwd, out, label, env)
        report['commands'].append(result)
        require(successful(result), label.upper() + '_FAILED')
        return (out / (label + '.stdout')).read_text()

    try:
        validate_source_pair(args.mode, args.driver_sha, args.source_sha)
        require(source != ROOT and not source.is_relative_to(ROOT) and not ROOT.is_relative_to(source),
                'INDEPENDENT_SOURCE_AND_DRIVER_CHECKOUTS')
        for label, root, sha in (('driver', ROOT, args.driver_sha), ('subject', source, args.source_sha)):
            try:
                identity = verify_source('head', sha, root=root)
            except BaseException as error:
                write(out / (label + '-source-before-error.json'), {
                    'schema': 'pon-component-source-check-failure-v1',
                    'expected_commit': sha, 'verified': False,
                    'error': type(error).__name__ + ': ' + str(error)})
                raise
            report['source_before'][label] = identity
            write(out / (label + '-source-before.json'), identity)
            checked(['bash', 'scripts/project-preflight.sh', '--audit'], label + '-preflight', root)
        if args.mode in BEFORE_SOURCES:
            require(report['source_before']['subject']['tested_tree'] == BEFORE_SOURCES[args.mode][1],
                    'EXACT_GROUP_BEFORE_TREE_REQUIRED')
        inputs = {}
        for group, relatives in same_input_groups(args.mode).items():
            inputs[group] = {}
            for relative in relatives:
                actual, current = file_record(source / relative), file_record(ROOT / relative)
                require(actual['sha256'] == current['sha256'], 'IDENTICAL_GROUP_TESTS_LOCK_AND_PROFILE_REQUIRED')
                inputs[group][relative] = {'subject': actual, 'driver': current}
        report['identical_group_inputs'] = inputs
        if args.mode == 'fixed':
            report['fixed_only_inputs'] = {relative: file_record(source / relative)
                                           for relative in FIXED_ONLY_INPUTS}
        require(tomllib.loads((source / 'rust-toolchain.toml').read_text())['toolchain']['channel']
                == '1.95.0', 'ORIGINAL_TOOLCHAIN_PIN')
        require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'NATIVE_X64_LINUX_REQUIRED')
        altered = [key for key, value in env.items() if value and (
            key.startswith('CARGO_PROFILE_') or key.endswith('_RUSTFLAGS')
            or key in ('RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_TARGET'))]
        require(not altered, 'BUILD_OVERRIDE_REFUSED:' + ','.join(altered))
        require(env.get('CARGO_BUILD_JOBS') == '1' and env.get('CARGO_INCREMENTAL') == '0',
                'ONE_ORIGINAL_RELEASE_BUILD_WORKER_REQUIRED')
        target = Path(env['CARGO_TARGET_DIR'])
        require(target.is_absolute() and target.resolve() == target and not target.exists()
                and not target.is_relative_to(source) and not target.is_relative_to(ROOT),
                'FRESH_EXTERNAL_TARGET_REQUIRED')
        target.mkdir()
        cargo_home = Path(env['CARGO_HOME'])
        require(cargo_home.is_absolute() and cargo_home.resolve() == cargo_home
                and not cargo_home.is_relative_to(source) and not cargo_home.is_relative_to(ROOT)
                and not any((cargo_home / name).exists() for name in ('config', 'config.toml')),
                'EXTERNAL_CARGO_HOME_WITHOUT_OVERRIDE_REQUIRED')
        rustc = Path(checked(['rustup', 'which', '--toolchain', '1.95.0', 'rustc'], 'rustc-path').strip()).resolve(strict=True)
        env['RUSTC'] = str(rustc)
        rustc_version = checked([str(rustc), '-Vv'], 'rustc-version')
        cargo_version = checked(['cargo', '+1.95.0', '-Vv'], 'cargo-version')
        require(re.findall(r'^release: (.+)$', rustc_version, re.M) == ['1.95.0']
                and re.findall(r'^release: (.+)$', cargo_version, re.M) == ['1.95.0'],
                'ACTUAL_COMPILER_AND_CARGO_195_REQUIRED')
        report['build_environment'] = {key: env.get(key) for key in (
            'CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL',
            'RUSTC', 'RUSTUP_TOOLCHAIN', 'LD_LIBRARY_PATH')}
        report['runner_environment'] = {key: env.get(key) for key in (
            'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB', 'GITHUB_EVENT_NAME',
            'RUNNER_NAME', 'RUNNER_ARCH', 'RUNNER_OS', 'ImageOS', 'ImageVersion')}
        checked(['cargo', '+1.95.0', 'metadata', '--locked', '--manifest-path',
                 'trillionnium/Cargo.toml', '--format-version', '1'], 'cargo-graph')
        build = checked(build_command(args.mode), 'build')
        built_artifacts = select_binaries(build, source, target, args.mode)
        write(out / 'compiler-artifacts.json', {role: artifact
              for role, (_, artifact) in built_artifacts.items()})
        for role, (built, artifact) in built_artifacts.items():
            initial = file_record(built)
            binary = out / ('trnm-pon-node-' + role)
            with built.open('rb') as original, binary.open('xb') as retained:
                shutil.copyfileobj(original, retained)
            binary.chmod(0o500)
            copied = file_record(binary)
            require(copied['sha256'] == initial['sha256'] and copied['bytes'] == initial['bytes'],
                    'BINARY_CAPTURE_CHANGED')
            report['executables'][role] = {'compiler_artifact': artifact,
                'built_before': initial, 'retained_before': copied,
                'execution_path': str(built if role == 'cli' else binary)}
            executable_paths[role] = (built, binary)
        binary = executable_paths['libtest'][1]
        listing = checked([str(binary), '--list', '--format=pretty'], 'libtest-list')
        report['libtest_list'] = validate_list(listing, selected)
        if args.mode == 'fixed':
            integration_binary = executable_paths['pool-integration'][1]
            listing = checked([str(integration_binary), '--list', '--format=pretty'], 'pool-integration-list')
            report['pool_integration_list'] = validate_list(listing, POOL_INTEGRATION, exact=True)
        for index, name in enumerate(selected):
            label = f'test-{index + 1:02d}'
            command = [str(binary), '--exact', name, '--nocapture', '--test-threads=1']
            process = capture(command, source, out, label, env)
            case = {'test': name, 'process': process, 'expected_outcome_observed': False}
            try:
                case.update(validate_control(name, args.mode, process,
                    (out / (label + '.stdout')).read_text(), (out / (label + '.stderr')).read_text()))
            except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
                case['error'] = type(error).__name__ + ': ' + str(error)
                report['errors'].append(name + ': ' + case['error'])
            report['cases'].append(case)
            write(out / 'report.json', report)
        if args.mode == 'fixed':
            label = 'pool-integration'
            command = [str(integration_binary), '--test-threads=1', '--format=pretty']
            process = capture(command, source, out, label, env)
            integration = {'process': process, 'expected_outcome_observed': False}
            try:
                require(successful(process), 'POOL_INTEGRATION_PROCESS_REQUIRED')
                integration.update(validate_pool_integration((out / (label + '.stdout')).read_text()))
                integration['expected_outcome_observed'] = True
            except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
                integration['error'] = type(error).__name__ + ': ' + str(error)
                report['errors'].append(label + ': ' + integration['error'])
            report['pool_integration'] = integration
            write(out / 'report.json', report)
        require(len(report['cases']) == len(selected) and all(
            case['expected_outcome_observed'] for case in report['cases']), 'ALL_ASSIGNED_OUTCOMES_REQUIRED')
    except BaseException as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        for role, (built, retained) in executable_paths.items():
            try:
                record = report['executables'][role]
                record['built_after'] = file_record(built)
                record['retained_after'] = file_record(retained)
                require(record['built_before'] == record['built_after']
                        and record['retained_before'] == record['retained_after'],
                        'EXECUTED_BINARY_CHANGED:' + role)
            except BaseException as error:
                report['errors'].append(role + '-binary-after: ' + type(error).__name__ + ': ' + str(error))
        report['native_control_processes_started'] = sum(
            case['process'].get('started') is True for case in report['cases'])
        report['matched_pass_controls'] = sum(
            case.get('expected_outcome_observed') is True and case.get('expected') == 'pass'
            for case in report['cases'])
        report['matched_failure_controls'] = sum(
            case.get('expected_outcome_observed') is True and case.get('expected') == 'fail'
            for case in report['cases'])
        report['native_pool_integration_process_started'] = (
            report['pool_integration'] is not None
            and report['pool_integration']['process'].get('started') is True)
        for label, root, sha in (('driver', ROOT, args.driver_sha), ('subject', source, args.source_sha)):
            try:
                identity = verify_source('head', sha, root=root)
                report['source_after'][label] = identity
                write(out / (label + '-source-after.json'), identity)
                require(identity == report['source_before'].get(label), 'SOURCE_CHANGED:' + label)
            except BaseException as error:
                failure = label + '-source-after: ' + type(error).__name__ + ': ' + str(error)
                report['errors'].append(failure)
                write(out / (label + '-source-after-error.json'), {
                    'schema': 'pon-component-source-check-failure-v1',
                    'expected_commit': sha, 'verified': False, 'error': failure})
        if not report['errors']:
            report['result'] = 'PASS'
        write(out / 'report.json', report)
    return report



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--driver-sha', required=True)
    parser.add_argument('--mode', required=True, choices=tuple(MODE_GROUPS))
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    try:
        report = run(args)
    except (OSError, ValueError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps({'schema': SCHEMA, 'result': report['result'], 'mode': args.mode,
                      'report': str(args.out / 'report.json'), **dict.fromkeys(FALSE_FLAGS, False)}))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
