#!/usr/bin/env python3
"""Run the separate SP27-02 balanced strata campaign in the unchanged public Host.

The controller distinguishes successful collection from business qualification.
Each native phase keeps the original four-second deadline.  A failed healthy
control stops the native experiment before any pressure data are collected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

import public_fixture_host_lease as lease
import run_from_zero_native as native
import run_history_native as history
from check_required_native_test import validate as named_test
from public_host_ci_observation import write_new
from replay_pinned_native import require

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = 'scripts/ci/run_sp27_strata_controls.py'
SELECTOR = 'sp27_receiver_campaign::balanced_native_stage_controls_stop_on_unhealthy_sentinel'
MODULE = 'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_controls.rs'
SCHEMA = 'sp27-native-strata-execution-v1'
PREPARATION = 'sp27-native-strata-preparation-v1'
STRATA_MODULE = 'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_strata.rs'
CAMPAIGN_MODULE = 'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_campaign.rs'
NATIVE_TIMEOUT_SECONDS = 90


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_identity() -> dict:
    actual = lease.workflow_source()
    return {'commit': actual['tested_commit'], 'tree': actual['tested_tree'],
            'tracked_source_identity': actual,
            'files_sha256': {p: digest(ROOT / p) for p in (
                native.SOURCE, MODULE, STRATA_MODULE, CAMPAIGN_MODULE, SCRIPT, 'config/systemd/trnmponpublic.slice',
                'trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs')}}


def output_path(out: Path) -> Path:
    receipts = Path(os.environ.get('TRNM_CI_RECEIPT_DIR', ''))
    require(receipts.is_absolute() and receipts.resolve(strict=True) == receipts
            and out == receipts / 'sp27-receiver-strata'
            and out.is_absolute() and out.resolve() == out
            and not out.is_relative_to(ROOT), 'SP27_EXACT_OUTPUT_REQUIRED')
    return out


def prepare(out: Path) -> dict:
    output_path(out).mkdir(exist_ok=False)
    result = {'schema': PREPARATION, 'job': history.job_identity(),
              'source_before': None, 'source_after': None, 'binary': None,
              'build': None, 'failures': [], 'completed': False,
              'native_tests_executed': False}
    try:
        result['source_before'] = source_identity()
        result['build'] = native.run_child(native.native_build_command(), out / 'build', 900)
        require(result['build']['exit_code'] == 0 and not result['build']['timed_out'],
                'SP27_SOURCE_BUILD_FAILED')
        binary = native.select_binary((out / 'build/stdout').read_text().splitlines())
        result['binary'], _ = history.file_observation(binary, history.BINARY_LIMIT)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['failures'].append(type(error).__name__ + ':' + str(error))
    finally:
        try:
            result['source_after'] = source_identity()
            require(result['source_before'] == result['source_after'], 'SP27_SOURCE_CHANGED')
        except (OSError, ValueError, KeyError, TypeError) as error:
            result['failures'].append(type(error).__name__ + ':' + str(error))
        result['completed'] = not result['failures'] and result['binary'] is not None
        write_new(out / 'preparation.json', result)
    return result


def validate_preparation(out: Path) -> dict:
    output_path(out)
    value, _ = history.load_object(out / 'preparation.json')
    require(value.get('schema') == PREPARATION and value.get('completed') is True
            and value.get('failures') == [] and value.get('native_tests_executed') is False
            and value.get('job') == history.job_identity(), 'SP27_PREPARATION_REQUIRED')
    require(value['source_before'] == value['source_after'] == source_identity(),
            'SP27_PREPARATION_SOURCE_CHANGED')
    build = value['build']
    require(build['command'] == native.native_build_command()
            and build['exit_code'] == 0 and build['timed_out'] is False
            and build['stdout_sha256'] == digest(out / 'build/stdout')
            and build['stderr_sha256'] == digest(out / 'build/stderr'), 'SP27_BUILD_CHANGED')
    binary = native.select_binary((out / 'build/stdout').read_text().splitlines())
    require(history.file_observation(binary, history.BINARY_LIMIT)[0] == value['binary'],
            'SP27_BINARY_CHANGED')
    return value


def exact_integer(value, expected: int) -> bool:
    # JSON booleans and floats compare equal to Python integers, but do not
    # satisfy the native collector's serde_json::Value::as_u64() checks.
    return type(value) is int and value == expected


def declared_run_id(job: dict) -> str:
    return '-'.join(job[key] for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB'))



ARMS = ('transport', 'early-reject', 'late-reject', 'valid-expensive')
ORDER = (0, 1, 2, 3, 3, 2, 1, 0)
WINDOW_NS = 4_000_000_000
RECORD_LIMIT = 32 * 1024 * 1024


def same_json(left, right) -> bool:
    return json.dumps(left, sort_keys=True, separators=(',', ':')) == json.dumps(
        right, sort_keys=True, separators=(',', ':'))


def expect(value: dict, fields: dict, code: str) -> None:
    require(type(value) is dict and all(key in value and same_json(value[key], item)
                                      for key, item in fields.items()), code)


def unsigned(value) -> bool:
    return type(value) is int and 0 <= value < 2 ** 64


def encoded(value, length=None) -> bool:
    return (type(value) is str and bool(value) and len(value) % 2 == 0
            and (length is None or len(value) == length)
            and all(char in '0123456789abcdef' for char in value))


def planned_phases() -> list[dict]:
    descriptions = [(f'health-{i:03}', 'initial-health', None, i, None) for i in range(3)]
    for index, arm in enumerate(ORDER):
        descriptions.append((f'control-{index:03}-{ARMS[arm]}', 'pressure-control', ARMS[arm], None, index))
        if index in (3, 7):
            health = 3 if index == 3 else 4
            descriptions.append((f'health-{health:03}', 'midpoint-sentinel' if index == 3
                                 else 'terminal-sentinel', None, health, None))
    return [{'planned_index': index, 'phase_id': identity, 'kind': kind, 'arm': arm,
             'health_index': health, 'control_index': control, 'requested_window_ns': WINDOW_NS,
             'workers_max': 16 if arm else 0, 'per_worker_attempt_cap': 1 if arm else 0,
             'control_scheduled_arrival_ns': 100_000_000 if arm else None}
            for index, (identity, kind, arm, health, control) in enumerate(descriptions)]


def native_business(phase: dict) -> bool:
    gate, count, end = (phase.get(key) for key in (
        'client_confirmed_before_original_window_end', 'client_confirmed_transactions',
        'confirmation_ended_ns'))
    require(type(gate) is bool and exact_integer(count, int(gate))
            and (end is None or unsigned(end)), 'SP27_STRATA_BUSINESS_TYPES')
    require(not gate or (unsigned(end) and end < WINDOW_NS),
            'SP27_STRATA_NATIVE_FINAL_GATE_CONTRADICTION')
    return gate


def healthy(phase: dict) -> bool:
    return (exact_integer(phase.get('requested_window_ns'), WINDOW_NS)
            and exact_integer(phase.get('workers'), 0)
            and all(phase.get(key) is True for key in (
                'invariant_target_met', 'finite_business_target_met',
                'client_confirmed_before_original_window_end', 'full_native_state_equal'))
            and exact_integer(phase.get('client_confirmed_transactions'), 1)
            and unsigned(phase.get('confirmation_ended_ns'))
            and phase['confirmation_ended_ns'] < WINDOW_NS
            and phase.get('verification_errors') == [])


def observed_stage(record: dict, arm: str) -> tuple[bool, bool, bool]:
    phases = record.get('submit_phases')
    require(type(phases) is list and all(type(row) is dict for row in phases)
            and len({row.get('phase') for row in phases}) == len(phases),
            'SP27_STRATA_OBSERVED_PHASES')
    by_name = {row.get('phase'): row for row in phases}

    def accepted(name):
        row = by_name.get(name, {})
        return all(row.get(key) is True for key in ('started', 'completed', 'accepted'))

    def refused(name):
        row = by_name.get(name, {})
        return row.get('started') is True and row.get('completed') is True and row.get('accepted') is False

    def unstarted(name):
        return by_name.get(name, {}).get('started') is False

    def message(expected):
        diagnostics = record.get('error_diagnostics')
        dispatch = diagnostics.get('dispatch') if type(diagnostics) is dict else None
        return (type(dispatch) is dict and dispatch.get('message_prefix') == expected
                and dispatch.get('message_truncated') is False)

    rejection = record.get('work_rejection')
    rejection = rejection if type(rejection) is dict else {}
    cache = rejection.get('cache')
    cache = cache if type(cache) is dict else {}
    full = (rejection.get('completed') is True
            and all(cache.get(key) is True for key in (
                'native_verifier_started', 'native_verifier_returned', 'full_replay_started'))
            and cache.get('cached_rejection_returned') is False)
    checked = accepted('body_decode')
    reached = checked and {
        'transport': (refused('decode') and by_name.get('decode', {}).get('error_code') == 'HEADER_CODEC'
                      and unstarted('context') and unstarted('work')),
        'early-reject': (accepted('decode') and refused('context') and unstarted('work')
                         and record.get('full_work_started') is False and message('WORK:Task')),
        'late-reject': (accepted('context') and refused('work') and full and message('WORK:Transcript')),
        'valid-expensive': (accepted('work') and full and record.get('full_work_accepted') is True
                            and record.get('dispatch_accepted') is True and accepted('submit_result')),
    }[arm]
    return checked, full, reached


def pressure_integrity(phase: dict, arm: str, requests: list[str]) -> bool:
    expect(phase, {'schema': 'sp27-native-stage-control-phase-v1', 'mode': arm,
                  'requested_window_ns': WINDOW_NS, 'workers': 16}, 'SP27_STRATA_PRESSURE_SCOPE')
    expect(phase.get('arrival_plan'), {
        'workers': 16, 'attempts_per_worker': 1, 'scheduled_start_ns': 100_000_000,
        'retries': 0, 'business_waits_for_pressure_completion': False},
        'SP27_STRATA_ARRIVAL_PLAN')
    workers = phase.get('attacks')
    require(type(workers) is list and len(workers) == 16, 'SP27_STRATA_WORKER_ROSTER')
    calls = []
    for index, worker in enumerate(workers):
        expect(worker, {'worker': index, 'planned_attempts': 1}, 'SP27_STRATA_WORKER_IDENTITY')
        require(type(worker.get('calls')) is list and len(worker['calls']) == 1,
                'SP27_STRATA_SINGLE_ATTEMPT')
        call = worker['calls'][0]
        expect(call, {'packet_index': index, 'attempt_index': 0, 'scheduled_start_ns': 100_000_000},
               'SP27_STRATA_OFFERING_IDENTITY')
        ready = call.get('offering_thread_ready_ns')
        require(unsigned(ready) and exact_integer(call.get('offering_lateness_ns'),
                                                 max(0, ready - 100_000_000)),
                'SP27_STRATA_OFFERING_CLOCK')
        calls.append(call)
    no_acceptance = all(call.get('status') != 'ok' for call in calls)
    require(phase.get('no_attack_accepted') is no_acceptance, 'SP27_STRATA_ACCEPTANCE_MISMATCH')
    captured = phase.get('observations')
    require(type(captured) is dict and type(captured.get('records')) is list
            and all(type(row) is dict for row in captured['records']),
            'SP27_STRATA_OBSERVATIONS_REQUIRED')
    coverage = (exact_integer(captured.get('records_not_retained'), 0)
                and exact_integer(captured.get('measurement_failures'), 0)
                and captured.get('counter_overflow') is False
                and exact_integer(captured.get('accepted_connections_seen'), len(captured['records']))
                and all(type(row) is dict and row.get('complete') is True
                        and row.get('observation_failed') is False for row in captured['records']))
    service = phase.get('service')
    require(type(service) is dict, 'SP27_STRATA_SERVICE_REQUIRED')
    metrics = service.get('metrics')
    metrics = metrics if type(metrics) is dict else {}
    costs = [metrics.get(key) for key in ('mutation_cpu_charged_ns',
             'mutation_full_work_cpu_ns', 'mutation_dispatch_excluding_work_cpu_ns')]
    accounting = (all(unsigned(value) for value in costs) and costs[1] + costs[2] == costs[0]
                  and unsigned(metrics.get('work_started'))
                  and exact_integer(metrics.get('work_finished'), metrics.get('work_started'))
                  and exact_integer(metrics.get('mutation_cpu_clock_failures'), 0))
    require(phase.get('accounting_closed') is accounting, 'SP27_STRATA_ACCOUNTING_MISMATCH')
    invariant = ((arm == 'valid-expensive' or no_acceptance) and coverage and accounting
                 and service.get('error') is None
                 and phase.get('receiver_matches_valid_honest_prefix') is True)
    require(phase.get('invariant_target_met') is invariant, 'SP27_STRATA_INVARIANT_MISMATCH')
    stage = phase.get('stage_readback')
    expect(stage, {'schema': 'sp27-native-stage-readback-v1', 'arm': arm,
                   'planned_offerings': 16}, 'SP27_STRATA_STAGE_SCHEMA')
    offered = sum(unsigned(call.get('started_ns')) for call in calls)
    require(exact_integer(stage.get('actual_calls_started'), offered)
            and type(stage.get('matched_records')) is list
            and exact_integer(stage.get('matched_claimed_body_connections'), len(stage['matched_records'])),
            'SP27_STRATA_STAGE_DENOMINATORS')
    body_digests = [native.H('public-request-body-v3', json.dumps(
        {'op': 'submit', 'packet': wire}, separators=(',', ':')).encode()).hex() for wire in requests]
    witnesses, unexpected = [], False
    for record in captured['records']:
        digest_bytes = record.get('body_digest')
        if digest_bytes is None:
            continue
        require(type(digest_bytes) is list and len(digest_bytes) == 32
                and all(type(value) is int and 0 <= value <= 255 for value in digest_bytes),
                'SP27_STRATA_OBSERVER_BODY_DIGEST')
        body_digest = bytes(digest_bytes).hex()
        if body_digest not in body_digests:
            continue
        checked, full, reached = observed_stage(record, arm)
        unexpected |= arm != 'valid-expensive' and record.get('dispatch_accepted') is True
        unexpected |= arm in ('transport', 'early-reject') and record.get('full_work_started') is True
        witnesses.append({'packet_index': body_digests.index(body_digest),
            'connection_id': record.get('connection_id'), 'body_digest': body_digest,
            'actual_body_checked': checked, 'target_stage_attained': reached,
            'full_native_replay_observed': full,
            **{key: record.get(key) for key in ('dispatch_accepted', 'lifecycle',
                'paid_task_queue_wait', 'work_rejection', 'submit_phases',
                'terminal_phase', 'terminal_error_code')}})
    require(same_json(stage['matched_records'], witnesses), 'SP27_STRATA_STAGE_WITNESS_CHANGED')
    attained = sum(row['target_stage_attained'] for row in witnesses)
    require(exact_integer(stage.get('target_stage_attained'), attained),
            'SP27_STRATA_STAGE_COUNT_MISMATCH')
    identifiable = offered == 16 and attained > 0
    require(stage.get('input_stage_identifiable') is identifiable
            and stage.get('unexpected_stage_or_acceptance') is unexpected,
            'SP27_STRATA_STAGE_QUALIFICATION_MISMATCH')
    integrity = invariant and identifiable and not stage['unexpected_stage_or_acceptance']
    require(phase.get('control_integrity_met') is integrity, 'SP27_STRATA_INTEGRITY_MISMATCH')
    return integrity


def read_campaign(out: Path, prepared: dict) -> tuple[dict, dict, dict]:
    readback = {}

    def read_record(name: str) -> dict:
        observed, raw = history.file_observation(out / 'native' / name, RECORD_LIMIT, retain=True)
        value = native.json_load(raw)
        require(type(value) is dict, 'SP27_STRATA_JSON_OBJECT')
        readback[name] = observed
        return value

    def host_record(name: str, claimed) -> bool:
        host = read_record(name)
        expect(host, {'schema': 'sp27-receiver-host-readback-v1',
                      'fixed_parent': '/sys/fs/cgroup/trnmponpublic.slice'}, 'SP27_STRATA_HOST_SCOPE')
        require(type(claimed) is bool and host.get('verified') is claimed,
                'SP27_STRATA_HOST_MISMATCH')
        require((claimed and type(host.get('sample')) is dict and host.get('error') is None)
                or (not claimed and host.get('sample') is None
                    and type(host.get('error')) is str and bool(host['error'])),
                'SP27_STRATA_HOST_OBSERVATION')
        return claimed

    report = read_record('report.json')
    report_file = readback.pop('report.json')
    expect(report, {'schema': 'sp27-receiver-strata-campaign-v1',
                    'planned_phases': 13, 'planned_health_repetitions': 3, 'planned_sentinels': 2,
                    'pressure_controls_planned': 8, 'balanced_arm_indices': list(ORDER),
                    'requested_window_ns': WINDOW_NS, 'mechanism_status': 'UNKNOWN',
                    'causal_mechanism_status': 'UNKNOWN', 'publication_qualified': False,
                    'public_network_ready': False, 'production_activation': False},
           'SP27_STRATA_CAMPAIGN_SCOPE')
    require(report.get('qualification') in ('NO_GO', 'COLLECTED_CONTROL_SERIES'),
            'SP27_STRATA_QUALIFICATION')
    planned = planned_phases()
    plan = read_record('plan.json')
    expect(plan, {'schema': 'sp27-receiver-strata-campaign-plan-v1', 'planned_phases': planned,
                  'initial_health_repetitions': 3, 'control_phase_count': 8, 'sentinel_count': 2,
                  'arm_names': list(ARMS), 'balanced_arm_indices': list(ORDER),
                  'same_seven_signed_packets': True, 'confirmation_depth': 6,
                  'requested_window_ns': WINDOW_NS, 'pressure_workers_max': 16,
                  'pressure_per_worker_attempt_cap': 1, 'control_scheduled_arrival_ns': 100_000_000,
                  'global_per_worker_attempt_ceiling': 1024, 'outer_selector_timeout_seconds': 90,
                  'fixed_parent': '/sys/fs/cgroup/trnmponpublic.slice',
                  'required_cpu_quota_us': 25000, 'required_cpu_period_us': 100000,
                  'required_memory_bytes': 2147483648, 'required_swap_bytes': 0},
           'SP27_STRATA_PLAN_CHANGED')
    source, binary, job = prepared['source_before'], prepared['binary'], prepared['job']
    binding = {'binary_path': binary['path'], 'binary_sha256': binary['sha256'],
               'runner_declared_source_sha': source['commit'], 'runner_declared_run_id': declared_run_id(job),
               'github_run_id': job['GITHUB_RUN_ID'], 'github_run_attempt': job['GITHUB_RUN_ATTEMPT']}
    for field, path in (('compiled_test_source_sha256', native.SOURCE),
                        ('compiled_health_module_sha256', MODULE),
                        ('compiled_strata_module_sha256', STRATA_MODULE),
                        ('compiled_campaign_module_sha256', CAMPAIGN_MODULE)):
        binding[field] = source['files_sha256'][path]
    identities = [read_record(f'identity-{when}.json') for when in ('before', 'after')]
    for identity in identities:
        expect(identity, {'schema': 'sp27-receiver-run-identity-v1',
                          'binary_identity_error': None, **binding}, 'SP27_STRATA_BUILD_RUN_BINDING')
        require(unsigned(identity.get('pid')) and identity['pid'] > 0
                and all(type(identity.get(key)) is str and bool(identity[key])
                        for key in ('hostname', 'boot_id', 'process_cgroup')),
                'SP27_STRATA_PROCESS_IDENTITY')
    require(all(same_json(identities[0][key], identities[1][key])
                for key in ('pid', 'hostname', 'boot_id', 'process_cgroup'))
            and report.get('binary_unchanged') is True, 'SP27_STRATA_IDENTITY_CHANGED')
    before_ok = host_record('host-before.json', report.get('host_before_verified'))
    after_ok = host_record('host-after.json', report.get('host_after_verified'))
    records = report.get('phases')
    require(type(records) is list and len(records) <= 13
            and exact_integer(report.get('attempted_phases'), len(records)), 'SP27_STRATA_ATTEMPTED_COUNT')
    if records or (out / 'native/business-acquisition.json').exists():
        acquisition = read_record('business-acquisition.json')
        expect(acquisition, {'schema': 'sp27-receiver-seven-packet-acquisition-v1',
                            'same_seven_packets_in_all_health_phases': True}, 'SP27_STRATA_BUSINESS_ACQUISITION')
        packets, ids = acquisition.get('signed_honest_packets'), acquisition.get('packet_ids')
        require(type(packets) is list and len(packets) == 7 and all(encoded(p) for p in packets)
                and type(ids) is list and len(ids) == 7 and all(encoded(p, 64) for p in ids),
                'SP27_STRATA_SEVEN_PACKETS')
        read_record('business-acquisition-started.json')
    require(before_ok or not records, 'SP27_STRATA_ATTEMPT_AFTER_GLOBAL_HOST_FAILURE')
    inputs_acquired = report.get('control_inputs_acquired')
    require(type(inputs_acquired) is bool, 'SP27_STRATA_INPUT_ACQUISITION_FLAG')
    streams = []
    if inputs_acquired:
        read_record('strata-acquisition-started.json')
        input_index = read_record('strata-inputs-index.json')
        expect(input_index, {'schema': 'sp27-receiver-control-input-index-v1',
                             'same_request_streams_for_balanced_repeats': True}, 'SP27_STRATA_INPUT_INDEX')
        require(type(input_index.get('inputs')) is list and len(input_index['inputs']) == 4,
                'SP27_STRATA_INPUT_ARMS')
        acquisition = read_record('strata-input-acquisition-native.json')
        expect(acquisition, {'schema': 'sp27-strata-input-acquisition-v1', 'arms': list(ARMS),
                            'workers_per_arm': 16, 'calls_per_worker': 1,
                            'valid_expensive_is_not_a_pure_W1_intervention': True},
               'SP27_STRATA_INPUT_SCOPE')
        require(type(acquisition.get('inputs')) is list and len(acquisition['inputs']) == 4,
                'SP27_STRATA_INPUT_IDENTITIES')
        for index, arm in enumerate(ARMS):
            name = f'inputs/arm-{index:03}.json'
            stream = read_record(name)
            expect(stream, {'schema': 'sp27-receiver-control-request-stream-v1',
                            'arm_index': index, 'arm': arm, 'request_count': 16}, 'SP27_STRATA_INPUT_STREAM')
            requests = stream.get('requests')
            require(type(requests) is list and len(requests) == 16 and all(encoded(v) for v in requests)
                    and len(set(requests)) == 16
                    and exact_integer(stream.get('packet_hex_bytes'), sum(len(v) for v in requests)),
                    'SP27_STRATA_INPUT_REQUESTS')
            streams.append(requests)
            expect(input_index['inputs'][index], {'arm_index': index, 'arm': arm, 'raw_record': name,
                   'sha256': readback[name]['sha256'], 'request_count': 16}, 'SP27_STRATA_INPUT_SHA')
            require(same_json(stream.get('canonical_submit_body_bytes'), [len(json.dumps(
                {'op': 'submit', 'packet': wire}, separators=(',', ':')).encode()) for wire in requests]),
                    'SP27_STRATA_CANONICAL_BODY_LENGTHS')
            values = acquisition['inputs'][index]
            require(type(values) is list and len(values) == 16, 'SP27_STRATA_INPUT_IDENTITIES')
            for wire, value in zip(requests, values):
                body = json.dumps({'op': 'submit', 'packet': wire}, separators=(',', ':')).encode()
                expect(value, {'packet_hex': wire, 'request_bytes': len(body),
                               'body_digest': native.H('public-request-body-v3', body).hex(),
                               'recorded_request_digest': native.H('pressure-recorded-request-v1', body).hex()},
                       'SP27_STRATA_INPUT_DIGEST')
                require(exact_integer(acquisition.get('canonical_submit_body_bytes_each'), len(body)),
                        'SP27_STRATA_EQUAL_BODY_LENGTH')
    health_rows, controls, completed, invoked, stopped = [], [], 0, 0, False
    allowed_raw = set()
    for index, row in enumerate(records):
        require(not stopped, 'SP27_STRATA_CONTINUED_AFTER_STOP')
        expect(row, planned[index], 'SP27_STRATA_PHASE_PLAN')
        expect(row, {'attempted': True}, 'SP27_STRATA_PHASE_ATTEMPT')
        prefix = 'raw/' + planned[index]['phase_id']
        expected_names = [prefix + suffix for suffix in ('-started.json', '-host-before.json',
                                                          '-host-after.json', '-index.json')]
        started = read_record(expected_names[0])
        expect(started, {'schema': 'sp27-receiver-campaign-phase-started-v1',
                         'status': 'STARTED_NOT_YET_OBSERVED_COMPLETE'}, 'SP27_STRATA_START_MARKER')
        expect(started.get('plan'), {**planned[index], 'attempted': True, 'helper_invoked': False,
               'completed': False, 'raw_phase_record': None, 'raw_phase_sha256': None}, 'SP27_STRATA_STARTED_PLAN')
        actual_index = read_record(prefix + '-index.json')
        require(same_json(actual_index, row), 'SP27_STRATA_PHASE_INDEX_CHANGED')
        phase_before = host_record(prefix + '-host-before.json', row.get('host_before_verified'))
        phase_after = host_record(prefix + '-host-after.json', row.get('host_after_verified'))
        require(type(row.get('completed')) is bool and type(row.get('helper_invoked')) is bool
                and row['helper_invoked'] is phase_before, 'SP27_STRATA_PHASE_INVOCATION')
        if row['helper_invoked']:
            invoked += 1
            expected_names.append(prefix + '-invoked.json')
            expect(read_record(prefix + '-invoked.json'), {
                'schema': 'sp27-receiver-campaign-phase-invoked-v1',
                'phase_id': planned[index]['phase_id'], 'planned_index': index,
                'requested_window_ns': WINDOW_NS, 'helper_invoked': True}, 'SP27_STRATA_INVOKED_MARKER')
        passed = False
        if row['completed']:
            require(row['helper_invoked'], 'SP27_STRATA_UNINVOKED_COMPLETION')
            completed += 1
            name = prefix + '.json'
            expected_names.append(name)
            phase = read_record(name)
            expect(row, {'raw_phase_record': name, 'raw_phase_sha256': readback[name]['sha256'],
                         'business_result_is_not_campaign_integrity': planned[index]['arm'] is not None},
                   'SP27_STRATA_RAW_CHANGED')
            native_business(phase)
            expect(row, {'native_final_gate': phase['client_confirmed_before_original_window_end'],
                         **{key: phase.get(key) for key in ('confirmation_ended_ns',
                            'client_confirmed_transactions', 'control_integrity_met',
                            'invariant_target_met', 'finite_business_target_met')}},
                   'SP27_STRATA_PHASE_SUMMARY')
            if planned[index]['arm'] is None:
                passed = healthy(phase)
                require(row.get('healthy') is passed, 'SP27_STRATA_HEALTH_MISMATCH')
            else:
                require(inputs_acquired, 'SP27_STRATA_PRESSURE_BEFORE_INPUTS')
                passed = pressure_integrity(phase, planned[index]['arm'],
                                            streams[ARMS.index(planned[index]['arm'])])
        else:
            expect(row, {'raw_phase_record': None, 'raw_phase_sha256': None}, 'SP27_STRATA_INCOMPLETE_RAW')
            if row['helper_invoked']:
                name = prefix + '-panic.json'
                expected_names.append(name)
                require(row.get('panic_record') == name, 'SP27_STRATA_PANIC_REQUIRED')
                expect(read_record(name), {'schema': 'sp27-receiver-campaign-native-panic-v1',
                    'phase_id': planned[index]['phase_id'], 'planned_index': index,
                    'raw_phase_complete': False, 'native_confirmation_result': None}, 'SP27_STRATA_PANIC')
        stopped = not (passed and phase_before and phase_after)
        require(row.get('stopped_campaign') is stopped, 'SP27_STRATA_STOP_MISMATCH')
        (health_rows if planned[index]['arm'] is None else controls).append(row)
        allowed_raw.update(Path(name).name for name in expected_names)
    require({path.name for path in (out / 'native/raw').iterdir()} == allowed_raw,
            'SP27_STRATA_UNINDEXED_OR_MISSING_RAW')
    initial_passed = (len(records) >= 3 and all(row.get('healthy') is True
                      and row.get('stopped_campaign') is False for row in records[:3]))
    require(report.get('health_gate_passed') is initial_passed
            and (not inputs_acquired or initial_passed)
            and (not controls or initial_passed)
            and (initial_passed or not (out / 'native/strata-acquisition-started.json').exists()),
            'SP27_STRATA_PRESSURE_BEFORE_HEALTH')
    expect(report, {'helper_invoked_phases': invoked, 'completed_phases': completed,
                    'incomplete_phases': len(records) - completed, 'unstarted_phases': 13 - len(records),
                    'health_phases': health_rows, 'control_phases': controls,
                    'healthy_completed_phases': sum(row.get('healthy') is True for row in health_rows),
                    'pressure_controls_attempted': len(controls),
                    'pressure_controls_executed': sum(row.get('completed') is True for row in controls),
                    'pressure_controls_unstarted': 8 - len(controls)}, 'SP27_STRATA_DENOMINATORS')
    collected = report['qualification'] == 'COLLECTED_CONTROL_SERIES'
    if collected:
        require(len(records) == completed == 13 and not stopped and inputs_acquired
                and before_ok and after_ok and report.get('first_divergence') is None,
                'SP27_STRATA_SERIES_NOT_ESTABLISHED')
    else:
        divergence = read_record('first-divergence.json')
        require(type(report.get('first_divergence')) is dict
                and same_json(divergence, report['first_divergence']), 'SP27_STRATA_DIVERGENCE_CHANGED')
        expect(divergence, {'schema': 'sp27-receiver-campaign-first-divergence-v1',
                           'qualification': 'NO_GO', 'causal_status': 'UNKNOWN'}, 'SP27_STRATA_DIVERGENCE_SCOPE')
        if stopped:
            expect(divergence, {'planned_index': len(records) - 1,
                               'phase_id': records[-1]['phase_id']}, 'SP27_STRATA_DIVERGENCE_PHASE')
        else:
            stage = divergence.get('stage')
            require((not records and stage in ('pre-execution-identity-or-host', 'business-acquisition-panic'))
                    or (len(records) == 3 and not inputs_acquired and stage in (
                        'strata-input-acquisition-panic', 'invalid-control-input-roster'))
                    or (len(records) == 13 and stage == 'post-execution-identity-or-host' and not after_ok),
                    'SP27_STRATA_UNEXPLAINED_STOP')
    # Preserve actual partial acquisition observations too. They are not
    # successes, reconstructed costs, or a second cryptographic verification.
    for name in ('business-acquisition-started.json', 'business-acquisition-panic.json',
                 'strata-acquisition-started.json', 'strata-acquisition-panic.json'):
        if name not in readback and (out / 'native' / name).exists():
            read_record(name)
    acquisition_dir = out / 'native/strata-acquisition'
    if acquisition_dir.exists():
        for path in sorted(acquisition_dir.glob('*.json')):
            read_record('strata-acquisition/' + path.name)
    return report, report_file, readback


def execution(out: Path) -> dict:
    prepared = validate_preparation(out)
    write_new(out / 'execution-start.json', {'schema': SCHEMA, 'job': history.job_identity()})
    result = {'schema': SCHEMA, 'job': history.job_identity(), 'source_before': source_identity(),
              'source_after': None, 'binary_before': prepared['binary'], 'binary_after': None,
              'process': None, 'named_execution': None, 'report_file': None, 'native_readback_files': None,
              'qualification': 'UNKNOWN', 'failures': [], 'collection_completed': False,
              'causal_mechanism_established': False, 'runtime_limits_or_deadlines_changed': False}
    binary = Path(prepared['binary']['path'])
    try:
        # Retain the actual executable independently of the build cache.
        saved = out / native.TARGET
        with binary.open('rb') as source, saved.open('xb') as destination:
            shutil.copyfileobj(source, destination)
        os.chmod(saved, 0o755)
        require(digest(saved) == prepared['binary']['sha256'], 'SP27_RETAINED_BINARY_CHANGED')
        os.environ['TRNM_SP27_RECEIVER_STRATA_DIR'] = str(out / 'native')
        os.environ['TRNM_SP27_SOURCE_SHA'] = result['source_before']['commit']
        os.environ['TRNM_SP27_RUN_ID'] = declared_run_id(prepared['job'])
        command = [str(binary), SELECTOR, '--exact', '--ignored', '--show-output', '--test-threads=1']
        result['process'] = native.run_child(command, out / 'run', NATIVE_TIMEOUT_SECONDS)
        require(result['process']['exit_code'] == 0 and not result['process']['timed_out'],
                'SP27_NATIVE_EXECUTION_FAILED')
        result['named_execution'] = named_test((out / 'run/stdout').read_text().splitlines(), SELECTOR)
        report, result['report_file'], result['native_readback_files'] = read_campaign(out, prepared)
        result['qualification'] = report['qualification']
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['failures'].append(type(error).__name__ + ':' + str(error))
    finally:
        for field, action in (
            ('source_after', source_identity),
            ('binary_after', lambda: history.file_observation(binary, history.BINARY_LIMIT)[0]),
        ):
            try:
                result[field] = action()
            except (OSError, ValueError, KeyError, TypeError) as error:
                result['failures'].append(type(error).__name__ + ':' + str(error))
        if result['source_before'] != result['source_after']:
            result['failures'].append('SP27_SOURCE_CHANGED')
        if result['binary_before'] != result['binary_after']:
            result['failures'].append('SP27_BINARY_CHANGED')
        result['collection_completed'] = not result['failures']
        write_new(out / 'manifest.json', result)
    return result


def bind_execution(prepared: dict, out: Path) -> dict:
    require(validate_preparation(out) == prepared, 'SP27_PREPARATION_CHANGED')
    result, manifest = history.load_object(out / 'manifest.json')
    require(result.get('schema') == SCHEMA and result.get('collection_completed') is True
            and result.get('failures') == [] and result.get('job') == history.job_identity()
            and result.get('causal_mechanism_established') is False
            and result.get('runtime_limits_or_deadlines_changed') is False,
            'SP27_COLLECTION_INCOMPLETE')
    require(result['source_before'] == result['source_after'] == prepared['source_before']
            and result['binary_before'] == result['binary_after'] == prepared['binary'],
            'SP27_SOURCE_BINARY_BINDING')
    report, observed, readback = read_campaign(out, prepared)
    require(observed == result['report_file'] and report['qualification'] == result['qualification'],
            'SP27_REPORT_CHANGED')
    require(readback == result.get('native_readback_files'), 'SP27_NATIVE_READBACK_CHANGED')
    process = result.get('process')
    command = [prepared['binary']['path'], SELECTOR, '--exact', '--ignored',
               '--show-output', '--test-threads=1']
    require(type(process) is dict and process.get('command') == command
            and type(process.get('exit_code')) is int and process['exit_code'] == 0
            and process.get('timed_out') is False, 'SP27_NATIVE_PROCESS_REQUIRED')
    require(result['process']['stdout_sha256'] == digest(out / 'run/stdout')
            and result['process']['stderr_sha256'] == digest(out / 'run/stderr')
            and named_test((out / 'run/stdout').read_text().splitlines(), SELECTOR)
            == result['named_execution'], 'SP27_NATIVE_LOG_CHANGED')
    return {'schema': 'sp27-strata-build-execution-binding-v1',
            'manifest_sha256': manifest['sha256'], 'source_commit': prepared['source_before']['commit'],
            'binary_sha256': prepared['binary']['sha256'], 'qualification': result['qualification'],
            'successful_collection_is_business_qualification': False,
            'runtime_limits_or_deadlines_changed': False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.out) if args.prepare else execution(args.out)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('completed', result.get('collection_completed')) is True else 1


if __name__ == '__main__':
    raise SystemExit(main())
