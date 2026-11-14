#!/usr/bin/env python3
"""Run a source-bound SP27-02 health gate in the unchanged public Host.

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
SCRIPT = 'scripts/ci/run_sp27_receiver_controls.py'
SELECTOR = 'sp27_receiver_controls::repeated_unpressured_confirmation_stops_before_pressure_on_first_divergence'
MODULE = 'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_controls.rs'
SCHEMA = 'sp27-native-health-execution-v2'
PREPARATION = 'sp27-native-health-preparation-v1'
NATIVE_TIMEOUT_SECONDS = 90


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_identity() -> dict:
    actual = lease.workflow_source()
    return {'commit': actual['tested_commit'], 'tree': actual['tested_tree'],
            'tracked_source_identity': actual,
            'files_sha256': {p: digest(ROOT / p) for p in (
                native.SOURCE, MODULE, SCRIPT, 'config/systemd/trnmponpublic.slice',
                'trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs')}}


def output_path(out: Path) -> Path:
    receipts = Path(os.environ.get('TRNM_CI_RECEIPT_DIR', ''))
    require(receipts.is_absolute() and receipts.resolve(strict=True) == receipts
            and out == receipts / 'sp27-receiver-controls'
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


def read_health(out: Path, prepared: dict) -> tuple[dict, dict, dict]:
    readback = {}

    def read_record(name: str) -> dict:
        observation, data = history.file_observation(out / 'native' / name,
                                                     4 * 1024 * 1024, retain=True)
        value = native.json_load(data)
        require(type(value) is dict, 'SP27_NATIVE_JSON_OBJECT_REQUIRED')
        readback[name] = observation
        return value

    observed, raw = history.file_observation(out / 'native/report.json', 4 * 1024 * 1024,
                                            retain=True)
    report = native.json_load(raw)
    require(type(report) is dict and report.get('schema') == 'sp27-receiver-health-gate-v1',
            'SP27_HEALTH_SCHEMA')
    require(report.get('qualification') in ('NO_GO', 'HEALTH_GATE_PASSED_CONTROLS_PENDING'),
            'SP27_QUALIFICATION_REQUIRED')
    require(exact_integer(report.get('planned_health_repetitions'), 3)
            and exact_integer(report.get('requested_window_ns'), 4_000_000_000)
            and exact_integer(report.get('pressure_controls_executed'), 0)
            and report.get('causal_mechanism_status') == 'UNKNOWN'
            and all(report.get(key) is False for key in (
                'publication_qualified', 'public_network_ready', 'production_activation')),
            'SP27_HEALTH_SCOPE_CHANGED')
    attempted, completed = (report.get(key) for key in (
        'attempted_health_repetitions', 'completed_health_repetitions'))
    require(type(attempted) is int and type(completed) is int
            and 0 <= completed <= attempted <= 3
            and exact_integer(report.get('not_executed_health_repetitions'), 3 - attempted)
            and exact_integer(report.get('incomplete_health_repetitions'), attempted - completed),
            'SP27_HEALTH_DENOMINATORS')
    source, job, binary = prepared['source_before'], prepared['job'], prepared['binary']
    expected_identity = {
        'binary_path': binary['path'], 'binary_sha256': binary['sha256'],
        'compiled_test_source_sha256': source['files_sha256'][native.SOURCE],
        'compiled_health_module_sha256': source['files_sha256'][MODULE],
        'runner_declared_source_sha': source['commit'],
        'runner_declared_run_id': declared_run_id(job),
        'github_run_id': job['GITHUB_RUN_ID'], 'github_run_attempt': job['GITHUB_RUN_ATTEMPT'],
    }
    identities = [read_record(f'identity-{when}.json') for when in ('before', 'after')]
    for identity in identities:
        require(identity.get('schema') == 'sp27-receiver-run-identity-v1'
                and identity.get('binary_identity_error') is None
                and all(type(identity.get(key)) is str and identity[key] == value
                        for key, value in expected_identity.items()),
                'SP27_COMPILED_SOURCE_BINARY_RUN_BINDING')
        require(type(identity.get('pid')) is int and identity['pid'] > 0
                and all(type(identity.get(key)) is str and bool(identity[key])
                        for key in ('hostname', 'boot_id', 'process_cgroup')),
                'SP27_NATIVE_PROCESS_IDENTITY_REQUIRED')
    require(all(identities[0][key] == identities[1][key]
                for key in ('pid', 'hostname', 'boot_id', 'process_cgroup')),
            'SP27_NATIVE_PROCESS_IDENTITY_CHANGED')
    require(report.get('binary_unchanged') is True, 'SP27_NATIVE_BINARY_CHANGED')
    for when in ('before', 'after'):
        host = read_record(f'host-{when}.json')
        require(host.get('schema') == 'sp27-receiver-host-readback-v1'
                and host.get('fixed_parent') == '/sys/fs/cgroup/trnmponpublic.slice'
                and type(host.get('verified')) is bool
                and report.get(f'host_{when}_verified') is host['verified'],
                'SP27_NATIVE_HOST_READBACK_MISMATCH')
        require((host['verified'] and type(host.get('sample')) is dict and host.get('error') is None)
                or (not host['verified'] and host.get('sample') is None
                    and type(host.get('error')) is str and bool(host['error'])),
                'SP27_NATIVE_HOST_OBSERVATION_REQUIRED')
    if attempted > 0 or (out / 'native/acquisition.json').exists():
        acquisition = read_record('acquisition.json')

        def encoded(value, length=None):
            return (type(value) is str and bool(value) and len(value) % 2 == 0
                    and (length is None or len(value) == length)
                    and all(char in '0123456789abcdef' for char in value))

        packets, packet_ids = (acquisition.get(key) for key in ('signed_honest_packets', 'packet_ids'))
        require(acquisition.get('schema') == 'sp27-receiver-seven-packet-acquisition-v1'
                and acquisition.get('same_seven_packets_in_all_health_phases') is True
                and type(packets) is list and len(packets) == 7
                and all(encoded(packet) for packet in packets)
                and type(packet_ids) is list and len(packet_ids) == 7
                and all(encoded(packet_id, 64) for packet_id in packet_ids),
                'SP27_SEVEN_PACKET_ACQUISITION_REQUIRED')
        # This records the actual acquisition bytes and packet inventory. It is
        # not a second cryptographic verifier; the native phase owns validation.
    else:
        require(report['qualification'] == 'NO_GO'
                and type(report.get('first_divergence')) is dict
                and report['first_divergence'].get('stage') in (
                    'pre-execution-identity-or-host', 'honest-packet-acquisition-panic'),
                'SP27_ACQUISITION_UNEXPLAINED_ABSENCE')
    phases = report.get('health_phases')
    require(type(phases) is list and len(phases) == completed, 'SP27_HEALTH_PHASES')
    outcomes = []
    for index, row in enumerate(phases):
        expected = f'raw/health-{index:03}.json'
        require(type(row) is dict and exact_integer(row.get('health_index'), index)
                and row.get('raw_record') == expected,
                'SP27_HEALTH_PHASE_IDENTITY')
        phase = read_record(expected)
        require(row.get('raw_sha256') == readback[expected]['sha256'], 'SP27_RAW_CHANGED')
        end = phase.get('confirmation_ended_ns')
        healthy = (exact_integer(phase.get('requested_window_ns'), 4_000_000_000)
                   and exact_integer(phase.get('workers'), 0)
                   and all(phase.get(key) is True for key in (
                       'invariant_target_met', 'finite_business_target_met',
                       'client_confirmed_before_original_window_end', 'full_native_state_equal'))
                   and exact_integer(phase.get('client_confirmed_transactions'), 1)
                   and type(end) is int and 0 <= end < 4_000_000_000
                   and phase.get('verification_errors') == [])
        require(row.get('healthy') is healthy
                and row.get('native_final_gate') is phase.get('client_confirmed_before_original_window_end')
                and type(row.get('confirmation_ended_ns')) is type(end)
                and row.get('confirmation_ended_ns') == end, 'SP27_NATIVE_GATE_MISMATCH')
        require(all(outcomes), 'SP27_CONTINUED_AFTER_UNHEALTHY_CONTROL')
        outcomes.append(healthy)
    qualified = report['qualification'] == 'HEALTH_GATE_PASSED_CONTROLS_PENDING'
    require(report.get('health_gate_passed') is qualified, 'SP27_HEALTH_QUALIFICATION_MISMATCH')
    if qualified:
        require(attempted == completed == 3 and all(outcomes)
                and all(report.get(key) is True for key in (
                    'binary_unchanged', 'host_before_verified', 'host_after_verified'))
                and report.get('first_divergence') is None, 'SP27_HEALTH_NOT_ESTABLISHED')
    else:
        require(type(report.get('first_divergence')) is dict, 'SP27_FIRST_DIVERGENCE_REQUIRED')
        divergence = read_record('first-divergence.json')
        require(divergence == report['first_divergence'], 'SP27_FIRST_DIVERGENCE_CHANGED')
    return report, observed, readback


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
        os.environ['TRNM_SP27_RECEIVER_CONTROLS_DIR'] = str(out / 'native')
        os.environ['TRNM_SP27_SOURCE_SHA'] = result['source_before']['commit']
        os.environ['TRNM_SP27_RUN_ID'] = declared_run_id(prepared['job'])
        command = [str(binary), SELECTOR, '--exact', '--ignored', '--show-output', '--test-threads=1']
        result['process'] = native.run_child(command, out / 'run', NATIVE_TIMEOUT_SECONDS)
        require(result['process']['exit_code'] == 0 and not result['process']['timed_out'],
                'SP27_NATIVE_EXECUTION_FAILED')
        result['named_execution'] = named_test((out / 'run/stdout').read_text().splitlines(), SELECTOR)
        report, result['report_file'], result['native_readback_files'] = read_health(out, prepared)
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
    report, observed, readback = read_health(out, prepared)
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
    return {'schema': 'sp27-health-build-execution-binding-v2',
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
