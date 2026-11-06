#!/usr/bin/env python3
"""Read original native campaign failures without shrinking planned denominators.

This is a bounded, offline evidence reader, not the successful-campaign verifier.
The caller pins the result bytes and declared measured head/tree. Optional raw
reports are checked against the result hashes or an independently pinned original
artifact file list. A missing report remains unknown; it is never a zero-cost
observation or a successful run. No status from this reader grants native,
current-source, host, cryptographic, WAN, or independent-acceptance qualification.

CLI exit 0 means all three reports were read consistently without a reported
failure (status ``observed``, never PASS); exit 1 retains failure/partial/unknown;
exit 2 rejects inconsistent or unbound input. All valid readbacks retain 27 slots.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_public_v3_phase_read as phase_reader
from read_original_native_campaign import INPUTS, SELECTOR, source as check_source

SCHEMA = 'pon-native-campaign-attempt-readback-v1'
MAX_RESULT_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_FILES = 4096
RUNS = (1, 2, 3)
CONTROLLER_RESOURCES = {'cpu_max': '400000 100000', 'memory_max': '17179869184', 'nice': 10}
PUBLIC_PLACEMENT = {
    'profile': 'fixed-public-phase-external-actors-v1',
    'receiver_and_verifier_cpu_max': '25000 100000',
    'receiver_and_verifier_memory_max': '2147483648',
    'fixed_parent': '/sys/fs/cgroup/trnmponpublic.slice',
    'attacker_processes_remain_in_original_controller_domain': True,
    'original_3x3_workload_and_depletion_predicates_changed': False,
}
CARGO_ARGS = ['+1.95.0', 'test', '--locked', '--offline', '--release', '--manifest-path',
              'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--test', 'public_v3_multiprocess']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value, length=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value),
            'full lowercase digest required')
    return value


def integer(value):
    require(type(value) is int and value >= 0, 'nonnegative integer required')
    return value


def boolean(value):
    require(type(value) is bool, 'boolean required')
    return value


def optional_text(value):
    require(value is None or (type(value) is str and bool(value)), 'nonempty error or null required')
    return value


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result

    def invalid(value):
        raise ValueError('nonfinite JSON: ' + value)

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def exact(actual, expected, message):
    # Python's structural equality alone equates 0/False and 1/True.
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
    require(encode(actual) == encode(expected), message)


class Directory:
    """Read regular files beneath one descriptor; never follow a path component."""

    def __init__(self, path):
        path = Path(path).absolute()
        require('..' not in path.parts, 'parent path component refused')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        self.fd = os.open(path.anchor, flags)
        try:
            for part in path.parts[1:]:
                child = os.open(part, flags, dir_fd=self.fd)
                os.close(self.fd)
                self.fd = child
        except BaseException:
            self.close()
            raise

    @staticmethod
    def parts(name):
        require(type(name) is str and name and '\\' not in name and '\0' not in name,
                'canonical relative artifact path required')
        parts = name.split('/')
        require(not name.startswith('/') and all(part not in ('', '.', '..') for part in parts),
                'artifact path escapes root')
        return parts

    def read(self, name, maximum, expected):
        digest(expected)
        parts = self.parts(name)
        directory = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = child
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
                        'bounded regular input required')
                raw = stream.read(maximum + 1)
                after = os.fstat(stream.fileno())
                identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                          value.st_mtime_ns, value.st_ctime_ns)
                require(len(raw) <= maximum and identity(before) == identity(after),
                        'input changed or exceeded byte bound')
                require(hashlib.sha256(raw).hexdigest() == expected, 'input SHA256 mismatch: ' + name)
                return raw
        finally:
            os.close(directory)

    def close(self):
        os.close(self.fd)


def manifest(directory, pin, result_pin):
    raw = directory.read('artifact-files.json', MAX_MANIFEST_BYTES, pin)
    value = strict_json(raw)
    require(type(value) is dict and type(value.get('files')) is list
            and 0 < len(value['files']) <= MAX_FILES, 'bounded original artifact file list required')
    rows = {}
    for row in value['files']:
        require(type(row) is dict, 'artifact row must be an object')
        name = '/'.join(Directory.parts(row['path']))
        require(name not in rows and name != 'artifact-files.json', 'duplicate or recursive artifact entry')
        integer(row['bytes'])
        digest(row['sha256'])
        rows[name] = row
    require('results.json' in rows and rows['results.json']['sha256'] == result_pin,
            'artifact manifest and result pin disagree')
    return rows


def step(value, name):
    require(type(value) is dict and value['name'] == name, 'original step identity required')
    build = name == 'build'
    expected = CARGO_ARGS + (['--no-run', '--message-format=json'] if build else
                            [SELECTOR, '--', '--exact', '--ignored', '--nocapture', '--test-threads=1'])
    command = value['command']
    require(type(command) is list and len(command) > 1 and type(command[0]) is str
            and PurePosixPath(command[0]).is_absolute() and PurePosixPath(command[0]).name == 'cargo',
            'explicit original cargo executable required')
    exact(command[1:], expected, 'original command changed')
    require(type(value['cwd']) is str and PurePosixPath(value['cwd']).is_absolute(),
            'original source directory required')
    timeout = 1800 if build else 600
    require(integer(value['outer_stage_timeout_seconds']) == timeout, 'original timeout changed')
    code = value['returncode']
    require(code is None or type(code) is int, 'integer exit or unknown required')
    error = optional_text(value['error'])
    elapsed = value['elapsed_ns']
    require(elapsed is None or (type(elapsed) is int and 0 <= elapsed < 2**128),
            'elapsed nanoseconds or unknown required')
    complete = boolean(value['complete_success'])
    require(not complete or (code == 0 and error is None and elapsed is not None
                            and elapsed <= timeout * 1_000_000_000), 'successful step contradicts outcome')
    return {'returncode': code, 'error': error, 'complete_success': complete, 'elapsed_ns': elapsed}


def envelope(value, head, tree):
    require(type(value) is dict and value['schema'] == 'pon-original-native-campaign-ci-v1',
            'original campaign result required')
    require(value['expected_head'] == head and value['expected_tree'] == tree
            and value['source_kind'] == 'head', 'declared measured source mismatch')
    require(value['profile'] == 'release' and value['toolchain'] == '1.95.0'
            and value['state_backend'] == 'authenticated-v1', 'original execution profile changed')
    require(integer(value['planned_complete_runs']) == 3
            and integer(value['build_timeout_seconds']) == 1800
            and integer(value['original_campaign_outer_timeout_seconds']) == 600, 'original planned runs or budgets changed')
    exact(value['original_inputs'], INPUTS, 'original workload or attacker denominators changed')
    exact(value['expected_resources'], CONTROLLER_RESOURCES, 'original controller resources changed')
    if 'public_phase_placement' in value:
        exact(value['public_phase_placement'], PUBLIC_PLACEMENT, 'public Host placement declaration changed')
    if value.get('expected_public_policy_id') is not None:
        digest(value['expected_public_policy_id'])
    source = value['source_after']
    if source is not None:
        check_source(source, head, tree)
    digest(value['runner_sha256'])
    boolean(value['complete_success'])
    optional_text(value['failure'])
    errors = value['finalization_failures']
    require(type(errors) is list and all(type(error) is str and error for error in errors),
            'finalization errors must be retained strings')
    attempts = value['attempts']
    require(type(attempts) is list and len(attempts) <= 3, 'at most three predeclared attempts required')
    for number, attempt in enumerate(attempts, 1):
        require(type(attempt) is dict and integer(attempt['number']) == number,
                'original attempt order or denominator changed')
        require(attempt['report_directory'] == f'run-{number}-raw', 'original report directory changed')
        boolean(attempt['complete_success'])
        boolean(attempt['original_criteria_met'])
        optional_text(attempt['report_validation_failure'])
        if 'phase_startup_errors' in attempt:
            startup = attempt['phase_startup_errors']
            require(type(startup) is list and len(startup) <= 3, 'bounded startup error list required')
            names = []
            for row in startup:
                require(type(row) is dict and set(row) == {'mode', 'error'}
                        and row['mode'] in phase_reader.MODES and optional_text(row['error']) is not None,
                        'original startup error required')
                names.append(row['mode'])
            require(len(names) == len(set(names)), 'duplicate phase startup error')
        if attempt.get('report_sha256') is not None:
            digest(attempt['report_sha256'])
        outcome = step(attempt['step'], f'run-{number}')
        require(not attempt['complete_success'] or (outcome['complete_success']
                and attempt['original_criteria_met'] and attempt['report_validation_failure'] is None),
                'successful attempt contradicts retained outcome')
    build = step(value['build'], 'build') if value.get('build') is not None else None
    require(not value['complete_success'] or (value['failure'] is None and not errors
            and len(attempts) == 3 and all(row['complete_success'] for row in attempts)
            and build is not None and build['complete_success'] and source is not None),
            'successful campaign contradicts retained outcomes')
    return attempts, build


def unknown_slots(number, reason):
    return [{'run': number, 'phase': phase, 'round': ordinal, 'observed': False,
             'confirmed_inside_pressure_window': None, 'started_ns': None, 'ended_ns': None,
             'unknown_reason': reason}
            for phase in phase_reader.MODES for ordinal in range(phase_reader.ROUNDS)]


def report_readback(raw, attempt, policy):
    report = strict_json(raw)
    require(type(report) is dict and report['schema'] == 'native-public-v3-separate-process-campaign-v2'
            and report['state_backend'] == 'authenticated-v1', 'original raw campaign profile required')
    for name in ('cryptographic_hardness_qualified', 'work_profile_qualified', 'independent_operators',
                 'wan_qualified', 'production_candidate', 'release_ready'):
        require(report[name] is False, 'raw report cannot grant ' + name)
    boolean(report['finite_experiment_criteria_met'])
    boolean(report['economics_complete'])
    preparation = report['preparation']
    require(preparation['state_backend'] == 'authenticated-v1'
            and integer(preparation['actual_signed_seed_transfers']) == 1024
            and integer(preparation['seed_blocks']) == 4
            and integer(preparation['business_blocks']) == 21, 'original preparation changed')
    require(type(report['phases']) is list and len(report['phases']) == 3, 'three original phases required')
    startup = []
    for phase, mode, attackers in zip(report['phases'], phase_reader.MODES, (0, 24, 24)):
        require(type(phase) is dict and phase['mode'] == mode
                and phase['state_backend'] == 'authenticated-v1', 'original phase order or backend changed')
        error = optional_text(phase.get('startup_or_campaign_error'))
        if error is not None:
            require(not phase.get('confirmations'), 'startup failure cannot erase retained confirmations')
            startup.append({'mode': mode, 'error': error})
            continue
        require(integer(phase['duration_seconds']) == 30
                and integer(phase['attacker_processes_requested']) == attackers, 'original phase inputs changed')
        boolean(phase['finite_phase_criteria_met'])
        boolean(phase['all_signed_rounds_confirmed_in_window'])
        require(type(phase['confirmations']) is list, 'confirmation records must be a list')
        for row in phase['confirmations']:
            require(type(row) is dict, 'confirmation record must be an object')
            boolean(row['confirmed_inside_pressure_window'])
            for key in ('started_ns', 'ended_ns'):
                clock = row.get(key)
                require(clock is None or (type(clock) is int and 0 <= clock < 2**128),
                        'confirmation clock or unknown required')
            if row.get('started_ns') is not None and row.get('ended_ns') is not None:
                require(row['started_ns'] <= row['ended_ns'], 'confirmation clocks reversed')
    if policy is not None:
        require('public_resource_policy' in report and
                phase_reader.identify_observation(report['public_resource_policy'])['policy_id'] == policy,
                'raw public policy and result pin disagree')
    derived = phase_reader.analyze(report)
    complete_rounds = []
    for native, observed in zip(report['phases'], derived['phases']):
        complete = (observed.get('observations_available') is True
                    and observed.get('observed_confirmation_rounds') == 3
                    and observed.get('unobserved_scheduled_rounds') == 0
                    and observed.get('confirmed_rounds') == 3
                    and native.get('all_signed_rounds_confirmed_in_window') is True)
        complete_rounds.append(complete)
        require(native.get('finite_phase_criteria_met') is not True or complete,
                'positive phase summary lacks all three planned confirmed rounds')
    if 'phase_startup_errors' in attempt:
        exact(attempt['phase_startup_errors'], startup, 'retained startup errors disagree')
    criteria = (not startup and report['finite_experiment_criteria_met'] and report['economics_complete']
                and all(phase['finite_phase_criteria_met'] for phase in report['phases'])
                and all(complete_rounds))
    require(report['finite_experiment_criteria_met'] is not True or criteria,
            'positive campaign summary contradicts complete phase and economics observations')
    if attempt['report_validation_failure'] is None:
        require(attempt['original_criteria_met'] is criteria, 'result criteria disagree with raw reports')
    rows, phases = [], []
    for native, observed in zip(report['phases'], derived['phases']):
        known = {row['round']: row for row in observed.get('confirmation_rounds', [])}
        for ordinal in range(3):
            row = known.get(ordinal)
            rows.append({'run': attempt['number'], 'phase': native['mode'], 'round': ordinal,
                'observed': row is not None,
                'confirmed_inside_pressure_window': row['confirmed_inside_pressure_window'] if row else None,
                'started_ns': row.get('started_ns') if row else None, 'ended_ns': row.get('ended_ns') if row else None,
                'unknown_reason': None if row else ('phase-startup-failed' if native.get('startup_or_campaign_error')
                                                   else 'scheduled-round-not-observed')})
        phases.append({key: observed.get(key) for key in (
            'mode', 'native_phase_criteria_met', 'startup_or_campaign_error', 'observations_available',
            'observed_confirmation_rounds', 'unobserved_scheduled_rounds', 'confirmed_rounds',
            'whole_parent_phase_cpu_ns', 'whole_parent_phase_wall_ns',
            'receiver_and_verifier_setup_cpu_ns', 'receiver_and_verifier_setup_wall_ns')})
    return {'native_criteria_met': criteria, 'phases': phases, 'slots': rows}


def read_attempt(result_path, expected_result_sha256, expected_head, expected_tree, *,
                 reports_root=None, artifact_manifest_sha256=None):
    """Return observations only; a declared success without originals is unknown."""
    digest(expected_head, 40)
    digest(expected_tree, 40)
    digest(expected_result_sha256)
    result_path = Path(result_path)
    reader = Directory(result_path.parent)
    try:
        raw = reader.read(result_path.name, MAX_RESULT_BYTES, expected_result_sha256)
    finally:
        reader.close()
    value = strict_json(raw)
    attempts, build = envelope(value, expected_head, expected_tree)
    require(artifact_manifest_sha256 is None or reports_root is not None, 'artifact manifest needs a report root')
    directory = Directory(reports_root) if reports_root is not None else None
    failures = []
    if value['failure'] is not None:
        failures.append({'where': 'campaign', 'reason': value['failure']})
    failures.extend({'where': 'finalization', 'reason': error} for error in value['finalization_failures'])
    if build and (build['error'] is not None or (build['returncode'] is not None and not build['complete_success'])):
        failures.append({'where': 'build', 'reason': build['error'] or 'terminal-build-failure'})
    runs, all_slots, reports = [], [], 0
    try:
        files = manifest(directory, artifact_manifest_sha256, expected_result_sha256) if artifact_manifest_sha256 else None
        if files is not None:
            require(files['results.json']['bytes'] == len(raw), 'result length and artifact manifest disagree')
        for number in RUNS:
            attempt = attempts[number - 1] if number <= len(attempts) else None
            run = {'number': number, 'attempt_recorded': attempt is not None,
                   'report_state': 'not_requested' if directory is None else 'missing',
                   'report_sha256': None, 'report_bytes': None, 'report_error': None,
                   'declared_complete_success': None, 'declared_original_criteria_met': None,
                   'declared_report_validation_failure': None, 'declared_phase_startup_errors': None,
                   'step': None, 'raw': None}
            slots = unknown_slots(number, 'attempt-not-recorded' if attempt is None else 'report-not-observed')
            if attempt is not None:
                run.update(declared_complete_success=attempt['complete_success'],
                    declared_original_criteria_met=attempt['original_criteria_met'],
                    declared_report_validation_failure=attempt['report_validation_failure'],
                    declared_phase_startup_errors=attempt.get('phase_startup_errors'),
                    step=step(attempt['step'], f'run-{number}'))
                outcome = run['step']
                if attempt['report_validation_failure'] is not None:
                    failures.append({'where': f'run-{number}', 'reason': attempt['report_validation_failure']})
                if outcome['error'] is not None or (outcome['returncode'] is not None and not attempt['complete_success']):
                    failures.append({'where': f'run-{number}', 'reason': outcome['error'] or 'terminal-run-failure'})
                name = f'run-{number}-raw/report.json'
                pin = attempt.get('report_sha256')
                if files is not None and name in files:
                    require(pin is None or files[name]['sha256'] == pin, 'report pins disagree')
                    pin = files[name]['sha256']
                elif files is not None and pin is not None:
                    raise ValueError('pinned report absent from original artifact file list')
                if directory is not None and pin is None:
                    run['report_state'] = 'unbound'
                if directory is not None and pin is not None:
                    try:
                        report_raw = directory.read(name, phase_reader.MAX_REPORT_BYTES, pin)
                    except FileNotFoundError:
                        run['report_state'] = 'missing'
                    else:
                        if files is not None:
                            require(len(report_raw) == files[name]['bytes'], 'report length and artifact manifest disagree')
                        run.update(report_sha256=pin, report_bytes=len(report_raw), report_state='rejected')
                        try:
                            observed = report_readback(report_raw, attempt, value.get('expected_public_policy_id'))
                        except (ValueError, KeyError, TypeError, IndexError) as error:
                            # The hash-bound original itself may be malformed. Keep
                            # the producer's failure and all planned unknown slots.
                            run['report_error'] = str(error)
                        else:
                            run.update(report_state='observed', raw=observed)
                            slots = observed['slots']
                            reports += 1
                            if observed['native_criteria_met'] is False:
                                failures.append({'where': f'run-{number}-raw', 'reason': 'native-criteria-false'})
            runs.append(run)
            all_slots.extend(slots)
    finally:
        if directory is not None:
            directory.close()
    status = ('failure' if failures else 'observed' if reports == 3 and value['complete_success'] else
              'partial' if reports or any(run['report_state'] == 'rejected' for run in runs) else 'unknown')
    return {
        'schema': SCHEMA, 'status': status,
        'coverage': 'selected_reports' if reports else 'status_only',
        'declared_measured_source': {'head': expected_head, 'tree': expected_tree},
        'result': {'sha256': expected_result_sha256, 'bytes': len(raw),
                   'declared_complete_success': value['complete_success'],
                   'declared_failure': value['failure'], 'finalization_failures': value['finalization_failures']},
        'artifact_manifest_sha256': artifact_manifest_sha256,
        'declared_controller_resources': value['expected_resources'],
        'declared_public_phase_placement': value.get('public_phase_placement'),
        'failures': failures, 'runs': runs, 'all_planned_slots': all_slots,
        'denominators': {'planned_runs': 3, 'planned_phases': 9, 'planned_confirmation_rounds': 27,
            'planned_business_packet_exposures': 189, 'attempt_records': len(attempts),
            'raw_reports_observed': reports, 'observed_confirmation_records': sum(row['observed'] for row in all_slots),
            'unknown_confirmation_slots': sum(not row['observed'] for row in all_slots),
            'retained_confirmation_flags_true': sum(row['confirmed_inside_pressure_window'] is True for row in all_slots)},
        'scope': {'reader_runs_native_test': False, 'complete_artifact_verified': False,
            'host_or_source_authenticated': False, 'binary_or_log_payloads_verified': False,
            'cryptographic_confirmations_verified': False, 'current_tuple_credit': False,
            'native_qualification': False, 'independent_acceptance': False, 'production_qualification': False,
            'four_second_slo_qualified': False, 'thirty_second_flags_are_not_four_second_slo': True,
            'unknown_cost_is_not_zero': True, 'declared_resources_are_not_host_observations': True,
            'business_tps_capacity': None},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', required=True, type=Path)
    parser.add_argument('--results-sha256', required=True)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-tree', required=True)
    parser.add_argument('--reports-root', type=Path)
    parser.add_argument('--artifact-manifest-sha256')
    args = parser.parse_args(argv)
    try:
        result = read_attempt(args.results, args.results_sha256, args.expected_head, args.expected_tree,
            reports_root=args.reports_root, artifact_manifest_sha256=args.artifact_manifest_sha256)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        print(json.dumps({'schema': SCHEMA, 'input_rejected': True, 'status': 'unknown', 'error': str(error),
                          'planned_confirmation_rounds': 27, 'native_qualification': False,
                          'current_tuple_credit': False}, sort_keys=True, allow_nan=False))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0 if result['status'] == 'observed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
