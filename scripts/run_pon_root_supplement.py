#!/usr/bin/env python3
"""Freeze one supplemental test binary; execute once in an explicit user service.

This does not run or replace the original three-run cheap-work campaign. Preparation
does not execute the 30+30 second selector. The operator creates a new systemd user
service with CPUQuota=400%, CPUQuotaPeriodSec=100ms, MemoryMax=16G, Nice=10,
KillMode=control-group and RuntimeMaxSec=600 before invoking execute in that service.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import sys

sys.dont_write_bytecode = True
from run_pon_w1_native_campaign import (
    ROOT, require, resource_observation, run_step, sha, source_snapshot,
    validate_build_environment, validate_resources, validate_source, write_new,
)
from read_original_native_campaign import depletion, integer

SELECTOR = 'separate_process_root_rejection_and_signed_confirmation_supplement'
INPUTS = {'seed_transfers': 1024, 'seed_blocks': 4, 'business_blocks': 21,
          'phase_seconds': 30, 'actor_call_cap': 480, 'planned_complete_runs': 1,
          'attackers': 24, 'm06_workers': 1, 'confirmation_depth': 6,
          'round_start_seconds': [1, 5, 9], 'cpu_burst_ns': 2_000_000_000,
          'cpu_refill_ns_per_second': 250_000_000, 'start_reserve_ns': 100_000_000}
QUALIFICATIONS = ('original_campaign_qualified', 'work_profile_qualified',
                  'independent_operators', 'wan_qualified', 'production_candidate',
                  'production_activation')


def now():
    return datetime.now(timezone.utc).isoformat()


def binary_from_build(path, target):
    artifacts = [row for row in map(json.loads, Path(path).read_bytes().splitlines())
                 if row.get('reason') == 'compiler-artifact'
                 and row.get('target', {}).get('name') == 'public_v3_multiprocess'
                 and row.get('profile', {}).get('test') is True and row.get('executable')]
    require(len(artifacts) == 1, 'ONE_EXACT_TEST_BINARY_REQUIRED')
    row = artifacts[0]
    require(row['profile'] == {'debug_assertions': False, 'debuginfo': 0,
            'opt_level': '3', 'overflow_checks': False, 'test': True},
            'EXACT_RELEASE_PROFILE_REQUIRED')
    binary = Path(row['executable']).resolve()
    require(binary.is_relative_to(target) and binary.is_file(), 'BUILD_TARGET_BINARY_REQUIRED')
    return binary, row['profile']


def exact_source(output, label, env, head, tree):
    validate_source(source_snapshot(), head, tree)
    step = run_step(output, label, [sys.executable, 'scripts/ci/verify_ci_source.py',
        '--kind', 'head', '--expected-head', head, '--output', str(output / (label + '.json'))],
        env, timeout=120)
    require(step['complete_success'], 'RAW_SOURCE_IDENTITY_FAILED')
    return step


def environment():
    validate_build_environment(os.environ)
    return {key: value for key, value in os.environ.items() if not key.startswith('TRNM_')}


def prepare(args, output):
    target = args.target_dir.resolve()
    require(not target.is_relative_to(ROOT) and not target.is_relative_to(output)
            and not output.is_relative_to(target), 'ISOLATED_BUILD_TARGET_REQUIRED')
    env = environment()
    env.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS='2', CARGO_NET_OFFLINE='true',
               RUSTUP_TOOLCHAIN='1.95.0', PYTHONDONTWRITEBYTECODE='1')
    result = {'schema': 'pon-root-supplement-prepared-v1', 'head': args.expected_head,
              'tree': args.expected_tree, 'runner_sha256': sha(__file__), 'inputs': INPUTS,
              'created_utc': now(), 'prepared': False, 'pressure_selector_executed': False,
              'steps': [], 'failure': None}
    try:
        write_new(output / 'resource-at-preparation.json', resource_observation())
        result['steps'].append(exact_source(output, 'source-before', env,
                                           args.expected_head, args.expected_tree))
        cargo = [str(args.cargo.absolute()), '+1.95.0']
        for label, command in (
            ('preflight', ['/bin/bash', 'scripts/project-preflight.sh']),
            ('rustc-version', [str(args.cargo.absolute().parent / 'rustup'), 'run', '1.95.0', 'rustc', '-Vv']),
            ('cargo-version', [*cargo, '-Vv']),
            ('build', [*cargo, 'test', '--offline', '--locked', '--release', '--jobs', '2',
                       '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node',
                       '--test', 'public_v3_multiprocess', '--no-run', '--message-format=json'])):
            row = run_step(output, label, command, env, timeout=1800 if label == 'build' else 60)
            result['steps'].append(row)
            require(row['complete_success'], label.upper() + '_FAILED')
        artifact, profile = binary_from_build(output / 'build.stdout.log', target)
        digest = sha(artifact)
        retained = output / 'public_v3_multiprocess.bin'
        with artifact.open('rb') as source, retained.open('xb') as destination:
            shutil.copyfileobj(source, destination)
        retained.chmod(0o500)
        require(sha(retained) == digest, 'BINARY_CHANGED_DURING_CAPTURE')
        result['binary'] = {'path': str(retained), 'sha256': digest, 'bytes': retained.stat().st_size,
                            'build_artifact': str(artifact), 'compiler_profile': profile}
        result['steps'].append(exact_source(output, 'source-after', env,
                                           args.expected_head, args.expected_tree))
        result['prepared'] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['failure'] = str(error)
    result['completed_utc'] = now()
    write_new(output / 'prepared.json', result)
    return result['prepared']


def prepared_input(path, digest, head, tree):
    require(re.fullmatch('[0-9a-f]{64}', digest) and sha(path) == digest,
            'PREPARED_MANIFEST_SHA_REQUIRED')
    value = json.loads(path.read_text())
    require(value['schema'] == 'pon-root-supplement-prepared-v1' and value['prepared'] is True
            and value['pressure_selector_executed'] is False and value['head'] == head
            and value['tree'] == tree and value['inputs'] == INPUTS
            and value['runner_sha256'] == sha(__file__), 'FROZEN_PREPARATION_REQUIRED')
    binary = Path(value['binary']['path'])
    require(binary == path.parent / 'public_v3_multiprocess.bin' and not binary.is_symlink()
            and binary.is_file() and binary.stat().st_mode & 0o222 == 0
            and binary.stat().st_size == value['binary']['bytes']
            and sha(binary) == value['binary']['sha256'], 'FROZEN_BINARY_SHA_REQUIRED')
    return value, binary


def service_identity(output, unit, resources, env):
    require(re.fullmatch(r'trnm-pn1-root-[a-zA-Z0-9_-]+\.service', unit), 'NEW_USER_SERVICE_NAME_REQUIRED')
    require(resources['cgroup'].endswith('/' + unit), 'CONTROLLER_MUST_OWN_DECLARED_SERVICE')
    row = run_step(output, 'service-identity', ['systemctl', '--user', 'show', unit,
        '--property=ControlGroup,MainPID,KillMode,RuntimeMaxUSec'], env, timeout=10)
    require(row['complete_success'], 'USER_SERVICE_OBSERVATION_FAILED')
    values = dict(line.split('=', 1) for line in (output / row['stdout']).read_text().splitlines())
    require(values.get('ControlGroup') == resources['cgroup']
            and values.get('MainPID') == str(os.getpid()) and values.get('KillMode') == 'control-group'
            and values.get('RuntimeMaxUSec') == '10min', 'SERVICE_OWNERSHIP_AND_CLEANUP_REQUIRED')


def checked_depletion_samples(pressure):
    samples = pressure['budget_samples']
    require(bool(samples), 'ACTUAL_DEPLETION_SAMPLES_REQUIRED')
    depleted = []
    for sample in samples:
        snapshot = sample['meter']['Ok']  # Err/unknown never becomes a zero-cost observation.
        start, end = (integer(sample[key]) for key in ('observation_started_ns', 'observation_ended_ns'))
        require(start <= integer(snapshot['sample_at_ns']) <= end, 'SAMPLE_INTERVAL_REQUIRED')
        if depletion(snapshot):
            depleted.append((start, end, snapshot))
    require(bool(depleted) and pressure['genuine_budget_depletion_observed'] is True
            and pressure['depletion_meter'] == depleted[0][2], 'NUMERIC_DEPLETION_REQUIRED')
    return depleted


def check_report(value, cgroup):
    require(value['schema'] == 'native-public-v3-root-supplement-v1'
            and all(value[key] is False for key in QUALIFICATIONS), 'SUPPLEMENT_SCOPE_REQUIRED')
    require(all(value[key] == INPUTS[key] for key in ('seed_transfers', 'seed_blocks',
            'business_blocks', 'phase_seconds', 'actor_call_cap', 'planned_complete_runs', 'm06_workers')),
            'ORIGINAL_FIXED_INPUTS_REQUIRED')
    baseline, pressure = value['phases']
    require(baseline['mode'] == 'baseline' and pressure['mode'] == 'valid-work-root'
            and baseline['finite_phase_criteria_met'] is True, 'BASELINE_MUST_PASS')
    root = pressure['root_supplement']
    require(root['controller_cgroup'] == cgroup and root['criteria_met'] is True
            and root['aggregate_membership_verified'] is True
            and root['whole_domain_paid_reconciled'] is True and root['aggregate_scoped_cpu_ns'] == 0
            and root['hostile_packets_absent_live'] is True and root['hostile_packets_absent_cold'] is True
            and root['cold_state_equal'] is True and root['expected_legal_counts_and_tip'] is True,
            'ROOT_COHORT_CLOSED_EVIDENCE_REQUIRED')
    require(len(root['hostile_packet_ids']) == len(set(root['hostile_packet_ids'])) == 24
            and len(pressure['children']) == pressure['attacker_processes_ready'] == 24
            and len(root['actor_readiness']) == 24
            and all(row['cgroup'] == cgroup for row in root['actor_readiness']), 'ALL_24_ACTORS_REQUIRED')
    require(pressure['observer_complete'] is True and pressure['verifier_errors'] == []
            and pressure['receiver_client_state_equal'] is True
            and pressure['actor_reports_successful_without_cap_or_kill'] is True,
            'NO_MISSING_OR_UNKNOWN_OBSERVATION_ALLOWED')
    require(root['checked_acquisitions_complete'] is True and value['preparation_cost_known'] is True
            and all(integer(value['preparation'][key]) > 0 for key in ('cpu_ns', 'wall_ns')),
            'KNOWN_PREPARATION_COST_REQUIRED')
    acquisitions = root['acquisitions']
    require(len(acquisitions) == 24, 'ALL_ACTUAL_ACQUISITIONS_REQUIRED')
    bodies = set()
    attacks = []
    for index, (child, acquisition, ready) in enumerate(zip(pressure['children'], acquisitions,
                                                           root['actor_readiness'])):
        actor = child['report']['result']
        require(child['exit_success'] is True and child['parent_forced_kill'] is False
                and child['report']['error'] is None and actor['attempt_cap_reached'] is False
                and actor['acquisition'] == acquisition and actor['worker'] == index
                and child['pid'] == actor['pid'] == ready['pid'] and 0 < len(actor['calls']) < 480
                and all(call['public_request_body_digest'] == acquisition['public_request_body_digest']
                        and call['status'] != 'ok' for call in actor['calls']), 'COMPLETE_FIXED_BODY_ACTOR_REQUIRED')
        require(acquisition['valid_work_for_root_rejection'] is True
                and acquisition['setup_calls'] == 1 and acquisition['method_index'] == 0
                and all(integer(acquisition[key]) > 0 for key in ('acquisition_cpu_ns',
                    'acquisition_wall_ns', 'diagnostic_cpu_ns', 'diagnostic_wall_ns')),
                'KNOWN_REAL_PRODUCER_COST_REQUIRED')
        bodies.add(acquisition['public_request_body_digest'])
        attacks.extend(actor['calls'])
    require(len(bodies) == 24, 'DISTINCT_HOSTILE_BODIES_REQUIRED')
    observer = pressure['receiver_observation']
    require(observer['records_not_retained'] == observer['measurement_failures'] == 0
            and observer['counter_overflow'] is False
            and observer['accepted_connections_seen'] == len(observer['records'])
            and all(row['complete'] is True and row['observation_failed'] is False
                    for row in observer['records']), 'COMPLETE_RECEIVER_OBSERVER_REQUIRED')
    owner_cpu = sum(integer(row['dispatch_thread_cpu_ns']) for row in observer['records']
                    if row['operation'] == 1 and row['dispatch_started'] is True)
    flow = pressure['final_actual_flow']
    require(owner_cpu > 0 and flow['balance_identity_verified'] is True
            and flow['live_owners'] == flow['booked_reservation_ns'] == flow['unsettled_known_live_cpu_ns'] == 0
            and owner_cpu == flow['paid_cpu_debit_ns'] == flow['settled_full_cpu_ns']
                == root['mutation_owner_cpu_ns'] == pressure['service_outcome']['Ok']['mutation_cpu_charged_ns'],
            'GLOBAL_PAID_SETTLEMENT_REQUIRED')
    depleted = checked_depletion_samples(pressure)
    for index, row in enumerate(pressure['confirmations']):
        require(row['round'] == index and row['started_ns'] >= (1 + 4 * index) * 1_000_000_000
                and row['started_ns'] <= row['ended_ns'] < 30_000_000_000
                and row['confirmed_inside_pressure_window'] is True
                and row['observation']['depth'] == 6
                and row['accepted_work_admission_refusal_during_round'] is True
                and row['signed_root_responses_inside_round'] > 0, 'EACH_REAL_ROUND_MUST_OVERLAP_ROOT')
        before, after = row['receiver_hostile_admission_before'], row['receiver_hostile_admission_after']
        require(all(integer(after[key]) > integer(before[key]) for key in
                ('accepted_work_admission_refusals', 'admission_cpu_ns')), 'ACTUAL_ADMISSION_PROGRESS_REQUIRED')
        actual_roots = sum(call['status'] == 'refused' and call['error'] is None
                           and call['returned_after_window'] is False and call['response']['ok'] is False
                           and call['response']['value'].get('error') == 'ROOT'
                           and row['started_ns'] <= integer(call['started_ns']) <= integer(call['ended_ns']) <= row['ended_ns']
                           for call in attacks)
        require(actual_roots == row['signed_root_responses_inside_round'] and actual_roots > 0,
                'EXACT_BODY_SIGNED_ROOT_RESPONSE_REQUIRED')
        numeric_overlap = any(row['started_ns'] <= start <= end <= row['ended_ns'] for start, end, _ in depleted)
        require(row['paid_credit_depletion_observed_during_round'] is numeric_overlap,
                'DEPLETION_MUST_FIT_WHOLE_ROUND')
    require(len(pressure['confirmations']) == 3 and pressure['genuine_budget_depletion_observed'] is True
            and any(row['paid_credit_depletion_observed_during_round'] is True
                    for row in pressure['confirmations']) and value['producer_state_equal'] is True
            and value['supplemental_criteria_met'] is True, 'SUPPLEMENTAL_CRITERIA_FAILED')


def execute(args, output):
    env = environment()
    result = {'schema': 'pon-root-supplement-execution-v2', 'head': args.expected_head,
              'tree': args.expected_tree, 'started_utc': now(), 'inputs': INPUTS,
              'prepared_sha256': args.prepared_sha256, 'binary': None,
              'complete_success': False, 'pressure_selector_executed': False, 'failure': None,
              'post_observations': {}}
    try:
        prepared, binary = prepared_input(args.prepared.resolve(), args.prepared_sha256,
                                          args.expected_head, args.expected_tree)
        result['binary'] = prepared['binary']
        resources = resource_observation()
        write_new(output / 'resource-before.json', resources)
        validate_resources(resources, 10)
        service_identity(output, args.unit, resources, env)
        exact_source(output, 'source-before', env, args.expected_head, args.expected_tree)
        # Claim exactly once after all source/binary/resource preconditions. A failed
        # measured run stays claimed; a new profile must be reviewed as a new cohort.
        write_new(args.prepared.resolve().parent / 'execute-claimed.json',
                  {'out': str(output), 'started_utc': now(), 'prepared_sha256': args.prepared_sha256})
        env['TRNM_ROOT_SUPPLEMENT_REPORT_DIR'] = str(output / 'raw')
        result['pressure_selector_executed'] = True
        result['step'] = run_step(output, 'supplement', [str(binary), '--exact', SELECTOR,
            '--ignored', '--nocapture', '--test-threads=1'], env, timeout=540)
        require(result['step']['complete_success'], 'NATIVE_SUPPLEMENT_FAILED')
        report = json.loads((output / 'raw/report.json').read_text())
        check_report(report, resources['cgroup'])
        result['complete_success'] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['failure'] = str(error)
    finally:
        if result['pressure_selector_executed']:
            # A failed native run remains claimed and failed. Each independent
            # after-observation is still attempted in the original live service;
            # one unavailable observation must not suppress the others.
            def frozen_binary():
                require(sha(binary) == prepared['binary']['sha256'], 'FROZEN_BINARY_CHANGED')

            def after_source():
                exact_source(output, 'source-after', env, args.expected_head, args.expected_tree)

            def after_resources():
                after = resource_observation()
                write_new(output / 'resource-after.json', after)
                validate_resources(after, 10)
                require(after['cgroup'] == resources['cgroup'], 'CGROUP_CHANGED')

            for label, observe in (('binary', frozen_binary), ('source', after_source),
                                   ('resources', after_resources)):
                row = {'complete_success': False, 'failure': None}
                try:
                    observe()
                    row['complete_success'] = True
                except (OSError, ValueError, KeyError, TypeError) as error:
                    row['failure'] = str(error)
                    result['complete_success'] = False
                    if result['failure'] is None:
                        result['failure'] = str(error)
                result['post_observations'][label] = row
    result['completed_utc'] = now()
    result['files'] = {str(p.relative_to(output)): {'bytes': p.stat().st_size, 'sha256': sha(p)}
                       for p in sorted(output.rglob('*')) if p.is_file() and not p.is_symlink()}
    write_new(output / 'results.json', result)
    return result['complete_success']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'execute'))
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-tree', required=True)
    parser.add_argument('--target-dir', type=Path)
    parser.add_argument('--cargo', type=Path)
    parser.add_argument('--prepared', type=Path)
    parser.add_argument('--prepared-sha256')
    parser.add_argument('--unit')
    args = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}', args.expected_head)
            and re.fullmatch('[0-9a-f]{40}', args.expected_tree), 'FULL_HEAD_TREE_REQUIRED')
    validate_source(source_snapshot(), args.expected_head, args.expected_tree)
    output = args.out.resolve()
    require(not output.is_relative_to(ROOT), 'OUTPUT_MUST_BE_OUTSIDE_SOURCE')
    require((args.target_dir and args.cargo) if args.mode == 'prepare'
            else (args.prepared and args.prepared_sha256 and args.unit), 'MODE_ARGUMENTS_REQUIRED')
    output.mkdir(parents=True, exist_ok=False)
    passed = prepare(args, output) if args.mode == 'prepare' else execute(args, output)
    print(json.dumps({'out': str(output), 'mode': args.mode, 'complete_success': passed}))
    return 0 if passed else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
