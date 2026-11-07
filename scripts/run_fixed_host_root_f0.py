#!/usr/bin/env python3
"""Freeze and execute one separately named fixed-Host ROOT F0 pilot.

Preparation only compiles. Execute must be an unprivileged hosted system service
with the unchanged 400% / 16 GiB controller ceilings; the actual public phases
use the original 0.25-core / 2 GiB Host via their independent exact launcher.
No retry, local fallback, F1 parameter, original-entry mutation or WAN claim.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import platform
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / 'ci'))
from run_pon_w1_native_campaign import (
    ROOT, require, resource_observation, run_step, sha, source_snapshot,
    validate_build_environment, validate_resources, validate_source, write_new,
)
from read_original_native_campaign import depletion, integer
from fixed_root_f0_ownership import (
    MANAGER_PROPERTIES, controller_intent, controller_unit, identity_environment,
    live_identity, manager_matches, parse_manager, receipt,
)
from fixed_root_f0_resources import SCHEMA as CONTROLLER_RESOURCE_SCHEMA, check_controller_resources

SELECTOR = 'fixed_public_host_root_rejection_and_signed_confirmation_diagnostic'
PHASE_PROFILE = 'fixed-public-root-phase-external-actors-v1'
INPUTS = {'seed_transfers': 1024, 'seed_blocks': 4, 'business_blocks': 21,
          'phase_seconds': 30, 'actor_call_cap': 480, 'planned_complete_runs': 1,
          'attackers': 24, 'm06_workers': 1, 'confirmation_depth': 6,
          'round_start_seconds': [1, 5, 9], 'cpu_burst_ns': 2_000_000_000,
          'cpu_refill_ns_per_second': 250_000_000, 'start_reserve_ns': 100_000_000,
          'phase_profile': PHASE_PROFILE, 'planned_phases': ['baseline', 'valid-work-root'],
          'planned_confirmations': 6, 'planned_business_packets': 42,
          'four_second_slo_ns': 4_000_000_000, 'slo_starts_at_scheduled_offset': True,
          'legacy_four_second_from_zero_epoch_changed': False, 'f1_implemented': False,
          'controller_resource_schema': CONTROLLER_RESOURCE_SCHEMA,
          'controller_resource_boundary_samples': 6}
QUALIFICATIONS = ('original_campaign_qualified', 'work_profile_qualified',
                  'independent_operators', 'wan_qualified', 'production_candidate',
                  'production_activation')
SOURCE_CONTROLS = (
    'phase_host::separate_broker_scope_clears_on_unwind_and_refuses_missing_actors',
    'root_phase_host::fixed_root_denominators_retain_all_missing_failed_and_duplicate_rounds',
    'root_phase_host::fixed_root_proc_identity_requires_exact_pid_and_start_despite_command_parentheses',
    'root_phase_host::fixed_root_four_second_slo_cannot_remove_queue_or_prior_round_delay',
    'root_phase_host::fixed_root_job_requires_its_exact_profile_and_complete_workload',
    'root_phase_host::controller_resources::fixed_root_controller_resource_parser_rejects_missing_duplicate_and_unknown_counters',
    'root_phase_host::controller_resources::fixed_root_controller_resource_interval_rejects_rewind_and_lifetime_peak_as_delta',
)


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
    result = {'schema': 'pon-fixed-host-root-f0-prepared-v1', 'head': args.expected_head,
              'tree': args.expected_tree, 'runner_sha256': sha(__file__), 'inputs': INPUTS,
              'created_utc': now(), 'prepared': False, 'selector_invocation_attempted': False,
              'steps': [], 'failure': None}
    try:
        write_new(output / 'resource-at-preparation.json', resource_observation())
        meminfo = Path('/proc/meminfo').read_text()
        total_kib = next((int(line.split()[1]) for line in meminfo.splitlines()
                          if line.startswith('MemTotal:')), None)
        write_new(output / 'hardware.json', {
            'machine': platform.machine(), 'kernel': platform.release(),
            'logical_cpu_count': os.cpu_count(), 'affinity': sorted(os.sched_getaffinity(0)),
            'meminfo': meminfo, 'physical_memtotal_bytes': None if total_kib is None else total_kib*1024,
            'controller_memory_max_bytes': 17179869184,
            'ceiling_is_not_reserved_physical_memory_or_cpu': True,
        })
        result['steps'].append(exact_source(output, 'source-before', env,
                                           args.expected_head, args.expected_tree))
        cargo = [str(args.cargo.absolute()), '+1.95.0']
        for label, command in (
            ('preflight', ['/bin/bash', 'scripts/project-preflight.sh', '--audit']),
            ('rustc-version', [str(args.cargo.absolute().parent / 'rustup'), 'run', '1.95.0', 'rustc', '-Vv']),
            ('cargo-version', [*cargo, '-Vv']),
            ('format', [*cargo, 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--check']),
            ('clippy', [*cargo, 'clippy', '--offline', '--locked', '--release', '--jobs', '2',
                        '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node',
                        '--test', 'public_v3_multiprocess', '--', '-D', 'warnings']),
            ('build', [*cargo, 'test', '--offline', '--locked', '--release', '--jobs', '2',
                       '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node',
                       '--test', 'public_v3_multiprocess', '--no-run', '--message-format=json'])):
            row = run_step(output, label, command, env, timeout=1800 if label == 'build' else 900 if label == 'clippy' else 60)
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
        result['rust_source_control_selectors'] = list(SOURCE_CONTROLS)
        result['rust_source_controls'] = []
        for index, selector in enumerate(SOURCE_CONTROLS):
            row = run_step(output, f'source-control-{index}', [str(retained), '--exact', selector,
                           '--nocapture', '--test-threads=1'], env, timeout=30)
            result['rust_source_controls'].append(row)
            stdout = (output / row['stdout']).read_text(errors='replace')
            require(row['complete_success'] and re.search(
                    r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', stdout, re.MULTILINE)
                    is not None, 'EXACT_NATIVE_SOURCE_CONTROL_FAILED')
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
    require(value['schema'] == 'pon-fixed-host-root-f0-prepared-v1' and value['prepared'] is True
            and value['selector_invocation_attempted'] is False and value['head'] == head
            and value['tree'] == tree and value['inputs'] == INPUTS
            and value['runner_sha256'] == sha(__file__), 'FROZEN_PREPARATION_REQUIRED')
    binary = Path(value['binary']['path'])
    require(binary == path.parent / 'public_v3_multiprocess.bin' and not binary.is_symlink()
            and binary.is_file() and binary.stat().st_mode & 0o222 == 0
            and binary.stat().st_size == value['binary']['bytes']
            and sha(binary) == value['binary']['sha256'], 'FROZEN_BINARY_SHA_REQUIRED')
    return value, binary


def service_identity(output, unit, resources, env):
    require(unit == controller_unit(identity_environment()), 'EXACT_F0_SYSTEM_SERVICE_REQUIRED')
    require(resources['cgroup'].endswith('/' + unit), 'CONTROLLER_MUST_OWN_DECLARED_SERVICE')
    row = run_step(output, 'service-identity', ['systemctl', 'show', unit,
        '--all', '--property=' + ','.join(MANAGER_PROPERTIES)], env, timeout=10)
    require(row['complete_success'], 'F0_SYSTEM_SERVICE_OBSERVATION_FAILED')
    values = parse_manager((output / row['stdout']).read_text())
    require(values.get('ControlGroup') == resources['cgroup']
            and values.get('MainPID') == str(os.getpid()) and values.get('KillMode') == 'control-group',
            'SERVICE_OWNERSHIP_AND_CLEANUP_REQUIRED')
    # Retain the exact runtime ceiling separately; manager identity is also bound
    # to its observed invocation rather than accepting a reused service name.
    runtime = run_step(output, 'service-runtime', ['systemctl', 'show', unit,
                       '--property=RuntimeMaxUSec', '--value'], env, timeout=10)
    require(runtime['complete_success']
            and (output / runtime['stdout']).read_text().strip() == '10min',
            'ORIGINAL_F0_CONTROLLER_OUTER_CEILING_REQUIRED')
    return values


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
    check_controller_resources(value, cgroup)
    require(value['schema'] == 'native-public-v3-fixed-host-root-f0-v1'
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



def f0_rounds(value):
    """All six scheduled slots remain even when a phase or report is missing."""
    phases = value.get('phases', []) if isinstance(value, dict) else []
    phases = phases if isinstance(phases, list) else []
    result = []
    for phase_index, name in enumerate(('baseline', 'valid-work-root')):
        phase = phases[phase_index] if phase_index < len(phases) else {}
        rows = phase.get('confirmations', []) if isinstance(phase, dict) and phase.get('mode') == name else []
        rows = rows if isinstance(rows, list) else []
        for ordinal in range(3):
            matches = [row for row in rows if isinstance(row, dict) and type(row.get('round')) is int and row.get('round') == ordinal]
            observed = len(matches) == 1
            row = matches[0] if observed else {}
            scheduled = (1 + 4 * ordinal) * 1_000_000_000
            started, ended = row.get('started_ns'), row.get('ended_ns')
            known = type(started) is int and type(ended) is int and scheduled <= started <= ended
            confirmed = observed and row.get('confirmed_inside_pressure_window') is True
            elapsed = ended - scheduled if type(ended) is int and ended >= scheduled else None
            slo = confirmed and known and elapsed < 4_000_000_000 and ended < 30_000_000_000
            result.append({'phase': name, 'round': ordinal, 'scheduled_offset_ns': scheduled,
                           'actual_started_ns': started, 'actual_ended_ns': ended,
                           'elapsed_from_scheduled_ns': elapsed,
                           'start_lateness_from_schedule_ns': started - scheduled if known else None,
                           'end_lateness_from_four_second_deadline_ns': max(0, ended-scheduled-4_000_000_000) if known else None,
                           'observed_exactly_once': observed,
                           'confirmed_inside_original_window': confirmed,
                           'four_second_slo_met': slo})
    return result



def f0_packets(value):
    phases = value.get('phases', []) if isinstance(value, dict) else []
    phases = phases if isinstance(phases, list) else []
    result = []
    for phase_index, name in enumerate(('baseline', 'valid-work-root')):
        phase = phases[phase_index] if phase_index < len(phases) else {}
        rows = phase.get('submissions', []) if isinstance(phase, dict) and phase.get('mode') == name else []
        rows = rows if isinstance(rows, list) else []
        for ordinal in range(21):
            attempts = [row for row in rows if isinstance(row, dict)
                        and type(row.get('packet_index')) is int and row.get('packet_index') == ordinal]
            result.append({'phase': name, 'packet_index': ordinal, 'observed_attempts': len(attempts),
                           'timely_network_ack': any(row.get('status') == 'ok'
                                                    and row.get('returned_after_window') is False
                                                    for row in attempts),
                           'ack_is_not_confirmation': True})
    return result


def check_f0_actor_membership(membership, controller, identity, expected):
    require(membership['verified'] is True and membership['controller_check'] == {'Ok': None}
            and membership['controller_identity'] == identity
            and membership['expected_actors'] == membership['observed_actors']
            == membership['distinct_pids'] == controller['launched'] == controller['reaped'] == expected
            and len(membership['actors']) == len(controller['actual_attack_process_contexts']) == expected,
            'F0_ALL_ACTUAL_ACTOR_IDENTITIES_REQUIRED')
    pids = set()
    for index, actor in enumerate(membership['actors']):
        observation = actor['observation']['Ok']
        process = observation['identity']
        spawned = controller['actual_attack_process_contexts'][index]
        pid = process['pid']
        require(type(pid) is int and pid > 1 and pid not in pids
                and type(actor['ordinal']) is int and actor['ordinal'] == index
                and type(spawned['ordinal']) is int and spawned['ordinal'] == index
                and actor['verified'] is True and actor['pid'] == pid == spawned['pid']
                and observation['spawn_observation'] == spawned
                and spawned['identity'] == process
                and process['cgroup'] == identity['process']['cgroup']
                and process['parent_pid'] == identity['process']['pid']
                and process['boot_id'] == identity['process']['boot_id']
                and type(process['start_ticks']) is int and process['start_ticks'] > 0
                and process['executable'] == identity['process']['executable']
                and observation['ready']['pid'] == pid
                and observation['ready']['mode'] == 'valid-work-root'
                and observation['ready']['cgroup'] == identity['process']['cgroup'],
                'F0_ACTOR_IDENTITY_BINDING')
        pids.add(pid)
    require(len(pids) == expected, 'F0_DISTINCT_OBSERVED_ACTOR_PIDS_REQUIRED')


def check_f0_placement_and_timing(value, cgroup):
    check_controller_resources(value, cgroup)
    require(value['placement_profile'] == PHASE_PROFILE and value['placement_complete'] is True
            and value['controller_stable'] is True and value['planned_confirmations'] == 6
            and value['new_f1_parameters_implemented'] is False
            and value['original_scalar_profile_changed'] is False, 'F0_EXPLICIT_PLACEMENT_REQUIRED')
    identity = value['controller_identity_before']
    require(value['controller_identity_after'] == {'Ok': identity}
            and identity['process']['cgroup'] == cgroup, 'F0_SAME_CONTROLLER_IDENTITY_REQUIRED')
    phases = value['phases']
    require(len(phases) == 2, 'F0_BOTH_PLANNED_PHASES_REQUIRED')
    for ordinal, phase in enumerate(phases):
        expected = 0 if ordinal == 0 else 24
        membership = phase['fixed_root_external_actor_membership']
        context, controller = phase['phase_process_context'], phase['external_controller_observation']
        require(context['schema'] == controller['schema'] == PHASE_PROFILE
                and context['controller_identity'] == controller['controller_identity'] == identity
                and context['controller_live_identity_after_verified'] is True
                and controller['controller_live_identity_after_verified'] is True
                and context['runtime_business_deadline_changed'] is False
                and context['scalar_policy_changed'] is False
                and context['phase_cgroup'] != cgroup
                and phase['duration_seconds'] == 30, 'F0_EXACT_PHASE_PLACEMENT_REQUIRED')
        check_f0_actor_membership(membership, controller, identity, expected)
        meter = phase['initial_meter']
        require(meter['burst_ns'] == 2_000_000_000 and meter['refill_ns_per_second'] == 250_000_000
                and meter['start_reserve_ns'] == 100_000_000 and meter['worker_limit'] == 2,
                'F0_ORIGINAL_CPU_GEOMETRY_REQUIRED')
    rounds = f0_rounds(value)
    require(len(value['all_planned_rounds']) == 6 and all(row['four_second_slo_met'] for row in rounds),
            'F0_ALL_SIX_SCHEDULED_FOUR_SECOND_TARGETS_REQUIRED')
    for actual, retained in zip(rounds, value['all_planned_rounds']):
        require(all(retained[key] == observed for key, observed in actual.items()),
                'F0_SCHEDULED_CLOCK_OR_DENOMINATOR_CHANGED')
        require(retained['old_root_code_already_enforced_four_second_slo'] is False,
                'F0_MUST_NOT_REWRITE_OLD_TIMING_CLAIM')
    packets = value['all_planned_business_packets']
    require(len(packets) == 42, 'F0_ALL_BUSINESS_EXPOSURES_REQUIRED')
    for index, packet in enumerate(packets):
        phase, position = divmod(index, 21)
        require(packet['phase'] == ('baseline' if phase == 0 else 'valid-work-root')
                and packet['packet_index'] == position and packet['ack_is_not_confirmation'] is True,
                'F0_BUSINESS_DENOMINATOR_IDENTITY')
        attempts = [row for row in phases[phase]['submissions'] if row['packet_index'] == position]
        on_time = any(row['status'] == 'ok' and row['returned_after_window'] is False for row in attempts)
        require(packet['observed_attempts'] == len(attempts) and packet['timely_network_ack'] is on_time
                and on_time, 'F0_REAL_BUSINESS_ATTEMPTS_REQUIRED')


def execute(args, output):
    env = environment()
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('CI') == 'true'
            and os.getuid() != 0, 'HOSTED_UNPRIVILEGED_F0_EXECUTION_REQUIRED')
    result = {'schema': 'pon-fixed-host-root-f0-execution-v1', 'head': args.expected_head,
              'tree': args.expected_tree, 'started_utc': now(), 'inputs': INPUTS,
              'prepared_sha256': args.prepared_sha256, 'binary': None,
              'complete_success': False, 'selector_invocation_attempted': False, 'failure': None,
              'post_observations': {}, 'all_planned_rounds': f0_rounds(None),
              'planned_confirmations': 6, 'planned_business_packet_exposures': 42,
              'four_second_slo_successes': 0, 'all_planned_business_packets': f0_packets(None),
              'report_validation_failure': None,
              'native_result_failure': None, 'native_execution_observed': False}
    result['controller_resources_complete'] = False
    result['controller_resource_summary'] = None
    try:
        prepared, binary = prepared_input(args.prepared.resolve(), args.prepared_sha256,
                                          args.expected_head, args.expected_tree)
        result['binary'] = prepared['binary']
        resources = resource_observation()
        write_new(output / 'resource-before.json', resources)
        validate_resources(resources, 10)
        manager = service_identity(output, args.unit, resources, env)
        intent = controller_intent(identity_environment(), ROOT, output.parent,
                                   args.expected_head, args.expected_tree,
                                   args.prepared_sha256, prepared['binary'])
        require(receipt(output.parent / 'controller-intent.json') == intent,
                'EXACT_CONTROLLER_PRIOR_INTENT_REQUIRED')
        live = live_identity(args.unit, resources['cgroup'], manager)
        manager_matches(manager, intent, live)
        write_new(output / 'controller-live.json', {
            **live, 'schema': 'fixed-root-owned-controller-live-v1', 'phase': 'controller',
            'job_sha256': args.prepared_sha256, 'binary_sha256': prepared['binary']['sha256'],
        })
        exact_source(output, 'source-before', env, args.expected_head, args.expected_tree)
        # Claim exactly once after all source/binary/resource preconditions. A failed
        # measured run stays claimed; a new profile must be reviewed as a new cohort.
        write_new(args.prepared.resolve().parent / 'execute-claimed.json',
                  {'out': str(output), 'started_utc': now(), 'prepared_sha256': args.prepared_sha256})
        env['TRNM_FIXED_HOST_ROOT_REPORT_DIR'] = str(output / 'raw')
        result['selector_invocation_attempted'] = True
        result['step'] = run_step(output, 'supplement', [str(binary), '--exact', SELECTOR,
            '--ignored', '--nocapture', '--test-threads=1'], env, timeout=540)
        result['direct_process_exit_observed'] = result['step']['returncode'] is not None
        captured_stdout = (output / result['step']['stdout']).read_text(errors='replace')
        result['native_execution_observed'] = (True if re.search(
            r'^test ' + re.escape(SELECTOR) + r' \.\.\.', captured_stdout, re.MULTILINE) else None)
        if not result['step']['complete_success']:
            result['native_result_failure'] = 'NATIVE_F0_FAILED'
        try:
            report_path = output / 'raw/report.json'
            report = receipt(report_path, 160 * 1024 * 1024)
            result['report_sha256'] = sha(report_path)
            result['all_planned_rounds'] = f0_rounds(report)
            result['all_planned_business_packets'] = f0_packets(report)
            result['four_second_slo_successes'] = sum(row['four_second_slo_met']
                                                    for row in result['all_planned_rounds'])
            result['controller_resource_summary'] = check_controller_resources(report, resources['cgroup'])
            result['controller_resources_complete'] = True
            check_report(report, resources['cgroup'])
            check_f0_placement_and_timing(report, resources['cgroup'])
        except (OSError, ValueError, KeyError, TypeError) as error:
            result['report_validation_failure'] = str(error)
        require(result['native_result_failure'] is None, 'NATIVE_F0_FAILED')
        require(result['report_validation_failure'] is None, 'F0_REPORT_OR_SERVICE_CRITERIA_FAILED')
        stdout = (output / result['step']['stdout']).read_text(errors='replace')
        require(re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', stdout, re.MULTILINE)
                is not None, 'EXACT_ONE_NATIVE_F0_TEST_REQUIRED')
        result['complete_success'] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['failure'] = str(error)
    finally:
        if result['selector_invocation_attempted']:
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
    result['files'], result['file_inventory_errors'] = {}, []
    for path in sorted(output.rglob('*')):
        try:
            require(not path.is_symlink() and path.resolve(strict=True) == path,
                    'REGULAR_OWNED_ARTIFACT_PATH_REQUIRED')
            if path.is_dir():
                continue
            require(path.is_file(), 'REGULAR_OWNED_ARTIFACT_FILE_REQUIRED')
            before = path.stat()
            digest = sha(path)
            after = path.stat()
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                    'ARTIFACT_CHANGED_DURING_INVENTORY')
            result['files'][str(path.relative_to(output))] = {'bytes': after.st_size, 'sha256': digest}
        except (OSError, ValueError) as error:
            result['file_inventory_errors'].append({'path': str(path.relative_to(output)), 'failure': str(error)})
            result['complete_success'] = False
            if result['failure'] is None:
                result['failure'] = str(error)
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
    write_new(output / 'predeclared.json', {'schema': 'fixed-host-root-f0-runner-predeclaration-v1',
              'mode': args.mode, 'inputs': INPUTS, 'selector': SELECTOR,
              'head': args.expected_head, 'tree': args.expected_tree,
              'all_planned_rounds': f0_rounds(None), 'all_planned_business_packets': f0_packets(None),
              'runner_sha256': sha(__file__),
              'four_second_slo_is_additional_to_old_root_predicate': True,
              'native_execution_observed': False, 'independent_wan_qualification': False})
    passed = prepare(args, output) if args.mode == 'prepare' else execute(args, output)
    print(json.dumps({'out': str(output), 'mode': args.mode, 'complete_success': passed}))
    return 0 if passed else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
