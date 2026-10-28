#!/usr/bin/env python3
"""Arm or finally observe only this F0 pilot's exact owned systemd services.

This is not a local Host installer. No service-name wildcard, PID kill, public
parent mutation or missing-receipt-to-zero conversion is permitted here.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_fixed_host_root_f0 as runner
import run_fixed_root_phase_host as phase_host
from fixed_root_f0_ownership import (
    MANAGER_PROPERTIES, controller_intent, controller_unit, identity_environment,
    kernel_text, manager_matches, observe_group, parse_manager, phase_unit_matches,
    process_start, receipt, regular_bytes, require, validate_live,
)
from run_pon_w1_native_campaign import ROOT, run_step, sha, write_new


def now():
    return datetime.now(timezone.utc).isoformat()


def hosted_context():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('CI') == 'true'
            and os.getuid() > 0 and Path.cwd() == ROOT
            and os.environ.get('GITHUB_WORKSPACE') == str(ROOT),
            'HOSTED_UNPRIVILEGED_EXACT_SOURCE_ONLY')
    return identity_environment()


def show_service(output, name, unit):
    row = run_step(output, name, ['systemctl', 'show', '--all', unit,
                   '--property=' + ','.join(MANAGER_PROPERTIES)], dict(os.environ),
                   timeout=10, stdout_limit=128 * 1024, stderr_limit=32 * 1024)
    require(row['error'] is None and not row['stdout_truncated'] and not row['stderr_truncated'],
            'MANAGER_OUTPUT_UNAVAILABLE')
    value = parse_manager((output / row['stdout']).read_text())
    require(row['returncode'] == 0 or
            (row['returncode'] == 1 and value['LoadState'] == 'not-found'),
            'MANAGER_EXIT_WITHOUT_NOT_FOUND_OBSERVATION')
    require(value['Id'] == unit, 'EXACT_MANAGER_UNIT_REQUIRED')
    return value


def manager_absent(value):
    return (value['LoadState'] == 'not-found' and value['ControlGroup'] == ''
            and value['MainPID'] in ('', '0')
            and value['ActiveState'] == 'inactive')


def arm_controller(args, out):
    identity = hosted_context()
    runner.validate_source(runner.source_snapshot(), args.expected_head, args.expected_tree)
    prepared_path = out / 'prepared/prepared.json'
    prepared_sha = sha(prepared_path)
    prepared, _binary = runner.prepared_input(prepared_path, prepared_sha,
                                              args.expected_head, args.expected_tree)
    destination = out / 'controller-arm'
    destination.mkdir(exist_ok=False)
    owned = controller_intent(identity, ROOT, out, args.expected_head, args.expected_tree,
                              prepared_sha, prepared['binary'])
    before = show_service(destination, 'prior-manager', owned['service'])
    write_new(destination / 'prior-manager.json', before)
    require(manager_absent(before), 'UNIQUE_UNUSED_CONTROLLER_UNIT_REQUIRED')
    require(not os.path.lexists(Path('/sys/fs/cgroup') / owned['expected_cgroup'][1:]),
            'UNIQUE_UNUSED_CONTROLLER_CGROUP_REQUIRED')
    write_new(out / 'controller-intent.json', owned)
    print(json.dumps({'controller_intent': str(out / 'controller-intent.json'),
                      'unit': owned['service'], 'prepared_sha256': prepared_sha}))
    return True


def expected_prepared(args, out):
    path = out / 'prepared/prepared.json'
    value, binary = runner.prepared_input(path, sha(path), args.expected_head, args.expected_tree)
    return value, binary, sha(path)


def owner_inputs(args, out, phase):
    identity = identity_environment()
    prepared, binary, prepared_sha = expected_prepared(args, out)
    controller = receipt(out / 'controller-intent.json')
    require(controller == controller_intent(identity, ROOT, out, args.expected_head,
            args.expected_tree, prepared_sha, prepared['binary']), 'EXACT_PRIOR_CONTROLLER_INTENT')
    controller_live = receipt(out / 'execution/controller-live.json')
    require(controller_live['schema'] == 'fixed-root-owned-controller-live-v1',
            'EXACT_CONTROLLER_LIVE_SCHEMA')
    validate_live(controller, controller_live)
    if phase == 'controller':
        return controller, controller_live
    control = out / 'execution/raw' / (phase + '-fixed-root-host-control')
    owned = receipt(control / 'host/owned-service.json')
    live = receipt(control / 'host/owned-service-live.json')
    require(owned['schema'] == 'fixed-root-owned-service-v1'
            and live['schema'] == 'fixed-root-owned-service-live-v1'
            and owned['phase'] == phase and owned['prior_load_state'] == 'not-found'
            and all(owned[key] == value for key, value in identity.items())
            and phase_unit_matches(owned['service'], identity, phase)
            and owned['uid'] == os.getuid() and owned['gid'] == os.getgid()
            and owned['source_root'] == str(ROOT), 'EXACT_PHASE_OWNERSHIP_REQUIRED')
    job = control / 'root-phase-job.json'
    require(owned['job_path'] == str(job) and owned['binary_path'] == str(binary)
            and owned['binary_sha256'] == prepared['binary']['sha256']
            and owned['expected_cgroup'] == '/trnmponpublic.slice/' + owned['service'],
            'EXACT_PHASE_PATH_BINARY_AND_GROUP_REQUIRED')
    value, job_sha = phase_host.validate_job(job, binary)
    require(job_sha == owned['job_sha256'] and value['controller'] == owned['controller_identity']
            and value['controller']['process']['cgroup'] == controller_live['cgroup']
            and value['controller']['process']['boot_id'] == controller_live['boot_id']
            and owned['description'] == 'Trillionnium F0 ROOT job ' + job_sha,
            'EXACT_PHASE_JOB_CONTROLLER_BINDING_REQUIRED')
    require(regular_bytes(control / 'host/child-load-state.log', 4096).strip() == b'not-found',
            'ORIGINAL_ABSENT_UNIT_OBSERVATION_REQUIRED')
    validate_live(owned, live)
    return owned, live


def current_process_matches(manager, live):
    if manager['MainPID'] == '0':
        return
    pid = live['pid']
    parent, start = process_start(kernel_text(Path(f'/proc/{pid}/stat')), pid)
    require(parent == live['parent_pid'] and start == live['process_start_ticks']
            and kernel_text(Path(f'/proc/{pid}/cgroup')) == '0::' + live['cgroup'],
            'OWNED_RUNNING_SERVICE_PROCESS_CHANGED')


def cleanup_one(output, owned, live):
    result = {'service': owned['service'], 'phase': owned['phase'],
              'ownership_validated': True, 'cleanup_attempted': False,
              'remaining': 'unknown', 'known_empty': False, 'failure': None,
              'stop_step': None, 'before': None, 'after': None}
    try:
        before = show_service(output, 'manager-before', owned['service'])
        group = observe_group(live)
        result['before'] = {'manager': before, 'group': group}
        if not manager_absent(before):
            manager_matches(before, owned, live)
            already_terminal = before['ActiveState'] in ('inactive', 'failed') and before['MainPID'] == '0'
            if not (already_terminal and group['empty']):
                require(group['exists'], 'LOADED_SERVICE_CGROUP_MUST_BE_OBSERVED')
                current_process_matches(before, live)
                # Identity has now been checked against the actual manager invocation
                # and root-owned cgroup inode. Only this exact unit can be addressed.
                result['cleanup_attempted'] = True
                result['stop_step'] = run_step(output, 'stop-exact-owned-service',
                    ['sudo', '-n', 'systemctl', 'stop', owned['service']], dict(os.environ),
                    timeout=30, stdout_limit=128 * 1024, stderr_limit=32 * 1024)
                if not result['stop_step']['complete_success']:
                    result['failure'] = 'EXACT_OWNED_STOP_FAILED_OR_TIMED_OUT'
        else:
            require(group['empty'], 'ABSENT_MANAGER_WITH_POPULATED_CGROUP')
        # A stop rc=0, reaped launcher, absent controller process group, or elapsed
        # RuntimeMaxSec is never substituted for this independent actual readback.
        after = show_service(output, 'manager-after', owned['service'])
        after_group = observe_group(live)
        result['after'] = {'manager': after, 'group': after_group}
        if manager_absent(after):
            terminal = True
        else:
            manager_matches(after, owned, live)
            terminal = after['ActiveState'] in ('inactive', 'failed') and after['MainPID'] == '0'
        require(terminal and after_group['empty'], 'ACTUAL_SERVICE_OR_DESCENDANTS_REMAIN')
        result['remaining'] = 'observed-empty'
        result['known_empty'] = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result['failure'] = str(error) if result['failure'] is None else result['failure'] + '; ' + str(error)
    return result


def final_report(out, expected_head=None, expected_tree=None):
    value = {'planned_confirmations': 6, 'planned_business_packet_exposures': 42,
             'all_planned_rounds': runner.f0_rounds(None),
             'all_planned_business_packets': runner.f0_packets(None),
             'four_second_slo_successes': 0, 'report_observed': False,
             'native_result_observed': False, 'native_complete_success': False,
             'controller_resources_complete': False, 'controller_resource_summary': None,
             'controller_resource_failure': None,
             'report_failure': None, 'native_result_failure': None}
    try:
        path = out / 'execution/raw/report.json'
        raw = receipt(path, 160 * 1024 * 1024)
        require(raw['schema'] == 'native-public-v3-fixed-host-root-f0-v1', 'EXACT_F0_REPORT_SCHEMA')
        value['report_observed'] = True
        value['report_sha256'] = sha(path)
        value['all_planned_rounds'] = runner.f0_rounds(raw)
        value['all_planned_business_packets'] = runner.f0_packets(raw)
        value['four_second_slo_successes'] = sum(row['four_second_slo_met']
                                                for row in value['all_planned_rounds'])
        try:
            value['controller_resource_summary'] = runner.check_controller_resources(
                raw, raw['controller_identity_before']['process']['cgroup'])
            value['controller_resources_complete'] = True
        except (ValueError, KeyError, TypeError) as error:
            value['controller_resource_failure'] = str(error)
    except (OSError, ValueError, KeyError, TypeError) as error:
        value['report_failure'] = str(error)
    try:
        result = receipt(out / 'execution/results.json', 16 * 1024 * 1024)
        require(result['schema'] == 'pon-fixed-host-root-f0-execution-v1', 'EXACT_F0_RESULT_SCHEMA')
        value['native_result_observed'] = True
        value['native_result_sha256'] = sha(out / 'execution/results.json')
        value['native_result_failure'] = result['failure']
        require(result['head'] == expected_head and result['tree'] == expected_tree
                and result['inputs'] == runner.INPUTS
                and result['prepared_sha256'] == sha(out / 'prepared/prepared.json'),
                'EXACT_NATIVE_RESULT_SOURCE_AND_PREPARATION_REQUIRED')
        require(value['report_observed'] and result.get('report_sha256') == value['report_sha256']
                and result['all_planned_rounds'] == value['all_planned_rounds']
                and result['all_planned_business_packets'] == value['all_planned_business_packets'],
                'NATIVE_RESULT_AND_ACTUAL_REPORT_MUST_AGREE')
        if result['complete_success'] is True:
            require(value['controller_resources_complete'] is True
                    and result.get('controller_resources_complete') is True
                    and result.get('controller_resource_summary') == value['controller_resource_summary'],
                    'COMPLETE_CONTROLLER_RESOURCE_COVERAGE_REQUIRED')
            require(result['native_execution_observed'] is True
                    and result['failure'] is None and result['report_validation_failure'] is None
                    and result['native_result_failure'] is None
                    and result['step']['complete_success'] is True
                    and all(result['post_observations'][name]['complete_success'] is True
                            for name in ('binary', 'source', 'resources')),
                    'COMPLETE_ACTUAL_EXECUTION_AND_POST_OBSERVATIONS_REQUIRED')
            group = receipt(out / 'execution/controller-live.json')['cgroup']
            runner.check_report(raw, group)
            runner.check_f0_placement_and_timing(raw, group)
            value['native_complete_success'] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        value['native_result_failure'] = str(error)
    return value


def finalize(args, out):
    identity = hosted_context()
    destination = out / 'finalization'
    destination.mkdir(exist_ok=False)
    result = {'schema': 'fixed-host-root-f0-finalization-v1', **identity,
              'head': args.expected_head, 'tree': args.expected_tree, 'started_utc': now(),
              'services': [], 'all_services_known_empty': False, 'complete_success': False,
              'scope': 'finite same-host diagnostic; no independent-WAN or production qualification'}
    # Stop/observe controller first: it must not create a later public phase while
    # finalization is inspecting already-created nested services.
    controller_terminal = False
    for phase in ('controller', 'baseline', 'valid-work-root'):
        directory = destination / phase
        directory.mkdir()
        row = {'phase': phase, 'service': None, 'ownership_validated': False,
               'cleanup_attempted': False, 'known_empty': False, 'remaining': 'unknown',
               'failure': None}
        try:
            owned, live = owner_inputs(args, out, phase)
            write_new(directory / 'validated-owned-receipt.json', owned)
            write_new(directory / 'validated-live-receipt.json', live)
            row = cleanup_one(directory, owned, live)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            row['failure'] = str(error)
        row['observed_empty_at_readback'] = row['known_empty']
        if phase == 'controller':
            controller_terminal = row['known_empty'] is True
        else:
            row['controller_terminal_before_phase_observation'] = controller_terminal
            if not controller_terminal and row['known_empty']:
                # The still-live controller could create a later phase after
                # this observation. Preserve the readback but not a final-empty
                # claim, and do not widen cleanup to any unverified service.
                row['known_empty'] = False
                row['remaining'] = 'unknown-controller-not-terminal'
        result['services'].append(row)
        write_new(directory / 'result.json', row)
    result['denominator'] = final_report(out, args.expected_head, args.expected_tree)
    result['all_services_known_empty'] = all(row['known_empty'] for row in result['services'])
    result['complete_success'] = (result['all_services_known_empty']
        and all(row['failure'] is None for row in result['services'])
        and result['denominator']['native_complete_success']
        and result['denominator']['controller_resources_complete']
        and result['denominator']['report_observed']
        and result['denominator']['four_second_slo_successes'] == 6)
    result['completed_utc'] = now()
    write_new(destination / 'result.json', result)
    print(json.dumps({'out': str(destination), 'complete_success': result['complete_success'],
                      'planned_confirmations': 6, 'planned_business_packet_exposures': 42,
                      'all_services_known_empty': result['all_services_known_empty']}))
    return result['complete_success']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('controller-intent', 'finalize'))
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-tree', required=True)
    args = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}', args.expected_head) is not None
            and re.fullmatch('[0-9a-f]{40}', args.expected_tree) is not None,
            'EXACT_F0_HEAD_TREE_REQUIRED')
    out = args.out
    require(out.is_absolute() and out.resolve(strict=True) == out
            and not out.is_relative_to(ROOT), 'OWNED_OUTPUT_OUTSIDE_SOURCE')
    return 0 if (arm_controller(args, out) if args.mode == 'controller-intent'
                 else finalize(args, out)) else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
