#!/usr/bin/env python3
"""Exact-source validation of grouped metering and the original native owners.

The original twenty-four command records are an unchanged prefix. Nine further
gates cover the native funded-task/M12 owners and their demand/evaluation
relations. This selected combined scope is not the full Node target inventory,
the public service campaign, physical cost qualification or consensus admission.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
RELATIVE = 'formal/pon-nakamoto-v1/experiments/validate_grouped_profile_closure_v1.py'
ORIGINAL_RELATIVE = 'formal/pon-nakamoto-v1/experiments/validate_grouped_fresh_work_v0.py'
ORIGINAL_DRIVER_SHA256 = 'f32c38ce97270511783051b48b1249c7ce0e93af0c4e728077cdddfaeef64b64'
ORIGINAL_COMMANDS = 24
ADDITIONAL_COMMANDS = 9
SELF_LOADED_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _original_module():
    path = Path(__file__).resolve().with_name('validate_grouped_fresh_work_v0.py')
    raw = path.read_bytes()
    name = 'grouped_profile_original_' + hashlib.sha256(str(path).encode()).hexdigest()[:16]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Execute these exact bytes instead of a possibly older bytecode cache.
    # No original globals, helper functions or command records are rewritten.
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module, hashlib.sha256(raw).hexdigest()


original, ORIGINAL_LOADED_SHA256 = _original_module()


def commands(python, env, fuzz_cargo_home):
    prefix = original.commands(python, env, fuzz_cargo_home)
    if len(prefix) != ORIGINAL_COMMANDS:
        raise ValueError('ORIGINAL_COMMAND_INVENTORY_CHANGED')
    manifest = ['--manifest-path', 'trillionnium/Cargo.toml']
    cargo_test = ['cargo', 'test', '--offline', '--locked', *manifest]
    appended = [
        ('native-task-core-all-targets', cargo_test + [
            '-p', 'trnm-service-settlement', '-p', 'trnm-protocol', '-p', 'trnm-mvcc-fee',
            '--all-targets', '--all-features', '--no-fail-fast']),
        *[(label, cargo_test + ['-p', 'trnm-pon-node', '--all-features', '--test', target])
          for label, target in (
              ('native-funded-service-contract', 'funded_service_contract'),
              ('native-active-anchor', 'native_active_anchor'),
              ('native-demand-evidence', 'native_demand_evidence'),
              ('native-task-operation-v2', 'native_task_operation_v2'),
              ('native-no-gain-fees', 'no_gain_fees'))],
        ('demand-evidence-python', [python, '-B',
            'formal/pon-nakamoto-v1/test_demand_evidence.py', '-v']),
        ('upgrade-policy-python', [python, '-B',
            'formal/pon-nakamoto-v1/test_upgrade_policy.py', '-v']),
        ('pq-research-integration-controls', [python, '-B',
            'scripts/ci/test_pq_research_integration.py']),
    ]
    result = list(prefix)
    for ordinal, (label, argv) in enumerate(appended, ORIGINAL_COMMANDS + 1):
        override = {}
        if label == 'native-task-operation-v2':
            override = {'TRNM_CAPTURE_NATIVE_TASK_CURRENT_V3': '1'}
            argv = argv + ['--', '--nocapture']
        command = {
            'ordinal': ordinal, 'label': label, 'command': argv,
            'environment_overrides': override, 'timeout_seconds': original.TIMEOUT_SECONDS,
            'original_gate': False, 'prior_fresh_floor_gate': False,
            'profile_closure_gate': True,
        }
        command['command_sha256'] = hashlib.sha256(original.canonical(command)).hexdigest()
        result.append(command)
    if len(appended) != ADDITIONAL_COMMANDS or len({row['label'] for row in result}) != len(result):
        raise ValueError('COMBINED_COMMAND_INVENTORY')
    return result


def driver_bindings():
    return {
        'driver_relative_path': RELATIVE,
        'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'loaded_driver_sha256': SELF_LOADED_SHA256,
        'original_driver_relative_path': ORIGINAL_RELATIVE,
        'original_driver_sha256': hashlib.sha256(Path(original.__file__).read_bytes()).hexdigest(),
        'loaded_original_driver_sha256': ORIGINAL_LOADED_SHA256,
        'frozen_original_driver_sha256': ORIGINAL_DRIVER_SHA256,
    }


def source_snapshot(repo, source_sha):
    """Pin both executing drivers, then reuse the complete original source guard."""
    if len(source_sha) != 40 or any(c not in '0123456789abcdef' for c in source_sha):
        raise ValueError('EXPECTED_SOURCE_SHA_FORMAT')
    if Path(__file__).resolve() != repo / RELATIVE:
        raise ValueError('EXECUTING_DRIVER_OUTSIDE_EXPECTED_REPOSITORY')
    if Path(original.__file__).resolve() != repo / ORIGINAL_RELATIVE:
        raise ValueError('ORIGINAL_DRIVER_OUTSIDE_EXPECTED_REPOSITORY')
    bindings = driver_bindings()
    if bindings['driver_sha256'] != SELF_LOADED_SHA256:
        raise ValueError('EXECUTING_DRIVER_CHANGED_SINCE_LOAD')
    if not (bindings['original_driver_sha256'] == ORIGINAL_LOADED_SHA256 == ORIGINAL_DRIVER_SHA256):
        raise ValueError('ORIGINAL_DRIVER_NOT_EXACT_FROZEN_BYTES')
    for relative in (RELATIVE, ORIGINAL_RELATIVE):
        committed = subprocess.check_output(
            ['git', '--no-replace-objects', 'show', source_sha + ':' + relative], cwd=repo)
        if committed != (repo / relative).read_bytes():
            raise ValueError('EXECUTING_DRIVER_NOT_EXACT_COMMITTED_BYTES:' + relative)
    return original.source_snapshot(repo, source_sha)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=ROOT)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--runner', required=True, type=Path)
    parser.add_argument('--fresh-runner', required=True, type=Path)
    parser.add_argument('--authority-runner', required=True, type=Path)
    parser.add_argument('--fuzz-cargo-home', type=Path)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    repo, out = args.repo.resolve(), args.out.resolve()
    if out == repo or repo in out.parents:
        raise ValueError('OUTPUT_MUST_BE_OUTSIDE_SOURCE_CHECKOUT')
    if not all(hasattr(os, name) for name in ('waitid', 'P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT', 'killpg')):
        raise ValueError('POSIX_PROCESS_GROUP_AND_WNOWAIT_REQUIRED')
    out.mkdir(parents=True, exist_ok=False)
    runners = {
        'grouped': args.runner.resolve(), 'fresh': args.fresh_runner.resolve(),
        'authority': args.authority_runner.resolve(),
    }
    env = dict(os.environ, TRNM_GROUPED_NATIVE=str(runners['grouped']),
               TRNM_GROUPED_FRESH_NATIVE=str(runners['fresh']),
               TRNM_GROUPED_AUTHORITY_NATIVE=str(runners['authority']),
               RUST_TEST_THREADS='1', PYTHONDONTWRITEBYTECODE='1')
    fuzz_home = args.fuzz_cargo_home.resolve() if args.fuzz_cargo_home else None
    planned = commands(sys.executable, env, fuzz_home)
    drivers_before = driver_bindings()
    original.save(out / 'plan.json', {
        'schema': 'pon-grouped-profile-closure-validation-plan-v1',
        'created_utc': original.utc(), 'repository': str(repo),
        'expected_source_sha': args.source_sha, **drivers_before,
        'commands': planned, 'planned_commands': len(planned),
        'unchanged_prefix_commands': ORIGINAL_COMMANDS,
        'additional_owner_relation_commands': ADDITIONAL_COMMANDS,
        'original_fairness_gates': 18, 'prior_fresh_floor_gates': 21,
        'prior_resource_transfer_gates': 24,
        'timeout_seconds_per_command': original.TIMEOUT_SECONDS,
        'fuzz_cargo_home_override': str(fuzz_home) if fuzz_home else None,
        'runners': {key: str(value) for key, value in runners.items()},
        'source_validation_is_not_qualification': True,
        'full_node_target_inventory_executed': False,
        'original_service_campaign_executed': False,
        'prior_failed_campaigns_superseded': False,
        'production_activation': False,
    })
    original.save(out / 'environment.json', {key: env.get(key) for key in original.ENVIRONMENT_KEYS})
    original.save(out / 'driver-bindings.json', drivers_before)
    original.save(out / 'runners-before.json', {name: original.artifact(path) for name, path in runners.items()})
    before = after = None
    failures, records, built = [], [], {}
    try:
        before = source_snapshot(repo, args.source_sha)
        original.save(out / 'source-before.json', {
            'status': 'PASS', 'source': before, 'drivers': drivers_before,
        })
    except Exception as error:
        failures.append({'stage': 'source-before', 'type': type(error).__name__, 'message': str(error)})
        original.save(out / 'source-before.json', {'status': 'FAIL', 'error': failures[-1]})
    with (out / 'commands.ndjson').open('x', encoding='utf-8') as ledger:
        interrupted = False
        for command in planned:
            if before is None or interrupted:
                record = original.not_started(command,
                    'EXACT_SOURCE_GATE_FAILED' if before is None else 'DRIVER_INTERRUPTED')
            else:
                record = original.run_command(command, repo, env, out)
                interrupted = bool(record.get('interrupted'))
                build_names = {
                    'native-build': 'grouped', 'fresh-native-build': 'fresh',
                    'authority-native-build': 'authority',
                }
                if record['label'] in build_names and record['status'] == 'PASS':
                    name = build_names[record['label']]
                    built[name] = original.artifact(runners[name])
                    record['built_runner'] = built[name]
            records.append(record)
            original.save(out / (command['label'] + '.result.json'), record)
            ledger.write(json.dumps(record, sort_keys=True, allow_nan=False) + '\n')
            ledger.flush()
            os.fsync(ledger.fileno())
            print(json.dumps(record, sort_keys=True), flush=True)
    original.save(out / 'commands.json', records)
    try:
        after = source_snapshot(repo, args.source_sha)
        drivers_after = driver_bindings()
        if before != after or drivers_after != drivers_before:
            raise ValueError('EXACT_SOURCE_CHANGED')
        original.save(out / 'source-after.json', {
            'status': 'PASS', 'source': after, 'drivers': drivers_after,
        })
    except Exception as error:
        failures.append({'stage': 'source-after', 'type': type(error).__name__, 'message': str(error)})
        original.save(out / 'source-after.json', {'status': 'FAIL', 'error': failures[-1], 'source': after})
    binding = original.runner_bindings(repo, out, records, runners, built)
    original.save(out / 'runner-bindings.json', binding)
    passed = (not failures and binding['status'] == 'PASS'
              and len(records) == len(planned)
              and all(row['status'] == 'PASS' for row in records))
    summary = {
        'schema': 'pon-grouped-profile-closure-local-validation-v1',
        'source': before, 'status': 'PASS' if passed else 'FAIL',
        'expected_source_sha': args.source_sha, **drivers_before,
        'commands_planned': len(planned), 'commands_recorded': len(records),
        'complete_command_denominator': len(records) == len(planned),
        'unchanged_prefix_commands': ORIGINAL_COMMANDS,
        'additional_owner_relation_commands': ADDITIONAL_COMMANDS,
        'commands_passed': sum(row['status'] == 'PASS' for row in records),
        'commands_failed': sum(row['status'] == 'FAIL' for row in records),
        'commands_not_started': sum(row['status'] == 'NOT_STARTED' for row in records),
        'commands_timed_out': sum(row['timed_out'] for row in records),
        'source_failures': failures, 'runner_bindings': binding,
        'native_runner_sha256': binding['artifacts']['grouped'].get('sha256'),
        'fresh_native_runner_sha256': binding['artifacts']['fresh'].get('sha256'),
        'authority_native_runner_sha256': binding['artifacts']['authority'].get('sha256'),
        'full_node_target_inventory_executed': False,
        'full_workspace_unit_tests_executed': False,
        'original_service_campaign_executed': False,
        'prior_failed_campaigns_superseded': False,
        'genuine_independent_demand_established': False,
        'minimum_legal_cost_proved': False,
        'physical_resource_lower_bound_proved': False,
        'native_consensus_profile_qualified': False,
        'pow_qualified': False, 'chainwork_awarded': 0, 'production_activation': False,
    }
    original.save(out / 'summary.json', summary)
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
