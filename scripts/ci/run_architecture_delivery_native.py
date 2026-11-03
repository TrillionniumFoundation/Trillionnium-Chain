#!/usr/bin/env python3
"""Run the complete Cargo-selected architecture test in the original fixed Host.

Cargo performs the original workspace build outside the service. This module
binds its selected binary, both unchanged tests, and their actual report. It
does not replace native replay, assert a four-second pressure result, or supply
an independent State oracle. The existing Host controller owns provisioning.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import run_history_native as history
from public_host_ci_observation import write_new
from replay_pinned_native import json_load, require

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = 'scripts/ci/run_architecture_delivery_native.py'
TARGET = 'architecture_delivery_compare'
SOURCE = 'trillionnium/crates/trnm-pon-node/tests/' + TARGET + '.rs'
TESTS = frozenset({
    'signed_dag_delivery_comparison_uses_same_native_business_and_confirmation_contract',
    'reference_dag_rejects_withheld_body_equivocation_and_changed_signed_history',
})
PREPARATION_SCHEMA = 'trnm-ci-architecture-cargo-preparation-v1'
EXECUTION_SCHEMA = 'trnm-ci-architecture-fixed-host-execution-v1'
REPORT_NAME = 'architecture-delivery-comparison.json'
REPORT_LIMIT = 16 * 1024 * 1024
MODES = ('serial-signed-batches', 'concurrent-proposer-batches', 'signed-reference-dag')
SCENARIOS = ('disjoint-recipients', 'hot-recipient')
NATIVE_CWD = ROOT / 'trillionnium/crates/trnm-pon-node'
RUNTIME_ENVIRONMENT = history.BUILD_ENVIRONMENT + (
    'LD_LIBRARY_PATH', 'CARGO_MANIFEST_DIR', 'CARGO_PKG_NAME', 'CARGO_PKG_VERSION',
    'RUST_TEST_THREADS', 'TRNM_ARCHITECTURE_COMPARE_DIR', 'TMPDIR', 'TMP', 'TEMP',
)


def output_path(out: Path) -> Path:
    receipts = Path(os.environ.get('TRNM_CI_RECEIPT_DIR', ''))
    require(receipts.is_absolute() and receipts.resolve(strict=True) == receipts
            and receipts.is_dir() and not receipts.is_relative_to(ROOT),
            'ARCHITECTURE_CURRENT_RECEIPT_DIRECTORY_REQUIRED')
    require(out == receipts / 'architecture-native' and out.resolve() == out,
            'ARCHITECTURE_EXACT_OUTPUT_REQUIRED')
    return out


def binary_path(raw: str) -> Path:
    binary = Path(raw)
    target = Path(os.environ.get('CARGO_TARGET_DIR', ''))
    require(target.is_absolute() and target.resolve(strict=True) == target,
            'ARCHITECTURE_CURRENT_CARGO_TARGET_REQUIRED')
    require(binary.is_absolute() and binary.resolve(strict=True) == binary
            and binary.parent == target / 'debug' / 'deps'
            and re.fullmatch(TARGET + r'-[0-9a-f]{16}', binary.name) is not None,
            'ARCHITECTURE_ORIGINAL_DEBUG_TEST_BINARY_REQUIRED')
    require(os.access(binary, os.X_OK), 'ARCHITECTURE_EXECUTABLE_REQUIRED')
    history.file_observation(binary, history.BINARY_LIMIT)
    return binary


def source_identity() -> dict:
    return history.source_identity(SOURCE)


def prepare(binary: Path, out: Path, native_cwd: Path) -> dict:
    out = output_path(out)
    require(native_cwd == NATIVE_CWD and native_cwd.resolve(strict=True) == native_cwd,
            'ARCHITECTURE_ORIGINAL_PACKAGE_DIRECTORY_REQUIRED')
    require(not (out.parent / REPORT_NAME).exists()
            and not (out.parent / REPORT_NAME).is_symlink(), 'ARCHITECTURE_FRESH_REPORT_REQUIRED')
    out.mkdir(exist_ok=False)
    source_before = source_identity()
    binary = binary_path(str(binary))
    observation, _ = history.file_observation(binary, history.BINARY_LIMIT)
    source_after = source_identity()
    require(source_before == source_after, 'ARCHITECTURE_PREPARATION_SOURCE_CHANGED')
    result = {'schema': PREPARATION_SCHEMA, 'target': TARGET, 'argv': [str(binary)],
              'native_cwd': str(native_cwd),
              'job': history.job_identity(), 'source_before': source_before,
              'source_after': source_after, 'binary': observation,
              'runtime_env': {name: os.environ.get(name) for name in RUNTIME_ENVIRONMENT},
              'prepared_by': 'original-workspace-cargo-target-runner',
              'separate_build_invoked': False, 'native_tests_executed': False,
              'completed': True}
    write_new(out / 'preparation.json', result)
    return result


def read_preparation(out: Path) -> dict:
    out = output_path(out)
    result, _ = history.load_object(out / 'preparation.json')
    require(result.get('schema') == PREPARATION_SCHEMA and result.get('target') == TARGET
            and result.get('prepared_by') == 'original-workspace-cargo-target-runner'
            and result.get('completed') is True and result.get('native_tests_executed') is False
            and result.get('separate_build_invoked') is False, 'ARCHITECTURE_COMPLETE_PREPARATION_REQUIRED')
    argv = result.get('argv')
    require(type(argv) is list and len(argv) == 1 and type(argv[0]) is str,
            'ARCHITECTURE_COMPLETE_UNFILTERED_BINARY_REQUIRED')
    require(result.get('native_cwd') == str(NATIVE_CWD)
            and NATIVE_CWD.resolve(strict=True) == NATIVE_CWD,
            'ARCHITECTURE_ORIGINAL_PACKAGE_DIRECTORY_REQUIRED')
    binary = binary_path(argv[0])
    observation, _ = history.file_observation(binary, history.BINARY_LIMIT)
    require(observation == result.get('binary'), 'ARCHITECTURE_PREPARED_BINARY_CHANGED')
    require(result.get('job') == history.job_identity(), 'ARCHITECTURE_PREPARATION_JOB_CHANGED')
    environment = result.get('runtime_env')
    require(type(environment) is dict and set(environment) == set(RUNTIME_ENVIRONMENT)
            and all(value is None or type(value) is str for value in environment.values()),
            'ARCHITECTURE_COMPLETE_RUNTIME_ENV_REQUIRED')
    current = source_identity()
    require(result.get('source_before') == result.get('source_after') == current,
            'ARCHITECTURE_PREPARATION_SOURCE_CHANGED')
    return result


def validate_preparation(out: Path) -> dict:
    result = read_preparation(out)
    require(result['runtime_env'] == {name: os.environ.get(name) for name in RUNTIME_ENVIRONMENT},
            'ARCHITECTURE_PREPARATION_RUNTIME_ENV_CHANGED')
    return result


def validate_transcript(raw: bytes) -> dict:
    lines = raw.decode('utf-8', 'strict').splitlines()
    require([line for line in lines if line.startswith('running ')] == ['running 2 tests'],
            'ARCHITECTURE_TWO_TESTS_REQUIRED')
    names = []
    for line in lines:
        if line.startswith('test ') and not line.startswith('test result:'):
            match = re.fullmatch(r'test ([A-Za-z0-9_:]+) \.\.\. ok', line)
            require(match is not None, 'ARCHITECTURE_NAMED_TEST_FAILED_OR_SKIPPED')
            names.append(match[1])
    summaries = [line for line in lines if line.startswith('test result:')]
    require(len(names) == 2 and set(names) == TESTS and len(summaries) == 1
            and re.fullmatch(r'test result: ok\. 2 passed; 0 failed; 0 ignored; 0 measured; '
                             r'0 filtered out; finished in [0-9]+(?:\.[0-9]+)?s', summaries[0]) is not None,
            'ARCHITECTURE_COMPLETE_TWO_TEST_EXECUTION_REQUIRED')
    return {'executed_tests': 2, 'passed': 2, 'skipped': 0, 'filtered': 0,
            'scope': 'libtest transcript binding; not authenticated native execution'}


def validate_report(value: dict) -> dict:
    require(type(value) is dict and value.get('schema') == 'native-signed-dag-delivery-comparison-v1',
            'ARCHITECTURE_ORIGINAL_REPORT_REQUIRED')
    for name in ('all_finite_business_targets_met', 'balanced_cyclic_mode_order',
                 'same_signed_packets_across_modes_and_repetitions'):
        require(value.get(name) is True, 'ARCHITECTURE_NATIVE_BUSINESS_FAILED:' + name)
    for name in ('architecture_winner_declared', 'independent_accepted', 'production_activation',
                 'protocol_switch_qualified', 'wan_tested'):
        require(value.get(name) is False, 'ARCHITECTURE_SCOPE_PROMOTION:' + name)
    require(type(value.get('samples_per_workload_and_mode')) is int
            and value['samples_per_workload_and_mode'] == 3, 'ARCHITECTURE_ORIGINAL_REPETITIONS')
    rows = value.get('samples')
    require(type(rows) is list and len(rows) == 18, 'ARCHITECTURE_COMPLETE_MATRIX_REQUIRED')
    seen = set()
    for row in rows:
        require(type(row) is dict and type(row.get('sample')) is int, 'ARCHITECTURE_SAMPLE_TYPE')
        key = row.get('scenario'), row.get('mode'), row['sample']
        require(key not in seen, 'ARCHITECTURE_DUPLICATE_SAMPLE')
        seen.add(key)
        require(row.get('finite_business_target_met') is True
                and row.get('native_state_equal') is True and row.get('cold_reopen_equal') is True
                and row.get('errors') == [], 'ARCHITECTURE_NATIVE_SAMPLE_FAILED')
        for name in ('confirmed_transactions', 'signed_transaction_count'):
            require(type(row.get(name)) is int and row[name] == 32, 'ARCHITECTURE_ALL_SIGNED_TRANSACTIONS')
        confirmations = row.get('independent_confirmations')
        require(type(confirmations) is list and len(confirmations) == 32,
                'ARCHITECTURE_COMPLETE_CONFIRMATIONS')
        require(all(type(item) is dict and item.get('confirmed') is True
                    and type(item.get('depth')) is int and item['depth'] == 6
                    and item.get('finalized') is False and item.get('execution_authority') is False
                    for item in confirmations), 'ARCHITECTURE_ORIGINAL_CONFIRMATION_CONTRACT')
    require(seen == {(scenario, mode, sample) for scenario in SCENARIOS
                     for mode in MODES for sample in range(3)}, 'ARCHITECTURE_MATRIX_IDENTITIES')
    return {'samples': 18, 'confirmed_transactions_per_sample': 32,
            'original_native_assertions_passed': True, 'four_second_pressure_gate_qualified': False,
            'production_activation': False}


def execution(out: Path) -> dict:
    out = output_path(out)
    write_new(out / 'execution-start.json', {'schema': EXECUTION_SCHEMA, 'completed': False})
    result = {'schema': EXECUTION_SCHEMA, 'target': TARGET, 'passed': False,
              'process': None, 'failures': [], 'native_execution_authenticated': False,
              'compilation_in_native_measurement': False, 'four_second_pressure_gate_qualified': False}
    try:
        prepared = validate_preparation(out)
        result['source_before'] = prepared['source_before']
        result['binary_before'] = prepared['binary']
        result['runtime_env_before'] = {name: os.environ.get(name) for name in RUNTIME_ENVIRONMENT}
        require(not (out.parent / REPORT_NAME).exists()
                and not (out.parent / REPORT_NAME).is_symlink(), 'ARCHITECTURE_FRESH_REPORT_REQUIRED')
        with (out / 'native.log').open('xb') as log:
            child = subprocess.Popen(prepared['argv'], cwd=NATIVE_CWD, stdout=log, stderr=subprocess.STDOUT)
            result['process'] = {'argv': prepared['argv'], 'cwd': str(NATIVE_CWD), 'pid': child.pid,
                                 'exit_code': child.wait()}
        result['binary_after'], _ = history.file_observation(Path(prepared['argv'][0]), history.BINARY_LIMIT)
        result['source_after'] = source_identity()
        result['runtime_env_after'] = {name: os.environ.get(name) for name in RUNTIME_ENVIRONMENT}
        require(result['process']['exit_code'] == 0, 'ARCHITECTURE_NATIVE_TEST_FAILED')
        result['log'], raw = history.file_observation(out / 'native.log', history.LOG_LIMIT, retain=True)
        result['named_execution'] = validate_transcript(raw)
        result['report'], raw = history.file_observation(out.parent / REPORT_NAME, REPORT_LIMIT, retain=True)
        result['business'] = validate_report(json_load(raw))
        require(result['binary_before'] == result['binary_after']
                and result['source_before'] == result['source_after']
                and result['runtime_env_before'] == result['runtime_env_after'] == prepared['runtime_env'],
                'ARCHITECTURE_EXECUTION_INPUT_CHANGED')
        result['passed'] = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result['failures'].append(type(error).__name__ + ':' + str(error))
    finally:
        write_new(out / 'manifest.json', result)
    return result


def bind_execution(prepared: dict, out: Path, *, in_cargo_runtime: bool = True) -> dict:
    # The controller and Cargo runner still compare the current execution env.
    # The outer shard only rereads their bound records: Cargo's injected package
    # variables and dynamic-library paths never propagate back into that parent.
    current = validate_preparation(out) if in_cargo_runtime else read_preparation(out)
    require(current == prepared, 'ARCHITECTURE_PREPARATION_CHANGED')
    result, manifest = history.load_object(out / 'manifest.json')
    require(result.get('schema') == EXECUTION_SCHEMA and result.get('target') == TARGET
            and result.get('passed') is True and result.get('failures') == []
            and result.get('native_execution_authenticated') is False
            and result.get('compilation_in_native_measurement') is False
            and result.get('four_second_pressure_gate_qualified') is False,
            'ARCHITECTURE_COMPLETE_EXECUTION_REQUIRED')
    process = result.get('process')
    require(type(process) is dict and process.get('argv') == prepared['argv']
            and process.get('cwd') == prepared['native_cwd']
            and type(process.get('pid')) is int and process['pid'] > 0
            and type(process.get('exit_code')) is int and process['exit_code'] == 0,
            'ARCHITECTURE_NATIVE_PROCESS_REQUIRED')
    require(result.get('source_before') == result.get('source_after') == prepared['source_before']
            and result.get('binary_before') == result.get('binary_after') == prepared['binary']
            and result.get('runtime_env_before') == result.get('runtime_env_after') == prepared['runtime_env'],
            'ARCHITECTURE_EXECUTION_SOURCE_BINARY_CHANGED')
    observed, raw = history.file_observation(out / 'native.log', history.LOG_LIMIT, retain=True)
    require(observed == result.get('log') and validate_transcript(raw) == result.get('named_execution'),
            'ARCHITECTURE_NATIVE_LOG_CHANGED')
    observed, raw = history.file_observation(out.parent / REPORT_NAME, REPORT_LIMIT, retain=True)
    require(observed == result.get('report') and validate_report(json_load(raw)) == result.get('business'),
            'ARCHITECTURE_NATIVE_REPORT_CHANGED')
    return {'schema': 'trnm-ci-architecture-host-binding-v1', 'source_commit': prepared['source_before']['commit'],
            'binary_sha256': prepared['binary']['sha256'], 'manifest_sha256': manifest['sha256'],
            'executed_tests': 2, 'matrix_samples': 18, 'four_second_pressure_gate_qualified': False,
            'runtime_limits_or_deadlines_changed': False}


def require_controller_success(out: Path, *, in_cargo_runtime: bool = True) -> dict:
    out = output_path(out)
    result, _ = history.load_object(out.with_name(out.name + '-host') / 'controller-result.json')
    prepared = validate_preparation(out) if in_cargo_runtime else read_preparation(out)
    binding = bind_execution(prepared, out, in_cargo_runtime=in_cargo_runtime)
    require(result.get('passed') is True and result.get('failure') is None
            and type(result.get('systemd_run_exit')) is int and result['systemd_run_exit'] == 0
            and result.get('final_host_errors') == []
            and result.get('command_argv') == ['python3', SCRIPT, '--out', str(out)]
            and result.get('preparation_execution_binding') == binding,
            'ARCHITECTURE_FIXED_HOST_EXECUTION_REQUIRED')
    return binding


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = execution(args.out)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['passed'] is True else 1


if __name__ == '__main__':
    raise SystemExit(main())
