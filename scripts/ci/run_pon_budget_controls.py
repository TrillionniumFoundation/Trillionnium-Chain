#!/usr/bin/env python3
"""Exact-source component controls, not a service campaign or TPS qualification.

The old production source and current source execute identical test bytes. Build
one release libtest per source, retain its actual list and binary, then require
each named native outcome. An arbitrary nonzero exit is never a negative control.
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
BEFORE_SHA = 'd6bbac6baf9e5356721ab56f7432058d07b6b49b'
BEFORE_TREE = '653b1a8b483ccdbf69b272255ec0369d98296302'
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
CONTROLS = (*HISTORY, *MINING_FAILURES, EQUIVALENCE)
# These are the assertion sites in the identical, committed test-only input.
# A setup unwrap or an unrelated assertion cannot establish this counterexample.
PANIC_LINES = {**dict.fromkeys(HISTORY, 133),
               **dict(zip(MINING_FAILURES, (82, 124, 176)))}
SAME_INPUTS = (
    'trillionnium/crates/trnm-pon-node/src/ingress/history_import_detached_budget_tests.rs',
    'trillionnium/crates/trnm-pon-node/src/mining_prepare_control_tests.rs',
    'trillionnium/Cargo.toml',
    'trillionnium/Cargo.lock',
    'trillionnium/crates/trnm-pon-node/Cargo.toml',
    'rust-toolchain.toml',
)
RELEASE_PROFILE = dict(debug_assertions=False, debuginfo=0, opt_level='3',
                       overflow_checks=False, test=True)
FALSE_FLAGS = ('native_campaign_executed', 'whole_business_liveness_qualified',
               'throughput_measured', 'production_activation')
SCHEMA = 'pon-original-budget-component-controls-v1'


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


def build_command() -> list[str]:
    return ['cargo', '+1.95.0', 'test', '--locked', '--release', '--manifest-path',
            'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--lib',
            '--no-run', '--message-format=json']


def select_binary(raw: str, source: Path, target_dir: Path) -> tuple[Path, dict]:
    artifacts, finished = [], False
    for line in raw.splitlines():
        row = json_load(line)
        require(type(row) is dict and not finished, 'BUILD_RECORD_ORDER')
        if row.get('reason') == 'build-finished':
            require(row.get('success') is True, 'BUILD_FINISH_REQUIRED')
            finished = True
        elif row.get('reason') == 'compiler-artifact' and row.get('executable') is not None:
            target, profile = row.get('target'), row.get('profile')
            require(type(target) is dict and type(profile) is dict, 'BUILD_ARTIFACT_OBJECT')
            if target.get('name') != 'trnm_pon_node':
                continue
            require(target.get('kind') == ['lib'] and target.get('crate_types') == ['lib']
                    and target.get('test') is True
                    and target.get('src_path') == str(source / 'trillionnium/crates/trnm-pon-node/src/lib.rs')
                    and row.get('manifest_path') == str(source / 'trillionnium/crates/trnm-pon-node/Cargo.toml'),
                    'LIBTEST_TARGET_SOURCE')
            require(profile == RELEASE_PROFILE and all(type(profile[key]) is type(value)
                    for key, value in RELEASE_PROFILE.items()), 'ORIGINAL_RELEASE_PROFILE_REQUIRED')
            require(type(row.get('filenames')) is list and row['executable'] in row['filenames'],
                    'BUILD_EXECUTABLE_BINDING')
            binary = Path(row['executable'])
            require(binary.is_absolute() and binary.is_relative_to(target_dir)
                    and os.access(binary, os.X_OK), 'FRESH_TARGET_EXECUTABLE_REQUIRED')
            file_record(binary)
            artifacts.append((binary, row))
    require(finished and len(artifacts) == 1, 'ONE_SUCCESSFUL_LIBTEST_BUILD_REQUIRED')
    return artifacts[0]


def validate_list(raw: str) -> dict:
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
    require(set(CONTROLS).issubset(names), 'SEVEN_EXACT_CONTROLS_REQUIRED')
    return {'listed_tests': len(names), 'required_tests': list(CONTROLS)}


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


def history_evidence(raw: str, name: str, mode: str) -> dict:
    records = []
    for line in raw.splitlines():
        if '"schema":"history-detached-original-refill-control-v1"' in line:
            records.append(json_load(line[line.index('{'):]))
    require(len(records) == 1, 'ONE_ACTUAL_HISTORY_RECORD_REQUIRED')
    record = records[0]
    require(record.get('schema') == 'history-detached-original-refill-control-v1'
            and record.get('mode') == HISTORY[name]
            and record.get('native_campaign_executed') is False, 'HISTORY_SCOPE_AND_MODE')
    replay = record.get('replay')
    require(type(replay) is dict, 'M06_REPLAY_WAS_NOT_REACHED')
    count, cpu, credit = (replay.get(key) for key in (
        'completed_native_replays', 'actual_thread_cpu_ns', 'projected_paid_credit_ns'))
    require(type(count) is int and count > 0 and type(cpu) is int and cpu > 0
            and type(credit) is int and cpu > credit + 25_000_000,
            'ACTUAL_REPLAY_CPU_DEFICIT_REQUIRED')
    flow = record.get('flow')
    require(type(flow) is dict and type(flow.get('initial_credit_ns')) is int
            and flow['initial_credit_ns'] == 0
            and type(flow.get('paid_cpu_debit_ns')) is int
            and flow['paid_cpu_debit_ns'] >= cpu
            and flow.get('balance_identity_verified') is True, 'ORIGINAL_CPU_ACCOUNT_REQUIRED')
    history = record.get('history')
    require(type(history) is dict and type(history.get('measurement_failures')) is int
            and history['measurement_failures'] == 0
            and type(history.get('packets')) is list and len(history['packets']) == 1,
            'ACTUAL_HISTORY_PACKET_REQUIRED')
    phases = history['packets'][0].get('phases')
    require(type(phases) is list, 'HISTORY_PHASES_REQUIRED')
    by_phase = {phase.get('phase'): phase for phase in phases if type(phase) is dict}
    require(len(by_phase) == len(phases), 'DUPLICATE_HISTORY_PHASE')
    work, execution, commit = (by_phase.get(key, {}) for key in ('work', 'execution', 'commit'))
    require(work.get('completed') is True and work.get('accepted') is True
            and execution.get('started') is True, 'REAL_W1_AND_M06_REQUIRED')
    checks = record.get('refill_resource_checks')
    require(type(checks) is int and checks >= 0, 'REFILL_CHECK_COUNT')
    if mode == 'before':
        require(checks == 0 and execution.get('completed') is True
                and execution.get('accepted') is False
                and execution.get('error_code') == 'PUBLIC_MUTATION_CPU_BUDGET'
                and commit.get('started') is False, 'ORIGINAL_DETACHED_REFUSAL_REQUIRED')
    else:
        require(checks > 0, 'ORIGINAL_REFILL_CONTROL_REQUIRED')
        if HISTORY[name] == 'Continue':
            require(execution.get('accepted') is True and commit.get('accepted') is True,
                    'CONTINUED_IMPORT_REQUIRED')
        else:
            expected = 'PUBLIC_REQUEST_CANCELLED' if HISTORY[name] == 'Cancel' else 'PUBLIC_REQUEST_DEADLINE'
            require(execution.get('error_code') == expected and commit.get('started') is False,
                    'ORIGINAL_CANCELLATION_REQUIRED')
    return record


def validate_case(name: str, mode: str, process: dict, stdout: str, stderr: str) -> dict:
    require(name in CONTROLS and mode in ('before', 'fixed'), 'EXACT_CASE_REQUIRED')
    failed = mode == 'before' and name != EQUIVALENCE
    require(process.get('started') is True and process.get('failure') is None
            and process.get('cleanup_errors') == []
            and type(process.get('exit_code')) is int
            and process.get('exit_code') == (101 if failed else 0), 'NATIVE_PROCESS_OUTCOME')
    if failed:
        validate_failed_transcript(stdout, name)
        source = ('ingress/history_import_detached_budget_tests.rs'
                  if name in HISTORY else 'mining_prepare_control_tests.rs')
        require(re.search(r'panicked at [^\n]*crates/trnm-pon-node/src/' + re.escape(source)
                          + ':' + str(PANIC_LINES[name]) + r':[0-9]+:', stderr) is not None,
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
    record = {'test': name, 'expected': 'fail' if failed else 'pass',
              'expected_outcome_observed': True}
    if name in HISTORY:
        record['history'] = history_evidence(stdout, name, mode)
    return record


def validate_source_pair(mode: str, driver_sha: str, source_sha: str) -> None:
    require(all(re.fullmatch(r'[0-9a-f]{40}', value) for value in (driver_sha, source_sha)),
            'EXACT_EXPECTED_SHA_REQUIRED')
    require((mode == 'before' and source_sha == BEFORE_SHA and driver_sha != BEFORE_SHA)
            or (mode == 'fixed' and source_sha == driver_sha and source_sha != BEFORE_SHA),
            'BEFORE_OR_CURRENT_HEAD_REQUIRED')


def run(args: argparse.Namespace) -> dict:
    source, out = args.source.resolve(strict=True), args.out.absolute()
    require(out.resolve() == out and not out.is_relative_to(source)
            and not out.is_relative_to(ROOT), 'OUTPUT_OUTSIDE_BOTH_CHECKOUTS')
    out.mkdir(exist_ok=False)
    report = {'schema': SCHEMA, 'result': 'FAIL', 'scope': 'seven-native-component-controls-only',
              'mode': args.mode, 'expected_driver': args.driver_sha, 'expected_source': args.source_sha,
              'commands': [], 'cases': [], 'errors': [], 'source_before': {}, 'source_after': {},
              'old_source_current_corpus_qualification': False,
              'expected_passes': 1 if args.mode == 'before' else 7,
              'expected_failures': 6 if args.mode == 'before' else 0,
              **dict.fromkeys(FALSE_FLAGS, False)}
    env = dict(os.environ)

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
        if args.mode == 'before':
            require(report['source_before']['subject']['tested_tree'] == BEFORE_TREE,
                    'EXACT_TEST_ONLY_BEFORE_TREE')
        inputs = {}
        for relative in SAME_INPUTS:
            actual, current = file_record(source / relative), file_record(ROOT / relative)
            require(actual['sha256'] == current['sha256'], 'IDENTICAL_TESTS_LOCK_AND_PROFILE_REQUIRED')
            inputs[relative] = actual
        report['identical_inputs'] = inputs
        require(tomllib.loads((source / 'rust-toolchain.toml').read_text())['toolchain']['channel']
                == '1.95.0', 'ORIGINAL_TOOLCHAIN_PIN')
        require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'NATIVE_X64_LINUX_REQUIRED')
        altered = [key for key, value in env.items() if value and (
            key.startswith('CARGO_PROFILE_') or key.endswith('_RUSTFLAGS')
            or key in ('RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_TARGET'))]
        require(not altered, 'BUILD_OVERRIDE_REFUSED:' + ','.join(altered))
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
        build = checked(build_command(), 'build')
        built, artifact = select_binary(build, source, target)
        write(out / 'compiler-artifact.json', artifact)
        report['compiler_artifact'] = artifact
        initial = file_record(built)
        binary = out / 'trnm-pon-node-libtest'
        with built.open('rb') as original, binary.open('xb') as retained:
            shutil.copyfileobj(original, retained)
        binary.chmod(0o500)
        report['binary_before'] = file_record(binary)
        require(report['binary_before']['sha256'] == initial['sha256'], 'BINARY_CAPTURE_CHANGED')
        listing = checked([str(binary), '--list', '--format=pretty'], 'libtest-list')
        report['libtest_list'] = validate_list(listing)
        for index, name in enumerate(CONTROLS):
            label = f'test-{index + 1:02d}'
            command = [str(binary), '--exact', name, '--nocapture', '--test-threads=1']
            process = capture(command, source, out, label, env)
            case = {'test': name, 'process': process, 'expected_outcome_observed': False}
            try:
                case.update(validate_case(name, args.mode, process,
                    (out / (label + '.stdout')).read_text(), (out / (label + '.stderr')).read_text()))
            except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
                case['error'] = type(error).__name__ + ': ' + str(error)
                report['errors'].append(name + ': ' + case['error'])
            report['cases'].append(case)
            write(out / 'report.json', report)
        report['binary_after'] = file_record(binary)
        require(report['binary_before'] == report['binary_after'], 'EXECUTED_BINARY_CHANGED')
        require(len(report['cases']) == 7 and all(
            case['expected_outcome_observed'] for case in report['cases']), 'SEVEN_EXPECTED_OUTCOMES_REQUIRED')
    except BaseException as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        report['native_control_processes_started'] = sum(
            case['process'].get('started') is True for case in report['cases'])
        report['matched_pass_controls'] = sum(
            case.get('expected_outcome_observed') is True and case.get('expected') == 'pass'
            for case in report['cases'])
        report['matched_failure_controls'] = sum(
            case.get('expected_outcome_observed') is True and case.get('expected') == 'fail'
            for case in report['cases'])
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
    parser.add_argument('--mode', required=True, choices=('before', 'fixed'))
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
