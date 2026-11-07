#!/usr/bin/env python3
"""Source-tracked, create-only exact-source validation for grouped fresh work.

All eighteen original fairness gates and three fresh-floor gates remain
mandatory. The resource-transfer continuation adds its finite theory, native
shared-authority tests and release authority executable, for twenty-four gates.
This uses the caller's compiler/PQ/cache environment; only the optional fuzz
Cargo home is scoped to one metadata command. Validation is not qualification.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
RELATIVE = 'formal/pon-nakamoto-v1/experiments/validate_grouped_fresh_work_v0.py'
TIMEOUT_SECONDS = 1800
ENVIRONMENT_KEYS = (
    'PATH', 'CARGO_HOME', 'RUSTUP_HOME', 'RUSTC', 'RUSTDOC', 'RUSTFLAGS',
    'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
    'OPENSSL_DIR', 'OPENSSL_STATIC', 'OPENSSL_CONF', 'OPENSSL_MODULES',
    'TRNM_PQ_OPENSSL', 'TRNM_PQ_OPENSSL_SHA256', 'TRNM_PQ_OPENSSL_VERSION',
    'CARGO_TARGET_DIR', 'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG',
    'CARGO_INCREMENTAL', 'CARGO_BUILD_JOBS', 'TRNM_GROUPED_NATIVE',
    'TRNM_GROUPED_FRESH_NATIVE', 'TRNM_GROUPED_AUTHORITY_NATIVE',
    'RUST_TEST_THREADS', 'PYTHONDONTWRITEBYTECODE')


def utc():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def save(path, value):
    with path.open('x', encoding='utf-8') as handle:
        json.dump(value, handle, sort_keys=True, indent=2, allow_nan=False)
        handle.write('\n')


def file_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path):
    result = {'path': str(path), 'exists': path.is_file()}
    if result['exists']:
        result.update(bytes=path.stat().st_size, sha256=file_sha(path), executable=os.access(path, os.X_OK))
    return result


def commands(python, env, fuzz_cargo_home):
    cargo, manifest = ['cargo'], ['--manifest-path', 'trillionnium/Cargo.toml']
    raw = [
        ('preflight', ['bash', 'scripts/project-preflight.sh']),
        ('cargo-version', ['cargo', '--version']), ('rustc-version', ['rustc', '--version']),
        # An absent configured PQ executable is a retained launch failure, not a
        # fallback to an unrelated system OpenSSL or a waived gate.
        ('openssl-version', [env.get('TRNM_PQ_OPENSSL'), 'version']),
        ('locked-workspace-graph', cargo + ['metadata', '--offline', '--locked', *manifest,
                                         '--all-features', '--format-version', '1']),
        ('locked-fuzz-graph', cargo + ['metadata', '--offline', '--locked', '--manifest-path',
                                    'tests/fuzz/Cargo.toml', '--all-features', '--format-version', '1']),
        ('format', cargo + ['fmt', *manifest, '--all', '--', '--check']),
        ('native-build', cargo + ['build', '--offline', '--locked', '--release', *manifest,
                                 '-p', 'trnm-crypto-primitives', '--example', 'pon_routed_int257_grouped']),
        ('fresh-native-build', cargo + ['build', '--offline', '--locked', '--release', *manifest,
                                       '-p', 'trnm-pon-node', '--example', 'grouped_fresh_admission_v0']),
        ('authority-native-build', cargo + ['build', '--offline', '--locked', '--release', *manifest,
                                           '-p', 'trnm-pon-node', '--example', 'grouped_verification_authority_v0']),
        ('grouped-python-and-native', [python, '-B', '-m', 'unittest', 'discover', '-s',
                                      'formal/pon-nakamoto-v1', '-p', 'test_grouped*.py', '-v']),
        ('conditional-query-bound', [python, '-B', '-m', 'unittest', 'discover', '-s',
                                    'formal/pon-nakamoto-v1', '-p', 'test_work_query_bound.py', '-v']),
        ('fresh-query-floor', [python, '-B', '-m', 'unittest', 'discover', '-s',
                              'formal/pon-nakamoto-v1', '-p', 'test_fresh_work_query_floor_v0.py', '-v']),
        ('fresh-resource-transfer', [python, '-B', '-m', 'unittest', 'discover', '-s',
                                    'formal/pon-nakamoto-v1', '-p', 'test_fresh_work_resource_transfer_v0.py', '-v']),
        ('native-crypto-all-targets', cargo + ['test', '--offline', '--locked', *manifest,
                                             '-p', 'trnm-crypto-primitives', '--all-targets', '--all-features']),
        ('native-header-binding', cargo + ['test', '--offline', '--locked', *manifest,
                                          '-p', 'trnm-pon-node', '--all-features', '--test', 'work_header_binding']),
        ('native-fresh-admission', cargo + ['test', '--offline', '--locked', *manifest,
                                           '-p', 'trnm-pon-node', '--all-features', '--test', 'grouped_fresh_admission_v0']),
        ('native-verification-authority', cargo + ['test', '--offline', '--locked', *manifest,
                                                   '-p', 'trnm-pon-node', '--all-features', '--test', 'grouped_verification_authority_v0']),
        ('source-integrity-controls', [python, '-B', 'scripts/ci/test_ci_source_integrity.py']),
        ('ci-contract-controls', [python, '-B', 'scripts/ci/test_ci_contract.py']),
        ('source-inventory', [python, '-B', 'scripts/refresh_distributed_source_inventory.py', '--check']),
        ('repository-and-links', [python, '-B', 'scripts/ci/check_repository.py']),
        ('strict-workspace-clippy', cargo + ['clippy', '--offline', '--locked', *manifest,
                                           '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings']),
        ('whitespace', ['git', 'diff', '--check']),
    ]
    result = []
    for ordinal, (label, argv) in enumerate(raw, 1):
        override = {'CARGO_HOME': str(fuzz_cargo_home)} if label == 'locked-fuzz-graph' and fuzz_cargo_home else {}
        command = {'ordinal': ordinal, 'label': label, 'command': argv,
                   'environment_overrides': override, 'timeout_seconds': TIMEOUT_SECONDS,
                   'original_gate': label not in {'fresh-native-build', 'fresh-query-floor', 'native-fresh-admission',
                       'authority-native-build', 'fresh-resource-transfer', 'native-verification-authority'},
                   'prior_fresh_floor_gate': label not in {'authority-native-build', 'fresh-resource-transfer',
                       'native-verification-authority'}}
        command['command_sha256'] = hashlib.sha256(canonical(command)).hexdigest()
        result.append(command)
    return result


def source_snapshot(repo, source_sha):
    """Check the running driver itself, then every tracked source byte."""
    if len(source_sha) != 40 or any(c not in '0123456789abcdef' for c in source_sha):
        raise ValueError('EXPECTED_SOURCE_SHA_FORMAT')
    if Path(__file__).resolve() != repo / RELATIVE:
        raise ValueError('EXECUTING_DRIVER_OUTSIDE_EXPECTED_REPOSITORY')
    committed = subprocess.check_output(
        ['git', '--no-replace-objects', 'show', source_sha + ':' + RELATIVE], cwd=repo)
    if committed != Path(__file__).read_bytes():
        raise ValueError('EXECUTING_DRIVER_NOT_EXACT_COMMITTED_BYTES')
    spec = importlib.util.spec_from_file_location('grouped_validation_source_guard', repo / 'scripts/ci/verify_ci_source.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify('head', source_sha, root=repo)


def run_command(command, repo, env, out):
    """Retain unlimited file logs; kill only our owned POSIX process group.

    WNOWAIT keeps the leader PID reserved until group cleanup, avoiding a reused
    group ID. Descendants which deliberately leave this session are not sandboxed.
    A timeout is FAIL even if an exiting leader happens to return zero.
    """
    record = dict(command, started_utc=utc(), process_started=False, timed_out=False,
                  exit_code=None, status='FAIL')
    log = out / (command['label'] + '.log')
    start, child, failure = time.monotonic(), None, None
    child_env = dict(env, **command['environment_overrides'])
    record['effective_cargo_home'] = child_env.get('CARGO_HOME')
    with log.open('xb') as stream:
        try:
            if not all(type(x) is str and x for x in command['command']):
                raise ValueError('COMMAND_EXECUTABLE_NOT_CONFIGURED')
            child = subprocess.Popen(command['command'], cwd=repo, env=child_env, stdin=subprocess.DEVNULL,
                                     stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            record.update(process_started=True, pid=child.pid, process_group=child.pid)
            deadline = start + command['timeout_seconds']
            while True:
                try:
                    status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except InterruptedError:
                    continue
                if status is not None:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    record['timed_out'] = True
                    break
                time.sleep(min(remaining, 0.05))
        except BaseException as error:
            failure = error
            record['error'] = {'type': type(error).__name__, 'message': str(error)}
            stream.write(('\nVALIDATION_DRIVER_ERROR: ' + repr(error) + '\n').encode())
        finally:
            if child is not None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                    record['owned_process_group_cleanup'] = 'SIGKILL'
                except ProcessLookupError:
                    record['owned_process_group_cleanup'] = 'already_gone'
                except OSError as error:
                    record['cleanup_error'] = {'type': type(error).__name__, 'message': str(error)}
                    child.kill()
                # Reap after cleanup; a timed-out process has a known observed
                # exit status rather than being recorded as an unknown success.
                record['exit_code'] = child.wait()
            stream.flush()
            os.fsync(stream.fileno())
    record.update(ended_utc=utc(), elapsed_seconds=time.monotonic() - start,
                  log=log.name, log_bytes=log.stat().st_size, log_sha256=file_sha(log))
    if failure is None and not record['timed_out'] and record['exit_code'] == 0 and 'cleanup_error' not in record:
        record['status'] = 'PASS'
    if failure is not None and not isinstance(failure, Exception):
        record['interrupted'] = True
    return record


def not_started(command, reason):
    return dict(command, status='NOT_STARTED', process_started=False, timed_out=False,
                exit_code=None, started_utc=None, ended_utc=None, elapsed_seconds=None,
                log=None, log_bytes=None, log_sha256=None, reason=reason)


def runner_bindings(repo, out, records, runners, built):
    """Bind passed executable paths to Cargo's actual workspace target directory."""
    try:
        graph = next(row for row in records if row['label'] == 'locked-workspace-graph')
        if graph['status'] != 'PASS':
            raise ValueError('WORKSPACE_METADATA_NOT_AVAILABLE')
        # Cargo metadata emits one JSON line; any diagnostics are separate log
        # lines. Accept exactly one complete matching metadata object.
        objects = []
        for line in (out / graph['log']).read_text().splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if type(value) is dict and {'packages', 'workspace_root', 'target_directory'} <= set(value):
                objects.append(value)
        if len(objects) != 1 or Path(objects[0]['workspace_root']).resolve() != repo / 'trillionnium':
            raise ValueError('WORKSPACE_METADATA_ROOT')
        target = Path(objects[0]['target_directory']).resolve()
        expected = {'grouped': target / 'release/examples/pon_routed_int257_grouped',
                    'fresh': target / 'release/examples/grouped_fresh_admission_v0',
                    'authority': target / 'release/examples/grouped_verification_authority_v0'}
        final = {name: artifact(path) for name, path in runners.items()}
        for name, path in runners.items():
            if path != expected[name].resolve() or not final[name].get('executable'):
                raise ValueError('RUNNER_NOT_EXPECTED_RELEASE_ARTIFACT_' + name.upper())
            if name not in built or built[name] != final[name]:
                raise ValueError('RUNNER_CHANGED_OR_BUILD_NOT_SUCCESSFUL_' + name.upper())
        return {'status': 'PASS', 'cargo_target_directory': str(target), 'artifacts': final}
    except Exception as error:
        return {'status': 'FAIL', 'error': {'type': type(error).__name__, 'message': str(error)},
                'artifacts': {name: artifact(path) for name, path in runners.items()}}


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
    runners = {'grouped': args.runner.resolve(), 'fresh': args.fresh_runner.resolve(),
               'authority': args.authority_runner.resolve()}
    env = dict(os.environ, TRNM_GROUPED_NATIVE=str(runners['grouped']),
               TRNM_GROUPED_FRESH_NATIVE=str(runners['fresh']),
               TRNM_GROUPED_AUTHORITY_NATIVE=str(runners['authority']),
               RUST_TEST_THREADS='1', PYTHONDONTWRITEBYTECODE='1')
    fuzz_home = args.fuzz_cargo_home.resolve() if args.fuzz_cargo_home else None
    planned = commands(sys.executable, env, fuzz_home)
    driver_sha = file_sha(Path(__file__))
    save(out / 'plan.json', {'schema': 'pon-grouped-fresh-validation-plan-v1', 'created_utc': utc(),
        'repository': str(repo), 'expected_source_sha': args.source_sha,
        'driver_relative_path': RELATIVE, 'driver_sha256': driver_sha,
        'commands': planned, 'planned_commands': len(planned), 'original_gates': 18, 'new_gates': 6,
        'prior_fresh_floor_gates': 21, 'new_resource_transfer_gates': 3,
        'timeout_seconds_per_command': TIMEOUT_SECONDS,
        'fuzz_cargo_home_override': str(fuzz_home) if fuzz_home else None,
        'runners': {key: str(value) for key, value in runners.items()},
        'source_validation_is_not_qualification': True, 'production_activation': False})
    save(out / 'environment.json', {key: env.get(key) for key in ENVIRONMENT_KEYS})
    save(out / 'runners-before.json', {name: artifact(path) for name, path in runners.items()})
    before = after = None
    failures, records, built = [], [], {}
    try:
        before = source_snapshot(repo, args.source_sha)
        save(out / 'source-before.json', {'status': 'PASS', 'source': before, 'driver_sha256': driver_sha})
    except Exception as error:
        failures.append({'stage': 'source-before', 'type': type(error).__name__, 'message': str(error)})
        save(out / 'source-before.json', {'status': 'FAIL', 'error': failures[-1]})
    with (out / 'commands.ndjson').open('x', encoding='utf-8') as ledger:
        interrupted = False
        for command in planned:
            if before is None or interrupted:
                record = not_started(command, 'EXACT_SOURCE_GATE_FAILED' if before is None else 'DRIVER_INTERRUPTED')
            else:
                record = run_command(command, repo, env, out)
                interrupted = bool(record.get('interrupted'))
                build_names = {'native-build': 'grouped', 'fresh-native-build': 'fresh',
                               'authority-native-build': 'authority'}
                if record['label'] in build_names and record['status'] == 'PASS':
                    name = build_names[record['label']]
                    built[name] = artifact(runners[name])
                    record['built_runner'] = built[name]
            records.append(record)
            save(out / (command['label'] + '.result.json'), record)
            ledger.write(json.dumps(record, sort_keys=True, allow_nan=False) + '\n')
            ledger.flush()
            os.fsync(ledger.fileno())
            print(json.dumps(record, sort_keys=True), flush=True)
    save(out / 'commands.json', records)
    try:
        after = source_snapshot(repo, args.source_sha)
        current_driver_sha = file_sha(Path(__file__))
        if before != after or current_driver_sha != driver_sha:
            raise ValueError('EXACT_SOURCE_CHANGED')
        save(out / 'source-after.json', {'status': 'PASS', 'source': after, 'driver_sha256': current_driver_sha})
    except Exception as error:
        failures.append({'stage': 'source-after', 'type': type(error).__name__, 'message': str(error)})
        save(out / 'source-after.json', {'status': 'FAIL', 'error': failures[-1], 'source': after})
    binding = runner_bindings(repo, out, records, runners, built)
    save(out / 'runner-bindings.json', binding)
    passed = not failures and binding['status'] == 'PASS' and all(row['status'] == 'PASS' for row in records)
    summary = {'schema': 'pon-grouped-fresh-local-validation-v1', 'source': before,
        'status': 'PASS' if passed else 'FAIL', 'expected_source_sha': args.source_sha,
        'driver_sha256': driver_sha, 'commands_planned': len(planned), 'commands_recorded': len(records),
        'commands_passed': sum(row['status'] == 'PASS' for row in records),
        'commands_failed': sum(row['status'] == 'FAIL' for row in records),
        'commands_not_started': sum(row['status'] == 'NOT_STARTED' for row in records),
        'commands_timed_out': sum(row['timed_out'] for row in records), 'source_failures': failures,
        'runner_bindings': binding, 'native_runner_sha256': binding['artifacts']['grouped'].get('sha256'),
        'fresh_native_runner_sha256': binding['artifacts']['fresh'].get('sha256'),
        'authority_native_runner_sha256': binding['artifacts']['authority'].get('sha256'),
        'original_service_campaign_executed': False, 'full_workspace_unit_tests_executed': False,
        'minimum_legal_cost_proved': False, 'physical_resource_lower_bound_proved': False,
        'pow_qualified': False, 'chainwork_awarded': 0, 'production_activation': False}
    save(out / 'summary.json', summary)
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
