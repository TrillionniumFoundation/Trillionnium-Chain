#!/usr/bin/env python3
"""Collect an explicit fixed W1 CPU campaign from one clean exact source.

Run under the explicitly declared runtime cgroup on each host. This script
checks the actual inherited limits; it does not create or modify services.
The default V1 four-file grid is unchanged. --cost-matrix-v2 selects the separate
fixed all-producer/fact-cache V2 matrix; both retain the original CPU domain.
Source, binary, logs, environment and failures are retained outside the repo.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
from bounded_process import ProcessFailure, run_bounded

GRID = (
    ('w1-seed1', 3, 32, 1, '7f' + 'ff' * 31, 1),
    ('w1-seed2', 3, 32, 1, '7f' + 'ff' * 31, 2),
    ('w1-exhausted', 1, 2, 1, '00' * 32, 1),
    ('w1-receiver-budget', 1, 1, 1024, 'ff' * 32, 1),
)
BUILD_SECONDS = 600
RUN_SECONDS = 120
STDOUT_LIMIT = 16 * 1024 * 1024
STDERR_LIMIT = 4 * 1024 * 1024
BUILD_ENV = ('RUSTC', 'CARGO_BUILD_RUSTC', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
             'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_TARGET',
             'CARGO_BUILD_RUSTFLAGS', 'CARGO_BUILD_RUSTC_WRAPPER',
             'CARGO_PROFILE_RELEASE_OPT_LEVEL', 'CARGO_PROFILE_RELEASE_LTO',
             'CARGO_PROFILE_RELEASE_CODEGEN_UNITS', 'CARGO_PROFILE_RELEASE_DEBUG',
             'CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS', 'CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS',
             'CARGO_PROFILE_RELEASE_PANIC', 'CARGO_PROFILE_RELEASE_INCREMENTAL')


def require(value, message):
    if not value:
        raise ValueError(message)


def validate_build_environment(env):
    require(all(not env.get(name) for name in BUILD_ENV), 'UNDECLARED_BUILD_OVERRIDE')


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def write_new(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args],
                                   text=True, timeout=30).strip()


def source_snapshot():
    return {'head': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'status_porcelain': git('status', '--porcelain', '--untracked-files=all'),
            'branch': git('branch', '--show-current')}


def validate_source(observed, expected_head, expected_tree):
    require(observed['head'] == expected_head and observed['tree'] == expected_tree,
            'EXACT_SOURCE_HEAD_TREE_REQUIRED')
    require(observed['status_porcelain'] == '', 'CLEAN_COMMITTED_SOURCE_REQUIRED')


def file_value(path):
    try:
        return path.read_text().strip()
    except FileNotFoundError:
        return None


def resource_observation():
    require(sys.platform.startswith('linux'), 'LINUX_NATIVE_CPU_OBSERVATION_REQUIRED')
    cgroups = Path('/proc/self/cgroup').read_text().splitlines()
    unified = [line.split(':', 2)[2] for line in cgroups if line.startswith('0::')]
    require(len(unified) == 1, 'UNIFIED_CGROUP_OBSERVATION_REQUIRED')
    path = Path('/sys/fs/cgroup') / unified[0].lstrip('/')
    rows = []
    while True:
        rows.append({'path': str(path), **{name: file_value(path / name) for name in (
            'cpu.max', 'cpu.stat', 'cpuset.cpus.effective', 'memory.max', 'memory.events')}})
        if path == Path('/sys/fs/cgroup'):
            break
        require(path.is_relative_to('/sys/fs/cgroup'), 'CGROUP_PATH_REQUIRED')
        path = path.parent
    return {'schema': 'trnm.resource-observation.v1', 'cgroup': unified[0],
            'limits': rows, 'nice': os.getpriority(os.PRIO_PROCESS, 0),
            'cpu_affinity': sorted(os.sched_getaffinity(0))}


def validate_resources(observation, expected_nice):
    rows = observation['limits']
    require(rows and rows[0]['cpu.max'] == '400000 100000'
            and rows[0]['memory.max'] == '17179869184', 'ACTUAL_400_PERCENT_16_GIB_REQUIRED')
    require(observation['nice'] == expected_nice, 'ACTUAL_EXPECTED_NICE_REQUIRED')
    require(len(observation['cpu_affinity']) >= 4, 'AT_LEAST_FOUR_AFFINITY_CPUS_REQUIRED')
    for row in rows:
        value = row['cpu.max']
        if value is not None:
            quota, period = value.split()
            require(int(period) > 0 and (quota == 'max' or int(quota) >= 4 * int(period)),
                    'ANCESTOR_CPU_LIMIT_BELOW_DECLARED_QUOTA')
        maximum = row['memory.max']
        require(maximum in (None, 'max') or int(maximum) >= 17179869184,
                'ANCESTOR_MEMORY_LIMIT_BELOW_DECLARED_LIMIT')


def run_step(output, name, command, environment, *, timeout, stdout_name=None,
             stdout_limit=STDOUT_LIMIT, stderr_limit=STDERR_LIMIT):
    """Retain exact bounded streams and the failure, including zero-exit I/O failures."""
    stdout_path = output / (stdout_name or name + '.stdout.log')
    stderr_path = output / (name + '.stderr.log')
    start = time.monotonic_ns()
    row = {'name': name, 'command': command, 'cwd': str(ROOT),
           'outer_stage_timeout_seconds': timeout, 'returncode': None, 'error': None,
           'stdout': stdout_path.name, 'stderr': stderr_path.name,
           'stdout_truncated': False, 'stderr_truncated': False}
    # Reserve both outputs before contacting a child. Never overwrite a prior run.
    with stdout_path.open('xb') as stdout_file, stderr_path.open('xb') as stderr_file:
        stdout = stderr = b''
        try:
            captured = run_bounded(command, b'', timeout=timeout, stdout_limit=stdout_limit,
                                   stderr_limit=stderr_limit, cwd=ROOT, env=environment)
            row['returncode'] = captured.returncode
            stdout, stderr = captured.stdout, captured.stderr
        except ProcessFailure as error:
            row.update(returncode=error.returncode, error=str(error),
                       stdout_truncated=error.stdout_truncated, stderr_truncated=error.stderr_truncated)
            stdout, stderr = error.stdout, error.stderr
        except (OSError, ValueError) as error:
            row['error'] = str(error)
        finally:
            stdout_file.write(stdout)
            stderr_file.write(stderr)
    row.update(elapsed_ns=time.monotonic_ns() - start, stdout_bytes=len(stdout), stderr_bytes=len(stderr))
    row['elapsed_seconds'] = row['elapsed_ns'] / 1_000_000_000
    row['stdout_sha256'], row['stderr_sha256'] = sha(stdout_path), sha(stderr_path)
    row['complete_success'] = row['returncode'] == 0 and row['error'] is None
    write_new(output / (name + '.step.json'), row)
    return row


def campaign_args(binary, row):
    _, samples, attempts, replays, target, seed = row
    return [str(binary), '--samples', str(samples), '--attempts', str(attempts),
            '--receiver-replays', str(replays), '--target', target, '--seed', str(seed)]


def run(args):
    require(re.fullmatch('[0-9a-f]{40}', args.expected_head)
            and re.fullmatch('[0-9a-f]{40}', args.expected_tree), 'FULL_HEAD_AND_TREE_REQUIRED')
    matrix_v2 = getattr(args, 'cost_matrix_v2', False)
    example = 'pon_w1_cost_matrix_v2' if matrix_v2 else 'pon_w1_budget_report'
    grid = [('w1-all-producers-v2',)] if matrix_v2 else GRID
    out, target = args.out.resolve(), args.target_dir.resolve()
    require(not out.is_relative_to(ROOT), 'OUTPUT_MUST_BE_OUTSIDE_SOURCE')
    require(not target.is_relative_to(ROOT), 'TARGET_MUST_BE_OUTSIDE_SOURCE')
    require(out != target and not out.is_relative_to(target) and not target.is_relative_to(out),
            'OUTPUT_AND_BUILD_TARGET_MUST_BE_DISJOINT')
    # Validate source before recording this as an attempted native campaign.
    before = source_snapshot()
    validate_source(before, args.expected_head, args.expected_tree)
    validate_build_environment(os.environ)
    out.mkdir(parents=True, exist_ok=False)
    env = {key: value for key, value in os.environ.items() if not key.startswith('TRNM_')}
    env.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS='2', CARGO_NET_OFFLINE='true',
               RUSTUP_TOOLCHAIN='1.95.0', PYTHONDONTWRITEBYTECODE='1')
    result = {'schema': ('pon-w1-native-cost-matrix-bundle-v2' if matrix_v2 else 'pon-w1-native-campaign-bundle-v1'), 'head': args.expected_head,
              'tree': args.expected_tree, 'native': False, 'operator_count': 1,
              'independent_operator_qualification': False, 'host_label': args.host_label,
              'started_utc': datetime.now(timezone.utc).isoformat(), 'steps': [],
              'source_before': before, 'source_after': None, 'source_unchanged': False,
              'binary': None, 'complete_success': False, 'failure': None,
              'scope': 'actual local executable observations; no host attestation, independent operators, GPU lower bound or production qualification',
              'environment': {key: env.get(key) for key in (
                  'CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN', 'CARGO_TARGET_DIR',
                  'CARGO_BUILD_JOBS', 'CARGO_NET_OFFLINE', 'PYTHONDONTWRITEBYTECODE')},
              'inherited_build_overrides': {name: os.environ.get(name) for name in BUILD_ENV},
              'runner_sha256': sha(__file__), 'toolchain': '1.95.0', 'profile': 'release',
              'outer_resources_expected': {'cpu_max': '400000 100000', 'memory_max': '17179869184',
                                           'nice': args.expected_nice}}
    binary = None
    try:
        resources = resource_observation()
        write_new(out / 'resource-before.json', resources)
        models = sorted({line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                         if line.startswith('model name')})
        hardware = {'host_label': args.host_label, 'cpu_models': models, 'kernel': platform.release(),
                    'machine': platform.machine(), 'logical_cpu_count': os.cpu_count(),
                    'platform': platform.platform(), 'python': sys.version,
                    'cpu_quota_percent': 400, 'resource_observation': resources,
                    'native_same_host_other_builds_possible': True,
                    'hardware_identity_is_external_observation_not_attestation': True}
        write_new(out / 'hardware.json', hardware)
        validate_resources(resources, args.expected_nice)
        cargo = [str(args.cargo), '+1.95.0']
        # Actual compiler identity, not inferred from the requested +toolchain name.
        for name, command in (
            ('preflight', ['/bin/bash', 'scripts/project-preflight.sh']),
            ('rustc-version', [str(args.cargo.parent / 'rustup'), 'run', '1.95.0', 'rustc', '-Vv']),
            ('cargo-version', [*cargo, '-Vv']),
            ('build', [*cargo, 'build', '--offline', '--locked', '--release', '--jobs', '2',
                       '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node',
                       '--example', example, '--message-format=json'])):
            step = run_step(out, name, command, env, timeout=BUILD_SECONDS if name == 'build' else 60)
            result['steps'].append(step)
            require(step['complete_success'], name.upper() + '_FAILED')
        candidates = []
        for line in (out / 'build.stdout.log').read_bytes().splitlines():
            row = json.loads(line)
            if (row.get('reason') == 'compiler-artifact'
                    and row.get('target', {}).get('name') == example
                    and row.get('executable')):
                candidates.append(Path(row['executable']).resolve())
        require(len(candidates) == 1, 'ONE_EXACT_NATIVE_BINARY_REQUIRED')
        build_artifact = candidates[0]
        require(build_artifact.is_relative_to(target) and build_artifact.is_file(), 'EXPECTED_TARGET_BINARY_REQUIRED')
        artifact_hash = sha(build_artifact)
        retained_binary = out / (example + '.bin')
        with build_artifact.open('rb') as source, retained_binary.open('xb') as destination:
            shutil.copyfileobj(source, destination)
        retained_binary.chmod(0o700)
        require(sha(retained_binary) == artifact_hash, 'NATIVE_BINARY_CHANGED_DURING_CAPTURE')
        binary = retained_binary
        result['binary'] = {'path': str(binary), 'build_artifact': str(build_artifact),
                            'sha256_before': artifact_hash, 'sha256_after': None,
                            'bytes': binary.stat().st_size, 'build_separate_from_measured_work': True,
                            'retained_bytes_are_executed_directly': True}
        validate_source(source_snapshot(), args.expected_head, args.expected_tree)
        write_new(out / 'binary-before.json', result['binary'])
        for row in grid:
            # Never replace, repeat or drop a failed arm/file to improve the cohort.
            step = run_step(out, row[0], [str(binary)] if matrix_v2 else campaign_args(binary, row), env,
                            timeout=RUN_SECONDS, stdout_name=row[0] + '.jsonl')
            result['steps'].append(step)
            result['native'] = result['native'] or step['returncode'] is not None
        require(all(row['complete_success'] for row in result['steps']), 'NATIVE_CAMPAIGN_STEP_FAILED')
        sys.path.insert(0, str(ROOT / 'scripts'))
        if matrix_v2:
            import pon_w1_cost_matrix_reader as reader
        else:
            import pon_w1_budget_reader as reader
        validations = {row[0]: reader.analyze(out / (row[0] + '.jsonl')) for row in grid}
        if matrix_v2:
            # A complete native capture may establish a real failing cost gate.
            # Preserve that verdict separately from framing/semantic correctness.
            result['local_cost_gate'] = validations['w1-all-producers-v2']['local_cost_gate']
            result['local_observation_gate'] = validations['w1-all-producers-v2']['local_observation_gate']
        write_new(out / 'raw-validation.json', validations)
        require(all(value['record_consistency'] == 'PASS' and not value['semantic_alerts']
                    for value in validations.values()), 'RAW_RECORD_CONSISTENCY_FAILED')
        result['complete_success'] = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result['failure'] = str(error)
    finally:
        try:
            result['source_after'] = source_snapshot()
            validate_source(result['source_after'], args.expected_head, args.expected_tree)
            result['source_unchanged'] = True
            if binary is not None:
                result['binary']['sha256_after'] = sha(binary)
                require(result['binary']['sha256_after'] == result['binary']['sha256_before'],
                        'NATIVE_BINARY_CHANGED_DURING_CAMPAIGN')
            resources_after = resource_observation()
            write_new(out / 'resource-after.json', resources_after)
            validate_resources(resources_after, args.expected_nice)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            result['complete_success'] = False
            result['finalization_failure'] = str(error)
        result['complete_success'] = result['complete_success'] and result['source_unchanged']
        result['completed_utc'] = datetime.now(timezone.utc).isoformat()
        result['files'] = {path.name: {'sha256': sha(path), 'bytes': path.stat().st_size}
                           for path in sorted(out.iterdir()) if path.is_file()}
        write_new(out / 'results.json', result)
    print(json.dumps({'out': str(out), 'head': result['head'], 'tree': result['tree'],
                      'complete_success': result['complete_success'], 'failure': result['failure'],
                      'finalization_failure': result.get('finalization_failure')}, sort_keys=True))
    return 0 if result['complete_success'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--target-dir', required=True, type=Path)
    parser.add_argument('--cargo', required=True, type=Path)
    parser.add_argument('--host-label', required=True)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-tree', required=True)
    parser.add_argument('--expected-nice', type=int, default=10)
    parser.add_argument('--cost-matrix-v2', action='store_true',
                        help='explicit 13-producer/fact-cache CPU capture; original four-file V1 grid is unchanged')
    return run(parser.parse_args())


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
