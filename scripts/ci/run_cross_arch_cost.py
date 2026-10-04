#!/usr/bin/env python3
"""Execute bounded native release costs; retain commands, raw output and failures."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time

from ci_observation import ROOT, digest, receipt_root, source
from check_cross_arch_cost import (ARCHITECTURES, CAMPAIGNS, SUITES, benchmark_arguments,
                                   elf_machine, suite_contract, COST_IDENTITY_TIMEOUT_SECONDS,
                                   COST_BUILD_TIMEOUT_SECONDS, COST_CAMPAIGN_TIMEOUT_SECONDS,
                                   COST_TERMINATION_GRACE_SECONDS)


def capture(command: list[str], output: Path, stem: str, *, timeout: float,
            cwd: Path = ROOT) -> dict:
    """Keep stdout and stderr even for a nonzero exit, signal or bounded timeout."""
    started = time.monotonic_ns()
    result = {'command': command, 'cwd': str(cwd), 'exit_code': None,
              'timed_out': False, 'timeout_seconds': timeout,
              'stdout': stem + '.stdout', 'stderr': stem + '.stderr'}
    with (output / result['stdout']).open('xb') as stdout, (output / result['stderr']).open('xb') as stderr:
        try:
            process = subprocess.Popen(command, cwd=cwd, stdout=stdout, stderr=stderr,
                                       start_new_session=True)
        except OSError as error:
            result['launch_error'] = str(error)
        else:
            try:
                result['exit_code'] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                result['timed_out'] = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=COST_TERMINATION_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                result['exit_code'] = 124
    result['elapsed_ns'] = time.monotonic_ns() - started
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=sorted(ARCHITECTURES), required=True)
    parser.add_argument('--suite', choices=SUITES, default='reused')
    parser.add_argument('--local', action='store_true',
                        help='explicit local native preflight; cannot satisfy hosted artifact comparison')
    args = parser.parse_args()
    contract = suite_contract(args.suite)
    example = contract['example']
    output = receipt_root(contract['directory'])
    spec = ARCHITECTURES[args.arch]
    observations: list[dict] = []
    report = {'schema': contract['execution_schema'], 'result': 'FAIL',
              'execution_context': 'local-native-preflight' if args.local else 'github-hosted',
              'architecture': args.arch, 'runner_label': os.environ.get('TRNM_COST_RUNNER_LABEL'),
              'observations': observations, 'campaigns': [], 'build_profile': 'release',
              'compiler_channel': '1.95.0', 'target': spec['target'],
              'public_network_ready': False, 'independent_hardware_qualified': False,
              'resource_fairness_qualified': False, 'work_profile_qualified': False,
              'production_activation': False}
    report['runner_context'] = {key: os.environ.get(key) for key in
        ['GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB', 'GITHUB_REPOSITORY',
         'GITHUB_EVENT_NAME', 'RUNNER_ARCH', 'RUNNER_OS', 'RUNNER_NAME', 'ImageOS', 'ImageVersion']}
    report['uname'] = dict(zip(['system', 'node', 'release', 'version', 'machine', 'processor'], platform.uname()))
    report['source_before'] = None

    def checked(command: list[str], stem: str, timeout: int = COST_IDENTITY_TIMEOUT_SECONDS) -> dict:
        observed = capture(command, output, stem, timeout=timeout)
        observations.append(observed)
        if observed['exit_code'] != 0 or observed['timed_out']:
            raise RuntimeError(f'{stem} failed; inspect retained stdout/stderr and command status')
        return observed

    try:
        report['source_before'] = source()
        if report['source_before']['source_state'] != 'committed-clean':
            raise ValueError('cost campaign requires actual committed source bytes')
        if report['uname']['machine'] != spec['machine'] or report['uname']['system'] != 'Linux':
            raise ValueError('requested architecture must actually execute on that native Linux host')
        if not args.local and report['runner_label'] != spec['runner']:
            raise ValueError('unexpected explicit hosted runner label')
        if not args.local and os.environ.get('RUNNER_ARCH') != spec['runner_arch']:
            raise ValueError('hosted runner architecture contradicts observed uname')
        if not args.local and (os.environ.get('GITHUB_ACTIONS') != 'true' or
                not os.environ.get('GITHUB_RUN_ID', '').isdigit() or
                not os.environ.get('GITHUB_RUN_ATTEMPT', '').isdigit()):
            raise ValueError('hosted observations require the actual workflow run context; use --local for preflight')
        overrides = {key: value for key, value in os.environ.items() if value and
                     (key in {'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
                              'RUSTC_WORKSPACE_WRAPPER', 'RUSTC', 'RUSTC_BOOTSTRAP'} or
                      key.startswith('CARGO_PROFILE_RELEASE_') or key.startswith('CARGO_TARGET_')
                      and key != 'CARGO_TARGET_DIR')}
        report['build_environment_overrides'] = overrides
        if overrides:
            raise ValueError('release compiler/target overrides would change the campaign build contract')
        checked(['uname', '-a'], 'uname')
        checked(['rustc', '+1.95.0', '-vV'], 'rustc')
        checked(['cargo', '+1.95.0', '--version'], 'cargo')
        compiler = (output / 'rustc.stdout').read_text()
        if '\nrelease: 1.95.0\n' not in compiler or '\nhost: ' + spec['target'] + '\n' not in compiler:
            raise ValueError('actual native rustc identity differs from the pinned target/compiler')
        shutil.copyfile('/proc/cpuinfo', output / 'cpuinfo.txt')
        checked(['cargo', '+1.95.0', 'build', '--locked', '--release', '--manifest-path',
                 'trillionnium/Cargo.toml', '--target', spec['target'], '-p',
                 'trnm-crypto-primitives', '--example', example], 'build', COST_BUILD_TIMEOUT_SECONDS)
        binary = Path(os.environ['CARGO_TARGET_DIR']) / spec['target'] / 'release/examples' / example
        report['binary_elf_machine'] = elf_machine(binary)
        if report['binary_elf_machine'] != spec['elf_machine']:
            raise ValueError('compiled executable architecture differs from the actual host')
        report['binary_sha256_before'] = digest(binary)
        shutil.copyfile(binary, output / example)
        failed = False
        for index, campaign in enumerate(CAMPAIGNS):
            observed = capture([str(binary), *benchmark_arguments(campaign)], output,
                               f'campaign-{index}', timeout=COST_CAMPAIGN_TIMEOUT_SECONDS)
            observations.append(observed)
            row = {'configuration': campaign, 'observation': observed, 'result': 'FAIL'}
            try:
                if observed['exit_code'] != 0 or observed['timed_out']:
                    raise ValueError('native campaign failed or timed out')
                data = json.loads((output / observed['stdout']).read_text())
                row['validated'] = contract['validate_raw_report'](data, campaign)
                row['result'] = 'PASS'
            except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
                row['error'] = str(error)
                failed = True
            report['campaigns'].append(row)
        report['binary_sha256_after'] = digest(binary)
        if report['binary_sha256_before'] != report['binary_sha256_after']:
            raise ValueError('measured binary changed during execution')
        if failed:
            raise ValueError('one or more native campaigns failed correctness/retention checks')
        report['result'] = 'PASS'
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        try:
            report['source_after'] = source()
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            report['source_after'] = {'error': str(error)}
        if report['source_before'] != report['source_after']:
            report['result'] = 'FAIL'
            report['source_changed'] = True
        else:
            report['source_changed'] = False
        inputs = contract['inputs']
        report['input_sha256'] = {name: digest(ROOT / name) for name in inputs if (ROOT / name).is_file()}
        report['artifact_sha256'] = {p.relative_to(output).as_posix(): digest(p)
                                     for p in sorted(output.rglob('*')) if p.is_file()}
        (output / 'manifest.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'result': report['result'], 'receipt': str(output)}, sort_keys=True))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
