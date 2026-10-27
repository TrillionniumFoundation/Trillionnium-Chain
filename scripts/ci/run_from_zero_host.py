#!/usr/bin/env python3
"""Run only the unchanged from-zero subprocess in its real fixed CI Host parent.

No native test, admission check, acceptance predicate or time budget is replaced.
The hosted runner provisions the checked-in unit; native code still owns the
original eligibility checks. This script must never provision a local workstation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

from public_host_ci_observation import (PARENT, RUNTIME_UNIT, UNIT, UNIT_SHA256,
                                        capture, validate, write_new)


ROOT = Path(__file__).resolve().parents[2]
# Explicit non-secret build/source inputs only. Do not copy or inspect all env.
ENVIRONMENT = (
    'PATH', 'CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL',
    'CARGO_TERM_COLOR', 'RUST_TEST_THREADS', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS',
    'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN', 'CI', 'PYTHONDONTWRITEBYTECODE', 'RUNNER_TEMP',
    'GITHUB_ACTIONS', 'GITHUB_WORKSPACE', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT',
    'GITHUB_JOB', 'GITHUB_SHA', 'GITHUB_EVENT_NAME', 'GITHUB_EVENT_PATH',
    'TRNM_CI_RECEIPT_DIR', 'TRNM_EXPECTED_SOURCE_SHA', 'TRNM_EXPECTED_CANDIDATE_SHA',
    'TRNM_EXPECTED_BASE_SHA', 'TRNM_COST_RUNNER_LABEL',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_command(command: list[str]) -> Path:
    require(len(command) == 4 and command[:3] == [
        'python3', 'scripts/ci/run_from_zero_native.py', '--out'], 'ORIGINAL_ARGV_REQUIRED')
    out = Path(command[3])
    require(out.is_absolute() and not out.resolve().is_relative_to(ROOT),
            'OUTPUT_MUST_BE_OUTSIDE_CHECKOUT')
    return out


def environment_arguments(environment: dict[str, str]) -> list[str]:
    return ['--setenv=' + key + '=' + environment[key]
            for key in ENVIRONMENT if key in environment]


def service_command(service: str, receipts: Path, command: list[str],
                    uid: int, gid: int, environment: dict[str, str]) -> list[str]:
    return [
        'sudo', '-n', 'systemd-run', '--unit=' + service, '--wait', '--pipe', '--collect',
        '--service-type=exec', '--expand-environment=no', '--slice=' + UNIT,
        '--uid=' + str(uid), '--gid=' + str(gid), '--working-directory=' + str(ROOT),
        '--property=KillMode=control-group', '--property=TimeoutStopSec=20s',
        '--property=Delegate=no', '--property=NoNewPrivileges=yes',
        '--property=CapabilityBoundingSet=', *environment_arguments(environment),
        sys.executable, str(Path(__file__).resolve()), '--inside', str(receipts), service,
        str(uid), str(gid), '--', *command,
    ]


def inside(receipts: Path, service: str, uid: int, gid: int, command: list[str]) -> int:
    validate_command(command)
    before = capture('inside-before-native', service)
    errors = validate(before, inside=True, uid=uid, gid=gid, cwd=str(ROOT))
    write_new(receipts / 'inside-before.json', before)
    result = {'schema': 'trnm-ci-original-public-host-child-v1', 'command_argv': command,
              'native_child_exit': None, 'host_errors': errors,
              'host_readiness_only': True, 'consensus_or_model_authority': False}
    try:
        if not errors:
            result['native_child_exit'] = subprocess.run(command, cwd=ROOT).returncode
    finally:
        after = capture('inside-after-native', service)
        write_new(receipts / 'inside-after.json', after)
        result['host_errors'] += validate(after, inside=True, uid=uid, gid=gid,
                                         cwd=str(ROOT), reference=before)
        write_new(receipts / 'child-result.json', result)
    if result['host_errors']:
        return 1
    return result['native_child_exit'] if result['native_child_exit'] is not None else 1


class HostSignal(Exception):
    def __init__(self, number):
        self.number = number


def exit_status(result: dict) -> int:
    # A late signal/failure cannot retain a previously computed successful flag.
    if result.get('passed') is True and result.get('failure') is None:
        return 0
    return result.get('systemd_run_exit') or 1


def outer(command: list[str]) -> int:
    output = validate_command(command)
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('CI') == 'true',
            'HOSTED_CI_ONLY_NO_LOCAL_PROVISION')
    require(Path.cwd().resolve() == ROOT, 'ORIGINAL_WORKING_DIRECTORY')
    uid, gid = os.getuid(), os.getgid()
    require(uid != 0, 'ORIGINAL_UNPRIVILEGED_RUNNER_REQUIRED')
    run, attempt, job = (os.environ.get(key, '') for key in (
        'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB'))
    require(run.isdecimal() and attempt.isdecimal()
            and re.fullmatch(r'[A-Za-z0-9_-]{1,80}', job), 'BOUNDED_JOB_IDENTITY')
    service = f'trnm-from-zero-{run}-{attempt}-{job}-{os.getpid()}.service'
    receipts = output.with_name(output.name + '-host')
    receipts.mkdir(parents=True, exist_ok=False)
    result = {'schema': 'trnm-ci-original-public-host-controller-v1',
              'service': service, 'command_argv': command, 'uid': uid, 'gid': gid,
              'cwd': str(ROOT), 'systemd_run_exit': None, 'failure': None,
              'cleanup': None, 'passed': False, 'host_readiness_only': True,
              'consensus_or_model_authority': False}
    owned_service = False
    provisioned = None

    def run_setup(arguments: list[str], name: str, *, must_succeed=True):
        with (receipts / (name + '.log')).open('xb') as stream:
            completed = subprocess.run(arguments, stdout=stream, stderr=subprocess.STDOUT,
                                       timeout=30)
        require(not must_succeed or completed.returncode == 0, name + '_FAILED')
        return completed.returncode

    def interrupted(number, _frame):
        raise HostSignal(number)

    previous_handlers = {number: signal.signal(number, interrupted)
                         for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        write_new(receipts / 'before-provision.json', capture('before-provision', service))
        require(Path('/run/systemd/system').is_dir()
                and Path('/sys/fs/cgroup/cgroup.controllers').is_file(), 'SYSTEMD_CGROUP_V2_REQUIRED')
        unit_source = ROOT / 'config/systemd' / UNIT
        require(hashlib.sha256(unit_source.read_bytes()).hexdigest() == UNIT_SHA256,
                'REVIEWED_UNIT_BYTES')
        # Do not overwrite or reconfigure any already provisioned Host parent.
        require(not RUNTIME_UNIT.exists() and not RUNTIME_UNIT.is_symlink()
                and not PARENT.exists() and not PARENT.is_symlink(), 'PARENT_ALREADY_PROVISIONED')
        run_setup(['systemctl', 'show', '--property=LoadState', '--value', UNIT],
                  'parent-load-state', must_succeed=False)
        require((receipts / 'parent-load-state.log').read_text().strip() == 'not-found',
                'PARENT_ALREADY_LOADED')
        run_setup(['sudo', '-n', 'install', '-o', 'root', '-g', 'root', '-m', '0644',
                   str(unit_source), str(RUNTIME_UNIT)], 'install-reviewed-unit')
        run_setup(['sudo', '-n', 'systemctl', 'daemon-reload'], 'systemd-reload')
        run_setup(['sudo', '-n', 'systemctl', 'start', UNIT], 'start-fixed-parent')
        run_setup(['systemctl', 'show', UNIT, '--property=FragmentPath,DropInPaths,ControlGroup,'
                   'CPUQuotaPerSecUSec,CPUQuotaPeriodUSec,MemoryMax,MemorySwapMax,TasksMax'],
                  'actual-systemd-parent')
        provisioned = capture('outside-after-provision', service)
        write_new(receipts / 'after-provision.json', provisioned)
        require(not validate(provisioned, inside=False, uid=uid, gid=gid, cwd=str(ROOT)),
                'ACTUAL_PARENT_VALIDATION_FAILED')
        run_setup(['systemctl', 'show', '--property=LoadState', '--value', service],
                  'child-load-state', must_succeed=False)
        require((receipts / 'child-load-state.log').read_text().strip() == 'not-found',
                'CHILD_SERVICE_ALREADY_EXISTS')
        environment = {key: os.environ[key] for key in ENVIRONMENT if key in os.environ}
        if 'RUSTUP_HOME' not in environment:
            environment['RUSTUP_HOME'] = subprocess.check_output(
                ['rustup', 'show', 'home'], text=True, timeout=30).strip()
        owned_service = True
        with (receipts / 'systemd-run.log').open('xb') as stream:
            result['systemd_run_exit'] = subprocess.run(
                service_command(service, receipts, command, uid, gid, environment),
                stdout=stream, stderr=subprocess.STDOUT).returncode
        child = json.loads((receipts / 'child-result.json').read_text())
        require(child['command_argv'] == command and not child['host_errors'],
                'ACTUAL_CHILD_HOST_VALIDATION_FAILED')
        for name in ('inside-before.json', 'inside-after.json'):
            sample = json.loads((receipts / name).read_text())
            require(not validate(sample, inside=True, uid=uid, gid=gid,
                                 cwd=str(ROOT), reference=provisioned),
                    'PROVISIONED_CHILD_CONTEXT_CHANGED:' + name)
        result['passed'] = result['systemd_run_exit'] == 0 and child['native_child_exit'] == 0
    except HostSignal as error:
        result['failure'] = 'SIGNAL_' + str(error.number)
        result['systemd_run_exit'] = 128 + error.number
        result['passed'] = False
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result['failure'] = str(error)
        result['passed'] = False
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
        # The shared fixed parent is never stopped, widened or removed here.
        # Only the unique service this invocation attempted to create is owned.
        if owned_service:
            try:
                run_setup(['systemctl', 'show', '--property=LoadState', '--value', service],
                          'child-final-load-state', must_succeed=False)
                if (receipts / 'child-final-load-state.log').read_text().strip() == 'not-found':
                    result['cleanup'] = 'already-collected'
                else:
                    run_setup(['sudo', '-n', 'systemctl', 'stop', service], 'stop-owned-child')
                    result['cleanup'] = 'owned-child-stopped'
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                result['cleanup'] = str(error)
                result['passed'] = False
        after = capture('outside-after-child', service)
        write_new(receipts / 'outside-after.json', after)
        if provisioned is not None:
            result['final_host_errors'] = validate(after, inside=False, uid=uid, gid=gid,
                                                 cwd=str(ROOT), reference=provisioned)
            if result['final_host_errors']:
                result['passed'] = False
        write_new(receipts / 'controller-result.json', result)
    print(json.dumps(result, sort_keys=True))
    return exit_status(result)


if __name__ == '__main__':
    try:
        args = sys.argv[1:]
        if args[:1] == ['--inside']:
            require(len(args) >= 7 and args[5] == '--', 'INNER_ARGV')
            code = inside(Path(args[1]), args[2], int(args[3]), int(args[4]), args[6:])
        else:
            require(args[:1] == ['--'], 'EXPLICIT_ARGV_SEPARATOR_REQUIRED')
            code = outer(args[1:])
        raise SystemExit(code)
    except (OSError, ValueError) as error:
        print(json.dumps({'passed': False, 'failure': str(error), 'host_readiness_only': True}))
        raise SystemExit(1)
