#!/usr/bin/env python3
"""Run exact current workspace integration ELFs in the original fixed CI Host.

Only the nine declared public fixtures may use this adapter. It never invokes
Cargo. Architecture retains its original 120-second selector bound and complete
18-sample reader. Other fixtures retain their own native lifetimes and the
original CI supervisor; pidfds prevent a detached service outliving its owners.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import time

import public_fixture_host_lease as lease
import run_history_native as history
from check_required_native_test import validate as validate_named_test
from public_host_ci_observation import write_new
from replay_pinned_native import json_load, require

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1/experiments'))
import architecture_compare as business

SCRIPT = 'scripts/ci/run_public_fixture_native.py'
TARGET = 'architecture_delivery_compare'
SELECTOR = business.SELECTORS[1]
CHILD = 'TRNM_PUBLIC_FIXTURE_HOST_CHILD'
PREPARATION_SCHEMA = 'trnm-ci-public-fixture-current-elf-preparation-v1'
EXECUTION_SCHEMA = 'trnm-ci-public-fixture-host-execution-v1'
REPORT_SCHEMA = 'native-signed-dag-delivery-comparison-v1'
NATIVE_TIMEOUT_SECONDS = 120
FIXTURE_ENVIRONMENT = ('EVALUATION_SYNC_OBSERVATION_EVIDENCE_DIR',)
# Exact target/selector pairs, not a general executable or shell runner.
FIXTURES = {
    (TARGET, SELECTOR): False,
    ('public_intake_v2', 'unknown_caller_cannot_override_ledger_and_full_sync_independently_verifies_actual_work'): False,
    ('public_intake_v2', 'one_packet_history_preserves_partial_progress_and_independent_validation'): False,
    ('public_cli', 'actual_public_cli_pins_server_denials_fail_and_sync_verifies_native_history'): True,
    ('public_pool_cli', 'actual_v3_cli_unknown_guest_funding_and_atomic_renewal_reach_native_receiver'): True,
    ('public_pool_cli', 'actual_pinned_peer_cli_follows_native_blocks_and_closes_shared_owner'): True,
    ('mining_service_budget', 'mining_runtime_ends_before_service_and_fresh_native_follower_confirms_last_chain'): True,
    ('evaluation_sync_observation', 'actual_public_full_sync_query_partial_refusals_reorg_and_retirement'): True,
    ('native_node', 'test_authenticated_cli_push_and_sync_share_one_durable_outbox_owner'): True,
}


def fixture(target: str, selector: str) -> dict:
    require((target, selector) in FIXTURES, 'PUBLIC_FIXTURE_EXACT_SELECTOR_REQUIRED')
    architecture = (target, selector) == (TARGET, SELECTOR)
    return {'target': target, 'selector': selector, 'cli_required': FIXTURES[(target, selector)],
            'source': 'trillionnium/crates/trnm-pon-node/tests/' + target + '.rs',
            'architecture_report_required': architecture,
            'timeout_seconds': NATIVE_TIMEOUT_SECONDS if architecture else None}


def configuration(out: Path) -> dict:
    receipts = Path(os.environ.get('TRNM_CI_RECEIPT_DIR', ''))
    require(receipts.is_absolute() and receipts.resolve(strict=True) == receipts
            and receipts.is_dir() and out.is_absolute() and out.resolve() == out
            and not out.is_relative_to(ROOT), 'PUBLIC_FIXTURE_CURRENT_OUTPUT_REQUIRED')
    relative = out.relative_to(receipts / 'public-fixtures')
    require(len(relative.parts) == 2, 'PUBLIC_FIXTURE_CURRENT_OUTPUT_REQUIRED')
    return fixture(*relative.parts)


def source_identity(target: str = TARGET) -> dict:
    actual = lease.workflow_source()
    test, _ = history.file_observation(
        ROOT / ('trillionnium/crates/trnm-pon-node/tests/' + target + '.rs'), history.JSON_LIMIT)
    return {'commit': actual['tested_commit'], 'tree': actual['tested_tree'],
            'tracked_source_identity': actual, 'test_sha256': test['sha256']}


def elf_observation(binary: Path) -> dict:
    observed, _ = history.file_observation(binary, history.BINARY_LIMIT)
    with binary.open('rb') as stream:
        require(stream.read(4) == b'\x7fELF', 'PUBLIC_FIXTURE_CURRENT_ELF_REQUIRED')
    require(os.access(binary, os.X_OK), 'PUBLIC_FIXTURE_EXECUTABLE_REQUIRED')
    return observed


def process_identity(pid: int) -> dict:
    require(type(pid) is int and pid > 1, 'PUBLIC_FIXTURE_OWNER_PID')
    proc = Path('/proc') / str(pid)
    before = proc.stat()
    require(before.st_uid == os.getuid(), 'PUBLIC_FIXTURE_OWNER_UID')
    with (proc / 'stat').open('rb') as stream:
        raw = stream.read(4097)
    require(len(raw) <= 4096, 'PUBLIC_FIXTURE_PROC_STAT_BOUND')
    fields = raw.decode('utf-8').rsplit(') ', 1)[1].split()
    require(len(fields) >= 20 and fields[19].isdecimal() and fields[1].isdecimal(),
            'PUBLIC_FIXTURE_PROC_START_REQUIRED')
    after = proc.stat()
    require((before.st_dev, before.st_ino, before.st_uid, before.st_gid)
            == (after.st_dev, after.st_ino, after.st_uid, after.st_gid),
            'PUBLIC_FIXTURE_OWNER_CHANGED')
    return {'pid': pid, 'parent_pid': int(fields[1]), 'start_ticks': int(fields[19]),
            'device': before.st_dev, 'inode': before.st_ino,
            'uid': before.st_uid, 'gid': before.st_gid}


def parent_binary(pid: int, binary: Path) -> dict:
    """Bind the actual waiting libtest process, not a caller-named executable."""
    process_identity(pid)
    executable = Path('/proc') / str(pid) / 'exe'
    before = executable.stat()
    observed = elf_observation(binary)
    after = executable.stat()
    require(executable.resolve(strict=True) == binary
            and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
            == (observed['device'], observed['inode']), 'PUBLIC_FIXTURE_PARENT_ELF_CHANGED')
    return observed


def parent_cwd(pid: int) -> dict:
    process_identity(pid)
    link = Path('/proc') / str(pid) / 'cwd'
    before = link.stat()
    path = link.resolve(strict=True)
    after = link.stat()
    require(path in (ROOT, ROOT / 'trillionnium/crates/trnm-pon-node')
            and stat.S_ISDIR(before.st_mode)
            and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
            'PUBLIC_FIXTURE_ORIGINAL_NATIVE_CWD_REQUIRED')
    return {'path': str(path), 'device': before.st_dev, 'inode': before.st_ino}


def native_output(out: Path) -> Path:
    require(configuration(out)['architecture_report_required'], 'ARCHITECTURE_OUTPUT_ONLY')
    requested = os.environ.get('TRNM_ARCHITECTURE_COMPARE_DIR')
    path = Path(requested) if requested is not None else out / 'native'
    require(path.is_absolute() and path.resolve() == path and not path.is_relative_to(ROOT)
            and path != out and path != out.parent
            and path.parent.is_dir() and not path.exists() and not path.is_symlink(),
            'ARCHITECTURE_FRESH_NATIVE_OUTPUT_REQUIRED')
    return path


def prepare(out: Path, binary: Path, pid: int, *, target: str = TARGET,
            selector: str = SELECTOR, cli_binary: Path | None = None) -> dict:
    spec = configuration(out)
    require(spec == fixture(target, selector), 'PUBLIC_FIXTURE_OUTPUT_SELECTOR_CHANGED')
    require((cli_binary is not None) == spec['cli_required'], 'PUBLIC_FIXTURE_EXACT_CLI_REQUIRED')
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('CI') == 'true'
            and os.getuid() != 0, 'PUBLIC_FIXTURE_HOSTED_CI_ONLY')
    require(Path.cwd().resolve() == ROOT and os.getppid() == pid and CHILD not in os.environ,
            'PUBLIC_FIXTURE_DIRECT_WORKSPACE_PARENT_REQUIRED')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.mkdir(exist_ok=False)
    result = {'schema': PREPARATION_SCHEMA, **spec, 'job': None, 'parent_pid': pid,
              'supervisors': [], 'source_before': None, 'source_after': None,
              'binary': None, 'cli_binary': None, 'native_cwd': None, 'native_output': None,
              'failures': [], 'completed': False,
              'build_env': {key: os.environ.get(key) for key in history.BUILD_ENVIRONMENT},
              'fixture_env': {key: os.environ.get(key) for key in FIXTURE_ENVIRONMENT},
              'native_tests_executed': False, 'nested_cargo_invoked': False}
    try:
        result['job'] = history.job_identity()
        result['source_before'] = source_identity(target)
        result['binary'] = parent_binary(pid, binary)
        result['native_cwd'] = parent_cwd(pid)
        result['supervisors'] = [
            {'role': 'libtest', 'process': process_identity(pid)},
            {'role': 'launcher', 'process': process_identity(os.getpid())}]
        require(result['supervisors'][1]['process']['parent_pid'] == pid,
                'PUBLIC_FIXTURE_DIRECT_LAUNCHER_REQUIRED')
        if cli_binary is not None:
            result['cli_binary'] = elf_observation(cli_binary)
        if spec['architecture_report_required']:
            result['native_output'] = str(native_output(out))
    except BaseException as error:
        result['failures'].append(type(error).__name__ + ':' + str(error))
    finally:
        try:
            result['source_after'] = source_identity(target)
            require(result['source_before'] == result['source_after'], 'PUBLIC_FIXTURE_PREPARATION_SOURCE_CHANGED')
        except BaseException as error:
            result['failures'].append(type(error).__name__ + ':' + str(error))
        result['completed'] = not result['failures'] and result['binary'] is not None
        write_new(out / 'preparation.json', result)
    return result


def validate_preparation(out: Path) -> dict:
    spec = configuration(out)
    value, _ = history.load_object(out / 'preparation.json')
    require(value.get('schema') == PREPARATION_SCHEMA
            and all(value.get(key) == item for key, item in spec.items())
            and value.get('completed') is True and value.get('failures') == []
            and value.get('native_tests_executed') is False
            and value.get('nested_cargo_invoked') is False
            and value.get('job') == history.job_identity(), 'PUBLIC_FIXTURE_PREPARATION_REQUIRED')
    require(value.get('build_env') == {key: os.environ.get(key) for key in history.BUILD_ENVIRONMENT}
            and value.get('fixture_env') == {key: os.environ.get(key) for key in FIXTURE_ENVIRONMENT}
            and value.get('source_before') == value.get('source_after') == source_identity(spec['target']),
            'PUBLIC_FIXTURE_PREPARATION_CONTEXT_CHANGED')
    supervisors = value.get('supervisors')
    require(type(supervisors) is list and len(supervisors) == 2
            and [row.get('role') for row in supervisors] == ['libtest', 'launcher']
            and supervisors[0]['process']['pid'] == value['parent_pid']
            and supervisors[1]['process']['parent_pid'] == value['parent_pid']
            and supervisors[0]['process']['pid'] != supervisors[1]['process']['pid'],
            'PUBLIC_FIXTURE_TWO_SUPERVISORS_REQUIRED')
    for row in supervisors:
        require(row['process'] == process_identity(row['process']['pid']), 'PUBLIC_FIXTURE_SUPERVISOR_CHANGED')
    require(value.get('binary') == parent_binary(value['parent_pid'], Path(value['binary']['path'])),
            'PUBLIC_FIXTURE_PREPARED_ELF_CHANGED')
    require(value.get('native_cwd') == parent_cwd(value['parent_pid']),
            'PUBLIC_FIXTURE_PARENT_CWD_CHANGED')
    if spec['cli_required']:
        require(value.get('cli_binary') == elf_observation(Path(value['cli_binary']['path'])),
                'PUBLIC_FIXTURE_PREPARED_CLI_CHANGED')
    else:
        require(value.get('cli_binary') is None, 'PUBLIC_FIXTURE_UNDECLARED_CLI')
    if spec['architecture_report_required']:
        path = Path(value['native_output'])
        requested = os.environ.get('TRNM_ARCHITECTURE_COMPARE_DIR')
        require(path == (Path(requested) if requested is not None else out / 'native')
                and path.is_absolute() and path.resolve() == path and not path.is_relative_to(ROOT),
                'ARCHITECTURE_PREPARED_OUTPUT_CHANGED')
    else:
        require(value.get('native_output') is None, 'PUBLIC_FIXTURE_UNDECLARED_REPORT')
    return value


def native_command(binary: Path, selector: str = SELECTOR) -> list[str]:
    return [str(binary), selector, '--exact', '--show-output', '--test-threads=1']


def run_native_process(command: list[str], log: Path, *, environment: dict,
                       supervisors: list[dict], timeout_seconds: int | None, cwd: Path) -> dict:
    """Original selector deadline plus both actual owners, without PID reuse."""
    result = {'command': command, 'started': False, 'pid': None, 'exit_code': None,
              'failure': None, 'cleanup_errors': [], 'timed_out': False, 'reaped': False,
              'timeout_seconds': timeout_seconds, 'wall_ns': None, 'cwd': str(cwd),
              'supervisors': supervisors, 'supervisors_bound': False, 'supervisor_exit': None}
    child = None
    fds = []
    started = time.monotonic_ns()
    try:
        require(len(supervisors) == 2 and [row['role'] for row in supervisors] == ['libtest', 'launcher'],
                'PUBLIC_FIXTURE_TWO_SUPERVISORS_REQUIRED')
        require(hasattr(os, 'pidfd_open'), 'PUBLIC_FIXTURE_PIDFD_REQUIRED')
        poll = select.poll()
        owners = {}
        for row in supervisors:
            identity = row['process']
            require(process_identity(identity['pid']) == identity, 'PUBLIC_FIXTURE_SUPERVISOR_CHANGED')
            fd = os.pidfd_open(identity['pid'], 0)
            fds.append(fd)
            require(process_identity(identity['pid']) == identity, 'PUBLIC_FIXTURE_SUPERVISOR_CHANGED')
            poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
            owners[fd] = row['role']
        require(not poll.poll(0), 'PUBLIC_FIXTURE_SUPERVISOR_ALREADY_EXITED')
        result['supervisors_bound'] = True
        with log.open('xb') as stream:
            child = subprocess.Popen(command, cwd=cwd, env=environment,
                                     stdin=subprocess.DEVNULL, stdout=stream,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            result.update(started=True, pid=child.pid)
            child_fd = os.pidfd_open(child.pid, 0)
            fds.append(child_fd)
            poll.register(child_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
            while True:
                elapsed = (time.monotonic_ns() - started) / 1_000_000_000
                if timeout_seconds is not None and elapsed >= timeout_seconds:
                    result['timed_out'] = True
                    raise subprocess.TimeoutExpired(command, timeout_seconds)
                wait_ms = -1 if timeout_seconds is None else max(1, int((timeout_seconds - elapsed) * 1000))
                ready = poll.poll(wait_ms)
                for fd, _ in ready:
                    if fd in owners:
                        result['supervisor_exit'] = owners[fd]
                        raise ValueError('PUBLIC_FIXTURE_SUPERVISOR_EXITED:' + owners[fd])
                if any(fd == child_fd for fd, _ in ready):
                    result['exit_code'] = child.wait(timeout=5)
                    result['reaped'] = True
                    break
    except BaseException as error:
        result['failure'] = type(error).__name__ + ':' + str(error)
        if child is not None and not result['reaped']:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as cleanup:
                result['cleanup_errors'].append(type(cleanup).__name__ + ':' + str(cleanup))
            try:
                result['exit_code'] = child.wait(timeout=5)
                result['reaped'] = True
            except BaseException as cleanup:
                result['cleanup_errors'].append(type(cleanup).__name__ + ':' + str(cleanup))
                result['exit_code'] = child.returncode
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except OSError as error:
                result['cleanup_errors'].append(type(error).__name__ + ':' + str(error))
        result['wall_ns'] = time.monotonic_ns() - started
    return result


def native_process_succeeded(process: dict, command: list[str], timeout_seconds, supervisors, cwd) -> bool:
    return (history.process_succeeded(process, command)
            and process.get('timed_out') is False and process.get('reaped') is True
            and process.get('timeout_seconds') == timeout_seconds
            and process.get('cwd') == str(cwd)
            and process.get('supervisors') == supervisors
            and process.get('supervisors_bound') is True and process.get('supervisor_exit') is None)


def report_observation(path: Path) -> tuple[dict, dict]:
    observed, raw = history.file_observation(path, business.REPORT_LIMIT, retain=True)
    value = json_load(raw)
    require(type(value) is dict and value.get('schema') == REPORT_SCHEMA
            and value.get('samples_per_workload_and_mode') == 3
            and type(value.get('samples')) is list and len(value['samples']) == 18
            and type(value.get('workloads')) is list and len(value['workloads']) == 2,
            'ARCHITECTURE_COMPLETE_NATIVE_REPORT_REQUIRED')
    scenarios = ('disjoint-recipients', 'hot-recipient')
    require([row.get('scenario') for row in value['workloads']] == list(scenarios),
            'ARCHITECTURE_ORIGINAL_WORKLOADS_REQUIRED')
    expected = [(scenario, sample, position, business.MODES[(sample + position) % 3])
                for scenario in scenarios for sample in range(3) for position in range(3)]
    for row, identity in zip(value['samples'], expected, strict=True):
        require(type(row) is dict and type(row.get('sample')) is int
                and type(row.get('position')) is int
                and (row.get('scenario'), row['sample'], row['position'], row.get('mode')) == identity
                and row.get('cold_reopen_equal') is True and row.get('errors') == [],
                'ARCHITECTURE_ORIGINAL_NATIVE_INVARIANTS_REQUIRED')
    # Keep the original libtest predicate separate from the stronger business gate.
    result = {'native_invariants_passed': True, 'samples': 18, 'business_reader': None,
              'business_reader_failure': None, 'business_acceptance_is_separate': True}
    try:
        result['business_reader'] = business.validate_report(path)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['business_reader_failure'] = type(error).__name__ + ':' + str(error)
    after, _ = history.file_observation(path, business.REPORT_LIMIT)
    require(after == observed, 'ARCHITECTURE_REPORT_CHANGED_DURING_READ')
    return result, observed


def execution(out: Path) -> dict:
    spec = configuration(out)
    write_new(out / 'execution-start.json', {'schema': EXECUTION_SCHEMA, 'passed': False})
    result = {'schema': EXECUTION_SCHEMA, **spec, 'job': None,
              'source_before': None, 'source_after': None, 'binary_before': None,
              'binary_after': None, 'cli_binary_before': None, 'cli_binary_after': None,
              'process': None, 'log': None, 'named_execution': None,
              'report': None, 'report_file': None, 'preparation_sha256': None,
              'failures': [], 'passed': False, 'nested_cargo_invoked': False,
              'native_execution_authenticated': False, 'runtime_limits_or_deadlines_changed': False}
    prepared = None
    try:
        result['job'] = history.job_identity()
        result['source_before'] = source_identity(spec['target'])
        prepared = validate_preparation(out)
        result['preparation_sha256'] = history.load_object(out / 'preparation.json')[1]['sha256']
        binary = Path(prepared['binary']['path'])
        result['binary_before'] = parent_binary(prepared['parent_pid'], binary)
        if spec['cli_required']:
            result['cli_binary_before'] = elf_observation(Path(prepared['cli_binary']['path']))
        environment = dict(os.environ)
        environment[CHILD] = spec['target'] + '::' + spec['selector']
        if spec['cli_required']:
            environment['TRNM_PUBLIC_FIXTURE_CLI_BINARY'] = prepared['cli_binary']['path']
        if spec['architecture_report_required']:
            path = native_output(out)
            require(str(path) == prepared['native_output'], 'ARCHITECTURE_NATIVE_OUTPUT_CHANGED')
            environment['TRNM_ARCHITECTURE_COMPARE_DIR'] = str(path)
        command = native_command(binary, spec['selector'])
        result['process'] = run_native_process(command, out / 'native.log', environment=environment,
            supervisors=prepared['supervisors'], timeout_seconds=spec['timeout_seconds'],
            cwd=Path(prepared['native_cwd']['path']))
        require(native_process_succeeded(result['process'], command, spec['timeout_seconds'],
                                          prepared['supervisors'], prepared['native_cwd']['path']),
                'PUBLIC_FIXTURE_NATIVE_PROCESS_REQUIRED')
    except BaseException as error:
        result['failures'].append(type(error).__name__ + ':' + str(error))
    finally:
        def observe(action):
            try:
                action()
            except BaseException as error:
                result['failures'].append(type(error).__name__ + ':' + str(error))

        def source_after():
            result['source_after'] = source_identity(spec['target'])
            require(result['source_before'] == result['source_after'], 'PUBLIC_FIXTURE_SOURCE_CHANGED')

        def binary_after():
            if prepared is not None:
                result['binary_after'] = parent_binary(prepared['parent_pid'], Path(prepared['binary']['path']))
                require(result['binary_before'] == result['binary_after'], 'PUBLIC_FIXTURE_ELF_CHANGED')
                if spec['cli_required']:
                    result['cli_binary_after'] = elf_observation(Path(prepared['cli_binary']['path']))
                    require(result['cli_binary_before'] == result['cli_binary_after'], 'PUBLIC_FIXTURE_CLI_CHANGED')

        def log_after():
            result['log'], raw = history.file_observation(out / 'native.log', history.LOG_LIMIT, retain=True)
            result['named_execution'] = validate_named_test(raw.decode('utf-8').splitlines(), spec['selector'])

        def report_after():
            if prepared is not None and spec['architecture_report_required']:
                result['report'], result['report_file'] = report_observation(Path(prepared['native_output']) / 'report.json')

        for action in (source_after, binary_after, log_after, report_after):
            observe(action)
        result['passed'] = not result['failures'] and result['process'] is not None
        write_new(out / 'manifest.json', result)
    return result


def bind_execution(prepared: dict, out: Path) -> dict:
    spec = configuration(out)
    require(validate_preparation(out) == prepared, 'PUBLIC_FIXTURE_PREPARATION_CHANGED')
    result, manifest = history.load_object(out / 'manifest.json')
    require(result.get('schema') == EXECUTION_SCHEMA
            and all(result.get(key) == value for key, value in spec.items())
            and result.get('job') == history.job_identity() and result.get('passed') is True
            and result.get('failures') == [] and result.get('nested_cargo_invoked') is False
            and result.get('native_execution_authenticated') is False
            and result.get('runtime_limits_or_deadlines_changed') is False,
            'PUBLIC_FIXTURE_EXACT_EXECUTION_REQUIRED')
    require(result.get('preparation_sha256') == history.load_object(out / 'preparation.json')[1]['sha256']
            and prepared['source_before'] == result.get('source_before') == result.get('source_after')
            and prepared['binary'] == result.get('binary_before') == result.get('binary_after')
            and prepared['cli_binary'] == result.get('cli_binary_before') == result.get('cli_binary_after'),
            'PUBLIC_FIXTURE_SOURCE_ELF_BINDING')
    command = native_command(Path(prepared['binary']['path']), spec['selector'])
    require(native_process_succeeded(result.get('process') or {}, command, spec['timeout_seconds'],
                                      prepared['supervisors'], prepared['native_cwd']['path']),
            'PUBLIC_FIXTURE_NATIVE_PROCESS_REQUIRED')
    log, raw = history.file_observation(out / 'native.log', history.LOG_LIMIT, retain=True)
    require(log == result.get('log') and validate_named_test(raw.decode('utf-8').splitlines(), spec['selector'])
            == result.get('named_execution'), 'PUBLIC_FIXTURE_NATIVE_LOG_CHANGED')
    binding = {'schema': 'trnm-ci-public-fixture-current-elf-binding-v1',
               'source_commit': prepared['source_before']['commit'], 'target': spec['target'],
               'selector': spec['selector'], 'binary_sha256': prepared['binary']['sha256'],
               'cli_binary_sha256': prepared['cli_binary']['sha256'] if prepared['cli_binary'] else None,
               'manifest_sha256': manifest['sha256'], 'performance_acceptance': False}
    if spec['architecture_report_required']:
        report, report_file = report_observation(Path(prepared['native_output']) / 'report.json')
        require(report == result.get('report') and report_file == result.get('report_file'),
                'ARCHITECTURE_NATIVE_REPORT_CHANGED')
        binding.update(report_sha256=report_file['sha256'], samples=18,
                       business_reader_passed=report['business_reader'] is not None,
                       business_reader_failure=report['business_reader_failure'])
    else:
        require(result.get('report') is None and result.get('report_file') is None,
                'PUBLIC_FIXTURE_UNDECLARED_REPORT')
    return binding


def launch(out: Path, binary: Path, pid: int, *, target: str, selector: str,
           cli_binary: Path | None) -> dict:
    prepared = prepare(out, binary, pid, target=target, selector=selector, cli_binary=cli_binary)
    require(prepared['completed'], 'PUBLIC_FIXTURE_PREPARATION_FAILED')
    import run_from_zero_host as host
    command = ['python3', SCRIPT, '--out', str(out)]
    result = {'schema': 'trnm-ci-public-fixture-host-launch-v1', 'passed': False,
              'host_exit': None, 'binding': None, 'failures': []}
    try:
        with (out / 'launcher.log').open('x') as stream, contextlib.redirect_stdout(stream):
            result['host_exit'] = host.outer(command)
        controller, _ = history.load_object(out.with_name(out.name + '-host') / 'controller-result.json')
        require(result['host_exit'] == 0 and controller.get('passed') is True
                and controller.get('command_argv') == command, 'PUBLIC_FIXTURE_HOST_EXECUTION_REQUIRED')
        result['binding'] = bind_execution(prepared, out)
        result['passed'] = True
    except BaseException as error:
        result['failures'].append(type(error).__name__ + ':' + str(error))
    finally:
        write_new(out / 'launch.json', result)
    return result


class FixtureSignal(Exception):
    pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--launch', action='store_true')
    parser.add_argument('--target')
    parser.add_argument('--selector')
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--cli-binary', type=Path)
    parser.add_argument('--parent-pid', type=int)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()

    def interrupted(number, _frame):
        raise FixtureSignal(str(number))

    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        require((args.binary is not None and args.parent_pid is not None
                 and args.target is not None and args.selector is not None) if args.launch
                else all(value is None for value in (args.binary, args.parent_pid, args.target,
                                                      args.selector, args.cli_binary)),
                'PUBLIC_FIXTURE_EXACT_ARGUMENTS')
        result = launch(args.out, args.binary, args.parent_pid, target=args.target,
                        selector=args.selector, cli_binary=args.cli_binary) if args.launch else execution(args.out)
        print(json.dumps({'schema': result['schema'], 'passed': result['passed'],
                          'failures': result['failures'], 'receipt': str(args.out)}))
        return 0 if result['passed'] else 1
    except (OSError, ValueError, KeyError, TypeError, FixtureSignal) as error:
        print(json.dumps({'passed': False, 'failure': type(error).__name__ + ':' + str(error)}))
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == '__main__':
    raise SystemExit(main())
