#!/usr/bin/env python3
"""One 30-second, exact-source engineering observation; no campaign acceptance."""
from __future__ import annotations

import time

STARTED = time.monotonic()

import argparse
from collections import Counter
import ctypes
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import stat
import subprocess
import sys

from run_rust_attribute_cases_v1 import NEW, RETAINED, TIMEOUT_MESSAGE

ROOT = Path(__file__).resolve().parents[2]
PARENT = '9af9de721543bcf279f62278568cbff939d0aaf0'
PARENT_REPORT_BLOB = 'be7b893faeee8c537b95472976a5a9308eb0b0ca'
PARENT_REPORT_SHA256 = '70941e508e48ef2f82553482b39b2b104bede82edfd9963e0d7e8f23343ff8bb'
REPORT_PATH = 'scripts/ci/report_module_evidence.py'
CAPSULE_PATHS = (
    REPORT_PATH, 'scripts/ci/test_applicability.py',
    'scripts/ci/check_applicability.py', 'scripts/ci/check_invariant_evidence.py',
)
PINS = {
    REPORT_PATH: '124355cf97d9951c9da55bff1f5716885e4998176337b01ba762bf470fd03473',
    'scripts/ci/test_applicability.py': '8faf23740860418c99cfb59a86364537581def4900831fd0feb32a334e696c4d',
    'scripts/ci/check_applicability.py': '1651c8adf3f86bb5302d84709192bee5d2703650be02e8d365c2a2f4142fa3f2',
    'scripts/ci/check_invariant_evidence.py': '1d21d001c3de0305e4718de76daf79c9f74a7cfc66522484b1db3e76c409a6ff',
    'scripts/ci/project_boundary.py': '5845b10022c1ce625e864c38a9c69ba1982a1d1efad1dc934cc06f3d8dafda47',
    'scripts/project-preflight.sh': '08645a9c6c8ab5cd9a92aa24e1c19fb71e7330d28e379b805d8e3f81ce8ede1f',
    'scripts/ci/verify_ci_source.py': '0ddfd07719eae98913348c82b06d3e4522d721c353d9b01d6deac0dfda619946',
    'scripts/ci/run_rust_attribute_cases_v1.py': 'ab39ac3f67971d25104cb4f347ba4b6a89710a87f86ce2b482140bc557a73c4d',
}
WALL_CAP = 30.0
COMMAND_END = STARTED + 28.0
CLEANUP_END = STARTED + 29.5
MAX_LOG_BYTES = 4 * 1024 * 1024
CANCELLED = None


def require(ok, message):
    if not ok:
        raise ValueError(message)


def cancel(signum, _frame):
    global CANCELLED
    CANCELLED = signum


def cpu():
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'self_user_seconds': own.ru_utime, 'self_system_seconds': own.ru_stime,
            'reaped_children_user_seconds': children.ru_utime,
            'reaped_children_system_seconds': children.ru_stime}


def difference(after, before):
    return {name: after[name] - before[name] for name in before}


def remaining():
    require(CANCELLED is None, 'scope cancelled by signal ' + str(CANCELLED))
    value = COMMAND_END - time.monotonic()
    require(value > 0, 'shared command deadline exhausted')
    return value


def raw_file(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                'nonregular or oversized observation input: ' + str(path))
        value = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(value) == before.st_size and len(value) <= limit
            and (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
            'observation input changed during reading: ' + str(path))
    return value


def fingerprint(path: Path, limit: int = MAX_LOG_BYTES):
    value = raw_file(path, limit)
    return {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}


def enable_owned_subreaper():
    require(sys.platform == 'linux' and sys.version_info >= (3, 11), 'Linux Python3.11+ required')
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
            'the runner must be the sole default child reaper')
    require(all(hasattr(os, name) for name in ('waitid', 'WNOWAIT', 'WEXITED', 'WNOHANG', 'P_PID')),
            'non-reaping child observation unavailable')
    require(shutil.rmtree.avoids_symlink_attacks, 'descriptor-based fixture cleanup required')
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(36, 1, 0, 0, 0) == 0, 'cannot own orphaned descendants')
    actual = ctypes.c_int()
    require(libc.prctl(37, ctypes.byref(actual), 0, 0, 0) == 0 and actual.value == 1,
            'subreaper state was not established')


def observe(process):
    # No poll/wait/communicate here: the group leader must retain its PID until
    # the final group signal, including a leader which exited successfully.
    return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


def clean_group(process):
    result = {'leader_pid': process.pid, 'last_group_signal_before_reap': False,
              'leader_reaped': False, 'adopted_children_reaped': [], 'resolved': False}
    try:
        observe(process)  # ECHILD means ownership was lost: never signal that PID.
    except ChildProcessError:
        result['error'] = 'leader wait ownership lost; no signal sent'
        return result
    try:
        os.killpg(process.pid, signal.SIGKILL)
        result['last_group_signal_before_reap'] = True
    except ProcessLookupError:
        result['group_absent_at_last_signal'] = True
    except OSError as error:
        result['signal_error'] = {'type': type(error).__name__, 'message': str(error)}
    try:
        while time.monotonic() < CLEANUP_END:
            if observe(process) is not None:
                process.wait(timeout=max(0.001, CLEANUP_END - time.monotonic()))
                result.update(leader_reaped=True, leader_returncode=process.returncode)
                break
            time.sleep(min(0.005, max(0, CLEANUP_END - time.monotonic())))
        if not result['leader_reaped']:
            result['error'] = 'leader cleanup unresolved at shared deadline'
            return result
        # Linux subreaper adoption keeps a killed unittest leader's regex child
        # owned here. Reap only this known group, and never signal after reaping.
        while time.monotonic() < CLEANUP_END:
            try:
                pid, status = os.waitpid(-process.pid, os.WNOHANG)
            except ChildProcessError:
                break
            if pid:
                result['adopted_children_reaped'].append({'pid': pid, 'wait_status': status})
            else:
                time.sleep(min(0.005, max(0, CLEANUP_END - time.monotonic())))
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            result['group_absent_after_reap'] = True
        except OSError as error:
            result['presence_error'] = {'type': type(error).__name__, 'message': str(error)}
        else:
            result['group_absent_after_reap'] = False
        result['resolved'] = (result.get('group_absent_after_reap') is True
                              and 'signal_error' not in result and 'presence_error' not in result)
    except (OSError, subprocess.TimeoutExpired) as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    return result


class Scope:
    def __init__(self, output, source):
        self.output = output
        self.report = {
            'schema': 'trnm-rust-attribute-engineering-v1', 'status': 'FAIL', 'complete': False,
            'scope': 'selected Python source-binding owner only; no native, scanner or E1-E6 qualification',
            'expected_head': source, 'expected_parent': PARENT, 'commands': [],
            'shared_wall_cap_seconds': WALL_CAP, 'command_reserve_seconds': 2.0,
            'baseline_actual_failures_preserved': False, 'fixed_all_named_passed': False,
            'cleanup_resolved': False, 'source_consistent': False,
            'native_qualified': False, 'security_qualified': False, 'production_activation': False,
            'runtime': {'python': sys.version, 'executable': sys.executable,
                        'platform': sys.platform, 'run_id': os.environ.get('GITHUB_RUN_ID'),
                        'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT')},
            'cpu_scope': 'owner lifetime plus reaped children/descendants, not whole-host CPU',
            'costs_nested_in_inclusive_scope': True,
        }
        self.persist()

    def persist(self):
        self.report['elapsed_seconds'] = time.monotonic() - STARTED
        self.report['process_lifetime_cpu'] = cpu()
        temporary = self.output / 'summary.tmp'
        temporary.write_text(json.dumps(self.report, indent=2, sort_keys=True) + '\n')
        os.replace(temporary, self.output / 'summary.json')

    def command(self, name, argv, *, cwd=ROOT, env=None):
        remaining()
        started, before_cpu = time.monotonic(), cpu()
        out, err = self.output / (name + '.stdout.log'), self.output / (name + '.stderr.log')
        row = {'name': name, 'argv': argv, 'cwd': str(cwd), 'status': 'RUNNING',
               'exit_code': None, 'timed_out': False, 'output_limit_exceeded': False,
               'cleanup': None}
        self.report['commands'].append(row)
        self.persist()
        process = None
        try:
            with out.open('xb') as stdout, err.open('xb') as stderr:
                environment = dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_NO_REPLACE_OBJECTS='1',
                                   GIT_TERMINAL_PROMPT='0', PYTHONDONTWRITEBYTECODE='1')
                if env is not None:
                    environment.update(env)
                process = subprocess.Popen(argv, cwd=cwd, env=environment,
                                           stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                           start_new_session=True)
                row['leader_pid'] = process.pid
                self.persist()
                while True:
                    observed = observe(process)
                    if observed is not None:
                        row['observed_terminal'] = {'code': observed.si_code, 'status': observed.si_status}
                        break
                    if CANCELLED is not None or time.monotonic() >= COMMAND_END:
                        row.update(timed_out=True, cancellation_signal=CANCELLED)
                        break
                    if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > MAX_LOG_BYTES:
                        row['output_limit_exceeded'] = True
                        break
                    time.sleep(min(0.01, max(0, COMMAND_END - time.monotonic())))
        except BaseException as error:
            row['error'] = {'type': type(error).__name__, 'message': str(error)}
        finally:
            if process is not None:
                try:
                    row['cleanup'] = clean_group(process)
                    row['exit_code'] = process.returncode
                except BaseException as error:
                    row['cleanup'] = {'resolved': False, 'error': str(error)}
            for label, path in [('stdout', out), ('stderr', err)]:
                if path.exists():
                    try:
                        row[label] = {'path': path.name, **fingerprint(path)}
                    except (OSError, ValueError) as error:
                        row[label] = {'path': path.name, 'retention_error': str(error)}
                        row['output_limit_exceeded'] = True
            if sum(row.get(label, {}).get('bytes', 0) for label in ('stdout', 'stderr')) > MAX_LOG_BYTES:
                row['output_limit_exceeded'] = True
            row['elapsed_seconds'] = time.monotonic() - started
            row['cpu'] = difference(cpu(), before_cpu)
            row['status'] = 'COMPLETE' if row['cleanup'] and row['cleanup'].get('resolved') else 'INCOMPLETE'
            self.persist()
        require(row['status'] == 'COMPLETE' and not row['timed_out']
                and not row['output_limit_exceeded'] and 'error' not in row,
                'owned command incomplete: ' + name)
        return row

    def success(self, name, argv, **kwargs):
        row = self.command(name, argv, **kwargs)
        require(row['exit_code'] == 0, 'command failed: ' + name)
        return row


def pin_inputs():
    result = {}
    for path, expected in PINS.items():
        row = fingerprint(ROOT / path, 1024 * 1024)
        require(row['sha256'] == expected, 'reviewed input differs: ' + path)
        result[path] = row
    # Self/metadata are bound by the whole raw worktree verifier and the actual
    # commit. Record them without a circular hard-coded self hash.
    for path in ('scripts/ci/run_rust_attribute_engineering_v1.py',
                 '.github/workflows/rust-attribute-owner-engineering-v1.yml'):
        result[path] = fingerprint(ROOT / path, 1024 * 1024)
    return result


def capsule_snapshot(root):
    actual = {str(path.relative_to(root)) for path in root.rglob('*') if path.is_file()}
    require(actual == set(CAPSULE_PATHS), 'capsule file roster changed')
    return {path: fingerprint(root / path) for path in CAPSULE_PATHS}


def check_controls(report, kind, exit_code):
    expected = list(NEW[-2:] if kind == 'baseline' else NEW + RETAINED)
    require(report['schema'] == 'trnm-rust-attribute-named-controls-v1'
            and report['kind'] == kind and report['complete'] is True
            and report['expected_ids'] == expected and not report['loader_errors']
            and Counter(report['registered_ids']) == Counter(expected)
            and Counter(report['started_ids']) == Counter(expected)
            and type(report['tests_run']) is int and report['tests_run'] == len(expected)
            and not report['errors'] and not report['skipped']
            and not report['expected_failures'] and not report['unexpected_successes'],
            'incomplete or different named control observation')
    if kind == 'baseline':
        require(exit_code == 1 and report['status'] == 'FAIL' and not report['success_ids']
                and Counter(row[0] for row in report['failures']) == Counter(expected)
                and Counter(row['id'] for row in report['failure_details']) == Counter(expected),
                'baseline must retain exactly two actual failures')
        for row in report['failure_details']:
            require(row['exception_type'] == 'AssertionError' and row['message'] == TIMEOUT_MESSAGE
                    and row['timeout_context'] is True and row['timeout_seconds'] == 3.0
                    and row['timeout_stdout_hex'] == b'BOUND-ENTERED\n'.hex()
                    and row['timeout_stderr_empty'] is True
                    and row['timeout_stderr_hex'] in (None, '')
                    and isinstance(row['child_argv'], list)
                    and row['child_argv'][1:4] == ['-I', '-B', '-c'],
                    'baseline failure was not the reviewed communicate timeout')
    else:
        require(exit_code == 0 and report['status'] == 'PASS'
                and Counter(report['success_ids']) == Counter(expected)
                and not report['failures'] and not report['failure_details'],
                'fixed owner did not pass every exact control')


def execute(output, source):
    require(output.is_absolute() and not output.resolve().is_relative_to(ROOT.resolve()),
            'output must be a fresh directory outside source')
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    scope = Scope(output, source)
    fixture = output.with_name(output.name + '-fixtures')
    fixture_fd = parent_fd = None
    fixture_owned = False
    try:
        enable_owned_subreaper()
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, cancel)
        require(os.environ.get('GITHUB_RUN_ATTEMPT') == '1', 'only the original workflow attempt is permitted')
        require(len(source) == 40 and all(c in '0123456789abcdef' for c in source), 'noncanonical head')
        scope.report['inputs_before'] = pin_inputs()
        git = ['git', '--no-replace-objects']
        scope.success('commit', git + ['cat-file', 'commit', source])
        commit = raw_file(output / 'commit.stdout.log', 1024 * 1024)
        require(hashlib.sha1(b'commit ' + str(len(commit)).encode() + b'\0' + commit).hexdigest() == source,
                'raw commit object differs from head')
        parents = [line[7:].decode() for line in commit.split(b'\n\n', 1)[0].splitlines()
                   if line.startswith(b'parent ')]
        require(parents == [PARENT], 'candidate must have the reviewed actual9af sole parent')
        scope.report['raw_commit_sha256'] = hashlib.sha256(commit).hexdigest()
        scope.success('source-before', [sys.executable, '-B', 'scripts/ci/verify_ci_source.py',
                      '--kind', 'head', '--expected-head', source, '--output', str(output / 'source-before.json')])
        scope.report['source_before'] = json.loads(raw_file(output / 'source-before.json', 65536))
        scope.success('preflight', ['bash', 'scripts/project-preflight.sh', '--audit'])
        scope.success('parent-report', git + ['cat-file', 'blob', PARENT + ':' + REPORT_PATH])
        baseline = raw_file(output / 'parent-report.stdout.log', 1024 * 1024)
        require(len(baseline) == 24277 and hashlib.sha256(baseline).hexdigest() == PARENT_REPORT_SHA256
                and hashlib.sha1(b'blob ' + str(len(baseline)).encode() + b'\0' + baseline).hexdigest()
                == PARENT_REPORT_BLOB, 'parent report differs from the original vulnerable owner')
        scope.report['parent_report'] = fingerprint(output / 'parent-report.stdout.log')
        parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        os.mkdir(fixture.name, 0o700, dir_fd=parent_fd)
        fixture_owned = True
        fixture_fd = os.open(fixture.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        fixture_identity = os.fstat(fixture_fd)
        scope.report['fixture_owner'] = {'path': str(fixture), 'device': fixture_identity.st_dev,
                                         'inode': fixture_identity.st_ino}
        scope.report['capsules'] = {}
        for kind in ('baseline', 'fixed'):
            remaining()
            root = output / 'capsules' / kind
            (root / 'scripts/ci').mkdir(parents=True, exist_ok=False)
            for path in CAPSULE_PATHS:
                data = baseline if kind == 'baseline' and path == REPORT_PATH else raw_file(ROOT / path, 1024 * 1024)
                (root / path).write_bytes(data)
            before = capsule_snapshot(root)
            command = scope.command(kind + '-controls', [sys.executable, '-I', '-B',
                                    str(ROOT / 'scripts/ci/run_rust_attribute_cases_v1.py'),
                                    '--root', str(root), '--kind', kind,
                                    '--output', str(output / (kind + '-controls.json'))],
                                    cwd=root, env={'TMPDIR': str(fixture)})
            observed = json.loads(raw_file(output / (kind + '-controls.json'), 1024 * 1024))
            after = capsule_snapshot(root)
            require(before == after, 'selected capsule source changed')
            scope.report['capsules'][kind] = {'before': before, 'after': after,
                                             'full_checkout': False, 'observation': observed}
            check_controls(observed, kind, command['exit_code'])
            scope.report['baseline_actual_failures_preserved' if kind == 'baseline' else 'fixed_all_named_passed'] = True
            scope.persist()
        scope.success('source-after', [sys.executable, '-B', 'scripts/ci/verify_ci_source.py',
                      '--kind', 'head', '--expected-head', source, '--output', str(output / 'source-after.json')])
        scope.report['source_after'] = json.loads(raw_file(output / 'source-after.json', 65536))
        scope.report['inputs_after'] = pin_inputs()
        require(scope.report['source_before'] == scope.report['source_after']
                and scope.report['source_after']['tracked_worktree_verified'] is True
                and scope.report['inputs_before'] == scope.report['inputs_after'], 'source changed')
        scope.report['source_consistent'] = True
    except BaseException as error:
        scope.report['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        processes_closed = all(row.get('cleanup', {}).get('resolved') is True
                               for row in scope.report['commands'] if row.get('leader_pid') is not None)
        fixture_closed = not fixture_owned
        if fixture_owned and fixture_fd is not None and processes_closed:
            try:
                original = os.fstat(fixture_fd)
                current = os.stat(fixture.name, dir_fd=parent_fd, follow_symlinks=False)
                require((original.st_dev, original.st_ino, original.st_mode)
                        == (current.st_dev, current.st_ino, current.st_mode), 'fixture owner changed')
                shutil.rmtree(fixture.name, dir_fd=parent_fd)
                fixture_closed = True
            except BaseException as error:
                scope.report['fixture_cleanup_error'] = str(error)
        for fd in (fixture_fd, parent_fd):
            if fd is not None:
                os.close(fd)
        scope.report['cleanup_resolved'] = processes_closed and fixture_closed
        elapsed = time.monotonic() - STARTED
        passed = (not scope.report.get('error') and scope.report['source_consistent']
                  and scope.report['baseline_actual_failures_preserved']
                  and scope.report['fixed_all_named_passed'] and scope.report['cleanup_resolved']
                  and CANCELLED is None and elapsed <= WALL_CAP)
        scope.report.update(status='PASS_SELECTED_OWNER_CONTROLS' if passed else 'FAIL', complete=True,
                            within_shared_wall_cap=elapsed <= WALL_CAP,
                            cancellation_signal=CANCELLED,
                            cleanup_contract='Known descendants remain in the created session/group; no arbitrary escaped-session or OS hard-deadline guarantee.')
        scope.persist()
        if time.monotonic() - STARTED > WALL_CAP:
            scope.report.update(status='FAIL', within_shared_wall_cap=False)
            scope.persist()
    print(json.dumps({'status': scope.report['status'], 'summary': str(output / 'summary.json')}))
    return 0 if scope.report['status'] == 'PASS_SELECTED_OWNER_CONTROLS' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-head', required=True)
    args = parser.parse_args()
    raise SystemExit(execute(args.output, args.expected_head))
