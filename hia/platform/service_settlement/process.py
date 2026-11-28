"""Source-bound process capture using the unchanged canonical owned collector.

Large original fixture output is written to owned regular files. The collector
still owns every descendant, the one execution deadline and one cleanup grace.
This module is qualification tooling, never part of the product runtime.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
COLLECTOR = HERE.parents[2] / 'scripts/w1_owned_process_collector_v1.py'
COLLECTOR_SHA = '01accf26eecd5b0bdecd94909d328cafc028d7d2bcf387ec9ecbcab533b146cc'


def identity(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n')


def collector():
    assert identity(COLLECTOR.read_bytes())['sha256'] == COLLECTOR_SHA
    spec = importlib.util.spec_from_file_location('settlement_owned_collector', COLLECTOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def execute(path, digest):
    assert __debug__ and not os.environ.get('PYTHONOPTIMIZE')
    raw = path.read_bytes()
    assert not path.is_symlink() and identity(raw)['sha256'] == digest
    request = json.loads(raw)
    assert set(request) == {'argv', 'cwd', 'environment', 'executable', 'executable_identity',
                            'stdin', 'stdin_identity', 'stdout', 'stderr'}
    executable = Path(request['executable'])
    fd = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and os.pread(fd, 4, 0) == b'\x7fELF'
        assert collector().fd_digest(fd) == request['executable_identity']['sha256']
        assert os.fstat(fd).st_size == request['executable_identity']['bytes']
        source = os.open(request['stdin'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            stamp = os.fstat(source)
            assert stat.S_ISREG(stamp.st_mode) and stamp.st_size == request['stdin_identity']['bytes']
            assert collector().fd_digest(source) == request['stdin_identity']['sha256']
            os.lseek(source, 0, os.SEEK_SET)
            os.dup2(source, 0)
        finally:
            os.close(source)
        for number, label in ((1, 'stdout'), (2, 'stderr')):
            output = os.open(request[label], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                os.dup2(output, number)
            finally:
                os.close(output)
        os.chdir(request['cwd'])
        os.execve(fd, request['argv'], request['environment'])
    finally:
        os.close(fd)


def run(directory, argv, *, cwd, environment, data=b'', seconds=240, expected_executable=None):
    assert __debug__ and type(seconds) is int and 0 < seconds <= 240
    assert isinstance(data, bytes)
    directory = Path(directory).resolve()
    directory.mkdir(mode=0o700)
    owned = collector()
    started = time.monotonic_ns()
    deadline = started + seconds * 1_000_000_000
    cleanup_deadline = deadline + 3_000_000_000
    python = Path(sys.executable).resolve(strict=True)
    command = list(map(str, argv))
    selected = shutil.which(command[0], path=environment.get('PATH'))
    assert selected, 'Actual executable unavailable'
    executable = Path(selected).resolve(strict=True)
    assert executable.is_file() and not executable.is_symlink()
    assert executable.read_bytes()[:4] == b'\x7fELF'
    executable_identity = identity(executable.read_bytes())
    if expected_executable is not None:
        assert executable_identity == expected_executable
    (directory / 'stdin.raw').write_bytes(data)
    spec = {'argv': command, 'cwd': str(cwd), 'environment': dict(environment),
            'executable': str(executable), 'executable_identity': executable_identity,
            'stdin': str(directory / 'stdin.raw'), 'stdin_identity': identity(data),
            'stdout': str(directory / 'stdout.raw'), 'stderr': str(directory / 'stderr.raw')}
    encoded = (json.dumps(spec, sort_keys=True, indent=2) + '\n').encode()
    (directory / 'command.json').write_bytes(encoded)
    boot = owned.boot_id()
    launch = [str(python), '-B', str(COLLECTOR), '--out', str(directory / 'owned'),
              '--cwd', str(cwd), '--deadline-monotonic-ns', str(deadline), '--deadline-boot-id', boot,
              '--cleanup-grace-seconds', '3', '--executable-sha256', identity(python.read_bytes())['sha256'],
              '--max-processes', '4096', '--max-log-bytes', str(16 * 1024 * 1024),
              '--env', 'PATH=/usr/bin:/bin', '--env', 'PYTHONDONTWRITEBYTECODE=1',
              '--', str(python), '-B', str(Path(__file__).resolve()), '--execute', str(directory / 'command.json'),
              '--sha256', identity(encoded)['sha256']]
    row = {'schema': 'trnm.service-settlement.owned-process.v1', 'status': 'INCOMPLETE',
           'argv': command, 'cwd': str(cwd), 'environment': dict(environment),
           'execution_deadline_seconds': seconds, 'cleanup_deadline_seconds': 3,
           'original_deadline_monotonic_ns': deadline, 'original_boot_id': boot,
           'collector_argv': launch, 'collector_sha256': COLLECTOR_SHA,
           'command': identity(encoded), 'stdin': identity(data), 'started': False,
           'exit_code': None, 'timed_out': False, 'cleanup_complete': False, 'cleanup_errors': []}
    save(directory / 'request.json', row)
    save(directory / 'receipt.json', row)
    child = None
    try:
        with (directory / 'collector.stdout.raw').open('xb') as stdout, (directory / 'collector.stderr.raw').open('xb') as stderr:
            child = subprocess.Popen(launch, cwd=cwd, env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'},
                                     stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
            row['started'] = True
            row['collector_exit_code'] = child.wait(timeout=max(0, (cleanup_deadline - time.monotonic_ns()) / 1e9))
            finished = time.monotonic_ns()
        intent_raw = (directory / 'owned/intent.json').read_bytes()
        intent = owned.read_json(directory / 'owned/intent.json')
        assert intent['command'] == launch[launch.index('--') + 1:]
        assert intent['original_boot_id'] == boot and intent['original_deadline_monotonic_ns'] == deadline
        assert intent['cleanup_grace_seconds'] == 3 and intent['max_process_records'] == 4096
        result = owned.read_result(directory / 'owned', row['collector_exit_code'], observed_boot_id=boot,
                                  observed_completed_monotonic_ns=finished,
                                  expected_intent_sha256=identity(intent_raw)['sha256'])
        row['collector_readback'] = result
        row['intent'] = identity(intent_raw)
        row['observed_completed_monotonic_ns'] = finished
        row['exit_code'] = result['result']['root_returncode']
        row['timed_out'] = result['result']['cause'] == 'original-deadline'
        row['cleanup_complete'] = result['collector_wait_domain_reaped'] is True
        assert result['deadline_qualified'] is True and result['command_success'] is True
        assert all(s['eof'] and not s['truncated'] for s in result['result']['streams'].values())
        assert row['cleanup_complete'] and not row['timed_out'] and row['exit_code'] == 0
        assert identity(executable.read_bytes()) == spec['executable_identity']
        assert identity((directory / 'command.json').read_bytes()) == identity(encoded)
        row['status'] = 'PASS'
    except BaseException:
        row.update(status='FAIL', exception=traceback.format_exc())
    finally:
        if child is not None and child.poll() is None:
            try:
                child.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass
            except BaseException as error:
                row['cleanup_errors'].append(repr(error))
            try:
                row['collector_exit_code'] = child.wait(timeout=max(0, (cleanup_deadline - time.monotonic_ns()) / 1e9))
            except BaseException as error:
                row['cleanup_errors'].append(repr(error))
                try:
                    child.kill()
                except ProcessLookupError:
                    pass
                row['cleanup_errors'].append('Collector terminal/reaping state is UNKNOWN')
        if row['cleanup_errors']:
            row['status'] = 'FAIL'
        row['elapsed_ns'] = time.monotonic_ns() - started
        for label in ('stdout', 'stderr', 'collector.stdout', 'collector.stderr'):
            path = directory / (label + '.raw')
            regular = path.exists() and not path.is_symlink() and stat.S_ISREG(path.stat().st_mode) and path.stat().st_nlink == 1
            row[label] = identity(path.read_bytes()) if regular else None
            if not regular:
                row['status'] = 'FAIL'
                row['cleanup_errors'].append('Actual raw output missing or nonregular: ' + label)
        save(directory / 'receipt.json', row)
    return row


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--execute', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    execute(args.execute, args.sha256)
