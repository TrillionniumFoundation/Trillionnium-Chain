"""Qualification-only absolute execution and single-deadline process cleanup."""
from __future__ import annotations
from pathlib import Path
import ctypes
import errno
import os
import signal
import subprocess
import time

POLICY = 'absolute-execution-single-group-cleanup-v1'
CLEANUP_SECONDS = 3.0


def subreaper():
    """Adopt and reap owned orphan descendants instead of relying on init."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    before = ctypes.c_int()
    if libc.prctl(37, ctypes.addressof(before), 0, 0, 0) != 0 or libc.prctl(36, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    after = ctypes.c_int()
    if libc.prctl(37, ctypes.addressof(after), 0, 0, 0) != 0 or after.value != 1:
        raise RuntimeError('child subreaper was not enabled')
    return {'previous': before.value, 'active': after.value}


def group_exists(pgid):
    assert type(pgid) is int and pgid > 1
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def reap_group(pgid, deadline):
    reaped = []
    # A nonblocking waitpid still consumes time. A stream of reapable children
    # must not keep this inner loop outside its caller's one absolute deadline.
    while time.monotonic() < deadline:
        try:
            pid, status = os.waitpid(-pgid, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == 0:
            break
        reaped.append({'pid': pid, 'wait_status': status, 'exit_code': os.waitstatus_to_exitcode(status)})
    return reaped


def cleanup(process, record, stdout, stderr):
    started = time.monotonic()
    deadline = started + CLEANUP_SECONDS
    record['cleanup_started_monotonic'] = started
    record['cleanup_deadline_monotonic'] = deadline
    if process.poll() is not None:
        record['adopted_reaped'].extend(reap_group(process.pid, deadline))
    alive = group_exists(process.pid)
    record['descendants_outlived_leader'] = bool(not record['timed_out'] and process.returncode is not None and alive)
    if alive and time.monotonic() < deadline:
        attempt = {'signal': int(signal.SIGKILL), 'monotonic': time.monotonic(), 'errno': 0}
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError as error:
            attempt['errno'] = error.errno
        record['killpg_attempts'].append(attempt)
    stream_failed = False
    while time.monotonic() < deadline:
        if not record['streams_complete'] and not stream_failed:
            try:
                stdout, stderr = process.communicate(timeout=max(0, deadline - time.monotonic()))
                record['streams_complete'] = True
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b'', error.stderr or b''
                break
            except OSError as error:
                record['stream_error'] = {'type': type(error).__name__, 'errno': error.errno}
                stream_failed = True
        if process.poll() is not None:
            record['adopted_reaped'].extend(reap_group(process.pid, deadline))
            record['direct_child_reaped'] = True
        record['group_absent'] = not group_exists(process.pid)
        if record['direct_child_reaped'] and record['group_absent']:
            record['cleanup_complete'] = record['streams_complete']
            break
        time.sleep(min(0.005, max(0, deadline - time.monotonic())))
    finished = time.monotonic()
    record.update(cleanup_finished_monotonic=finished, cleanup_seconds=finished - started,
                  exit_code=process.returncode)
    if finished > deadline:
        record['cleanup_complete'] = False
    return stdout, stderr


def run(argv, *, cwd, data=b'', environment=None, execution_seconds=240):
    """Execute once, then share one independent three-second cleanup deadline.

    The group receives at most one SIGKILL. An incomplete cleanup is a failure,
    with no unbounded wait or second cleanup budget. Native observations use at
    most 240 seconds; the unchanged original Cargo aggregate has its own budget.
    """
    assert isinstance(data, bytes)
    assert type(execution_seconds) in (int, float) and 0 < execution_seconds <= 1200
    command = list(map(str, argv))
    working = str(Path(cwd))
    record = {'schema': 'trnm.pq.process-supervision.v1', 'policy': POLICY,
              'argv': command, 'cwd': working, 'execution_limit_seconds': execution_seconds,
              'cleanup_limit_seconds': CLEANUP_SECONDS, 'start_new_session': True,
              'environment_overridden': environment is not None,
              'pid': None, 'pgid': None, 'session_id': None, 'exit_code': None,
              'timed_out': False, 'outcome': 'launch-error', 'killpg_attempts': [],
              'adopted_reaped': [], 'direct_child_reaped': False, 'group_absent': False,
              'descendants_outlived_leader': False, 'streams_complete': False,
              'cleanup_complete': False, 'launch_error': None, 'execution_error': None}
    stdout, stderr = b'', b''
    process = None
    started = time.monotonic()
    record['started_monotonic'] = started
    record['execution_deadline_monotonic'] = started + execution_seconds
    try:
        record['subreaper'] = subreaper()
        process = subprocess.Popen(command, cwd=working, env=environment, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        record.update(pid=process.pid, pgid=os.getpgid(process.pid), session_id=os.getsid(process.pid))
        if record['pgid'] != process.pid or record['session_id'] != process.pid:
            raise RuntimeError('child did not enter its own process group and session')
        remaining = max(0, record['execution_deadline_monotonic'] - time.monotonic())
        try:
            stdout, stderr = process.communicate(input=data, timeout=remaining)
            record['streams_complete'] = True
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            record['timed_out'] = True
    except BaseException as error:
        detail = {'type': type(error).__name__, 'errno': getattr(error, 'errno', None), 'message': str(error)}
        record['launch_error' if process is None else 'execution_error'] = detail
    finally:
        finished = time.monotonic()
        record.update(execution_finished_monotonic=finished, execution_seconds=finished - started)
        if finished > record['execution_deadline_monotonic']:
            record['timed_out'] = True
        if process is None:
            record.update(cleanup_started_monotonic=finished, cleanup_deadline_monotonic=finished + CLEANUP_SECONDS,
                          cleanup_finished_monotonic=finished, cleanup_seconds=0.0)
        else:
            try:
                stdout, stderr = cleanup(process, record, stdout, stderr)
            finally:
                # Pipe close does not wait for a child. Do not enter a Popen
                # context manager or invoke an unbounded wait after the deadline.
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            pass
            if not record['cleanup_complete']:
                record['outcome'] = 'cleanup-incomplete'
            elif record['execution_error'] is not None:
                record['outcome'] = 'execution-error'
            elif record['timed_out']:
                record['outcome'] = 'timeout'
            elif record['descendants_outlived_leader']:
                record['outcome'] = 'descendants-outlived-leader'
            elif process.returncode != 0:
                record['outcome'] = 'exit-nonzero'
            else:
                record['outcome'] = 'success'
        record['seconds'] = time.monotonic() - started
    return {'stdout': stdout, 'stderr': stderr, 'receipt': record}
