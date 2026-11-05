"""Bounded offline native child I/O; only the process group created here is reaped.

Not a sandbox: the installed executable is a trusted local input. Output and elapsed
budgets protect the calling owner from accidental/malicious pipe overproduction.
"""
from __future__ import annotations
import math,os,selectors,signal,subprocess,time
from dataclasses import dataclass

@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: bytes
    stderr: bytes


class ProcessFailure(ValueError):
    """A failed exchange, not an executable success or an execution receipt.

    Retain only bounded observed prefixes. A zero child exit can still accompany
    NATIVE_STDIN_INCOMPLETE; callers must not treat returncode alone as success.
    """
    def __init__(self, code, *, returncode, stdout, stderr, stdin_written,
                 stdout_truncated=False, stderr_truncated=False):
        super().__init__(code)
        self.returncode=returncode
        self.stdout=stdout
        self.stderr=stderr
        self.stdin_written=stdin_written
        self.stdout_truncated=stdout_truncated
        self.stderr_truncated=stderr_truncated


def run_bounded(argv, data, *, timeout=30.0, stdout_limit=32*1024*1024,
                stderr_limit=65536, cwd=None, env=None):
    if not argv or not isinstance(data,bytes) or type(timeout) not in (int,float):
        raise ValueError('NATIVE_PROCESS_ARGUMENT')
    try:timeout=float(timeout)
    except OverflowError as error:raise ValueError('NATIVE_PROCESS_ARGUMENT') from error
    if not math.isfinite(timeout) or timeout<=0:
        raise ValueError('NATIVE_PROCESS_ARGUMENT')
    if any(type(n)is not int or n<0 for n in [stdout_limit,stderr_limit]):
        raise ValueError('NATIVE_PROCESS_LIMIT')
    deadline=time.monotonic()+timeout
    try:
        child=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,start_new_session=True,cwd=cwd,env=env)
    except OSError as error:
        raise ValueError('NATIVE_EXECUTOR_UNAVAILABLE')from error
    buffers={'stdout':bytearray(),'stderr':bytearray()}
    limits={'stdout':stdout_limit,'stderr':stderr_limit}
    position=0;completed=False;failure=None
    selector=None
    streams=[child.stdin,child.stdout,child.stderr]
    try:
        selector=selectors.DefaultSelector()
        for stream in streams:os.set_blocking(stream.fileno(),False)
        selector.register(child.stdout,selectors.EVENT_READ,'stdout')
        selector.register(child.stderr,selectors.EVENT_READ,'stderr')
        if data:selector.register(child.stdin,selectors.EVENT_WRITE,'stdin')
        else:child.stdin.close()
        while selector.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0:raise ValueError('NATIVE_EXECUTOR_TIMEOUT')
            for key,_ in selector.select(min(remaining,.05)):
                stream=key.fileobj;name=key.data
                if name=='stdin':
                    try:position+=os.write(stream.fileno(),memoryview(data)[position:position+65536])
                    except BrokenPipeError:
                        # A closed pipe is not proof that the unsent suffix arrived.
                        # Continue draining diagnostics so an ordinary nonzero
                        # rejection keeps its original exit code and stderr.
                        selector.unregister(stream);stream.close();continue
                    except BlockingIOError:continue
                    if position==len(data):selector.unregister(stream);stream.close()
                else:
                    # One extra byte suffices to prove the cap was crossed.
                    want=min(65536,limits[name]-len(buffers[name])+1)
                    try:chunk=os.read(stream.fileno(),want)
                    except BlockingIOError:continue
                    if not chunk:selector.unregister(stream);stream.close();continue
                    buffers[name].extend(chunk)
                    if len(buffers[name])>limits[name]:raise ValueError('NATIVE_'+name.upper()+'_LIMIT')
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ValueError('NATIVE_EXECUTOR_TIMEOUT')
        try:returncode=child.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:raise ValueError('NATIVE_EXECUTOR_TIMEOUT')from error
        if returncode==0 and position!=len(data):
            raise ValueError('NATIVE_STDIN_INCOMPLETE')
        completed=True
        return Result(returncode,bytes(buffers['stdout']),bytes(buffers['stderr']))
    except (ValueError,OSError) as error:
        failure=error
    finally:
        if selector is not None:selector.close()
        # Reap our session only, including an inherited-pipe child on timeout/failure.
        if not completed:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        for stream in streams:
            if not stream.closed:stream.close()
        child.wait()
    # Observe cleanup's actual exit while preserving the primary exchange
    # failure. Spawn/kill/wait and filesystem operations are not hard real-time
    # guarantees; this owner retains its existing POSIX cleanup boundary.
    code=str(failure) if isinstance(failure,ValueError) else 'NATIVE_EXECUTOR_IO'
    raise ProcessFailure(code,returncode=child.returncode,
        stdout=bytes(buffers['stdout'][:stdout_limit]),
        stderr=bytes(buffers['stderr'][:stderr_limit]),stdin_written=position,
        stdout_truncated=len(buffers['stdout'])>stdout_limit,
        stderr_truncated=len(buffers['stderr'])>stderr_limit) from failure
