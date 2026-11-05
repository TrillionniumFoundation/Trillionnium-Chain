"""Bounded offline native child I/O; only the process group created here is reaped.

Not a sandbox: the installed executable is a trusted local input. Output and elapsed
budgets protect the calling owner from accidental/malicious pipe overproduction.
"""
from __future__ import annotations
import os,selectors,signal,subprocess,time
from dataclasses import dataclass

@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: bytes
    stderr: bytes


def run_bounded(argv, data, *, timeout=30.0, stdout_limit=32*1024*1024, stderr_limit=65536):
    if not argv or not isinstance(data,bytes) or timeout<=0:
        raise ValueError('NATIVE_PROCESS_ARGUMENT')
    if any(type(n)is not int or n<0 for n in [stdout_limit,stderr_limit]):
        raise ValueError('NATIVE_PROCESS_LIMIT')
    try:
        child=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,start_new_session=True)
    except OSError as error:
        raise ValueError('NATIVE_EXECUTOR_UNAVAILABLE')from error
    buffers={'stdout':bytearray(),'stderr':bytearray()}
    limits={'stdout':stdout_limit,'stderr':stderr_limit}
    deadline=time.monotonic()+timeout;position=0;completed=False
    selector=selectors.DefaultSelector()
    streams=[child.stdin,child.stdout,child.stderr]
    try:
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
    finally:
        selector.close()
        # Reap our session only, including an inherited-pipe child on timeout/failure.
        if not completed:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        for stream in streams:
            if not stream.closed:stream.close()
        child.wait()
