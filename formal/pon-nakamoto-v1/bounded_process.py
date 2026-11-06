"""Bounded offline native child I/O; only the process group created here is signalled.

Not a sandbox: the installed executable is a trusted local input. Output and elapsed
budgets protect the calling owner from accidental/malicious pipe overproduction.
The owner must be the sole reaper of its direct child. POSIX waitid/WNOWAIT keeps
the group leader reserved until group cleanup on success as well as failure.
Descendants that create another session are outside this owner, not sandboxed.
"""
from __future__ import annotations
import math,os,selectors,signal,subprocess,sys,time
from dataclasses import dataclass

@dataclass(frozen=True)
class Usage:
    """wait4 for this child and descendants it reaped, not a cgroup total."""
    pid: int
    user_seconds: float
    system_seconds: float
    max_single_process_rss_bytes: int


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: bytes
    stderr: bytes
    usage: Usage | None = None


class ProcessFailure(ValueError):
    """A failed exchange, not an executable success or an execution receipt.

    Retain only bounded observed prefixes. A zero child exit can still accompany
    NATIVE_STDIN_INCOMPLETE; callers must not treat returncode alone as success.
    """
    def __init__(self, code, *, returncode, stdout, stderr, stdin_written,
                 stdout_truncated=False, stderr_truncated=False, usage=None):
        super().__init__(code)
        self.returncode=returncode
        self.stdout=stdout
        self.stderr=stderr
        self.stdin_written=stdin_written
        self.stdout_truncated=stdout_truncated
        self.stderr_truncated=stderr_truncated
        self.usage=usage


def _wait_without_reaping(child, deadline):
    """Observe exit under the original deadline without releasing the group ID."""
    while True:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ValueError('NATIVE_EXECUTOR_TIMEOUT')
        try:
            status=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        except InterruptedError:
            continue
        if status is not None:
            if status.si_code==os.CLD_EXITED:return status.si_status
            if status.si_code in (os.CLD_KILLED,os.CLD_DUMPED):return -status.si_status
            raise ValueError('NATIVE_EXECUTOR_WAIT_STATUS')
        time.sleep(min(remaining,.005))


def _darwin_only_exited_leader(child):
    """Disambiguate Darwin's zombie-only EPERM without waiving live denial.

    XNU killpg1 excludes zombies and can return EPERM for our unreaped leader.
    Its proc_listpids(PROC_PGRP_ONLY=2) walks both live and zombie lists under
    proc_list_lock. An eight-byte buffer returning exactly our single PID is
    therefore a complete singleton census, not a truncated list or size hint.
    Require WNOWAIT exit evidence first; zero/error/extra/foreign entries refuse.
    This trusts the system libproc/kernel and exclusive reaping, as the owner
    already trusts POSIX process isolation. It neither signals discovered PIDs
    nor manages descendants which left this session.
    """
    if sys.platform!='darwin' or child.returncode is not None:return False
    try:
        status=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        if (status is None or status.si_pid!=child.pid or
                status.si_code not in (os.CLD_EXITED,os.CLD_KILLED,os.CLD_DUMPED)):
            return False
        import ctypes
        library=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
        census=library.proc_listpids
        census.argtypes=[ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_int]
        census.restype=ctypes.c_int
        pids=(ctypes.c_int*2)()
        ctypes.set_errno(0)
        size=census(2,child.pid,pids,ctypes.sizeof(pids))
        return (size==ctypes.sizeof(ctypes.c_int) and pids[0]==child.pid
                and ctypes.get_errno()==0)
    except (OSError,AttributeError,ValueError):
        return False


def run_bounded(argv, data, *, timeout=30.0, stdout_limit=32*1024*1024,
                stderr_limit=65536, cwd=None, env=None, pass_fds=(), collect_usage=False,
                absolute_deadline=None):
    if not argv or not isinstance(data,bytes) or type(timeout) not in (int,float):
        raise ValueError('NATIVE_PROCESS_ARGUMENT')
    try:timeout=float(timeout)
    except OverflowError as error:raise ValueError('NATIVE_PROCESS_ARGUMENT') from error
    if not math.isfinite(timeout) or timeout<=0:
        raise ValueError('NATIVE_PROCESS_ARGUMENT')
    if absolute_deadline is not None:
        if type(absolute_deadline)not in (int,float):raise ValueError('NATIVE_PROCESS_ARGUMENT')
        try:absolute_deadline=float(absolute_deadline)
        except OverflowError as error:raise ValueError('NATIVE_PROCESS_ARGUMENT') from error
        if not math.isfinite(absolute_deadline):raise ValueError('NATIVE_PROCESS_ARGUMENT')
    if any(type(n)is not int or n<0 for n in [stdout_limit,stderr_limit]):
        raise ValueError('NATIVE_PROCESS_LIMIT')
    if (type(collect_usage)is not bool or type(pass_fds)not in (tuple,list)
            or any(type(fd)is not int or fd<0 for fd in pass_fds)
            or len(set(pass_fds))!=len(pass_fds)):
        raise ValueError('NATIVE_PROCESS_ARGUMENT')
    if not all(hasattr(os,name) for name in ('waitid','P_PID','WEXITED','WNOHANG','WNOWAIT','CLD_EXITED','CLD_KILLED','CLD_DUMPED','killpg')):
        raise ValueError('NATIVE_PROCESS_PLATFORM')
    if collect_usage and not hasattr(os,'wait4'):
        raise ValueError('NATIVE_PROCESS_PLATFORM')
    deadline=time.monotonic()+timeout
    if absolute_deadline is not None:
        # A scheduling pause before this call must not restart the caller's
        # original budget. This distinct error proves no Popen was attempted.
        deadline=min(deadline,absolute_deadline)
        if time.monotonic()>=deadline:
            raise ValueError('NATIVE_EXECUTOR_DEADLINE_BEFORE_SPAWN')
    try:
        child=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,start_new_session=True,cwd=cwd,env=env,
                               pass_fds=pass_fds)
    except OSError as error:
        raise ValueError('NATIVE_EXECUTOR_UNAVAILABLE')from error
    buffers={'stdout':bytearray(),'stderr':bytearray()}
    limits={'stdout':stdout_limit,'stderr':stderr_limit}
    position=0;failure=None;usage=None;returncode=None
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
        returncode=_wait_without_reaping(child,deadline)
        if returncode==0 and position!=len(data):
            raise ValueError('NATIVE_STDIN_INCOMPLETE')
    except (ValueError,OSError) as error:
        failure=error
    finally:
        # No wait/poll may reap the leader before the last group signal: an
        # exited leader still reserves its PID/PGID. A successful exit does not
        # prove that descendants which closed all three pipes have stopped.
        try:
            if selector is not None:selector.close()
        finally:
            try:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                except PermissionError:
                    if not _darwin_only_exited_leader(child):raise
            finally:
                try:
                    for stream in streams:
                        if not stream.closed:stream.close()
                finally:
                    if collect_usage:
                        # Keep the same signal-before-reap ownership. This is
                        # opt-in so existing owners keep their old interface.
                        # No getrusage(RUSAGE_CHILDREN) delta: concurrent owners
                        # must not charge another worker's process time.
                        while True:
                            try:
                                pid,status,found=os.wait4(child.pid,0)
                                break
                            except InterruptedError:
                                continue
                        child.returncode=os.waitstatus_to_exitcode(status)
                        usage=Usage(pid,found.ru_utime,found.ru_stime,
                            found.ru_maxrss*(1 if sys.platform=='darwin' else 1024))
                    else:
                        child.wait()
    # Observe cleanup's actual exit while preserving the primary exchange
    # failure. Spawn/kill/wait and filesystem operations are not hard real-time
    # guarantees; this owner retains its existing POSIX cleanup boundary.
    if failure is None:
        return Result(returncode,bytes(buffers['stdout']),bytes(buffers['stderr']),usage)
    code=str(failure) if isinstance(failure,ValueError) else 'NATIVE_EXECUTOR_IO'
    raise ProcessFailure(code,returncode=child.returncode,
        stdout=bytes(buffers['stdout'][:stdout_limit]),
        stderr=bytes(buffers['stderr'][:stderr_limit]),stdin_written=position,
        stdout_truncated=len(buffers['stdout'])>stdout_limit,
        stderr_truncated=len(buffers['stderr'])>stderr_limit,usage=usage) from failure
