"""Private Linux qualification controller for children created by this test.

This module never attaches to an existing process. Crash cuts send SIGKILL only
after a selected real syscall returns successfully. Explicit EIO controls skip
exactly one selected syscall and replace its ENOSYS return; those controls are
reported as injected faults. Neither mode is a power-failure simulation.
"""
from pathlib import Path
import ctypes
import os
import signal
import struct
import time
import traceback

import hashlib,json
def identity(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def need(value,message):
    if not value:raise AssertionError(message)
def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.ptrace.restype = ctypes.c_long
LIBC.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
MAX = (1 << 64) - 1


class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
        "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp",
        "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs")]


def ptrace(request, pid, address=0, data=0):
    ctypes.set_errno(0)
    result = LIBC.ptrace(request, pid, ctypes.c_void_p(address),
                         ctypes.c_void_p(data) if isinstance(data, int) else data)
    error = ctypes.get_errno()
    if result == -1 and error:
        raise OSError(error, os.strerror(error), (request, pid))
    return result


def registers(pid):
    value = Registers()
    ptrace(12, pid, 0, ctypes.byref(value))
    return value


def cstring(pid, address):
    result = bytearray()
    for offset in range(0, 4096, 8):
        raw = (ptrace(2, pid, address + offset) & MAX).to_bytes(8, "little")
        if b"\0" in raw:
            result.extend(raw.split(b"\0", 1)[0])
            return os.fsdecode(bytes(result))
        result.extend(raw)
    raise ValueError("Owned test child path exceeds the bounded Linux pathname fixture")


def run(executable, payload, directory, *, storage, target, inject=False):
    executable, directory, storage = Path(executable).absolute(), Path(directory).absolute(), Path(storage).absolute()
    directory.mkdir(mode=0o700)
    (directory / "stdin.raw").write_bytes(payload)
    before = identity(executable.read_bytes())
    input_file = (directory / "stdin.raw").open("rb")
    stdout = (directory / "stdout.raw").open("xb")
    stderr = (directory / "stderr.raw").open("xb")
    report = {"schema": "trnm.payload-owned-process-trace.v1", "status": "FAIL",
              "executable": str(executable), "executable_before": before,
              "target": target, "fault_injected": inject, "power_failure_claimed": False,
              "storage": str(storage), "input": identity(payload), "events": [], "actions": []}
    child = os.fork()
    if child == 0:
        try:
            os.dup2(input_file.fileno(), 0)
            os.dup2(stdout.fileno(), 1)
            os.dup2(stderr.fileno(), 2)
            ptrace(0, 0)
            os.kill(os.getpid(), signal.SIGSTOP)
            os.execve(str(executable), [str(executable)], os.environ)
        except BaseException:
            os.write(2, traceback.format_exc().encode())
            os._exit(124)
    input_file.close()
    stdout.close()
    stderr.close()
    report["pid"] = child
    started = time.monotonic_ns()
    pending = None
    alive, fired = True, False
    saw_record, published = False, False
    counter = 0

    def event(kind, **fields):
        nonlocal counter
        counter += 1
        row = {"sequence": counter, "kind": kind, **fields}
        report["events"].append(row)
        return row

    def label(row):
        nr,name=row['nr'],row.get('fd_path','')
        phase='admit' if saw_record else 'open'
        if nr==1 and name==str(storage/'journal') and row['args'][2]==380:
            raw=b''.join((ptrace(2,child,row['args'][1]+i)&MAX).to_bytes(8,'little') for i in (0,8,16))
            index=int.from_bytes(raw[12:20],'big')
            need(index in (0,1),'Crash fixture must write actual genesis or first admission')
            row['record_index']=index
            return ('admit' if index else 'open')+'-journal-write'
        if nr==74 and name==str(storage/'journal'):return phase+'-journal-fsync'
        if nr==74 and name==str(storage):
            return phase+('-published-directory-fsync' if published else '-directory-fsync')
        if '..journal.head-v1.tmp-' in name:
            label={1:'head-write',74:'head-fsync'}.get(nr)
            return phase+'-'+label if label else None
        if nr==82 and row.get('to')==str(storage/'.journal.head-v1'):return phase+'-head-rename'
        return None

    def deadline(signum, frame):
        raise TimeoutError("Owned trace exceeded its 30 second supervisor budget")

    old_handler = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(30)
    failure = None
    try:
        pid, status = os.waitpid(child, 0)
        event("initial-wait", wait_status=status,
              exit_code=os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,
              signal=os.WTERMSIG(status) if os.WIFSIGNALED(status) else None)
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            alive = False
        need(pid == child and os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP,
             "Missing owned TRACEME initial stop")
        ptrace(0x4200, child, 0, 1 | 16 | 0x100000)
        ptrace(24, child)
        while alive:
            pid, status = os.waitpid(child, 0)
            need(pid == child, "Observed another process identity")
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                report["exit_code"] = os.WEXITSTATUS(status) if os.WIFEXITED(status) else None
                report["signal"] = os.WTERMSIG(status) if os.WIFSIGNALED(status) else None
                event("terminal", exit_code=report["exit_code"], signal=report["signal"])
                alive = False
                break
            need(os.WIFSTOPPED(status), "Unexpected private trace status")
            stop, ptrace_event = os.WSTOPSIG(status), status >> 16
            if ptrace_event:
                need(ptrace_event == 4, "Unrequested child ptrace event")
                actual = Path("/proc/" + str(child) + "/exe").resolve(strict=True)
                need(actual == executable.resolve(strict=True), "The owned child executed another binary")
                event("exec", actual=str(actual))
                ptrace(24, child)
                continue
            if stop == (signal.SIGTRAP | 0x80):
                data = ctypes.create_string_buffer(128)
                ptrace(0x420e, child, 128, ctypes.byref(data))
                raw = bytes(data)
                operation, arch = raw[0], struct.unpack_from("<I", raw, 4)[0]
                need(arch == 0xc000003e and operation in (1, 2), "Unexpected syscall architecture")
                if operation == 1:
                    need(pending is None, "Overlapping syscall entry")
                    nr = struct.unpack_from("<Q", raw, 24)[0]
                    args = list(struct.unpack_from("<6Q", raw, 32))
                    pending = event("entry", nr=nr, args=args)
                    if nr in (0, 1, 3, 5, 8, 17, 73, 74, 75, 77):
                        try:
                            pending["fd_path"] = os.readlink("/proc/" + str(child) + "/fd/" + str(args[0]))
                        except OSError:
                            pass
                    if nr == 82:
                        pending["from"], pending["to"] = cstring(child, args[0]), cstring(child, args[1])
                    selected = label(pending)
                    if selected:
                        pending["storage_stage"] = selected
                    if selected == target and inject and not fired:
                        r = registers(child)
                        need(r.orig_rax == nr, "Selected original syscall register differs")
                        r.orig_rax = MAX
                        ptrace(13, child, 0, ctypes.byref(r))
                        need(registers(child).orig_rax == MAX, "Fault skip did not read back")
                        pending["injected_eio"] = True
                else:
                    need(pending is not None, "Syscall exit lacks actual entry")
                    kernel_result = struct.unpack_from("<q", raw, 24)[0]
                    result = kernel_result
                    if pending.get("injected_eio"):
                        need(kernel_result == -38, "Skipped syscall did not produce ENOSYS")
                        r = registers(child)
                        r.rax = (-5) & MAX
                        ptrace(13, child, 0, ctypes.byref(r))
                        need(registers(child).rax == (-5) & MAX, "Injected EIO did not read back")
                        result, fired = -5, True
                        report["actions"].append({"kind": "injected-EIO", "entry": pending["sequence"],
                                                  "stage": target, "kernel_result": -38, "result": -5})
                    row = event("exit", entry=pending["sequence"], nr=pending["nr"],
                                result=result, kernel_result=kernel_result,
                                storage_stage=pending.get("storage_stage"))
                    stage = pending.get("storage_stage")
                    if result > 0 and stage in ("open-journal-write", "admit-journal-write"):
                        saw_record = stage.startswith("admit-")
                        published = False
                    if result == 0 and stage in ("open-head-rename", "admit-head-rename"):
                        published = True
                    if stage == target and not inject and not fired:
                        need(result >= 0, "Requested crash cut syscall failed before the cut")
                        fired = True
                        report["actions"].append({"kind": "SIGKILL-after-real-syscall", "entry": pending["sequence"],
                                                  "exit": row["sequence"], "stage": target})
                        os.kill(child, signal.SIGKILL)
                        pending = None
                        continue
                    pending = None
                ptrace(24, child)
                continue
            event("signal", signal=stop)
            ptrace(24, child, 0, stop)
        need(fired and len(report["actions"]) == 1, "Requested durability boundary was never reached")
        need((inject and report["exit_code"] == 0 and report["signal"] is None)
             or (not inject and report["signal"] == signal.SIGKILL), "Unexpected owned child termination")
    except BaseException:
        failure = traceback.format_exc()
        raise
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
        if alive:
            cleanup_start = time.monotonic_ns()
            cleanup_deadline = cleanup_start + 3_000_000_000
            cleanup_reaped = False
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            while time.monotonic_ns() < cleanup_deadline:
                try:
                    waited, status = os.waitpid(child, os.WNOHANG)
                except ChildProcessError:
                    waited = child
                if waited == child:
                    cleanup_reaped = True
                    break
                time.sleep(min(0.001, max(0, (cleanup_deadline-time.monotonic_ns())/1e9)))
            report["supervisor_cleanup"] = {"signal": "SIGKILL", "windows": 1,
                "limit_seconds": 3, "complete": cleanup_reaped,
                "elapsed_ns": time.monotonic_ns()-cleanup_start}
            if not cleanup_reaped:
                failure = (failure or "") + "Owned trace root not reaped before the only cleanup deadline"
        report["failure"] = failure
        report["executable_after"] = identity(executable.read_bytes())
        report["stdout"] = identity((directory / "stdout.raw").read_bytes())
        report["stderr"] = identity((directory / "stderr.raw").read_bytes())
        report["elapsed_ns"] = time.monotonic_ns() - started
        report["status"] = "PASS" if failure is None and report["executable_after"] == before else "FAIL"
        save(directory / "trace.json", report)
    return report
