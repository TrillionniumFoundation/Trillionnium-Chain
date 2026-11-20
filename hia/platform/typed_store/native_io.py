"""Test-only real Linux descriptors and subprocesses; no production state proxy."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import struct
import subprocess
import threading
import time

from hia.platform.build import sealed_executable, sha256

MAX = (1 << 64) - 1

def file_hash(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1 << 20):
            value.update(block)
    return value.hexdigest()

def read_all(fd: int) -> bytes:
    chunks, position = [], 0
    while block := os.pread(fd, 1 << 20, position):
        chunks.append(block)
        position += len(block)
    return b"".join(chunks)

def sealed_input(raw: bytes | Path, label: str, sealed: bool = True) -> int:
    fd = os.memfd_create(label, os.MFD_ALLOW_SEALING)
    try:
        if isinstance(raw, Path):
            with raw.open("rb") as stream:
                while block := stream.read(1 << 20):
                    cursor = 0
                    while cursor < len(block):
                        count = os.write(fd, block[cursor:])
                        if count <= 0:
                            raise OSError("short input capture")
                        cursor += count
        else:
            cursor = 0
            while cursor < len(raw):
                count = os.write(fd, raw[cursor:])
                if count <= 0:
                    raise OSError("short input capture")
                cursor += count
        if sealed:
            fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), 15)
        return fd
    except BaseException:
        os.close(fd)
        raise

def fd_hash(fd: int) -> str:
    value, offset = hashlib.sha256(), 0
    while block := os.pread(fd, 1 << 20, offset):
        value.update(block)
        offset += len(block)
    return value.hexdigest()

def read_exact(fd: int, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        block = os.read(fd, count - len(result))
        if not block:
            break
        result.extend(block)
    return bytes(result)

def run(executable: bytes, directory: Path, base: bytes | Path, delta: bytes | Path, *,
        detach=False, root=True, profile=0, cancel=None, cancel_class=2, token=0x12345678,
        observe=True, kill=None, capability=None, bootstrap_mutator=None,
        timeout=45, retain_bytes=True, file_limit=None, lose_receipt=False, stop_file=None) -> dict:
    directory.mkdir(mode=0o700)
    out_path = directory / "staging.kv"
    fds = []
    def keep(fd):
        fds.append(fd)
        return fd
    fd_base = keep(sealed_input(base, "typed-base", capability != "unsealed-base"))
    fd_delta = keep(sealed_input(delta, "typed-delta", capability != "unsealed-delta"))
    fd_output = keep(os.open(out_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600))
    if capability == "output-mode":
        os.fchmod(fd_output, 0o640)
    if capability == "output-link":
        os.link(out_path, directory / "linked.kv")
    if capability == "output-nonempty":
        os.write(fd_output, b"untouched")
    if capability == "output-append":
        fcntl.fcntl(fd_output, fcntl.F_SETFL, os.O_APPEND)
    if capability == "output-readonly":
        fd_output = keep(os.open(out_path, os.O_RDONLY))
    if capability == "output-locked":
        lock = keep(os.open(out_path, os.O_RDWR))
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if capability == "output-alias-base":
        fd_output = keep(os.dup(fd_base))
    er, ew = os.pipe()
    cr, cw = os.pipe()
    fds.extend((er, ew, cr, cw))
    gw, gr = (ew, cr) if observe else (MAX, MAX)
    if capability == "gw-output-alias":
        gw = keep(os.dup(fd_output))
    elif capability == "gr-output-alias":
        gr = keep(os.dup(fd_output))
    elif capability == "gw-base-alias":
        gw = keep(os.dup(fd_base))
    elif capability == "gr-delta-alias":
        gr = keep(os.dup(fd_delta))
    elif capability == "gw-read-end":
        gw = er
    elif capability == "gr-write-end":
        gr = cw
    elif capability == "gate-self-loop":
        gr = er
    elif capability == "gw-separate-regular":
        gw = keep(os.open(directory / "gate-regular", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600))
    elif capability == "gr-separate-regular":
        gr = keep(os.open(directory / "gate-regular", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600))
    elif capability == "gate-rdwr-fifo":
        fifo = directory / "gate.fifo"
        os.mkfifo(fifo, 0o600)
        gw = keep(os.open(fifo, os.O_RDWR | os.O_NONBLOCK))
    elif capability == "gate-opath-fifo":
        fifo = directory / "gate.fifo"
        os.mkfifo(fifo, 0o600)
        gr = keep(os.open(fifo, os.O_PATH))
    fd_exe = keep(sealed_executable(executable, "typed-staging"))
    before_base, before_delta = fd_hash(fd_base), fd_hash(fd_delta)
    original_output = out_path.read_bytes()
    payload = b"TSTAGE01" + struct.pack("<11Q", fd_base, fd_delta, fd_output,
        int(detach), gw, gr, profile, int(root), 0, 0, 0)
    if bootstrap_mutator is not None:
        payload = bootstrap_mutator(payload)
    (directory / "stdin.raw").write_bytes(payload)
    gate_failure = capability is not None and (capability.startswith(("gw-", "gr-", "gate-")))
    # Historical alias reproduction supplies a real pending cancellation on the
    # real pipe. The fixed kernel must reject before reading or writing any gate.
    if gate_failure:
        os.write(cw, struct.pack("<3Q", 1, cancel_class, token))
    pass_fds = tuple(sorted({fd_exe, fd_base, fd_delta, fd_output} |
        ({gw, gr} if observe else set())))
    def limit_child():
        if file_limit is not None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    receipt_reader = None
    if lose_receipt:
        receipt_reader, receipt_writer = os.pipe()
        os.close(receipt_reader)
        receipt_reader = None
        fds.append(receipt_writer)
        stdout_target = receipt_writer
    else:
        stdout_target = subprocess.PIPE
    start = time.monotonic_ns()
    process = subprocess.Popen(["/proc/self/fd/" + str(fd_exe)], cwd=directory,
        stdin=subprocess.PIPE, stdout=stdout_target, stderr=subprocess.PIPE,
        pass_fds=pass_fds, env={"PATH": ""}, start_new_session=True, umask=0o077,
        preexec_fn=limit_child if file_limit is not None else None)
    (directory / "process-start.json").write_text(json.dumps({"pid": process.pid,
        "process_group": os.getpgid(process.pid), "executable_sha256": sha256(executable),
        "stop_file": None if stop_file is None else str(stop_file)}, sort_keys=True) + "\n")
    # Only the child retains these endpoint copies, so EOF is observable.
    for fd in (ew, cr):
        os.close(fd)
        fds.remove(fd)
    progress, gate_errors, controller_stop = [], [], []
    controller_done = threading.Event()
    def stop_controller():
        try:
            while not controller_done.wait(0.05):
                if Path(stop_file).exists():
                    row = {"requested": True, "pid": process.pid, "signal": "SIGKILL"}
                    controller_stop.append(row)
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                        row["signal_outcome"] = "sent"
                    except ProcessLookupError:
                        row["signal_outcome"] = "already_exited"
                    break
        except BaseException as error:
            gate_errors.append("controller stop: " + repr(error))
    stopper = None
    if stop_file is not None:
        stopper = threading.Thread(target=stop_controller, daemon=True)
        stopper.start()
    def gate():
        try:
            while record := read_exact(er, 32):
                if len(record) != 32 or record[:8] != b"TSPROG01":
                    raise ValueError("invalid physical progress record")
                seq, kind, row = struct.unpack("<3Q", record[8:])
                progress.append([seq, kind, row])
                if seq != len(progress):
                    raise ValueError("nonmonotonic physical progress sequence")
                if kill == seq:
                    if stop_file is None:
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        Path(stop_file).write_text("explicit owned qualification stop\n")
                    break
                cls, value = (cancel_class, token) if cancel == seq else (0, 0)
                os.write(cw, struct.pack("<3Q", seq, cls, value))
        except BrokenPipeError:
            pass
        except BaseException as error:
            gate_errors.append(repr(error))
    thread = None
    if observe and not gate_failure:
        thread = threading.Thread(target=gate, daemon=True)
        thread.start()
    timed_out = False
    try:
        stdout, stderr = process.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate(timeout=3)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            outcome = "sent"
        except ProcessLookupError:
            outcome = "already_exited"
        interrupted_stdout, interrupted_stderr = process.communicate(timeout=3)
        (directory / "interrupted-process.json").write_text(json.dumps({
            "pid": process.pid, "signal": "SIGKILL", "signal_outcome": outcome,
            "exit": process.returncode, "stdout_hex": (interrupted_stdout or b"").hex(),
            "stderr_hex": interrupted_stderr.hex()}, sort_keys=True) + "\n")
        raise
    finally:
        controller_done.set()
        if stopper is not None:
            stopper.join(timeout=1)
    if thread is not None:
        thread.join(timeout=3)
        if thread.is_alive():
            gate_errors.append("physical gate did not reach EOF after child reap")
    stdout = stdout or b""
    output_bytes = out_path.read_bytes() if retain_bytes else None
    same_inputs = (fd_hash(fd_base), fd_hash(fd_delta)) == (before_base, before_delta)
    result = {"exit": process.returncode, "stdout_hex": stdout.hex(), "stderr_hex": stderr.hex(),
        "controller_stop_requested": bool(controller_stop), "controller_stop": controller_stop,
        "timed_out": timed_out, "gate_errors": gate_errors, "progress_records": progress,
        "input_hashes_before": [before_base, before_delta], "inputs_unchanged": same_inputs,
        "output_bytes": out_path.stat().st_size, "output_sha256": file_hash(out_path),
        "output_before_hex": original_output.hex(), "output_path": str(out_path),
        "elapsed_ns": time.monotonic_ns() - start}
    if output_bytes is not None:
        result["output_hex"] = output_bytes.hex()
    if len(stderr) == 56:
        result["diagnostic"] = list(struct.unpack("<7Q", stderr))
    if len(stdout) == 128 and stdout[:8] == b"TSRESULT":
        values = struct.unpack("<5Q", stdout[8:48])
        result["receipt"] = {"kind": values[0], "count": values[1], "output_bytes": values[2],
            "delta_count": values[3], "progresses": values[4], "block_hex": stdout[48:80].hex(),
            "slot": int.from_bytes(stdout[80:88], "little"), "root_hex": stdout[88:120].hex(),
            "reserved": int.from_bytes(stdout[120:128], "little")}
    (directory / "stdout.raw").write_bytes(stdout)
    (directory / "stderr.raw").write_bytes(stderr)
    for fd in reversed(fds):
        try:
            os.close(fd)
        except OSError:
            pass
    return result
