"""Bind an explicitly selected Linux ELF command to one open executable object.

This opt-in observer is for source qualification, not performance measurement.
Hashing is charged to the recorder's elapsed interval. An observation identifies
the kernel's executable file object at an instant; it does not measure process
memory, loaded libraries, models, descendants or later exec transitions. Build
provenance remains an independent obligation. No pathname or argv hash is used
as a substitute when the live executable observation is unavailable.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
SCHEMA = "trnm-pinned-native-process-v1"


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def descriptor_digest(descriptor):
    before = os.fstat(descriptor)
    if (not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111
            or not 0 < before.st_size <= MAX_EXECUTABLE_BYTES):
        raise ValueError("native executable must be a bounded regular executable file")
    value = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        block = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        if not block:
            raise ValueError("native executable truncated during hashing")
        value.update(block)
        offset += len(block)
    if (os.pread(descriptor, 1, offset)
            or fingerprint(os.fstat(descriptor)) != fingerprint(before)):
        raise ValueError("native executable changed during hashing")
    return value.hexdigest(), before


def process_identity(proc_descriptor, expected_pid):
    descriptor = os.open("stat", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                         dir_fd=proc_descriptor)
    try:
        raw = os.read(descriptor, 8193)
    finally:
        os.close(descriptor)
    end = raw.rfind(b") ")
    if (len(raw) > 8192 or not raw.startswith(str(expected_pid).encode() + b" (")
            or end == -1):
        raise ValueError("noncanonical owned-process identity")
    fields = raw[end + 2:].split()
    if len(fields) < 20 or fields[0] in (b"Z", b"X", b"x"):
        raise ValueError("owned process is no longer live")
    parent, start_ticks = int(fields[1]), int(fields[19])
    if parent != os.getpid() or start_ticks <= 0:
        raise ValueError("process is not the recorder's live direct child")
    return {"pid": expected_pid, "parent_pid": parent, "start_ticks": start_ticks}


def observe_executable(pid, pinned_descriptor, expected_sha256):
    """Open only the owned PID's kernel executable link; never a disk fallback."""
    observation_started = time.monotonic_ns()
    proc_descriptor = os.open("/proc/" + str(pid),
                              os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = process_identity(proc_descriptor, pid)
        # Following this one kernel-provided link is intentional. Hold the proc
        # directory and executable descriptors so PID/path reuse cannot retarget
        # the object being hashed after the short live-process observation.
        executable = os.open("exe", os.O_RDONLY | os.O_CLOEXEC,
                             dir_fd=proc_descriptor)
        executable_opened = time.monotonic_ns()
        try:
            link = os.readlink("exe", dir_fd=proc_descriptor)
            after = process_identity(proc_descriptor, pid)
            if before != after:
                raise ValueError("owned process changed during executable observation")
            observed_at = time.monotonic_ns()
            pinned_info = os.fstat(pinned_descriptor)
            if fingerprint(os.fstat(executable)) != fingerprint(pinned_info):
                raise ValueError("kernel executable differs from the pinned dispatch object")
            observed_sha256, info = descriptor_digest(executable)
            if (observed_sha256 != expected_sha256
                    or fingerprint(info) != fingerprint(pinned_info)
                    or fingerprint(os.fstat(pinned_descriptor)) != fingerprint(pinned_info)):
                raise ValueError("kernel executable bytes differ from the explicit pin")
            return {"status": "OBSERVED", "process": before,
                    "observation_started_monotonic_ns": observation_started,
                    "executable_opened_monotonic_ns": executable_opened,
                    "process_binding_finished_monotonic_ns": observed_at,
                    "hash_finished_monotonic_ns": time.monotonic_ns(),
                    "exe_link": link, "sha256": observed_sha256,
                    "device": info.st_dev, "inode": info.st_ino, "bytes": info.st_size}
        finally:
            os.close(executable)
    finally:
        os.close(proc_descriptor)


def run_pinned(command, cwd, stream, expected_sha256):
    """Refuse a bad pin before dispatch, own/reap the child, retain missing data."""
    if sys.platform != "linux" or not Path("/proc/self/fd").is_dir():
        raise ValueError("pinned native observation requires Linux procfs")
    if not re.fullmatch("[0-9a-f]{64}", expected_sha256):
        raise ValueError("native executable pin must be a lowercase SHA-256")
    path = Path(command[0])
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("pinned native command requires an absolute executable path")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        actual_sha256, info = descriptor_digest(descriptor)
        if actual_sha256 != expected_sha256:
            raise ValueError("native executable pin mismatch before dispatch")
        if os.pread(descriptor, 4, 0) != b"\x7fELF":
            raise ValueError("pinned native command requires ELF; no interpreter fallback")
        report = {"schema": SCHEMA, "status": "DISPATCH_PENDING",
                  "requested_path": str(path), "expected_sha256": expected_sha256,
                  "dispatch_object": {"sha256": actual_sha256, "device": info.st_dev,
                                      "inode": info.st_ino, "bytes": info.st_size},
                  "observation": None, "child_reaped": False,
                  "loaded_memory_sha256": None, "libraries_sha256": None,
                  "model_closure_sha256": None, "descendant_execution_verified": False,
                  "entire_lifetime_image_verified": False,
                  "build_provenance_verified_by_observer": False,
                  "performance_measurement": False}
        # Dispatch the descriptor that was actually checked. A later pathname
        # replacement cannot select a different executable for this child.
        with subprocess.Popen(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT,
                              executable="/proc/self/fd/" + str(descriptor),
                              pass_fds=(descriptor,)) as process:
            report["owned_pid"] = process.pid
            try:
                report["observation"] = observe_executable(process.pid, descriptor, expected_sha256)
            except (OSError, ValueError) as error:
                report["observation"] = {"status": "NOT_OBSERVED", "error": str(error)}
            code = process.wait()
        report["child_reaped"] = True
        report["native_exit_code"] = code
        try:
            final_sha256, final_info = descriptor_digest(descriptor)
            report["dispatch_object_after_sha256"] = final_sha256
            stable = (final_sha256 == actual_sha256
                      and fingerprint(final_info) == fingerprint(info))
        except (OSError, ValueError) as error:
            stable = False
            report["dispatch_object_after_error"] = str(error)
        report["status"] = ("PINNED_AND_OBSERVED" if stable
                            and report["observation"]["status"] == "OBSERVED"
                            else "IDENTITY_INCOMPLETE")
        return code, report
    finally:
        os.close(descriptor)
