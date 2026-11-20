"""Stop the actual daemon while its tracer remains alive to reap it."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import signal
import time


def process_identity(pid):
    raw = (Path('/proc') / str(pid) / 'stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    return {'pid': pid, 'parent': int(fields[1]), 'start_ticks': int(fields[19])}


def finish_traced(child, executable, *, terminal=False):
    started = time.monotonic_ns()
    deadline = started + (4 if terminal else 3) * 1_000_000_000
    result = {'mode': 'natural-terminal' if terminal else 'tracee-pidfd-then-tracer-wait',
              'started_monotonic_ns': started, 'deadline_monotonic_ns': deadline,
              'tracer_pid': child.pid, 'tracee': None, 'signal': None}
    if not terminal:
        while child.poll() is None:
            children = Path('/proc') / str(child.pid) / 'task' / str(child.pid) / 'children'
            try:
                pids = [int(value) for value in children.read_text().split()]
            except FileNotFoundError:
                pids = []
            if pids:
                if len(pids) != 1:
                    raise ValueError('The traced daemon must have exactly one direct tracee')
                pid = pids[0]
                before = process_identity(pid)
                if before['parent'] != child.pid:
                    raise ValueError('Tracee does not belong to the actual tracer')
                descriptor = os.pidfd_open(pid)
                try:
                    with (Path('/proc') / str(pid) / 'exe').open('rb') as stream:
                        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                    with Path(executable).open('rb') as stream:
                        expected = hashlib.file_digest(stream, 'sha256').hexdigest()
                    if digest != expected or process_identity(pid) != before:
                        raise ValueError('Actual tracee executable or process identity changed')
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                    result.update(tracee=before, executable_sha256=digest, signal=signal.SIGKILL)
                finally:
                    os.close(descriptor)
                break
            if time.monotonic_ns() >= deadline:
                raise TimeoutError('Tracer did not expose or reap its actual tracee')
            time.sleep(.002)
    code = child.wait(timeout=max(0, (deadline - time.monotonic_ns()) / 1_000_000_000))
    result.update(returncode=code, completed_monotonic_ns=time.monotonic_ns())
    if result['completed_monotonic_ns'] > deadline:
        raise TimeoutError('Actual traced process exceeded its one terminal deadline')
    return code, result
