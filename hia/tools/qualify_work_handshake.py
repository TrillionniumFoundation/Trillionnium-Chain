"""Force both native Work startup interleavings with hardware breakpoints.

The tracee is the exact sealed ELF produced by the actual HIA emitter.  Only
debug registers control scheduling; no instruction, general register, syscall
result, clock, or successful state transition is synthesized.  Separate named
corruption controls write an invalid private handshake word and require refusal.
This finite regression does not qualify live Node/Paid integration or service.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import signal
import struct
import sys
import time
import traceback

from hia.platform.build import sealed_executable
from hia.platform.host_resource.native_io import provision
from hia.platform.work_owner.cases import corpus, require_semantics
from hia.platform.work_owner.native_io import decode

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x400000
MASK = (1 << 64) - 1
WALL = 0x40000000
OPTIONS = 1 | 8 | 16 | 64 | (1 << 20)  # syscall, clone, exec, exit, exitkill
REGISTERS = ('r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi '
             'orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs').split()
DR_BASE = 848  # offsetof(struct user, u_debugreg), Linux x86_64 UAPI
IMPORTS = (
    'hia/tools/qualify_work_handshake.py', 'hia/platform/build.py',
    'hia/platform/host_resource/native_io.py', 'hia/platform/host_resource/cases.py',
    'hia/platform/work_owner/native_io.py', 'hia/platform/work_owner/cases.py',
)
LOOPS = {
    'parent-ready': {'field': 36, 'read': 0x400d78, 'publish': 0x400dd1,
                     'main_break': 0x400d78, 'worker_break': 0x400dd1,
                     'old': '41837c242401741f41837c2424000f851b050000',
                     'new': '418b44242483f801741d85c00f851d0500009090'},
    'worker-go': {'field': 40, 'read': 0x400de4, 'publish': 0x400e87,
                  'main_break': 0x400e87, 'worker_break': 0x400de4,
                  'old': '41837c242801741f41837c2428000f85af040000',
                  'new': '418b44242883f801741d85c00f85b10400009090'},
}
PAID_LOOPS = {
    'parent-ready': {'field': 36, 'read': 0x4012c2, 'publish': 0x40131b,
                     'main_break': 0x4012c2, 'worker_break': 0x40131b,
                     'old': '41837c242401741f41837c2424000f8525060000',
                     'new': '418b44242483f801741d85c00f85270600009090'},
    'worker-go': {'field': 40, 'read': 0x40132e, 'publish': 0x4013d1,
                  'main_break': 0x4013d1, 'worker_break': 0x40132e,
                  'old': '41837c242801741f41837c2428000f85b9050000',
                  'new': '418b44242883f801741d85c00f85bb0500009090'},
}
LAYOUTS = {
    'work-owner-v1': {'loops': LOOPS, 'closed_fd_shift': 40},
    'work-paid-v2': {'loops': PAID_LOOPS, 'closed_fd_shift': 50},
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def binding(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read_file(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), 'Regular nonsymlink input required: ' + str(path))
    return path.read_bytes()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def json_file(path):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'Duplicate JSON field: ' + key)
            result[key] = value
        return result
    return json.loads(read_file(path), object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


class Regs(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in REGISTERS]


class Trace:
    def __init__(self, image, payload, directory, timeout=15):
        self.directory = directory
        self.events = []
        self.raw = {'stdout': bytearray(), 'stderr': bytearray(), 'observer': bytearray()}
        self.active = set()
        self.stopped = set()
        self.exits = {}
        self.deadline = time.monotonic() + timeout
        self.started_ns = time.monotonic_ns()
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.ptrace.restype = ctypes.c_long
        self.libc.ptrace.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
        self.fds = set()
        self.readers = {}
        self.pid = None
        self.worker = None
        self.worker_exit_events = []
        self.code_writes = 0
        self.general_register_writes = 0
        self.private_state_writes = []
        try:
            executable = sealed_executable(image, 'hia-work-handshake-exact-image')
            self.fds.add(executable)
            input_fd = os.memfd_create('hia-work-handshake-input', os.MFD_ALLOW_SEALING)
            self.fds.add(input_fd)
            need(os.write(input_fd, payload) == len(payload), 'Complete request capture')
            fcntl.fcntl(input_fd, 1033, 15)
            out_r, out_w = os.pipe(); err_r, err_w = os.pipe()
            observer_r, observer_w = os.pipe(); ack_r, ack_w = os.pipe()
            self.fds.update((out_r, out_w, err_r, err_w, observer_r, observer_w, ack_r, ack_w))
            self.readers = {out_r: 'stdout', err_r: 'stderr', observer_r: 'observer'}
            for fd in self.readers:
                os.set_blocking(fd, False)
            original = [input_fd, out_w, err_w, observer_w, ack_r, executable]
            high = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 30) for fd in original]
            self.fds.update(high)
            self.events.append({'event': 'captured-sealed-inputs', 'image': binding(image),
                                'stdin': binding(payload), 'image_seals': fcntl.fcntl(executable, 1034),
                                'input_seals': fcntl.fcntl(input_fd, 1034)})
            pid = os.fork()
            if pid == 0:
                try:
                    os.setsid(); os.chdir(directory)
                    for target, source in enumerate(high[:5]):
                        os.dup2(source, target, inheritable=True)
                    os.set_inheritable(high[5], True)
                    for fd in self.fds:
                        if fd not in {0, 1, 2, 3, 4, high[5]}:
                            os.close(fd)
                    ctypes.set_errno(0)
                    if self.libc.ptrace(0, 0, None, None) == -1:
                        raise OSError(ctypes.get_errno(), 'PTRACE_TRACEME')
                    os.kill(os.getpid(), signal.SIGSTOP)
                    path = '/proc/self/fd/' + str(high[5])
                    os.execve(path, [path], {'PATH': ''})
                except BaseException as error:
                    os.write(2, ('tracee setup failure: ' + repr(error) + '\n').encode())
                    os._exit(125)
            self.pid = pid; self.active.add(pid)
            for fd in list(self.fds):
                if fd not in {*self.readers, ack_w, executable}:
                    os.close(fd); self.fds.remove(fd)
            for fd in self.readers:
                os.set_blocking(fd, False)
            self.image = image
        except BaseException:
            self.close()
            raise

    def ptrace(self, request, tid, addr=0, data=0):
        # There is deliberately no SETREGS, POKETEXT, or syscall substitution.
        need(request in {2, 3, 5, 6, 7, 9, 12, 24, 0x4200, 0x4201, 0x420e},
             'Undeclared ptrace request')
        ctypes.set_errno(0)
        result = self.libc.ptrace(request, tid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
        error = ctypes.get_errno()
        if result == -1 and error:
            raise OSError(error, f'ptrace({request}, {tid}, {addr:#x})')
        return result

    def regs(self, tid):
        values = Regs()
        self.ptrace(12, tid, 0, ctypes.addressof(values))
        return {name: getattr(values, name) for name in REGISTERS}

    def word(self, tid, address):
        return self.ptrace(2, tid, address) & MASK

    def memory(self, tid, address, size):
        return b''.join(self.word(tid, address + i).to_bytes(8, 'little')
                        for i in range(0, size, 8))[:size]

    def event_message(self, tid):
        result = ctypes.c_ulonglong()
        self.ptrace(0x4201, tid, 0, ctypes.addressof(result))
        return result.value

    def debug(self, tid, address=None):
        self.ptrace(6, tid, DR_BASE + 7 * 8, 0)
        self.ptrace(6, tid, DR_BASE + 6 * 8, 0)
        if address is not None:
            self.ptrace(6, tid, DR_BASE, address)
            self.ptrace(6, tid, DR_BASE + 7 * 8, 1)
        self.events.append({'event': 'hardware-execute-breakpoint', 'tid': tid,
                            'address': address, 'DR7': self.ptrace(3, tid, DR_BASE + 7 * 8) & MASK})

    def resume(self, tid, request=7, sig=0):
        need(tid in self.stopped, 'Resume requires an observed ptrace stop')
        self.ptrace(request, tid, 0, sig)
        self.stopped.remove(tid)

    def drain(self):
        for fd, label in list(self.readers.items()):
            while True:
                try:
                    raw = os.read(fd, 65536)
                except BlockingIOError:
                    break
                if not raw:
                    del self.readers[fd]
                    break
                self.raw[label].extend(raw)

    def wait(self):
        while True:
            self.drain()
            need(time.monotonic() < self.deadline, 'Native ptrace case timed out')
            tid, status = os.waitpid(-1, WALL | os.WNOHANG)
            if not tid:
                select.select(list(self.readers), [], [], 0.0005)
                continue
            row = {'event': 'waitpid', 'tid': tid, 'status': status,
                   'elapsed_ns': time.monotonic_ns() - self.started_ns}
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                row['exit_code'] = os.waitstatus_to_exitcode(status)
                self.exits[tid] = row['exit_code']; self.active.discard(tid); self.stopped.discard(tid)
            elif os.WIFSTOPPED(status):
                row['signal'] = os.WSTOPSIG(status); row['ptrace_event'] = status >> 16
                self.stopped.add(tid)
            else:
                raise ValueError('Unexpected wait status')
            self.events.append(row)
            return row

    def step(self, tid, next_rip, label):
        before = self.regs(tid)
        self.debug(tid)
        self.resume(tid, 9)
        event = self.wait()
        need(event.get('signal') == signal.SIGTRAP and event['tid'] == tid
             and event['ptrace_event'] == 0, 'Single step did not produce its exact trap')
        after = self.regs(tid)
        need(after['rip'] == next_rip, 'Native instruction did not execute to expected next RIP')
        self.events.append({'event': 'single-step', 'label': label, 'tid': tid,
                            'before': before, 'after': after})
        return after

    def syscall(self, tid):
        buf = ctypes.create_string_buffer(88)
        count = self.ptrace(0x420e, tid, 88, ctypes.addressof(buf))
        raw = bytes(buf); kind = raw[0]
        need(kind in (1, 2), 'Actual syscall-entry/exit information required')
        regs = self.regs(tid)
        row = {'event': 'syscall-entry' if kind == 1 else 'syscall-exit', 'tid': tid,
               'number': regs['orig_rax'], 'rip': regs['rip'], 'info_bytes': count}
        if kind == 1:
            values = struct.unpack_from('<7Q', raw, 24)
            need(values[0] == regs['orig_rax'], 'Syscall registers disagree with kernel information')
            row['args'] = list(values[1:])
        else:
            row['return'] = struct.unpack_from('<q', raw, 24)[0]
            row['is_error'] = raw[32]
        self.events.append(row)
        return row

    def close(self):
        if self.active:
            try:
                os.killpg(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            cleanup_deadline = time.monotonic() + 3
            while self.active and time.monotonic() < cleanup_deadline:
                try:
                    tid, status = os.waitpid(-1, WALL | os.WNOHANG)
                except ChildProcessError:
                    break
                if not tid:
                    time.sleep(0.001); continue
                if os.WIFSTOPPED(status):
                    try:
                        self.ptrace(7, tid, 0, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                elif os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    self.exits[tid] = os.waitstatus_to_exitcode(status); self.active.discard(tid)
            self.events.append({'event': 'cleanup', 'remaining_tids': sorted(self.active),
                                'exit_codes': self.exits})
        self.drain()
        for fd in self.fds:
            os.close(fd)
        self.fds.clear()


def capture_breakpoints(trace, loop):
    event = trace.wait()
    need(event['tid'] == trace.pid and event.get('signal') == signal.SIGSTOP,
         'Own-child TRACEME did not reach initial stop')
    trace.ptrace(0x4200, trace.pid, 0, OPTIONS)
    trace.resume(trace.pid)
    event = trace.wait()
    need(event['tid'] == trace.pid and event.get('ptrace_event') == 4,
         'Exact native executable did not reach exec stop')
    actual_image = Path(f'/proc/{trace.pid}/exe').read_bytes()
    need(actual_image == trace.image, 'Executed image differs from actual HIA build output')
    trace.events.append({'event': 'actual-exec-image', **binding(actual_image)})
    trace.debug(trace.pid, loop['main_break']); trace.resume(trace.pid)
    reached = set()
    initial_children = set()
    while len(reached) != 2:
        event = trace.wait(); tid = event['tid']
        need('signal' in event, 'Tracee exited before both actual handshake instructions')
        if event['ptrace_event'] == 3:
            need(tid == trace.pid and trace.worker is None, 'Exactly one native owned worker required')
            trace.worker = trace.event_message(tid); trace.active.add(trace.worker)
            trace.events.append({'event': 'actual-clone', 'main_tid': tid, 'worker_tid': trace.worker})
            trace.resume(tid)
            if trace.worker in initial_children:
                trace.debug(trace.worker, loop['worker_break']); trace.resume(trace.worker)
        elif tid != trace.pid and event['signal'] == signal.SIGSTOP:
            initial_children.add(tid)
            if trace.worker is not None:
                need(tid == trace.worker, 'Unknown native thread')
                trace.debug(tid, loop['worker_break']); trace.resume(tid)
        else:
            need(event['signal'] == signal.SIGTRAP and event['ptrace_event'] == 0,
                 'Unexpected stop before deterministic interleaving')
            registers = trace.regs(tid)
            expected = loop['main_break'] if tid == trace.pid else loop['worker_break']
            need(tid in (trace.pid, trace.worker) and registers['rip'] == expected,
                 'Hardware stop is not the exact native handshake instruction')
            need(trace.ptrace(3, tid, DR_BASE + 6 * 8) & 1, 'DR0 execution breakpoint did not fire')
            reached.add(tid)
            trace.events.append({'event': 'reached-handshake', 'tid': tid, 'registers': registers})
    need(initial_children == {trace.worker}, 'Actual clone child start not observed')


def finish(trace, loop, waiter, publisher, version, invalid):
    positive = version == 'fixed' and invalid is None
    pending = {}
    waiting_calls = []
    joins = []
    fatal = []
    worker_released = False
    if positive:
        # Hold the worker until the main thread actually enters clear_tid wait.
        # This proves a real join and avoids depending on the scheduler's speed.
        trace.debug(trace.pid)
        trace.resume(trace.pid, 24)
    else:
        trace.debug(waiter)
        trace.resume(waiter, 24)
    while trace.active:
        event = trace.wait(); tid = event['tid']
        if 'signal' not in event:
            continue
        if event['ptrace_event'] == 6:
            value = trace.event_message(tid)
            trace.events.append({'event': 'actual-exit-event', 'tid': tid, 'status': value})
            if tid == trace.worker:
                trace.worker_exit_events.append(value)
            trace.resume(tid)
            continue
        need(event['ptrace_event'] == 0 and event['signal'] == (signal.SIGTRAP | 0x80),
             'Unexpected signal or event during actual native continuation')
        row = trace.syscall(tid)
        if row['event'] == 'syscall-entry':
            need(tid not in pending, 'Missing observed syscall exit')
            pending[tid] = row
            if row['number'] == 231:
                fatal.append(row)
            is_join = (positive and tid == trace.pid and row['number'] == 202
                       and row['args'][:3] == [loop['global'] + 32, 0, trace.worker])
            trace.resume(tid, 24)
            if is_join:
                need(not worker_released, 'Unexpected duplicate native join entry')
                worker_released = True
                trace.debug(trace.worker)
                trace.resume(trace.worker, 24 if waiter == trace.worker else 7)
        else:
            entry = pending.pop(tid)
            need(entry['number'] == row['number'], 'Actual syscall entry/exit mismatch')
            pair = {'entry': entry, 'exit': row}
            is_wait = (tid == waiter and entry['number'] == 202
                       and entry['args'][:3] == [loop['global'] + loop['field'], 128, 0])
            is_join = (tid == trace.pid and entry['number'] == 202
                       and entry['args'][:3] == [loop['global'] + 32, 0, trace.worker])
            if is_wait:
                pair['handshake_word_after'] = trace.word(tid, loop['global'] + loop['field']) & 0xffffffff
                waiting_calls.append(pair)
            if is_join:
                pair['clear_tid_after'] = trace.word(tid, loop['global'] + 32) & 0xffffffff
                pair['worker_exit_events_before_return'] = list(trace.worker_exit_events)
                joins.append(pair)
            # The worker's remaining business execution runs without syscall
            # stops. The main thread stops only until its real kernel join ends.
            trace.resume(tid, 7 if (is_join or (is_wait and tid == trace.worker)) else 24)
    trace.drain()
    if positive:
        need(worker_released and len(waiting_calls) == 1 and waiting_calls[0]['exit']['return'] == -errno.EAGAIN
             and waiting_calls[0]['handshake_word_after'] == 1,
             'Single captured zero did not take actual futex EAGAIN and then observe published one')
        need(len(joins) == 1 and joins[0]['exit']['return'] == 0
             and joins[0]['clear_tid_after'] == 0 and joins[0]['worker_exit_events_before_return'] == [0],
             'Native worker did not exit and complete real clear_tid kernel join')
        need(trace.exits.get(trace.worker) == 0, 'Actual owned worker failed')
    else:
        need(len(fatal) == 1 and fatal[0]['tid'] == waiter and fatal[0]['args'][0] == 88,
             'Exact waiting thread did not reject through unchanged fatal exit_group(88)')
        need(trace.exits.get(trace.pid) == 88 and not any(trace.raw.values()),
             'Refusal did not preserve the real empty-output exit88 result')
    return {'handshake_waits': waiting_calls, 'joins': joins, 'fatal_syscalls': fatal}


def run_case(image, version, profile, loop_name, invalid, expected, directory,
             *, layout='work-owner-v1'):
    need(not directory.exists(), 'Fresh native case output required')
    directory.mkdir(mode=0o700); provision(directory)
    payload = struct.pack('<8Q', int.from_bytes(b'WOFIX001', 'little'), *([0] * 7))
    payload += bytes.fromhex(expected['request_hex'])
    (directory / 'stdin.raw').write_bytes(payload)
    row = {'schema': 'trnm.hia.work-handshake-case.v1', 'status': 'FAIL',
           'version': version, 'profile': profile, 'layout': layout,
           'loop': loop_name, 'invalid_word': invalid,
           'image': binding(image), 'stdin': binding(payload), 'production_authority': False,
           'instruction_patching': False, 'syscall_or_clock_substitution': False}
    trace = None
    try:
        spec = LAYOUTS[layout]
        loop = dict(spec['loops'][loop_name])
        shift = spec['closed_fd_shift'] if profile == 'closed-fd' else 0
        for key in ('read', 'publish', 'main_break', 'worker_break'):
            loop[key] += shift
        trace = Trace(image, payload, directory)
        capture_breakpoints(trace, loop)
        waiter = trace.pid if loop_name == 'parent-ready' else trace.worker
        publisher = trace.worker if loop_name == 'parent-ready' else trace.pid
        a, b = trace.regs(waiter), trace.regs(publisher)
        need(a['r12'] == b['r12'] and a['r12'] != 0, 'Both owned threads must share actual private globals')
        loop['global'] = a['r12']; address = a['r12'] + loop['field']
        need(trace.word(waiter, address) & 0xffffffff == 0, 'Handshake was published before forced first read')
        read_code = bytes.fromhex(loop['new' if version == 'fixed' else 'old'])
        need(trace.memory(waiter, loop['read'], 20) == read_code,
             'Actually executing read instructions differ from reviewed HIA emitter')
        publish_code = bytes.fromhex('41c74424') + bytes([loop['field']]) + bytes.fromhex('01000000')
        need(trace.memory(publisher, loop['publish'], 9) == publish_code,
             'Actually executing publisher differs from unchanged production store')
        if invalid is not None:
            old_word = trace.word(waiter, address)
            trace.ptrace(5, waiter, address, (old_word & ~0xffffffff) | invalid)
            trace.private_state_writes.append({'address': address, 'before': old_word,
                                               'after': trace.word(waiter, address), 'purpose': 'invalid-word-refusal'})
        first = trace.step(waiter, loop['read'] + (5 if version == 'fixed' else 6), 'first-handshake-read')
        captured = 0 if invalid is None else invalid
        if version == 'fixed':
            need(first['rax'] == captured, 'Single actual load did not capture exact dword')
        else:
            need(not first['eflags'] & 64, 'Old first comparison unexpectedly observed one')
        if invalid is None:
            need(trace.word(publisher, address) & 0xffffffff == 0, 'Publisher changed during isolated first instruction')
            trace.step(publisher, loop['publish'] + 9, 'actual-zero-to-one-publisher-store')
            need(trace.word(waiter, address) & 0xffffffff == 1, 'Actual native store did not publish one')
        else:
            # Publisher remains stopped before its real store. Only this named
            # refusal control corrupts data, and no successful run does so.
            trace.debug(publisher)
        row.update(main_tid=trace.pid, worker_tid=trace.worker, global_address=loop['global'],
                   first_snapshot=captured, first_read_registers=first,
                   published_word=trace.word(waiter, address) & 0xffffffff)
        row.update(finish(trace, loop, waiter, publisher, version, invalid))
        if version == 'fixed' and invalid is None:
            stdout = bytes(trace.raw['stdout']); decoded = decode(stdout)
            physical = {'decoded': decoded, 'exit_code': trace.exits.get(trace.pid),
                        'status': 'PHYSICAL_FRAME_PASS_SEMANTIC_EXPECTATIONS_PENDING'}
            require_semantics(expected, physical)
            need(trace.exits.get(trace.pid) == (0 if expected['domain'] == 0 else 64 + expected['domain']),
                 'Actual native exit disagrees with returned terminal domain')
            need(decoded['header']['main_tid'] == trace.pid and decoded['header']['worker_tid'] == trace.worker,
                 'Returned frame does not bind actual traced thread identities')
            need(not trace.raw['stderr'] and not trace.raw['observer'], 'Unexpected native side output')
            row['decoded'] = decoded
        row['status'] = 'PASS'
    except BaseException as error:
        row.update(failure=repr(error), traceback=traceback.format_exc())
    finally:
        if trace is not None:
            trace.close()
            row.update(exit_codes=trace.exits, elapsed_ns=time.monotonic_ns() - trace.started_ns,
                       code_writes=trace.code_writes, general_register_writes=trace.general_register_writes,
                       private_state_writes=trace.private_state_writes, unreaped_tids=sorted(trace.active))
            if trace.active:
                row.update(status='FAIL', cleanup_failure='Unreaped actual tracee')
            for label, raw in trace.raw.items():
                (directory / (label + '.raw')).write_bytes(raw)
                row[label] = binding(raw)
            (directory / 'ptrace-events.jsonl').write_text(''.join(json.dumps(e, sort_keys=True) + '\n' for e in trace.events))
        write_json(directory / 'case.json', row)
    return row


def build_inputs(directory, version, *, layout='work-owner-v1'):
    report = json_file(directory / 'build.json')
    need(report['schema'] == 'trnm.hia.work-owner-build.v1' and report['status'] == 'PASS',
         'Actual HIA build evidence required')
    need(report['compiler_sha256'] == '87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54',
         'Pinned actual compiler required')
    result = {}
    for profile in ('owner', 'fixture', 'closed-fd'):
        image = read_file(directory / (profile + '.elf'))
        info = report['images'][profile]
        need(binding(image) == {k: info[k] for k in ('bytes', 'sha256')}, 'Actual image binding mismatch')
        emitted = read_file(directory / ('emit-' + profile) / 'stdout.raw')
        need(image == emitted, 'Image was not the retained actual HIA emitter stdout')
        stage = json_file(directory / ('emit-' + profile) / 'receipt.json')
        need(stage in report['stages'] and stage['exit_code'] == 0 and stage['timed_out'] is False,
             'Actual emitter stage did not complete')
        need(binding(read_file(directory / ('emit-' + profile) / 'stdin.raw')) ==
             {'bytes': stage['input_bytes'], 'sha256': stage['input_sha256']}, 'Emitter input binding mismatch')
        emitter = 'closed-emitter' if profile == 'closed-fd' else 'emitter'
        native = read_file(directory / (emitter + '.elf'))
        need(binding(native) == report['native_images'][emitter]
             and binding(native) == {'bytes': stage['executable_bytes'], 'sha256': stage['executable_sha256']},
             'Stage did not execute the compiled HIA emitter')
        need(native == read_file(directory / ('compile-' + emitter) / 'stdout.raw'),
             'Emitter differs from actual pinned compiler stdout')
        code = read_file(directory / (emitter + '.hepta'))
        need(binding(code) == report['composed_sources'][emitter]
             and code == read_file(directory / ('compile-' + emitter) / 'stdin.raw'),
             'Emitter HIA source is not bound to actual compilation')
        spec = LAYOUTS[layout]
        shift = spec['closed_fd_shift'] if profile == 'closed-fd' else 0
        for loop in spec['loops'].values():
            start = loop['read'] + shift - BASE
            need(image[start:start + 20] == bytes.fromhex(loop['new' if version == 'fixed' else 'old']),
                 'Handshake instruction profile is not exact old/fixed source')
        result[profile] = image
    return report, result


def qualify(original, fixed, output, *, layout='work-owner-v1'):
    need(__debug__, 'Qualification refuses optimized Python')
    need(platform.system() == 'Linux' and platform.machine() == 'x86_64' and ctypes.sizeof(Regs) == 216,
         'Actual Linux x86_64 ptrace ABI required')
    need(layout in LAYOUTS, 'Explicit reviewed native handshake layout required')
    spec = LAYOUTS[layout]
    loops = spec['loops']
    output = output.absolute()
    need(output.resolve() == output and not output.exists() and ROOT not in output.parents,
         'Fresh canonical output outside repository required')
    output.mkdir(parents=True, mode=0o700)
    expected_names = [f'{version}-{profile}-{loop}-{mode}' for profile in ('fixture', 'closed-fd')
                      for loop in loops for mode in ('race', 'invalid-2', 'invalid-4294967295')
                      for version in ('original', 'fixed')]
    report = {'schema': 'trnm.hia.work-handshake-qualification.v1', 'status': 'INCOMPLETE',
              'finalized': False, 'layout': layout,
              'expected_cases': expected_names, 'started_cases': [],
              'completed_cases': [], 'cases': [], 'actual_original_rust': False,
              'production_fixed_parent_authority': False, 'whole_Node_or_paid_checkpoint_closed': False,
              'four_second_deadline_changed': False, 'ptrace_instruction_patching': False}
    write_json(output / 'report.json', report)
    before = None
    try:
        before = {name: binding(read_file(ROOT / name)) for name in IMPORTS}
        report['qualification_sources'] = before
        old_report, old = build_inputs(original, 'original', layout=layout)
        new_report, new = build_inputs(fixed, 'fixed', layout=layout)
        report['builds'] = {'original': binding(read_file(original / 'build.json')),
                            'fixed': binding(read_file(fixed / 'build.json'))}
        report['build_source_inputs'] = {'original': old_report['source_inputs'], 'fixed': new_report['source_inputs']}
        for name in IMPORTS[1:]:
            need(new_report['source_inputs'][name] == before[name], 'Loaded harness dependency differs from actual build')
        for profile in old:
            shift = spec['closed_fd_shift'] if profile == 'closed-fd' else 0
            allowed = {loop['read'] + shift - BASE + i for loop in loops.values() for i in range(20)}
            need(len(old[profile]) == len(new[profile]), 'Fix changed native section layout')
            actual = {i for i, (a, b) in enumerate(zip(old[profile], new[profile], strict=True)) if a != b}
            need(actual and actual <= allowed, 'Actual native build changed instructions outside the two reviewed loops')
            report.setdefault('image_delta', {})[profile] = {'original': binding(old[profile]), 'fixed': binding(new[profile]),
                                                              'changed_offsets': sorted(actual)}
        base_case = corpus()[0]
        need(base_case['name'] == 'dense-positive' and base_case['domain'] == 0, 'Exact independent retained proof required')
        write_json(output / 'independent-case.json', base_case)
        report['independent_case'] = binding(read_file(output / 'independent-case.json'))
        for profile in ('fixture', 'closed-fd'):
            expected = base_case if profile == 'fixture' else {**base_case, 'domain': 3, 'code': 4,
                       'product_hex': None, 'progress': base_case['progress'][:1]}
            for loop in loops:
                for invalid in (None, 2, 0xffffffff):
                    mode = 'race' if invalid is None else 'invalid-' + str(invalid)
                    for version, images in (('original', old), ('fixed', new)):
                        name = f'{version}-{profile}-{loop}-{mode}'
                        report['started_cases'].append(name); write_json(output / 'report.json', report)
                        result = run_case(images[profile], version, profile, loop, invalid, expected,
                                          output / name, layout=layout)
                        report['cases'].append({'name': name, 'status': result['status'],
                                                'report': binding(read_file(output / name / 'case.json'))})
                        report['completed_cases'].append(name); write_json(output / 'report.json', report)
                        print(json.dumps({'case': name, 'status': result['status'], 'failure': result.get('failure')}), flush=True)
        need(report['completed_cases'] == expected_names and all(r['status'] == 'PASS' for r in report['cases']),
             'Complete deterministic old/new race and invalid-state roster must pass')
        report['status'] = 'PASS'
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error), traceback=traceback.format_exc())
    finally:
        if before is not None:
            after = {name: binding(read_file(ROOT / name)) for name in IMPORTS}
            report['source_unchanged'] = before == after
            if before != after:
                report.update(status='FAIL', source_failure='Qualification source changed during actual execution')
        report['finalized'] = True
        files = {p.relative_to(output).as_posix(): binding(read_file(p)) for p in sorted(output.rglob('*'))
                 if p.is_file() and p.name != 'report.json'}
        report['artifacts'] = files
        write_json(output / 'report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original-build', type=Path, required=True)
    parser.add_argument('--fixed-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--layout', choices=tuple(LAYOUTS), default='work-owner-v1')
    args = parser.parse_args()
    report = qualify(args.original_build, args.fixed_build, args.output, layout=args.layout)
    print(json.dumps({'status': report['status'], 'completed': len(report['completed_cases']),
                      'expected': len(report['expected_cases']), 'failure': report.get('failure')}), flush=True)
    raise SystemExit(0 if report['status'] == 'PASS' else 1)


if __name__ == '__main__':
    main()
