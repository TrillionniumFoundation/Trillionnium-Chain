"""Audit complete real same-worker traces, including bytes, EOF and lifetime.

The strict successful-resource profile is deliberately explicit. A different
fault trace must be given its own reviewed profile; no unknown call is removed
to make a successful check sequence. This observer grants no runtime authority.
"""
from __future__ import annotations
import hashlib
import os
import re
import struct
from .native_io import decode, require

HEX = r'0x[0-9a-f]+'
PID = re.compile(r'^(?:\[pid\s+)?(\d+)(?:\])?\s+(.*)$')
CALL = re.compile(r'^([a-z0-9_]+)\((.*)\)\s+=\s+(.+)$')
RESULT = re.compile(r'^(-?\d+|0x[0-9a-f]+|\?)(?:\s|$)')
CLONE_FLAGS = 'CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID'
PARENT = b'sys/fs/cgroup/trnmponpublic.slice'
READ_FLAGS = 'O_RDONLY|O_CLOEXEC'
PARENT_FLAGS = 'O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY'
LIMIT_FLAGS = 'O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC'
LIMITS = ((b'cpu.max', b'25000 100000\n'), (b'cpu.max.burst', b'0\n'),
          (b'memory.max', b'2147483648\n'), (b'memory.swap.max', b'0\n'), (b'pids.max', b'256\n'))
COUNTERS = ((b'cpu.stat', b'usage_usec 10\nnr_periods 20\nnr_throttled 3\nthrottled_usec 40\n', 2049),
            (b'memory.current', b'64\n', 65), (b'pids.current', b'2\n', 65))

def c_string(text, start=0):
    require(start < len(text) and text[start] == '"', 'Expected complete trace C string')
    data = bytearray(); i = start + 1
    escapes = {'a': 7, 'b': 8, 't': 9, 'n': 10, 'v': 11, 'f': 12, 'r': 13, '"': 34, '\\': 92}
    while i < len(text):
        ch = text[i]; i += 1
        if ch == '"': return bytes(data), i
        if ch != '\\':
            require(32 <= ord(ch) < 127, 'Noncanonical literal trace byte'); data.append(ord(ch)); continue
        require(i < len(text), 'Truncated trace escape'); ch = text[i]; i += 1
        if ch in escapes: data.append(escapes[ch])
        elif ch in '01234567':
            token = ch
            while i < len(text) and len(token) < 3 and text[i] in '01234567': token += text[i]; i += 1
            value = int(token, 8); require(value < 256, 'Trace octal overflow'); data.append(value)
        elif ch == 'x':
            require(re.fullmatch('[0-9a-fA-F]{2}', text[i:i+2]) is not None, 'Trace hex escape differs')
            data.append(int(text[i:i+2], 16)); i += 2
        else: raise ValueError('Unsupported trace escape')
    raise ValueError('Unclosed trace C string')

def arguments(text):
    fields = []; start = 0; nesting = []; i = 0
    while i < len(text):
        ch = text[i]
        if ch == '"': _, i = c_string(text, i); continue
        if ch in '([{': nesting.append(ch)
        elif ch in ')]}':
            require(nesting and '([{'.index(nesting.pop()) == ')]}'.index(ch), 'Unbalanced syscall arguments')
        elif ch == ',' and not nesting:
            fields.append(text[start:i]); require(text[i:i+2] == ', ', 'Noncanonical syscall separator'); start = i + 2; i += 1
        i += 1
    require(not nesting, 'Unclosed syscall arguments'); fields.append(text[start:])
    return fields

def complete_calls(text):
    pending = {}; calls = []; signals = []; exits = []
    for number, line in enumerate(text.splitlines(), 1):
        match = PID.fullmatch(line); require(match is not None, 'Missing exact trace TID')
        tid = int(match[1]); body = match[2]
        if body.startswith('--- '):
            require(re.fullmatch(r'--- SIGUSR[12] \{[^{}]*\} ---', body) is not None, 'Unexpected native signal')
            signals.append({'tid': tid, 'line': number, 'text': body}); continue
        if body.startswith('+++'):
            ended = re.fullmatch(r'\+\+\+ exited with (\d+) \+\+\+', body)
            require(ended is not None, 'Unclean trace exit'); exits.append((tid, int(ended[1]), number)); continue
        resumed = re.fullmatch(r'<\.\.\. ([a-z0-9_]+) resumed>(.*)', body)
        if resumed:
            require(tid in pending, 'Resume without a pending syscall'); start, first = pending.pop(tid)
            require(first.startswith(resumed[1] + '('), 'Wrong syscall resume'); body = first + resumed[2]
        else:
            start = number; require(tid not in pending, 'Second call while a syscall is pending')
        if body.endswith(' <unfinished ...>'):
            require(not resumed, 'Repeated unfinished resume'); pending[tid] = (start, body[:-len(' <unfinished ...>')]); continue
        call = CALL.fullmatch(body); require(call is not None, 'Unparsed complete syscall: ' + body[:180])
        value = RESULT.match(call[3]); require(value is not None, 'Unparsed syscall return')
        calls.append({'tid': tid, 'name': call[1], 'args': call[2], 'result': call[3],
                      'value': None if value[1] == '?' else int(value[1], 0), 'start': start, 'end': number})
    require(calls and not pending, 'Incomplete actual syscall trace')
    return calls, signals, exits

def pair_signals(calls, signals, worker, expected_signal):
    require(len(signals) == (0 if expected_signal is None else 1), 'Actual signal roster differs')
    returns = [c for c in calls if c['name'] == 'rt_sigreturn']
    require(len(returns) == len(signals), 'Unpaired native signal return')
    results = []
    for delivered, returned in zip(signals, returns, strict=True):
        require(delivered['tid'] == returned['tid'] == worker and returned['args'] == '{mask=[]}'
                and delivered['line'] < returned['start'], 'Signal was not handled by the actual working thread')
        signame = 'SIGUSR' + str(expected_signal)
        require(re.fullmatch(r'--- ' + signame + r' \{si_signo=' + signame +
                            r', si_code=SI_(?:USER|TKILL), si_pid=\d+, si_uid=\d+\} ---', delivered['text']) is not None,
                'Signal sender/profile differs')
        before = sorted((c for c in calls if c['tid'] == worker and c['end'] < delivered['line']), key=lambda c: c['end'])
        require(before, 'Signal lacks a native predecessor')
        interrupted = before[-1]
        pseudo = '? ERESTARTSYS (To be restarted if SA_RESTART is set)'
        if interrupted['result'] == pseudo:
            require(interrupted['name'] == 'read' and returned['result'] == '-1 EINTR (Interrupted system call)',
                    'Restart pseudo-result lacks actual EINTR return')
            interrupted['value'] = -1; interrupted['actual_signal_interrupted'] = True
        else:
            # A pending signal can be delivered after ACK has completed. Its
            # sigreturn restores the interrupted user register state, rather
            # than proving another failed read or requesting an ACK retry.
            require(interrupted['name'] in ('read', 'write')
                    and re.fullmatch(r'-?\d+', returned['result']) is not None,
                    'Non-interrupted gate signal has an error/injected return')
        fd, data, wanted, value = io_fields(interrupted)
        require((interrupted['name'] == 'write' and fd == 3 and wanted == value == 32
                 and data[:8] == b'WGATE001')
                or (interrupted['name'] == 'read' and fd == 4 and wanted == 1
                    and (interrupted.get('actual_signal_interrupted') or value == 1 and data == b'\x01')),
                'Signal did not follow this actual private gate I/O')
        returned['paired_gate_signal'] = True
        require(not any(c['tid'] == worker and delivered['line'] < c['start'] < returned['start'] for c in calls),
                'Native work intervened before the real signal return')
        results.append({'signal': signame, 'tid': worker, 'signal_line': delivered['line'],
                        'return_line': returned['end'], 'interrupted': interrupted.get('actual_signal_interrupted', False)})
    require(not any(c['result'].startswith('? ERESTART') and not c.get('actual_signal_interrupted') for c in calls),
            'Unaccounted restarted syscall')
    return results

def io_fields(call, *, positioned=False):
    fields = arguments(call['args']); require(len(fields) == (4 if positioned else 3), 'I/O argument extent differs')
    require(fields[0].isdigit() and fields[2].isdigit(), 'I/O descriptor/count differs')
    raw = None
    if fields[1].startswith('"'):
        raw, end = c_string(fields[1]); require(end == len(fields[1]), 'Abbreviated I/O bytes')
    else: require(re.fullmatch(HEX, fields[1]) is not None, 'Invalid I/O buffer')
    value = call['value']; count = int(fields[2]); fd = int(fields[0])
    if value is not None and value >= 0:
        require(raw is not None and 0 <= value <= count and len(raw) == (count if call['name'] == 'write' else value),
                'I/O returned or displayed a different byte extent')
    if positioned:
        require(fields[3].isdigit(), 'Negative/unknown input offset'); return fd, raw, count, value, int(fields[3])
    return fd, raw, count, value

def stat_fields(call):
    fields = arguments(call['args']); raw = fields[1] if call['name'] == 'fstat' else fields[2]
    device = re.search(r'(?:^\{|, )st_dev=makedev\((0x[0-9a-f]+|\d+), (0x[0-9a-f]+|\d+)\)', raw)
    inode = re.search(r', st_ino=(\d+),', raw); mode = re.search(r', st_mode=(S_IF[A-Z]+)\|([0-7]+),', raw)
    uid = re.search(r', st_uid=(\d+),', raw); size = re.search(r', st_size=(\d+),', raw)
    require(call['value'] == 0 and device and inode and mode and uid and size and raw.endswith('}'), 'Incomplete actual fstat metadata')
    return {'dev': os.makedev(int(device[1], 0), int(device[2], 0)), 'ino': int(inode[1]),
            'kind': mode[1], 'permissions': int(mode[2], 8), 'uid': int(uid[1]), 'size': int(size[1])}

class Cursor:
    def __init__(self, calls, tid):
        self.calls = sorted((c for c in calls if c['tid'] == tid), key=lambda c: c['start'])
        self.tid = tid; self.index = 0; self.active = {}; self.checks = 0; self.samples = 0; self.bytes = 0
        self.paid_cpu_samples = []; self.paid_wall_samples = []

    def peek(self): return self.calls[self.index] if self.index < len(self.calls) else None

    def take(self, name, args=None, value=0, *, injected=False):
        call = self.peek(); require(call is not None and call['name'] == name,
            'Expected ' + name + ' on actual TID ' + str(self.tid) + ', got ' + str(call)[:250])
        require(args is None or call['args'] == args, 'Unexpected ' + name + ' arguments: ' + call['args'][:200])
        require(value == 'any' or call['value'] == value, 'Unexpected ' + name + ' result: ' + call['result'])
        require(('INJECTED' in call['result']) == injected, 'Controlled result in another trace position/profile')
        self.index += 1; return call

    def tid_call(self): return self.take('gettid', '', self.tid)

    def opened(self, dirfd, path, flags):
        call = self.take('openat', value='any'); fields = arguments(call['args'])
        require(len(fields) == 3 and fields[0] == str(dirfd) and fields[2] == flags, 'Readonly open profile differs')
        data, end = c_string(fields[1]); require(end == len(fields[1]) and data == path, 'Actual path differs')
        fd = call['value']; require(type(fd) is int and fd >= 5 and fd not in self.active, 'Resource FD was not freshly acquired')
        if str(dirfd) != 'AT_FDCWD': require(int(dirfd) in self.active, 'Relative open lacks a live checked parent')
        self.active[fd] = path; return fd

    def closed(self, fd):
        require(fd in self.active, 'Closing an uncaptured FD'); self.take('close', str(fd)); del self.active[fd]

    def metadata(self, fd, kind):
        require(fd in self.active, 'Metadata does not refer to a live captured FD')
        call = self.take('fstat'); require(arguments(call['args'])[0] == str(fd), 'fstat changed FD')
        value = stat_fields(call); require(value['kind'] == kind, 'Actual resource type differs'); return value

    def path_metadata(self, path, flags):
        call = self.take('newfstatat'); fields = arguments(call['args'])
        require(len(fields) == 4 and fields[0] == 'AT_FDCWD' and fields[3] == flags, 'Final metadata profile differs')
        actual, end = c_string(fields[1]); require(end == len(fields[1]) and actual == path, 'Metadata path differs')
        return stat_fields(call)

    def stream(self, dirfd, path, flags, bound, expected, *, typed=False):
        fd = self.opened(dirfd, path, flags)
        if typed: self.metadata(fd, 'S_IFREG')
        data = bytearray(); remaining = bound; calls = 0
        while True:
            call = self.take('read', value='any'); actual_fd, raw, wanted, count = io_fields(call)
            require(actual_fd == fd and wanted == remaining and count is not None and count >= 0,
                    'Native read bounds/FD changed or unexpected fault')
            calls += 1
            if count == 0: break
            data.extend(raw); remaining -= count; self.bytes += count
            require(remaining > 0 and len(data) < bound, 'Stream exceeded its preserved bound')
        require(calls >= 2 and bytes(data) == expected, 'Actual fresh stream/EOF bytes differ')
        self.closed(fd); return bytes(data)

    def parent_identity(self, value, parent):
        require(tuple(value[k] for k in ('dev', 'ino', 'uid')) == parent and value['kind'] == 'S_IFDIR'
                and not value['permissions'] & 0o022, 'Parent no longer has the acquired authority identity')

    def fresh(self, parent, context_bound, *, keep=False):
        self.stream('AT_FDCWD', b'boot', READ_FLAGS, context_bound, b'boot-identity\n')
        fd = self.opened('AT_FDCWD', PARENT, PARENT_FLAGS)
        self.parent_identity(self.metadata(fd, 'S_IFDIR'), parent)
        self.stream('AT_FDCWD', b'membership', READ_FLAGS, context_bound, b'0::/trnmponpublic.slice\n')
        for name, raw in LIMITS: self.stream(fd, name, LIMIT_FLAGS, 129, raw, typed=True)
        self.parent_identity(self.path_metadata(PARENT, 'AT_SYMLINK_NOFOLLOW'), parent)
        self.checks += 1
        if not keep: self.closed(fd)
        return fd

    def sample(self, parent, context_bound):
        self.tid_call(); fd = self.fresh(parent, context_bound, keep=True)
        for name, raw, bound in COUNTERS: self.stream(fd, name, LIMIT_FLAGS, bound, raw, typed=True)
        self.closed(fd); self.fresh(parent, context_bound); self.samples += 1

    def host(self, parent, context_bound):
        self.tid_call(); self.fresh(parent, context_bound)

    def clock(self):
        require(not self.active, 'CLOCK1 sampled with an authority FD still active')
        call = self.take('clock_gettime')
        match = re.fullmatch(r'CLOCK_MONOTONIC, \{tv_sec=(-?\d+), tv_nsec=(-?\d+)\}', call['args'])
        require(match is not None and 0 <= int(match[2]) < 1000000000, 'Clock identity/timespec differs')
        return int(match[1]) * 1000000000 + int(match[2])

    def paid_cpu(self):
        require(not self.active, 'Paid CPU clock retained an authority FD')
        self.tid_call()
        call = self.take('clock_gettime')
        match = re.fullmatch(r'CLOCK_THREAD_CPUTIME_ID, \{tv_sec=(\d+), tv_nsec=(\d+)\}', call['args'])
        require(match is not None and int(match[2]) < 1000000000, 'Actual same-worker CLOCK3 identity/timespec')
        value = int(match[1]) * 1000000000 + int(match[2])
        require(value < 1 << 64 and (not self.paid_cpu_samples or value >= self.paid_cpu_samples[-1]), 'Actual CPU timestamp overflow/rewind')
        self.paid_cpu_samples.append(value)
        return value

    def paid_wall(self):
        value = self.clock()
        require(not self.paid_wall_samples or value >= self.paid_wall_samples[-1], 'Actual Paid CLOCK1 rewound')
        self.paid_wall_samples.append(value)
        return value

    def paid_begin(self):
        self.tid_call(); self.paid_cpu(); self.paid_wall()

    def paid_checkpoint(self):
        self.tid_call(); self.paid_cpu(); self.paid_wall()

    def paid_finish(self):
        self.tid_call(); self.paid_cpu(); self.paid_wall()
        self.paid_cpu(); self.paid_wall()

    def paid_drop(self):
        # Work CLOCK1 panic occurs outside both mutexes. Original Drop still
        # observes the live thread once, then settles the unknown reservation.
        self.tid_call(); self.paid_cpu(); self.paid_wall(); self.paid_wall()

    def output(self, fd, raw):
        offset = 0
        while offset < len(raw):
            call = self.take('write', value='any'); actual_fd, data, count, written = io_fields(call)
            require(actual_fd == fd and count == len(raw) - offset and data == raw[offset:]
                    and written is not None and written > 0, 'Actual output bytes/count/FD differ')
            offset += written

def audit_trace(text, stdin, stdout, *, expected_signal=None, fault_profile=None):
    """Fully consume a normal-resource success/cancel trace and its exact I/O."""
    decoded = decode(stdout); header = decoded['header']
    clock_match = re.fullmatch(r'worker-clock-(EIO|EINVAL)-([0-9]+)', fault_profile or '')
    clock_ordinal = int(clock_match[2]) if clock_match else None
    require(fault_profile in (None, 'closed-parent-first-progress') or clock_match is not None,
            'Unknown private fault trace profile')
    require(clock_ordinal is None or 2 <= clock_ordinal <= 2200, 'Invalid exact working-thread clock fault ordinal')
    closed_fd = fault_profile == 'closed-parent-first-progress'
    require(not closed_fd or (expected_signal is None and header['domain'] == 3 and header['code'] == 4),
            'Closed-FD trace did not retain the original parent error')
    require(clock_ordinal is None or (expected_signal is None and header['domain'] == 4 and header['code'] == 1),
            'Controlled CLOCK1 failure did not retain the original panic boundary')
    require(header['fixture'] == 1 and header['domain'] in ((4,) if clock_ordinal else (3,) if closed_fd else (0, 2)) and header['post_sample_error'] == 0,
            'This trace profile requires an explicitly successful resource path')
    require(len(stdin) == 49348 and stdin[:8] == b'WOFIX001', 'Exact sealed fixture input required')
    words = struct.unpack('<8Q', stdin[:64]); sequence, stage = words[1:3]
    require(not any(words[3:]) and ((stage == 0 and sequence == 0) or (1 <= sequence <= 1099 and stage in (3, 4, 5, 7))),
            'Unsupported exact progress gate profile')
    calls, signals, exits = complete_calls(text)
    main = header['main_tid']; worker = header['worker_tid']
    require(main > 0 and worker > 0 and main != worker and {c['tid'] for c in calls} == {main, worker},
            'Unexpected actual thread roster')
    signal_rows = pair_signals(calls, signals, worker, expected_signal)
    parent = (header['parent_dev'], header['parent_ino'], header['parent_uid'])
    p = Cursor(calls, main); w = Cursor(calls, worker)
    start = p.take('execve'); parts = arguments(start['args'])
    executable, end = c_string(parts[0]); require(end == len(parts[0]) and re.fullmatch(rb'/proc/self/fd/[0-9]+', executable), 'Unsealed native exec path')
    require(parts[1] == '[' + parts[0] + ']' and len(parts) == 3, 'Unexpected native executable argv')
    env, end = c_string(parts[2], 1); require(env == b'PATH=' and parts[2][end:] == ']', 'Unexpected native environment')
    mappings = []
    for size in (229376, 270336, 8192, 57344, 155648):
        call = p.take('mmap', f'NULL, {size}, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0', value='any')
        require(type(call['value']) is int and call['value'] > 0 and call['value'] % 4096 == 0, 'Failed/private mapping differs')
        mappings.append(call['value'])
    global_base = mappings[0]; captured_base = mappings[3]
    for signame in ('SIGUSR1', 'SIGUSR2', 'SIGPIPE'):
        call = p.take('rt_sigaction'); match = re.fullmatch(signame + r', \{sa_handler=(0x[0-9a-f]+|SIG_IGN), sa_mask=\[\], sa_flags=SA_RESTORER, sa_restorer=(0x[0-9a-f]+)\}, NULL, 8', call['args'])
        require(match is not None and (match[1] == 'SIG_IGN') == (signame == 'SIGPIPE'), 'Signal handler/restart policy differs')
        require(0x400000 <= int(match[2], 16) < 0x800000 and (match[1] == 'SIG_IGN' or 0x400000 <= int(match[1], 16) < 0x800000), 'Signal pointer escaped static native text')
    p.tid_call(); seals = p.take('fcntl', '0, F_GET_SEALS', 15)
    require('F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE' in seals['result'], 'Native input lacks four actual seals')
    call = p.take('fstat'); require(arguments(call['args'])[0] == '0', 'Input fstat changed FD')
    input_stat = stat_fields(call); require(input_stat['kind'] == 'S_IFREG' and input_stat['size'] == len(stdin), 'Native captured input metadata differs')
    offset = 0
    while offset < len(stdin):
        call = p.take('pread64', value='any'); fd, data, count, returned, position = io_fields(call, positioned=True)
        require(fd == 0 and position == offset and count == len(stdin) - offset and returned > 0
                and data == stdin[offset:offset+returned], 'Captured sealed input offset/bytes differ')
        offset += returned
    capabilities = {}
    for fd in (3, 4, 1, 2):
        call = p.take('fstat'); require(arguments(call['args'])[0] == str(fd), 'Callback cap metadata FD differs')
        value = stat_fields(call); capabilities[fd] = (value['dev'], value['ino'])
        if fd in (3, 4): require(value['kind'] == 'S_IFIFO', 'Callback cap is not an actual pipe')
    require(capabilities[3] != capabilities[4] and all(capabilities[x] != capabilities[y] for x in (3, 4) for y in (1, 2)),
            'Callback capability aliases an input/output or itself')
    p.take('fcntl', '3, F_GETFL', 1); p.take('fcntl', '4, F_GETFL', 0)
    p.take('mprotect', f'{captured_base:#x}, 57344, PROT_READ')
    started = p.clock(); deadline = started + 4000000000
    p.tid_call(); p.paid_wall()
    p.take('getuid', '', parent[2]); p.tid_call()
    previous = None
    for index, name in enumerate((b'.', b'sys', b'fs', b'cgroup', b'trnmponpublic.slice')):
        fd = p.opened('AT_FDCWD' if previous is None else previous, name,
                      PARENT_FLAGS if index < 4 else 'O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH')
        if previous is not None: p.closed(previous)
        previous = fd
    p.parent_identity(p.metadata(fd, 'S_IFDIR'), parent); p.closed(fd)
    require(p.path_metadata(b'controllers', '0')['kind'] == 'S_IFREG', 'Controller acquisition metadata differs')
    p.parent_identity(p.path_metadata(PARENT, 'AT_SYMLINK_NOFOLLOW'), parent)
    p.stream('AT_FDCWD', b'boot', READ_FLAGS, 4096, b'boot-identity\n')
    fd = p.opened('AT_FDCWD', PARENT, PARENT_FLAGS); p.parent_identity(p.metadata(fd, 'S_IFDIR'), parent)
    for name, raw in LIMITS: p.stream(fd, name, LIMIT_FLAGS, 129, raw, typed=True)
    p.closed(fd)
    require(header['boot_bytes'] == 13 and decoded['host_before'][24] == 8192, 'Private context mapping/retained boot extent differs')
    context_bound = 8192 - 4096 - 13
    p.fresh(parent, context_bound); p.sample(parent, context_bound)
    require(p.checks == header['pre_checks'] == 3 and not p.active, 'Acquisition/baseline extent differs')
    call = p.take('mmap', 'NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0', value='any')
    require(type(call['value']) is int and call['value'] > 0, 'Worker private Host mapping failed')
    stack = p.take('mmap', 'NULL, 1056768, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0', value='any')['value']
    require(type(stack) is int and stack > 0 and stack % 4096 == 0, 'Worker guarded stack allocation failed')
    p.take('mprotect', f'{stack+4096:#x}, 1048576, PROT_READ|PROT_WRITE')
    birth = p.take('clone', value=worker)
    require(birth['args'] == f'child_stack={stack+4096+1048576:#x}, flags={CLONE_FLAGS}, parent_tid=[{worker}], child_tidptr={global_base+32:#x}',
            'Actual clone identity/stack/clear-TID contract differs')
    death = [c for c in calls if c['tid'] == worker and c['name'] == 'exit']
    require(len(death) == 1 and death[0]['args'] == '0' and death[0]['value'] is None, 'Owned child did not execute SYS_exit')
    death = death[0]
    require(all(birth['start'] < c['start'] <= c['end'] <= death['end'] for c in calls if c['tid'] == worker),
            'Worker syscall lies outside its actual birth/exit lifetime')
    require(all(c['name'] == 'futex' for c in calls if c['tid'] == main and birth['end'] < c['start'] < death['end']),
            'Main accessed authority or output before the owned child exited')
    w.tid_call()
    call = w.take('futex', f'{global_base+36:#x}, FUTEX_WAKE_PRIVATE, 1', value='any')
    require(call['value'] in (0, 1), 'Ready wake return differs')
    while w.peek() and w.peek()['name'] == 'futex':
        call = w.take('futex', f'{global_base+40:#x}, FUTEX_WAIT_PRIVATE, 0, NULL', value='any')
        require(call['value'] == 0 or call['result'] in ('-1 EAGAIN (Resource temporarily unavailable)', '-1 EINTR (Interrupted system call)'), 'Child start wait return differs')
    while p.peek() and p.peek()['name'] == 'futex' and 'FUTEX_WAIT_PRIVATE' in p.peek()['args']:
        call = p.take('futex', f'{global_base+36:#x}, FUTEX_WAIT_PRIVATE, 0, NULL', value='any')
        require(call['value'] == 0 or call['result'] in ('-1 EAGAIN (Resource temporarily unavailable)', '-1 EINTR (Interrupted system call)'), 'Parent ready wait return differs')
    call = p.take('futex', f'{global_base+40:#x}, FUTEX_WAKE_PRIVATE, 1', value='any')
    require(call['value'] in (0, 1), 'Parent start wake return differs')
    joined = []
    while p.peek() and p.peek()['name'] == 'futex':
        call = p.take('futex', f'{global_base+32:#x}, FUTEX_WAIT, {worker}, NULL', value='any')
        require(call['value'] == 0 or call['result'] in ('-1 EAGAIN (Resource temporarily unavailable)', '-1 EINTR (Interrupted system call)'), 'Actual shared clear-TID join return differs')
        joined.append(call)
    require(joined and joined[-1]['end'] > death['end'] and header['joins'] == 1, 'No actual post-exit join observation')
    clocks = []; gates = []; consumed_signal_returns = []
    def clock():
        if clock_ordinal == len(clocks) + 1:
            actual_ordinal = sum(c['name'] == 'clock_gettime' for c in w.calls[:w.index]) + 1
            mapped_ordinal = 2 * clock_ordinal + (1 if clock_ordinal % 2 else 2)
            require(actual_ordinal == mapped_ordinal, 'Controlled CLOCK1 moved across a Paid checkpoint')
            require(not w.active, 'Failing CLOCK1 retained an authority FD')
            call = w.take('clock_gettime', value=-1, injected=True)
            require(call['args'] == f'CLOCK_MONOTONIC, {global_base+65536+81920+64:#x}',
                    'Controlled failure did not target this actual worker event timespec')
            error = 'EIO (Input/output error)' if clock_match[1] == 'EIO' else 'EINVAL (Invalid argument)'
            require(call['result'] == '-1 ' + error + ' (INJECTED)', 'Actual controlled CLOCK1 errno differs')
            clocks.append(None)
            return None
        value = w.clock(); require(not clocks or clocks[-1] is not None and value >= clocks[-1],
                                   'Actual monotonic clock rewound or failed clock was retried')
        clocks.append(value); return value
    def gate(at_stage, at_sequence):
        if (stage, sequence) != (at_stage, at_sequence): return False
        require(not w.active, 'Private progress callback retained authority FDs')
        message = struct.pack('<4Q', int.from_bytes(b'WGATE001', 'little'), stage, sequence, worker)
        w.output(3, message)
        def signal_return():
            returned = w.take('rt_sigreturn', '{mask=[]}', value='any')
            require(returned.get('paired_gate_signal')
                    and returned['start'] not in consumed_signal_returns,
                    'Gate consumed an unpaired or repeated signal return')
            consumed_signal_returns.append(returned['start'])
        while True:
            if w.peek() and w.peek()['name'] == 'rt_sigreturn': signal_return(); continue
            call = w.take('read', value='any'); fd, data, wanted, value = io_fields(call)
            require(fd == 4 and wanted == 1, 'Gate did not read its own ACK capability')
            if value == -1:
                require(call.get('actual_signal_interrupted'), 'Unverified gate EINTR'); continue
            require(value == 1 and data == b'\x01', 'Gate ACK extent/value differs'); break
        if w.peek() and w.peek()['name'] == 'rt_sigreturn': signal_return()
        gates.append((stage, sequence)); return expected_signal is not None
    w.paid_begin()
    w.host(parent, context_bound); require(clock() < deadline, 'Initial real task deadline already expired')
    w.paid_checkpoint()
    n = header['progress_count']; cancelled = False; expired = False; failed_host = False; clock_panic = False
    require(not closed_fd or n == 1, 'Closed parent fixture moved to another progress boundary')
    for number in range(1, n + 1):
        w.tid_call()
        if gate(3, number): cancelled = True; break
        timestamp = clock()
        if timestamp is None: clock_panic = True; break
        if timestamp >= deadline:
            expired = True; break
        signalled = gate(4, number)
        if closed_fd:
            # The diagnostic adapter really closes the freshly opened parent;
            # neither fstat nor the HIA cleanup is given an injected errno.
            w.tid_call(); w.stream('AT_FDCWD', b'boot', READ_FLAGS, context_bound, b'boot-identity\n')
            fd = w.opened('AT_FDCWD', PARENT, PARENT_FLAGS); w.closed(fd)
            broken = w.take('fstat', value=-1); fields = arguments(broken['args'])
            require(len(fields) == 2 and fields[0] == str(fd) and re.fullmatch(HEX, fields[1])
                    and broken['result'] == '-1 EBADF (Bad file descriptor)', 'No real fstat on the actually closed parent FD')
            cleanup = w.take('close', str(fd), -1)
            require(cleanup['result'] == '-1 EBADF (Bad file descriptor)' and not w.active,
                    'Actual invalid-FD cleanup or first-error ordering differs')
            failed_host = True; break
        w.host(parent, context_bound)
        signalled = gate(5, number) or signalled
        if signalled: cancelled = True; break
        timestamp = clock()
        if timestamp is None: clock_panic = True; break
        if timestamp >= deadline:
            expired = True; break
        w.paid_checkpoint()
    if not cancelled and not expired and not failed_host and not clock_panic: w.tid_call()
    if not clock_panic: w.host(parent, context_bound)
    final_host_ran = not clock_panic
    if not cancelled and not expired and not failed_host and not clock_panic:
        gate(7, n); final_time = clock()
        if final_time is None: clock_panic = True
        else:
            expired = final_time >= deadline
            require((not expired) == (header['domain'] == 0), 'Final resource-before-deadline outcome differs')
    elif cancelled:
        require(header['domain'] == 2 and header['code'] == expected_signal, 'Actual cancel/stop error priority differs')
    if expired:
        require(header['domain'] == 2 and header['code'] == 2, 'Actual deadline expiration differs from native refusal')
    if clock_panic: w.paid_drop()
    else: w.paid_finish()
    paid = decoded['paid']; account = paid['owner']; binding = paid['binding']; epoch = paid['epoch']
    cpu = w.paid_cpu_samples
    require(len(cpu) == binding[4] + (2 if clock_panic else 3)
            and len(p.paid_wall_samples) == 1 and len(w.paid_wall_samples) == binding[4]+3,
            'Actual complete Paid clock roster')
    require(paid['global_poison'] == paid['request_poison'] == 0,
            'Work error outside a mutex claimed poison')
    if clock_panic:
        expected_account = [int.from_bytes(b'PCOWN001','little')] + [0] * 63
        expected_account[19:23] = [1, worker, 2, 1]
        require(account == expected_account,
                'Work panic must retain Unknown account output and actual worker identity')
        require(binding == [0,4,binding[4]+2,2,binding[4],3,0,0,1,1]
                and paid['meta'] == [0,1,binding[4]+2,4,0,0,0,0],
                'Work panic did not consume the one private Operation through Drop')
        require(epoch[1] == 1, 'Work panic did not make the original account unavailable')
    else:
        require(account[4] == account[6] == account[8] == account[10] == account[12] == 1,
                'Known native CPU accounting required by this trace profile')
        require(account[2:4] == [0,0] and account[7] == 0 and account[14:20] == [0]*6
                and account[22:] == [0]*42 and account[5] == account[9],
                'Normal same-worker receipt claims panic, scoped workers or failed settlement')
        require(binding == [0,3,binding[4]+2,2,binding[4],0,0,0,1,1]
                and paid['meta'] == [0,0,binding[4]+2,3,0,0,0,0],
                'Normal private method did not retire exactly once without a panic')
        require(account[9] == cpu[-1]-cpu[0] and account[11] == cpu[-2]-cpu[0]
                and account[13] == cpu[-1]-cpu[-2] and account[9] == account[11]+account[13],
                'Raw CLOCK3 does not equal full/charged/unique residual receipt')
        require(epoch[1] == 0, 'Normal Work path made the account unavailable')
    require(epoch[6:9] == [0,0,0]
            and epoch[4]*1000000000+epoch[5] == w.paid_wall_samples[-1],
            'Actual settlement watermark or remaining account authority differs')
    w.take('exit', '0', None); require(w.peek() is None and not w.active, 'Extra child calls after final cleanup')
    if clock_panic:
        require(clock_ordinal == len(clocks) and clocks[-1] is None and header['domain'] == 4
                and header['post_checks'] == header['aggregate_samples'] == 0
                and decoded['host_after'] == [0] * 32, 'Panic performed ordinary after-sampling or another clock retry')
    else:
        require(clock_ordinal is None, 'Expected actual controlled clock failure was never reached')
        p.sample(parent, context_bound)
        require(p.checks == header['post_checks'] == 5 and p.samples == header['aggregate_samples'] == 2,
                'Final complete resource sampling differs')
    require(w.checks + int(failed_host) == header['worker_host_calls'] and len(clocks) == header['alive_clocks'],
            'Actual complete Host/clock/sample counts disagree with the native receipt')
    require(len(gates) == header['gates'] and len(signals) == int(cancelled)
            and len(consumed_signal_returns) == len(signals), 'Gate/signal facts differ from native result')
    require(all(r[25:27] == [0, 0] for r in (decoded['host_before'], decoded['host_after'], decoded['host_worker_final'])),
            'Standalone observer clocks were retained')
    require(decoded['host_before'][8:14] == [10, 20, 3, 40, 64, 2] and decoded['host_before'][23] == main,
            'Actual baseline read bytes/TID do not match receipt values')
    if not clock_panic:
        require(decoded['host_after'][8:14] == [10, 20, 3, 40, 64, 2]
                and decoded['host_after'][14:18] == [0, 0, 0, 0] and decoded['host_after'][23] == main,
                'Actual final read bytes/TID do not match receipt values')
    if final_host_ran:
        require(decoded['host_worker_final'][4] == 3 + w.checks and decoded['host_worker_final'][23] == worker,
                'Receipt TID/checkpoint lineage differs')
    else:
        require(decoded['host_worker_final'] == [0] * 32, 'Panic claimed an unexecuted final Host method')
    require(decoded['host_worker_final'][22] == int(failed_host), 'Actual failed-FD cleanup count differs')
    product_start = 2304 + n * 40
    for raw in (stdout[:512], stdout[512:1024], stdout[1024:1280], stdout[1280:2304], stdout[2304:product_start], stdout[product_start:]):
        p.output(1, raw)
    terminal = p.take('exit_group', str(0 if header['domain'] == 0 else 64 + header['domain']), None)
    require(p.peek() is None and not p.active, 'Unaccounted main calls or leaked authority FD')
    # strace -qq may omit every exit notification. Any one it does emit must
    # describe this actual thread's already completed terminal syscall once.
    notified = set()
    for tid, code, line in exits:
        require(tid in (main, worker) and tid not in notified,
                'Exit notification has an unknown or repeated thread identity')
        ended = death if tid == worker else terminal
        expected = 0 if tid == worker or header['domain'] == 0 else 64 + header['domain']
        require(code == expected and line > ended['end'],
                'Exit notification precedes or differs from the actual terminal syscall')
        require(all(c['end'] < line for c in calls if c['tid'] == tid),
                'Thread executes a syscall after its exit notification')
        notified.add(tid)
    return {'status': 'PASS', 'schema': 'trnm.hia.paid-work-same-worker-real-trace.v1', 'syscalls': len(calls),
        'actual_main_tid': main, 'actual_worker_tid': worker, 'worker_lifetimes': 1, 'actual_shared_join_calls': len(joined),
        'full_fresh_checks': p.checks + w.checks, 'worker_fresh_checks': w.checks,
        'resource_samples': p.samples, 'actual_clock1_calls': len(clocks) + 1 + len(p.paid_wall_samples) + len(w.paid_wall_samples),
        'actual_clock3_calls': len(cpu), 'paid_checkpoints': binding[4],
        'raw_cpu_samples_ns': cpu, 'full_cpu_known': account[8] == 1, 'full_cpu_ns': account[9], 'charged_ns': account[11], 'unique_residual_ns': account[13],
        'actual_same_thread_paid_clock_identity': True,
        'actual_host_observer_clocks': 0, 'progress_points': n, 'signals': signal_rows,
        'all_resource_FDs_closed': True, 'closed_parent_fault_executed': failed_host,
        'optional_exit_notifications': len(exits), 'exit_notification_lifetimes_checked': True,
        'private_fault_profile': fault_profile, 'actual_clock_failure_ordinal': clock_ordinal,
        'original_panic_boundary_observed': clock_panic, 'sealed_input_bytes': len(stdin), 'stdout_bytes': len(stdout),
        'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'all_syscalls_consumed': True,
        'production_fixed_parent_authority': False, 'whole_Node_or_public_intake_closed': False, 'finite_paid_work_checkpoints_complete': True,
        'actual_original_4s_deadline_ns': deadline, 'actual_deadline_expired': expired}
