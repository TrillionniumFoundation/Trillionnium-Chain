"""Private tiny three-record transport, never model export or native authority."""
import json
import math
import os
import select
import stat
import struct
import threading
import time

SCHEMA = 'trnm-tiny-evidence-pipe-v1'
KINDS = ('tiny-payload', 'inner-supervisor', 'payload-supervisor')
MAX_FRAME, MAX_TOTAL, READ_SIZE = 65536, 262144, 4096
_TOKEN = object()


class EvidencePipeError(ValueError): pass


def require(value, code):
    if not value: raise EvidencePipeError(code)


def _add(state, size):
    state[1] += size
    require(state[1] <= MAX_FRAME, 'evidence-pipe-json-byte-bound')


def _string(value, state):
    # len first: never encode/copy an arbitrarily large string or key.
    require(type(value) is str and len(value) <= MAX_FRAME, 'evidence-pipe-json-byte-bound')
    _add(state, 2)
    for character in value:  # At most64KiB total characters across this traversal.
        number = ord(character)
        _add(state, 2 if character in '"\\\b\f\n\r\t' else
             1 if 32 <= number < 127 else 6 if number <= 65535 else 12)


def _tree(value, depth=0, state=None, *, snapshot=False):
    if state is None: state = [0, 0]
    state[0] += 1
    require(depth <= 16 and state[0] <= 8192, 'evidence-pipe-json-bound')
    if type(value) is dict:
        require(len(value) <= 8192, 'evidence-pipe-json-bound')
        _add(state, 2)
        private = {} if snapshot else None
        for index, (key, item) in enumerate(value.items()):
            if index: _add(state,1)
            require(type(key) is str, 'evidence-pipe-json-key')
            _string(key,state); _add(state,1)
            captured = _tree(item,depth+1,state,snapshot=snapshot)
            if snapshot: private[key] = captured
        return private
    elif type(value) is list:
        require(len(value) <= 8192, 'evidence-pipe-json-bound')
        _add(state, 2)
        private = [] if snapshot else None
        for index, item in enumerate(value):
            if index: _add(state,1)
            captured = _tree(item,depth+1,state,snapshot=snapshot)
            if snapshot: private.append(captured)
        return private
    elif type(value) is str:
        _string(value,state)
    else:
        require(type(value) in (int, float, bool, type(None)) and
            (type(value) is not float or math.isfinite(value)), 'evidence-pipe-json-value')
        if type(value) is int:
            require(value.bit_length() <= 256, 'evidence-pipe-json-integer-bound')
            _add(state, (value.bit_length()*30103)//100000+1+(value < 0))
        else:
            _add(state, 32 if type(value) is float else 5 if value is False else 4)
    return value  # Exact immutable leaf; no caller-owned dict/list escapes.


def _pid(value): return type(value) is int and 0 < value < 2**31
def _member(value):
    return type(value) is str and len(value) <= 4096 and value.startswith('0::/') and value.count('\n') == 1 and value.endswith('\n')


def _result(value):
    require(type(value) is dict and value.get('outcome') in ('success', 'failed') and
        type(value.get('waited_child_reaped')) is bool and type(value.get('child_spawned')) is bool and
        type(value.get('cleanup_method')) is str and len(value['cleanup_method']) <= 128 and
        value.get('budget') == dict(wall_seconds=2, rss_bytes=64*1024**2) and
        type(value['budget'].get('wall_seconds')) is int and type(value['budget'].get('rss_bytes')) is int and
        'controlled_kernel_spawn' not in value, 'evidence-pipe-result-schema')


def _record(kind, data):
    require(kind in KINDS and type(data) is dict, 'evidence-pipe-record-schema')
    _tree(data)
    if kind == KINDS[0]:
        require(set(data) == {'pid', 'ppid', 'membership', 'anonymous_bytes', 'iterations', 'checksum',
            'own_peak_rss_kib', 'model_loaded', 'descendants_spawned'} and _pid(data['pid']) and
            _pid(data['ppid']) and _member(data['membership']) and type(data['anonymous_bytes']) is int and
            data['anonymous_bytes'] == 1048576 and type(data['iterations']) is int and
            0 <= data['iterations'] <= 100000 and type(data['checksum']) is int and
            0 <= data['checksum'] < 2**32 and type(data['own_peak_rss_kib']) is int and
            0 <= data['own_peak_rss_kib'] < 2**64 and data['model_loaded'] is False and
            data['descendants_spawned'] is False, 'evidence-pipe-payload-schema')
    elif kind == KINDS[1]:
        require(set(data) == {'result', 'owned_child_pid', 'supervisor_pid'} and
            _pid(data['supervisor_pid']), 'evidence-pipe-inner-schema')
        _result(data['result'])
        require(_pid(data['owned_child_pid']) if data['result']['child_spawned'] else
            data['owned_child_pid'] is None, 'evidence-pipe-inner-child')
    else:
        require(set(data) == {'pid', 'ppid', 'membership_before', 'membership_after', 'result', 'model_loaded'} and
            _pid(data['pid']) and _pid(data['ppid']) and _member(data['membership_before']) and
            _member(data['membership_after']) and data['model_loaded'] is False, 'evidence-pipe-wrapper-schema')
        _result(data['result'])


def encode_frame(kind, data):
    try:
        # One shared total budget, incremental containers, no eager items/deepcopy.
        envelope = _tree(dict(schema=SCHEMA, kind=kind, data=data), snapshot=True)
    except RuntimeError:
        raise EvidencePipeError('evidence-pipe-json-input-mutated') from None
    _record(envelope['kind'], envelope['data'])  # Only the private snapshot below.
    raw = json.dumps(envelope, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode()
    require(1 <= len(raw) <= MAX_FRAME and (envelope['kind'] != KINDS[0] or len(raw)+4 <= 4096),
            'evidence-pipe-frame-bound')
    return struct.pack('<I', len(raw))+raw


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'evidence-pipe-duplicate-key')
        result[key] = value
    return result


def _nonfinite(value): raise EvidencePipeError('evidence-pipe-nonfinite')


class _TinyFrames:
    def __init__(self):
        self.header, self.body = bytearray(), bytearray()
        self.expected = None; self.index = self.received = 0
        self.records = [None, None, None]  # Fixed evidence destinations, no queue.
        self.failure = None; self.error_ns = 0; self.fragment = b''

    def bad(self, code, fragment=b''):
        if self.failure is None:
            self.failure = code; self.error_ns = time.monotonic_ns()
            self.fragment = bytes(fragment[:READ_SIZE])
        raise EvidencePipeError(self.failure)

    def feed(self, raw):
        if self.failure is not None: raise EvidencePipeError(self.failure)
        if type(raw) is not bytes or len(raw) > READ_SIZE:
            self.bad('evidence-pipe-read-bound')
        if self.received+len(raw) > MAX_TOTAL: self.bad('evidence-pipe-total-bound', raw)
        self.received += len(raw); offset = 0
        while offset < len(raw):  # At most4096 consumed bytes, no observation retry.
            if self.index == 3: self.bad('evidence-pipe-extra-frame', raw[offset:])
            target = self.header if self.expected is None else self.body
            limit = 4 if self.expected is None else self.expected
            size = min(limit-len(target), len(raw)-offset)
            target.extend(raw[offset:offset+size]); offset += size
            if len(target) != limit: continue
            if self.expected is None:
                self.expected = struct.unpack('<I', self.header)[0]
                if not 1 <= self.expected <= MAX_FRAME: self.bad('evidence-pipe-frame-bound', self.header)
                self.header.clear(); continue
            try:
                value = json.loads(self.body.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_nonfinite)
                require(type(value) is dict and set(value) == {'schema','kind','data'} and
                    value['schema'] == SCHEMA and value['kind'] == KINDS[self.index], 'evidence-pipe-order-schema')
                _record(value['kind'], value['data'])
                self.records[self.index] = value['data']
            except (ValueError, RecursionError, OverflowError) as error:
                self.bad(str(error) if type(error) is EvidencePipeError else 'evidence-pipe-invalid-json', self.body)
            self.body.clear(); self.expected = None; self.index += 1

    def complete(self):
        if self.failure is not None: raise EvidencePipeError(self.failure)
        if self.index != 3 or self.header or self.body or self.expected is not None:
            self.bad('evidence-pipe-truncated-or-missing', self.body or self.header)


class _EvidencePipeWriter:
    """Borrows stdout1 only; never owns/closes it or claims an exit receipt."""
    def __init__(self, token, deadline_ns, role):
        from llm_runtime_kernel_owned import _native_rlock
        require(token is _TOKEN and role in ('payload', 'supervisor') and
            type(deadline_ns) is int and 0 < deadline_ns-time.monotonic_ns() <= 8*10**9,
            'evidence-pipe-writer-interface')
        self._pid, self._thread, self._busy = os.getpid(), threading.current_thread(), _native_rlock()
        self.deadline_ns, self.role, self.sent, self.failed = deadline_ns, role, 0, False
        import fcntl
        self.signature = self._signature()
        require(stat.S_ISFIFO(self.signature[2]) and fcntl.fcntl(1, fcntl.F_GETPIPE_SZ) >= 4096,
            'evidence-pipe-writer-fifo')
        self._validate()

    def _signature(self):
        value = os.fstat(1)
        return value.st_dev, value.st_ino, value.st_mode

    def _validate(self):
        import fcntl
        flags = fcntl.fcntl(1, fcntl.F_GETFL)
        require(os.getpid() == self._pid and threading.current_thread() is self._thread and
            self._signature() == self.signature and flags & os.O_ACCMODE == os.O_WRONLY and
            flags & os.O_NONBLOCK and not self.failed and time.monotonic_ns() < self.deadline_ns,
            'evidence-pipe-writer-owner-or-deadline')

    def fileno(self):
        self._validate()
        return 1

    def __enter__(self): return self
    def __exit__(self, *args): return False  # Borrowed1/2 close only at process exit.

    def emit(self, kind, data):
        require(os.getpid() == self._pid and threading.current_thread() is self._thread,
            'evidence-pipe-writer-thread')
        with self._busy:
            require(self._busy._recursion_count() == 1, 'evidence-pipe-writer-reentry')
            try:
                self._validate()
                expected = (KINDS[0],) if self.role == 'payload' else KINDS[1:]
                require(self.sent < len(expected) and kind == expected[self.sent], 'evidence-pipe-writer-order')
                raw = encode_frame(kind, data); offset = 0
                poll = select.poll(); poll.register(1, select.POLLOUT)
                for _ in range(2*(MAX_FRAME+4)):
                    self._validate()
                    try:
                        size = os.write(1, raw[offset:offset+4096])
                        require(size > 0, 'evidence-pipe-write-zero'); offset += size
                    except (BlockingIOError, InterruptedError):
                        poll.poll(max(1,min(50,(self.deadline_ns-time.monotonic_ns()+999999)//1000000)))
                    if offset == len(raw): self.sent += 1; return
                raise EvidencePipeError('evidence-pipe-write-attempt-bound')
            except BaseException:
                self.failed = True
                raise


def borrow_evidence_stdout(deadline_ns, role):
    return _EvidencePipeWriter(_TOKEN, deadline_ns, role)
