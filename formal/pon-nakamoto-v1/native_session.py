"""Bounded private compute cache; the existing Ledger alone owns durable chain state.

Replies are checked against exact predecessor bytes and independently rehashed. A lost
reply, rejected transition or parent/backend change discards the cache, never the ledger.
There is no listener, persistent session database, permission token or reference fallback.
"""
from __future__ import annotations

import copy
import json
import math
import os
import re
import selectors
import signal
import struct
import subprocess
import time
from pathlib import Path

from contract_wire import H, NETWORK, PARAMETER_HASH, PARAMS, canonical, state_root, unique

MAX_FRAME = 16 * 1024 * 1024
MAX_STDERR = 64 * 1024
METRIC_COUNTS = {
    'workers', 'workers_spawned', 'signature_verifications', 'reexecuted', 'speculative',
    'committed_without_replay', 'serial_conflict_batches', 'peak_inflight', 'commitment_nodes',
}
METRIC_TIMES = {'state_transition_ns', 'state_root_ns'}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def strict_hex(value, maximum, *, exact=None):
    require(isinstance(value, str) and len(value) <= 2 * maximum
            and len(value) % 2 == 0 and re.fullmatch('[0-9a-f]*', value) is not None,
            'SESSION_HEX')
    raw = bytes.fromhex(value)
    require(exact is None or len(raw) == exact, 'SESSION_HEX')
    return raw


class FramedProcess:
    """One owned child with simultaneous pipe draining and bounded cumulative stderr."""

    def __init__(self, argv, *, timeout=30, limit=MAX_FRAME):
        require(bool(argv) and type(timeout) in {int, float} and math.isfinite(timeout)
                and timeout > 0 and type(limit) is int and 1 <= limit <= MAX_FRAME,
                'SESSION_ARGUMENT')
        self.timeout, self.limit, self.closed = timeout, limit, False
        self.stderr = bytearray()
        self.bytes_sent = self.bytes_received = 0
        try:
            self.child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, start_new_session=True)
        except OSError as error:
            raise ValueError('NATIVE_SESSION_UNAVAILABLE') from error
        try:
            for stream in (self.child.stdin, self.child.stdout, self.child.stderr):
                os.set_blocking(stream.fileno(), False)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            os.killpg(self.child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            for stream in (self.child.stdin, self.child.stdout, self.child.stderr):
                try:
                    stream.close()
                except OSError:
                    pass
        try:
            self.child.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            raise ValueError('SESSION_REAP_TIMEOUT') from error

    def exchange(self, payload):
        require(not self.closed, 'SESSION_CLOSED')
        require(isinstance(payload, bytes) and 1 <= len(payload) <= self.limit, 'SESSION_FRAME_LIMIT')
        frame = struct.pack('>I', len(payload)) + payload
        sent, received, expected = 0, bytearray(), None
        deadline = time.monotonic() + self.timeout
        selector = selectors.DefaultSelector()
        selector.register(self.child.stdin, selectors.EVENT_WRITE, 'stdin')
        selector.register(self.child.stdout, selectors.EVENT_READ, 'stdout')
        selector.register(self.child.stderr, selectors.EVENT_READ, 'stderr')
        try:
            while True:
                left = deadline - time.monotonic()
                require(left > 0, 'SESSION_TIMEOUT')
                for event, _ in selector.select(min(left, .05)):
                    stream, name = event.fileobj, event.data
                    if name == 'stdin':
                        try:
                            n = os.write(stream.fileno(), memoryview(frame)[sent:sent + 65536])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError as error:
                            raise ValueError('SESSION_BROKEN_PIPE') from error
                        sent += n
                        self.bytes_sent += n
                        if sent == len(frame):
                            selector.unregister(stream)
                    else:
                        budget = MAX_STDERR - len(self.stderr) + 1 if name == 'stderr' else self.limit + 5 - len(received)
                        try:
                            chunk = os.read(stream.fileno(), min(65536, budget))
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(stream)
                            require(name != 'stdout', 'SESSION_EOF')
                            continue
                        if name == 'stderr':
                            self.stderr.extend(chunk)
                            require(len(self.stderr) <= MAX_STDERR, 'SESSION_STDERR_LIMIT')
                        else:
                            received.extend(chunk)
                            self.bytes_received += len(chunk)
                            require(len(received) <= self.limit + 4, 'SESSION_FRAME_LIMIT')
                            if expected is None and len(received) >= 4:
                                expected = struct.unpack('>I', received[:4])[0]
                                require(1 <= expected <= self.limit, 'SESSION_FRAME_LIMIT')
                            require(expected is None or len(received) <= expected + 4, 'SESSION_EXTRA_OUTPUT')
                if expected is not None and len(received) == expected + 4:
                    require(sent == len(frame), 'SESSION_EARLY_RESPONSE')
                    return bytes(received[4:])
        except BaseException:
            self.close()
            raise
        finally:
            selector.close()


class NativeExecutionSession:
    def __init__(self, binary, *, timeout=30):
        path = Path(binary)
        require(path.is_file(), 'NATIVE_SESSION_UNAVAILABLE')
        self.binary, self.timeout = path.resolve(), timeout
        self.process = self.state = self.root = self.last = None
        self.state_bytes = self.last_input = None
        self.sequence, self.reset_count = 0, 0

    def close(self):
        process, self.process = self.process, None
        self.state = self.root = self.last = None
        self.state_bytes = self.last_input = None
        if process is not None:
            process.close()

    def _exchange(self, message):
        try:
            raw = self.process.exchange(canonical(message))
            result = json.loads(raw, object_pairs_hook=unique)
            require(isinstance(result, dict), 'SESSION_JSON')
            canonical(result)  # Reject floats, NaN, excessive integers and unsupported nested values.
            return result
        except (ValueError, TypeError, UnicodeError, RecursionError) as error:
            self.close()
            raise ValueError('SESSION_JSON_OR_TRANSPORT: ' + str(error)) from error

    def _open(self, state, *, checked_root=None):
        self.close()
        self.process = FramedProcess([str(self.binary)], timeout=self.timeout)
        try:
            root = state_root(state).hex() if checked_root is None else checked_root
            result = self._exchange({'op': 'open', 'network': NETWORK.hex(),
                                     'parameters': PARAMETER_HASH.hex(), 'state': state, 'root': root})
            require(type(result.get('sequence')) is int and result == {
                'op': 'opened', 'network': NETWORK.hex(), 'parameters': PARAMETER_HASH.hex(),
                'root': root, 'sequence': 0}, 'SESSION_OPEN_CONTEXT')
            self.state, self.root, self.sequence = copy.deepcopy(state), root, 0
            self.state_bytes = canonical(state)
            self.reset_count += 1
        except BaseException:
            self.close()
            raise

    def execute(self, state, transactions, height, miner, parent, workers=1):
        require(type(workers) is int and workers in {1, 2, 4, 8}, 'WORKERS')
        require(type(height) is int and 0 <= height < 2**64, 'SESSION_HEIGHT')
        require(isinstance(miner, bytes) and len(miner) == 32
                and isinstance(parent, bytes) and len(parent) == 32, 'SESSION_CONTEXT')
        require(isinstance(transactions, (list, tuple)) and len(transactions) <= PARAMS['max_transactions']
                and all(isinstance(tx, bytes) and len(tx) <= PARAMS['max_transaction_bytes']
                        for tx in transactions), 'SESSION_TRANSACTIONS')
        state_bytes = canonical(state)
        if self.state_bytes == state_bytes:
            root = self.root
        elif self.last_input is not None and self.last_input[0] == state_bytes:
            root = self.last_input[1]
        else:
            root = state_root(state).hex()
        logical = {'root': root, 'transactions': [tx.hex() for tx in transactions],
                   'height': height, 'miner': miner.hex(), 'parent': parent.hex(), 'workers': workers}
        fingerprint = H('native-session-request', canonical(logical))
        if self.last is not None and self.last[0] == fingerprint:
            value = copy.deepcopy(self.last[1])
            value[2].update(request_cache_hit=True, bridge_request_bytes=0, bridge_response_bytes=0,
                            state_transition_ns='0', state_root_ns='0', workers_spawned=0,
                            signature_verifications=0, speculative=0, reexecuted=0,
                            committed_without_replay=0, serial_conflict_batches=0, peak_inflight=0)
            return value  # Cached facts are not additional verification, work or communication.
        if self.process is None or self.root != root:
            self._open(state, checked_root=root)  # Exact canonical bytes, never True == 1 equality.
        before_sent, before_received = self.process.bytes_sent, self.process.bytes_received
        try:
            result = self._exchange(dict(logical, op='execute', sequence=self.sequence))
            if result.get('op') == 'rejected':
                require(set(result) == {'op', 'error', 'sequence', 'root'}
                        and type(result['sequence']) is int and result['sequence'] == self.sequence
                        and result['root'] == root and isinstance(result['error'], str),
                        'SESSION_REJECT_CONTEXT')
                raise ValueError('NATIVE_' + result['error'])
            require(set(result) == {'op', 'sequence', 'predecessor', 'root', 'changes',
                                    'receipts', 'metrics', 'scope'}, 'SESSION_FIELDS')
            require(result['op'] == 'executed' and type(result['sequence']) is int
                    and result['sequence'] == self.sequence + 1 and result['predecessor'] == root,
                    'SESSION_PREDECESSOR')
            require(result['scope'] == 'native-compute-cache-not-chain-authority', 'SESSION_SCOPE')
            strict_hex(result['root'], 32, exact=32)
            require(isinstance(result['changes'], list)
                    and len(result['changes']) <= PARAMS['max_state_keys'], 'SESSION_CHANGE_LIMIT')
            next_state, previous = copy.deepcopy(state), None
            for change in result['changes']:
                require(isinstance(change, dict) and set(change) == {
                    'key', 'before_present', 'before', 'after_present', 'after'}, 'SESSION_DELTA')
                key, bp, ap = change['key'], change['before_present'], change['after_present']
                require(isinstance(key, str) and (previous is None or key > previous)
                        and type(bp) is bool and type(ap) is bool, 'SESSION_DELTA')
                previous = key
                require(bp == (key in state)
                        and (canonical(state[key]) == canonical(change['before']) if bp else change['before'] is None),
                        'SESSION_BEFORE')
                if ap:
                    next_state[key] = change['after']
                else:
                    require(change['after'] is None, 'SESSION_DELTA')
                    next_state.pop(key, None)
            require(state_root(next_state).hex() == result['root'], 'SESSION_ROOT')
            # Mandatory expiry receipts precede transaction receipts, including empty blocks.
            # Derive their exact order from the unchanged predecessor, not a reply counter.
            due = []
            for name, value in state.items():
                if name.startswith(('task:', 'quota:', 'release:')):
                    require(isinstance(value, dict) and type(value.get('remaining')) is int
                            and type(value.get('deadline')) is int, 'SESSION_EXPIRY_STATE')
                    if value['remaining'] > 0 and value['deadline'] <= height:
                        due.append((value['deadline'], name))
            expiries = [canonical({'expiry': name}) for _, name in
                        sorted(due)[:PARAMS['mandatory_expiry_per_block']]]
            require(isinstance(result['receipts'], list)
                    and len(result['receipts']) == len(transactions) + len(expiries), 'SESSION_RECEIPTS')
            receipts = [strict_hex(raw, PARAMS['max_transaction_bytes']) for raw in result['receipts']]
            require(receipts[:len(expiries)] == expiries, 'SESSION_EXPIRY_RECEIPTS')
            metrics = result['metrics']
            require(isinstance(metrics, dict) and set(metrics) == METRIC_COUNTS | METRIC_TIMES,
                    'SESSION_METRICS')
            require(all(type(metrics[k]) is int and 0 <= metrics[k] < 2**64 for k in METRIC_COUNTS),
                    'SESSION_METRICS')
            require(all(isinstance(metrics[k], str) and re.fullmatch('0|[1-9][0-9]{0,38}', metrics[k])
                        and int(metrics[k]) < 2**128 for k in METRIC_TIMES), 'SESSION_METRICS')
            require(metrics['workers'] == workers and metrics['workers_spawned'] <= workers
                    and metrics['signature_verifications'] == len(transactions)
                    and metrics['reexecuted'] <= len(transactions)
                    and metrics['commitment_nodes'] <= max(0, 2 * len(next_state) - 1), 'SESSION_METRICS')
            metrics = dict(metrics, bridge_request_bytes=self.process.bytes_sent - before_sent,
                           bridge_response_bytes=self.process.bytes_received - before_received,
                           session_resets=self.reset_count, request_cache_hit=False, mandatory_receipts=len(expiries))
            self.state, self.root, self.sequence = next_state, result['root'], result['sequence']
            self.state_bytes, self.last_input = canonical(next_state), (state_bytes, root)
            value = (copy.deepcopy(next_state), receipts, metrics)
            self.last = (fingerprint, copy.deepcopy(value))
            return value
        except BaseException:
            self.close()  # An unknown advanced cache is discarded; authoritative state is untouched.
            raise
