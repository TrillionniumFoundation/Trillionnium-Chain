"""Bounded, caller-clock request batching for the grouped research operator.

This is an in-memory scheduler, not request authentication, a durable replay owner,
model adoption, or a service guarantee. The caller must drive ``advance`` at
``next_wakeup_ns`` and deliver actual completion/cancellation observations. A late
scheduler invocation records expiry instead of inventing an earlier dispatch.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

MAX_U64 = (1 << 64) - 1
MAX_BATCH = 64
SCHEMA = 'pon-grouped-request-batch-research-v0'


def require(ok, code):
    if not ok:
        raise ValueError(code)


def uint(value, code):
    require(type(value) is int and 0 <= value <= MAX_U64, code)
    return value


def digest(value, code='IDENTITY'):
    require(isinstance(value, str) and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value), code)
    return value


def commitment(domain, value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    name = domain.encode()
    return hashlib.sha256(b'pon.grouped.scheduler.v0\0' + len(name).to_bytes(8, 'big') + name +
                          len(raw).to_bytes(8, 'big') + raw).hexdigest()


@dataclass(frozen=True, slots=True)
class Request:
    request_id: str
    scope: str
    model_version: str
    input_sha256: str
    arrival_ns: int
    deadline_ns: int

    def validate(self):
        for value in (self.request_id, self.scope, self.model_version, self.input_sha256):
            digest(value)
        uint(self.arrival_ns, 'ARRIVAL')
        uint(self.deadline_ns, 'DEADLINE')
        require(self.arrival_ns < self.deadline_ns, 'INTERVAL')
        return self

    def identity(self):
        return dict(request_id=self.request_id, scope=self.scope,
                    model_version=self.model_version, input_sha256=self.input_sha256,
                    arrival_ns=self.arrival_ns, deadline_ns=self.deadline_ns)


@dataclass(frozen=True, slots=True)
class Batch:
    batch_id: str
    requests: tuple[Request, ...]
    dispatched_ns: int
    reason: str

    def as_dict(self):
        return {'batch_id': self.batch_id, 'request_ids': [r.request_id for r in self.requests],
                'dispatched_ns': self.dispatched_ns, 'reason': self.reason,
                'queue_wait_ns': [self.dispatched_ns - r.arrival_ns for r in self.requests],
                'earliest_original_deadline_ns': min(r.deadline_ns for r in self.requests)}


class BatchPlanner:
    """One finite ordered intake; never pads, extends a deadline, or drops an outcome.

    ``service_reserve_ns`` is a caller-provided scheduling allowance, not a proved
    runtime bound. Completion always checks the original deadline again. A scope
    or model change flushes the current queue, so it cannot silently share one
    encoder invocation across incompatible owners or representations.
    """

    def __init__(self, *, max_batch=64, max_wait_ns, service_reserve_ns=0,
                 max_requests=4096):
        require(type(max_batch) is int and 1 <= max_batch <= MAX_BATCH, 'BATCH_LIMIT')
        require(type(max_requests) is int and max_batch <= max_requests <= 65536,
                'SESSION_LIMIT')
        uint(max_wait_ns, 'WAIT_LIMIT')
        uint(service_reserve_ns, 'RESERVE')
        self.max_batch = max_batch
        self.max_wait_ns = max_wait_ns
        self.service_reserve_ns = service_reserve_ns
        self.max_requests = max_requests
        self._now = 0
        self._pending = []
        self._seen = {}
        self._dispatched = {}
        self._terminal = {}
        self._batches = []
        self._events = []

    def _clock(self, now_ns):
        uint(now_ns, 'CLOCK')
        require(now_ns >= self._now, 'CLOCK_REWIND')
        self._now = now_ns

    def _record(self, request, status, now_ns, **extra):
        event = {'request_id': request.request_id, 'status': status, 'observed_ns': now_ns,
                 'original_deadline_ns': request.deadline_ns, **extra}
        self._events.append(event)
        return dict(event)

    def _finish(self, request, status, now_ns, **extra):
        require(request.request_id not in self._terminal, 'TERMINAL_ALREADY_RECORDED')
        event = self._record(request, status, now_ns, **extra)
        self._terminal[request.request_id] = dict(event)
        return dict(event)

    @property
    def batches(self):
        return tuple(self._batches)

    @property
    def events(self):
        return tuple(dict(event) for event in self._events)

    @property
    def pending_ids(self):
        return tuple(r.request_id for r in self._pending)

    @property
    def next_wakeup_ns(self):
        if not self._pending:
            return None
        # Python integer arithmetic prevents overflow before saturating at u64.
        due = min(min(MAX_U64, r.arrival_ns + self.max_wait_ns,
                      max(r.arrival_ns, r.deadline_ns - self.service_reserve_ns))
                  for r in self._pending)
        return max(self._now, due)

    def _seal(self, now_ns, reason):
        if not self._pending:
            return []
        requests = tuple(self._pending)
        require(all(now_ns < r.deadline_ns for r in requests), 'SEAL_EXPIRED')
        value = {'schema': SCHEMA, 'ordinal': len(self._batches), 'dispatched_ns': now_ns,
                 'reason': reason, 'requests': [r.identity() for r in requests]}
        batch = Batch(commitment('batch', value), requests, now_ns, reason)
        self._pending.clear()
        self._batches.append(batch)
        for request in requests:
            self._dispatched[request.request_id] = batch
            self._record(request, 'dispatched', now_ns, batch_id=batch.batch_id)
        return [batch]

    def advance(self, now_ns, *, flush=False):
        self._clock(now_ns)
        keep = []
        for request in self._pending:
            if now_ns >= request.deadline_ns:
                self._finish(request, 'expired_before_dispatch', now_ns)
            else:
                keep.append(request)
        self._pending = keep
        if not self._pending:
            return []
        if flush:
            return self._seal(now_ns, 'explicit_flush')
        if len(self._pending) >= self.max_batch:
            return self._seal(now_ns, 'capacity')
        if self.next_wakeup_ns <= now_ns:
            return self._seal(now_ns, 'wait_or_deadline_budget')
        return []

    def submit(self, request, now_ns):
        require(type(request) is Request, 'REQUEST_TYPE')
        request.validate()
        uint(now_ns, 'CLOCK')
        require(now_ns >= self._now, 'CLOCK_REWIND')
        require(request.arrival_ns <= now_ns, 'FUTURE_ARRIVAL')
        require(request.request_id not in self._seen, 'DUPLICATE_REQUEST')
        require(len(self._seen) < self.max_requests, 'SESSION_EXHAUSTED')
        emitted = self.advance(now_ns)
        self._seen[request.request_id] = request
        if now_ns >= request.deadline_ns:
            self._finish(request, 'expired_on_arrival', now_ns)
            return emitted
        if self._pending and (request.scope, request.model_version) != (
                self._pending[0].scope, self._pending[0].model_version):
            emitted += self._seal(now_ns, 'scope_or_model_boundary')
        self._pending.append(request)
        self._record(request, 'queued', now_ns)
        emitted += self.advance(now_ns)
        return emitted

    def cancel(self, request_id, now_ns):
        digest(request_id)
        require(request_id in self._seen, 'UNKNOWN_REQUEST')
        require(request_id not in self._terminal, 'TERMINAL_ALREADY_RECORDED')
        self._clock(now_ns)
        request = self._seen[request_id]
        self._pending = [r for r in self._pending if r.request_id != request_id]
        return self._finish(request, 'cancelled', now_ns,
                            after_dispatch=request_id in self._dispatched)

    def complete(self, batch_id, request_id, now_ns, *, scope, model_version, input_sha256):
        """Record observed local completion; this never authenticates a product."""
        digest(batch_id)
        digest(request_id)
        require(request_id in self._dispatched, 'NOT_DISPATCHED')
        batch = self._dispatched[request_id]
        require(batch.batch_id == batch_id, 'BATCH_IDENTITY')
        request = self._seen[request_id]
        require((scope, model_version, input_sha256) ==
                (request.scope, request.model_version, request.input_sha256), 'COMPLETION_IDENTITY')
        self._clock(now_ns)
        require(now_ns >= batch.dispatched_ns, 'COMPLETION_BEFORE_DISPATCH')
        if request_id in self._terminal:
            # A cancelled output can arrive physically but cannot rewrite cancellation.
            require(self._terminal[request_id]['status'] == 'cancelled' and
                    not any(e['request_id'] == request_id and e['status'] == 'output_after_cancellation'
                            for e in self._events), 'TERMINAL_ALREADY_RECORDED')
            return self._record(request, 'output_after_cancellation', now_ns,
                                batch_id=batch_id, accepted=False)
        return self._finish(request, 'completed_on_time' if now_ns < request.deadline_ns
                            else 'completed_late', now_ns, batch_id=batch_id,
                            accepted=now_ns < request.deadline_ns)

    def snapshot(self):
        return {'schema': SCHEMA, 'requests_seen': len(self._seen),
                'pending_ids': list(self.pending_ids), 'next_wakeup_ns': self.next_wakeup_ns,
                'batches': [b.as_dict() for b in self.batches], 'events': [dict(event) for event in self.events],
                'uncompleted_ids': [rid for rid in self._dispatched if rid not in self._terminal],
                'clock_scope': 'caller-supplied monotonic observations',
                'state_scope': 'bounded volatile session; no durable replay protection',
                'real_demand_authenticated': False, 'service_qualified': False,
                'production_activation': False, 'model_reward': 0}
