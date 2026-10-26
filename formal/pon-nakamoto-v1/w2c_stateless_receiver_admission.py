"""W2-C RESEARCH ONLY: stateless issuance, receiver-local one-use paid admission.

No W1/chain authority, no public listener and no replacement for V3 Cookie.
A successful ticket may still carry forged mathematical work. The spent table
is bounded but paid request occupancy can still starve honest callers.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
import hashlib
import hmac
import secrets
import struct
import threading
import time
from contract_wire import H

DOMAIN = b'w2c-receiver-stateless-research-v1'
MAX_U64 = (1 << 64) - 1


def fixed32(value, label):
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(label)
    return value


def u64(value, label):
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise ValueError(label)
    return value


@dataclass(frozen=True)
class Grant:
    receiver: bytes
    epoch: bytes
    proposal: bytes
    token: bytes
    bits: int
    issued_ms: int
    expires_ms: int
    mac: bytes

    def unsigned(self):
        for field in ('receiver', 'epoch', 'proposal', 'token'):
            fixed32(getattr(self, field), field)
        if type(self.bits) is not int or not 8 <= self.bits <= 24:
            raise ValueError('BITS')
        start = u64(self.issued_ms, 'ISSUED')
        finish = u64(self.expires_ms, 'EXPIRES')
        if not start < finish or finish - start > 2000:
            raise ValueError('DURATION')
        return DOMAIN + self.receiver + self.epoch + self.proposal + self.token + struct.pack('<BQQ', self.bits, start, finish)


def ticket(grant, nonce):
    return H('w2c-stateless-paid-ticket-v1', grant.unsigned(), fixed32(grant.mac, 'MAC'),
             struct.pack('<Q', u64(nonce, 'NONCE')))


def qualifies(value, bits):
    fixed32(value, 'TICKET')
    if type(bits) is not int or not 8 <= bits <= 24:
        raise ValueError('BITS')
    return int.from_bytes(value[:4], 'big') >> (32 - bits) == 0


def solve(grant, cap=65536):
    if type(cap) is not int or not 1 <= cap <= (1 << 20):
        raise ValueError('CAP')
    started = time.process_time_ns()
    for nonce in range(cap):
        if qualifies(ticket(grant, nonce), grant.bits):
            return nonce, {'trials':nonce + 1, 'cpu_ns':time.process_time_ns()-started,
                           'status':'TARGET_HIT_UNVERIFIED'}
    return None, {'trials':cap, 'cpu_ns':time.process_time_ns()-started,
                  'status':'EXHAUSTED'}


class StatelessReceiver:
    """Only *paid accepted* tokens consume server state; issuance uses HMAC.

    A deployment must separately bound network/HMAC issuance CPU, provide a
    trusted monotonic clock, keep the issuer's secret private and rotate the
    epoch when the in-memory spent table is lost (including power cuts).
    """
    def __init__(self, receiver, secret, epoch, *, capacity=128,
                 ttl_ms=2000, bits=8, entropy=None):
        self.receiver = fixed32(receiver, 'RECEIVER')
        self.secret = fixed32(secret, 'SECRET')
        self.epoch = fixed32(epoch, 'EPOCH')
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError('CAPACITY')
        if type(ttl_ms) is not int or not 100 <= ttl_ms <= 2000:
            raise ValueError('TTL')
        if type(bits) is not int or not 8 <= bits <= 24:
            raise ValueError('BITS')
        self.capacity, self.ttl_ms, self.bits = capacity, ttl_ms, bits
        self.entropy = entropy if entropy is not None else secrets.token_bytes
        self.spent = {}  # exact grant-id -> original absolute expiry, never evict live
        self.now_ms = 0
        self.lock = threading.Lock()

    def _clock(self, now_ms, *, sweep=True):
        u64(now_ms, 'CLOCK')
        if now_ms < self.now_ms:
            raise ValueError('CLOCK_REGRESSION')
        self.now_ms = now_ms
        if sweep:
            for key, expiry in tuple(self.spent.items()):
                if expiry <= now_ms:
                    del self.spent[key]

    def offer(self, proposal, bits, now_ms):
        with self.lock:
            # Cheap untrusted issuance MUST NOT scan the entire paid spent table.
            self._clock(now_ms, sweep=False)
            fixed32(proposal, 'PROPOSAL')
            if type(bits) is not int or not 8 <= bits <= 24:
                raise ValueError('BITS')
            if bits != self.bits:
                raise ValueError('BITS_POLICY')
            if now_ms > MAX_U64 - self.ttl_ms:
                raise ValueError('CLOCK_OVERFLOW')
            token = fixed32(self.entropy(32), 'ENTROPY')
            # No allocation in self.spent, even under arbitrary unpaid offers.
            claim = Grant(self.receiver, self.epoch, proposal, token, bits,
                          now_ms, now_ms + self.ttl_ms, bytes(32))
            mac = hmac.new(self.secret, claim.unsigned(), hashlib.sha256).digest()
            return replace(claim, mac=mac)

    def consume(self, grant, proposal, nonce, now_ms):
        with self.lock:
            self._clock(now_ms)
            if not isinstance(grant, Grant):
                return 'MALFORMED'
            try:
                encoded = grant.unsigned()
                mac = fixed32(grant.mac, 'MAC')
                fixed32(proposal, 'PROPOSAL')
                u64(nonce, 'NONCE')
            except ValueError:
                return 'MALFORMED'
            if (grant.receiver != self.receiver or grant.epoch != self.epoch
                    or proposal != grant.proposal):
                return 'CONTEXT'
            if not hmac.compare_digest(hmac.new(self.secret, encoded, hashlib.sha256).digest(), mac):
                return 'MAC'
            if grant.bits != self.bits:
                return 'BITS_POLICY'
            if not grant.issued_ms <= now_ms < grant.expires_ms:
                return 'EXPIRED'
            key = H('w2c-stateless-grant-id-v1', encoded, mac)
            if key in self.spent:
                return 'REPLAY'
            if not qualifies(ticket(grant, nonce), grant.bits):
                return 'TARGET'
            if len(self.spent) >= self.capacity:
                # A true paid ticket can be refused on capacity. No runtime
                # verdict, no chain invalidity or fabricated refund follows.
                return 'BUSY_RESOURCE_ONLY'
            self.spent[key] = grant.expires_ms
            return 'READY_RESOURCE_ONLY'
