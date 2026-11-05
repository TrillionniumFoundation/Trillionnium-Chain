"""Research-only receiver-local W2-C admission; NEVER consensus or VerifiedWork.

The existing research W2-C ticket is globally replayable. This separate
experiment tests a short-lived server-MACed, proposal-bound, one-use ticket.
The server must use its own secret/epoch and a trusted monotonic clock. Issuance
is bounded before any W1 execution. No protocol or V3 Cookie is changed.
"""
from dataclasses import dataclass, replace
import hashlib
import hmac
import secrets
import struct
import threading
import time
from contract_wire import H

DOMAIN = b'TRNM-W2C-RECEIVER-ADMISSION-RESEARCH-V1\0'
MAX_U64 = (1 << 64) - 1


def exact_u64(value, label):
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise ValueError(label)
    return value


def bytes32(value, label):
    if type(value) is not bytes or len(value) != 32:
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
        for name in ('receiver', 'epoch', 'proposal', 'token'):
            bytes32(getattr(self, name), name)
        if type(self.bits) is not int or not 8 <= self.bits <= 24:
            raise ValueError('BITS')
        if exact_u64(self.issued_ms, 'ISSUED_MS') > exact_u64(self.expires_ms, 'EXPIRES_MS'):
            raise ValueError('TIME_ORDER')
        return (DOMAIN + self.receiver + self.epoch + self.proposal + self.token
                + struct.pack('<BQQ', self.bits, self.issued_ms, self.expires_ms))


def ticket(grant, nonce):
    exact_u64(nonce, 'NONCE')
    # The server MAC is committed too; changing receiver/epoch/body invalidates
    # even a once-successful proof-of-cost nonce.
    return H('w2c-local-admission-v1', grant.unsigned(), bytes32(grant.mac, 'MAC'),
             struct.pack('<Q', nonce))


def qualifies(value, bits):
    bytes32(value, 'TICKET')
    if type(bits) is not int or not 8 <= bits <= 24:
        raise ValueError('BITS')
    return (int.from_bytes(value[:4], 'big') >> (32 - bits)) == 0


def solve(grant, cap=1 << 18):
    if type(cap) is not int or not 1 <= cap <= (1 << 20):
        raise ValueError('CAP')
    started = time.process_time_ns()
    for n in range(cap):
        if qualifies(ticket(grant, n), grant.bits):
            return n, {'attempts': n + 1, 'cpu_ns': time.process_time_ns() - started,
                       'status': 'TARGET_HIT_UNVERIFIED'}
    return None, {'attempts': cap, 'cpu_ns': time.process_time_ns() - started,
                  'status': 'CAPPED'}


class ReceiverAdmission:
    def __init__(self, receiver, secret, epoch, lifetime_ms=2000,
                 capacity=64, entropy=None):
        self.receiver = bytes32(receiver, 'RECEIVER')
        self.secret = bytes32(secret, 'SECRET')
        self.epoch = bytes32(epoch, 'EPOCH')
        if type(lifetime_ms) is not int or not 100 <= lifetime_ms <= 2000:
            raise ValueError('LIFETIME')
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError('CAPACITY')
        self.lifetime_ms, self.capacity = lifetime_ms, capacity
        self.entropy = entropy if entropy is not None else secrets.token_bytes
        self.issued = {}  # token -> (expiry, spent); never evict a live token.
        self.last_now_ms = 0
        self.lock = threading.RLock()

    def clock(self, now_ms):
        with self.lock:
            return self._clock(now_ms)

    def _clock(self, now_ms):
        exact_u64(now_ms, 'CLOCK')
        if now_ms < self.last_now_ms:
            raise ValueError('CLOCK_REGRESSION')
        self.last_now_ms = now_ms
        for token, (expiry, _) in list(self.issued.items()):
            if now_ms >= expiry:
                del self.issued[token]

    def offer(self, proposal, bits, now_ms):
        with self.lock:
            return self._offer(proposal, bits, now_ms)

    def _offer(self, proposal, bits, now_ms):
        bytes32(proposal, 'PROPOSAL')
        if type(bits) is not int or not 8 <= bits <= 24:
            raise ValueError('BITS')
        self.clock(now_ms)
        if len(self.issued) >= self.capacity:
            return None  # BUSY, never consensus-invalid.
        if now_ms > MAX_U64 - self.lifetime_ms:
            raise ValueError('CLOCK_OVERFLOW')
        token = bytes32(self.entropy(32), 'ENTROPY')
        if token in self.issued:
            raise ValueError('ENTROPY_REUSE')
        unsigned = Grant(self.receiver, self.epoch, proposal, token, bits,
                         now_ms, now_ms + self.lifetime_ms, b'')
        mac = hmac.new(self.secret, unsigned.unsigned(), hashlib.sha256).digest()
        grant = replace(unsigned, mac=mac)
        self.issued[token] = (grant.expires_ms, False)
        return grant

    def consume(self, grant, proposal, nonce, now_ms):
        """A READY result is only admission to a *separate* full W1 verifier."""
        with self.lock:
            return self._consume(grant, proposal, nonce, now_ms)

    def _consume(self, grant, proposal, nonce, now_ms):
        self._clock(now_ms)
        if not isinstance(grant, Grant):
            return 'GRANT_ENCODING'
        try:
            payload = grant.unsigned()
            mac = bytes32(grant.mac, 'MAC')
            bytes32(proposal, 'PROPOSAL')
            exact_u64(nonce, 'NONCE')
        except ValueError:
            return 'GRANT_ENCODING'
        if (grant.receiver != self.receiver or grant.epoch != self.epoch
                or grant.proposal != proposal):
            return 'CONTEXT'
        if not hmac.compare_digest(hmac.new(self.secret, payload, hashlib.sha256).digest(), mac):
            return 'GRANT_MAC'
        if not grant.issued_ms <= now_ms < grant.expires_ms:
            return 'EXPIRED_OR_FUTURE'
        state = self.issued.get(grant.token)
        if state is None:
            return 'NOT_ISSUED'
        if state[0] != grant.expires_ms:
            return 'GRANT_STATE'
        if state[1]:
            return 'REPLAY'
        if not qualifies(ticket(grant, nonce), grant.bits):
            return 'TARGET'
        # Spend before handing to an expensive W1 verifier. Failure in the
        # subsequent W1 path cannot refund a consumed admission token.
        self.issued[grant.token] = (state[0], True)
        return 'READY_RESOURCE_ONLY'
