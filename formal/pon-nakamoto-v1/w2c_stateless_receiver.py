"""Standalone W2-C research: stateless challenge issuance, paid single-use receipt.

Not used in native Chain, consensus, real V3 Cookie or public listener.
No unpaid grant consumes a persistent replay/worker slot. Existing V3 network
challenge throughput and signed request bounds are separate mandatory owners.
"""
from dataclasses import replace
import hashlib
import hmac
import secrets
import struct
import threading
from contract_wire import H
from w2c_receiver_admission import (
    DOMAIN, Grant, MAX_U64, bytes32, exact_u64, qualifies, ticket,
)


class StatelessReceiverAdmission:
    def __init__(self, receiver, secret, epoch, bits=8, lifetime_ms=2000,
                 spent_capacity=64, entropy=None):
        self.receiver = bytes32(receiver, 'RECEIVER')
        self.secret = bytes32(secret, 'SECRET')
        self.epoch = bytes32(epoch, 'EPOCH')
        if type(bits) is not int or not 8 <= bits <= 24:
            raise ValueError('BITS')
        if type(lifetime_ms) is not int or not 100 <= lifetime_ms <= 2000:
            raise ValueError('LIFETIME')
        if type(spent_capacity) is not int or not 1 <= spent_capacity <= 1024:
            raise ValueError('CAPACITY')
        self.bits = bits
        self.lifetime_ms = lifetime_ms
        self.capacity = spent_capacity
        self.entropy = secrets.token_bytes if entropy is None else entropy
        # Only PAID completed grant identities are retained. No issuance
        # reservations and no untrusted caller-ID keyed positive entitlement.
        self.spent = {}  # exact signed grant identity -> expiry
        self.last_now_ms = 0
        self.lock = threading.RLock()

    def _clock(self, now_ms):
        exact_u64(now_ms, 'CLOCK')
        if now_ms < self.last_now_ms:
            raise ValueError('CLOCK_REGRESSION')
        self.last_now_ms = now_ms

    def offer(self, proposal, now_ms):
        """Cheap receiver MAC, no grant table reservation."""
        with self.lock:
            self._clock(now_ms)
            bytes32(proposal, 'PROPOSAL')
            if now_ms > MAX_U64 - self.lifetime_ms:
                raise ValueError('CLOCK_OVERFLOW')
            token = bytes32(self.entropy(32), 'ENTROPY')
            unsigned = Grant(self.receiver, self.epoch, proposal, token,
                             self.bits, now_ms, now_ms + self.lifetime_ms, b'')
            mac = hmac.new(self.secret, unsigned.unsigned(), hashlib.sha256).digest()
            return replace(unsigned, mac=mac)

    def consume(self, grant, proposal, nonce, now_ms):
        """A paid, not-yet-used ticket grants resource admission, NEVER W1."""
        with self.lock:
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
            if not hmac.compare_digest(
                hmac.new(self.secret, payload, hashlib.sha256).digest(), mac
            ):
                return 'GRANT_MAC'
            if grant.bits != self.bits:
                return 'BITS_POLICY'
            if not grant.issued_ms <= now_ms < grant.expires_ms:
                return 'EXPIRED_OR_FUTURE'
            if not qualifies(ticket(grant, nonce), self.bits):
                return 'TARGET'
            identity = H('w2c-receiver-paid-grant-v1', DOMAIN, payload, mac)
            if identity in self.spent:
                return 'REPLAY'
            # Reclaim only on a VALID paid ticket and when capacity is full.
            # Invalid unsigned floods cannot buy an O(capacity) cleanup scan.
            if len(self.spent) >= self.capacity:
                self.spent = {key: exp for key, exp in self.spent.items()
                              if now_ms < exp}
            if len(self.spent) >= self.capacity:
                return 'PAID_CAPACITY_BUSY'
            # Linearized single-use claim before any full W1 work. If W1 later
            # rejects or caller disconnects, no claim refund is permitted.
            self.spent[identity] = grant.expires_ms
            return 'READY_RESOURCE_ONLY'
