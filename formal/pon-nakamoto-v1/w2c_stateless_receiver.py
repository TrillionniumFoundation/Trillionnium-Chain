"""W2-C research only: stateless issue; bounded *paid* spend memory.

Compared with w2c_receiver_admission.ReceiverAdmission, unpaid issued grants
occupy NO stored entries. A passing target pays for an atomic one-use slot.
This is a local anti-amplification experiment, not W1/Chainwork, public-V3
wire compatibility, independent cost-hardness or a deployment policy.
"""
from __future__ import annotations
from dataclasses import replace
import hashlib
import hmac
import secrets
import threading
from contract_wire import H
from w2c_receiver_admission import (
    Grant, bytes32, exact_u64, MAX_U64, qualifies, ticket
)


class StatelessReceiverAdmission:
    """Caller MUST supply trusted monotonic time and secure unshared credentials."""

    def __init__(self, receiver: bytes, secret: bytes, epoch: bytes,
                 *, lifetime_ms: int = 2000, capacity: int = 64,
                 required_bits: int = 8, entropy=None, durable_spend=None):
        self.receiver = bytes32(receiver, 'RECEIVER')
        self.secret = bytes32(secret, 'SECRET')
        self.epoch = bytes32(epoch, 'EPOCH')
        if type(lifetime_ms) is not int or not 100 <= lifetime_ms <= 2000:
            raise ValueError('LIFETIME')
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError('CAPACITY')
        if type(required_bits) is not int or not 8 <= required_bits <= 24:
            raise ValueError('REQUIRED_BITS')
        # An unauthenticated caller is never allowed to price its own W1 replay.
        # Policy is selected by the receiver owner and checked again on consume.
        self.required_bits = required_bits
        # Only an explicitly configured durable journal shares spent tokens
        # between process clones. The original ephemeral research mode remains
        # unchanged and deliberately retains its clone-epoch replay negative.
        if durable_spend is not None:
            from w2c_durable_spend import SQLiteSpentOwner
            if (not isinstance(durable_spend, SQLiteSpentOwner)
                    or durable_spend.receiver != self.receiver
                    or durable_spend.epoch != self.epoch
                    or durable_spend.required_bits != required_bits
                    or durable_spend.capacity != capacity):
                raise ValueError('SPEND_OWNER_CONTEXT')
        self.durable_spend = durable_spend
        self.lifetime_ms = lifetime_ms
        self.capacity = capacity
        self.entropy = secrets.token_bytes if entropy is None else entropy
        self.spent: dict[bytes, int] = {}  # exact paid grant -> original expiry
        self.last_now_ms = 0
        self.lock = threading.RLock()

    def _clock(self, now_ms: int):
        exact_u64(now_ms, 'CLOCK')
        if now_ms < self.last_now_ms:
            raise ValueError('CLOCK_REGRESSION')
        self.last_now_ms = now_ms
        for key, expiry in list(self.spent.items()):
            if now_ms >= expiry:
                del self.spent[key]

    def clock(self, now_ms: int):
        with self.lock:
            self._clock(now_ms)

    def pending_paid(self) -> int:
        with self.lock:
            if self.durable_spend is not None:
                return self.durable_spend.pending_paid()
            return len(self.spent)

    def offer(self, proposal: bytes, caller: bytes, bits: int, now_ms: int) -> Grant:
        """Caller identity is checked by an upstream authenticated transport."""
        with self.lock:
            bytes32(proposal, 'PROPOSAL')
            bytes32(caller, 'CALLER')
            if type(bits) is not int or not 8 <= bits <= 24:
                raise ValueError('BITS')
            if bits != self.required_bits:
                raise ValueError('REQUIRED_BITS')
            self._clock(now_ms)
            if now_ms > MAX_U64 - self.lifetime_ms:
                raise ValueError('CLOCK_OVERFLOW')
            token = bytes32(self.entropy(32), 'ENTROPY')
            caller_proposal = H('w2c-stateless-caller-proposal-v1', caller, proposal)
            unsigned = Grant(self.receiver, self.epoch, caller_proposal, token, bits,
                             now_ms, now_ms + self.lifetime_ms, b'')
            mac = hmac.new(self.secret, unsigned.unsigned(), hashlib.sha256).digest()
            return replace(unsigned, mac=mac)

    def consume(self, grant: Grant, proposal: bytes, caller: bytes,
                nonce: int, now_ms: int) -> str:
        """Only READY_RESOURCE_ONLY allows a SEPARATE, still-full W1 validation."""
        with self.lock:
            self._clock(now_ms)
            if not isinstance(grant, Grant):
                return 'GRANT_ENCODING'
            try:
                payload = grant.unsigned()
                mac = bytes32(grant.mac, 'MAC')
                bytes32(proposal, 'PROPOSAL')
                bytes32(caller, 'CALLER')
                exact_u64(nonce, 'NONCE')
            except ValueError:
                return 'GRANT_ENCODING'
            caller_proposal = H('w2c-stateless-caller-proposal-v1', caller, proposal)
            if (grant.receiver != self.receiver or grant.epoch != self.epoch
                    or grant.proposal != caller_proposal):
                return 'CONTEXT'
            if grant.expires_ms - grant.issued_ms != self.lifetime_ms:
                return 'LIFETIME_POLICY'
            if not hmac.compare_digest(
                    hmac.new(self.secret, payload, hashlib.sha256).digest(), mac):
                return 'GRANT_MAC'
            # Reject authentic old-policy grants after verifying the MAC, so
            # mutated unsigned difficulty remains a tamper error rather than
            # masquerading as a legitimate policy downgrade.
            if grant.bits != self.required_bits:
                return 'REQUIRED_BITS'
            if not grant.issued_ms <= now_ms < grant.expires_ms:
                return 'EXPIRED_OR_FUTURE'
            if not qualifies(ticket(grant, nonce), grant.bits):
                return 'TARGET'
            # MAC binds the exact grant. One paid ticket spends once, regardless
            # of caller key, retransmission, or other signed connection identity.
            key = H('w2c-stateless-paid-grant-v1', payload, mac)
            if self.durable_spend is not None:
                # SQLite transaction commits before returning READY. A process
                # crash or duplicate worker cannot mint a second admission
                # using the same shared original durable owner.
                return self.durable_spend.spend(key, grant.expires_ms, now_ms)
            if key in self.spent:
                return 'REPLAY'
            # Fail closed on saturation *before* expensive W1 replay.
            if len(self.spent) >= self.capacity:
                return 'PAID_CAPACITY_BUSY'
            self.spent[key] = grant.expires_ms
            return 'READY_RESOURCE_ONLY'
