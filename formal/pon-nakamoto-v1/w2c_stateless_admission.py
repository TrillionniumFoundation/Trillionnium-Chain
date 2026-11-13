"""Unactivated W2-C research: stateless signed offers and paid-only replay memory.

No W1 VerifiedWork, chainwork, public V3 Cookie or network authority is created.
The real receiver must supply a random boot epoch, an owner-shared spent store,
trusted monotonic milliseconds and a host-wide admission/CPU policy.
"""
from __future__ import annotations
from dataclasses import dataclass
from collections import OrderedDict
import hashlib
import hmac
import secrets
import struct
import threading
from contract_wire import H

DOMAIN = b'w2c-receiver-stateless-research-v1'
UINT64 = (1 << 64) - 1


def hash32(value, label):
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(label)
    return value


def u64(value, label):
    if type(value) is not int or not 0 <= value <= UINT64:
        raise ValueError(label)
    return value


@dataclass(frozen=True)
class Offer:
    receiver: bytes
    epoch: bytes
    network: bytes
    proposal: bytes
    salt: bytes
    bits: int
    issued_ms: int
    expires_ms: int
    mac: bytes

    def unsigned(self):
        for name in ('receiver', 'epoch', 'network', 'proposal', 'salt'):
            hash32(getattr(self, name), name)
        if type(self.bits) is not int or not 8 <= self.bits <= 24:
            raise ValueError('BITS')
        issued, expires = u64(self.issued_ms, 'TIME'), u64(self.expires_ms, 'TIME')
        if issued >= expires or expires - issued > 2000:
            raise ValueError('LIFETIME')
        return (DOMAIN + self.receiver + self.epoch + self.network + self.proposal
                + self.salt + struct.pack('<BQQ', self.bits, issued, expires))


def ticket(offer: Offer, nonce: int) -> bytes:
    u64(nonce, 'NONCE')
    return H('w2c-stateless-receiver-ticket-v1', offer.unsigned(),
             hash32(offer.mac, 'MAC'), struct.pack('<Q', nonce))


def qualifies(value: bytes, bits: int) -> bool:
    hash32(value, 'TICKET')
    if type(bits) is not int or not 8 <= bits <= 24:
        raise ValueError('BITS')
    return int.from_bytes(value[:4], 'big') >> (32-bits) == 0


def solve(offer: Offer, max_attempts: int = 65536):
    if type(max_attempts) is not int or not 1 <= max_attempts <= (1 << 20):
        raise ValueError('CAP')
    for nonce in range(max_attempts):
        if qualifies(ticket(offer, nonce), offer.bits):
            return nonce, nonce + 1
    return None, max_attempts


class PaidReplayOwner:
    """Shared, bounded owner. Only valid paid ticket identities consume slots."""
    def __init__(self, capacity: int = 64):
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError('CAPACITY')
        self.capacity = capacity
        self.lock = threading.RLock()
        self.paid = OrderedDict()  # exact ticket identity -> original expiry
        self.latest_ms = 0

    def now(self, now_ms):
        u64(now_ms, 'CLOCK')
        if now_ms < self.latest_ms:
            raise ValueError('CLOCK_REGRESSION')
        self.latest_ms = now_ms
        for key, expires in tuple(self.paid.items()):
            if now_ms >= expires:
                del self.paid[key]

    def mark_paid(self, offer: Offer, now_ms: int):
        with self.lock:
            self.now(now_ms)
            identity = H('w2c-stateless-paid-replay-v1', offer.unsigned(), offer.mac)
            if identity in self.paid:
                return 'REPLAY'
            if len(self.paid) >= self.capacity:
                return 'BUSY_PAID_STORE'
            self.paid[identity] = offer.expires_ms
            return 'READY_RESOURCE_ONLY'


class Issuer:
    """No per-offer state. A finite shared mint rate bounds unpaid HMAC work."""
    def __init__(self, receiver, network, secret, epoch, paid: PaidReplayOwner,
                 bits=12, lifetime_ms=2000, mint_capacity=32,
                 mint_refill_per_second=32, entropy=None):
        self.receiver = hash32(receiver, 'RECEIVER')
        self.network = hash32(network, 'NETWORK')
        self.secret = hash32(secret, 'SECRET')
        self.epoch = hash32(epoch, 'EPOCH')
        if not isinstance(paid, PaidReplayOwner):
            raise ValueError('OWNER')
        self.paid = paid
        if type(bits) is not int or not 8 <= bits <= 24:
            raise ValueError('BITS')
        if type(lifetime_ms) is not int or not 100 <= lifetime_ms <= 2000:
            raise ValueError('LIFETIME')
        if type(mint_capacity) is not int or not 1 <= mint_capacity <= 1024:
            raise ValueError('MINT_CAPACITY')
        if type(mint_refill_per_second) is not int or not 1 <= mint_refill_per_second <= 1024:
            raise ValueError('MINT_RATE')
        self.bits, self.lifetime_ms = bits, lifetime_ms
        self.mint_capacity, self.mint_refill_per_second = mint_capacity, mint_refill_per_second
        self.entropy = entropy if entropy is not None else secrets.token_bytes
        self.mint_credit = mint_capacity * 1000
        self.last_mint_ms = 0
        self.lock = threading.RLock()

    def issue(self, proposal: bytes, now_ms: int):
        with self.lock:
            hash32(proposal, 'PROPOSAL')
            with self.paid.lock:
                self.paid.now(now_ms)
            if now_ms < self.last_mint_ms:
                raise ValueError('CLOCK_REGRESSION')
            delta = now_ms - self.last_mint_ms
            self.last_mint_ms = now_ms
            self.mint_credit = min(self.mint_capacity * 1000,
                                   self.mint_credit + delta * self.mint_refill_per_second)
            if self.mint_credit < 1000:
                return None  # Local busy, not consensus-invalid proof.
            if now_ms > UINT64 - self.lifetime_ms:
                raise ValueError('CLOCK_OVERFLOW')
            # The debit occurs before entropy/HMAC work and is not refunded
            # on unsupported entropy or backend failure.
            self.mint_credit -= 1000
            salt = hash32(self.entropy(32), 'ENTROPY')
            blank = Offer(self.receiver, self.epoch, self.network, proposal, salt,
                          self.bits, now_ms, now_ms + self.lifetime_ms, bytes(32))
            mac = hmac.new(self.secret, blank.unsigned(), hashlib.sha256).digest()
            return Offer(self.receiver, self.epoch, self.network, proposal, salt,
                         self.bits, now_ms, now_ms + self.lifetime_ms, mac)

    def pay(self, offer: Offer, proposal: bytes, nonce: int, now_ms: int):
        # A caller cannot self-select a lower difficulty than this issuer's
        # immutable bits. Receiver/epoch/network/proposal/MAC are all bound.
        with self.paid.lock:
            self.paid.now(now_ms)
            if not isinstance(offer, Offer):
                return 'OFFER_ENCODING'
            try:
                unsigned = offer.unsigned()
                mac = hash32(offer.mac, 'MAC')
                hash32(proposal, 'PROPOSAL')
                u64(nonce, 'NONCE')
            except ValueError:
                return 'OFFER_ENCODING'
            if (offer.receiver != self.receiver or offer.network != self.network
                    or offer.epoch != self.epoch or offer.proposal != proposal
                    or offer.bits != self.bits):
                return 'CONTEXT'
            expected_mac = hmac.new(self.secret, unsigned, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected_mac):
                return 'MAC'
            if not offer.issued_ms <= now_ms < offer.expires_ms:
                return 'EXPIRED_OR_FUTURE'
            if not qualifies(ticket(offer, nonce), offer.bits):
                return 'TARGET'
            # Exactly one paid slot acquisition. Cryptographic checks above
            # do not mutate the replay store. Under concurrency the store is
            # owned by the same lock. Successful payment cannot be refunded by
            # a later invalid W1 transcript or failed M06 application.
            return self.paid.mark_paid(offer, now_ms)
