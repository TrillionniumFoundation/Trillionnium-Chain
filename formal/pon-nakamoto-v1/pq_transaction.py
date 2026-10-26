"""QTX1: research-only, PQ-signed transfer candidate / deterministic preflight.

This DOES NOT change PoN ledger bytes, M05/M06, account owners, installed limits,
mainnet, Final-use or fork-choice. The AccountView is supplied by a caller and
is NOT a trusted state proof. OpenSSL via pq_envelope is an offline oracle.
There is no Ed25519 or signature-optional path in this new research profile.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

from pq_envelope import (Reject, SIGNED_BYTES, make_unsigned, parse_signed,
                         public_key_id, sign_reference, verify_reference)

MAGIC = b"QTX1"
VERSION = 1
TRANSFER = 1
HEADER_BYTES = 144
MAX_MEMO_BYTES = 512
RESEARCH_MAX_TX_BYTES = 8192
INSTALLED_MAX_TX_BYTES = 2048
U64_MAX = (1 << 64) - 1
CONTEXT_DOMAIN = b"TRNM/PoN/QTX1Context/v1\x00"
IDENTITY_DOMAIN = b"TRNM/PoN/QTX1Identity/v1\x00"


def _bytes(value: bytes, count: int, name: str) -> bytes:
    if type(value) is not bytes or len(value) != count:
        raise Reject(name)
    return value


def _u64(value: int, name: str, *, nonzero: bool = False) -> bytes:
    if type(value) is not int or value < int(nonzero) or value > U64_MAX:
        raise Reject(name)
    return value.to_bytes(8, "big")


def _context(network: bytes, sender: bytes) -> bytes:
    return hashlib.sha256(CONTEXT_DOMAIN + network + sender).digest()


@dataclass(frozen=True)
class Transfer:
    network: bytes
    sender: bytes
    recipient: bytes
    generation: int
    nonce: int
    expires_at: int
    amount: int
    max_fee: int
    memo: bytes = b""

    def encode(self) -> bytes:
        n = _bytes(self.network, 32, "network")
        s = _bytes(self.sender, 32, "sender")
        r = _bytes(self.recipient, 32, "recipient")
        if s == bytes(32) or r == bytes(32) or s == r:
            raise Reject("sender/recipient")
        if type(self.memo) is not bytes or len(self.memo) > MAX_MEMO_BYTES:
            raise Reject("memo")
        return (MAGIC + bytes([VERSION, TRANSFER]) + n + s + r
                + _u64(self.generation, "generation", nonzero=True)
                + _u64(self.nonce, "nonce", nonzero=True)
                + _u64(self.expires_at, "expiry", nonzero=True)
                + _u64(self.amount, "amount", nonzero=True)
                + _u64(self.max_fee, "fee_limit")
                + len(self.memo).to_bytes(2, "big") + self.memo)


def decode_transfer(body: bytes) -> Transfer:
    if type(body) is not bytes or not HEADER_BYTES <= len(body) <= HEADER_BYTES + MAX_MEMO_BYTES:
        raise Reject("transfer length")
    if body[:4] != MAGIC or body[4] != VERSION or body[5] != TRANSFER:
        raise Reject("transfer type/version")
    memo_length = int.from_bytes(body[142:144], "big")
    if memo_length > MAX_MEMO_BYTES or len(body) != HEADER_BYTES + memo_length:
        raise Reject("transfer memo framing")
    t = Transfer(
        body[6:38], body[38:70], body[70:102],
        int.from_bytes(body[102:110], "big"),
        int.from_bytes(body[110:118], "big"),
        int.from_bytes(body[118:126], "big"),
        int.from_bytes(body[126:134], "big"),
        int.from_bytes(body[134:142], "big"), body[144:])
    if t.encode() != body:
        raise Reject("transfer noncanonical")
    return t


@dataclass(frozen=True)
class AccountView:
    """Caller-provided snapshot; not authenticated by this module."""
    network: bytes
    account: bytes
    signer_key_id: bytes
    generation: int
    next_nonce: int
    available_units: int
    active: bool


@dataclass(frozen=True)
class Preflight:
    """No ledger/effect/release authority. Pure research observation only."""
    identity: bytes
    encoded_bytes: int
    required_fee: int
    remaining_units: int


def sign_transfer(t: Transfer, *, public_pem: bytes, private_key_path: Path) -> bytes:
    body = t.encode()
    statement = make_unsigned(
        purpose=1, network=t.network, context=_context(t.network, t.sender),
        signer_key_id=public_key_id(public_pem),
        owner_generation=t.generation, operation_sequence=t.nonce,
        expires_at=t.expires_at, payload=body)
    signed = body + sign_reference(statement, private_key_path=private_key_path)
    if len(signed) > RESEARCH_MAX_TX_BYTES:
        raise Reject("research transfer size")
    return signed


def parse_signed_transfer(raw: bytes) -> tuple[Transfer, bytes, bytes]:
    if type(raw) is not bytes or not HEADER_BYTES + SIGNED_BYTES <= len(raw) <= RESEARCH_MAX_TX_BYTES:
        raise Reject("signed transfer length")
    memo_length = int.from_bytes(raw[142:144], "big")
    if memo_length > MAX_MEMO_BYTES:
        raise Reject("signed memo size")
    body_size = HEADER_BYTES + memo_length
    if len(raw) != body_size + SIGNED_BYTES:
        raise Reject("signed transfer trailing/missing bytes")
    body, signed = raw[:body_size], raw[body_size:]
    t = decode_transfer(body)
    statement, _ = parse_signed(signed)  # strict grammar; never a verified signature
    if (statement.purpose != 1 or statement.network != t.network
            or statement.context != _context(t.network, t.sender)
            or statement.owner_generation != t.generation
            or statement.operation_sequence != t.nonce or statement.expires_at != t.expires_at):
        raise Reject("transaction/signature context mismatch")
    return t, body, signed


def preflight_transfer(raw: bytes, *, public_pem: bytes, account: AccountView,
                       now: int, base_fee: int, byte_fee: int) -> Preflight:
    """Full offline ML-DSA verification and bounded fee/state preflight, NO commit."""
    t, body, frame = parse_signed_transfer(raw)
    if not isinstance(account, AccountView) or type(account.active) is not bool:
        raise Reject("account owner type")
    if account.active is not True:
        raise Reject("account inactive")
    for name, v in (("account_generation", account.generation),
                    ("account_nonce", account.next_nonce),
                    ("balance", account.available_units),
                    ("base_fee", base_fee), ("byte_fee", byte_fee)):
        _u64(v, name)
    if (account.network != t.network or account.account != t.sender
            or t.generation != account.generation or t.nonce != account.next_nonce):
        raise Reject("untrusted/stale account view")
    _bytes(account.network, 32, "account_network")
    _bytes(account.account, 32, "account_id")
    _bytes(account.signer_key_id, 32, "signer_key_id")
    if account.signer_key_id != public_key_id(public_pem):
        raise Reject("key does not own account")
    _u64(now, "now")
    if now > t.expires_at:
        raise Reject("transaction expired")
    required = base_fee + byte_fee * len(raw)
    if required > U64_MAX or required > t.max_fee:
        raise Reject("fee insufficient/overflow")
    if t.amount + required > U64_MAX or t.amount + required > account.available_units:
        raise Reject("balance insufficient/overflow")
    verify_reference(
        frame, payload=body, public_pem=public_pem,
        expected_network=t.network, expected_context=_context(t.network, t.sender),
        expected_purpose=1, expected_generation=t.generation,
        expected_sequence=t.nonce, now=now)
    identity = hashlib.sha384(
        IDENTITY_DOMAIN + len(body).to_bytes(4, "big") + body
        + account.signer_key_id).digest()
    return Preflight(identity, len(raw), required, account.available_units - t.amount - required)
