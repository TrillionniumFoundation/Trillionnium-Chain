#!/usr/bin/env python3
"""Independent bounded semantic parser for the PoCO-BFT v0 wire tranche.

The Rust transport decoder and this checker intentionally have no shared
parser code.  This implementation uses only the Python standard library and
reconstructs the CEV0 Vote, TimeoutVote, QC, and TC domains from the protobuf
projection.  The canonical structural vector remains crypto-neutral; the same
standard-library implementation also checks a separate authenticated corpus
with strict RFC 8032 Ed25519 and digest-preserving nested-signature mutants.
This is candidate evidence, not a production node: the ten not-yet-adapted
body kinds and production network activation remain explicit blockers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTOR = ROOT / "docs/protocol/poco-bft-v0/vectors/wire-semantic-v0.json"
DEFAULT_AUTHENTICATED_VECTOR = (
    ROOT / "docs/protocol/poco-bft-v0/vectors/wire-authenticated-v0.json"
)
HASH_PREFIX = b"trnm.cev0.hash.v0"
DOMAIN_VOTE = b"trnm.poco-bft.vote.v0"
DOMAIN_TIMEOUT = b"trnm.poco-bft.timeout.v0"
DOMAIN_QC = b"trnm.poco-bft.qc.v0"
DOMAIN_TC = b"trnm.poco-bft.tc.v0"
DOMAIN_VALIDATOR_SET = b"trnm.poco-bft.validator-set.v0"
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_ENVELOPE_BYTES = MAX_BODY_BYTES + 1024
MAX_CHAIN_ID_BYTES = 128
MAX_VALIDATOR_ID_BYTES = 128
MAX_VALIDATORS = 100
MAX_NESTED_DEPTH = 8
MAX_NESTED_FIELDS = 4096
MAX_LIST_ITEMS = 100
MAX_TC_AGGREGATE_SHARES = 10_000
SIGNATURE_BYTES = 64

BODY_NAMES = {
    1: "proposal",
    2: "vote",
    3: "timeout_vote",
    4: "quorum_certificate",
    5: "timeout_certificate",
    6: "sync_info",
    7: "equivocation_evidence",
    8: "handoff_vote",
    9: "joint_handoff_certificate",
    10: "protocol_upgrade_plan",
    11: "next_epoch_commitment",
    12: "validator_set",
    13: "consensus_parameters",
    14: "light_client_proof",
}


class DecodeError(ValueError):
    def __init__(self, code: str, offset: int = 0):
        super().__init__(f"{code} at byte {offset}")
        self.code = code
        self.offset = offset


class ReferenceError(ValueError):
    pass


class AuthenticatedReferenceError(ValueError):
    """A deterministic authenticated nested-wire rejection."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


# The authenticated corpus carries no private key material.  These constants
# and the tiny RFC 8032 implementation are used only while constructing the
# checked-in deterministic fixtures and while independently verifying them.
# Keeping this implementation in the reference lane avoids importing either
# ed25519-dalek or any consensus crate into the second implementation.
ED25519_FIELD = 2**255 - 19
ED25519_GROUP_ORDER = 2**252 + 27742317777372353535851937790883648493
ED25519_CURVE_D = (
    -121665 * pow(121666, ED25519_FIELD - 2, ED25519_FIELD)
) % ED25519_FIELD
ED25519_SQRT_MINUS_ONE = pow(2, (ED25519_FIELD - 1) // 4, ED25519_FIELD)
ED25519_IDENTITY = (0, 1, 1, 0)


def _ed25519_point_add(
    first: tuple[int, int, int, int], second: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = first
    x2, y2, z2, t2 = second
    a = ((y1 - x1) * (y2 - x2)) % ED25519_FIELD
    b = ((y1 + x1) * (y2 + x2)) % ED25519_FIELD
    c = (2 * ED25519_CURVE_D * t1 * t2) % ED25519_FIELD
    d = (2 * z1 * z2) % ED25519_FIELD
    e = (b - a) % ED25519_FIELD
    f = (d - c) % ED25519_FIELD
    g = (d + c) % ED25519_FIELD
    h = (b + a) % ED25519_FIELD
    return (
        e * f % ED25519_FIELD,
        g * h % ED25519_FIELD,
        f * g % ED25519_FIELD,
        e * h % ED25519_FIELD,
    )


def _ed25519_point_double(point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x, y, z, _ = point
    a = x * x % ED25519_FIELD
    b = y * y % ED25519_FIELD
    c = 2 * z * z % ED25519_FIELD
    d = -a % ED25519_FIELD
    e = ((x + y) * (x + y) - a - b) % ED25519_FIELD
    g = (d + b) % ED25519_FIELD
    f = (g - c) % ED25519_FIELD
    h = (d - b) % ED25519_FIELD
    return (
        e * f % ED25519_FIELD,
        g * h % ED25519_FIELD,
        f * g % ED25519_FIELD,
        e * h % ED25519_FIELD,
    )


def _ed25519_scalar_multiply(
    point: tuple[int, int, int, int], scalar: int
) -> tuple[int, int, int, int]:
    result = ED25519_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed25519_point_add(result, addend)
        addend = _ed25519_point_double(addend)
        scalar >>= 1
    return result


def _ed25519_affine(point: tuple[int, int, int, int]) -> tuple[int, int]:
    x, y, z, _ = point
    inverse = pow(z, ED25519_FIELD - 2, ED25519_FIELD)
    return x * inverse % ED25519_FIELD, y * inverse % ED25519_FIELD


def _ed25519_points_equal(first: tuple[int, int, int, int], second: tuple[int, int, int, int]) -> bool:
    return (
        (first[0] * second[2] - second[0] * first[2]) % ED25519_FIELD == 0
        and (first[1] * second[2] - second[1] * first[2]) % ED25519_FIELD == 0
    )


def _ed25519_recover_x(y: int, sign: int) -> int | None:
    numerator = (y * y - 1) % ED25519_FIELD
    denominator = (ED25519_CURVE_D * y * y + 1) % ED25519_FIELD
    x_squared = numerator * pow(denominator, ED25519_FIELD - 2, ED25519_FIELD)
    x_squared %= ED25519_FIELD
    x = pow(x_squared, (ED25519_FIELD + 3) // 8, ED25519_FIELD)
    if (x * x - x_squared) % ED25519_FIELD != 0:
        x = x * ED25519_SQRT_MINUS_ONE % ED25519_FIELD
    if (x * x - x_squared) % ED25519_FIELD != 0:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = ED25519_FIELD - x
    return x


_ED25519_BASE_Y = 4 * pow(5, ED25519_FIELD - 2, ED25519_FIELD) % ED25519_FIELD
_ED25519_BASE_X = _ed25519_recover_x(_ED25519_BASE_Y, 0)
if _ED25519_BASE_X is None:  # pragma: no cover - module invariant
    raise RuntimeError("failed to construct the Ed25519 base point")
ED25519_BASE_POINT = (
    _ED25519_BASE_X,
    _ED25519_BASE_Y,
    1,
    _ED25519_BASE_X * _ED25519_BASE_Y % ED25519_FIELD,
)


def _ed25519_encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y = _ed25519_affine(point)
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed25519_decode_point(encoded: bytes) -> tuple[int, int, int, int] | None:
    if len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= ED25519_FIELD:
        return None
    x = _ed25519_recover_x(y, sign)
    if x is None:
        return None
    point = (x, y, 1, x * y % ED25519_FIELD)
    # Strict verification rejects weak/small-order public keys and R points.
    if _ed25519_points_equal(
        _ed25519_scalar_multiply(point, 8), ED25519_IDENTITY
    ):
        return None
    return point


def _ed25519_secret_scalar(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ReferenceError("Ed25519 seed must contain 32 bytes")
    expanded = bytearray(hashlib.sha512(seed).digest())
    expanded[0] &= 248
    expanded[31] &= 63
    expanded[31] |= 64
    return int.from_bytes(expanded[:32], "little"), bytes(expanded[32:])


def ed25519_public_key(seed: bytes) -> bytes:
    scalar, _ = _ed25519_secret_scalar(seed)
    return _ed25519_encode_point(_ed25519_scalar_multiply(ED25519_BASE_POINT, scalar))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = _ed25519_secret_scalar(seed)
    public_key = _ed25519_encode_point(
        _ed25519_scalar_multiply(ED25519_BASE_POINT, scalar)
    )
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little")
    nonce %= ED25519_GROUP_ORDER
    encoded_r = _ed25519_encode_point(
        _ed25519_scalar_multiply(ED25519_BASE_POINT, nonce)
    )
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    )
    challenge %= ED25519_GROUP_ORDER
    scalar_signature = (nonce + challenge * scalar) % ED25519_GROUP_ORDER
    return encoded_r + scalar_signature.to_bytes(32, "little")


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != SIGNATURE_BYTES:
        return False
    public_point = _ed25519_decode_point(public_key)
    r_point = _ed25519_decode_point(signature[:32])
    if public_point is None or r_point is None:
        return False
    scalar_signature = int.from_bytes(signature[32:], "little")
    if scalar_signature >= ED25519_GROUP_ORDER:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    )
    challenge %= ED25519_GROUP_ORDER
    return _ed25519_points_equal(
        _ed25519_scalar_multiply(ED25519_BASE_POINT, scalar_signature),
        _ed25519_point_add(
            r_point, _ed25519_scalar_multiply(public_point, challenge)
        ),
    )


def ed25519_self_test() -> None:
    """Run RFC 8032 test 1 before accepting any authenticated fixture."""

    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    expected_public = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    expected_signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    if ed25519_public_key(seed) != expected_public:
        raise ReferenceError("Ed25519 key generation failed RFC 8032 test 1")
    if ed25519_sign(seed, b"") != expected_signature:
        raise ReferenceError("Ed25519 signing failed RFC 8032 test 1")
    if not ed25519_verify(expected_public, b"", expected_signature):
        raise ReferenceError("Ed25519 verification failed RFC 8032 test 1")


def fail(code: str, offset: int = 0) -> DecodeError:
    return DecodeError(code, offset)


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def frame(value: bytes) -> bytes:
    return u32(len(value)) + value


def consensus_string(value: bytes) -> bytes:
    if not value or len(value) > MAX_CHAIN_ID_BYTES:
        raise ReferenceError("invalid chain id length")
    if not (value[:1].isalnum() and value[:1].isascii()):
        raise ReferenceError("invalid chain id first byte")
    allowed = b"abcdefghijklmnopqrstuvwxyz0123456789._:-"
    if any(byte not in allowed for byte in value):
        raise ReferenceError("invalid chain id grammar")
    return u16(len(value)) + value


def hash_domain(domain: bytes, encoded: bytes) -> bytes:
    return hashlib.sha256(frame(HASH_PREFIX) + frame(domain) + frame(encoded)).digest()


def encode_varint(value: int) -> bytes:
    if value < 0 or value >= 1 << 64:
        raise ReferenceError("u64 out of range")
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        result.append(byte)
        if not value:
            return bytes(result)


def field_varint(field: int, value: int) -> bytes:
    return encode_varint(field << 3) + encode_varint(value)


def field_bytes(field: int, value: bytes) -> bytes:
    return encode_varint((field << 3) | 2) + encode_varint(len(value)) + value


class Cursor:
    __slots__ = ("data", "offset", "depth", "fields", "last", "seen", "ordered")

    def __init__(self, data: bytes, depth: int, ordered: bool = True):
        if not data:
            raise fail("empty")
        if len(data) > MAX_BODY_BYTES:
            raise fail("nested_too_large")
        if depth > MAX_NESTED_DEPTH:
            raise fail("nested_depth_exceeded")
        self.data = data
        self.offset = 0
        self.depth = depth
        self.fields = 0
        self.last = 0
        self.seen: set[int] = set()
        self.ordered = ordered

    def done(self) -> bool:
        return self.offset == len(self.data)

    def varint(self) -> int:
        start = self.offset
        value = 0
        for index in range(10):
            if self.offset >= len(self.data):
                raise fail("unexpected_eof", start)
            byte = self.data[self.offset]
            self.offset += 1
            if index == 9 and byte > 1:
                raise fail("varint_overflow", start)
            value |= (byte & 0x7F) << (index * 7)
            if not byte & 0x80:
                if len(encode_varint(value)) != self.offset - start:
                    raise fail("noncanonical_varint", start)
                return value
        raise fail("varint_overflow", start)

    def field(self, maximum: int, repeated: set[int] = frozenset()) -> tuple[int, int, int]:
        start = self.offset
        key = self.varint()
        number = key >> 3
        wire_type = key & 7
        if number == 0 or number > maximum:
            raise fail("unknown_field", start)
        if wire_type not in (0, 2):
            raise fail("unsupported_wire_type", start)
        self.fields += 1
        if self.fields > MAX_NESTED_FIELDS:
            raise fail("nested_too_large", start)
        if self.ordered and number < self.last:
            raise fail("noncanonical_field_order", start)
        if number in self.seen and (number not in repeated or number != self.last):
            raise fail("duplicate_field", start)
        self.seen.add(number)
        self.last = number
        return start, number, wire_type

    def scalar(self, start: int, wire_type: int, bits: int) -> int:
        if wire_type != 0:
            raise fail("field_type_mismatch", start)
        value = self.varint()
        if value >= 1 << bits:
            raise fail("invalid_value", start)
        return value

    def bytes(self, start: int, wire_type: int, maximum: int) -> bytes:
        if wire_type != 2:
            raise fail("field_type_mismatch", start)
        length = self.varint()
        if length > maximum or length > MAX_BODY_BYTES:
            raise fail("field_too_large", start)
        end = self.offset + length
        if end > len(self.data):
            raise fail("unexpected_eof", start)
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def fixed32(self, start: int, wire_type: int) -> bytes:
        value = self.bytes(start, wire_type, 32)
        if len(value) != 32:
            raise fail("invalid_value", start)
        return value

    def signature(self, start: int, wire_type: int) -> bytes:
        value = self.bytes(start, wire_type, SIGNATURE_BYTES)
        if len(value) != SIGNATURE_BYTES:
            raise fail("invalid_signature", start)
        return value

    def nested(self, start: int, wire_type: int) -> bytes:
        value = self.bytes(start, wire_type, MAX_BODY_BYTES)
        if self.depth >= MAX_NESTED_DEPTH:
            raise fail("nested_depth_exceeded", start)
        return value


def required(values: dict[int, Any], field: int) -> Any:
    if field not in values:
        raise fail("missing_field", field)
    return values[field]


def strict_hex(value: Any, length: int, label: str) -> bytes:
    # `bytes.fromhex` intentionally accepts embedded whitespace.  That is
    # useful for human-facing tooling but not for a canonical wire vector:
    # accepting `aa ` (or a newline) would let two textual manifests denote
    # the same bytes while carrying different signed/raw evidence.
    if (
        not isinstance(value, str)
        or value.lower() != value
        or len(value) != length * 2
        or len(value) % 2 != 0
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ReferenceError(f"{label} must be lowercase hex")
    try:
        result = bytes.fromhex(value)
    except ValueError as error:
        raise ReferenceError(f"{label} is not hex") from error
    if len(result) != length:
        raise ReferenceError(f"{label} must be {length} bytes")
    return result


def parse_context(
    data: bytes, context: dict[str, Any], expected_kind: int, outer_view: int, depth: int
) -> dict[str, Any]:
    cursor = Cursor(data, depth)
    values: dict[int, Any] = {}
    while not cursor.done():
        start, field, wire = cursor.field(9)
        if field in (1, 4, 8):
            values[field] = cursor.scalar(start, wire, 32)
        elif field in (5, 7):
            values[field] = cursor.scalar(start, wire, 64)
        elif field in (2, 6, 9):
            values[field] = cursor.fixed32(start, wire)
        elif field == 3:
            values[field] = cursor.bytes(start, wire, MAX_CHAIN_ID_BYTES)
        else:
            raise fail("unknown_field", start)
    for field in range(1, 10):
        if field not in values:
            raise fail("missing_field", field)
    if values[1] != 0 or values[4] != 0:
        raise fail("scope_mismatch")
    expected = {
        2: context["genesis_hash"],
        3: context["chain_id"],
        5: context["epoch"],
        6: context["validator_set_hash"],
        9: context["consensus_parameters_hash"],
    }
    for field, expected_value in expected.items():
        if values[field] != expected_value:
            raise fail("scope_mismatch")
    if required(values, 7) != outer_view:
        raise fail("scope_mismatch")
    if required(values, 8) != expected_kind:
        raise fail("message_kind_mismatch")
    return {"view": values[7], "message_kind": values[8]}


def parse_high_qc(data: bytes, context: dict[str, Any], depth: int) -> dict[str, Any]:
    cursor = Cursor(data, depth)
    values: dict[int, Any] = {}
    while not cursor.done():
        start, field, wire = cursor.field(5)
        if field in (1, 5):
            values[field] = cursor.fixed32(start, wire)
        elif field in (2, 3, 4):
            values[field] = cursor.scalar(start, wire, 64)
        else:
            raise fail("unknown_field", start)
    result = {
        "digest": required(values, 1),
        "epoch": required(values, 2),
        "view": required(values, 3),
        "height": required(values, 4),
        "block_id": required(values, 5),
        "validator_set_hash": context["validator_set_hash"],
    }
    if result["epoch"] != context["epoch"]:
        raise fail("scope_mismatch")
    return result


def parse_vote(data: bytes, context: dict[str, Any], outer_view: int) -> dict[str, Any]:
    cursor = Cursor(data, 0)
    values: dict[int, Any] = {}
    while not cursor.done():
        start, field, wire = cursor.field(5)
        if field == 1:
            values[field] = parse_context(cursor.nested(start, wire), context, 1, outer_view, 1)
        elif field == 2:
            values[field] = cursor.scalar(start, wire, 64)
        elif field == 3:
            values[field] = cursor.fixed32(start, wire)
        elif field == 4:
            values[field] = cursor.bytes(start, wire, MAX_VALIDATOR_ID_BYTES)
        elif field == 5:
            values[field] = cursor.signature(start, wire)
        else:
            raise fail("unknown_field", start)
    author = required(values, 4)
    if not author or author not in context["validators"]:
        raise fail("invalid_signer")
    required(values, 1)
    return {
        "height": required(values, 2),
        "block_id": required(values, 3),
        "author": author,
        "signature": required(values, 5),
        "view": outer_view,
    }


def parse_signature_share(data: bytes, depth: int) -> dict[str, bytes]:
    cursor = Cursor(data, depth)
    values: dict[int, bytes] = {}
    while not cursor.done():
        start, field, wire = cursor.field(2)
        if field == 1:
            values[field] = cursor.bytes(start, wire, MAX_VALIDATOR_ID_BYTES)
        elif field == 2:
            values[field] = cursor.signature(start, wire)
        else:
            raise fail("unknown_field", start)
    author = required(values, 1)
    if not author:
        raise fail("invalid_signer")
    return {"author": author, "signature": required(values, 2)}


def canonical_qc(context: dict[str, Any], qc: dict[str, Any]) -> bytes:
    encoded = b"".join(
        (
            u16(0),
            context["genesis_hash"],
            consensus_string(context["chain_id"]),
            u32(0),
            u64(context["epoch"]),
            context["validator_set_hash"],
            u64(qc["view"]),
            u64(qc["height"]),
            qc["block_id"],
            u32(len(qc["shares"])),
            b"".join(frame(share["author"]) + share["signature"] for share in qc["shares"]),
        )
    )
    return encoded


def qc_digest(context: dict[str, Any], qc: dict[str, Any]) -> bytes:
    return hash_domain(b"trnm.poco-bft.qc.v0", canonical_qc(context, qc))


def parse_qc(
    data: bytes,
    context: dict[str, Any],
    outer_view: int | None,
    depth: int,
    aggregate: list[int],
    maximum_aggregate: int,
) -> dict[str, Any]:
    cursor = Cursor(data, depth)
    values: dict[int, Any] = {}
    shares: list[dict[str, bytes]] = []
    while not cursor.done():
        start, field, wire = cursor.field(12, {11})
        if field == 11:
            if len(shares) >= MAX_LIST_ITEMS or len(shares) >= len(context["validators"]):
                raise fail("aggregate_limit_exceeded", start)
            # Apply the caller's authenticated aggregate ceiling before
            # descending into the nested SignatureShare payload.  This keeps
            # the reference parser's allocation/work boundary aligned with
            # the Rust decoder instead of parsing an over-budget share first.
            if aggregate[0] >= min(MAX_TC_AGGREGATE_SHARES, maximum_aggregate):
                raise fail("aggregate_limit_exceeded", start)
            share = parse_signature_share(cursor.nested(start, wire), depth + 1)
            aggregate[0] += 1
            shares.append(share)
        elif field in (1, 4):
            values[field] = cursor.scalar(start, wire, 32)
        elif field == 5 or field == 8 or field == 9:
            values[field] = cursor.scalar(start, wire, 64)
        elif field in (2, 6, 7, 10, 12):
            values[field] = cursor.fixed32(start, wire) if field != 7 else cursor.fixed32(start, wire)
        elif field == 3:
            values[field] = cursor.bytes(start, wire, MAX_CHAIN_ID_BYTES)
        else:
            raise fail("unknown_field", start)
    scope = {
        "genesis_hash": required(values, 2),
        "chain_id": required(values, 3),
        "epoch": required(values, 5),
        "validator_set_hash": required(values, 6),
        "consensus_parameters_hash": required(values, 7),
    }
    if scope != {key: context[key] for key in scope}:
        raise fail("scope_mismatch")
    if required(values, 1) != 0 or required(values, 4) != 0:
        raise fail("scope_mismatch")
    if outer_view is not None and required(values, 8) != outer_view:
        raise fail("scope_mismatch")
    # Ordinary QCs are never valid at view zero.  This is a typed CEV0
    # invariant (and prevents an ordinary empty/genesis anchor from being
    # smuggled through the transport projection).
    if required(values, 8) == 0:
        raise fail("invalid_quorum")
    if not shares:
        raise fail("invalid_quorum")
    authors = [share["author"] for share in shares]
    if authors != sorted(authors) or len(set(authors)) != len(authors):
        raise fail("invalid_signer")
    signed_power = sum(context["validators"].get(author, 0) for author in authors)
    if any(author not in context["validators"] for author in authors):
        raise fail("invalid_signer")
    quorum = (context["total_power"] * 2) // 3 + 1
    if signed_power < quorum:
        raise fail("invalid_quorum")
    qc = {
        "view": values[8],
        "height": required(values, 9),
        "block_id": required(values, 10),
        "shares": shares,
        "validator_set_hash": context["validator_set_hash"],
    }
    expected = qc_digest(context, qc)
    if required(values, 12) != expected:
        raise fail("digest_mismatch")
    qc["digest"] = expected
    return qc


def timeout_signing_root(context: dict[str, Any], timeout_view: int, high: dict[str, Any]) -> bytes:
    common = (
        u16(0)
        + context["genesis_hash"]
        + consensus_string(context["chain_id"])
        + u32(0)
        + u64(context["epoch"])
        + context["validator_set_hash"]
        + u64(timeout_view)
        + b"\x02"
    )
    ref = high["digest"] + u64(high["epoch"]) + u64(high["view"]) + u64(high["height"]) + high["block_id"]
    return hash_domain(b"trnm.poco-bft.timeout.v0", common + ref)


def parse_timeout_vote(
    data: bytes, context: dict[str, Any], outer_view: int, expected_view: int | None, depth: int
) -> dict[str, Any]:
    cursor = Cursor(data, depth)
    values: dict[int, Any] = {}
    while not cursor.done():
        start, field, wire = cursor.field(4)
        if field == 1:
            values[field] = parse_context(cursor.nested(start, wire), context, 2, outer_view, depth + 1)
        elif field == 2:
            values[field] = parse_high_qc(cursor.nested(start, wire), context, depth + 1)
        elif field == 3:
            values[field] = cursor.bytes(start, wire, MAX_VALIDATOR_ID_BYTES)
        elif field == 4:
            values[field] = cursor.signature(start, wire)
        else:
            raise fail("unknown_field", start)
    context_value = required(values, 1)
    view = context_value["view"]
    if expected_view is not None and view != expected_view:
        raise fail("scope_mismatch")
    high = required(values, 2)
    if high["epoch"] != context["epoch"] or high["view"] > view:
        raise fail("scope_mismatch")
    author = required(values, 3)
    if not author or author not in context["validators"]:
        raise fail("invalid_signer")
    return {"view": view, "high": high, "author": author, "signature": required(values, 4)}


def canonical_tc(context: dict[str, Any], tc: dict[str, Any]) -> bytes:
    def entry_bytes(entry: dict[str, Any]) -> bytes:
        high = entry["high"]
        return (
            frame(entry["author"])
            + high["digest"]
            + u64(high["epoch"])
            + u64(high["view"])
            + u64(high["height"])
            + high["block_id"]
            + entry["signature"]
        )

    encoded = (
        u16(0)
        + context["genesis_hash"]
        + consensus_string(context["chain_id"])
        + u32(0)
        + u64(context["epoch"])
        + context["validator_set_hash"]
        + u64(tc["timed_out_view"])
        + u32(len(tc["entries"]))
        + b"".join(entry_bytes(entry) for entry in tc["entries"])
        + u32(len(tc["qcs"]))
        + b"".join(canonical_qc(context, qc) for qc in tc["qcs"])
        + tc["selected"]
    )
    return encoded


def parse_tc(
    data: bytes,
    context: dict[str, Any],
    outer_view: int,
    depth: int,
    aggregate: list[int],
    maximum_aggregate: int,
) -> dict[str, Any]:
    cursor = Cursor(data, depth)
    values: dict[int, Any] = {}
    entries: list[dict[str, Any]] = []
    qcs: list[dict[str, Any]] = []
    while not cursor.done():
        start, field, wire = cursor.field(13, {9, 10})
        if field == 9:
            if len(entries) >= MAX_LIST_ITEMS or len(entries) >= len(context["validators"]):
                raise fail("aggregate_limit_exceeded", start)
            entries.append(
                parse_timeout_vote(
                    cursor.nested(start, wire), context, outer_view, values.get(8), depth + 1
                )
            )
        elif field == 10:
            if len(qcs) >= MAX_LIST_ITEMS or len(qcs) >= len(context["validators"]):
                raise fail("aggregate_limit_exceeded", start)
            qcs.append(
                parse_qc(
                    cursor.nested(start, wire),
                    context,
                    None,
                    depth + 1,
                    aggregate,
                    maximum_aggregate,
                )
            )
        elif field in (1, 4):
            values[field] = cursor.scalar(start, wire, 32)
        elif field in (5, 8):
            values[field] = cursor.scalar(start, wire, 64)
        elif field in (2, 6, 7, 11, 12):
            values[field] = cursor.fixed32(start, wire) if field != 7 else cursor.fixed32(start, wire)
        elif field == 3:
            values[field] = cursor.bytes(start, wire, MAX_CHAIN_ID_BYTES)
        elif field == 13:
            raise fail("unsupported_body_kind", start)
        else:
            raise fail("unknown_field", start)
    if required(values, 1) != 0 or required(values, 4) != 0:
        raise fail("scope_mismatch")
    for key in (2, 3, 5, 6, 7):
        if required(values, key) != context["genesis_hash" if key == 2 else "chain_id" if key == 3 else "epoch" if key == 5 else "validator_set_hash" if key == 6 else "consensus_parameters_hash"]:
            raise fail("scope_mismatch")
    timed_out_view = required(values, 8)
    if timed_out_view != outer_view or not entries or not qcs:
        raise fail("invalid_quorum")
    # Field 8 is canonically before the repeated entry field, but keep the
    # relation explicit even when this independent parser is exercised with a
    # reordered/mutated stream.  Otherwise an entry parsed while field 8 was
    # still absent could retain an unrelated view and the later aggregate
    # checks would accidentally accept it.
    if any(entry["view"] != timed_out_view for entry in entries):
        raise fail("scope_mismatch")
    authors = [entry["author"] for entry in entries]
    if authors != sorted(authors) or len(set(authors)) != len(authors):
        raise fail("invalid_signer")
    signed_power = sum(context["validators"].get(author, 0) for author in authors)
    if any(author not in context["validators"] for author in authors):
        raise fail("invalid_signer")
    quorum = (context["total_power"] * 2) // 3 + 1
    if signed_power < quorum:
        raise fail("invalid_quorum")
    qcs_by_digest = {qc["digest"]: qc for qc in qcs}
    if len(qcs_by_digest) != len(qcs) or [qc["digest"] for qc in qcs] != sorted(qc["digest"] for qc in qcs):
        raise fail("validation_failed")
    # Mirror the typed TC relation checks before resolving entry references:
    # every referenced QC is at or below the timed-out view, no two QCs
    # certify different blocks at one (epoch, view), and one block ID cannot
    # be reused at unrelated coordinates.
    coordinates: dict[tuple[int, int], tuple[int, bytes]] = {}
    block_coordinates: dict[bytes, tuple[int, int, int]] = {}
    for qc in qcs:
        if qc["view"] > timed_out_view:
            raise fail("validation_failed")
        coordinate = (context["epoch"], qc["view"])
        certified = (qc["height"], qc["block_id"])
        prior = coordinates.get(coordinate)
        if prior is not None and prior != certified:
            raise fail("validation_failed")
        coordinates[coordinate] = certified
        block_coordinate = (context["epoch"], qc["view"], qc["height"])
        prior_coordinate = block_coordinates.get(qc["block_id"])
        if prior_coordinate is not None and prior_coordinate != block_coordinate:
            raise fail("validation_failed")
        block_coordinates[qc["block_id"]] = block_coordinate
    used: set[bytes] = set()
    for entry in entries:
        high = entry["high"]
        match = next(
            (
                qc
                for qc in qcs
                if high["digest"] == qc["digest"]
                and high["epoch"] == context["epoch"]
                and high["view"] == qc["view"]
                and high["height"] == qc["height"]
                and high["block_id"] == qc["block_id"]
            ),
            None,
        )
        if match is None:
            raise fail("validation_failed")
        used.add(match["digest"])
    if used != set(qcs_by_digest):
        raise fail("validation_failed")
    maximum = max(qcs, key=lambda qc: (qc["view"], qc["block_id"], qc["digest"]))
    if required(values, 11) != maximum["digest"]:
        raise fail("validation_failed")
    tc = {"timed_out_view": timed_out_view, "entries": entries, "qcs": qcs, "selected": maximum["digest"]}
    expected = hash_domain(b"trnm.poco-bft.tc.v0", canonical_tc(context, tc))
    if required(values, 12) != expected:
        raise fail("digest_mismatch")
    tc["digest"] = expected
    return tc


def parse_envelope(data: bytes, context: dict[str, Any], maximum_aggregate: int) -> dict[str, Any]:
    if not data:
        raise fail("empty")
    if len(data) > MAX_ENVELOPE_BYTES:
        raise fail("envelope_too_large")
    # The frozen outer preflight intentionally checks duplicate fields but
    # does not make transport field order an admission rule. Nested logical
    # messages below do require canonical ascending order.
    cursor = Cursor(data, 0, ordered=False)
    values: dict[int, Any] = {}
    body: bytes | None = None
    body_kind: int | None = None
    while not cursor.done():
        start, field, wire = cursor.field(45)
        if 32 <= field <= 45:
            if body is not None:
                raise fail("duplicate_field", start)
            body = cursor.bytes(start, wire, MAX_BODY_BYTES)
            body_kind = field - 31
        elif field in (1, 2, 5, 10, 11, 12):
            values[field] = cursor.scalar(start, wire, 32)
        elif field in (6, 7, 15):
            values[field] = cursor.scalar(start, wire, 64)
        elif field in (3, 8, 9, 16):
            values[field] = cursor.bytes(start, wire, 32)
        elif field == 4:
            values[field] = cursor.bytes(start, wire, MAX_CHAIN_ID_BYTES)
        elif field == 13:
            values[field] = cursor.bytes(start, wire, 32)
        elif field == 14:
            values[field] = cursor.bytes(start, wire, 64)
        else:
            raise fail("unknown_field", start)
    for field in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15):
        required(values, field)
    if values[3] == bytes(32) or values[8] == bytes(32) or values[9] == bytes(32):
        raise fail("invalid_value")
    if values.get(1) != 0 or values.get(2) != 0 or values.get(5) != 0:
        raise fail("invalid_value")
    try:
        consensus_string(values[4])
    except ReferenceError:
        raise fail("invalid_value")
    if values.get(3) != context["genesis_hash"] or values.get(4) != context["chain_id"]:
        raise fail("scope_mismatch")
    if values.get(6) != context["epoch"] or values.get(8) != context["validator_set_hash"]:
        raise fail("scope_mismatch")
    if values.get(9) != context["consensus_parameters_hash"]:
        raise fail("scope_mismatch")
    if (
        not values.get(13)
        or len(values[13]) != 32
        or values[13] == bytes(32)
        or not values.get(14)
    ):
        raise fail("invalid_value")
    if body is None or body_kind is None or not body:
        raise fail("missing_field")
    if values.get(16) is not None:
        if len(values[16]) != 32:
            raise fail("invalid_value")
        if values[16] != hashlib.sha256(body).digest():
            raise fail("digest_mismatch")
    if values.get(10) not in (0, 1):
        raise fail("invalid_value")
    msg_kind = values.get(11)
    if values.get(10) == 1 and msg_kind is None:
        raise fail("invalid_consensus_message_kind")
    if values.get(10) == 0 and msg_kind is not None:
        raise fail("invalid_consensus_message_kind")
    if body_kind in (1, 2, 3, 8):
        expected = {1: 0, 2: 1, 3: 2, 8: (3, 4)}[body_kind]
        if msg_kind not in (expected if isinstance(expected, tuple) else (expected,)):
            raise fail("invalid_consensus_message_kind")
    elif msg_kind is not None:
        raise fail("invalid_consensus_message_kind")
    if body_kind not in BODY_NAMES:
        raise fail("invalid_body_kind")
    if values[12] != body_kind:
        raise fail("body_kind_mismatch")
    return {
        "body_kind": body_kind,
        "view": values.get(7, 0),
        "message_kind": msg_kind,
        "body": body,
        "values": values,
        "maximum_aggregate": maximum_aggregate,
    }


def semantic_decode(data: bytes, context: dict[str, Any], maximum_aggregate: int) -> dict[str, Any]:
    envelope = parse_envelope(data, context, maximum_aggregate)
    kind = envelope["body_kind"]
    aggregate = [0]
    if kind == 2:
        body = parse_vote(envelope["body"], context, envelope["view"])
        digest = hash_domain(
            b"trnm.poco-bft.vote.v0",
            (
                u16(0)
                + context["genesis_hash"]
                + consensus_string(context["chain_id"])
                + u32(0)
                + u64(context["epoch"])
                + context["validator_set_hash"]
                + u64(body["view"])
                + b"\x01"
                + u64(body["height"])
                + body["block_id"]
            ),
        )
        aggregate[0] = 1
        return {"kind": "vote", "digest": digest, "signers": 1, "nested_qcs": 0, "aggregate": 1}
    if kind == 3:
        body = parse_timeout_vote(envelope["body"], context, envelope["view"], None, 0)
        digest = timeout_signing_root(context, body["view"], body["high"])
        aggregate[0] = 1
        return {"kind": "timeout_vote", "digest": digest, "signers": 1, "nested_qcs": 0, "aggregate": 1}
    if kind == 4:
        qc = parse_qc(
            envelope["body"], context, envelope["view"], 0, aggregate, maximum_aggregate
        )
        if aggregate[0] > maximum_aggregate:
            raise fail("aggregate_limit_exceeded")
        return {
            "kind": "quorum_certificate",
            "digest": qc["digest"],
            "signers": len(qc["shares"]),
            "nested_qcs": 0,
            "aggregate": aggregate[0],
        }
    if kind == 5:
        tc = parse_tc(
            envelope["body"], context, envelope["view"], 0, aggregate, maximum_aggregate
        )
        if aggregate[0] > maximum_aggregate:
            raise fail("aggregate_limit_exceeded")
        work = aggregate[0] + len(tc["entries"])
        return {
            "kind": "timeout_certificate",
            "digest": tc["digest"],
            "signers": len(tc["entries"]),
            "nested_qcs": len(tc["qcs"]),
            "aggregate": work,
        }
    raise fail("unsupported_body_kind")


def reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReferenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_vector(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_json_pairs)
    except (OSError, json.JSONDecodeError, ReferenceError) as error:
        raise ReferenceError(f"invalid vector {path}: {error}") from error


def context_from_vector(value: dict[str, Any]) -> dict[str, Any]:
    raw = value["context"]
    if type(raw.get("protocol_version")) is not int or raw.get("protocol_version") != 0:
        raise ReferenceError("only protocol v0 is supported")
    if not isinstance(raw.get("chain_id"), str):
        raise ReferenceError("chain_id must be text")
    context = {
        "genesis_hash": strict_hex(raw["genesis_hash_hex"], 32, "genesis_hash"),
        "chain_id": raw["chain_id"].encode("ascii"),
        "epoch": raw["epoch"],
        "validator_set_hash": strict_hex(raw["validator_set_hash_hex"], 32, "validator_set_hash"),
        "consensus_parameters_hash": strict_hex(raw["consensus_parameters_hash_hex"], 32, "consensus_parameters_hash"),
        "validators": {},
        # Retain public keys in the independent context projection when an
        # authenticated corpus supplies them.  Existing structural vectors
        # remain unchanged: their crypto-inert keys are still parsed only for
        # set-hash reconstruction.
        "public_keys": {},
        "total_power": 0,
    }
    if type(context["epoch"]) is not int or context["epoch"] < 0:
        raise ReferenceError("epoch must be a non-negative integer")
    validators = raw["validators"]
    if not isinstance(validators, list) or not (4 <= len(validators) <= MAX_VALIDATORS):
        raise ReferenceError("validator count outside v0 bounds")
    previous = None
    public_keys: set[bytes] = set()
    encoded = bytearray(
        u16(0)
        + context["genesis_hash"]
        + consensus_string(context["chain_id"])
        + u32(0)
        + u64(context["epoch"])
        + context["consensus_parameters_hash"]
        + u32(len(validators))
    )
    for item in validators:
        identifier = strict_hex(
            item["validator_id_hex"], len(bytes.fromhex(item["validator_id_hex"])), "validator id"
        )
        if not identifier or len(identifier) > MAX_VALIDATOR_ID_BYTES:
            raise ReferenceError("validator id bound")
        power = item["power"]
        if type(power) is not int or power <= 0 or power >= 1 << 64:
            raise ReferenceError("validator power must be positive")
        if previous is not None and identifier <= previous:
            raise ReferenceError("validator IDs must be sorted")
        previous = identifier
        key = strict_hex(item["consensus_public_key_hex"], 32, "consensus public key")
        if key == bytes(32):
            raise ReferenceError("consensus public key must be nonzero")
        if key in public_keys:
            raise ReferenceError("duplicate consensus public key")
        public_keys.add(key)
        context["validators"][identifier] = power
        context["public_keys"][identifier] = key
        context["total_power"] += power
        encoded.extend(frame(identifier) + key + u64(power))
    expected_set = hash_domain(b"trnm.poco-bft.validator-set.v0", bytes(encoded))
    if expected_set != context["validator_set_hash"]:
        raise ReferenceError("validator_set_hash does not recompute")
    return context


def _common(context: dict[str, Any], view: int, message_kind: int) -> bytes:
    return b"".join(
        (
            field_varint(1, 0),
            field_bytes(2, context["genesis_hash"]),
            field_bytes(3, context["chain_id"]),
            field_varint(4, 0),
            field_varint(5, context["epoch"]),
            field_bytes(6, context["validator_set_hash"]),
            field_varint(7, view),
            field_varint(8, message_kind),
            field_bytes(9, context["consensus_parameters_hash"]),
        )
    )


def _scope(context: dict[str, Any]) -> bytes:
    return b"".join(
        (
            field_varint(1, 0),
            field_bytes(2, context["genesis_hash"]),
            field_bytes(3, context["chain_id"]),
            field_varint(4, 0),
            field_varint(5, context["epoch"]),
            field_bytes(6, context["validator_set_hash"]),
            field_bytes(7, context["consensus_parameters_hash"]),
        )
    )


def _high(reference: dict[str, Any]) -> bytes:
    return b"".join(
        (
            field_bytes(1, reference["digest"]),
            field_varint(2, reference["epoch"]),
            field_varint(3, reference["view"]),
            field_varint(4, reference["height"]),
            field_bytes(5, reference["block_id"]),
        )
    )


def _share(share: dict[str, bytes]) -> bytes:
    return field_bytes(1, share["author"]) + field_bytes(2, share["signature"])


def _qc_body(context: dict[str, Any], qc: dict[str, Any]) -> bytes:
    result = bytearray(_scope(context))
    result.extend(field_varint(8, qc["view"]))
    result.extend(field_varint(9, qc["height"]))
    result.extend(field_bytes(10, qc["block_id"]))
    for share in qc["shares"]:
        result.extend(field_bytes(11, _share(share)))
    result.extend(field_bytes(12, qc["digest"]))
    return bytes(result)


def _timeout_body(context: dict[str, Any], vote: dict[str, Any]) -> bytes:
    return (
        field_bytes(1, _common(context, vote["view"], 2))
        + field_bytes(2, _high(vote["high"]))
        + field_bytes(3, vote["author"])
        + field_bytes(4, vote["signature"])
    )


def _vote_body(context: dict[str, Any]) -> bytes:
    block_id = bytes([0x42] * 32)
    return (
        field_bytes(1, _common(context, 1, 1))
        + field_varint(2, 1)
        + field_bytes(3, block_id)
        + field_bytes(4, bytes([1] * 32))
        + field_bytes(5, bytes([0xA1] * 64))
    )


def _outer(context: dict[str, Any], kind: int, view: int, body: bytes, message_kind: int | None) -> bytes:
    result = bytearray()
    result.extend(field_varint(1, 0))
    result.extend(field_varint(2, 0))
    result.extend(field_bytes(3, context["genesis_hash"]))
    result.extend(field_bytes(4, context["chain_id"]))
    result.extend(field_varint(5, 0))
    result.extend(field_varint(6, context["epoch"]))
    result.extend(field_varint(7, view))
    result.extend(field_bytes(8, context["validator_set_hash"]))
    result.extend(field_bytes(9, context["consensus_parameters_hash"]))
    result.extend(field_varint(10, int(message_kind is not None)))
    if message_kind is not None:
        result.extend(field_varint(11, message_kind))
    result.extend(field_varint(12, kind))
    result.extend(field_bytes(13, bytes([0x81] * 32)))
    result.extend(field_bytes(14, bytes([0x71] * 16)))
    result.extend(field_varint(15, 0))
    result.extend(field_bytes(16, hashlib.sha256(body).digest()))
    result.extend(field_bytes(31 + kind, body))
    return bytes(result)


def vote_signing_root(
    context: dict[str, Any], view: int, height: int, block_id: bytes
) -> bytes:
    """Rebuild the exact CEV0 VoteSignV0 root used by nested signatures."""

    return hash_domain(
        DOMAIN_VOTE,
        u16(0)
        + context["genesis_hash"]
        + consensus_string(context["chain_id"])
        + u32(0)
        + u64(context["epoch"])
        + context["validator_set_hash"]
        + u64(view)
        + b"\x01"
        + u64(height)
        + block_id,
    )


def _raw_fields(
    data: bytes, maximum: int, repeated: set[int] | frozenset[int] = frozenset()
) -> dict[int, list[int | bytes]]:
    """Read already-semantic-validated protobuf fields for auth extraction.

    This intentionally performs a second, tiny field walk rather than relying
    on the Rust projection or on an object serializer.  The semantic parser
    has already checked field types; retaining the raw nested bytes here lets
    the independent verifier bind each signature to the exact CEV0 root.
    """

    cursor = Cursor(data, 0)
    values: dict[int, list[int | bytes]] = {}
    while not cursor.done():
        offset, field, wire_type = cursor.field(maximum, repeated)
        if wire_type == 0:
            value: int | bytes = cursor.scalar(offset, wire_type, 64)
        else:
            value = cursor.bytes(offset, wire_type, MAX_BODY_BYTES)
        values.setdefault(field, []).append(value)
    return values


def _single_field(values: dict[int, list[int | bytes]], field: int) -> int | bytes:
    items = values.get(field)
    if items is None or len(items) != 1:
        raise AuthenticatedReferenceError("missing_or_duplicate_signature_field")
    return items[0]


def _bytes_field(values: dict[int, list[int | bytes]], field: int) -> bytes:
    value = _single_field(values, field)
    if not isinstance(value, bytes):
        raise AuthenticatedReferenceError("signature_field_type_mismatch")
    return value


def _int_field(values: dict[int, list[int | bytes]], field: int) -> int:
    value = _single_field(values, field)
    if not isinstance(value, int):
        raise AuthenticatedReferenceError("signature_field_type_mismatch")
    return value


def _auth_vote_records(
    data: bytes, context: dict[str, Any], outer_view: int
) -> list[dict[str, bytes]]:
    values = _raw_fields(data, 5)
    parsed_context = parse_context(
        _bytes_field(values, 1), context, 1, outer_view, 1
    )
    author = _bytes_field(values, 4)
    signature = _bytes_field(values, 5)
    root = vote_signing_root(
        context,
        parsed_context["view"],
        _int_field(values, 2),
        _bytes_field(values, 3),
    )
    return [{"author": author, "root": root, "signature": signature}]


def _auth_timeout_vote_records(
    data: bytes,
    context: dict[str, Any],
    outer_view: int,
    expected_view: int | None,
) -> list[dict[str, bytes]]:
    values = _raw_fields(data, 4)
    parsed_context = parse_context(
        _bytes_field(values, 1), context, 2, outer_view, 1
    )
    high_values = _raw_fields(_bytes_field(values, 2), 5)
    high = {
        "digest": _bytes_field(high_values, 1),
        "epoch": _int_field(high_values, 2),
        "view": _int_field(high_values, 3),
        "height": _int_field(high_values, 4),
        "block_id": _bytes_field(high_values, 5),
    }
    if expected_view is not None and parsed_context["view"] != expected_view:
        raise AuthenticatedReferenceError("timeout_view_mismatch")
    return [
        {
            "author": _bytes_field(values, 3),
            "root": timeout_signing_root(context, parsed_context["view"], high),
            "signature": _bytes_field(values, 4),
        }
    ]


def _auth_qc_records(
    data: bytes, context: dict[str, Any], outer_view: int | None
) -> list[dict[str, bytes]]:
    values = _raw_fields(data, 12, {11})
    view = _int_field(values, 8)
    height = _int_field(values, 9)
    block_id = _bytes_field(values, 10)
    records: list[dict[str, bytes]] = []
    for raw_share in values.get(11, []):
        if not isinstance(raw_share, bytes):
            raise AuthenticatedReferenceError("signature_share_type_mismatch")
        share_values = _raw_fields(raw_share, 2)
        author = _bytes_field(share_values, 1)
        records.append(
            {
                "author": author,
                "root": vote_signing_root(context, view, height, block_id),
                "signature": _bytes_field(share_values, 2),
            }
        )
    if outer_view is not None and view != outer_view:
        raise AuthenticatedReferenceError("qc_view_mismatch")
    return records


def authenticated_signature_records(
    frame: bytes, context: dict[str, Any], maximum_aggregate: int
) -> list[dict[str, bytes]]:
    """Extract every nested signature and its exact CEV0 signing root."""

    envelope = parse_envelope(frame, context, maximum_aggregate)
    kind = envelope["body_kind"]
    body = envelope["body"]
    if kind == 2:
        return _auth_vote_records(body, context, envelope["view"])
    if kind == 3:
        return _auth_timeout_vote_records(
            body, context, envelope["view"], None
        )
    if kind == 4:
        return _auth_qc_records(body, context, envelope["view"])
    if kind != 5:
        raise AuthenticatedReferenceError("unsupported_body_kind")

    values = _raw_fields(body, 13, {9, 10})
    timed_out_view = _int_field(values, 8)
    records: list[dict[str, bytes]] = []
    for raw_entry in values.get(9, []):
        if not isinstance(raw_entry, bytes):
            raise AuthenticatedReferenceError("timeout_entry_type_mismatch")
        records.extend(
            _auth_timeout_vote_records(
                raw_entry, context, envelope["view"], timed_out_view
            )
        )
    for raw_qc in values.get(10, []):
        if not isinstance(raw_qc, bytes):
            raise AuthenticatedReferenceError("nested_qc_type_mismatch")
        records.extend(_auth_qc_records(raw_qc, context, None))
    return records


def verify_authenticated_signatures(
    frame: bytes, context: dict[str, Any], maximum_aggregate: int
) -> list[dict[str, bytes]]:
    records = authenticated_signature_records(frame, context, maximum_aggregate)
    if not records:
        raise AuthenticatedReferenceError("missing_signature_records")
    for record in records:
        public_key = context["public_keys"].get(record["author"])
        if public_key is None:
            raise AuthenticatedReferenceError("invalid_signer")
        if not ed25519_verify(public_key, record["root"], record["signature"]):
            raise AuthenticatedReferenceError("invalid_signature")
    return records


def build_reference() -> dict[str, Any]:
    genesis = bytes([0x99] * 32)
    chain = b"trnm-wire-semantic"
    parameters_hash = bytes.fromhex("49e6ddaf2ef8e59844b0fd8fc78322019cd04ce3b704466d71c5f7b8d8e0b885")
    validators = [
        {
            "validator_id_hex": bytes([i] * 32).hex(),
            "consensus_public_key_hex": bytes([0x10 + i] * 32).hex(),
            "power": 1,
        }
        for i in range(1, 5)
    ]
    context = {
        "genesis_hash": genesis,
        "chain_id": chain,
        "epoch": 0,
        "consensus_parameters_hash": parameters_hash,
        "validators": {bytes([i] * 32): 1 for i in range(1, 5)},
        "total_power": 4,
    }
    encoded_set = bytearray(
        u16(0) + genesis + consensus_string(chain) + u32(0) + u64(0) + parameters_hash + u32(4)
    )
    for item in validators:
        encoded_set.extend(
            frame(bytes.fromhex(item["validator_id_hex"]))
            + bytes.fromhex(item["consensus_public_key_hex"])
            + u64(item["power"])
        )
    context["validator_set_hash"] = hash_domain(
        b"trnm.poco-bft.validator-set.v0", bytes(encoded_set)
    )
    block_id = bytes([0x42] * 32)
    shares = [
        {"author": bytes([i] * 32), "signature": bytes([0xA0 + i] * 64)}
        for i in range(1, 4)
    ]
    qc = {"view": 1, "height": 1, "block_id": block_id, "shares": shares}
    qc["digest"] = qc_digest(context, qc)
    high = {
        "digest": qc["digest"],
        "epoch": 0,
        "view": 1,
        "height": 1,
        "block_id": block_id,
    }
    timeout_votes = [
        {
            "view": 2,
            "high": high,
            "author": bytes([i] * 32),
            "signature": bytes([0xD0 + i] * 64),
        }
        for i in range(1, 4)
    ]
    tc = {"timed_out_view": 2, "entries": timeout_votes, "qcs": [qc], "selected": qc["digest"]}
    tc["digest"] = hash_domain(b"trnm.poco-bft.tc.v0", canonical_tc(context, tc))
    vote_body = _vote_body(context)
    timeout_body = _timeout_body(context, timeout_votes[0])
    qc_body = _qc_body(context, qc)
    tc_body = bytearray(_scope(context))
    tc_body.extend(field_varint(8, 2))
    for vote in timeout_votes:
        tc_body.extend(field_bytes(9, _timeout_body(context, vote)))
    tc_body.extend(field_bytes(10, _qc_body(context, qc)))
    tc_body.extend(field_bytes(11, tc["selected"]))
    tc_body.extend(field_bytes(12, tc["digest"]))
    cases = []
    for case_id, kind, view, body, msg, digest, signers, nested, aggregate, name in (
        ("vote", 2, 1, vote_body, 1, hash_domain(b"trnm.poco-bft.vote.v0", u16(0) + genesis + consensus_string(chain) + u32(0) + u64(0) + context["validator_set_hash"] + u64(1) + b"\x01" + u64(1) + block_id), 1, 0, 1, "vote"),
        ("timeout_vote", 3, 2, timeout_body, 2, timeout_signing_root(context, 2, high), 1, 0, 1, "timeout_vote"),
        ("quorum_certificate", 4, 1, qc_body, None, qc["digest"], 3, 0, 3, "quorum_certificate"),
        ("timeout_certificate", 5, 2, bytes(tc_body), None, tc["digest"], 3, 1, 6, "timeout_certificate"),
    ):
        cases.append(
            {
                "id": case_id,
                "kind": name,
                "body_kind": kind,
                "view": view,
                "message_kind": msg,
                "frame_hex": _outer(context, kind, view, body, msg).hex(),
                "semantic_digest_hex": digest.hex(),
                "signers": signers,
                "nested_qcs": nested,
                "aggregate": aggregate,
            }
        )
    mutation_count = sum(len(bytes.fromhex(case["frame_hex"])) * 3 for case in cases)
    return {
        "schema": "trnm_poco_bft_wire_semantic_reference_v0",
        "schema_version": 0,
        "status": "bounded-reference-only",
        "wire_conformance": False,
        "activation": False,
        "scope": "Vote/TimeoutVote/QC/TC nested protobuf plus authenticated CEV0 reconstruction; this structural reference corpus remains crypto-neutral, while a separate candidate-only P2P seam performs strict nested Ed25519 verification; other body kinds, production authenticated P2P, wire_conformance, and activation remain disabled",
        "context": {
            "genesis_hash_hex": genesis.hex(),
            "chain_id": chain.decode(),
            "protocol_version": 0,
            "epoch": 0,
            "validator_set_hash_hex": context["validator_set_hash"].hex(),
            "consensus_parameters_hash_hex": parameters_hash.hex(),
            "validators": validators,
        },
        "limits": {
            "max_body_bytes": MAX_BODY_BYTES,
            "max_envelope_bytes": MAX_ENVELOPE_BYTES,
            "max_nested_depth": MAX_NESTED_DEPTH,
            "max_nested_fields": MAX_NESTED_FIELDS,
            "max_list_items": MAX_LIST_ITEMS,
            "max_tc_aggregate_signature_shares": 16,
            "signature_bytes": SIGNATURE_BYTES,
        },
        "mutation_contract": {
            "strict_prefix": "every length 0..frame_length-1 rejects",
            "byte_masks": [1, 128, 255],
            "expected_mutation_cases": mutation_count,
            "narrow_tc_aggregate_limit": 2,
        },
        "cases": cases,
    }


def check_vector(value: dict[str, Any]) -> tuple[int, int, int]:
    if value.get("schema") != "trnm_poco_bft_wire_semantic_reference_v0":
        raise ReferenceError("unexpected vector schema")
    if value.get("schema_version") != 0 or value.get("wire_conformance") is not False:
        raise ReferenceError("vector status/version drift")
    context = context_from_vector(value)
    cases = value.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ReferenceError("vector must contain cases")
    accepted = 0
    mutations = 0
    contract = value.get("mutation_contract", {})
    for case in cases:
        frame_bytes = bytes.fromhex(case["frame_hex"])
        result = semantic_decode(frame_bytes, context, int(value["limits"]["max_tc_aggregate_signature_shares"]))
        if result["kind"] != case["kind"]:
            raise ReferenceError(f"{case['id']}: kind mismatch")
        if result["digest"].hex() != case["semantic_digest_hex"]:
            raise ReferenceError(f"{case['id']}: digest mismatch")
        for key in ("signers", "nested_qcs", "aggregate"):
            if result[key] != case[key]:
                raise ReferenceError(f"{case['id']}: {key} mismatch")
        accepted += 1
        # Every strict prefix must reject; this is the bounded fuzz corpus
        # that catches slice/length/panic regressions in both implementations.
        for length in range(len(frame_bytes)):
            try:
                semantic_decode(frame_bytes[:length], context, int(value["limits"]["max_tc_aggregate_signature_shares"]))
            except DecodeError:
                pass
            else:
                raise ReferenceError(f"{case['id']}: accepted truncated frame at {length}")
        for offset in range(len(frame_bytes)):
            for mask in (0x01, 0x80, 0xFF):
                mutated = bytearray(frame_bytes)
                mutated[offset] ^= mask
                try:
                    result = semantic_decode(
                        bytes(mutated),
                        context,
                        int(value["limits"]["max_tc_aggregate_signature_shares"]),
                    )
                except DecodeError:
                    pass
                else:
                    # A crypto-inert signature/transport mutation can remain
                    # structurally valid, but it must not become a different
                    # semantic object under the same fixture case.
                    if result["kind"] != case["kind"] or result["digest"].hex() != case["semantic_digest_hex"]:
                        raise ReferenceError(f"{case['id']}: mutation changed semantic identity")
                mutations += 1

    tc_case = next((case for case in cases if case["kind"] == "timeout_certificate"), None)
    if tc_case is not None:
        try:
            semantic_decode(
                bytes.fromhex(tc_case["frame_hex"]),
                context,
                int(contract.get("narrow_tc_aggregate_limit", 2)),
            )
        except DecodeError as error:
            if error.code != "aggregate_limit_exceeded":
                raise ReferenceError(f"TC narrow-budget code drift: {error.code}")
        else:
            raise ReferenceError("TC accepted beyond the authenticated aggregate share limit")
    expected_mutations = contract.get("expected_mutation_cases")
    if expected_mutations is not None and mutations != expected_mutations:
        raise ReferenceError(
            f"mutation corpus count drift: got {mutations}, expected {expected_mutations}"
        )
    return accepted, len(cases), mutations


# Deterministic test-only seeds for the authenticated corpus.  They are kept
# in the checker (and deliberately omitted from the JSON vector) so a clean
# clone can reproduce the public keys/signatures without publishing private
# key material.  The values are not used by any node or signing API.
_AUTHENTICATED_SEEDS = tuple(
    bytes.fromhex(f"{index:064x}") for index in range(1, 5)
)


def _authenticated_context() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    genesis = bytes([0x99] * 32)
    chain = b"trnm-wire-auth"
    parameters_hash = bytes.fromhex(
        "49e6ddaf2ef8e59844b0fd8fc78322019cd04ce3b704466d71c5f7b8d8e0b885"
    )
    validators: list[dict[str, Any]] = []
    for index, seed in enumerate(_AUTHENTICATED_SEEDS, 1):
        validators.append(
            {
                "validator_id_hex": bytes([index] * 32).hex(),
                "consensus_public_key_hex": ed25519_public_key(seed).hex(),
                "power": 1,
            }
        )
    encoded_set = bytearray(
        u16(0)
        + genesis
        + consensus_string(chain)
        + u32(0)
        + u64(0)
        + parameters_hash
        + u32(len(validators))
    )
    for validator in validators:
        encoded_set.extend(
            frame(bytes.fromhex(validator["validator_id_hex"]))
            + bytes.fromhex(validator["consensus_public_key_hex"])
            + u64(validator["power"])
        )
    validator_set_hash = hash_domain(DOMAIN_VALIDATOR_SET, bytes(encoded_set))
    context = {
        "genesis_hash": genesis,
        "chain_id": chain,
        "epoch": 0,
        "validator_set_hash": validator_set_hash,
        "consensus_parameters_hash": parameters_hash,
        "validators": {
            bytes.fromhex(validator["validator_id_hex"]): validator["power"]
            for validator in validators
        },
        "public_keys": {
            bytes.fromhex(validator["validator_id_hex"]): bytes.fromhex(
                validator["consensus_public_key_hex"]
            )
            for validator in validators
        },
        "total_power": sum(validator["power"] for validator in validators),
    }
    return context, validators


def _signed_vote(
    context: dict[str, Any], signer: int, view: int, height: int, block_id: bytes
) -> dict[str, bytes]:
    author = bytes([signer] * 32)
    root = vote_signing_root(context, view, height, block_id)
    return {
        "author": author,
        "root": root,
        "signature": ed25519_sign(_AUTHENTICATED_SEEDS[signer - 1], root),
    }


def _signed_timeout_vote(
    context: dict[str, Any],
    signer: int,
    view: int,
    high: dict[str, bytes | int],
) -> dict[str, Any]:
    author = bytes([signer] * 32)
    root = timeout_signing_root(context, view, high)
    return {
        "view": view,
        "high": high,
        "author": author,
        "root": root,
        "signature": ed25519_sign(_AUTHENTICATED_SEEDS[signer - 1], root),
    }


def _signed_vote_body(
    context: dict[str, Any], vote: dict[str, bytes | int]
) -> bytes:
    return (
        field_bytes(1, _common(context, int(vote["view"]), 1))
        + field_varint(2, int(vote["height"]))
        + field_bytes(3, vote["block_id"])
        + field_bytes(4, vote["author"])
        + field_bytes(5, vote["signature"])
    )


def _authenticated_tc_body(
    context: dict[str, Any],
    tc: dict[str, Any],
) -> bytes:
    body = bytearray(_scope(context))
    body.extend(field_varint(8, tc["timed_out_view"]))
    for entry in tc["entries"]:
        body.extend(field_bytes(9, _timeout_body(context, entry)))
    for qc in tc["qcs"]:
        body.extend(field_bytes(10, _qc_body(context, qc)))
    body.extend(field_bytes(11, tc["selected"]))
    body.extend(field_bytes(12, tc["digest"]))
    return bytes(body)


def _signature_metadata(
    context: dict[str, Any], records: list[dict[str, bytes]]
) -> list[dict[str, str]]:
    return [
        {
            "validator_id_hex": record["author"].hex(),
            "signing_root_hex": record["root"].hex(),
            "signature_hex": record["signature"].hex(),
            "public_key_hex": context["public_keys"][record["author"]].hex(),
        }
        for record in records
    ]


def _auth_case(
    context: dict[str, Any],
    case_id: str,
    kind: int,
    view: int,
    body: bytes,
    message_kind: int | None,
    digest: bytes,
    records: list[dict[str, bytes]],
    nested_qcs: int,
) -> dict[str, Any]:
    frame_bytes = _outer(context, kind, view, body, message_kind)
    return {
        "id": case_id,
        "kind": BODY_NAMES[kind],
        "body_kind": kind,
        "view": view,
        "message_kind": message_kind,
        "frame_hex": frame_bytes.hex(),
        "semantic_digest_hex": digest.hex(),
        "signers": len(records) if kind != 5 else 3,
        "nested_qcs": nested_qcs,
        "aggregate": len(records),
        "signatures": _signature_metadata(context, records),
    }


def build_authenticated_reference() -> dict[str, Any]:
    """Build the public authenticated nested-wire corpus deterministically."""

    context, validators = _authenticated_context()
    block_id = bytes([0x42] * 32)
    vote = _signed_vote(context, 1, 1, 1, block_id)
    vote_body = _signed_vote_body(
        context,
        {
            "view": 1,
            "height": 1,
            "block_id": block_id,
            "author": vote["author"],
            "signature": vote["signature"],
        },
    )

    qc_shares = [_signed_vote(context, signer, 1, 1, block_id) for signer in (1, 2, 3)]
    qc = {
        "view": 1,
        "height": 1,
        "block_id": block_id,
        "shares": [
            {"author": share["author"], "signature": share["signature"]}
            for share in qc_shares
        ],
    }
    qc["digest"] = qc_digest(context, qc)
    high = {
        "digest": qc["digest"],
        "epoch": 0,
        "view": 1,
        "height": 1,
        "block_id": block_id,
    }
    timeout_entries = [
        _signed_timeout_vote(context, signer, 2, high) for signer in (1, 2, 3)
    ]
    tc = {
        "timed_out_view": 2,
        "entries": timeout_entries,
        "qcs": [qc],
        "selected": qc["digest"],
    }
    tc["digest"] = hash_domain(DOMAIN_TC, canonical_tc(context, tc))

    cases = [
        _auth_case(
            context,
            "vote",
            2,
            1,
            vote_body,
            1,
            vote["root"],
            [vote],
            0,
        ),
        _auth_case(
            context,
            "timeout_vote",
            3,
            2,
            _timeout_body(context, timeout_entries[0]),
            2,
            timeout_entries[0]["root"],
            [timeout_entries[0]],
            0,
        ),
        _auth_case(
            context,
            "quorum_certificate",
            4,
            1,
            _qc_body(context, qc),
            None,
            qc["digest"],
            qc_shares,
            0,
        ),
        _auth_case(
            context,
            "timeout_certificate",
            5,
            2,
            _authenticated_tc_body(context, tc),
            None,
            tc["digest"],
            timeout_entries + qc_shares,
            1,
        ),
    ]

    def flip(signature: bytes) -> bytes:
        mutated = bytearray(signature)
        mutated[0] ^= 1
        return bytes(mutated)

    # Recompute transport/body/certificate digests after each signature
    # mutation.  This is important: semantic decoding must still succeed so
    # the negative reaches the independent strict-authentication boundary.
    bad_vote = dict(vote)
    bad_vote["signature"] = flip(vote["signature"])
    bad_vote_body = _signed_vote_body(
        context,
        {
            "view": 1,
            "height": 1,
            "block_id": block_id,
            "author": bad_vote["author"],
            "signature": bad_vote["signature"],
        },
    )
    bad_vote_frame = _outer(context, 2, 1, bad_vote_body, 1)

    bad_timeout = dict(timeout_entries[0])
    bad_timeout["signature"] = flip(timeout_entries[0]["signature"])
    bad_timeout_frame = _outer(
        context, 3, 2, _timeout_body(context, bad_timeout), 2
    )

    bad_qc = {
        **qc,
        "shares": [dict(share) for share in qc["shares"]],
    }
    bad_qc["shares"][0]["signature"] = flip(bad_qc["shares"][0]["signature"])
    bad_qc["digest"] = qc_digest(context, bad_qc)
    bad_qc_frame = _outer(context, 4, 1, _qc_body(context, bad_qc), None)

    bad_tc_entries = [dict(entry) for entry in timeout_entries]
    bad_tc_entries[0]["signature"] = flip(bad_tc_entries[0]["signature"])
    bad_tc = {
        "timed_out_view": 2,
        "entries": bad_tc_entries,
        "qcs": [qc],
        "selected": qc["digest"],
    }
    bad_tc["digest"] = hash_domain(DOMAIN_TC, canonical_tc(context, bad_tc))
    bad_tc_frame = _outer(context, 5, 2, _authenticated_tc_body(context, bad_tc), None)

    # Mutating a nested QC changes the exact HighQCSummary in every timeout
    # entry.  Re-sign those timeout entries so the only invalid share is the
    # deliberately changed nested QC signature.
    nested_bad_qc = {
        **qc,
        "shares": [dict(share) for share in qc["shares"]],
    }
    nested_bad_qc["shares"][0]["signature"] = flip(
        nested_bad_qc["shares"][0]["signature"]
    )
    nested_bad_qc["digest"] = qc_digest(context, nested_bad_qc)
    nested_high = {
        "digest": nested_bad_qc["digest"],
        "epoch": 0,
        "view": 1,
        "height": 1,
        "block_id": block_id,
    }
    nested_entries = [
        _signed_timeout_vote(context, signer, 2, nested_high) for signer in (1, 2, 3)
    ]
    nested_tc = {
        "timed_out_view": 2,
        "entries": nested_entries,
        "qcs": [nested_bad_qc],
        "selected": nested_bad_qc["digest"],
    }
    nested_tc["digest"] = hash_domain(DOMAIN_TC, canonical_tc(context, nested_tc))
    nested_bad_qc_frame = _outer(
        context, 5, 2, _authenticated_tc_body(context, nested_tc), None
    )

    negatives = [
        {
            "id": "vote_signature_bitflip",
            "source_case_id": "vote",
            "mutation": "nested_vote_signature_bitflip",
            "expected_error": "invalid_signature",
            "frame_hex": bad_vote_frame.hex(),
        },
        {
            "id": "timeout_vote_signature_bitflip",
            "source_case_id": "timeout_vote",
            "mutation": "nested_timeout_signature_bitflip",
            "expected_error": "invalid_signature",
            "frame_hex": bad_timeout_frame.hex(),
        },
        {
            "id": "qc_signature_bitflip",
            "source_case_id": "quorum_certificate",
            "mutation": "nested_qc_signature_bitflip",
            "expected_error": "invalid_signature",
            "frame_hex": bad_qc_frame.hex(),
        },
        {
            "id": "tc_entry_signature_bitflip",
            "source_case_id": "timeout_certificate",
            "mutation": "nested_tc_entry_signature_bitflip",
            "expected_error": "invalid_signature",
            "frame_hex": bad_tc_frame.hex(),
        },
        {
            "id": "tc_nested_qc_signature_bitflip",
            "source_case_id": "timeout_certificate",
            "mutation": "nested_tc_qc_signature_bitflip",
            "expected_error": "invalid_signature",
            "frame_hex": nested_bad_qc_frame.hex(),
        },
        {
            "id": "tc_truncated",
            "source_case_id": "timeout_certificate",
            "mutation": "strict_final_byte_truncation",
            "expected_error": "unexpected_eof",
            "frame_hex": cases[3]["frame_hex"][:-2],
        },
    ]

    return {
        "schema": "trnm_poco_bft_wire_authenticated_reference_v0",
        "schema_version": 0,
        "status": "bounded-authenticated-reference-only",
        "wire_conformance": False,
        "activation": False,
        "algorithm": "RFC 8032 Ed25519 strict verification",
        "scope": "Independent strict authentication of every Vote/TimeoutVote/QC/TC signature in the semantic transport corpus; this is candidate evidence only and does not authorize P2P, Core, SafetyRules, network signing, wire_conformance, or activation.",
        "context": {
            "genesis_hash_hex": context["genesis_hash"].hex(),
            "chain_id": context["chain_id"].decode(),
            "protocol_version": 0,
            "epoch": 0,
            "validator_set_hash_hex": context["validator_set_hash"].hex(),
            "consensus_parameters_hash_hex": context[
                "consensus_parameters_hash"
            ].hex(),
            "validators": validators,
        },
        "limits": {
            "max_body_bytes": MAX_BODY_BYTES,
            "max_envelope_bytes": MAX_ENVELOPE_BYTES,
            "max_nested_depth": MAX_NESTED_DEPTH,
            "max_nested_fields": MAX_NESTED_FIELDS,
            "max_list_items": MAX_LIST_ITEMS,
            "max_tc_aggregate_signature_shares": 16,
            "signature_bytes": SIGNATURE_BYTES,
        },
        "mutation_contract": {
            "strict_prefix": "every length 0..frame_length-1 rejects",
            "authenticated_negative_cases": len(negatives),
            "nested_signature_mutations_recompute_transport_digests": True,
        },
        "cases": cases,
        "negative_cases": negatives,
    }


def _assert_no_private_key_material(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).lower()
            if "seed" in lowered or "private" in lowered or "secret" in lowered:
                raise ReferenceError("authenticated vector contains private key material")
            _assert_no_private_key_material(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_no_private_key_material(nested)


def check_authenticated_vector(value: dict[str, Any]) -> tuple[int, int, int, int]:
    if value.get("schema") != "trnm_poco_bft_wire_authenticated_reference_v0":
        raise ReferenceError("unexpected authenticated vector schema")
    if value.get("schema_version") != 0:
        raise ReferenceError("authenticated vector schema version drift")
    if value.get("wire_conformance") is not False or value.get("activation") is not False:
        raise ReferenceError("authenticated vector must remain candidate-only")
    _assert_no_private_key_material(value)
    ed25519_self_test()
    context = context_from_vector(value)
    limits = value.get("limits")
    if not isinstance(limits, dict):
        raise ReferenceError("authenticated vector limits missing")
    maximum_aggregate = int(limits.get("max_tc_aggregate_signature_shares", 0))
    if maximum_aggregate <= 0 or maximum_aggregate > MAX_TC_AGGREGATE_SHARES:
        raise ReferenceError("authenticated aggregate limit outside bounds")
    cases = value.get("cases")
    if not isinstance(cases, list) or len(cases) != 4:
        raise ReferenceError("authenticated vector must contain four canonical cases")
    accepted = 0
    prefix_checks = 0
    auth_mutation_checks = 0
    for case in cases:
        if not isinstance(case, dict):
            raise ReferenceError("authenticated case must be an object")
        frame_bytes = bytes.fromhex(case["frame_hex"])
        result = semantic_decode(frame_bytes, context, maximum_aggregate)
        if result["kind"] != case["kind"]:
            raise ReferenceError(f"{case['id']}: semantic kind mismatch")
        if result["digest"].hex() != case["semantic_digest_hex"]:
            raise ReferenceError(f"{case['id']}: semantic digest mismatch")
        for key in ("signers", "nested_qcs", "aggregate"):
            if result[key] != case[key]:
                raise ReferenceError(f"{case['id']}: {key} mismatch")
        records = verify_authenticated_signatures(
            frame_bytes, context, maximum_aggregate
        )
        metadata = case.get("signatures")
        if not isinstance(metadata, list) or len(metadata) != len(records):
            raise ReferenceError(f"{case['id']}: signature metadata count mismatch")
        for record, expected in zip(records, metadata):
            if record["author"].hex() != expected.get("validator_id_hex"):
                raise ReferenceError(f"{case['id']}: signer metadata mismatch")
            if record["root"].hex() != expected.get("signing_root_hex"):
                raise ReferenceError(f"{case['id']}: signing-root metadata mismatch")
            if record["signature"].hex() != expected.get("signature_hex"):
                raise ReferenceError(f"{case['id']}: signature metadata mismatch")
            public_key = context["public_keys"].get(record["author"])
            if public_key is None or public_key.hex() != expected.get("public_key_hex"):
                raise ReferenceError(f"{case['id']}: public-key metadata mismatch")
            # Exercise strict cryptographic negatives independently of the
            # protobuf mutation cases.  These checks catch accidental
            # acceptance of a wrong root, a different validator key, a
            # changed R point, or a non-canonical S scalar.
            mutated_signature = bytearray(record["signature"])
            mutated_signature[0] ^= 1
            if ed25519_verify(public_key, record["root"], bytes(mutated_signature)):
                raise ReferenceError(f"{case['id']}: mutated signature accepted")
            wrong_root = bytearray(record["root"])
            wrong_root[0] ^= 1
            if ed25519_verify(public_key, bytes(wrong_root), record["signature"]):
                raise ReferenceError(f"{case['id']}: wrong signing root accepted")
            alternate_key = next(
                (
                    candidate
                    for author, candidate in context["public_keys"].items()
                    if author != record["author"]
                ),
                None,
            )
            if alternate_key is None or ed25519_verify(
                alternate_key, record["root"], record["signature"]
            ):
                raise ReferenceError(f"{case['id']}: wrong validator key accepted")
            noncanonical_s = record["signature"][:32] + ED25519_GROUP_ORDER.to_bytes(
                32, "little"
            )
            if ed25519_verify(public_key, record["root"], noncanonical_s):
                raise ReferenceError(f"{case['id']}: noncanonical S accepted")
            auth_mutation_checks += 4
        accepted += 1
        # Keep the authenticated corpus total over strict truncation too.  No
        # prefix may accidentally reach a signature verifier as a valid body.
        for length in range(len(frame_bytes)):
            prefix_checks += 1
            try:
                semantic_decode(frame_bytes[:length], context, maximum_aggregate)
            except (DecodeError, ReferenceError, ValueError):
                pass
            else:
                raise ReferenceError(f"{case['id']}: accepted truncated frame at {length}")

    negatives = value.get("negative_cases")
    if not isinstance(negatives, list):
        raise ReferenceError("authenticated negative corpus missing")
    expected_negative_count = value.get("mutation_contract", {}).get(
        "authenticated_negative_cases"
    )
    if expected_negative_count is not None and len(negatives) != expected_negative_count:
        raise ReferenceError("authenticated negative corpus count drift")
    rejected = 0
    for case in negatives:
        frame_bytes = bytes.fromhex(case["frame_hex"])
        expected_error = case.get("expected_error")
        try:
            semantic_decode(frame_bytes, context, maximum_aggregate)
        except DecodeError as error:
            if expected_error == "invalid_signature":
                raise ReferenceError(
                    f"{case['id']}: signature mutation stopped at semantic layer ({error.code})"
                )
            if error.code != expected_error:
                raise ReferenceError(
                    f"{case['id']}: expected {expected_error}, got {error.code}"
                )
            rejected += 1
            continue
        try:
            verify_authenticated_signatures(frame_bytes, context, maximum_aggregate)
        except AuthenticatedReferenceError as error:
            if error.code != expected_error:
                raise ReferenceError(
                    f"{case['id']}: expected {expected_error}, got {error.code}"
                )
            rejected += 1
        else:
            raise ReferenceError(f"{case['id']}: authenticated mutation was accepted")
    return accepted, rejected, prefix_checks, auth_mutation_checks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vector", type=Path, default=DEFAULT_VECTOR)
    parser.add_argument(
        "--authenticated-vector", type=Path, default=DEFAULT_AUTHENTICATED_VECTOR
    )
    parser.add_argument(
        "--write", action="store_true", help="write the deterministic reference vector"
    )
    parser.add_argument(
        "--write-authenticated",
        action="store_true",
        help="write the deterministic authenticated reference vector",
    )
    parser.add_argument(
        "--skip-authenticated",
        action="store_true",
        help="skip the authenticated nested-wire corpus (fixture generation only)",
    )
    args = parser.parse_args()
    try:
        if args.write:
            args.vector.parent.mkdir(parents=True, exist_ok=True)
            args.vector.write_text(
                json.dumps(build_reference(), indent=2, sort_keys=False) + "\n", encoding="utf-8"
            )
        if args.write_authenticated:
            args.authenticated_vector.parent.mkdir(parents=True, exist_ok=True)
            args.authenticated_vector.write_text(
                json.dumps(build_authenticated_reference(), indent=2, sort_keys=False)
                + "\n",
                encoding="utf-8",
            )
        value = read_vector(args.vector)
        accepted, total, mutations = check_vector(value)
        auth_result = None
        if not args.skip_authenticated:
            auth_value = read_vector(args.authenticated_vector)
            auth_result = check_authenticated_vector(auth_value)
    except (DecodeError, ReferenceError, KeyError, TypeError, ValueError) as error:
        print(f"wire semantic reference: FAIL: {error}", file=sys.stderr)
        return 1
    print(
        f"wire semantic reference: PASS ({accepted}/{total} canonical nested frames; "
        f"strict-prefix corpus complete; {mutations} bounded byte mutations)"
    )
    if auth_result is not None:
        auth_accepted, auth_rejected, auth_prefixes, auth_mutations = auth_result
        print(
            "wire authenticated reference: PASS "
            f"({auth_accepted} canonical frames; {auth_rejected} auth negatives; "
            f"{auth_prefixes} strict-prefix checks; {auth_mutations} crypto mutations)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
