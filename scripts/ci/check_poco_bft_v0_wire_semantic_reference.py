#!/usr/bin/env python3
"""Independent bounded semantic parser for the PoCO-BFT v0 wire tranche.

The Rust transport decoder and this checker intentionally have no shared
parser code.  This implementation uses only the Python standard library and
reconstructs the CEV0 Vote, TimeoutVote, QC, and TC domains from the protobuf
projection.  It is a conformance/reference gate, not a production node: Ed25519
verification and the ten not-yet-adapted body kinds remain explicit blockers.
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
HASH_PREFIX = b"trnm.cev0.hash.v0"
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
        context["validators"][identifier] = power
        context["total_power"] += power
        key = strict_hex(item["consensus_public_key_hex"], 32, "consensus public key")
        if key == bytes(32):
            raise ReferenceError("consensus public key must be nonzero")
        if key in public_keys:
            raise ReferenceError("duplicate consensus public key")
        public_keys.add(key)
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
        "scope": "Vote/TimeoutVote/QC/TC nested protobuf plus authenticated CEV0 reconstruction; other body kinds, P2P, and cryptographic verification remain disabled",
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vector", type=Path, default=DEFAULT_VECTOR)
    parser.add_argument("--write", action="store_true", help="write the deterministic reference vector")
    args = parser.parse_args()
    try:
        if args.write:
            args.vector.parent.mkdir(parents=True, exist_ok=True)
            args.vector.write_text(
                json.dumps(build_reference(), indent=2, sort_keys=False) + "\n", encoding="utf-8"
            )
        value = read_vector(args.vector)
        accepted, total, mutations = check_vector(value)
    except (DecodeError, ReferenceError, KeyError, TypeError, ValueError) as error:
        print(f"wire semantic reference: FAIL: {error}", file=sys.stderr)
        return 1
    print(
        f"wire semantic reference: PASS ({accepted}/{total} canonical nested frames; "
        f"strict-prefix corpus complete; {mutations} bounded byte mutations)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
