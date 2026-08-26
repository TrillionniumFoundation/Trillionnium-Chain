#!/usr/bin/env python3
"""Independently parse and mutate the bounded PoCO-BFT v0 WireEnvelope.

This is deliberately a small, standard-library-only implementation of the
*outer* protobuf admission boundary.  It does not import generated bindings,
load a consensus crate, invoke a compiler, or decode a nested body.  The
committed JSON fixture is the independently curated canonical frame.  The
checker reconstructs that frame, parses it, byte-identically re-encodes it,
and then runs a deterministic truncation, exhaustive single-byte, fixed
xorshift, and boundary corpus.

The result is a bounded second implementation slice, not a complete wire
conformance claim.  Protobuf field order is not treated as an admission rule:
the fixture is canonical and the re-encoder emits ascending field numbers,
while the parser intentionally accepts valid fields in any order just as the
frozen outer preflight does.  Nested semantic CEV0 decoding, authenticated
peer context, P2P integration, signatures, activation, and production use
remain outside this gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTOR = ROOT / "docs/protocol/poco-bft-v0/vectors/wire-envelope-v0.json"

SCHEMA = "trnm_poco_bft_wire_envelope_reference_v0"
SCHEMA_VERSION = 0
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_ENVELOPE_BYTES = MAX_BODY_BYTES + 1024
MAX_NODE_ID_BYTES = 32
MAX_MESSAGE_ID_BYTES = 64
HASH_BYTES = 32
MAX_CHAIN_ID_BYTES = 128

BODY_KINDS = {
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

# Keep this order identical to the stable machine-readable decoder taxonomy.  A
# zero ordinal means a successful decode; the remaining ordinals are used to
# hash deterministic mutation outcomes without storing a 49k-entry corpus.
ERROR_CODES = (
    "empty",
    "envelope_too_large",
    "unexpected_eof",
    "varint_overflow",
    "noncanonical_varint",
    "invalid_field_key",
    "unsupported_wire_type",
    "unknown_field",
    "duplicate_field",
    "field_type_mismatch",
    "length_overflow",
    "field_too_large",
    "missing_field",
    "invalid_value",
    "invalid_chain_id",
    "invalid_body_kind",
    "body_kind_mismatch",
    "invalid_consensus_message_kind",
)
ERROR_ORDINAL = {name: index + 1 for index, name in enumerate(ERROR_CODES)}

U64_MASK = (1 << 64) - 1


class ReferenceError(ValueError):
    """Malformed fixture or an independent-reference mismatch."""


class DecodeError(ValueError):
    """A bounded outer-frame rejection with a stable code and byte offset."""

    def __init__(self, code: str, offset: int):
        if code not in ERROR_ORDINAL:
            raise AssertionError(f"unknown decoder code: {code}")
        super().__init__(f"{code} at byte {offset}")
        self.code = code
        self.offset = offset


@dataclass(frozen=True)
class Envelope:
    schema_version: int
    wire_version: int
    genesis_hash: bytes
    chain_id: bytes
    protocol_version: int
    epoch: int
    view: int
    validator_set_hash: bytes
    consensus_parameters_hash: bytes
    has_consensus_message_kind: bool
    consensus_message_kind: int | None
    body_kind: int
    sender_node_id: bytes
    message_id: bytes
    sender_sequence: int
    body_semantic_hash: bytes | None
    body_field: int
    body: bytes


def exact_int(value: Any, label: str) -> int:
    if type(value) is not int:  # bool is an int subclass; reject it here.
        raise ReferenceError(f"{label} must be an integer")
    return value


def exact_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise ReferenceError(f"{label} must be a boolean")
    return value


def exact_string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ReferenceError(f"{label} must be a string")
    return value


def strict_hex(value: Any, length: int, label: str) -> bytes:
    text = exact_string(value, label)
    try:
        decoded = bytes.fromhex(text)
    except ValueError as error:
        raise ReferenceError(f"{label} is not hexadecimal") from error
    if text != text.lower() or decoded.hex() != text:
        raise ReferenceError(f"{label} is not canonical lowercase hexadecimal")
    if len(decoded) != length:
        raise ReferenceError(f"{label} must contain exactly {length} bytes")
    return decoded


def strict_bounded_hex(value: Any, maximum: int, label: str) -> bytes:
    text = exact_string(value, label)
    try:
        decoded = bytes.fromhex(text)
    except ValueError as error:
        raise ReferenceError(f"{label} is not hexadecimal") from error
    if text != text.lower() or decoded.hex() != text:
        raise ReferenceError(f"{label} is not canonical lowercase hexadecimal")
    if not decoded or len(decoded) > maximum:
        raise ReferenceError(f"{label} must contain 1..{maximum} bytes")
    return decoded


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReferenceError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReferenceError(f"{path} must contain a JSON object")
    return value


def varint_length(value: int) -> int:
    if value < 1 << 7:
        return 1
    if value < 1 << 14:
        return 2
    if value < 1 << 21:
        return 3
    if value < 1 << 28:
        return 4
    if value < 1 << 35:
        return 5
    if value < 1 << 42:
        return 6
    if value < 1 << 49:
        return 7
    if value < 1 << 56:
        return 8
    if value < 1 << 63:
        return 9
    return 10


def encode_varint(value: int) -> bytes:
    if type(value) is not int or value < 0 or value >= 1 << 64:
        raise ReferenceError(f"varint value is outside u64: {value!r}")
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        output.append(byte)
        if not value:
            return bytes(output)


def field_varint(field: int, value: int) -> bytes:
    return encode_varint(field << 3) + encode_varint(value)


def field_bytes(field: int, value: bytes) -> bytes:
    return encode_varint((field << 3) | 2) + encode_varint(len(value)) + value


def _wire_error(code: str, offset: int) -> DecodeError:
    return DecodeError(code, offset)


class Cursor:
    """A checked cursor over one immutable input frame."""

    __slots__ = ("data", "offset")

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def done(self) -> bool:
        return self.offset == len(self.data)

    def varint(self) -> int:
        start = self.offset
        value = 0
        for index in range(10):
            if self.offset >= len(self.data):
                raise _wire_error("unexpected_eof", start)
            byte = self.data[self.offset]
            self.offset += 1
            if index == 9 and byte > 1:
                raise _wire_error("varint_overflow", start)
            value |= (byte & 0x7F) << (index * 7)
            if not byte & 0x80:
                if varint_length(value) != self.offset - start:
                    raise _wire_error("noncanonical_varint", start)
                return value
        raise _wire_error("varint_overflow", start)

    def scalar(self, field_offset: int, wire_type: int, bits: int) -> int:
        if wire_type != 0:
            raise _wire_error("field_type_mismatch", field_offset)
        value = self.varint()
        if value >= 1 << bits:
            raise _wire_error("invalid_value", field_offset)
        return value

    def bytes(self, field_offset: int, wire_type: int, maximum: int) -> bytes:
        if wire_type != 2:
            raise _wire_error("field_type_mismatch", field_offset)
        length = self.varint()
        # The bound is checked before asking for a slice.  This is the key
        # no-allocation property of the outer admission boundary.
        if length > maximum:
            raise _wire_error("field_too_large", field_offset)
        if length > sys.maxsize:
            raise _wire_error("length_overflow", field_offset)
        end = self.offset + length
        if end < self.offset:
            raise _wire_error("length_overflow", field_offset)
        if end > len(self.data):
            raise _wire_error("unexpected_eof", field_offset)
        value = self.data[self.offset : end]
        self.offset = end
        return value


def _required(values: dict[int, Any], field: int, total: int) -> Any:
    if field not in values:
        raise _wire_error("missing_field", max(total, field))
    return values[field]


def valid_chain_id(value: bytes) -> bool:
    if not value or len(value) > MAX_CHAIN_ID_BYTES:
        return False
    first = value[0]
    if not (ord("a") <= first <= ord("z") or ord("0") <= first <= ord("9")):
        return False
    allowed_tail = b"abcdefghijklmnopqrstuvwxyz0123456789._:-"
    return all(byte in allowed_tail for byte in value[1:])


def decode_wire_envelope(data: bytes) -> Envelope:
    """Decode exactly the frozen outer admission contract."""

    if not isinstance(data, bytes):
        raise TypeError("wire input must be bytes")
    if not data:
        raise _wire_error("empty", 0)
    if len(data) > MAX_ENVELOPE_BYTES:
        raise _wire_error("envelope_too_large", 0)

    cursor = Cursor(data)
    seen: set[int] = set()
    values: dict[int, Any] = {}
    body: bytes | None = None
    body_field: int | None = None

    while not cursor.done():
        field_offset = cursor.offset
        key = cursor.varint()
        wire_type = key & 0x07
        field = key >> 3
        if field == 0 or field > 45:
            raise _wire_error("unknown_field", field_offset)
        if wire_type not in (0, 2):
            raise _wire_error("unsupported_wire_type", field_offset)
        if field in seen:
            raise _wire_error("duplicate_field", field_offset)
        seen.add(field)

        if field in (1, 2, 5):
            values[field] = cursor.scalar(field_offset, wire_type, 32)
        elif field in (6, 7, 15):
            values[field] = cursor.scalar(field_offset, wire_type, 64)
        elif field == 3:
            values[field] = cursor.bytes(field_offset, wire_type, HASH_BYTES)
        elif field == 4:
            values[field] = cursor.bytes(field_offset, wire_type, MAX_CHAIN_ID_BYTES)
        elif field in (8, 9):
            values[field] = cursor.bytes(field_offset, wire_type, HASH_BYTES)
        elif field == 10:
            value = cursor.scalar(field_offset, wire_type, 64)
            if value > 1:
                raise _wire_error("invalid_value", field_offset)
            values[field] = value == 1
        elif field == 11:
            value = cursor.scalar(field_offset, wire_type, 64)
            if value > 4:
                raise _wire_error("invalid_consensus_message_kind", field_offset)
            values[field] = value
        elif field == 12:
            value = cursor.scalar(field_offset, wire_type, 64)
            if value not in BODY_KINDS:
                raise _wire_error("invalid_body_kind", field_offset)
            values[field] = value
        elif field == 13:
            values[field] = cursor.bytes(field_offset, wire_type, MAX_NODE_ID_BYTES)
        elif field == 14:
            values[field] = cursor.bytes(field_offset, wire_type, MAX_MESSAGE_ID_BYTES)
        elif field == 16:
            values[field] = cursor.bytes(field_offset, wire_type, HASH_BYTES)
        elif 32 <= field <= 45:
            # Match the oneof duplicate rule before decoding the second body
            # length/type, which makes the failure deterministic.
            if body is not None:
                raise _wire_error("duplicate_field", field_offset)
            body = cursor.bytes(field_offset, wire_type, MAX_BODY_BYTES)
            body_field = field
        else:
            raise _wire_error("unknown_field", field_offset)

    schema_version = _required(values, 1, len(data))
    if schema_version != 0:
        raise _wire_error("invalid_value", 0)
    wire_version = _required(values, 2, len(data))
    if wire_version != 0:
        raise _wire_error("invalid_value", 0)
    genesis_hash = _required(values, 3, len(data))
    if len(genesis_hash) != HASH_BYTES or not any(genesis_hash):
        raise _wire_error("invalid_value", 0)
    chain_id = _required(values, 4, len(data))
    if not valid_chain_id(chain_id):
        raise _wire_error("invalid_chain_id", 0)
    protocol_version = _required(values, 5, len(data))
    if protocol_version != 0:
        raise _wire_error("invalid_value", 0)
    epoch = _required(values, 6, len(data))
    view = _required(values, 7, len(data))
    validator_set_hash = _required(values, 8, len(data))
    if not any(validator_set_hash):
        raise _wire_error("invalid_value", 0)
    consensus_parameters_hash = _required(values, 9, len(data))
    if not any(consensus_parameters_hash):
        raise _wire_error("invalid_value", 0)
    has_kind = _required(values, 10, len(data))
    message_kind = values.get(11)
    if has_kind:
        if message_kind is None:
            raise _wire_error("missing_field", max(len(data), 11))
    elif message_kind is not None:
        raise _wire_error("invalid_consensus_message_kind", 0)

    body_kind = _required(values, 12, len(data))
    if body_field is None or body is None:
        raise _wire_error("missing_field", max(len(data), 32))
    if body_kind != body_field - 31:
        raise _wire_error("body_kind_mismatch", 0)

    sender_node_id = _required(values, 13, len(data))
    message_id = _required(values, 14, len(data))
    sender_sequence = _required(values, 15, len(data))

    if (
        len(sender_node_id) != MAX_NODE_ID_BYTES
        or not any(sender_node_id)
        or not message_id
    ):
        raise _wire_error("invalid_value", 0)
    body_semantic_hash = values.get(16)
    if body_semantic_hash is not None and len(body_semantic_hash) != HASH_BYTES:
        raise _wire_error("invalid_value", 0)
    if not body:
        raise _wire_error("invalid_value", 0)

    pair = (body_kind, message_kind)
    if pair in ((1, 0), (2, 1), (3, 2), (8, 3), (8, 4)):
        pass
    elif body_kind in (1, 2, 3, 8) or message_kind is not None:
        raise _wire_error("invalid_consensus_message_kind", 0)

    return Envelope(
        schema_version=schema_version,
        wire_version=wire_version,
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=protocol_version,
        epoch=epoch,
        view=view,
        validator_set_hash=validator_set_hash,
        consensus_parameters_hash=consensus_parameters_hash,
        has_consensus_message_kind=has_kind,
        consensus_message_kind=message_kind,
        body_kind=body_kind,
        sender_node_id=sender_node_id,
        message_id=message_id,
        sender_sequence=sender_sequence,
        body_semantic_hash=body_semantic_hash,
        body_field=body_field,
        body=body,
    )


def envelope_projection(value: Envelope) -> dict[str, Any]:
    return {
        "schema_version": value.schema_version,
        "wire_version": value.wire_version,
        "genesis_hash_hex": value.genesis_hash.hex(),
        "chain_id": value.chain_id.decode("ascii"),
        "protocol_version": value.protocol_version,
        "epoch": value.epoch,
        "view": value.view,
        "validator_set_hash_hex": value.validator_set_hash.hex(),
        "consensus_parameters_hash_hex": value.consensus_parameters_hash.hex(),
        "has_consensus_message_kind": value.has_consensus_message_kind,
        "consensus_message_kind": value.consensus_message_kind,
        "body_kind": value.body_kind,
        "sender_node_id_hex": value.sender_node_id.hex(),
        "message_id_hex": value.message_id.hex(),
        "sender_sequence": value.sender_sequence,
        "body_semantic_hash_hex": (
            None
            if value.body_semantic_hash is None
            else value.body_semantic_hash.hex()
        ),
        "body_field": value.body_field,
        "body_hex": value.body.hex(),
    }


def fields_from_json(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ReferenceError("canonical_fields must be an object")
    expected_keys = {
        "schema_version",
        "wire_version",
        "genesis_hash_hex",
        "chain_id",
        "protocol_version",
        "epoch",
        "view",
        "validator_set_hash_hex",
        "consensus_parameters_hash_hex",
        "has_consensus_message_kind",
        "consensus_message_kind",
        "body_kind",
        "sender_node_id_hex",
        "message_id_hex",
        "sender_sequence",
        "body_semantic_hash_hex",
        "body_field",
        "body_hex",
    }
    if set(raw) != expected_keys:
        raise ReferenceError(
            "canonical_fields keys differ: "
            f"expected {sorted(expected_keys)!r}, found {sorted(raw)!r}"
        )
    normalized = {
        "schema_version": exact_int(raw["schema_version"], "schema_version"),
        "wire_version": exact_int(raw["wire_version"], "wire_version"),
        "genesis_hash_hex": strict_hex(raw["genesis_hash_hex"], 32, "genesis_hash_hex").hex(),
        "chain_id": exact_string(raw["chain_id"], "chain_id"),
        "protocol_version": exact_int(raw["protocol_version"], "protocol_version"),
        "epoch": exact_int(raw["epoch"], "epoch"),
        "view": exact_int(raw["view"], "view"),
        "validator_set_hash_hex": strict_hex(
            raw["validator_set_hash_hex"], 32, "validator_set_hash_hex"
        ).hex(),
        "consensus_parameters_hash_hex": strict_hex(
            raw["consensus_parameters_hash_hex"], 32, "consensus_parameters_hash_hex"
        ).hex(),
        "has_consensus_message_kind": exact_bool(
            raw["has_consensus_message_kind"], "has_consensus_message_kind"
        ),
        "consensus_message_kind": raw["consensus_message_kind"],
        "body_kind": exact_int(raw["body_kind"], "body_kind"),
        "sender_node_id_hex": strict_hex(
            raw["sender_node_id_hex"], 32, "sender_node_id_hex"
        ).hex(),
        "message_id_hex": strict_bounded_hex(
            raw["message_id_hex"], MAX_MESSAGE_ID_BYTES, "message_id_hex"
        ).hex(),
        "sender_sequence": exact_int(raw["sender_sequence"], "sender_sequence"),
        "body_semantic_hash_hex": raw["body_semantic_hash_hex"],
        "body_field": exact_int(raw["body_field"], "body_field"),
        "body_hex": exact_string(raw["body_hex"], "body_hex"),
    }
    # The message kind is nullable only when the boolean says it is absent.
    if normalized["consensus_message_kind"] is not None:
        normalized["consensus_message_kind"] = exact_int(
            normalized["consensus_message_kind"], "consensus_message_kind"
        )
    if normalized["body_semantic_hash_hex"] is not None:
        normalized["body_semantic_hash_hex"] = strict_hex(
            normalized["body_semantic_hash_hex"], 32, "body_semantic_hash_hex"
        ).hex()
    else:
        normalized["body_semantic_hash_hex"] = None
    body_hex = normalized["body_hex"]
    try:
        body_bytes = bytes.fromhex(body_hex)
    except ValueError as error:
        raise ReferenceError("body_hex is not hexadecimal") from error
    if body_hex != body_hex.lower() or body_bytes.hex() != body_hex:
        raise ReferenceError("body_hex is not canonical lowercase hexadecimal")
    normalized["body_hex"] = body_bytes.hex()
    if normalized["schema_version"] != 0 or normalized["wire_version"] != 0:
        raise ReferenceError("canonical fixture versions must be zero")
    if normalized["protocol_version"] != 0:
        raise ReferenceError("canonical fixture protocol_version must be zero")
    if normalized["body_kind"] not in BODY_KINDS:
        raise ReferenceError("canonical fixture body_kind is unknown")
    if normalized["body_field"] != 31 + normalized["body_kind"]:
        raise ReferenceError("canonical fixture body_field does not match body_kind")
    if normalized["has_consensus_message_kind"] != (
        normalized["consensus_message_kind"] is not None
    ):
        raise ReferenceError("canonical fixture message-kind presence is inconsistent")
    if normalized["sender_sequence"] < 0 or normalized["sender_sequence"] >= 1 << 64:
        raise ReferenceError("canonical fixture sender_sequence is outside u64")
    for key in ("schema_version", "wire_version", "protocol_version", "body_kind", "body_field"):
        if normalized[key] < 0:
            raise ReferenceError(f"canonical fixture {key} cannot be negative")
    # The committed mutation operations intentionally target this one small
    # positive profile.  Reject a silently changed fixture rather than
    # constructing negatives against assumptions that no longer hold.
    expected_profile = {
        "chain_id": "trnm-wire-test",
        "has_consensus_message_kind": True,
        "consensus_message_kind": 0,
        "body_kind": 1,
        "body_field": 32,
        "body_semantic_hash_hex": None,
        "body_hex": "aabb",
    }
    for key, expected in expected_profile.items():
        if normalized[key] != expected:
            raise ReferenceError(
                f"canonical fixture mutation profile {key} differs: "
                f"expected {expected!r}, found {normalized[key]!r}"
            )
    return normalized


def canonical_frame(fields: dict[str, Any]) -> bytes:
    """Build the ascending-field canonical protobuf fixture from JSON facts."""

    def hex_bytes(name: str) -> bytes:
        return bytes.fromhex(fields[name])

    output = bytearray()
    output.extend(field_varint(1, fields["schema_version"]))
    output.extend(field_varint(2, fields["wire_version"]))
    output.extend(field_bytes(3, hex_bytes("genesis_hash_hex")))
    output.extend(field_bytes(4, fields["chain_id"].encode("ascii")))
    output.extend(field_varint(5, fields["protocol_version"]))
    output.extend(field_varint(6, fields["epoch"]))
    output.extend(field_varint(7, fields["view"]))
    output.extend(field_bytes(8, hex_bytes("validator_set_hash_hex")))
    output.extend(field_bytes(9, hex_bytes("consensus_parameters_hash_hex")))
    output.extend(field_varint(10, int(fields["has_consensus_message_kind"])))
    if fields["consensus_message_kind"] is not None:
        output.extend(field_varint(11, fields["consensus_message_kind"]))
    output.extend(field_varint(12, fields["body_kind"]))
    output.extend(field_bytes(13, hex_bytes("sender_node_id_hex")))
    output.extend(field_bytes(14, hex_bytes("message_id_hex")))
    output.extend(field_varint(15, fields["sender_sequence"]))
    if fields["body_semantic_hash_hex"] is not None:
        output.extend(field_bytes(16, bytes.fromhex(fields["body_semantic_hash_hex"])))
    output.extend(field_bytes(fields["body_field"], bytes.fromhex(fields["body_hex"])))
    return bytes(output)


def replace_once(data: bytes, old: bytes, new: bytes, label: str) -> bytes:
    if data.count(old) != 1:
        raise ReferenceError(f"{label} expected one source sequence, found {data.count(old)}")
    return data.replace(old, new, 1)


def targeted_mutations(frame: bytes, fields: dict[str, Any]) -> dict[str, bytes]:
    """Construct stable negatives without importing a generated decoder."""

    body = bytes.fromhex(fields["body_hex"])
    body_field = fields["body_field"]
    body_wire = field_bytes(body_field, body)
    return {
        "unknown_field": frame + field_varint(17, 1),
        "duplicate_field": frame + field_varint(15, 1),
        "body_kind_mismatch": replace_once(
            frame, field_varint(12, fields["body_kind"]), field_varint(12, 2), "body kind"
        ),
        "noncanonical_key_varint": replace_once(
            frame, field_varint(1, fields["schema_version"]), b"\x88\x80\x00\x00", "key varint"
        ),
        "unsupported_wire_type": b"\x09" + frame[1:],
        "invalid_chain_id": replace_once(
            frame,
            field_bytes(4, fields["chain_id"].encode("ascii")),
            field_bytes(4, b"Trnm-wire-test"),
            "chain id",
        ),
        "zero_genesis_hash": replace_once(
            frame,
            field_bytes(3, bytes.fromhex(fields["genesis_hash_hex"])),
            field_bytes(3, b"\x00" * HASH_BYTES),
            "genesis hash",
        ),
        "invalid_body_kind": replace_once(
            frame, field_varint(12, fields["body_kind"]), field_varint(12, 99), "body kind value"
        ),
        "invalid_message_kind": replace_once(
            frame, field_varint(11, fields["consensus_message_kind"]), field_varint(11, 5), "message kind"
        ),
        "message_kind_presence_false": replace_once(
            frame, field_varint(10, 1), field_varint(10, 0), "message-kind presence"
        ),
        "zero_sender_node_id": replace_once(
            frame,
            field_bytes(13, bytes.fromhex(fields["sender_node_id_hex"])),
            field_bytes(13, b"\x00" * MAX_NODE_ID_BYTES),
            "sender node ID",
        ),
        "empty_message_id": replace_once(
            frame,
            field_bytes(14, bytes.fromhex(fields["message_id_hex"])),
            field_bytes(14, b""),
            "message ID",
        ),
        "empty_oneof_body": replace_once(frame, body_wire, field_bytes(body_field, b""), "body"),
        "duplicate_oneof_body": frame + field_bytes(body_field + 1, b"\xaa"),
        "missing_body": frame[: -len(body_wire)],
        "bad_semantic_hash_length": frame + field_bytes(16, b"\x06" * 31),
        "oversized_body_length": replace_once(
            frame,
            body_wire,
            encode_varint((body_field << 3) | 2)
            + encode_varint(MAX_BODY_BYTES + 1),
            "body length",
        ),
    }


def classify(data: bytes) -> str:
    try:
        decode_wire_envelope(data)
    except DecodeError as error:
        return error.code
    return "ok"


def outcome_ordinal(code: str) -> int:
    if code == "ok":
        return 0
    try:
        return ERROR_ORDINAL[code]
    except KeyError as error:  # pragma: no cover - defensive invariant
        raise ReferenceError(f"unknown mutation outcome {code!r}") from error


def outcome_digest(outcomes: Iterable[str]) -> str:
    return hashlib.sha256(bytes(outcome_ordinal(code) for code in outcomes)).hexdigest()


def next_xorshift_byte(state: int) -> tuple[int, int]:
    state ^= (state << 13) & U64_MASK
    state ^= state >> 7
    state ^= (state << 17) & U64_MASK
    state &= U64_MASK
    return state, (state >> 24) & 0xFF


def fixed_random_corpus(seed: int, count: int, max_length: int) -> list[bytes]:
    state = seed
    corpus: list[bytes] = []
    for _ in range(count):
        state, length_byte = next_xorshift_byte(state)
        length = length_byte % max_length
        current = bytearray()
        for _ in range(length):
            state, byte = next_xorshift_byte(state)
            current.append(byte)
        corpus.append(bytes(current))
    return corpus


def validate_vector(document: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    if document.get("schema") != SCHEMA:
        raise ReferenceError(f"vector schema must be {SCHEMA!r}")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise ReferenceError("vector schema_version must be zero")
    if document.get("status") != "bounded-reference-only":
        raise ReferenceError("vector status must remain bounded-reference-only")
    if document.get("wire_conformance") is not False or document.get("activation") is not False:
        raise ReferenceError("wire reference vector cannot turn on conformance or activation")
    fields = fields_from_json(document.get("canonical_fields"))
    frame_hex = document.get("canonical_frame_hex")
    frame_text = exact_string(frame_hex, "canonical_frame_hex")
    try:
        committed = bytes.fromhex(frame_text)
    except ValueError as error:
        raise ReferenceError("canonical_frame_hex is not hexadecimal") from error
    if frame_text != frame_text.lower() or committed.hex() != frame_text:
        raise ReferenceError("canonical_frame_hex is not canonical lowercase hexadecimal")
    if len(committed) == 0:
        raise ReferenceError("canonical frame cannot be empty")
    expected_frame = canonical_frame(fields)
    if committed != expected_frame:
        raise ReferenceError("canonical frame differs from the independent field reconstruction")
    if document.get("canonical_frame_length") != len(committed):
        raise ReferenceError("canonical_frame_length does not match the committed frame")
    claimed_hash = strict_hex(document.get("canonical_frame_sha256"), 32, "canonical_frame_sha256")
    if hashlib.sha256(committed).digest() != claimed_hash:
        raise ReferenceError("canonical_frame_sha256 does not match the frame")
    limits = document.get("limits")
    expected_limits = {
        "max_body_bytes": MAX_BODY_BYTES,
        "max_envelope_bytes": MAX_ENVELOPE_BYTES,
        "max_sender_node_id_bytes": MAX_NODE_ID_BYTES,
        "max_message_id_bytes": MAX_MESSAGE_ID_BYTES,
        "max_chain_id_bytes": MAX_CHAIN_ID_BYTES,
    }
    if limits != expected_limits:
        raise ReferenceError(f"limits differ: expected {expected_limits!r}, found {limits!r}")
    contract = document.get("mutation_contract")
    if not isinstance(contract, dict):
        raise ReferenceError("mutation_contract must be an object")
    if contract.get("strict_prefix_algorithm") != "every_length_0_through_frame_length_minus_1":
        raise ReferenceError("strict prefix corpus algorithm drifted")
    single = contract.get("single_byte_replacements")
    if not isinstance(single, dict) or single.get("mode") != "every_byte_every_u8":
        raise ReferenceError("single-byte corpus mode drifted")
    random = contract.get("fixed_random")
    if not isinstance(random, dict):
        raise ReferenceError("fixed_random contract must be an object")
    if random.get("algorithm") != "xorshift64_triplet":
        raise ReferenceError("fixed random algorithm drifted")
    if random.get("seed_hex") != "54524e4d50524546":
        raise ReferenceError("fixed random seed drifted")
    if random.get("cases") != 1024 or random.get("max_length_exclusive") != 192:
        raise ReferenceError("fixed random corpus dimensions drifted")
    targeted = document.get("targeted_mutations")
    if not isinstance(targeted, list) or not targeted:
        raise ReferenceError("targeted_mutations must be a non-empty list")
    for item in targeted:
        if not isinstance(item, dict) or set(item) != {"id", "expected_code"}:
            raise ReferenceError("targeted mutation entries must contain id/expected_code")
        if not isinstance(item["id"], str) or item["id"] == "":
            raise ReferenceError("targeted mutation id must be non-empty")
        if item["expected_code"] not in ERROR_ORDINAL:
            raise ReferenceError(f"unknown targeted error code: {item['expected_code']!r}")
    return fields, committed


def compute_observations(frame: bytes, fields: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    canonical = classify(frame)
    if canonical != "ok":
        raise ReferenceError(f"canonical frame was rejected: {canonical}")

    prefix_outcomes = [classify(frame[:length]) for length in range(len(frame))]
    single_outcomes: list[str] = []
    for index in range(len(frame)):
        for replacement in range(256):
            mutated = bytearray(frame)
            mutated[index] = replacement
            single_outcomes.append(classify(bytes(mutated)))

    contract = document["mutation_contract"]
    random_contract = contract["fixed_random"]
    random_seed = int(random_contract["seed_hex"], 16)
    random_corpus = fixed_random_corpus(
        random_seed,
        int(random_contract["cases"]),
        int(random_contract["max_length_exclusive"]),
    )
    random_outcomes = [classify(item) for item in random_corpus]

    targeted = targeted_mutations(frame, fields)
    targeted_outcomes = {name: classify(value) for name, value in targeted.items()}
    boundary = {
        "oversized_envelope": classify(b"\x00" * (MAX_ENVELOPE_BYTES + 1)),
    }
    return {
        "canonical": canonical,
        "prefix": {
            "cases": len(prefix_outcomes),
            "accepted": sum(code == "ok" for code in prefix_outcomes),
            "rejected": sum(code != "ok" for code in prefix_outcomes),
            "outcome_sha256": outcome_digest(prefix_outcomes),
        },
        "single": {
            "cases": len(single_outcomes),
            "accepted": sum(code == "ok" for code in single_outcomes),
            "rejected": sum(code != "ok" for code in single_outcomes),
            "outcome_sha256": outcome_digest(single_outcomes),
        },
        "random": {
            "cases": len(random_outcomes),
            "accepted": sum(code == "ok" for code in random_outcomes),
            "rejected": sum(code != "ok" for code in random_outcomes),
            "outcome_sha256": outcome_digest(random_outcomes),
        },
        "targeted": targeted_outcomes,
        "boundary": boundary,
    }


def check_observations(document: dict[str, Any], observations: dict[str, Any]) -> None:
    contract = document["mutation_contract"]
    expected_prefix = {
        "cases": document["canonical_frame_length"],
        "accepted": 0,
        "rejected": document["canonical_frame_length"],
        "outcome_sha256": contract["strict_prefix_outcome_sha256"],
    }
    if observations["prefix"] != expected_prefix:
        raise ReferenceError(
            f"strict-prefix corpus differs: expected {expected_prefix!r}, "
            f"found {observations['prefix']!r}"
        )
    expected_single = contract["single_byte_replacements"]
    expected_single_projection = {
        "cases": document["canonical_frame_length"] * 256,
        "accepted": expected_single["expected_accepted"],
        "rejected": expected_single["expected_rejected"],
        "outcome_sha256": expected_single["outcome_sha256"],
    }
    if observations["single"] != expected_single_projection:
        raise ReferenceError(
            f"single-byte corpus differs: expected {expected_single_projection!r}, "
            f"found {observations['single']!r}"
        )
    expected_random = contract["fixed_random"]
    expected_random_projection = {
        "cases": expected_random["cases"],
        "accepted": expected_random["expected_accepted"],
        "rejected": expected_random["expected_rejected"],
        "outcome_sha256": expected_random["outcome_sha256"],
    }
    if observations["random"] != expected_random_projection:
        raise ReferenceError(
            f"fixed-random corpus differs: expected {expected_random_projection!r}, "
            f"found {observations['random']!r}"
        )
    expected_targeted = {
        item["id"]: item["expected_code"] for item in document["targeted_mutations"]
    }
    if set(expected_targeted) != set(observations["targeted"]):
        raise ReferenceError("targeted mutation inventory differs from the vector")
    for name, expected in expected_targeted.items():
        actual = observations["targeted"][name]
        if actual != expected:
            raise ReferenceError(
                f"targeted mutation {name!r} differs: expected {expected}, found {actual}"
            )
    expected_boundary = contract.get("boundary_outcomes")
    if observations["boundary"] != expected_boundary:
        raise ReferenceError(
            f"boundary corpus differs: expected {expected_boundary!r}, "
            f"found {observations['boundary']!r}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vector", type=Path, default=DEFAULT_VECTOR)
    parser.add_argument(
        "--print-contract",
        action="store_true",
        help="print computed deterministic corpus outcomes without comparing claims",
    )
    args = parser.parse_args()
    document = read_json(args.vector)
    fields, frame = validate_vector(document)
    parsed = decode_wire_envelope(frame)
    expected_projection = fields
    if envelope_projection(parsed) != expected_projection:
        raise ReferenceError("canonical frame parsed projection differs from canonical_fields")
    if canonical_frame(envelope_projection(parsed)) != frame:
        raise ReferenceError("parsed canonical frame failed byte-identical re-encoding")
    observations = compute_observations(frame, fields, document)
    if args.print_contract:
        print(json.dumps(observations, indent=2, sort_keys=True))
        return 0
    check_observations(document, observations)
    print(
        "PoCO-BFT v0 independent WireEnvelope reference passed: "
        f"canonical_bytes={len(frame)} "
        f"single_byte_cases={observations['single']['cases']} "
        f"single_byte_accepted={observations['single']['accepted']} "
        f"random_cases={observations['random']['cases']} targeted={len(observations['targeted'])}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReferenceError, DecodeError, OSError, TypeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
