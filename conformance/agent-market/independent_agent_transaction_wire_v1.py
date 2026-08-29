#!/usr/bin/env python3
"""Independent outer parser for the candidate AgentTransactionV1 wire."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAGIC = b"TRNMATX1"
WIRE_VERSION = 1
HEADER_BYTES = 294
TRAILER_BYTES = 32
MAX_COMMAND_BYTES = 1_048_576
PAYLOAD_DOMAIN = b"trnm.poco-ai.agent-transaction-payload.v1"
WIRE_DOMAIN = b"trnm.poco-ai.agent-transaction-wire.v1"


class Reject(ValueError):
    pass


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise Reject(f"duplicate-json-key:{key}")
        output[key] = value
    return output


def digest_encoded(domain: bytes, payload: bytes) -> bytes:
    if not domain or any(byte > 0x7F for byte in domain):
        raise Reject("digest-domain")
    return hashlib.sha256(struct.pack("<I", len(domain)) + domain + payload).digest()


@dataclass(frozen=True)
class Parsed:
    context_digest: bytes
    sender_agent_id: bytes
    authorizing_key_id: bytes
    signer_key_id: bytes
    capability_id: bytes | None
    session_key_grant_id: bytes | None
    live_capability_generation: int
    session_generation: int
    nonce_lane: int
    operation_kind: int
    nonce: int
    expected_lane_version: int
    valid_after_height: int
    expires_after_height: int
    command_bytes: bytes
    transaction_id: bytes


class Reader:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.raw):
            raise Reject("truncated-field")
        value = self.raw[self.offset : self.offset + size]
        self.offset += size
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def remaining(self) -> int:
        return len(self.raw) - self.offset


def optional_id(reader: Reader) -> bytes | None:
    tag = reader.u8()
    value = reader.take(32)
    if tag == 0 and value == bytes(32):
        return None
    if tag == 0:
        raise Reject("absent-id-nonzero")
    if tag == 1 and value != bytes(32):
        return value
    if tag == 1:
        raise Reject("present-id-zero")
    raise Reject("optional-id-tag")


def parse(raw: bytes) -> Parsed:
    if len(raw) < HEADER_BYTES + TRAILER_BYTES:
        raise Reject("short-envelope")
    reader = Reader(raw)
    if reader.take(8) != MAGIC:
        raise Reject("magic")
    if reader.u16() != WIRE_VERSION:
        raise Reject("wire-version")
    if reader.u16() != 0:
        raise Reject("flags")

    context_digest = reader.take(32)
    sender_agent_id = reader.take(32)
    authorizing_key_id = reader.take(32)
    signer_key_id = reader.take(32)
    capability_id = optional_id(reader)
    session_key_grant_id = optional_id(reader)
    live_capability_generation = reader.u64()
    session_generation = reader.u64()
    nonce_lane = reader.u16()
    operation_kind = reader.u16()
    if operation_kind not in range(2, 8):
        raise Reject("operation-kind")
    nonce = reader.u64()
    expected_lane_version = reader.u64()
    valid_after_height = reader.u64()
    expires_after_height = reader.u64()
    if valid_after_height > expires_after_height:
        raise Reject("validity-window")
    command_len = reader.u32()
    if command_len > MAX_COMMAND_BYTES:
        raise Reject("command-bound")
    payload_digest = reader.take(32)
    if reader.remaining() != command_len + TRAILER_BYTES:
        raise Reject("command-length")
    command_bytes = reader.take(command_len)
    transaction_id = reader.take(32)
    if reader.remaining() != 0:
        raise Reject("trailing-data")
    if digest_encoded(PAYLOAD_DOMAIN, command_bytes) != payload_digest:
        raise Reject("payload-digest")
    if digest_encoded(WIRE_DOMAIN, raw[:-TRAILER_BYTES]) != transaction_id:
        raise Reject("wire-digest")

    return Parsed(
        context_digest=context_digest,
        sender_agent_id=sender_agent_id,
        authorizing_key_id=authorizing_key_id,
        signer_key_id=signer_key_id,
        capability_id=capability_id,
        session_key_grant_id=session_key_grant_id,
        live_capability_generation=live_capability_generation,
        session_generation=session_generation,
        nonce_lane=nonce_lane,
        operation_kind=operation_kind,
        nonce=nonce,
        expected_lane_version=expected_lane_version,
        valid_after_height=valid_after_height,
        expires_after_height=expires_after_height,
        command_bytes=command_bytes,
        transaction_id=transaction_id,
    )


def reject(name: str, operation: Any, rows: list[dict[str, str]]) -> None:
    try:
        operation()
    except Reject as error:
        rows.append({"case": name, "error": str(error)})
    else:
        raise AssertionError(f"accepted:{name}")


def load_fixture(path: Path) -> tuple[dict[str, Any], bytes]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    if value.get("schema") != "trnm-agent-transaction-wire-fixture-v1":
        raise Reject("fixture-schema")
    wire_hex = value.get("wire_hex")
    if not isinstance(wire_hex, str) or len(wire_hex) % 2:
        raise Reject("fixture-wire-hex")
    try:
        raw = bytes.fromhex(wire_hex)
    except ValueError as error:
        raise Reject("fixture-wire-hex") from error
    return value, raw


def self_test(path: Path) -> dict[str, Any]:
    fixture, raw = load_fixture(path)
    parsed = parse(raw)
    if parsed.transaction_id.hex() != fixture.get("transaction_id"):
        raise AssertionError("fixture-transaction-id")
    if parsed.operation_kind != fixture.get("operation_kind") or parsed.operation_kind != 2:
        raise AssertionError("fixture-operation-kind")
    if parsed.nonce != fixture.get("nonce") or parsed.nonce != 0:
        raise AssertionError("fixture-nonce")
    if parsed.nonce_lane != fixture.get("nonce_lane") or parsed.nonce_lane != 0:
        raise AssertionError("fixture-nonce-lane")
    if parsed.sender_agent_id != bytes([1]) * 32:
        raise AssertionError("fixture-sender")
    if parsed.authorizing_key_id != bytes(32):
        raise AssertionError("fixture-controller-namespace")
    if parsed.signer_key_id != bytes([11]) * 32:
        raise AssertionError("fixture-signer")
    if parsed.capability_id is not None or parsed.session_key_grant_id is not None:
        raise AssertionError("fixture-optionals")
    if parsed.valid_after_height != 90 or parsed.expires_after_height != 110:
        raise AssertionError("fixture-validity")
    for key in (
        "candidate_only",
        "wire_accepted",
        "global_state_authority",
        "production_activation",
    ):
        expected = key == "candidate_only"
        if fixture.get(key) is not expected:
            raise AssertionError(f"fixture-boundary:{key}")

    negative: list[dict[str, str]] = []

    def flip(offset: int) -> bytes:
        value = bytearray(raw)
        value[offset] ^= 1
        return bytes(value)

    reject("magic", lambda: parse(flip(0)), negative)
    reject("version", lambda: parse(flip(8)), negative)
    reject("flags", lambda: parse(flip(10)), negative)
    reject("capability-tag", lambda: parse(flip(140)), negative)
    reject("session-tag", lambda: parse(flip(173)), negative)
    reject("operation-kind", lambda: parse(flip(224)), negative)
    reject("command-length", lambda: parse(flip(258)), negative)
    reject("payload", lambda: parse(flip(HEADER_BYTES)), negative)
    reject("payload-digest", lambda: parse(flip(262)), negative)
    reject("wire-digest", lambda: parse(flip(len(raw) - 1)), negative)
    reject("trailing-data", lambda: parse(raw + b"\x00"), negative)
    reject("truncated", lambda: parse(raw[:-1]), negative)

    return {
        "schema": "trnm-agent-transaction-independent-wire-evidence-v1",
        "positive": 1,
        "negative": negative,
        "transaction_id": parsed.transaction_id.hex(),
        "command_bytes": len(parsed.command_bytes),
        "candidate_only": True,
        "wire_accepted": False,
        "global_state_authority": False,
        "production_activation": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if not args.self_test:
        raise SystemExit("use --self-test")
    print(json.dumps(self_test(args.fixture), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
