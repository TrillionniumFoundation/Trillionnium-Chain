"""Reference-v1 sparse application tree used by the candidate harness.

This is deliberately small and dependency-free.  The domains and sibling
ordering mirror protocol document 09, but this module is not a replacement for
the canonical Rust application JMT implementation.  It exists to make the
root-binding boundary executable and to retain negative mutants.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from typing import Iterable, Sequence


DEPTH = 256
MAX_VALUE_BYTES = 4 * 1024 * 1024
ZERO32 = b"\x00" * 32


class StateTreeError(ValueError):
    """Malformed or non-canonical state-tree input."""


def _u16(value: int) -> bytes:
    if not 0 <= value <= 0xFFFF:
        raise StateTreeError("u16 overflow")
    return struct.pack("<H", value)


def _u32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise StateTreeError("u32 overflow")
    return struct.pack("<I", value)


def _u64(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise StateTreeError("u64 overflow")
    return struct.pack("<Q", value)


def digest(domain: str, payload: bytes) -> bytes:
    """DigestV1: length-prefixed UTF-8 domain followed by exact bytes."""

    encoded_domain = domain.encode("utf-8")
    return hashlib.sha256(_u32(len(encoded_domain)) + encoded_domain + payload).digest()


@dataclass(frozen=True)
class StateRecord:
    object_kind: int
    object_id: bytes
    object_version: int
    value: bytes

    def __post_init__(self) -> None:
        if (
            isinstance(self.object_kind, bool)
            or not isinstance(self.object_kind, int)
            or not 0 < self.object_kind <= 0xFFFF
        ):
            raise StateTreeError("object kind out of range")
        if not isinstance(self.object_id, (bytes, bytearray)) or len(self.object_id) != 32:
            raise StateTreeError("object id must be 32 bytes")
        if (
            isinstance(self.object_version, bool)
            or not isinstance(self.object_version, int)
            or not 0 <= self.object_version <= 0xFFFFFFFFFFFFFFFF
        ):
            raise StateTreeError("object version out of range")
        if not isinstance(self.value, (bytes, bytearray)) or len(self.value) > MAX_VALUE_BYTES:
            raise StateTreeError("value exceeds bound")
        object.__setattr__(self, "object_id", bytes(self.object_id))
        object.__setattr__(self, "value", bytes(self.value))

    @property
    def key(self) -> bytes:
        return state_key(self.object_kind, self.object_id)

    @property
    def encoded(self) -> bytes:
        return (
            _u16(self.object_kind)
            + self.object_id
            + _u64(self.object_version)
            + _u32(len(self.value))
            + self.value
        )


@dataclass(frozen=True)
class SparseProof:
    object_version: int | None
    value: bytes | None
    siblings: tuple[bytes, ...]


def state_key(object_kind: int, object_id: bytes) -> bytes:
    if not 0 < object_kind <= 0xFFFF or len(object_id) != 32:
        raise StateTreeError("invalid typed object id")
    return digest("trnm.poco-ai.state-key.v1", _u16(object_kind) + object_id)


def leaf_hash(record: StateRecord) -> bytes:
    return digest(
        "trnm.poco-ai.state-leaf.v1",
        record.key
        + _u16(record.object_kind)
        + _u64(record.object_version)
        + _u32(len(record.value))
        + record.value,
    )


def empty_hashes() -> tuple[bytes, ...]:
    values = [
        digest("trnm.poco-ai.state-empty-leaf.v1", _u16(0)),
    ]
    for level in range(DEPTH):
        values.append(
            digest(
                "trnm.poco-ai.state-node.v1",
                _u16(level) + values[level] + values[level],
            )
        )
    return tuple(values)


def _checked_records(records: Iterable[StateRecord]) -> tuple[StateRecord, ...]:
    ordered = tuple(sorted(records, key=lambda record: record.key))
    if len({record.key for record in ordered}) != len(ordered):
        raise StateTreeError("duplicate state key")
    for left, right in zip(ordered, ordered[1:]):
        if left.key >= right.key:
            raise StateTreeError("state records are not strictly ordered")
    return ordered


def encode_records(records: Iterable[StateRecord]) -> bytes:
    """Canonical chunk payload: count followed by a sorted record list."""

    ordered = _checked_records(records)
    if len(ordered) > 0xFFFF:
        raise StateTreeError("record count exceeds u16")
    return _u16(len(ordered)) + b"".join(record.encoded for record in ordered)


def decode_records(payload: bytes, *, max_records: int = 1024) -> tuple[StateRecord, ...]:
    if len(payload) < 2:
        raise StateTreeError("truncated record list")
    count = struct.unpack_from("<H", payload, 0)[0]
    if count > max_records:
        raise StateTreeError("record count exceeds bound")
    offset = 2
    records: list[StateRecord] = []
    for _ in range(count):
        if offset + 2 + 32 + 8 + 4 > len(payload):
            raise StateTreeError("truncated record")
        kind = struct.unpack_from("<H", payload, offset)[0]
        offset += 2
        object_id = payload[offset : offset + 32]
        offset += 32
        version = struct.unpack_from("<Q", payload, offset)[0]
        offset += 8
        value_length = struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        if value_length > MAX_VALUE_BYTES or offset + value_length > len(payload):
            raise StateTreeError("value exceeds bound or is truncated")
        value = payload[offset : offset + value_length]
        offset += value_length
        records.append(StateRecord(kind, object_id, version, value))
    if offset != len(payload):
        raise StateTreeError("trailing bytes in record list")
    return _checked_records(records)


def records_digest(records: Sequence[StateRecord]) -> bytes:
    encoded = encode_records(records)
    return digest("trnm.poco-ai.state-record-list.v1", encoded)


def sparse_root(records: Iterable[StateRecord]) -> bytes:
    ordered = _checked_records(records)
    empties = empty_hashes()
    if not ordered:
        return empties[DEPTH]

    # At level zero the protocol consumes the least-significant key bit; each
    # next level moves one bit toward the most-significant end.
    current: dict[int, bytes] = {
        int.from_bytes(record.key, "big"): leaf_hash(record) for record in ordered
    }
    for level in range(DEPTH):
        parents: dict[int, bytes] = {}
        parent_indices = {index >> 1 for index in current}
        for parent in parent_indices:
            left = current.get(parent << 1, empties[level])
            right = current.get((parent << 1) | 1, empties[level])
            parents[parent] = digest(
                "trnm.poco-ai.state-node.v1", _u16(level) + left + right
            )
        current = parents
    return current.get(0, empties[DEPTH])


def proof_for(records: Iterable[StateRecord], target: StateRecord) -> SparseProof:
    ordered = _checked_records(records)
    if target not in ordered:
        raise StateTreeError("target is not in state")
    empties = empty_hashes()
    key_number = int.from_bytes(target.key, "big")
    current: dict[int, bytes] = {
        int.from_bytes(record.key, "big"): leaf_hash(record) for record in ordered
    }
    siblings: list[bytes] = []
    for level in range(DEPTH):
        index = key_number >> level
        siblings.append(current.get(index ^ 1, empties[level]))
        parent_indices = {entry >> 1 for entry in current}
        current = {
            parent: digest(
                "trnm.poco-ai.state-node.v1",
                _u16(level)
                + current.get(parent << 1, empties[level])
                + current.get((parent << 1) | 1, empties[level]),
            )
            for parent in parent_indices
        }
    return SparseProof(target.object_version, target.value, tuple(siblings))


def verify_membership(
    object_kind: int,
    object_id: bytes,
    proof: SparseProof,
    expected_root: bytes,
) -> bool:
    if len(expected_root) != 32 or len(proof.siblings) != DEPTH:
        return False
    if proof.object_version is None or proof.value is None:
        return False
    try:
        target = StateRecord(object_kind, object_id, proof.object_version, proof.value)
    except StateTreeError:
        return False
    running = leaf_hash(target)
    key_number = int.from_bytes(target.key, "big")
    for level, sibling in enumerate(proof.siblings):
        if len(sibling) != 32:
            return False
        if (key_number >> level) & 1:
            left, right = sibling, running
        else:
            left, right = running, sibling
        running = digest(
            "trnm.poco-ai.state-node.v1", _u16(level) + left + right
        )
    return running == expected_root
