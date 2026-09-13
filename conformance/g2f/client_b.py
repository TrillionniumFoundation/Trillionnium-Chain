"""Independent light-client parser B for the candidate G2F carrier.

The parser is intentionally self-contained: it imports no fixture, wire, state
tree, or client-A code.  It implements the same *published candidate* byte
contract with a different cursor, hash, and sparse-tree implementation.  A
conformance runner can therefore detect parser disagreement instead of merely
running the same helper twice.  This module is evidence tooling only; it does
not hold validator, signer, voting, activation, or release authority.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any


_MAGIC = b"TRNM-G2F1"
_VERSION = 1
_TREE_VERSION = 0
_MAX_BUNDLE_BYTES = 2 * 1024 * 1024
_MAX_CHAIN_BYTES = 128
_MAX_FAMILY_BYTES = 512
_MAX_RECORDS = 128
_FAMILY_TAGS = (3, 4, 5, 6, 7, 8)
_ZERO = b"\x00" * 32
_DEPTH = 256


class _Reject(Exception):
    """Internal fail-closed rejection carrying a stable code."""

    def __init__(self, code: str):
        self.code = code


class _Reader:
    """A bounds-first cursor distinct from client A's tuple-based parser."""

    __slots__ = ("_data", "_offset")

    def __init__(self, data: bytes):
        self._data = memoryview(data)
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    def take(self, count: int) -> bytes:
        if count < 0 or self._offset + count > len(self._data):
            raise _Reject("truncated")
        start = self._offset
        self._offset += count
        return self._data[start : self._offset].tobytes()

    def byte(self) -> int:
        return self.take(1)[0]

    def number16(self) -> int:
        return int.from_bytes(self.take(2), "little")

    def number32(self) -> int:
        return int.from_bytes(self.take(4), "little")

    def number64(self) -> int:
        return int.from_bytes(self.take(8), "little")

    def done(self) -> bool:
        return self._offset == len(self._data)


def _hash(domain: str, payload: bytes) -> bytes:
    domain_bytes = domain.encode("utf-8")
    return hashlib.sha256(
        len(domain_bytes).to_bytes(4, "little") + domain_bytes + payload
    ).digest()


def _pack16(value: int) -> bytes:
    try:
        return struct.pack("<H", value)
    except struct.error as exc:
        raise _Reject("integer") from exc


def _pack32(value: int) -> bytes:
    try:
        return struct.pack("<I", value)
    except struct.error as exc:
        raise _Reject("integer") from exc


def _pack64(value: int) -> bytes:
    try:
        return struct.pack("<Q", value)
    except struct.error as exc:
        raise _Reject("integer") from exc


def _context_hash(chain: bytes, fields: tuple[bytes, ...], epoch: int) -> bytes:
    if len(chain) == 0 or len(chain) > _MAX_CHAIN_BYTES:
        raise _Reject("context")
    if len(fields) != 7 or any(len(item) != 32 or item == _ZERO for item in fields):
        raise _Reject("context")
    return _hash(
        "trnm.poco-ai.protocol-context.v1",
        _pack16(len(chain)) + chain + b"".join(fields) + _pack64(epoch),
    )


def _empty_nodes() -> tuple[bytes, ...]:
    values = [_hash("trnm.poco-ai.state-empty-leaf.v1", _pack16(0))]
    for level in range(_DEPTH):
        values.append(
            _hash(
                "trnm.poco-ai.state-node.v1",
                _pack16(level) + values[level] + values[level],
            )
        )
    return tuple(values)


def _state_root(records: list[tuple[int, bytes, int, bytes]]) -> bytes:
    empty = _empty_nodes()
    if not records:
        return empty[_DEPTH]
    leaves: dict[int, bytes] = {}
    prior_key: bytes | None = None
    for kind, object_id, version, value in records:
        if kind == 0 or len(object_id) != 32 or len(value) > 4 * 1024 * 1024:
            raise _Reject("record_bound")
        state_key = _hash("trnm.poco-ai.state-key.v1", _pack16(kind) + object_id)
        if prior_key is not None and state_key <= prior_key:
            raise _Reject("record_order")
        prior_key = state_key
        leaf = _hash(
            "trnm.poco-ai.state-leaf.v1",
            state_key + _pack16(kind) + _pack64(version) + _pack32(len(value)) + value,
        )
        numeric = int.from_bytes(state_key, "big")
        if numeric in leaves:
            raise _Reject("duplicate_state_key")
        leaves[numeric] = leaf
    for level in range(_DEPTH):
        parent_values: dict[int, bytes] = {}
        for parent in {index // 2 for index in leaves}:
            left = leaves.get(parent * 2, empty[level])
            right = leaves.get(parent * 2 + 1, empty[level])
            parent_values[parent] = _hash(
                "trnm.poco-ai.state-node.v1", _pack16(level) + left + right
            )
        leaves = parent_values
    return leaves.get(0, empty[_DEPTH])


def _read_records(reader: _Reader) -> list[tuple[int, bytes, int, bytes]]:
    count = reader.number16()
    if count > _MAX_RECORDS:
        raise _Reject("record_bound")
    result: list[tuple[int, bytes, int, bytes]] = []
    previous_key: bytes | None = None
    for _ in range(count):
        kind = reader.number16()
        object_id = reader.take(32)
        version = reader.number64()
        size = reader.number32()
        if size > 4 * 1024 * 1024:
            raise _Reject("record_bound")
        value = reader.take(size)
        key = _hash("trnm.poco-ai.state-key.v1", _pack16(kind) + object_id)
        if previous_key is not None and key <= previous_key:
            raise _Reject("record_order")
        previous_key = key
        result.append((kind, object_id, version, value))
    return result


def verify_bundle(data: bytes | bytearray) -> dict[str, Any]:
    """Parse and verify the complete W0-W7 candidate carrier."""

    try:
        if not isinstance(data, (bytes, bytearray)):
            raise _Reject("bundle_type")
        raw = bytes(data)
        if not raw or len(raw) > _MAX_BUNDLE_BYTES:
            raise _Reject("bundle_bound")
        reader = _Reader(raw)
        if reader.take(len(_MAGIC)) != _MAGIC:
            raise _Reject("magic")
        if reader.number16() != _VERSION:
            raise _Reject("unsupported_version")
        # Reserved flags are deliberately forbidden: no composite-root or
        # hidden compatibility mode may bypass the application JMT check.
        if reader.number16() != 0:
            raise _Reject("composite_root_substitution")
        chain_size = reader.number16()
        if not 1 <= chain_size <= _MAX_CHAIN_BYTES:
            raise _Reject("context")
        chain = reader.take(chain_size)
        try:
            chain.decode("ascii")
        except UnicodeDecodeError as exc:
            raise _Reject("context") from exc
        context_fields = tuple(reader.take(32) for _ in range(7))
        epoch = reader.number64()
        height = reader.number64()
        if height == 0:
            raise _Reject("height")
        block_id = reader.take(32)
        post_state_root = reader.take(32)
        if reader.number16() != _TREE_VERSION:
            raise _Reject("state_tree_version")
        context_hash = _context_hash(chain, context_fields, epoch)
        if block_id != _hash(
            "trnm.poco-ai.block-header.v1",
            context_hash + _pack64(height) + post_state_root + _pack16(_TREE_VERSION),
        ):
            raise _Reject("header_id")

        if reader.byte() != 8:
            raise _Reject("trace_incomplete")
        previous = _ZERO
        for expected_stage in range(8):
            stage = reader.byte()
            step_height = reader.number64()
            step_hash = reader.take(32)
            if stage != expected_stage or step_height != height:
                raise _Reject("trace_order")
            expected = _hash(
                "trnm.poco-ai.w0-w7-trace-step.candidate.v1",
                bytes((stage,)) + _pack64(height) + previous + block_id,
            )
            if step_hash != expected:
                raise _Reject("trace_digest")
            previous = step_hash

        if reader.byte() != len(_FAMILY_TAGS):
            raise _Reject("missing_family")
        families: dict[int, bytes] = {}
        for expected_tag in _FAMILY_TAGS:
            tag = reader.byte()
            if tag != expected_tag or tag in families:
                raise _Reject("family_order")
            size = reader.number32()
            if size > _MAX_FAMILY_BYTES:
                raise _Reject("proof_bound")
            families[tag] = reader.take(size)

        records = _read_records(reader)
        if not reader.done():
            raise _Reject("trailing_bytes")
        root = _state_root(records)
        if root != post_state_root:
            raise _Reject("root_mismatch")

        order = families[3]
        if len(order) != 120:
            raise _Reject("order_proof")
        if (
            order[0:8] != _pack64(height)
            or order[8:40] != block_id
            or order[40:72] != post_state_root
            or order[72:80] != _pack64(epoch)
            or order[80:88] != _pack64(3)
            or order[88:120]
            != _hash("trnm.poco-ai.order-qc.candidate.v1", block_id + post_state_root)
        ):
            raise _Reject("order_proof")

        batch_id = _hash("trnm.poco-ai.batch-id.candidate.v1", block_id)
        artifact = _hash("trnm.poco-ai.artifact-root.candidate.v1", batch_id)
        if families[4] != batch_id + artifact + _pack64(height + 64) + context_fields[4]:
            raise _Reject("da_proof")

        encoded_records = _pack16(len(records)) + b"".join(
            _pack16(kind) + object_id + _pack64(version) + _pack32(len(value)) + value
            for kind, object_id, version, value in records
        )
        record_digest = _hash("trnm.poco-ai.state-record-list.v1", encoded_records)
        execution = _hash("trnm.poco-ai.execution-root.candidate.v1", record_digest)
        receipt = _hash(
            "trnm.poco-ai.execution-receipt-root.candidate.v1",
            execution + _pack32(len(records)),
        )
        if families[5] != execution + _pack32(len(records)) + receipt:
            raise _Reject("execution_proof")

        result_id = _hash("trnm.poco-ai.result-id.candidate.v1", execution)
        profile = _hash("trnm.poco-ai.verification-profile.candidate.v1", context_hash)
        result_root = _hash(
            "trnm.poco-ai.result-state-root.candidate.v1",
            result_id + profile + bytes((5,)),
        )
        if families[6] != result_id + profile + bytes((5,)) + result_root:
            raise _Reject("result_proof")

        settlement_id = _hash("trnm.poco-ai.settlement-id.candidate.v1", result_id)
        conservation = _hash(
            "trnm.poco-ai.conservation-root.candidate.v1",
            result_root + _pack64(height),
        )
        if families[7] != settlement_id + conservation + _pack64(height + 2) + bytes((2,)):
            raise _Reject("settlement_proof")

        upgrade_plan = _hash(
            "trnm.poco-ai.upgrade-plan.candidate.v1", context_hash + _pack64(height)
        )
        migration = _hash(
            "trnm.poco-ai.migration-root.candidate.v1", upgrade_plan + post_state_root
        )
        if families[8] != _pack32(0) + _pack32(1) + upgrade_plan + migration:
            raise _Reject("upgrade_proof")
        return {
            "ok": True,
            "code": "ok",
            "height": height,
            "block_id": block_id.hex(),
            "post_state_root": post_state_root.hex(),
            "families": list(_FAMILY_TAGS),
            "trace_stages": list(range(8)),
        }
    except _Reject as reject:
        return {"ok": False, "code": reject.code}
    except (struct.error, ValueError, OverflowError, IndexError):
        return {"ok": False, "code": "malformed"}


__all__ = ["verify_bundle"]
