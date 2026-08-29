"""Independent light-client parser A.

It intentionally does not import the fixture encoder or the other verifier.
The parser is a small cursor machine with its own digest and sparse-tree code;
that separation makes disagreement visible in the conformance runner.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any


MAGIC = b"TRNM-G2F1"
MAX_BUNDLE = 2 * 1024 * 1024
MAX_CHAIN = 128
MAX_FAMILIES = 6
MAX_RECORDS = 128
FAMILIES = (3, 4, 5, 6, 7, 8)


class _Reject(Exception):
    def __init__(self, code: str):
        self.code = code


def _digest(domain: str, payload: bytes) -> bytes:
    encoded = domain.encode("utf-8")
    return hashlib.sha256(struct.pack("<I", len(encoded)) + encoded + payload).digest()


def _u16(value: int) -> bytes:
    return struct.pack("<H", value)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def _take(data: bytes, cursor: int, count: int) -> tuple[bytes, int]:
    end = cursor + count
    if end > len(data):
        raise _Reject("truncated")
    return data[cursor:end], end


def _sparse_root(records: list[tuple[int, bytes, int, bytes]]) -> bytes:
    empty = [_digest("trnm.poco-ai.state-empty-leaf.v1", _u16(0))]
    for level in range(256):
        empty.append(
            _digest("trnm.poco-ai.state-node.v1", _u16(level) + empty[-1] + empty[-1])
        )
    current: dict[int, bytes] = {}
    seen: set[bytes] = set()
    for kind, object_id, version, value in records:
        if kind == 0 or len(object_id) != 32 or len(value) > 4 * 1024 * 1024:
            raise _Reject("record_bound")
        key = _digest("trnm.poco-ai.state-key.v1", _u16(kind) + object_id)
        if key in seen:
            raise _Reject("duplicate_state_key")
        seen.add(key)
        leaf = _digest(
            "trnm.poco-ai.state-leaf.v1",
            key + _u16(kind) + _u64(version) + _u32(len(value)) + value,
        )
        current[int.from_bytes(key, "big")] = leaf
    if not current:
        return empty[256]
    for level in range(256):
        parents: dict[int, bytes] = {}
        for index in {entry >> 1 for entry in current}:
            left = current.get(index << 1, empty[level])
            right = current.get((index << 1) | 1, empty[level])
            parents[index] = _digest(
                "trnm.poco-ai.state-node.v1", _u16(level) + left + right
            )
        current = parents
    return current.get(0, empty[256])


def _context_digest(
    chain: bytes, hashes: list[bytes], epoch: int
) -> bytes:
    return _digest(
        "trnm.poco-ai.protocol-context.v1",
        _u16(len(chain)) + chain + b"".join(hashes) + _u64(epoch),
    )


def verify_bundle(data: bytes) -> dict[str, Any]:
    """Verify the candidate carrier and return a stable summary/error code."""

    try:
        if not isinstance(data, (bytes, bytearray)):
            raise _Reject("bundle_type")
        # Freeze mutable input before any slice is retained or hashed.  This
        # mirrors client B's boundary and prevents a caller from changing a
        # bytearray while verification is in progress.
        data = bytes(data)
        if not data or len(data) > MAX_BUNDLE:
            raise _Reject("bundle_bound")
        cursor = 0
        magic, cursor = _take(data, cursor, len(MAGIC))
        if magic != MAGIC:
            raise _Reject("magic")
        raw_version, cursor = _take(data, cursor, 2)
        version = struct.unpack("<H", raw_version)[0]
        if version != 1:
            raise _Reject("unsupported_version")
        raw_flags, cursor = _take(data, cursor, 2)
        flags = struct.unpack("<H", raw_flags)[0]
        if flags:
            raise _Reject("composite_root_substitution")
        raw_len, cursor = _take(data, cursor, 2)
        chain_len = struct.unpack("<H", raw_len)[0]
        if not 1 <= chain_len <= MAX_CHAIN:
            raise _Reject("context")
        chain, cursor = _take(data, cursor, chain_len)
        try:
            chain.decode("ascii")
        except UnicodeDecodeError as exc:
            raise _Reject("context") from exc
        hashes: list[bytes] = []
        for _ in range(7):
            value, cursor = _take(data, cursor, 32)
            if value == b"\x00" * 32:
                raise _Reject("context")
            hashes.append(value)
        raw_epoch, cursor = _take(data, cursor, 8)
        epoch = struct.unpack("<Q", raw_epoch)[0]
        raw_height, cursor = _take(data, cursor, 8)
        height = struct.unpack("<Q", raw_height)[0]
        if height == 0:
            raise _Reject("height")
        block_id, cursor = _take(data, cursor, 32)
        post_root, cursor = _take(data, cursor, 32)
        raw_tree, cursor = _take(data, cursor, 2)
        if struct.unpack("<H", raw_tree)[0] != 0:
            raise _Reject("state_tree_version")

        context_hash = _context_digest(chain, hashes, epoch)
        expected_block = _digest(
            "trnm.poco-ai.block-header.v1",
            context_hash + _u64(height) + post_root + _u16(0),
        )
        if block_id != expected_block:
            raise _Reject("header_id")

        raw_trace_count, cursor = _take(data, cursor, 1)
        if raw_trace_count[0] != 8:
            raise _Reject("trace_incomplete")
        previous = b"\x00" * 32
        for expected_stage in range(8):
            raw_stage, cursor = _take(data, cursor, 1)
            stage = raw_stage[0]
            raw_step_height, cursor = _take(data, cursor, 8)
            step_height = struct.unpack("<Q", raw_step_height)[0]
            step_hash, cursor = _take(data, cursor, 32)
            if stage != expected_stage or step_height != height:
                raise _Reject("trace_order")
            expected_step = _digest(
                "trnm.poco-ai.w0-w7-trace-step.candidate.v1",
                bytes((stage,)) + _u64(height) + previous + block_id,
            )
            if step_hash != expected_step:
                raise _Reject("trace_digest")
            previous = step_hash

        raw_family_count, cursor = _take(data, cursor, 1)
        if raw_family_count[0] != MAX_FAMILIES:
            raise _Reject("missing_family")
        families: dict[int, bytes] = {}
        for expected_family in FAMILIES:
            raw_tag, cursor = _take(data, cursor, 1)
            family = raw_tag[0]
            if family != expected_family or family in families:
                raise _Reject("family_order")
            raw_size, cursor = _take(data, cursor, 4)
            size = struct.unpack("<I", raw_size)[0]
            if size > 512:
                raise _Reject("proof_bound")
            payload, cursor = _take(data, cursor, size)
            families[family] = payload

        raw_count, cursor = _take(data, cursor, 2)
        count = struct.unpack("<H", raw_count)[0]
        if count > MAX_RECORDS:
            raise _Reject("record_bound")
        records: list[tuple[int, bytes, int, bytes]] = []
        previous_key: bytes | None = None
        for _ in range(count):
            raw_kind, cursor = _take(data, cursor, 2)
            kind = struct.unpack("<H", raw_kind)[0]
            object_id, cursor = _take(data, cursor, 32)
            raw_version, cursor = _take(data, cursor, 8)
            object_version = struct.unpack("<Q", raw_version)[0]
            raw_value_len, cursor = _take(data, cursor, 4)
            value_len = struct.unpack("<I", raw_value_len)[0]
            if value_len > 4 * 1024 * 1024:
                raise _Reject("record_bound")
            value, cursor = _take(data, cursor, value_len)
            key = _digest("trnm.poco-ai.state-key.v1", _u16(kind) + object_id)
            if previous_key is not None and key <= previous_key:
                raise _Reject("record_order")
            previous_key = key
            records.append((kind, object_id, object_version, value))
        if cursor != len(data):
            raise _Reject("trailing_bytes")

        root = _sparse_root(records)
        if post_root != root:
            raise _Reject("root_mismatch")
        self = families[3]
        if len(self) != 120:
            raise _Reject("order_proof")
        if self[:8] != _u64(height) or self[8:40] != block_id or self[40:72] != post_root:
            raise _Reject("order_proof")
        if self[72:80] != _u64(epoch) or self[80:88] != _u64(3):
            raise _Reject("order_proof")
        if self[88:] != _digest("trnm.poco-ai.order-qc.candidate.v1", block_id + post_root):
            raise _Reject("order_proof")

        batch_id = _digest("trnm.poco-ai.batch-id.candidate.v1", block_id)
        artifact_root = _digest("trnm.poco-ai.artifact-root.candidate.v1", batch_id)
        if families[4] != batch_id + artifact_root + _u64(height + 64) + hashes[4]:
            raise _Reject("da_proof")
        rec_payload = _u16(count) + b"".join(
            _u16(kind) + object_id + _u64(ver) + _u32(len(value)) + value
            for kind, object_id, ver, value in records
        )
        execution_root = _digest("trnm.poco-ai.execution-root.candidate.v1", _digest("trnm.poco-ai.state-record-list.v1", rec_payload))
        receipt_root = _digest("trnm.poco-ai.execution-receipt-root.candidate.v1", execution_root + _u32(count))
        if families[5] != execution_root + _u32(count) + receipt_root:
            raise _Reject("execution_proof")
        result_id = _digest("trnm.poco-ai.result-id.candidate.v1", execution_root)
        profile_hash = _digest("trnm.poco-ai.verification-profile.candidate.v1", context_hash)
        result_root = _digest("trnm.poco-ai.result-state-root.candidate.v1", result_id + profile_hash + bytes((5,)))
        if families[6] != result_id + profile_hash + bytes((5,)) + result_root:
            raise _Reject("result_proof")
        settlement_id = _digest("trnm.poco-ai.settlement-id.candidate.v1", result_id)
        conservation = _digest("trnm.poco-ai.conservation-root.candidate.v1", result_root + _u64(height))
        if families[7] != settlement_id + conservation + _u64(height + 2) + bytes((2,)):
            raise _Reject("settlement_proof")
        plan = _digest("trnm.poco-ai.upgrade-plan.candidate.v1", context_hash + _u64(height))
        migration = _digest("trnm.poco-ai.migration-root.candidate.v1", plan + post_root)
        if families[8] != _u32(0) + _u32(1) + plan + migration:
            raise _Reject("upgrade_proof")
        return {
            "ok": True,
            "code": "ok",
            "height": height,
            "block_id": block_id.hex(),
            "post_state_root": post_root.hex(),
            "families": list(FAMILIES),
            "trace_stages": list(range(8)),
        }
    except _Reject as reject:
        return {"ok": False, "code": reject.code}
    except (struct.error, ValueError, OverflowError, TypeError, IndexError):
        return {"ok": False, "code": "malformed"}
