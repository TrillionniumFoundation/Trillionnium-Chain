"""Deterministic positive bundle and state-sync snapshot for G2F tests."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from .state_tree import StateRecord, digest, encode_records, sparse_root
from .wire import (
    CandidateBundle,
    context_digest,
    derived_family_payloads,
    header_id,
    trace_digest,
)


def _hex(value: bytes) -> str:
    return value.hex()


def _context() -> dict[str, Any]:
    labels = {
        "genesis_hash": b"g2f-genesis",
        "stack_profile_hash": b"g2f-stack-profile-v1",
        "validator_set_hash": b"g2f-validator-set-v1",
        "state_schema_hash": b"g2f-state-schema-v1",
        "da_policy_hash": b"g2f-da-policy-v1",
        "verification_registry_hash": b"g2f-verification-registry-v1",
        "fee_schedule_hash": b"g2f-fee-schedule-v1",
    }
    result: dict[str, Any] = {
        "chain_id": "trnm-g2f-candidate-chain",
        "epoch": 7,
    }
    for name, label in labels.items():
        result[name] = _hex(digest(f"trnm.poco-ai.fixture.{name}.v1", label))
    return result


def _records() -> tuple[StateRecord, ...]:
    values = (
        (4, b"task-0000000000000000000000000001", b"task:active"),
        (7, b"escrow-00000000000000000000000001", b"escrow:1000:TRN"),
        (9, b"result-000000000000000000000000001", b"result:final-valid"),
        (14, b"challenge-0000000000000000000000001", b"challenge:closed"),
        (20, b"settlement-000000000000000000000001", b"settlement:final"),
    )
    records: list[StateRecord] = []
    for kind, label, value in values:
        object_id = digest("trnm.poco-ai.fixture.object-id.v1", label)
        records.append(StateRecord(kind, object_id, 0, value))
    return tuple(sorted(records, key=lambda record: record.key))


@dataclass(frozen=True)
class Fixture:
    context: dict[str, Any]
    height: int
    records: tuple[StateRecord, ...]
    bundle: CandidateBundle
    manifest: dict[str, Any]
    chunks: tuple[bytes, ...]


def _chunk_descriptor(index: int, payload: bytes, records: tuple[StateRecord, ...]) -> dict[str, Any]:
    keys = [record.key for record in records]
    return {
        "chunk_index": index,
        "first_state_key": _hex(keys[0]),
        "last_state_key": _hex(keys[-1]),
        "uncompressed_bytes": len(payload),
        "compressed_bytes": len(payload),
        "uncompressed_hash": _hex(digest("trnm.poco-ai.state-sync-chunk-bytes.v1", payload)),
        "compressed_hash": _hex(digest("trnm.poco-ai.state-sync-chunk-bytes.v1", payload)),
    }


def build_fixture() -> Fixture:
    context = _context()
    height = 42
    records = _records()
    root = sparse_root(records)
    block = header_id(context, height, root)
    families = derived_family_payloads(context, height, block, records, root)
    trace: list[tuple[int, int, bytes]] = []
    previous = b"\x00" * 32
    for stage in range(8):
        step = trace_digest(stage, height, block, previous)
        trace.append((stage, height, step))
        previous = step
    bundle = CandidateBundle(context, height, records, families, tuple(trace), root, block)

    # Identity compression is the only reference-v1 algorithm.  One chunk is
    # sufficient for this bounded fixture and leaves room for gap/duplicate
    # chunk mutants in the tests.
    payload = encode_records(records)
    descriptor = _chunk_descriptor(0, payload, records)
    profile_hash = digest(
        "trnm.poco-ai.state-sync-chunking-profile.v1",
        b"schema=1;algorithm=0;target=65536;max=1048576;split=1",
    )
    compression_hash = digest(
        "trnm.poco-ai.state-sync-compression-profile.v1",
        b"schema=1;algorithm=0",
    )
    checkpoint_id = digest(
        "trnm.poco-ai.epoch-checkpoint-id.candidate.v1", block + root
    )
    descriptor_bytes = json.dumps(
        descriptor, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    manifest_root = digest(
        "trnm.poco-ai.state-sync-chunk-manifest-root.v1", descriptor_bytes
    )
    manifest: dict[str, Any] = {
        "schema_version": 1,
        # State-sync and the binary carrier use the same complete context
        # preimage (all seven descriptor hashes plus epoch), preventing a
        # validator/DA/fee profile swap under a reused genesis/stack digest.
        "context_digest": _hex(context_digest(context)),
        "height": height,
        "block_id": _hex(block),
        "epoch_checkpoint_id": _hex(checkpoint_id),
        "state_root": _hex(root),
        "state_schema_hash": context["state_schema_hash"],
        "chunking_profile_hash": _hex(profile_hash),
        "compression_profile_hash": _hex(compression_hash),
        "chunk_count": 1,
        "total_uncompressed_bytes": len(payload),
        "chunk_manifest_root": _hex(manifest_root),
        "chunk_entries": [descriptor],
        "epoch": context["epoch"],
        "validator_set_hash": context["validator_set_hash"],
        "da_policy_hash": context["da_policy_hash"],
        "verification_registry_hash": context["verification_registry_hash"],
        "fee_schedule_hash": context["fee_schedule_hash"],
        "history_start_height": 0,
        "catch_up_start_height": height + 1,
        "max_chunk_uncompressed_bytes": 1_048_576,
        "max_chunk_count": 64,
    }
    return Fixture(context, height, records, bundle, manifest, (payload,))


_FIXTURE: Fixture | None = None


def fixture() -> Fixture:
    global _FIXTURE
    if _FIXTURE is None:
        _FIXTURE = build_fixture()
    return _FIXTURE
