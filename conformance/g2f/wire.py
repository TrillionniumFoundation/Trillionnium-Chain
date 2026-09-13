"""Deterministic candidate light-client carrier.

The carrier is intentionally a tiny binary fixture rather than a second
protocol implementation.  It gives the two independent clients one exact byte
stream to parse while keeping all production and normative wire code untouched.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Mapping, Sequence

from .state_tree import StateRecord, digest, records_digest, sparse_root


MAGIC = b"TRNM-G2F1"  # fixed nine-byte candidate fixture magic
VERSION = 1
TREE_VERSION = 0
FAMILY_ORDER = (3, 4, 5, 6, 7, 8)  # Order, DA, execution, result, settlement, upgrade
TRACE_STAGES = tuple(range(8))  # W0 .. W7
ZERO32 = b"\x00" * 32


def u16(value: int) -> bytes:
    return struct.pack("<H", value)


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def context_digest(context: Mapping[str, object]) -> bytes:
    chain = str(context["chain_id"]).encode("ascii")
    parts = [
        u16(len(chain)),
        chain,
        bytes.fromhex(str(context["genesis_hash"])),
        bytes.fromhex(str(context["stack_profile_hash"])),
        bytes.fromhex(str(context["validator_set_hash"])),
        bytes.fromhex(str(context["state_schema_hash"])),
        bytes.fromhex(str(context["da_policy_hash"])),
        bytes.fromhex(str(context["verification_registry_hash"])),
        bytes.fromhex(str(context["fee_schedule_hash"])),
        u64(int(context["epoch"])),
    ]
    return digest("trnm.poco-ai.protocol-context.v1", b"".join(parts))


def header_id(
    context: Mapping[str, object], height: int, post_state_root: bytes
) -> bytes:
    return digest(
        "trnm.poco-ai.block-header.v1",
        context_digest(context) + u64(height) + post_state_root + u16(TREE_VERSION),
    )


def trace_digest(stage: int, height: int, block_id: bytes, previous: bytes) -> bytes:
    return digest(
        "trnm.poco-ai.w0-w7-trace-step.candidate.v1",
        bytes((stage,)) + u64(height) + previous + block_id,
    )


def derived_family_payloads(
    context: Mapping[str, object],
    height: int,
    block_id: bytes,
    records: Sequence[StateRecord],
    post_state_root: bytes,
) -> dict[int, bytes]:
    """Construct the six fixed-size proof-family payloads for the fixture."""

    ctx = context_digest(context)
    rec_digest = records_digest(records)
    execution_root = digest("trnm.poco-ai.execution-root.candidate.v1", rec_digest)
    receipt_root = digest(
        "trnm.poco-ai.execution-receipt-root.candidate.v1",
        execution_root + u32(len(records)),
    )
    result_id = digest("trnm.poco-ai.result-id.candidate.v1", execution_root)
    profile_hash = digest(
        "trnm.poco-ai.verification-profile.candidate.v1", ctx
    )
    result_root = digest(
        "trnm.poco-ai.result-state-root.candidate.v1",
        result_id + profile_hash + bytes((5,)),
    )
    settlement_id = digest("trnm.poco-ai.settlement-id.candidate.v1", result_id)
    conservation_root = digest(
        "trnm.poco-ai.conservation-root.candidate.v1", result_root + u64(height)
    )
    batch_id = digest("trnm.poco-ai.batch-id.candidate.v1", block_id)
    artifact_root = digest("trnm.poco-ai.artifact-root.candidate.v1", batch_id)
    order_qc_hash = digest(
        "trnm.poco-ai.order-qc.candidate.v1", block_id + post_state_root
    )
    plan_hash = digest(
        "trnm.poco-ai.upgrade-plan.candidate.v1", ctx + u64(height)
    )
    migration_root = digest(
        "trnm.poco-ai.migration-root.candidate.v1", plan_hash + post_state_root
    )
    return {
        3: u64(height)
        + block_id
        + post_state_root
        + u64(int(context["epoch"]))
        + u64(3)
        + order_qc_hash,
        4: batch_id
        + artifact_root
        + u64(height + 64)
        + bytes.fromhex(str(context["da_policy_hash"])),
        5: execution_root + u32(len(records)) + receipt_root,
        6: result_id + profile_hash + bytes((5,)) + result_root,
        7: settlement_id + conservation_root + u64(height + 2) + bytes((2,)),
        8: u32(0) + u32(1) + plan_hash + migration_root,
    }


@dataclass(frozen=True)
class CandidateBundle:
    context: Mapping[str, object]
    height: int
    records: tuple[StateRecord, ...]
    families: Mapping[int, bytes]
    trace: tuple[tuple[int, int, bytes], ...]
    post_state_root: bytes
    block_id: bytes

    @property
    def encoded(self) -> bytes:
        return encode_bundle(self)

    @property
    def digest(self) -> bytes:
        return digest(
            "trnm.poco-ai.g2f-light-client-bundle.candidate.v1", self.encoded
        )


def encode_bundle(bundle: CandidateBundle) -> bytes:
    context = bundle.context
    chain = str(context["chain_id"]).encode("ascii")
    if len(chain) > 128:
        raise ValueError("chain id exceeds bound")
    hashes = (
        "genesis_hash",
        "stack_profile_hash",
        "validator_set_hash",
        "state_schema_hash",
        "da_policy_hash",
        "verification_registry_hash",
        "fee_schedule_hash",
    )
    out = bytearray(MAGIC + u16(VERSION) + u16(0))
    out += u16(len(chain)) + chain
    for name in hashes:
        value = bytes.fromhex(str(context[name]))
        if len(value) != 32:
            raise ValueError(f"{name} must be 32 bytes")
        out += value
    out += u64(int(context["epoch"]))
    out += u64(bundle.height)
    out += bundle.block_id
    out += bundle.post_state_root
    out += u16(TREE_VERSION)

    if len(bundle.trace) != len(TRACE_STAGES):
        raise ValueError("fixture must carry exactly W0-W7")
    out += bytes((len(bundle.trace),))
    for stage, height, step_hash in bundle.trace:
        out += bytes((stage,)) + u64(height) + step_hash

    if tuple(sorted(bundle.families)) != FAMILY_ORDER:
        raise ValueError("proof families must be complete and ordered")
    out += bytes((len(bundle.families),))
    for family in FAMILY_ORDER:
        payload = bytes(bundle.families[family])
        out += bytes((family,)) + u32(len(payload)) + payload

    if len(bundle.records) > 0xFFFF:
        raise ValueError("too many records")
    out += u16(len(bundle.records))
    for record in bundle.records:
        out += record.encoded
    return bytes(out)
