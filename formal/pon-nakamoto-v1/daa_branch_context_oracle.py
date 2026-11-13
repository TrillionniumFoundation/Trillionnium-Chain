"""Independent non-activated ASERT branch-context screen.

The supplied map is assumed previously authenticated; no W1 proof, receipt,
genesis timestamp authority or production consensus validity is established.
"""
from dataclasses import dataclass
from typing import Mapping
from daa_research_oracle import asert_target, mtp11

@dataclass(frozen=True)
class ResearchHeader:
    claimed_id: bytes
    network: bytes
    parameters: bytes
    parent: bytes
    height: int
    timestamp: int
    target: int

@dataclass(frozen=True)
class ResearchContext:
    network: bytes
    parameters: bytes
    genesis: bytes
    genesis_timestamp: int
    anchor_block: bytes
    anchor_target: int
    anchor_height: int
    spacing: int
    half_life: int
    pow_limit: int
    clock: str
    max_reads: int = 4096

def shadow_target_from_ancestry(context: ResearchContext, parent_id: bytes,
                                verified_headers: Mapping[bytes, ResearchHeader]) -> int:
    if not (
        context.anchor_height == 1
        and context.anchor_block != context.genesis
        and context.genesis != bytes(32)
        and context.network != bytes(32)
        and context.parameters != bytes(32)
        and 1 <= context.max_reads <= 4096
        and context.spacing > 0 and context.half_life > 0
        and context.clock in ("raw", "mtp11")
    ):
        raise ValueError("ASERT_BRANCH_CONTEXT")
    cursor = parent_id
    prev_height = None
    parent_height = None
    parent_time = None
    recent = []
    for _ in range(context.max_reads):
        if cursor == context.genesis:
            raise ValueError("ASERT_ANCHOR_MISSING")
        try:
            header = verified_headers[cursor]
        except KeyError as ex:
            raise ValueError("ASERT_ANCESTRY_UNAVAILABLE") from ex
        if (header.claimed_id != cursor or header.network != context.network
                or header.parameters != context.parameters
                or header.height < context.anchor_height):
            raise ValueError("ASERT_ANCESTRY_CONTEXT")
        if prev_height is not None and header.height + 1 != prev_height:
            raise ValueError("ASERT_ANCESTRY_HEIGHT")
        if parent_height is None:
            parent_height, parent_time = header.height, header.timestamp
        if len(recent) < 11:
            recent.append(header.timestamp)
        if cursor == context.anchor_block:
            if (header.height != context.anchor_height
                    or header.parent != context.genesis
                    or header.target != context.anchor_target):
                raise ValueError("ASERT_ANCHOR_BINDING")
            if len(recent) < 11:
                recent.append(context.genesis_timestamp)
            selected = parent_time if context.clock == "raw" else mtp11(recent)
            return asert_target(context.anchor_target, context.genesis_timestamp,
                                selected, context.anchor_height, parent_height + 1,
                                context.spacing, context.half_life, context.pow_limit)
        prev_height = header.height
        cursor = header.parent
    raise ValueError("ASERT_ANCESTRY_BUDGET")
