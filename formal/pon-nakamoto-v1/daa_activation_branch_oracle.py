"""Fork-local ASERT activation-height research, never a production consensus selector.

Unlike the original genesis-adjacent research shadow, this derives the ASERT
anchor and its predecessor timestamp from the *candidate branch*. This permits
reorgs crossing the proposed activation height without pinning an arbitrary
block hash as administrator finality.

CRITICAL: `verified_headers` must already be independently work-, signature-,
state-, context- and target-validated by a real native Node. This function does
NOT verify those facts, issue admission authority, select a fork, or implement
an activated consensus version. It refuses incomplete ancestry and excess work.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from daa_research_oracle import UINT64_MAX, UINT256_MAX, asert_target, mtp11
from daa_branch_context_oracle import ResearchHeader

Hash32 = bytes


@dataclass(frozen=True)
class ActivationContext:
    network: Hash32
    parameters: Hash32
    genesis: Hash32
    genesis_timestamp: int
    activation_height: int
    spacing: int
    half_life: int
    pow_limit: int
    clock: str
    # A source-independent, externally frozen rule/profile commitment. Its
    # mere presence is *not* a signature or evidence of honest administration.
    rule_commitment: Hash32
    max_reads: int = 4096


@dataclass(frozen=True)
class ActivationShadow:
    branch_parent: Hash32
    anchor_block: Hash32
    anchor_parent: Hash32
    anchor_height: int
    anchor_target: int
    anchor_parent_time: int
    candidate_height: int
    observed_parent_time: int
    target: int
    ancestry_reads: int
    clock: str


def _hash32(value: object, *, nonzero: bool = True) -> bool:
    return (type(value) is bytes and len(value) == 32
            and (not nonzero or value != bytes(32)))


def _uint64(value: object, *, positive: bool = False) -> bool:
    return (type(value) is int and 0 <= value <= UINT64_MAX
            and (not positive or value > 0))


def _verify_context(ctx: ActivationContext, parent_id: bytes) -> None:
    if not (
        isinstance(ctx, ActivationContext)
        and all(_hash32(k) for k in (ctx.network, ctx.parameters, ctx.genesis,
                                    ctx.rule_commitment, parent_id))
        and parent_id != ctx.genesis
        and _uint64(ctx.genesis_timestamp)
        and _uint64(ctx.activation_height, positive=True)
        and ctx.activation_height < UINT64_MAX
        and _uint64(ctx.spacing, positive=True)
        and _uint64(ctx.half_life, positive=True)
        and type(ctx.pow_limit) is int and 1 <= ctx.pow_limit <= UINT256_MAX
        and ctx.clock in ('raw', 'mtp11')
        and type(ctx.max_reads) is int and 1 <= ctx.max_reads <= 4096
    ):
        raise ValueError('ASERT_ACTIVATION_CONTEXT')


def activation_shadow_from_ancestry(
    context: ActivationContext,
    parent_id: Hash32,
    verified_headers: Mapping[Hash32, ResearchHeader],
) -> ActivationShadow:
    """Derive a *shadow* target with a branch-local activation-height anchor.

    The block at `activation_height` is still checked by the OLD difficulty
    rule. The first ASERT-eligible candidate is its successor. A heavier fork
    that replaces the anchor block selects a *different* anchor from that same
    candidate branch; no administrator-chosen hash becomes irreversible.

    For the experimental `mtp11` clock, BOTH parent time and anchored-block
    predecessor time are independently evaluated as their own MTP11 windows.
    Mixing MTP(parent) with raw(anchor.parent) would bias even an honest,
    constant-spacing branch and is explicitly prohibited here.

    This linear read remains bounded and requires a separately VERIFIED and
    immutable ancestry view. It does not verify PoW, legacy target or signatures.
    Native scale requires an authenticated ancestry summary, not a magic cache.
    """
    _verify_context(context, parent_id)
    if not isinstance(verified_headers, Mapping):
        raise ValueError('ASERT_ANCESTRY_TYPE')
    cursor = parent_id
    expected_height: int | None = None
    parent_height: int | None = None
    parent_raw_time: int | None = None
    anchor_id: bytes | None = None
    anchor_parent_id: bytes | None = None
    anchor_target: int | None = None
    anchor_prev_raw_time: int | None = None
    parent_window: list[int] = []
    anchor_window: list[int] = []
    anchor_predecessor_seen = False
    visited: set[bytes] = set()
    reads = 0

    while True:
        if cursor == context.genesis:
            if expected_height != 0:
                raise ValueError('ASERT_GENESIS_HEIGHT')
            if anchor_id is None:
                raise ValueError('ASERT_ANCHOR_MISSING')
            if anchor_parent_id == context.genesis:
                anchor_prev_raw_time = context.genesis_timestamp
                anchor_window.append(context.genesis_timestamp)
            elif anchor_predecessor_seen and len(anchor_window) < 11:
                anchor_window.append(context.genesis_timestamp)
            if len(parent_window) < 11:
                parent_window.append(context.genesis_timestamp)
            # Early genesis terminal is a legitimate short MTP window.
            break
        if reads >= context.max_reads:
            raise ValueError('ASERT_ANCESTRY_BUDGET')
        if cursor in visited:
            raise ValueError('ASERT_ANCESTRY_CYCLE')
        visited.add(cursor)
        try:
            h = verified_headers[cursor]
        except (KeyError, TypeError) as e:
            raise ValueError('ASERT_ANCESTRY_UNAVAILABLE') from e
        reads += 1
        if not (
            isinstance(h, ResearchHeader)
            and _hash32(h.claimed_id) and h.claimed_id == cursor
            and h.network == context.network and h.parameters == context.parameters
            and _hash32(h.parent)
            and _uint64(h.height, positive=True)
            and _uint64(h.timestamp)
            and type(h.target) is int and 1 <= h.target <= context.pow_limit
        ):
            raise ValueError('ASERT_ANCESTRY_CONTEXT')
        if h.parent == cursor:
            raise ValueError('ASERT_ANCESTRY_CYCLE')
        if expected_height is not None and h.height != expected_height:
            raise ValueError('ASERT_ANCESTRY_HEIGHT')
        if parent_height is None:
            parent_height, parent_raw_time = h.height, h.timestamp
            if parent_height < context.activation_height or parent_height == UINT64_MAX:
                raise ValueError('ASERT_NOT_ACTIVE')
        if len(parent_window) < 11:
            parent_window.append(h.timestamp)
        if h.height == context.activation_height:
            anchor_id = cursor
            anchor_target = h.target
            anchor_parent_id = h.parent
        if h.height == context.activation_height - 1 and anchor_id is not None:
            if cursor != anchor_parent_id:
                raise ValueError('ASERT_ANCHOR_PARENT')
            anchor_predecessor_seen = True
            anchor_prev_raw_time = h.timestamp
        if anchor_predecessor_seen and len(anchor_window) < 11:
            anchor_window.append(h.timestamp)
        expected_height = h.height - 1
        cursor = h.parent
        if (anchor_id is not None and anchor_prev_raw_time is not None
                and (context.clock == 'raw'
                     or (len(parent_window) == 11 and len(anchor_window) == 11))):
            break

    if not (parent_height is not None and parent_raw_time is not None
            and anchor_id is not None and anchor_parent_id is not None
            and anchor_target is not None and anchor_prev_raw_time is not None):
        raise ValueError('ASERT_ANCHOR_MISSING')
    if context.clock == 'raw':
        observed_time = parent_raw_time
        anchor_time = anchor_prev_raw_time
    else:
        if not parent_window or not anchor_window:
            raise ValueError('ASERT_MTP_WINDOW')
        observed_time = mtp11(parent_window)
        anchor_time = mtp11(anchor_window)

    target = asert_target(
        anchor_target=anchor_target,
        anchor_parent_time=anchor_time,
        parent_time=observed_time,
        anchor_height=context.activation_height,
        candidate_height=parent_height + 1,
        spacing=context.spacing,
        half_life=context.half_life,
        pow_limit=context.pow_limit,
    )
    return ActivationShadow(
        branch_parent=parent_id,
        anchor_block=anchor_id,
        anchor_parent=anchor_parent_id,
        anchor_height=context.activation_height,
        anchor_target=anchor_target,
        anchor_parent_time=anchor_time,
        candidate_height=parent_height + 1,
        observed_parent_time=observed_time,
        target=target,
        ancestry_reads=reads,
        clock=context.clock,
    )
