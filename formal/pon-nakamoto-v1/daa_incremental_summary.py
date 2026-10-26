"""Research-only, branch-local bounded-work ASERT state projection.

Assumes caller has *already* independently validated full PoN work, legacy or
candidate target, complete body, time, state, and the immutable header identity.
This code NEVER does those things or provides a consensus-validity capability.
Never import a peer's cached summary as a verified parent. A release version must
attach equivalent owned, recoverable state to the native branch database.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from daa_research_oracle import UINT64_MAX, UINT256_MAX, asert_target, mtp11

Hash = bytes


def _hash(value: object) -> bool:
    return type(value) is bytes and len(value) == 32 and value != bytes(32)


def _u64(value: object) -> bool:
    return type(value) is int and 0 <= value <= UINT64_MAX


@dataclass(frozen=True)
class Context:
    network: Hash
    parameters: Hash
    genesis: Hash
    genesis_timestamp: int
    activation_height: int
    spacing: int
    half_life: int
    pow_limit: int
    clock: str
    rule_commitment: Hash

    def __post_init__(self) -> None:
        if not (all(_hash(x) for x in (self.network, self.parameters, self.genesis,
                                      self.rule_commitment))
                and self.genesis not in (self.network, self.parameters)
                and _u64(self.genesis_timestamp)
                and _u64(self.activation_height) and 0 < self.activation_height < UINT64_MAX
                and _u64(self.spacing) and self.spacing > 0
                and _u64(self.half_life) and self.half_life > 0
                and type(self.pow_limit) is int and 1 <= self.pow_limit <= UINT256_MAX
                and self.clock in ('raw', 'mtp11')):
            raise ValueError('ASERT_SUMMARY_CONTEXT')


@dataclass(frozen=True)
class Header:
    claimed_id: Hash
    network: Hash
    parameters: Hash
    parent: Hash
    height: int
    timestamp: int
    target: int


@dataclass(frozen=True)
class Summary:
    """Constant-bounded per-block derived state, NOT a peer-transferable proof."""
    block_id: Hash
    height: int
    timestamp: int
    recent_parent_first: tuple[int, ...]
    anchor_id: Hash | None
    anchor_parent_id: Hash | None
    anchor_target: int | None
    anchor_parent_time: int | None
    rule_commitment: Hash

    def __post_init__(self) -> None:
        if not (_hash(self.block_id) and _u64(self.height) and _u64(self.timestamp)
                and type(self.recent_parent_first) is tuple
                and 1 <= len(self.recent_parent_first) <= 11
                and all(_u64(t) for t in self.recent_parent_first)
                and self.recent_parent_first[0] == self.timestamp
                and _hash(self.rule_commitment)):
            raise ValueError('ASERT_SUMMARY_ENCODING')


def genesis(ctx: Context) -> Summary:
    return Summary(ctx.genesis, 0, ctx.genesis_timestamp,
                   (ctx.genesis_timestamp,), None, None, None, None,
                   ctx.rule_commitment)


def extend(ctx: Context, parent: Summary, header: Header) -> Summary:
    """A one-parent O(11) update after external complete native validation.

    The apparent identity and target correctness asserted here are strictly
    structural. They do NOT replace proof/target validation in a native Node.
    """
    if not (isinstance(parent, Summary) and isinstance(header, Header)
            and parent.rule_commitment == ctx.rule_commitment
            and header.network == ctx.network and header.parameters == ctx.parameters
            and _hash(header.claimed_id) and _hash(header.parent)
            and header.claimed_id != ctx.genesis and header.claimed_id != header.parent
            and header.parent == parent.block_id
            and _u64(header.height) and header.height == parent.height + 1
            and _u64(header.timestamp)
            and type(header.target) is int and 1 <= header.target <= ctx.pow_limit):
        raise ValueError('ASERT_SUMMARY_PARENT_OR_CONTEXT')
    if header.height == ctx.activation_height:
        if parent.anchor_id is not None:
            raise ValueError('ASERT_SUMMARY_EARLY_ANCHOR')
        anchor_id, anchor_parent_id = header.claimed_id, header.parent
        anchor_target = header.target
        anchor_parent_time = (parent.timestamp if ctx.clock == 'raw'
                              else mtp11(parent.recent_parent_first))
    elif header.height > ctx.activation_height:
        if parent.anchor_id is None:
            raise ValueError('ASERT_SUMMARY_ANCHOR_MISSING')
        anchor_id, anchor_parent_id = parent.anchor_id, parent.anchor_parent_id
        anchor_target, anchor_parent_time = parent.anchor_target, parent.anchor_parent_time
    else:
        if parent.anchor_id is not None:
            raise ValueError('ASERT_SUMMARY_PREACTIVATION')
        anchor_id = anchor_parent_id = anchor_target = anchor_parent_time = None
    return Summary(
        header.claimed_id, header.height, header.timestamp,
        (header.timestamp, *parent.recent_parent_first)[:11],
        anchor_id, anchor_parent_id, anchor_target, anchor_parent_time,
        ctx.rule_commitment)


def expected_shadow_target(ctx: Context, parent: Summary) -> int:
    """Shadow target only: MUST NOT feed current native consensus validity."""
    if not isinstance(parent, Summary) or parent.rule_commitment != ctx.rule_commitment:
        raise ValueError('ASERT_SUMMARY_CONTEXT')
    if parent.height < ctx.activation_height or parent.anchor_id is None:
        raise ValueError('ASERT_NOT_ACTIVE')
    if parent.height == UINT64_MAX:
        raise ValueError('ASERT_HEIGHT_OVERFLOW')
    if not (_hash(parent.anchor_parent_id)
            and type(parent.anchor_target) is int and 1 <= parent.anchor_target <= ctx.pow_limit
            and _u64(parent.anchor_parent_time)):
        raise ValueError('ASERT_SUMMARY_ANCHOR_INVALID')
    parent_time = (parent.timestamp if ctx.clock == 'raw'
                   else mtp11(parent.recent_parent_first))
    return asert_target(
        parent.anchor_target, parent.anchor_parent_time, parent_time,
        ctx.activation_height, parent.height + 1, ctx.spacing,
        ctx.half_life, ctx.pow_limit)


class OwnedBranchIndex:
    """Mutable local research index; NEVER admit summary values from untrusted peers."""
    def __init__(self, context: Context):
        self.context = context
        base = genesis(context)
        self._summaries: dict[Hash, Summary] = {base.block_id: base}
        self._observed_ids: set[Hash] = {base.block_id}

    def at(self, block_id: Hash) -> Summary:
        try:
            return self._summaries[block_id]
        except KeyError as exc:
            # Unavailable history is NOT invalid proof or reason for low DAA.
            raise ValueError('ASERT_SUMMARY_UNAVAILABLE') from exc

    def observe_already_validated(self, header: Header) -> Summary:
        """Call only after native owner has authenticated full block semantics."""
        previous = self._summaries.get(header.claimed_id)
        if previous is not None:
            raise ValueError('ASERT_SUMMARY_DUPLICATE')
        current = extend(self.context, self.at(header.parent), header)
        self._summaries[header.claimed_id] = current
        self._observed_ids.add(header.claimed_id)
        return current

    def mark_unavailable(self, block_id: Hash) -> None:
        """Test-only loss injection, not verified pruning or replay."""
        if block_id == self.context.genesis:
            raise ValueError('ASERT_SUMMARY_GENESIS')
        self._summaries.pop(block_id, None)

    def __len__(self) -> int:
        return len(self._summaries)
