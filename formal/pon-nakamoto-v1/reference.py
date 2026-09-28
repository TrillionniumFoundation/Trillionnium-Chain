"""Arithmetic and state examples only: NO cryptographic work proof or miner.

All validity/availability inputs are abstract test premises, never production
capabilities. This file cannot be used for consensus admission or activation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from copy import deepcopy
from typing import Sequence


def work(target: int, bits: int = 256) -> int:
    if type(bits) is not int or bits < 2 or type(target) is not int or not 1 <= target < (1 << bits):
        raise ValueError('invalid target/width')
    return (1 << bits) // (target + 1)


def retarget(parent_target: int, first_time: int, last_time: int, interval: int,
             spacing: int, pow_limit: int) -> int:
    values = (parent_target, first_time, last_time, interval, spacing, pow_limit)
    if any(type(v) is not int for v in values) or interval < 16 or spacing < 1:
        raise ValueError('invalid parameters')
    if not 1 <= parent_target <= pow_limit < (1 << 256) or min(first_time, last_time) < 0:
        raise ValueError('invalid target/time')
    desired = (interval - 1) * spacing
    observed = max(1, last_time - first_time)
    bounded = min(4 * desired, max((desired + 3) // 4, observed))
    return min(pow_limit, max(1, parent_target * bounded // desired))


def timestamp_state(candidate: int, ancestors: Sequence[int], now: int, future_skew: int) -> str:
    if any(type(v) is not int or v < 0 for v in [candidate, now, future_skew, *ancestors]):
        raise ValueError('invalid timestamp')
    recent = sorted(ancestors[-11:])
    if recent and candidate <= recent[len(recent) // 2]:
        return 'invalid-median'
    return 'deferred-future' if candidate > now + future_skew else 'admissible'


@dataclass(frozen=True)
class Branch:
    name: str
    targets: tuple[int, ...]
    abstract_valid: bool = True
    abstract_available: bool = True

    @property
    def chainwork(self) -> int:
        return sum(work(t) for t in self.targets)


def preferred(current: Branch | None, candidates: Sequence[Branch]) -> Branch | None:
    best = current
    if best is not None and not (best.abstract_valid and best.abstract_available):
        raise ValueError('active tip must be fully validated')
    for candidate in candidates:
        if not (candidate.abstract_valid and candidate.abstract_available):
            continue
        if best is None or candidate.chainwork > best.chainwork:
            best = candidate
    return best


def allocate(pool: int, scores: Sequence[int], credible_gain: bool) -> tuple[list[int], int]:
    if type(pool) is not int or pool < 0 or any(type(v) is not int or v < 0 for v in scores):
        raise ValueError('invalid money/score')
    total = sum(scores)
    if not credible_gain or total == 0:
        return [0] * len(scores), pool
    payouts = [pool * score // total for score in scores]
    return payouts, pool - sum(payouts)


@dataclass
class ChainState:
    balances: dict[str, int] = field(default_factory=dict)
    nonces: dict[str, int] = field(default_factory=dict)
    release: str = 'base'
    claims: set[str] = field(default_factory=set)


@dataclass
class LocalEffects:
    entered: set[str] = field(default_factory=set)
    revoked: set[str] = field(default_factory=set)

    def enter(self, operation: str) -> None:
        if operation in self.entered or operation in self.revoked:
            raise ValueError('query/reconcile only; no blind replay')
        self.entered.add(operation)


class ReorgExample:
    """Abstract atomic-publication example; not filesystem/crash durability proof."""
    def __init__(self, state: ChainState):
        self.visible = deepcopy(state)
        self.pending: ChainState | None = None
        self.generation = 0

    def stage(self, next_state: ChainState) -> None:
        if self.pending is not None:
            raise ValueError('one reorg owner')
        self.pending = deepcopy(next_state)

    def publish(self) -> None:
        if self.pending is None:
            raise ValueError('missing exact intent')
        self.visible = self.pending
        self.pending = None
        self.generation += 1

    def recover(self) -> None:
        if self.pending is not None:
            self.publish()


def claim(state: ChainState, root_component: str, beneficiary: str, amount: int, budget: int) -> int:
    if type(amount) is not int or type(budget) is not int or amount < 0 or amount > budget:
        raise ValueError('unfunded allocation')
    if root_component in state.claims:
        raise ValueError('duplicate contribution component')
    state.claims.add(root_component)
    state.balances[beneficiary] = state.balances.get(beneficiary, 0) + amount
    return budget - amount
