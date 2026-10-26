"""Research-only event-driven PoN DAA/lease/partition simulator.

IMPORTANT: Mining events are exponentially sampled, not W1 proofs. Each event
assumes a mathematically valid work ticket and costs exactly one abstract work
unit. There is no cryptographic, network, physical-storage or economic security
claim. Consensus and task authority are never modified or delegated here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import heapq
import math
import random
from typing import Literal

from daa_research_oracle import asert_target, legacy_retarget, mtp11, valid_time

Algorithm = Literal['legacy', 'asert_raw', 'asert_mtp']
Mode = Literal['maintenance', 'leased_only']
GENESIS_ID = hashlib.sha256(b'trnm-network-sim-v1/genesis').digest()
INITIAL_TARGET = 1 << 248
POW_LIMIT = (1 << 255) - 1
GENESIS_TIME = 1_800_000_000
WORK_NUMERATOR = 1 << 256


@dataclass(frozen=True)
class Participant:
    name: str
    fraction: float
    mode: Mode = 'maintenance'
    speed: float = 1.0
    timestamp_style: Literal['honest', 'endpoint'] = 'honest'
    withhold_until_lead: int = 0

    def __post_init__(self):
        if not self.name or self.mode not in ('maintenance', 'leased_only'):
            raise ValueError('participant name/mode')
        if not (math.isfinite(self.fraction) and 0 <= self.fraction <= 1 and
                math.isfinite(self.speed) and 0 < self.speed <= 16):
            raise ValueError('participant work budget')
        if self.timestamp_style not in ('honest', 'endpoint') or self.withhold_until_lead not in (0, 2):
            raise ValueError('participant policy')


@dataclass(frozen=True)
class Profile:
    algorithm: Algorithm
    seconds: int = 1000
    seed: int = 1
    expected_spacing: int = 10
    half_life: int = 7200
    base_rate: float = 0.1
    propagation_delay: int = 2
    partition_from: int = 0
    partition_until: int = 0
    external_lease_lost_at: int = 0
    time_offset: int = 0

    def __post_init__(self):
        if self.algorithm not in ('legacy', 'asert_raw', 'asert_mtp'):
            raise ValueError('algorithm')
        if not (1 <= self.seconds <= 20000 and 1 <= self.seed < 2**64 and
                1 <= self.expected_spacing <= 600 and 1 <= self.half_life <= 86400 and
                math.isfinite(self.base_rate) and 0 < self.base_rate <= 10 and
                0 <= self.propagation_delay <= 120 and
                0 <= self.partition_from <= self.partition_until <= self.seconds and
                0 <= self.external_lease_lost_at <= self.seconds and
                -120 <= self.time_offset <= 120):
            raise ValueError('profile bounds')


@dataclass(frozen=True)
class Block:
    identity: bytes
    parent: bytes
    height: int
    target: int
    timestamp: int
    chainwork: int
    miner: str
    kind: str


@dataclass
class View:
    tip: bytes = GENESIS_ID
    seen: set[bytes] = field(default_factory=lambda: {GENESIS_ID})
    reorg_count: int = 0
    reorg_detached: int = 0
    deliveries: int = 0
    missing_ancestors: int = 0


class Campaign:
    """Finite complete-header mathematical simulation; no real proof or sockets."""

    def __init__(self, profile: Profile, participants: tuple[Participant, ...]):
        if not 2 <= len(participants) <= 12:
            raise ValueError('participant count')
        if len({p.name for p in participants}) != len(participants):
            raise ValueError('duplicate actor')
        if not math.isclose(sum(p.fraction for p in participants), 1.0,
                            rel_tol=0, abs_tol=1e-10):
            raise ValueError('fractions')
        self.profile = profile
        self.participants = participants
        self.rng = random.Random(profile.seed)
        self.blocks: dict[bytes, Block] = {
            GENESIS_ID: Block(GENESIS_ID, GENESIS_ID, 0, INITIAL_TARGET,
                              GENESIS_TIME, 0, 'genesis', 'genesis')
        }
        self.views = {p.name: View() for p in participants}
        self.queue: list[tuple[int, int, str, bytes]] = []
        self.serial = 0
        self.accepted = {p.name: 0 for p in participants}
        self.lease_block_count = 0
        self.maintenance_block_count = 0
        self.deferred = 0
        self.rejected = 0
        self.withheld = 0
        self.confirmed_orphaned = 0
        self.time = 0

    def ancestry(self, block_id: bytes) -> list[Block]:
        result = []
        while block_id != GENESIS_ID:
            b = self.blocks[block_id]
            result.append(b)
            block_id = b.parent
        result.append(self.blocks[GENESIS_ID])
        return result

    def expected_target(self, tip: bytes) -> int:
        parent = self.blocks[tip]
        h = parent.height + 1
        if h == 1:
            return INITIAL_TARGET
        if self.profile.algorithm == 'legacy':
            if h % 16:
                return parent.target
            rows = self.ancestry(tip)
            # h-1 and h-16, fifteen actual spacings in a 16-header window.
            first = rows[15].timestamp
            return legacy_retarget(parent.target, first, parent.timestamp, 16,
                                   self.profile.expected_spacing, POW_LIMIT)
        rows = self.ancestry(tip)
        anchor = next((b for b in rows if b.height == 1), None)
        if anchor is None:
            raise AssertionError('missing branch anchor')
        if self.profile.algorithm == 'asert_mtp':
            time = mtp11([b.timestamp for b in rows[:11]])
            before_anchor = mtp11([self.blocks[GENESIS_ID].timestamp])
        else:
            time, before_anchor = parent.timestamp, GENESIS_TIME
        return asert_target(anchor.target, before_anchor, time, 1, h,
                            self.profile.expected_spacing, self.profile.half_life, POW_LIMIT)

    def _timestamp(self, actor: Participant, tip: bytes, when: int) -> int:
        parent = self.blocks[tip]
        median = mtp11([b.timestamp for b in self.ancestry(tip)[:11]])
        true_clock = GENESIS_TIME + when + self.profile.time_offset
        if actor.timestamp_style == 'endpoint':
            # An intentionally artificial legal-clock strategy. Its ability to mine
            # the block and its profitability are NOT assumed or proved.
            stamp = (true_clock + 120 if (parent.height + 2) % 16 == 0
                     else median + 1)
        else:
            stamp = max(true_clock, median + 1)
        return stamp

    def _partitioned(self, a: str, b: str, when: int) -> bool:
        p = self.profile
        if not (p.partition_from <= when < p.partition_until):
            return False
        # One fixed bipartition for reproducibility, not a Sybil/eclipse model.
        midpoint = (len(self.participants) + 1) // 2
        left = {x.name for x in self.participants[:midpoint]}
        return (a in left) != (b in left)

    def _schedule(self, when: int, recipient: str, block_id: bytes):
        self.serial += 1
        heapq.heappush(self.queue, (when, self.serial, recipient, block_id))

    def _deliver(self, recipient: str, block_id: bytes, when: int):
        view = self.views[recipient]
        if block_id in view.seen:
            return
        rows = list(reversed(self.ancestry(block_id)))
        # This is an explicit perfect-history-availability approximation: real
        # networks must pay for and validate each missing ancestor separately.
        missed = sum(b.identity not in view.seen for b in rows[1:])
        view.missing_ancestors += max(0, missed - 1)
        for b in rows[1:]:
            if not valid_time(b.timestamp,
                              [x.timestamp for x in self.ancestry(b.parent)[:11]],
                              GENESIS_TIME + when, 120):
                self.deferred += 1
                return
        for b in rows[1:]:
            view.seen.add(b.identity)
        view.deliveries += 1
        selected = self.blocks[view.tip]
        challenger = self.blocks[block_id]
        if challenger.chainwork > selected.chainwork:
            if not self._extends(block_id, view.tip):
                view.reorg_count += 1
                view.reorg_detached += self._detached_length(view.tip, block_id)
            view.tip = block_id

    def _extends(self, tip: bytes, predecessor: bytes) -> bool:
        while tip != GENESIS_ID:
            if tip == predecessor:
                return True
            tip = self.blocks[tip].parent
        return predecessor == GENESIS_ID

    def _detached_length(self, original: bytes, challenger: bytes) -> int:
        other = {b.identity for b in self.ancestry(challenger)}
        return sum(1 for b in self.ancestry(original)
                   if b.identity not in other)

    def _transmit(self, actor: Participant, block_id: bytes, when: int):
        for p in self.participants:
            if p.name == actor.name or self._partitioned(actor.name, p.name, when):
                continue
            self._schedule(when + self.profile.propagation_delay, p.name, block_id)

    def _mine(self, actor: Participant, when: int):
        if (actor.mode == 'leased_only' and self.profile.external_lease_lost_at
                and when >= self.profile.external_lease_lost_at):
            return
        parent_id = self.views[actor.name].tip
        target = self.expected_target(parent_id)
        # Abstract Poisson process. A real W1 proof is NOT computed here.
        rate = self.profile.base_rate * actor.fraction * actor.speed * target / INITIAL_TARGET
        if self.rng.random() >= -math.expm1(-rate):
            return
        timestamp = self._timestamp(actor, parent_id, when)
        ancestors = [x.timestamp for x in self.ancestry(parent_id)[:11]]
        if not valid_time(timestamp, ancestors, GENESIS_TIME + when, 120):
            self.deferred += 1
            return
        height = self.blocks[parent_id].height + 1
        work = WORK_NUMERATOR // (target + 1)
        body = (parent_id + actor.name.encode() + height.to_bytes(8, 'big') +
                self.serial.to_bytes(8, 'big') + when.to_bytes(8, 'big') +
                len(self.blocks).to_bytes(8, 'big'))
        ident = hashlib.sha256(body).digest()
        kind = actor.mode
        block = Block(ident, parent_id, height, target, timestamp,
                      self.blocks[parent_id].chainwork + work, actor.name, kind)
        self.blocks[ident] = block
        view = self.views[actor.name]
        view.seen.add(ident)
        view.tip = ident
        self.accepted[actor.name] += 1
        if kind == 'maintenance':
            self.maintenance_block_count += 1
        else:
            self.lease_block_count += 1
        if actor.withhold_until_lead:
            other_best = max((self.blocks[v.tip].height for name,v in self.views.items()
                              if name != actor.name), default=0)
            if height - other_best < actor.withhold_until_lead:
                self.withheld += 1
                return
        self._transmit(actor, ident, when)

    def run(self) -> dict:
        p = self.profile
        for second in range(1, p.seconds + 1):
            self.time = second
            while self.queue and self.queue[0][0] <= second:
                _, _, recipient, block_id = heapq.heappop(self.queue)
                self._deliver(recipient, block_id, second)
            if second == p.partition_until:
                # Restart repair after partition: model complete history retrieval,
                # including orphan ancestors; nothing has been finalized.
                for actor in self.participants:
                    for other in self.participants:
                        if actor.name != other.name:
                            self._schedule(second + p.propagation_delay, other.name,
                                           self.views[actor.name].tip)
            for actor in self.participants:
                self._mine(actor, second)
        # No further mining during bounded propagation drain; do not grant more
        # clock/work or change the original event identities.
        for tail in range(p.seconds + 1, p.seconds + p.propagation_delay + 2):
            while self.queue and self.queue[0][0] <= tail:
                _, _, recipient, block_id = heapq.heappop(self.queue)
                self._deliver(recipient, block_id, tail)
        tips = {name: self.blocks[v.tip] for name,v in self.views.items()}
        # Confirmation is purely mathematical and is NOT a native membership
        # proof. Count only blocks on the local active chain with >=6 depth and
        # >=6 times their own required expected work.
        confirmed = {}
        for name,view in self.views.items():
            tip = self.blocks[view.tip]
            confirmed[name] = sum(1 for b in self.ancestry(view.tip)[1:]
                if tip.height - b.height >= 6 and tip.chainwork - b.chainwork >=
                   6 * (WORK_NUMERATOR // (b.target + 1)))
        return {
            'schema': 'pon-daa-lease-network-mathematical-simulation-v1',
            'not_native_w1': True, 'not_independent_operators': True,
            'perfect_history_fetch_assumption': True,
            'not_timestamp_attack_profitability': True,
            'profile': vars(p),
            'participants': [vars(x) for x in self.participants],
            'created_headers': len(self.blocks) - 1,
            'synthetic_maintenance_headers': self.maintenance_block_count,
            'synthetic_leased_headers': self.lease_block_count,
            'by_miner': dict(self.accepted),
            'tips': {name: {'height': b.height, 'chainwork': str(b.chainwork),
                             'id': b.identity.hex()} for name,b in tips.items()},
            'confirmed_abstract': confirmed,
            'reorgs': {name: v.reorg_count for name,v in self.views.items()},
            'detached_blocks': {name: v.reorg_detached for name,v in self.views.items()},
            'missing_ancestor_fetches_idealized': {name: v.missing_ancestors
                                                     for name,v in self.views.items()},
            'deferred_time_observations': self.deferred,
            'withheld_headers': self.withheld,
            'all_views_agree': len({v.tip for v in self.views.values()}) == 1,
        }


def fixed_campaign() -> list[dict]:
    """Same seeded budget envelope across the three unactivated DAA candidates."""
    out = []
    for algorithm in ('legacy', 'asert_raw', 'asert_mtp'):
        for scenario, kwargs in (
            ('steady', {}),
            ('partition', {'partition_from': 150, 'partition_until': 350}),
            ('lease_loss', {'external_lease_lost_at': 250}),
            ('specialized_miner', {}),
            ('timestamp_endpoint', {}),
            ('withholding', {}),
        ):
            actors = (
                Participant('miner_a', .55, mode='maintenance'),
                Participant('miner_b', .45, mode='leased_only'
                            if scenario == 'lease_loss' else 'maintenance',
                            speed=1.7 if scenario == 'specialized_miner' else 1.0,
                            timestamp_style='endpoint' if scenario == 'timestamp_endpoint' else 'honest',
                            withhold_until_lead=2 if scenario == 'withholding' else 0),
            )
            profile = Profile(algorithm, seconds=600, seed=41, **kwargs)
            report = Campaign(profile, actors).run()
            report['scenario'] = scenario
            out.append(report)
    return out


if __name__ == '__main__':
    import json
    print(json.dumps(fixed_campaign(), sort_keys=True, indent=2))