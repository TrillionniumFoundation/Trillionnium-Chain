"""Research-only joint PoN DAA, task-source-outage and fork-choice screen.

There is NO neural-work miner, signature, real network, ledger or independent
operator in this program. Every discovered block is a *simulated valid ticket*;
Poisson clocks assume equal marginal work cost across miner groups. Recompute
work and timestamps branch-locally instead of awarding height or score weight.
No results are security acceptance, finality or a bound on attacker resources.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from dataclasses import asdict, dataclass
from pathlib import Path

from daa_research_oracle import asert_target, legacy_retarget, mtp11, valid_time
from daa_confirmation_risk import fork_risk

SPACING = 10
INITIAL = ((1 << 255) - 1) // 4096
POW_LIMIT = (1 << 255) - 1
ALGORITHMS = ("legacy16", "asert_raw", "asert_mtp11")
TIMESTAMP_POLICIES = ("honest", "mtp_min", "endpoint_push")


def required_work(target: int) -> int:
    if not 1 <= target <= POW_LIMIT:
        raise ValueError("invalid research target")
    return (1 << 256) // (target + 1)


@dataclass(frozen=True)
class Parameters:
    seed: int = 20261025
    algorithm: str = "legacy16"
    half_life: int = 7200
    warmup_blocks: int = 24
    split_blocks: int = 64
    followup_blocks: int = 24
    share_a: float = 0.65
    # Absolute global discovery count: source loss is exogenous, not signed.
    task_outage_at: int = 40
    a_maintenance_fraction: float = 0.35
    b_maintenance_fraction: float = 0.80
    genesis_time: int = 1_000_000
    timestamp_policy_a: str = "honest"
    timestamp_policy_b: str = "endpoint_push"
    max_clock_seconds: int = 100_000

    def validate(self) -> None:
        if (self.algorithm not in ALGORITHMS or self.half_life not in
                (3600, 7200, 14400, 28800) or self.seed < 0
                or self.warmup_blocks < 1 or self.split_blocks < 2
                or self.followup_blocks < 1 or self.warmup_blocks +
                self.split_blocks + self.followup_blocks > 1000
                or not 0 < self.share_a < 1 or not 0 <= self.a_maintenance_fraction <= 1
                or not 0 <= self.b_maintenance_fraction <= 1
                or not 0 <= self.task_outage_at <= 1000
                or self.timestamp_policy_a not in TIMESTAMP_POLICIES
                or self.timestamp_policy_b not in TIMESTAMP_POLICIES
                or not 100 <= self.max_clock_seconds <= 1_000_000
                or self.genesis_time <= 0):
            raise ValueError("invalid frozen simulation parameters")


@dataclass(frozen=True)
class Header:
    key: int  # Simulation-local ID, NOT an authenticated PoN BlockId.
    parent: int | None
    height: int
    timestamp: int
    target: int
    chainwork: int
    miner: str
    found_wall: float


class ForkSimulator:
    def __init__(self, parameters: Parameters):
        parameters.validate()
        self.p = parameters
        self.rng = random.Random(parameters.seed)
        self.blocks: dict[int, Header] = {
            0: Header(0, None, 0, parameters.genesis_time, INITIAL, 0,
                      "genesis", float(parameters.genesis_time))
        }
        self.tip_a = self.tip_b = 0
        self.next_id = 1
        self.found = 0
        self.wall = float(parameters.genesis_time)
        self.stale_time_attempts = 0
        self.healed = False
        self.reorg_removed = 0
        self.reorg_confirmed_depth6 = 0
        self.reorg_policy_confirmed = 0
        self.work_at_heal_a = self.work_at_heal_b = 0
        self.heal_preferred = "none"
        self.stopped = False
        self.stop_reason: str | None = None

    def ancestry(self, tip: int) -> list[Header]:
        result = []
        cursor: int | None = tip
        while cursor is not None:
            row = self.blocks[cursor]
            result.append(row)
            cursor = row.parent
        return result

    def next_target(self, tip: int) -> int:
        ancestors = self.ancestry(tip)
        parent = ancestors[0]
        height = parent.height + 1
        if height == 1:
            return INITIAL
        if self.p.algorithm == "legacy16":
            if height % 16:
                return parent.target
            if len(ancestors) <= 15:
                raise AssertionError("retarget window absent")
            return legacy_retarget(parent.target, ancestors[15].timestamp,
                                   parent.timestamp, 16, SPACING, POW_LIMIT)
        clock = parent.timestamp if self.p.algorithm == "asert_raw" else mtp11(
            [header.timestamp for header in ancestors[:11]])
        return asert_target(INITIAL, self.p.genesis_time, clock, 1, height,
                            SPACING, self.p.half_life, POW_LIMIT)

    def fraction(self, miner: str) -> float:
        base = self.p.share_a if miner == "A" else 1.0 - self.p.share_a
        if self.found < self.p.task_outage_at:
            return base
        retained = self.p.a_maintenance_fraction if miner == "A" else self.p.b_maintenance_fraction
        return base * retained

    def rate(self, miner: str, tip: int) -> float:
        # This assumption deliberately does NOT model fastest legal W1 cost or GPU.
        return self.fraction(miner) * (self.next_target(tip) / INITIAL) / SPACING

    def mine(self, miner: str, tip: int) -> int | None:
        parent = self.blocks[tip]
        height = parent.height + 1
        ancestors = self.ancestry(tip)
        past = [b.timestamp for b in ancestors[:11]]
        median = mtp11(past)
        policy = self.p.timestamp_policy_a if miner == "A" else self.p.timestamp_policy_b
        if policy == "honest":
            stamp = max(int(self.wall), median + 1)
        elif policy == "mtp_min":
            stamp = median + 1
        else:
            stamp = int(self.wall) + 120 if height % 16 == 15 else median + 1
        if not valid_time(stamp, past, int(self.wall), 120):
            self.stale_time_attempts += 1
            return None
        target = self.next_target(tip)
        work = required_work(target)
        key = self.next_id
        self.next_id += 1
        self.blocks[key] = Header(key, tip, height, stamp, target,
                                  parent.chainwork + work, miner, self.wall)
        self.found += 1
        return key

    def round(self, phase: str) -> bool:
        if phase == "shared" or phase == "healed":
            tip_a = tip_b = self.tip_a
        else:
            tip_a, tip_b = self.tip_a, self.tip_b
        ra, rb = self.rate("A", tip_a), self.rate("B", tip_b)
        total = ra + rb
        if total <= 0:
            self.stopped = True
            self.stop_reason = "no_assumed_work_capacity"
            return False
        self.wall += self.rng.expovariate(total)
        if self.wall - self.p.genesis_time > self.p.max_clock_seconds:
            self.stopped = True
            self.stop_reason = "bounded_wall_window_exhausted"
            return False
        miner = "A" if self.rng.random() * total < ra else "B"
        next_tip = self.mine(miner, tip_a if miner == "A" else tip_b)
        if next_tip is not None:
            if phase in ("shared", "healed"):
                self.tip_a = self.tip_b = next_tip
            elif miner == "A":
                self.tip_a = next_tip
            else:
                self.tip_b = next_tip
        return True

    def heal(self) -> None:
        self.work_at_heal_a = self.blocks[self.tip_a].chainwork
        self.work_at_heal_b = self.blocks[self.tip_b].chainwork
        if self.work_at_heal_a >= self.work_at_heal_b:
            winner, loser = self.tip_a, self.tip_b
            self.heal_preferred = "A"
        else:
            winner, loser = self.tip_b, self.tip_a
            self.heal_preferred = "B"
        ancestors = {x.key for x in self.ancestry(winner)}
        old_path = self.ancestry(loser)
        orphaned = [x for x in old_path if x.key not in ancestors]
        self.reorg_removed = len(orphaned)
        losing_tip = self.blocks[loser]
        self.reorg_confirmed_depth6 = sum(
            1 for x in orphaned if losing_tip.height - x.height >= 6)
        # The installed client requires BOTH depth and added branch work.
        # This is an assumed-valid *simulation* graph, never native Node
        # authority or a verified transaction membership receipt.
        risk = fork_risk(self.blocks, winner, loser, depth=6, multiplier=6,
                         max_reads=4096)
        if (risk.depth_only_removed != self.reorg_confirmed_depth6
                or risk.losing_blocks != self.reorg_removed):
            raise AssertionError("synthetic orphan risk accounting mismatch")
        self.reorg_policy_confirmed = risk.depth_and_work_confirmed_removed
        self.tip_a = self.tip_b = winner
        self.healed = True

    def verify_all(self) -> None:
        # Recompute branch-local state, not just the winning chain summary.
        for key in range(1, self.next_id):
            block = self.blocks[key]
            assert block.parent is not None
            parent = self.blocks[block.parent]
            assert block.height == parent.height + 1
            assert block.chainwork == parent.chainwork + required_work(block.target)
            assert block.timestamp <= int(block.found_wall) + 120
            assert block.timestamp > mtp11(
                [x.timestamp for x in self.ancestry(block.parent)[:11]])
            assert block.target == self.next_target(block.parent)
        if self.healed:
            assert self.tip_a == self.tip_b
            assert self.blocks[self.tip_a].chainwork >= min(
                self.work_at_heal_a, self.work_at_heal_b)

    def report(self) -> dict:
        self.verify_all()
        path = self.ancestry(self.tip_a)
        effective = (self.found >= self.p.task_outage_at)
        a_work = sum(required_work(h.target) for h in path if h.miner == "A")
        b_work = sum(required_work(h.target) for h in path if h.miner == "B")
        result = {
            "assumptions": asdict(self.p),
            "simulated_blocks_produced": self.next_id - 1,
            "simulated_events": self.found + self.stale_time_attempts,
            "tip_height": self.blocks[self.tip_a].height,
            "final_required_work": str(self.blocks[self.tip_a].chainwork),
            "winning_a_required_work": str(a_work),
            "winning_b_required_work": str(b_work),
            "lease_outage_reached": effective,
            "partition_healed": self.healed,
            "partition_heal_preferred": self.heal_preferred,
            "partition_a_chainwork": str(self.work_at_heal_a),
            "partition_b_chainwork": str(self.work_at_heal_b),
            "losing_branch_blocks_removed": self.reorg_removed,
            "losing_branch_depth6_blocks_removed": self.reorg_confirmed_depth6,
            "losing_branch_depth_work_confirmed_removed": self.reorg_policy_confirmed,
            "timestamp_unavailable_attempts": self.stale_time_attempts,
            "terminal_stopped": self.stopped,
            "stop_reason": self.stop_reason,
            "wall_elapsed_seconds": round(self.wall - self.p.genesis_time, 4),
            "final_target_ratio": round(self.next_target(self.tip_a) / INITIAL, 8),
            "actual_w1_proofs": 0,
            "real_network_transmissions": 0,
            "independently_operated_nodes": 0,
            "consensus_activated": False,
            "claim": "synthetic fork choice and timestamp screening, not PoN security validation",
        }
        return result


def simulate(p: Parameters = Parameters()) -> dict:
    s = ForkSimulator(p)
    for _ in range(p.warmup_blocks):
        if not s.round("shared"):
            return s.report()
    for _ in range(p.split_blocks):
        if not s.round("partition"):
            return s.report()
    s.heal()
    for _ in range(p.followup_blocks):
        if not s.round("healed"):
            return s.report()
    return s.report()


def campaign() -> dict:
    cases = []
    for seed in (0, 1, 20261025):
        for algo in ALGORITHMS:
            for half in (3600, 7200, 14400, 28800):
                for mode in ("honest", "endpoint_push"):
                    p = Parameters(seed=seed, algorithm=algo, half_life=half,
                                   timestamp_policy_b=mode)
                    cases.append(simulate(p))
    body = json.dumps(cases, sort_keys=True, separators=(",", ":"))
    return {"schema": "pon-daa-fork-outage-screen-v1", "cases": len(cases),
            "cases_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "rows": cases, "qualification": {"native_w1": False,
                                             "independent_operator": False,
                                             "production_daa": False}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    ns = parser.parse_args()
    result = campaign()
    with ns.output.open("x", encoding="utf8") as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write("\n")
    print(json.dumps({key: result[key] for key in ("schema", "cases", "cases_sha256")}, sort_keys=True))


if __name__ == "__main__":
    main()
