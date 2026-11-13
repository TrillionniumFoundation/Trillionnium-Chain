"""Non-activated, synthetic PoN Lease × DAA adversarial *screening* experiment.

The *same* target arithmetic as the existing Python oracle is used. This is NOT
native W1 mining, proof-cost qualification, a network simulation, or a source
authorization certificate. Each simulated miner discovery is assumed to have
paid its declared fixed synthetic work cost; no conclusion about the fastest
legal W1 implementation follows. Outputs are bounded and reproducible.

Important: operators must explicitly select genesis Maintenance; a failed
signed task is NEVER silently converted to Maintenance by this model.
"""
from __future__ import annotations

from dataclasses import dataclass
import argparse
import hashlib
import json
import math
import random
from pathlib import Path

from daa_research_oracle import (
    asert_target, legacy_retarget, mtp11, q4_slot_reclaimable, Lease, valid_time,
)

TARGET_LIMIT = (1 << 255) - 1
INITIAL = TARGET_LIMIT // (1 << 20)
SPACING = 10
N = 16
U64_MAX = (1 << 64) - 1
ALGORITHMS = ("legacy16", "asert_raw", "asert_mtp11")
SCENARIOS = ("steady", "abrupt_hashrate_drop", "oscillating_hashrate", "all_leases_lapse")
HALF_LIVES = (3600, 7200, 14400, 28800)


@dataclass(frozen=True)
class CampaignConfig:
    seed: int
    blocks: int = 192
    half_life: int = 7200
    adversary_nominal_share: float = 0.25
    adversary_work_speedup: float = 1.0
    future_skew: int = 120

    def validate(self) -> None:
        if (isinstance(self.seed, bool) or not isinstance(self.seed, int)
                or not 0 <= self.seed <= U64_MAX or not 32 <= self.blocks <= 4096
                or self.half_life not in HALF_LIVES
                or not 0 <= self.adversary_nominal_share <= 1
                or not 1 <= self.adversary_work_speedup <= 64
                or not 0 <= self.future_skew <= 3600):
            raise ValueError("invalid bounded research input")


def effective_adversary_share(nominal_share: float, speedup: float) -> float:
    if not 0 <= nominal_share <= 1 or not 1 <= speedup <= 64:
        raise ValueError("invalid effective-share assumptions")
    adjusted = nominal_share * speedup
    return adjusted / (1.0 - nominal_share + adjusted)


def stated_total_rate(scenario: str, height: int) -> float:
    """Exogenous assumed nominal mining capacity. No source is being signed."""
    if scenario == "steady":
        return 1.0
    if scenario == "abrupt_hashrate_drop":
        return 1.0 if height <= 64 else 0.20
    if scenario == "oscillating_hashrate":
        return 2.0 if (height // N) % 2 == 0 else 0.40
    if scenario == "all_leases_lapse":
        # Assume only 40% of nominal capacity chooses the explicitly available
        # genesis-maintenance path. Another deployment could have 0% or 100%.
        return 1.0 if height <= 64 else 0.40
    raise ValueError("unknown capacity scenario")


def nominal_work(target: int) -> int:
    return (1 << 256) // (target + 1)


def next_target(algorithm: str, parent_target: int, parent_first_times: list[int],
                candidate_height: int, half_life: int) -> int:
    """Caller-supplied exact candidate-branch timestamps, never peer header target."""
    if algorithm not in ALGORITHMS:
        raise ValueError("unknown DAA")
    if candidate_height < 1 or len(parent_first_times) != candidate_height:
        raise ValueError("incomplete ancestry")
    if algorithm == "legacy16":
        if candidate_height % N != 0:
            return parent_target
        chronological = list(reversed(parent_first_times))
        return legacy_retarget(parent_target, chronological[candidate_height-N],
                               chronological[candidate_height-1], N, SPACING, TARGET_LIMIT)
    if candidate_height == 1:
        return INITIAL
    observed = parent_first_times[0] if algorithm == "asert_raw" else mtp11(parent_first_times)
    # Fixed research anchor = block 1, whose predecessor is the genesis block;
    # authenticated branch derivation is a future P1-C consensus obligation.
    return asert_target(INITIAL, parent_first_times[-1], observed, 1,
                        candidate_height, SPACING, half_life, TARGET_LIMIT)


def simulate(config: CampaignConfig, algorithm: str, scenario: str,
             attacker_timestamp_strategy: str) -> dict:
    config.validate()
    if algorithm not in ALGORITHMS or scenario not in SCENARIOS:
        raise ValueError("invalid scenario")
    if attacker_timestamp_strategy not in ("honest", "endpoint_push", "median_push"):
        raise ValueError("invalid timestamp strategy")
    rng = random.Random(config.seed)
    wall = 0.0
    timestamps = [0]  # genesis
    target = INITIAL
    intervals = []
    retarget_steps = []
    tip_work = 0
    attacker = 0
    deferred = 0
    timewarped = 0
    lease_lapse_blocks = 0
    worst_future_gap = 0
    for height in range(1, config.blocks + 1):
        parent_first = list(reversed(timestamps))
        old_target = target
        target = next_target(algorithm, target, parent_first, height, config.half_life)
        if algorithm == "legacy16" and height % N == 0:
            retarget_steps.append({"h": height, "parent": old_target, "target": target})
        rate = stated_total_rate(scenario, height)
        # Select *effective* share after normalizing the research-only speedup;
        # implementation advantage is not proof of actual adversarial capacity.
        qa = effective_adversary_share(config.adversary_nominal_share,
                                       config.adversary_work_speedup)
        attacker_wins = rng.random() < qa
        if attacker_wins:
            attacker += 1
        # Under a uniform 256-bit ticket model expected block time is inversely
        # proportional to target. The speedup is held fixed across both cohorts.
        effective_total = rate * ((1 - config.adversary_nominal_share)
                                  + config.adversary_nominal_share * config.adversary_work_speedup)
        mean_interval = SPACING * (INITIAL / target) / effective_total
        # Exponential mining waiting time. Avoid inf times; this is bounded
        # research input, not a physical simulation of multi-year chain stalls.
        if not math.isfinite(mean_interval) or mean_interval > 1e12:
            raise ValueError("synthetic mining interval outside configured model")
        uniform = 1.0 - rng.random()
        duration = -math.log(uniform) * mean_interval
        old_wall = wall
        wall += duration
        now = int(wall)
        floor = mtp11(parent_first) + 1
        stamp = max(now, floor)
        if attacker_wins and attacker_timestamp_strategy == "endpoint_push":
            if height % N == N - 1:
                stamp = max(floor, now + config.future_skew)
            elif height % N == 0:
                stamp = floor
        elif attacker_wins and attacker_timestamp_strategy == "median_push":
            # Test frequent low timestamps, not just period-endpoint values.
            stamp = floor
        if stamp > now + config.future_skew:
            # Enforce local future-skew instead of generating an impossible
            # admission pass. This represents a hypothetical waiting cost.
            wall += stamp - (now + config.future_skew)
            now = int(wall)
            deferred += 1
        if not valid_time(stamp, parent_first, now, config.future_skew):
            raise AssertionError("model generated a time-invalid header")
        if stamp != max(now, floor):
            timewarped += 1
        worst_future_gap = max(worst_future_gap, stamp - now)
        timestamps.append(stamp)
        intervals.append(wall - old_wall)
        tip_work += nominal_work(target)
        if scenario == "all_leases_lapse" and height > 64:
            lease_lapse_blocks += 1
    ordered = sorted(intervals)
    assert tip_work > 0
    return {
        "algorithm": algorithm, "scenario": scenario,
        "timestamp_strategy": attacker_timestamp_strategy,
        "seed": config.seed, "blocks": config.blocks,
        "half_life": config.half_life,
        "synthetic_speedup": config.adversary_work_speedup,
        "effective_adversary_share_assumed": round(
            effective_adversary_share(config.adversary_nominal_share,
                                      config.adversary_work_speedup), 8),
        "attacker_discovered_headers": attacker,
        "delayed_for_future_timestamp": deferred,
        "non_honest_timestamp_headers": timewarped,
        "worst_future_clock_gap_seconds": worst_future_gap,
        "assumed_explicit_maintenance_blocks": lease_lapse_blocks,
        "all_simulated_timestamps_passed_MTP_and_skew": True,
        "mean_block_interval_seconds": round(wall / config.blocks, 6),
        "p95_interarrival_seconds": round(ordered[math.ceil(.95 * len(ordered))-1], 6),
        "max_interarrival_seconds": round(ordered[-1], 6),
        "final_target_vs_initial": round(target / INITIAL, 8),
        "required_chainwork": str(tip_work),
        "native_W1_proofs": 0, "real_WAN_operators": 0,
        "claim": "research-only synthetic Poisson/lumped-operator/time-validity model",
    }


def q4_recovery_sequence() -> dict:
    """Exact *time* and retention model; no actual signatures or consensus state."""
    old = Lease(0, 1000, 1100, 1)
    # At h=1001, a Q4 successor cannot be authorized under the old lease.
    # If a different slot is empty, independent requester/source may open a
    # new lease in a maintenance block; if all 32 are retained, wait to 1101.
    assert not q4_slot_reclaimable(old, 1100, "revoked")
    assert q4_slot_reclaimable(old, 1101, "revoked")
    return {
        "all_external_leases_expire_height": 1000,
        "initial_retention_last_height": 1100,
        "earliest_retained_slot_reuse_height": 1101,
        "maintenance_explicit_selection": True,
        "valid_automatic_old_lease_renewal_after_expiry": False,
        "fresh_lease_requires_new_owner_source_signed_open_register": True,
        "source_signatures_generated_by_experiment": 0,
        "native_W1_blocks_produced_by_experiment": 0,
    }


def campaign(seeds: tuple[int, ...] = (0, 1, 20261025),
             heights: int = 192) -> dict:
    if not seeds or any(not 0 <= seed <= U64_MAX for seed in seeds):
        raise ValueError("invalid seeds")
    # Pre-registered small screening grid. This is not statistical evidence of
    # PoN chain quality, independent sampling or timewarp exploit profit.
    runs = []
    for seed in seeds:
        for scenario in SCENARIOS:
            for algorithm in ALGORITHMS:
                for mode in ("honest", "endpoint_push", "median_push"):
                    config = CampaignConfig(seed=seed, blocks=heights)
                    runs.append(simulate(config, algorithm, scenario, mode))
    return {
        "schema": "trnm-lease-daa-fault-screen-v1",
        "source": "independent Python program without Node or W1 implementation",
        "work_source_recovery": q4_recovery_sequence(),
        "run_count": len(runs),
        "seeds": list(seeds), "heights_per_run": heights,
        "assumptions": {
            "nominal_attacker_share": .25,
            "speedup": 1.0,
            "all_leases_lapse_h": 64,
            "lease_lapse_maintenance_participation_fraction": .40,
            "time_skew_seconds": 120,
            "difficulty_half_life_seconds": 7200,
        },
        "runs_sha256": hashlib.sha256(json.dumps(runs, sort_keys=True,
                                              separators=(",", ":")).encode()).hexdigest(),
        "runs": runs,
        "qualification": {
            "new_consensus_activated": False,
            "W1_shortcut_cost_qualified": False,
            "public_attack_safety_qualified": False,
            "independent_operators_qualified": False,
            "full_native_acceptance": False,
        },
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--blocks", type=int, default=192)
    p.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 20261025])
    args = p.parse_args()
    result = campaign(tuple(args.seeds), args.blocks)
    with args.output.open("x", encoding="utf8") as dest:
        json.dump(result, dest, indent=2, sort_keys=True)
        dest.write("\n")
    print(json.dumps({k:result[k] for k in ("schema","run_count","runs_sha256")},sort_keys=True))


if __name__ == "__main__":
    main()
