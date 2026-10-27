"""Non-consensus Monte Carlo input generator for lease-loss/DAA comparison.

Run with Python stdlib only. This uses deterministic synthetic arrival draws,
NOT mined W1 blocks, SHA-256 lottery tickets or permissionless attack proof.
The same draw at each height is reused for each DAA arm (paired experiments).
"""
from __future__ import annotations

from fractions import Fraction
import hashlib
import json
import math

from daa_research_v1 import (
    asert_target, check_header_time, effective_work_share,
    legacy_target, median11,
)

ANCHOR_TARGET = 1 << 128
POW_LIMIT = (1 << 255) - 1
SPACING = 10
BLOCKS = 256


def deterministic_draw(seed: int, height: int) -> float:
    if not 0 <= seed <= (1 << 32) - 1 or not 0 <= height <= 100000:
        raise ValueError("seed/height")
    msg = b"TRNM-DAA-ARRIVAL-RESEARCH\0" + seed.to_bytes(4, "big") + height.to_bytes(4, "big")
    num = int.from_bytes(hashlib.sha256(msg).digest()[:8], "big")
    return (num + 0.5) / (1 << 64)


def rate_for(case: str, height: int) -> Fraction:
    if case in ("honest", "lease-loss"):
        return Fraction(1)
    if case == "oscillation":
        return (Fraction(4), Fraction(1, 4), Fraction(1), Fraction(2))[
            ((height - 1) // 32) % 4
        ]
    if case == "sudden-loss":
        return Fraction(1, 8) if 65 <= height < 193 else Fraction(1)
    if case == "partition":
        return Fraction(1, 2) if 65 <= height < 97 else Fraction(1)
    raise ValueError("scenario")


def one_arm(case: str, daa: str, half_life: int, seed: int) -> dict[str, object]:
    if daa not in ("legacy16", "asert-raw", "asert-mtp"):
        raise ValueError("daa")
    history = [0]
    target = ANCHOR_TARGET
    wall = 0
    gaps = []
    time_checks = []
    maintenance_blocks = 0
    no_external_lease_blocks = 0
    work = 0
    for height in range(1, BLOCKS + 1):
        if daa == "legacy16" and height % 16 == 0:
            target = legacy_target(
                target, history[height - 16], history[height - 1],
                pow_limit=POW_LIMIT,
            )
        if daa.startswith("asert") and height >= 2:
            parent_time = history[-1] if daa == "asert-raw" else median11(
                list(reversed(history[-11:]))
            )
            target = asert_target(
                ANCHOR_TARGET, anchor_height=1, anchor_parent_time=0,
                parent_height=height - 1, parent_time=parent_time,
                spacing=SPACING, half_life=half_life, pow_limit=POW_LIMIT,
            )
        hashrate = rate_for(case, height)
        # Synthetic exponential interarrival time. This is floating-point
        # *measurement modelling* only, NEVER target or timestamp consensus.
        expected_seconds = SPACING * (ANCHOR_TARGET / target) / float(hashrate)
        gap = max(1, math.ceil(-math.log(deterministic_draw(seed, height)) * expected_seconds))
        if gap > 100000:
            raise ValueError("unmodelled long stall: censor this cohort")
        wall += gap
        # Honest miners use their present simulated wall time (or minimum
        # MTP+1 if the synthetic clock has not caught up). This may expose a
        # deferred observation; do not silently reclassify it as valid.
        ancestor = list(reversed(history[-11:]))
        timestamp = max(wall, median11(ancestor) + 1)
        verdict = check_header_time(timestamp, ancestor, wall)
        time_checks.append(verdict)
        if verdict != "valid":
            raise ValueError("synthetic clock cannot admit next header")
        history.append(timestamp)
        gaps.append(gap)
        work += (1 << 256) // (target + 1)
        if case == "lease-loss" and height >= 65:
            no_external_lease_blocks += 1
            maintenance_blocks += 1
    ordered = sorted(gaps)
    return {
        "case": case,
        "daa": daa,
        "half_life_seconds": half_life if daa != "legacy16" else None,
        "seed": seed,
        "blocks": BLOCKS,
        "synthetic_wall_seconds": wall,
        "gap_p50_seconds": ordered[len(ordered) // 2],
        "gap_p95_seconds": ordered[math.ceil(len(ordered) * .95) - 1],
        "largest_gap_seconds": max(gaps),
        "target_hex": f"{target:064x}",
        "cumulative_required_work_hex": f"{work:x}",
        "valid_time_checks": time_checks.count("valid"),
        "deferred_time_checks": time_checks.count("deferred"),
        "maintenance_blocks_without_external_lease": maintenance_blocks,
        "missing_external_lease_blocks": no_external_lease_blocks,
        "consensus_activation": False,
    }


def full_campaign(seed: int = 20261027) -> dict[str, object]:
    cases = ("honest", "oscillation", "sudden-loss", "lease-loss", "partition")
    arms = []
    for case in cases:
        for daa in ("legacy16", "asert-raw", "asert-mtp"):
            for half_life in ((7200, 14400, 28800) if daa != "legacy16" else (0,)):
                arms.append(one_arm(case, daa, half_life, seed))
    q = effective_work_share(Fraction(3, 10), Fraction(3))
    return {
        "schema": "pon-daa-lease-adversarial-campaign-v1",
        "source": "deterministic synthetic SHA-256 arrival draws; no W1 mining",
        "network": "none",
        "real_wan": False,
        "real_task_signatures": False,
        "selfish_mining_proof": False,
        "partition_finality_proof": False,
        "work_hardness_accepted": False,
        "production_eligible": False,
        "rate_model": "declared block-indexed relative hashrate; no honest/attacker control inferred",
        "same_seed_paired_arms": True,
        "seed": seed,
        "results": arms,
        "legal_strategy_sensitivity": {
            "hypothetical_resource_fraction": "3/10",
            "hypothetical_legal_speedup": "3/1",
            "conditional_effective_work_share": str(q),
            "attacker_owns_majority_proven": False,
        },
        "unmodelled": [
            "task provenance", "real W1 attempt time", "network delay",
            "selfish-mining branching", "true partition recovery", "clock drift",
            "independent operators", "profitable attack strategies",
        ],
    }


if __name__ == "__main__":
    import sys
    seed = int(sys.argv[1]) if len(sys.argv) == 2 else 20261027
    print(json.dumps(full_campaign(seed), indent=2, sort_keys=True))
