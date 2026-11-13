"""Research-only sensitivity to faster *valid* W1 proofs after task-source loss.

The installed PoN proof/target/chainwork code is unchanged. This experiment
changes only an assumed miner's Poisson *discovery rate* (cost per legal proof),
not the consensus work assigned to any successfully validated header.
It extends the existing fork-local simulation and is NOT public security proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

from daa_fork_outage_research import ForkSimulator, Parameters

FROZEN_SPEED_FACTORS = (1.0, 1.5, 3.0, 8.0)
FROZEN_SEEDS = (0, 1, 20261025)
FROZEN_ALGORITHMS = ("legacy16", "asert_raw", "asert_mtp11")


def valid_speedup(s: float) -> float:
    if isinstance(s, bool) or not isinstance(s, (int, float)):
        raise ValueError("legal-producer-speedup type")
    speed = float(s)
    if not math.isfinite(speed) or not 1.0 <= speed <= 64.0:
        raise ValueError("legal-producer-speedup bounds")
    return speed


def effective_share(a_capacity: float, b_capacity: float,
                    faster_b: float) -> float | None:
    """Expected B share of valid tickets, not a chain-quality guarantee."""
    speed = valid_speedup(faster_b)
    if (not all(math.isfinite(z) for z in (a_capacity, b_capacity))
            or a_capacity < 0 or b_capacity < 0):
        raise ValueError("capacity bounds")
    weighted_b = b_capacity * speed
    total = a_capacity + weighted_b
    return weighted_b / total if total > 0 else None


class CostAwareForkSimulator(ForkSimulator):
    """Same state machine; only B's legal proof production cost is changed."""
    def __init__(self, p: Parameters, speedup_b: float):
        self.legal_prover_speedup_b = valid_speedup(speedup_b)
        super().__init__(p)

    def rate(self, miner: str, tip: int) -> float:
        original_rate = super().rate(miner, tip)
        return original_rate * (self.legal_prover_speedup_b if miner == "B" else 1.0)


def run(p: Parameters, speedup_b: float) -> dict:
    speedup_b = valid_speedup(speedup_b)
    sim = CostAwareForkSimulator(p, speedup_b)
    for _ in range(p.warmup_blocks):
        if not sim.round("shared"):
            break
    else:
        for _ in range(p.split_blocks):
            if not sim.round("partition"):
                break
        else:
            sim.heal()
            for _ in range(p.followup_blocks):
                if not sim.round("healed"):
                    break
    # The parent method checks fork-local ancestry, target and cumulative work.
    report = sim.report()
    base_a, base_b = p.share_a, 1 - p.share_a
    post_a = base_a * p.a_maintenance_fraction
    post_b = base_b * p.b_maintenance_fraction
    return {**report,
            "cost_sensitivity": {
                "schema": "pon-valid-w1-cost-after-source-outage-v1",
                "legal_prover_speedup_b": speedup_b,
                "pre_outage_effective_b_share": effective_share(base_a, base_b, speedup_b),
                "post_outage_effective_b_share": effective_share(post_a, post_b, speedup_b),
                "simulated_pre_outage_a_capacity": base_a,
                "simulated_pre_outage_b_capacity": base_b,
                "simulated_post_outage_a_capacity": post_a,
                "simulated_post_outage_b_capacity": post_b,
                "counts_faster_miner_as_extra_chainwork": False,
                "actual_proofs": 0,
                "operator_evidence": False,
                "security_conclusion": "none; assumption sensitivity only",
            }}


def campaign() -> dict:
    rows = []
    for seed in FROZEN_SEEDS:
        for algorithm in FROZEN_ALGORITHMS:
            for timestamp_policy_b in ("honest", "endpoint_push"):
                for speed in FROZEN_SPEED_FACTORS:
                    p = Parameters(seed=seed, algorithm=algorithm,
                                   timestamp_policy_b=timestamp_policy_b)
                    rows.append(run(p, speed))
    raw = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    return {"schema": "pon-daa-legal-cost-sensitivity-v1",
            "cases": len(rows),
            "cases_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "rows": rows,
            "qualification": {"real_w1": False, "wan": False,
                              "independent_operators": False,
                              "fastest_prover": False,
                              "production_consensus": False}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    ns = parser.parse_args()
    result = campaign()
    with ns.output.open("x", encoding="utf-8") as file:
        json.dump(result, file, indent=2, sort_keys=True)
        file.write("\n")
    print(json.dumps({"schema": result["schema"], "cases": result["cases"],
                      "cases_sha256": result["cases_sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
