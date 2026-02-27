#!/usr/bin/env python3
"""
Tokenomics v2 Monte Carlo simulator (draft).

Usage:
  python3 scripts/v2/tokenomics_v2_sim.py --rounds 5000 --seed 42
"""

from __future__ import annotations

import argparse
import random
import statistics
from dataclasses import dataclass


@dataclass
class Params:
    alpha: float = 0.70  # worker share multiplier
    beta: float = 0.15   # verifier share
    gamma: float = 0.10  # treasury share
    delta: float = 0.05  # burn share

    s_base: float = 50_000.0
    s_task_min: float = 500.0
    s_task_max: float = 20_000.0

    k1: float = 0.10
    k2: float = 400.0
    k3: float = 6_000.0
    k4: float = 3_000.0

    challenge_reward_lambda: float = 0.20
    challenge_treasury_mu: float = 0.60
    challenge_burn_nu: float = 0.20


def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def s_task_for_job(bounty: float, risk_level: float, fail_rate: float, reputation: float, p: Params) -> float:
    raw = p.k1 * bounty + p.k2 * risk_level + p.k3 * fail_rate - p.k4 * reputation
    return clamp(raw, p.s_task_min, p.s_task_max)


def simulate_one_round(rng: random.Random, p: Params) -> dict:
    bounty = rng.uniform(1_000, 100_000)
    fee = bounty * rng.uniform(0.02, 0.08)
    risk_level = rng.uniform(0.0, 1.0)

    reputation = rng.uniform(0.0, 1.0)
    fail_rate = 1.0 - reputation * 0.8

    s_task = s_task_for_job(bounty, risk_level, fail_rate, reputation, p)

    # success probability increases with reputation, decreases with risk
    success_prob = clamp(0.30 + 0.60 * reputation - 0.20 * risk_level, 0.02, 0.98)
    success = rng.random() < success_prob

    # challenge triggered more likely on failures/high risk
    challenge_prob = clamp(0.05 + 0.50 * (1 - success_prob) + 0.20 * risk_level, 0.0, 0.95)
    challenged = rng.random() < challenge_prob

    worker_reward = fee * p.alpha * (1.0 if success else 0.0)
    verifier_reward = fee * p.beta
    treasury_income = fee * p.gamma
    burn_amount = fee * p.delta

    slash = 0.0
    challenger_reward = 0.0

    if (not success) and challenged:
        slash = s_task * rng.uniform(0.4, 1.0)
        challenger_reward = slash * p.challenge_reward_lambda
        treasury_income += slash * p.challenge_treasury_mu
        burn_amount += slash * p.challenge_burn_nu

    publisher_cost = fee
    worker_net = worker_reward - slash

    return {
        "success": 1 if success else 0,
        "challenged": 1 if challenged else 0,
        "publisher_cost": publisher_cost,
        "worker_net": worker_net,
        "verifier_reward": verifier_reward,
        "treasury_income": treasury_income,
        "burn_amount": burn_amount,
        "slash": slash,
        "s_task": s_task,
    }


def summarize(rows: list[dict]) -> dict:
    def avg(key: str) -> float:
        return statistics.fmean(r[key] for r in rows)

    n = len(rows)
    success_rate = sum(r["success"] for r in rows) / n
    challenge_rate = sum(r["challenged"] for r in rows) / n

    return {
        "rounds": n,
        "success_rate": success_rate,
        "challenge_rate": challenge_rate,
        "avg_publisher_cost": avg("publisher_cost"),
        "avg_worker_net": avg("worker_net"),
        "avg_verifier_reward": avg("verifier_reward"),
        "avg_treasury_income": avg("treasury_income"),
        "avg_burn_amount": avg("burn_amount"),
        "avg_slash": avg("slash"),
        "avg_s_task": avg("s_task"),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    p = Params()

    rows = [simulate_one_round(rng, p) for _ in range(args.rounds)]
    out = summarize(rows)

    print("tokenomics_v2_sim_result")
    for k, v in out.items():
        if isinstance(v, float):
            print(f"{k}={v:.6f}")
        else:
            print(f"{k}={v}")


if __name__ == "__main__":
    main()
