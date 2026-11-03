#!/usr/bin/env python3
"""Illustrative toy screen for difficulty/chainwork asymmetry under Grover search.

NOT a W1 attack, lower bound, full quantum oracle, or consensus security proof.
Assumes independent search trials, chainwork proportional to difficulty, and an
idealized O(sqrt(difficulty)) oracle count. No hardware/fault/retarget model.
"""
from __future__ import annotations
import argparse
import json
import math


def ratios(difficulty_multiplier: float) -> dict[str, float]:
    if not math.isfinite(difficulty_multiplier) or difficulty_multiplier < 1:
        raise ValueError("difficulty multiplier must be finite and >= 1")
    quantum_workload_multiplier = math.sqrt(difficulty_multiplier)
    return {
        "difficulty_multiplier": difficulty_multiplier,
        "credited_chainwork_multiplier": difficulty_multiplier,
        "idealized_quantum_queries_multiplier": quantum_workload_multiplier,
        "credited_work_per_quantum_query_multiplier":
            difficulty_multiplier / quantum_workload_multiplier,
    }


def main():
    p = argparse.ArgumentParser(description="Illustrative asymmetry screen: NOT a PoN W1 proof")
    p.add_argument("--difficulty-multipliers", nargs="+", type=float,
                   default=[1, 4, 16, 256, 65536])
    args = p.parse_args()
    print(json.dumps({
        "non_applicability_warning": "Toy model only; NOT evidence of a valid W1 quantum attack",
        "paper": "Bailey & Sattath, arXiv:2403.08023",
        "assumptions": ["chainwork proportional to difficulty", "idealized sqrt(D) search",
                        "ignores W1 material, oracle uncomputation, hardware, reorg and timestamps"],
        "cases": [ratios(x) for x in args.difficulty_multipliers]
    }, indent=2))


if __name__ == "__main__":
    main()
