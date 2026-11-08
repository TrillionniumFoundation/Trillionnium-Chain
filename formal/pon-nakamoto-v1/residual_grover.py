#!/usr/bin/env python3
"""Exact four-address Grover residual-state counterexample, not a W1 attack.

Uses rational amplitudes; no quantum computer, noise model or physical cost is
simulated. Oracle queries are the only resource in this deliberately tiny model.
"""
from fractions import Fraction as F
import argparse
import json
from pathlib import Path


def results():
    uniform = [F(1, 2)] * 4
    rows = []
    for marked in range(4):
        phase = [-v if i == marked else v for i, v in enumerate(uniform)]
        mean = sum(phase) / 4
        after = [2 * mean - v for v in phase]
        expected = [F(int(i == marked)) for i in range(4)]
        assert after == expected
        assert sum(v * v for v in after) == 1
        rows.append({"marked": marked, "initial_amplitudes": list(map(str, uniform)),
                     "post_query_amplitudes": list(map(str, phase)),
                     "post_diffusion_amplitudes": list(map(str, after)),
                     "success_on_measurement": str(after[marked] ** 2)})
    # Both joint states have A marginal I/4. In the correlated state F=A;
    # in the independent state F and A are independent uniform addresses.
    correlated = [[F(int(f == a), 4) for a in range(4)] for f in range(4)]
    independent = [[F(1, 16) for _ in range(4)] for _ in range(4)]
    marginal = lambda joint: [sum(joint[f][a] for f in range(4)) for a in range(4)]
    success = lambda joint: sum(joint[i][i] for i in range(4))
    assert marginal(correlated) == marginal(independent) == [F(1, 4)] * 4
    assert success(correlated) == 1 and success(independent) == F(1, 4)
    return {
        "schema": "pon-exact-residual-grover-countermodel-v1",
        "scope": "Four-address oracle model only; no W1 or physical-resource claim",
        "grover_cases": rows,
        "cut": {"position": "after one Grover iterate, before measurement",
                "new_oracle_queries": 0, "measured_winner_records": 0,
                "winner_probability": "1"},
        "same_private_marginal": {"diagonal": list(map(str, marginal(correlated))),
                                  "correlated_success": str(success(correlated)),
                                  "independent_success": str(success(independent)),
                                  "conclusion": "Private marginal alone omits oracle correlation"},
        "checks": {"exact_grover_cases": 4, "norm_checks": 4,
                   "joint_state_counterexample": True},
        "claims": {"actual_W1_attack": False, "quantum_hardware_executed": False,
                   "actual_W1_resource_tail_proved": False}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    data = json.dumps(results(), indent=2) + "\n"
    if args.out:
        with args.out.open("x") as stream:
            stream.write(data)
    else:
        print(data, end="")
