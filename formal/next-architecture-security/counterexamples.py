#!/usr/bin/env python3
"""Exact finite research counterexamples; never a consensus or PQ qualification.

S is static, while W and U are declared timed resources in an auxiliary model.
No physical meaning, common unit, independence or real sampler is certified.
Only fixed formulas and fixed small grids are used; there is no expression eval.
"""
from __future__ import annotations

import argparse
from fractions import Fraction as F
import hashlib
import itertools
import json
from pathlib import Path
import sys

SCHEMA = "trnm-next-consensus-pq-counterexamples-v1"
HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures/research-counterexamples-v1.json"
CANDIDATES = (
    ("security_work", "W"),
    ("timed_sum", "W + U"),
    ("timed_product", "W * U"),
    ("timed_sum_squares", "W^2 + U^2"),
    ("timed_bottleneck", "min(W, U)"),
    ("static_multiplier", "S * W"),
    ("static_additive_bonus", "W + S"),
)
VALUES = tuple(map(F, (0, 1, 2, 3))) + (F(1, 2),)
SEED = (F(2), F(2), F(3))
STATES = (SEED,) + tuple(x for x in itertools.product(VALUES, repeat=3) if x != SEED)
SCALES = (F(2), F(1, 2), F(3, 2))
RISC0_SOURCE = (
    "https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/"
    "0c830e0be8939ce80c8443c9ad68021b87343a00/"
    "config/pon/w1-qrom-implementation-v1.json"
)
RISC0_OBLIGATIONS = (
    "latest_theorem_version_equivalence",
    "complete_relation_and_compiler",
    "all_27_recursion_program_semantics",
    "control_padding_and_recursive_trace_size_reachability",
    "relaxed_rbr_knowledge_soundness",
    "committed_relation_monotonicity",
    "merkle_multi_extractability",
    "sponge_and_domain_separation_mapping",
    "fiat_shamir_challenge_and_salt_mapping",
    "finite_field_sampling_and_challenge_length",
    "sequential_adaptive_composition",
    "lifetime_global_quantum_budget",
    "concrete_enabled_features_and_debug_exclusion",
    "quantum_work_and_chainweight",
    "pq_signature_owner_authorization",
)


def rational(value: F, *, positive: bool = False) -> None:
    if type(value) is not F or value < 0 or (positive and value == 0):
        raise ValueError("EXACT_NONNEGATIVE_FRACTION_REQUIRED")


def weight(candidate: str, s: F, w: F, u: F) -> F:
    """Evaluate one declared auxiliary formula, not chainwork or real cost."""
    for value in (s, w, u):
        rational(value)
    if candidate == "security_work":
        return w
    if candidate == "timed_sum":
        return w + u
    if candidate == "timed_product":
        return w * u
    if candidate == "timed_sum_squares":
        return w * w + u * u
    if candidate == "timed_bottleneck":
        return min(w, u)
    if candidate == "static_multiplier":
        return s * w
    if candidate == "static_additive_bonus":
        return w + s
    raise ValueError("UNKNOWN_FIXED_CANDIDATE")


def homogeneity_pair(candidate: str, state: tuple[F, F, F], alpha: F) -> tuple[F, F]:
    rational(alpha, positive=True)
    s, w, u = state
    return weight(candidate, s, alpha * w, alpha * u), alpha * weight(candidate, s, w, u)


def candidate_report(candidate: str, formula: str) -> dict:
    first = None
    failures = 0
    monotonic_failures = 0
    for state in STATES:
        for alpha in SCALES:
            left, right = homogeneity_pair(candidate, state, alpha)
            if left != right:
                failures += 1
                if first is None:
                    first = {
                        "S": str(state[0]), "W": str(state[1]), "U": str(state[2]),
                        "alpha": str(alpha), "Gamma_S_alphaW_alphaU": str(left),
                        "alpha_Gamma_S_W_U": str(right), "difference": str(left - right),
                    }
        base = weight(candidate, *state)
        for axis in range(3):
            enlarged = list(state)
            enlarged[axis] += F(1, 2)
            monotonic_failures += weight(candidate, *enlarged) < base
    return {
        "candidate": candidate, "formula": formula,
        "homogeneity": {
            "comparisons": len(STATES) * len(SCALES),
            "counterexamples": failures, "first_counterexample": first,
            "status": "COUNTEREXAMPLE_FOUND" if failures else "NOT_REFUTED_ON_FINITE_GRID",
        },
        "coordinatewise_monotonicity": {
            "comparisons": len(STATES) * 3, "counterexamples": monotonic_failures,
            "status": "COUNTEREXAMPLE_FOUND" if monotonic_failures else "NOT_REFUTED_ON_FINITE_GRID",
        },
        "real_resource_interpretation": "UNKNOWN",
        "security_qualification": "HOLD_NO_GO",
    }


def subset_probability(population: int, subset: int, queries: int, *, replacement: bool) -> F:
    """All draws hit one fixed subset, assuming uniform independent/unique draws.

    These are auxiliary finite samplers, not the implemented Poseidon2 RNG.
    Without replacement, queries above the population are undefined and refused.
    """
    if (type(population) is not int or not 1 <= population <= 2**32
            or type(subset) is not int or not 0 <= subset <= population
            or type(queries) is not int or not 0 <= queries <= 128
            or type(replacement) is not bool):
        raise ValueError("BOUNDED_INTEGER_SAMPLER_REQUIRED")
    if replacement:
        return F(subset, population) ** queries
    if queries > population:
        raise ValueError("DISTINCT_DRAWS_EXCEED_POPULATION")
    if queries > subset:
        return F(0)
    probability = F(1)
    for draw in range(queries):
        probability *= F(subset - draw, population - draw)
    return probability


def sampling_report(population: int, subset: int, queries: int) -> dict:
    repeated = subset_probability(population, subset, queries, replacement=True)
    distinct = subset_probability(population, subset, queries, replacement=False)
    return {
        "population": population, "fixed_subset_size": subset, "queries": queries,
        "with_replacement": str(repeated), "without_replacement": str(distinct),
        "understatement_if_distinct_bound_substituted": str(repeated - distinct),
        "status": "COUNTEREXAMPLE_FOUND" if repeated > distinct else "NO_STRICT_GAP",
        "actual_fri_failure_probability": None,
    }


def report() -> dict:
    return {
        "schema": SCHEMA,
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scope": "Fixed finite auxiliary models only; no native runtime or proof verification.",
        "rational_encoding": "Exact reduced n or n/d strings; no floating-point probabilities.",
        "qualification": {
            "decision": "HOLD_NO_GO", "research_only": True,
            "consensus_admission": False, "production_qualified": False,
            "chainweight_changed": False, "physical_cost_model_qualified": False,
            "complete_qrom_proof": False, "security_bits_quantum": None,
            "universal_property_proved_by_finite_grid": False,
            "actual_sampler_distribution_qualified": False,
        },
        "resource_model": {
            "static_axes": ["S"], "timed_axes": ["W", "U"],
            "meaning": "S is hypothetical fixed capacity; W,U are hypothetical timed resource quantities.",
            "physical_calibration_and_common_units": "UNKNOWN",
            "quality_scores_or_rewards_are_not_calibrated_work": True,
            "grid_values": [str(x) for x in VALUES], "states": len(STATES),
            "scales": [str(x) for x in SCALES], "monotonic_increment": "1/2",
            "first_state": [str(x) for x in SEED],
        },
        "candidate_checks": [candidate_report(*candidate) for candidate in CANDIDATES],
        "sampling": {
            "assumption": "Fixed subset, ideal uniform draws; independence only in replacement model.",
            "cases": [sampling_report(8, 4, 3), sampling_report(8, 2, 3)],
            "actual_risc0_reference": {
                "source": RISC0_SOURCE.replace("config/pon/w1-qrom-implementation-v1.json",
                                               "scripts/w1_fri_transcript_audit.py"),
                "queries": 50, "sampling_with_replacement": True,
                "actual_outer_domain_size": None,
                "real_poseidon2_qrom_distribution_proved": False,
                "reference_only_not_executed_or_imported": True,
            },
        },
        "risc0_obligations": {
            "profile_id": "trnm-w1-risc0-3.0.6-poseidon2-join-v2",
            "source": RISC0_SOURCE,
            "items": [{"id": item, "status": "OPEN"} for item in RISC0_OBLIGATIONS],
            "obligations_closed_by_this_checker": 0,
        },
        "plonky3_inherits_risc0_proof_or_profile_specific_obligations": False,
    }


def report_bytes() -> bytes:
    return (json.dumps(report(), sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-fixture", action="store_true")
    args = parser.parse_args(argv)
    expected = report_bytes()
    if not args.check_fixture:
        sys.stdout.buffer.write(expected)
        return 0
    try:
        matched = FIXTURE.read_bytes() == expected
    except OSError:
        matched = False
    print(json.dumps({"fixture_matches": matched, "research_only": True,
                      "consensus_admission": False, "production_qualified": False}, sort_keys=True))
    return 0 if matched else 1


if __name__ == "__main__":
    raise SystemExit(main())
