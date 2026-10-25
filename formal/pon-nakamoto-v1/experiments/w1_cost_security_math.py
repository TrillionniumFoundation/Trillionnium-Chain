"""Exact arithmetic controls for the conditional W1 cost-security research game.

This module does not run W1, measure a producer, prove a cost lower bound, or
change a protocol parameter. Its binomial statements assume a fixed upper bound
on distinct, conditionally independent lottery opportunities. Its hybrid model
assumes additive costs for comparable opportunities and explicit acceleration
bounds. The accompanying specification states the missing reduction obligations.
"""

from __future__ import annotations

import json
from fractions import Fraction
from math import comb


def _probability(value: Fraction) -> Fraction:
    value = Fraction(value)
    if not 0 <= value <= 1:
        raise ValueError("probability must be in [0, 1]")
    return value


def _positive(value: Fraction, name: str) -> Fraction:
    value = Fraction(value)
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _query_count(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 4096:
        raise ValueError("query bound must be an integer in [0, 4096]")
    return value


def target_probability(target: int) -> Fraction:
    """Uniform 256-bit ticket probability for W1's inclusive nonzero target.

    This is a random-oracle probability, not an empirical W1 hardness claim.
    Target zero is explicitly refused by W1, despite an inclusive comparison
    alone admitting the all-zero digest with probability 2**-256.
    """
    if isinstance(target, bool) or not isinstance(target, int):
        raise ValueError("target must be an integer")
    if not 0 <= target < 1 << 256:
        raise ValueError("target must fit 256 bits")
    return Fraction(target + 1, 1 << 256) if target else Fraction(0)


def binomial_tail(query_bound: int, probability: Fraction, threshold: int) -> Fraction:
    """P[Binomial(query_bound, probability) >= threshold], exactly.

    A stopped search's observed query count is not generally an admissible
    fixed query_bound. A precommitted maximum can yield stochastic domination
    only under the conditional independence and opportunity-cost premises.
    """
    query_bound = _query_count(query_bound)
    probability = _probability(probability)
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise ValueError("threshold must be an integer")
    if threshold <= 0:
        return Fraction(1)
    if threshold > query_bound:
        return Fraction(0)
    return sum(
        (
            Fraction(comb(query_bound, successes))
            * probability**successes
            * (1 - probability) ** (query_bound - successes)
            for successes in range(threshold, query_bound + 1)
        ),
        Fraction(0),
    )


def binomial_pgf_upper(
    query_bound: int, probability: Fraction, threshold: int, z: Fraction
) -> Fraction:
    """An exact rational probability-generating-function upper bound.

    With z >= 1, Markov's inequality gives
    P[N >= k] <= (1 - p + p*z)**Q / z**k for N ~ Binomial(Q,p).
    The value is clipped to the elementary [0, 1] probability bound.
    """
    query_bound = _query_count(query_bound)
    probability = _probability(probability)
    z = Fraction(z)
    if z < 1:
        raise ValueError("z must be at least one")
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise ValueError("threshold must be an integer")
    if threshold <= 0:
        return Fraction(1)
    if threshold > query_bound:
        return Fraction(0)
    return min(Fraction(1), (1 - probability + probability * z) ** query_bound / z**threshold)


def effective_share(raw_share: Fraction, acceleration: Fraction) -> Fraction:
    """Conditional equal-resource, linear-throughput share conversion."""
    raw_share = _probability(raw_share)
    acceleration = _positive(acceleration, "acceleration")
    return raw_share * acceleration / (1 - raw_share + raw_share * acceleration)


def raw_share_at_threshold(acceleration: Fraction, threshold: Fraction) -> Fraction:
    """Invert effective_share; this does not establish a consensus threshold."""
    acceleration = _positive(acceleration, "acceleration")
    threshold = _probability(threshold)
    return threshold / (acceleration * (1 - threshold) + threshold)


def hybrid_acceleration(
    floor_fraction: Fraction,
    useful_acceleration: Fraction,
    floor_acceleration: Fraction = Fraction(1),
) -> Fraction:
    """Additive-cost sensitivity model, not a composed PoW security theorem.

    The reference expected cost of one comparable opportunity is normalized to
    one. With component acceleration bounds, the returned value is an upper
    envelope: the adversary pays at least beta/k_H + (1-beta)/k_U. Equality
    additionally needs simultaneous attainment. Binding, failure schedule,
    reuse, resource overlap and independent floor soundness must be established
    separately before this model applies.
    """
    floor_fraction = _probability(floor_fraction)
    useful_acceleration = _positive(useful_acceleration, "useful acceleration")
    floor_acceleration = _positive(floor_acceleration, "floor acceleration")
    return 1 / (
        floor_fraction / floor_acceleration
        + (1 - floor_fraction) / useful_acceleration
    )


def hybrid_unknown_useful_limit(
    floor_fraction: Fraction, floor_acceleration: Fraction = Fraction(1)
) -> Fraction | None:
    """Limit as useful acceleration tends to infinity; None means unbounded."""
    floor_fraction = _probability(floor_fraction)
    floor_acceleration = _positive(floor_acceleration, "floor acceleration")
    return floor_acceleration / floor_fraction if floor_fraction else None


def minimum_floor_fraction(
    useful_acceleration: Fraction,
    target_acceleration: Fraction,
    floor_acceleration: Fraction = Fraction(1),
) -> Fraction | None:
    """Smallest beta in [0,1] meeting the additive model's target, if any.

    Returns None when even the floor cannot meet the target and the pure useful
    arm also exceeds it. This is a sensitivity target, never an activation rule.
    """
    useful_acceleration = _positive(useful_acceleration, "useful acceleration")
    target_acceleration = _positive(target_acceleration, "target acceleration")
    floor_acceleration = _positive(floor_acceleration, "floor acceleration")
    if useful_acceleration <= target_acceleration:
        return Fraction(0)
    if floor_acceleration > target_acceleration:
        return None
    return (
        1 / target_acceleration - 1 / useful_acceleration
    ) / (1 / floor_acceleration - 1 / useful_acceleration)


def _ratio(value: Fraction | None) -> str | None:
    return str(value) if value is not None else None


def report() -> dict:
    targets = (Fraction(11, 10), Fraction(5, 4), Fraction(2), Fraction(4))
    q, p = 8, Fraction(1, 2)
    return {
        "schema": "pon-w1-cost-security-math-v1",
        "scope": "conditional exact arithmetic and counterexamples; no native W1 observation",
        "native_measurement": False,
        "work_hardness_qualified": False,
        "production_activation": False,
        "uniform_ticket_probabilities": {
            "zero_target_refused": _ratio(target_probability(0)),
            "7f_followed_by_31_ff": _ratio(target_probability((1 << 255) - 1)),
            "07_followed_by_31_ff": _ratio(target_probability((1 << 251) - 1)),
        },
        "same_mean_is_not_same_tail": {
            "query_bound": q,
            "mean_successes_both_models": _ratio(q * p),
            "independent_probability_all_eight": _ratio(binomial_tail(q, p, q)),
            "perfectly_correlated_probability_all_eight": _ratio(p),
            "mean_only_markov_upper_at_eight": _ratio(q * p / q),
        },
        "charging_only_successes_hides_work": {
            "actual_attempt_cap": q,
            "actual_probability_one_or_more": _ratio(binomial_tail(q, p, 1)),
            "incorrect_one_charged_attempt_probability": _ratio(p),
            "expected_actual_attempts_until_first_hit_or_cap": _ratio(
                sum(((1 - p) ** i for i in range(q)), Fraction(0))
            ),
        },
        "one_setup_shared_across_four_parent_searches": {
            "setup_cost_units": 8,
            "online_cost_units_per_parent": 2,
            "parents": 4,
            "actual_joint_cost_units": 8 + 4 * 2,
            "incorrect_setup_charged_four_times": 4 * (8 + 2),
            "discarded_parent_work_refund_units": 0,
        },
        "preselected_sensitivity_targets": [
            {
                "kappa_target": _ratio(target),
                "raw_share_at_conditional_half_work": _ratio(
                    raw_share_at_threshold(target, Fraction(1, 2))
                ),
                "minimum_floor_fraction_if_useful_acceleration_four": _ratio(
                    minimum_floor_fraction(Fraction(4), target)
                ),
                "minimum_floor_fraction_if_useful_acceleration_unbounded": _ratio(
                    1 / target
                ),
            }
            for target in targets
        ],
        "hybrid_sensitivity": [
            {
                "floor_fraction": _ratio(beta),
                "floor_acceleration": _ratio(floor_speed),
                "useful_acceleration": "4",
                "conditional_combined_acceleration": _ratio(
                    hybrid_acceleration(beta, Fraction(4), floor_speed)
                ),
                "limit_if_useful_acceleration_unbounded": _ratio(
                    hybrid_unknown_useful_limit(beta, floor_speed)
                ),
            }
            for beta in (Fraction(0), Fraction(1, 10), Fraction(1, 2), Fraction(1))
            for floor_speed in (Fraction(1), Fraction(2))
        ],
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2, sort_keys=True))
