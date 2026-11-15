"""Exact arithmetic boundaries for the existing conditional DAA research.

This module reuses reference.py; it is not another miner or network simulator.
It distinguishes a clamped timespan, a rounded target, ideal uniform-ticket
expected queries, and integer credited work.  A sequence of selected spans is
an arithmetic example, not evidence that a W1-valid branch can be produced.

All quantum costs below are explicit constant-oracle-cost square-root premises.
Changing the target changes the challenged W1 relation: no stored W1 ticket is
retested under another target.  This file does not enumerate or synthesize W1.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from math import isqrt
from pathlib import Path
from typing import Any, Sequence

from reference import retarget, work

BITS = 256
SPACE = 1 << BITS
POW_LIMIT = (1 << 255) - 1
INTERVAL = 16
SPACING = 10
DESIRED_SPAN = (INTERVAL - 1) * SPACING
MIN_SPAN = (DESIRED_SPAN + 3) // 4
MAX_SPAN = 4 * DESIRED_SPAN


def ratio(value: Fraction | int) -> dict[str, str]:
    """Lossless JSON representation, including integers above JavaScript 2^53."""
    value = Fraction(value)
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def uniform_expected_queries(target: int, bits: int = BITS) -> Fraction:
    """Geometric mean under independent uniform tickets, not measured W1 cost."""
    work(target, bits)  # Reuse the reference domain validation.
    return Fraction(1 << bits, target + 1)


def rational_sqrt(value: Fraction) -> Fraction | None:
    """Return an exact rational root only when it exists; never round a root."""
    if not isinstance(value, Fraction) or value < 0:
        raise ValueError("NONNEGATIVE_FRACTION_REQUIRED")
    n, d = isqrt(value.numerator), isqrt(value.denominator)
    return Fraction(n, d) if n * n == value.numerator and d * d == value.denominator else None


def clamp_path(initial_target: int, observed_spans: Sequence[int]) -> list[dict[str, Any]]:
    """Apply selected signed endpoint differences through native-style arithmetic.

    No timestamps, successful predicates, mining durations or branch activation
    are inferred.  Negative endpoint differences exercise saturating subtraction.
    Actual branch-history and MTP witnesses live in the native node tests.
    """
    if type(initial_target) is not int or not 1 <= initial_target <= POW_LIMIT:
        raise ValueError("INITIAL_TARGET")
    if not observed_spans or len(observed_spans) > 256:
        raise ValueError("SPAN_SEQUENCE")
    current = initial_target
    rows: list[dict[str, Any]] = []
    for epoch, span in enumerate(observed_spans, 1):
        if type(span) is not int or not -(1 << 64) < span < (1 << 64):
            raise ValueError("SIGNED_SPAN")
        # Both constructed endpoints fit u64; reference.retarget performs the
        # existing saturated/subsequently clamped endpoint arithmetic.
        first, last = max(0, -span), max(0, span)
        bounded = min(MAX_SPAN, max(MIN_SPAN, max(1, span)))
        following = retarget(current, first, last, INTERVAL, SPACING, POW_LIMIT)
        queries_before = uniform_expected_queries(current)
        queries_after = uniform_expected_queries(following)
        rows.append({
            "retarget_index": epoch,
            "selected_signed_endpoint_span": span,
            "bounded_span": bounded,
            "span_multiplier": ratio(Fraction(bounded, DESIRED_SPAN)),
            "target_before_hex": f"{current:064x}",
            "target_after_hex": f"{following:064x}",
            "integer_work_before": str(work(current)),
            "integer_work_after": str(work(following)),
            "realized_credited_work_ratio": ratio(Fraction(work(following), work(current))),
            "realized_uniform_query_ratio": ratio(queries_after / queries_before),
            "uniform_query_ratio_from_initial": ratio(queries_after / uniform_expected_queries(initial_target)),
            "credited_work_ratio_from_initial": ratio(Fraction(work(following), work(initial_target))),
            "minimum_target_reached": following == 1,
        })
        current = following
    return rows


def square_root_cost_counterexample() -> dict[str, Any]:
    """Exact 16x difficulty example; quantum conclusion is a cost hypothesis.

    These are two independently target-bound lottery relations.  Their mean
    independent uniform query counts happen to be integers and perfect squares,
    so this comparison requires neither numerical square roots nor floor errors.
    It does not price the path that changes a branch's required target.
    """
    easy, hard = (1 << 252) - 1, (1 << 248) - 1
    easy_queries, hard_queries = uniform_expected_queries(easy), uniform_expected_queries(hard)
    difficulty_ratio = hard_queries / easy_queries
    quantum_ratio = rational_sqrt(difficulty_ratio)
    assert quantum_ratio is not None
    credit_ratio = Fraction(work(hard), work(easy))
    return {
        "easy_target_hex": f"{easy:064x}",
        "hard_target_hex": f"{hard:064x}",
        "easy_uniform_expected_queries": ratio(easy_queries),
        "hard_uniform_expected_queries": ratio(hard_queries),
        "credited_work_ratio_hard_over_easy": ratio(credit_ratio),
        "classical_query_cost_ratio_hard_over_easy": ratio(difficulty_ratio),
        "hypothesized_quantum_cost_ratio_hard_over_easy": ratio(quantum_ratio),
        "classical_credit_per_cost_relative_ratio": ratio(credit_ratio / difficulty_ratio),
        "hypothesized_quantum_credit_per_cost_relative_ratio": ratio(credit_ratio / quantum_ratio),
        "quantum_assumption": "C_Q(T) = c * sqrt(2^256/(T+1)), with the same c for both target-bound relations",
        "target_dependent_oracle_cost_or_failure_constant_proved": False,
        "distinct_target_bound_relations_required": True,
        "stored_ticket_rethresholding_performed": False,
        "retarget_transition_cost_included": False,
        "native_attack_or_profitability_established": False,
    }


def square_root_weight_classical_counterexample() -> dict[str, Any]:
    """Changing block score to sqrt(work) rewards cheaper classical lotteries.

    At the same EXPECTED query budget, 16 easy successes and one hard success
    cost 256 uniform queries each, but their sqrt scores are 64 and 16.  Equal
    means are not pathwise equality or a claim about their completion-time tails.
    Neither sequence is asserted to be a valid competing branch from one fork.
    """
    easy, hard = (1 << 252) - 1, (1 << 248) - 1
    easy_blocks, hard_blocks = 16, 1
    easy_work, hard_work = work(easy), work(hard)
    easy_root, hard_root = rational_sqrt(Fraction(easy_work)), rational_sqrt(Fraction(hard_work))
    assert easy_root is not None and hard_root is not None
    easy_cost = easy_blocks * uniform_expected_queries(easy)
    hard_cost = hard_blocks * uniform_expected_queries(hard)
    return {
        "easy_blocks": easy_blocks,
        "hard_blocks": hard_blocks,
        "easy_expected_classical_queries": ratio(easy_cost),
        "hard_expected_classical_queries": ratio(hard_cost),
        "easy_linear_chain_score": str(easy_blocks * easy_work),
        "hard_linear_chain_score": str(hard_blocks * hard_work),
        "easy_sum_of_square_root_block_scores": ratio(easy_blocks * easy_root),
        "hard_sum_of_square_root_block_scores": ratio(hard_blocks * hard_root),
        "cheap_sequence_score_advantage_at_equal_mean_cost": ratio(
            easy_blocks * easy_root / (hard_blocks * hard_root)),
        "formula_under_perfect_square_work": "sqrt(W)/E[queries] = sqrt(W) * (T+1)/2^256",
        "sqrt_of_total_chainwork_changes_fork_order": False,
        "sqrt_of_total_chainwork_explanation": "Exact real sqrt(sum(W)) is strictly increasing and preserves fork order; sum(sqrt(W)) changes it",
        "integer_floor_of_sqrt_total_can_create_new_ties": True,
        "competing_branch_target_paths_or_transition_cost_included": False,
        "pathwise_equal_cost_or_success_probability_claimed": False,
        "native_attack_or_profitability_established": False,
    }


def floor_credit_counterexample() -> dict[str, Any]:
    """A fourfold span clamp is not a fourfold bound on integer block credits."""
    target = SPACE // 3
    row = clamp_path(target, [0])[0]
    changed = int(row["target_after_hex"], 16)
    before, after = uniform_expected_queries(target), uniform_expected_queries(changed)
    return {
        "selected_retarget": row,
        "uniform_expected_queries_before": ratio(before),
        "uniform_expected_queries_after": ratio(after),
        "before_credit_rounding_loss": ratio(before - work(target)),
        "after_credit_rounding_loss": ratio(after - work(changed)),
        "actual_query_ratio_at_most_four": after <= 4 * before,
        "integer_credit_ratio_exceeds_four": work(changed) > 4 * work(target),
        "generic_inclusive_query_bound": "Q(next) <= 4 Q(parent) for a lower span multiplier >= 1/4",
        "generic_integer_credit_bound": "W(next) <= 4 W(parent) + 3; exact Q and W must not be identified",
        "classical_credit_per_uniform_query_before": ratio(Fraction(work(target), 1) / before),
        "classical_credit_per_uniform_query_after": ratio(Fraction(work(changed), 1) / after),
        "classical_expected_credit_exceeds_one_per_query": False,
        "native_attack_or_profitability_established": False,
    }


def report() -> dict[str, Any]:
    initial = (1 << 240) - 1
    path = clamp_path(initial, [0] * 6)
    saturation = clamp_path(7, [0, 0])
    return {
        "schema": "trnm-joint-consensus-boundaries-v1",
        "scope": "exact arithmetic counterexamples plus explicitly conditional lottery costs",
        "profile": {
            "target_bits": BITS, "interval": INTERVAL, "spacing_seconds": SPACING,
            "desired_span_seconds": DESIRED_SPAN,
            "minimum_clamped_span_seconds": MIN_SPAN,
            "maximum_clamped_span_seconds": MAX_SPAN,
            "lower_target_span_multiplier": ratio(Fraction(MIN_SPAN, DESIRED_SPAN)),
            "inverse_lower_span_multiplier": ratio(Fraction(DESIRED_SPAN, MIN_SPAN)),
            "inverse_span_is_not_always_realized_inclusive_query_ratio": True,
            "lottery_probability_if_uniform": "(T+1)/2^256",
            "credited_work": "floor(2^256/(T+1))",
        },
        "repeated_clamp": {
            "initial_target_hex": f"{initial:064x}", "rows": path,
            "span_clamp_does_not_bound_lifetime_difficulty_change": True,
            "rounding_free_target_expression": "T_0 * (19/75)^k before integer rounding and the target floor",
            "exact_recurrence": "T_(k+1) = max(1, floor(19*T_k/75))",
            "mtp_admissible_branch_or_production_clock_constructed_here": False,
        },
        "integer_floor_credit": floor_credit_counterexample(),
        "minimum_target_boundary": {
            "rows": saturation,
            "maximum_per_block_work": str(1 << 255),
            "difficulty_growth_is_unbounded": False,
        },
        "linear_work_vs_sqrt_cost": square_root_cost_counterexample(),
        "sqrt_block_weight_classical_counterexample": square_root_weight_classical_counterexample(),
        "target_binding": {
            "changed_target_requires_changed_challenged_header": True,
            "stored_ticket_rethresholding_performed": False,
            "existing_binding_controls": [
                "test_w1_marked_domain.py::test_changing_target_changes_the_challenge_and_ticket",
                "test_w1_quantum_restricted_oracle.py::test_changed_target_rebuilds_challenge_and_construction_identity",
            ],
            "w1_binding_controls_executed_by_this_module": False,
        },
        "limitations": {
            "uniform_iid_ticket_premise_proved_for_w1": False,
            "w1_oracle_cost_measured_or_synthesized": False,
            "native_w1_proofs_generated": 0,
            "native_node_activation_executed": False,
            "network_profitability_or_consensus_safety_theorem": False,
            "production_consensus_activation": False,
            "proof_latency_propagation_availability_and_reorg_state_priced": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Create a new JSON report; an existing path is refused")
    args = parser.parse_args()
    payload = json.dumps(report(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(payload, end="")
    else:
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(payload)


if __name__ == "__main__":
    main()
