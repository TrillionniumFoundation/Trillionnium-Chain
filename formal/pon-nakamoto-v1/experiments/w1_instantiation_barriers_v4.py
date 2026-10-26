"""Exact controls for W1 instantiation obligations, not a SHA work bound.

The countermodels distinguish a public algorithm from an ideal oracle, separate
range-threshold behavior from generic hash properties, and check why one direct
auxiliary-input lift of the existing coarse seeded-path bound is vacuous.
Nothing in this module accepts a benchmark as a universal resource conversion.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import json
from typing import Callable

import w1_multi_instance_cost_v2 as geometry
import w1_sha256_model_boundary as sha
import w1_ticket_composition_v3 as composition

TRACE_BLOCKS = 2049
FULL_OPENING_CALLS = 3594
STATE_SIZE = 1 << 256
NATIVE_COUNT_UNIT = "distinct-native-block-candidate-identities"
MAX_EXACT_TRIALS = 128


def integer(value: int, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def probability(value: Fraction | None, name: str) -> Fraction | None:
    if value is None:
        return None
    if type(value) is not Fraction or not 0 <= value <= 1:
        raise ValueError(f"{name} must be an exact Fraction in [0,1] or unknown")
    return value


def public_algorithm_advantage(size: int) -> Fraction:
    """One fresh comparison with a locally known fixed permutation value."""
    integer(size, "size", 2)
    return Fraction(size - 1, size)


def compare_public_sha_round(
    oracle: Callable[[tuple[int, ...], bytes], tuple[int, ...]], block: bytes,
    state: tuple[int, ...] = sha.IV,
) -> bool:
    """One oracle call plus one public local evaluation; not a W1 forgery."""
    prediction = sha.permutation(state, block)
    return oracle(state, block) == prediction


def inline_sha_digest(message: bytes) -> dict:
    """Actual standard-IV SHA through the retained scalar round implementation.

    No hashlib API is called here. The reported compression count belongs to
    this implementation only; zero external API calls never means zero work.
    """
    return {
        "digest_hex": sha.sha256(message).hex(),
        "scalar_compression_executions": len(sha.blocks(message)),
        "hashlib_sha256_api_calls": 0,
        "physical_resource_lower_bound": None,
    }


def prefix_family_parameters(output_bits: int, fixed_prefix_bits: int) -> dict:
    integer(output_bits, "output_bits", 2)
    integer(fixed_prefix_bits, "fixed_prefix_bits", 1)
    if fixed_prefix_bits >= output_bits:
        raise ValueError("a nonempty random suffix is required")
    suffix_bits = output_bits - fixed_prefix_bits
    return {
        "output_bits": output_bits,
        "fixed_prefix_bits": fixed_prefix_bits,
        "random_suffix_bits": suffix_bits,
        "image_size": 1 << suffix_bits,
        "threshold": (1 << suffix_bits) - 1,
        "uniform_n_bit_threshold_probability": Fraction(1, 1 << fixed_prefix_bits),
        "prefix_family_threshold_probability": Fraction(1),
        "preserves_full_n_bit_preimage_or_collision_strength": False,
    }


def fresh_preimage_probability(image_size: int, queries: int) -> Fraction:
    """Uniform target in the declared image; distinct fresh random-function inputs."""
    integer(image_size, "image_size", 2)
    integer(queries, "queries")
    return 1 - Fraction(image_size - 1, image_size) ** queries


def fresh_collision_probability(image_size: int, queries: int) -> Fraction:
    integer(image_size, "image_size", 2)
    integer(queries, "queries")
    no_collision = Fraction(1)
    for seen in range(min(queries, image_size + 1)):
        no_collision *= Fraction(image_size - seen, image_size)
    return 1 - no_collision


def presampling_direct_lift(
    advice_bits: int, captured_calls: int, opening_cap: int,
    gamma_bits: int, fixed_pairs: int,
) -> dict:
    """Check ONLY the direct lift of m <= P + floor(Q/L).

    CDG's Theorem 1 uses the attacker PLUS challenger query cap. Here that cap
    is the declared complete checker Q + 3594 G, not merely the miner's Q.
    P is arbitrary in the additive branch. The multiplicative minimum is exact
    for gamma = 2^-gamma_bits. No auxiliary-input theorem for W1 is asserted.
    """
    integer(advice_bits, "advice_bits")
    integer(captured_calls, "captured_calls")
    integer(opening_cap, "opening_cap", 1)
    integer(gamma_bits, "gamma_bits", 2)
    integer(fixed_pairs, "fixed_pairs", 1)
    combined = captured_calls + FULL_OPENING_CALLS * opening_cap
    gamma = Fraction(1, 1 << gamma_bits)
    multiplicative_minimum = 6 * (advice_bits + 2 * gamma_bits) * combined
    additive_loss = Fraction(12 * (advice_bits + gamma_bits) * combined, fixed_pairs) + 2 * gamma
    first_capacity_violation = fixed_pairs + captured_calls // TRACE_BLOCKS + 1
    capacity_event_nonempty = first_capacity_violation <= opening_cap
    return {
        "combined_calls": combined,
        "gamma": gamma,
        "fixed_pairs": fixed_pairs,
        "multiplicative_minimum_fixed_pairs": multiplicative_minimum,
        "multiplicative_capacity_threshold": multiplicative_minimum + captured_calls // TRACE_BLOCKS + 1,
        "multiplicative_capacity_event_nonempty": multiplicative_minimum + captured_calls // TRACE_BLOCKS + 1 <= opening_cap,
        "additive_loss_before_clipping": additive_loss,
        "additive_capacity_threshold": first_capacity_violation,
        "additive_capacity_event_nonempty": capacity_event_nonempty,
        "additive_joint_bound_can_be_nontrivial": capacity_event_nonempty and additive_loss < 1,
        "actual_sha_instantiation": False,
    }


@dataclass(frozen=True)
class CapturedCaps:
    preprocessing: int
    online: int
    audit: int
    openings: int
    explicit_references: int = 0

    def __post_init__(self):
        for name in ("preprocessing", "online", "audit", "openings", "explicit_references"):
            integer(getattr(self, name), name)

    @property
    def total(self) -> int:
        return self.preprocessing + self.online + self.audit

    @property
    def references(self) -> int:
        return 3 * self.total + 2 * self.openings + self.explicit_references


def conditional_native_tail(
    caps: CapturedCaps, *, target: int, retirement_threshold: int,
    additional_winners: int, event_loss: Fraction | None,
    resource_conversion_loss: Fraction | None,
    identity_loss: Fraction | None,
    count_unit: str = NATIVE_COUNT_UNIT, fanout: int = 1,
    size: int = STATE_SIZE, trace_blocks: int = TRACE_BLOCKS,
) -> dict:
    """Algebra for DECLARED hypotheses; it cannot certify those hypotheses.

    Unknown losses stay unknown. The actual-protocol result remains explicitly
    unestablished even if a caller supplies numerical hypothetical assumptions.
    The event is W >= K0+k AND D0 >= d, with fixed d/k, not a postselected D0.
    """
    if type(caps) is not CapturedCaps:
        raise ValueError("exact CapturedCaps required")
    integer(size, "size", 2)
    integer(trace_blocks, "trace_blocks", 1)
    integer(target, "target", 1)
    if target > size // 2 - 1:
        raise ValueError("target exceeds the native development proof-of-work limit")
    integer(retirement_threshold, "retirement_threshold")
    integer(additional_winners, "additional_winners", 1)
    integer(fanout, "fanout", 1)
    if count_unit != NATIVE_COUNT_UNIT or fanout != 1:
        raise ValueError("v3 supplies fanout one only for native candidate identities")
    if retirement_threshold * trace_blocks > caps.preprocessing:
        raise ValueError("cannot retire more captured path capacity than QP")
    losses = {
        "w1_event_domination": probability(event_loss, "event_loss"),
        "resource_conversion": probability(resource_conversion_loss, "resource_conversion_loss"),
        "identity_transfer": probability(identity_loss, "identity_loss"),
    }
    trials = (caps.preprocessing - trace_blocks * retirement_threshold + caps.online) // trace_blocks
    if caps.total > size:
        pbar = Fraction(1)
        delta = Fraction(1)
    elif caps.total == 0:
        pbar = Fraction(target + 1, size)
        delta = Fraction(0)
    else:
        denominator = size - caps.total + 1
        pbar = min(Fraction(1), Fraction(target + 1, denominator))
        delta = min(Fraction(1), Fraction(2 * caps.total * (caps.total + caps.references), denominator))
    if delta == 1:
        ideal_bound = Fraction(1)
    elif additional_winners > trials:
        ideal_bound = delta
    elif pbar == 1:
        ideal_bound = Fraction(1)
    else:
        if trials > MAX_EXACT_TRIALS:
            raise OverflowError("exact binomial computation limit; no numerical bound fabricated")
        ideal_bound = min(Fraction(1), composition.binomial_tail(trials, pbar, additional_winners) + delta)
    missing = tuple(name for name, value in losses.items() if value is None)
    conditional = None if missing else min(Fraction(1), ideal_bound + sum(losses.values(), Fraction(0)))
    return {
        "event": "W >= K0+k AND D0 >= d",
        "d_fixed_before_experiment": retirement_threshold,
        "k_fixed_before_experiment": additional_winners,
        "K0_is_not_assumed_zero": True,
        "count_unit": count_unit,
        "fanout": fanout,
        "state_space": size,
        "trace_blocks": trace_blocks,
        "matches_w1_geometry": size == STATE_SIZE and trace_blocks == TRACE_BLOCKS,
        "new_opportunity_cap": trials,
        "combined_calls": caps.total,
        "reference_cap": caps.references,
        "pbar": pbar,
        "join_failure": delta,
        "ideal_model_tail": ideal_bound,
        "missing_actual_hypotheses": missing,
        "conditional_formula_only": conditional,
        "actual_protocol_bound_established": False,
        "physical_cost_floor_established": False,
    }


def summary() -> dict:
    caps = CapturedCaps(preprocessing=2049, online=2049 * 3, audit=FULL_OPENING_CALLS * 4, openings=4)
    noise = geometry.noise_message(bytes(range(32)), 0, 0)
    ticket = geometry.pon_message(b"ticket", bytes(range(32)), bytes(reversed(range(32))))
    return {
        "schema": "w1-instantiation-barriers-v4",
        "public_sha_vs_ideal_one_query_advantage": public_algorithm_advantage(STATE_SIZE),
        "inline_actual_sha_controls": [inline_sha_digest(message) for message in (noise, ticket)],
        "threshold_property_countermodel": prefix_family_parameters(256, 64),
        "presampling_direct_lift_examples": [
            presampling_direct_lift(256, 2049 * 8, 4, 40, pairs)
            for pairs in (1, 2, 4, 1024, 1 << 32)
        ],
        "actual_w1_hypotheses_are_unknown": conditional_native_tail(
            caps, target=(1 << 192) - 1, retirement_threshold=1,
            additional_winners=1, event_loss=None,
            resource_conversion_loss=None, identity_loss=None,
        ),
        "claims": {
            "whole_public_sha_indistinguishability_route_rejected": True,
            "generic_hash_properties_imply_uniform_threshold_work": False,
            "direct_coarse_seeded_presampling_lift_is_useful": False,
            "actual_sha_w1_attack_demonstrated": False,
            "actual_sha_instantiation_proved": False,
            "arbitrary_auxiliary_input_w1_bound_proved": False,
            "production_activation": False,
            "benchmark": False,
        },
    }


def json_exact(value):
    if isinstance(value, Fraction):
        return {"numerator": value.numerator, "denominator": value.denominator}
    raise TypeError(type(value).__name__)


if __name__ == "__main__":
    print(json.dumps(summary(), default=json_exact, indent=2, sort_keys=True))
