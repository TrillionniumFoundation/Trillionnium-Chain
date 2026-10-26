#!/usr/bin/env python3
"""Exact conditional W1-to-chain interfaces; never a production safety verdict.

This is a research arithmetic model, not a second native Node implementation.
See W1_CHAIN_SECURITY_ENVELOPE_V1.md for proofs and required coupling premises.
"""
from __future__ import annotations

import hashlib
import json
from decimal import Decimal, localcontext
from fractions import Fraction
from math import comb
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
U64_MAX = (1 << 64) - 1


def integer(value, name, minimum=0, maximum=None):
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ValueError(name)
    return value


def rational(value, name, minimum=Fraction(0), maximum=None):
    if type(value) not in (int, Fraction):
        raise ValueError(name)
    value = Fraction(value)
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(name)
    return value


def encoded(value):
    value = Fraction(value)
    with localcontext() as context:
        context.prec = 45
        decimal = str(Decimal(value.numerator) / Decimal(value.denominator))
    return {"numerator": value.numerator, "denominator": value.denominator,
            "decimal_rounded_for_display": decimal}


def target_probability(target, bits=256):
    integer(bits, "bits", 2, 256)
    integer(target, "target", 1, (1 << bits) - 1)
    return Fraction(target + 1, 1 << bits)


def required_work(target, bits=256):
    target_probability(target, bits)
    return (1 << bits) // (target + 1)


def expected_work_per_opportunity(target, bits=256):
    return target_probability(target, bits) * required_work(target, bits)


def retarget(parent, first, last, interval, spacing, pow_limit, bits=256):
    """Independent integer restatement of the inspected native reference rule."""
    target_probability(parent, bits)
    target_probability(pow_limit, bits)
    integer(first, "first", 0, U64_MAX)
    integer(last, "last", 0, U64_MAX)
    integer(interval, "interval", 16, U64_MAX)
    integer(spacing, "spacing", 1, U64_MAX)
    if parent > pow_limit:
        raise ValueError("parent above pow_limit")
    desired = integer((interval - 1) * spacing, "desired", 1, U64_MAX)
    upper = integer(desired * 4, "upper", 1, U64_MAX)
    lower = (desired + 3) // 4
    observed = max(lower, min(upper, max(1, last - first)))
    return max(1, min(pow_limit, parent * observed // desired))


def timestamp_verdict(candidate, ancestors_parent_first, now, skew):
    integer(candidate, "candidate", 0, U64_MAX)
    integer(now, "now", 0, U64_MAX)
    integer(skew, "skew", 0, U64_MAX)
    if not ancestors_parent_first:
        raise ValueError("UNKNOWN_PARENT")
    recent = sorted(integer(v, "ancestor", 0, U64_MAX) for v in ancestors_parent_first[:11])
    if candidate <= recent[len(recent) // 2]:
        return "TIME"
    return "accept" if candidate <= now + skew else "TIME_DEFERRED"


def effective_share(resource_fraction, kappa):
    q = rational(resource_fraction, "resource_fraction", maximum=Fraction(1))
    k = rational(kappa, "kappa", minimum=Fraction(1))
    return k * q / (1 - q + k * q)


def fixed_target_rates(resource_fraction, kappa, reference_hit_rate,
                       honest_active_fraction=Fraction(1)):
    """Declared constant Poisson rates only; no inference from benchmark means."""
    q = rational(resource_fraction, "resource_fraction", maximum=Fraction(1))
    k = rational(kappa, "kappa", minimum=Fraction(1))
    rate = rational(reference_hit_rate, "reference_hit_rate")
    active = rational(honest_active_fraction, "honest_active_fraction", maximum=Fraction(1))
    return rate * k * q, rate * (1 - q) * active


def delayed_region(adversary_rate, honest_rate, validated_delay):
    """Asymptotic fixed-target bounded-delay feasibility, not a depth certificate."""
    a = rational(adversary_rate, "adversary_rate")
    h = rational(honest_rate, "honest_rate")
    delay = rational(validated_delay, "validated_delay")
    if h == 0:
        return {"status": "no-honest-growth", "pacer_rate": Fraction(0), "margin": -a,
                "fixed_target_model_feasible": False}
    pacer = h / (1 + h * delay)
    margin = pacer - a
    return {"status": "strictly-inside" if margin > 0 else "boundary" if margin == 0 else "outside",
            "pacer_rate": pacer, "margin": margin,
            "fixed_target_model_feasible": margin > 0}


def kappa_ceiling(resource_fraction, reference_hit_rate, validated_delay,
                  honest_active_fraction=Fraction(1)):
    """Strict ceiling; equality is not certified. None for the q=0 vacuous case."""
    q = rational(resource_fraction, "resource_fraction", maximum=Fraction(1))
    rate = rational(reference_hit_rate, "reference_hit_rate")
    delay = rational(validated_delay, "validated_delay")
    active = rational(honest_active_fraction, "honest_active_fraction", maximum=Fraction(1))
    if q == 0:
        return None
    h_fraction = (1 - q) * active
    if rate == 0:
        return None  # zero arrivals are not a finite-security operating point
    return h_fraction / (q * (1 + h_fraction * rate * delay))


def bernoulli_count_pmf(trials, probability):
    integer(trials, "trials", 0, 2048)
    p = rational(probability, "probability", maximum=Fraction(1))
    return [Fraction(comb(trials, j)) * p**j * (1 - p)**(trials - j)
            for j in range(trials + 1)]


def grouped_or_pmf(group_sizes, probability):
    """At most one credited block per group, despite a multi-trial OR probability."""
    p = rational(probability, "probability", maximum=Fraction(1))
    if len(group_sizes) > 128:
        raise ValueError("group count")
    result = [Fraction(1)]
    for size in group_sizes:
        integer(size, "group_size", 1, 2048)
        success = 1 - (1 - p)**size
        following = [Fraction(0)] * (len(result) + 1)
        for count, mass in enumerate(result):
            following[count] += mass * (1 - success)
            following[count + 1] += mass * success
        result = following
    return result


def private_catchup_from_deficit(adversarial_event_fraction, deficit, tie_counts_as_success=False):
    """Exact zero-delay equal-weight independent race after a known state.

Native equal-work tip retention means strict heavier requires deficit+1 jumps.
The tie-success variant is a deliberately different worst-case race model.
"""
    q = rational(adversarial_event_fraction, "adversarial_event_fraction", maximum=Fraction(1))
    integer(deficit, "deficit", 0, 2048)
    if type(tie_counts_as_success) is not bool:
        raise ValueError("tie rule")
    hurdle = deficit + (0 if tie_counts_as_success else 1)
    if hurdle == 0 or q >= Fraction(1, 2):
        return Fraction(1)
    return (q / (1 - q))**hurdle


def private_attack_after_honest_wait(adversarial_event_fraction, honest_blocks,
                                   initial_private_blocks=0, tie_counts_as_success=False):
    """Negative-binomial premining plus exact subsequent private catchup.

This is the probability for this specified private strategy, not a worst-case
network/common-prefix upper bound. No hidden initial bank is set to zero.
"""
    q = rational(adversarial_event_fraction, "adversarial_event_fraction", maximum=Fraction(1))
    integer(honest_blocks, "honest_blocks", 1, 512)
    integer(initial_private_blocks, "initial_private_blocks", 0, 2048)
    if type(tie_counts_as_success) is not bool:
        raise ValueError("tie rule")
    if q == 1:
        raise ValueError("honest waiting time does not finish")
    threshold = honest_blocks - initial_private_blocks + (0 if tie_counts_as_success else 1)
    if threshold <= 0 or q >= Fraction(1, 2):
        return Fraction(1)
    before_threshold = Fraction(0)
    catchup_contribution = Fraction(0)
    for k in range(threshold):
        mass = Fraction(comb(honest_blocks + k - 1, k)) * (1 - q)**honest_blocks * q**k
        before_threshold += mass
        catchup_contribution += mass * (q / (1 - q))**(threshold - k)
    return 1 - before_threshold + catchup_contribution


def lead_mgf_upper(adversary_probability_upper, honest_extension_probability_lower,
                   adversary_weight, honest_weight, z):
    """One mutually exclusive A/H/idle step under predictable conditional bounds.

The honest predicate must already imply the asserted settled progress. Merely
finding an honest sibling or a header does not satisfy that premise.
"""
    a = rational(adversary_probability_upper, "adversary_probability_upper", maximum=Fraction(1))
    h = rational(honest_extension_probability_lower, "honest_extension_probability_lower", maximum=Fraction(1))
    if a + h > 1:
        raise ValueError("A/H/idle probabilities")
    integer(adversary_weight, "adversary_weight", 1, 4096)
    integer(honest_weight, "honest_weight", 1, 4096)
    z = rational(z, "z", minimum=Fraction(1))
    if z == 1:
        raise ValueError("z must exceed one")
    return 1 + a * (z**adversary_weight - 1) + h * (z**(-honest_weight) - 1)


def lead_crossing_bound(z, hurdle, initial_work_bank=0, failure_probability=Fraction(0)):
    """Conditional Ville bound, only if every pre-outcome MGF bound is <=1."""
    z = rational(z, "z", minimum=Fraction(1))
    if z == 1:
        raise ValueError("z must exceed one")
    integer(hurdle, "hurdle", 0, 4096)
    integer(initial_work_bank, "initial_work_bank", 0, 4096)
    epsilon = rational(failure_probability, "failure_probability", maximum=Fraction(1))
    if hurdle <= initial_work_bank:
        return Fraction(1)
    return min(Fraction(1), z**(initial_work_bank - hurdle) + epsilon)


def exact_adaptive_crossing(policy, rounds, hurdle, initial_work_bank=0):
    """Exact finite tree check of a declared conditional A/H/idle process."""
    integer(rounds, "rounds", 0, 12)
    integer(hurdle, "hurdle", 0, 4096)
    integer(initial_work_bank, "initial_work_bank", 0, 4096)
    if initial_work_bank >= hurdle:
        return Fraction(1)
    alive = {((), initial_work_bank): Fraction(1)}
    crossed = Fraction(0)
    for _ in range(rounds):
        following = {}
        for (history, lead), mass in alive.items():
            a, h, aw, hw = policy(history)
            # Validate without requiring the policy to meet any MGF certificate.
            lead_mgf_upper(a, h, aw, hw, Fraction(2))
            for label, probability, change in (("A", a, aw), ("H", h, -hw), ("I", 1 - a - h, 0)):
                if probability == 0:
                    continue
                next_lead = lead + change
                next_mass = mass * probability
                if next_lead >= hurdle:
                    crossed += next_mass
                else:
                    key = (history + (label,), next_lead)
                    following[key] = following.get(key, Fraction(0)) + next_mass
        alive = following
    if crossed + sum(alive.values()) != 1:
        raise AssertionError("probability conservation")
    return crossed


def model_report():
    config_path = "config/pon/devnet-v1.json"
    config = json.loads((ROOT / config_path).read_text())
    reviewed_parameters = {"target_spacing_seconds": 10, "retarget_interval": 16,
                           "median_time_width": 11, "retarget_factor": 4,
                           "future_skew_seconds": 120, "confirmation_depth": 6,
                           "confirmation_work_multiplier": 6}
    if config.get("production_activation") is not False or any(
            type(config.get(key)) is not int or config[key] != value
            for key, value in reviewed_parameters.items()):
        raise ValueError("unreviewed development consensus parameters")
    limit = int(config["pow_limit_hex"], 16)
    scale = 1 << 256
    if limit != scale // 2 - 1:
        raise ValueError("unreviewed development target limit")
    inspected = [config_path, "trillionnium/crates/trnm-pon-node/src/consensus.rs",
                 "docs/protocol/pon-nakamoto-v1/CONSENSUS.md"]
    geometry = []
    for label, target in [("devnet-pow-limit", limit), ("floor-efficiency-minimizer", scale // 3),
                          ("quarter-lottery", scale // 4 - 1), ("small-probability-example", scale // 1024 - 1),
                          ("hardest-positive-target", 1)]:
        geometry.append({"label": label, "target_hex": f"{target:064x}",
                         "probability": encoded(target_probability(target)),
                         "required_work": required_work(target),
                         "expected_work_per_opportunity": encoded(expected_work_per_opportunity(target))})
    delays = []
    for kappa in [Fraction(11, 10), Fraction(5, 4), Fraction(2), Fraction(4)]:
        for delay in [Fraction(0), Fraction(1), Fraction(10), Fraction(20)]:
            q, baseline = Fraction(1, 3), Fraction(1, 10)
            a, h = fixed_target_rates(q, kappa, baseline)
            region = delayed_region(a, h, delay)
            delays.append({"raw_resource_fraction": encoded(q), "kappa_assumed": encoded(kappa),
                           "reference_hit_rate_per_second_assumed": encoded(baseline),
                           "validated_delay_seconds_assumed": encoded(delay),
                           "adversary_rate": encoded(a), "honest_rate": encoded(h),
                           "effective_share": encoded(effective_share(q, kappa)),
                           "strict_kappa_ceiling": encoded(kappa_ceiling(q, baseline, delay)),
                           **{key: encoded(value) if isinstance(value, Fraction) else value for key, value in region.items()}})
    catchup = []
    for q in [Fraction(1, 10), Fraction(1, 4), Fraction(1, 3)]:
        catchup.append({"adversarial_event_fraction": encoded(q), "honest_wait_blocks": 6,
                        "strict_catchup_if_known_deficit_six": encoded(private_catchup_from_deficit(q, 6)),
                        "private_attack_including_wait_period": encoded(private_attack_after_honest_wait(q, 6)),
                        "private_attack_with_two_initial_blocks": encoded(private_attack_after_honest_wait(q, 6, 2)),
                        "full_chain_common_prefix_bound": False})
    z = Fraction(3, 2)
    def policy(history):
        return (Fraction(1, 10), Fraction(3, 5), 2, 1) if history and history[-1] == "H" else (Fraction(1, 5), Fraction(3, 10), 1, 1)
    parent = limit
    first_epoch = retarget(parent, 0, 15, 16, 10, limit)
    second_epoch = retarget(first_epoch, 16, 31, 16, 10, limit)
    daa = []
    for name, first, last in [("ordinary", 320, 470), ("lower", 32, 47), ("upper", 27, 627)]:
        target = retarget(second_epoch, first, last, 16, 10, limit)
        daa.append({"branch": name, "first": first, "last": last,
                    "next_target_hex": f"{target:064x}", "required_work": required_work(target),
                    "scope": "independent arithmetic reconstruction of existing native test schedule; not a new native execution"})
    return {"schema": "pon-w1-chain-security-envelope-v1", "production_activation": False,
            "O03_closed": False, "actual_W1_resource_bound_established": False,
            "all_adversarial_network_security_established": False,
            "executable_control_limits": {"adaptive_rounds": 12, "lead_weights": 4096, "lead_hurdle_or_bank": 4096, "honest_wait_blocks": 512, "private_initial_bank": 2048, "limits_are_not_protocol_rules": True},
            "source_bindings": [{"path": path, "sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest()} for path in inspected],
            "native_parameters": {key: config[key] for key in ["target_spacing_seconds", "retarget_interval", "future_skew_seconds", "confirmation_depth", "confirmation_work_multiplier", "production_activation"]},
            "target_work_geometry": geometry, "fixed_target_rate_sensitivity": delays,
            "private_attack_examples": catchup,
            "virtual_OR_countermodel": {"groups": [2], "probability": encoded(Fraction(1, 2)),
                                        "actual_block_count_pmf": [encoded(v) for v in grouped_or_pmf([2], Fraction(1, 2))],
                                        "virtual_trial_count_pmf": [encoded(v) for v in bernoulli_count_pmf(2, Fraction(1, 2))],
                                        "same_at_least_one_probability": True, "same_count_distribution": False},
            "conditional_adaptive_lead_control": {"z": encoded(z), "rounds": 8, "hurdle": 4,
                                                 "exact_crossing_probability": encoded(exact_adaptive_crossing(policy, 8, 4)),
                                                 "ville_upper_bound": encoded(lead_crossing_bound(z, 4)),
                                                 "step_mgf_values": [encoded(lead_mgf_upper(*policy(history), z)) for history in [(), ("H",)]],
                                                 "actual_Node_settlement_coupling_established": False},
            "reference_DAA_arithmetic": daa,
            "limitations": ["Rates, resource conversion, delay bound and process coupling are assumptions, not measured parameters.",
                            "Fixed-target asymptotic feasibility supplies neither confirmation depth nor variable-difficulty safety.",
                            "Mean kappa alone does not establish Poisson arrivals or conditional tail domination.",
                            "The lead certificate requires honest settled-progress lower bounds; raw honest sibling counts do not suffice.",
                            "Targets and weights must be fixed before the relevant fresh lottery reveal.",
                            "The entire preprocessing bank must be charged once across forks and epochs, never reset by DAA.",
                            "Reference DAA agreement and finite exact controls do not select production parameters."]}


if __name__ == "__main__":
    print(json.dumps(model_report(), indent=2, sort_keys=True, allow_nan=False))
