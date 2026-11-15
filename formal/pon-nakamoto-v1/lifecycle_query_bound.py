"""LQC1: lifetime classical-prefix/coherent-query bounds for frozen MU1.

These are exact rational consequences of the ideal terminal-oracle model in
lifecycle_query_charging_v1.md.  Caps and complete-prefix parameters are
assumptions, not facts authenticated by their Python types or an observation.
No existing MU1 byte, native score, or physical work claim is changed.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from math import comb

from mandatory_units_query import bernoulli_bounds
from mandatory_units_relation import IDEAL_TICKET_PROBABILITY, MAX_CREDIT


TERMINAL_DOMAIN_SIZE = 1 << 512
MAX_FULL_QUERIES = 4096
MAX_OUTPUTS = 64


def integer(value: int, code: str, maximum: int, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(code)
    return value


def probability(p: Fraction) -> None:
    if type(p) is not Fraction or not 0 < p < 1:
        raise ValueError("BERNOULLI_PROBABILITY")


def mu1_probability(p: Fraction) -> None:
    probability(p)
    if p != IDEAL_TICKET_PROBABILITY:
        raise ValueError("FROZEN_MU1_TERMINAL_PROBABILITY")


@dataclass(frozen=True)
class LifetimeCaps:
    """Hard caps declared before the ideal oracle/execution, not measured totals.

    C counts distinct complete classical revelations before the *coalition's*
    first coherent query. Q counts every remaining noncached full-value oracle
    call by that same coalition, including public helpers and preprocessing.
    All intermediate complete outputs share M. These conditions are external.
    """
    classical_prefix_C: int
    post_prefix_Q: int
    complete_outputs_M: int
    domain_size: int = TERMINAL_DOMAIN_SIZE

    def check(self) -> None:
        integer(self.classical_prefix_C, "PREFIX_CAP", MAX_FULL_QUERIES)
        integer(self.post_prefix_Q, "POST_PREFIX_CAP", MAX_FULL_QUERIES)
        integer(self.complete_outputs_M, "OUTPUT_CAP", MAX_OUTPUTS)
        integer(self.domain_size, "DOMAIN_SIZE", TERMINAL_DOMAIN_SIZE)
        if self.classical_prefix_C + self.post_prefix_Q > MAX_FULL_QUERIES:
            raise ValueError("FINITE_TOTAL_QUERY_CHECK_LIMIT")


def binomial_tail(trials: int, required: int, p: Fraction) -> Fraction:
    integer(trials, "BINOMIAL_TRIALS", MAX_FULL_QUERIES + MAX_OUTPUTS)
    integer(required, "BINOMIAL_REQUIRED", (1 << 64) - 1)
    probability(p)
    if required == 0:
        return Fraction(1)
    if required > trials:
        return Fraction(0)
    if required <= trials // 2:
        return 1 - sum((Fraction(comb(trials, s)) * p ** s * (1 - p) ** (trials - s)
                        for s in range(required)), Fraction(0))
    return sum((Fraction(comb(trials, s)) * p ** s * (1 - p) ** (trials - s)
                for s in range(required, trials + 1)), Fraction(0))


def fixed_list_bound(bit_queries: int, output_slots: int, required: int,
                     p: Fraction = IDEAL_TICKET_PROBABILITY) -> Fraction:
    """At least k distinct marked addresses in <=M outputs, including guesses.

    For each FIXED k-index subset, extract its k addresses without reading the
    oracle; incomplete slots abort. The recording theorem bounds this strategy.
    Union over C(M,k) subsets pays for not identifying which addresses win.
    Real online membership/acceptance feedback still costs oracle queries.
    """
    integer(bit_queries, "BIT_QUERY_CAP", 2 * MAX_FULL_QUERIES)
    integer(output_slots, "OUTPUT_CAP", MAX_OUTPUTS)
    integer(required, "REQUIRED_SUCCESSES", (1 << 64) - 1)
    probability(p)
    if required == 0:
        return Fraction(1)
    if required > output_slots:
        return Fraction(0)
    return min(Fraction(1), comb(output_slots, required)
               * bernoulli_bounds(bit_queries, required, p)["bound"])


def _continuation(*, distinct_seen: int, marked_seen: int, post_queries: int,
                  output_slots: int, required: int, domain_size: int,
                  p: Fraction) -> dict[str, object]:
    """Internal unweighted marked-address game after a COMPLETE prefix."""
    if required == 0:
        value, slots, deficit = Fraction(1), 0, 0
    elif required > output_slots or required > domain_size:
        value, slots, deficit = Fraction(0), 0, required
    elif marked_seen >= required:
        value, slots, deficit = Fraction(1), 0, 0
    else:
        deficit = required - marked_seen
        slots = min(domain_size - distinct_seen, output_slots - marked_seen)
        # Oracle-free augmentation adds all s known winners and drops at most
        # s-r unknowns. Even if every dropped unknown wins, success cannot fall.
        # This is a relaxed final-output game, not revocation of real publishes.
        value = (binomial_tail(slots, deficit, p) if post_queries == 0 else
                 fixed_list_bound(2 * post_queries, slots, deficit, p))
    return {"bound": value, "unknown_output_slots": slots,
            "required_unknown_successes": deficit,
            "exact_relaxed_game_when_Q_zero": post_queries == 0}


def continuation_given_complete_prefix(*, distinct_seen: int, marked_seen: int,
                                       post_queries: int, output_slots: int,
                                       credit: int,
                                       domain_size: int = TERMINAL_DOMAIN_SIZE,
                                       p: Fraction = IDEAL_TICKET_PROBABILITY) -> dict:
    """Conditional bound with ACTUAL s, never a fresh Bin(C,p) reset.

    The caller must prove the prefix covers the whole coalition, that its
    complete joint state is independent of the untouched oracle conditional
    on the full prefix, and that Q/M hold uniformly on every continuation.
    Numeric validation does not establish any of those facts.
    """
    integer(domain_size, "DOMAIN_SIZE", TERMINAL_DOMAIN_SIZE)
    integer(distinct_seen, "DISTINCT_SEEN", min(MAX_FULL_QUERIES, domain_size))
    integer(marked_seen, "MARKED_SEEN", distinct_seen)
    integer(post_queries, "POST_PREFIX_CAP", MAX_FULL_QUERIES)
    integer(output_slots, "OUTPUT_CAP", MAX_OUTPUTS)
    integer(credit, "CREDIT_THRESHOLD", (1 << 64) - 1)
    mu1_probability(p)
    required = (credit + MAX_CREDIT - 1) // MAX_CREDIT
    return {
        "model": "mu1-complete-classical-prefix-continuation-v1",
        "probability_scope": "conditional_on_complete_coalition_prefix",
        "p": p, "maximum_identity_credit": MAX_CREDIT,
        "credit_threshold": credit, "required_distinct_successes": required,
        "actual_distinct_seen": distinct_seen, "actual_marked_seen": marked_seen,
        "post_prefix_Q": post_queries, "complete_outputs_M": output_slots,
        "domain_size": domain_size,
        **_continuation(distinct_seen=distinct_seen, marked_seen=marked_seen,
                        post_queries=post_queries, output_slots=output_slots,
                        required=required, domain_size=domain_size, p=p),
        **UNATTESTED,
    }


def global_lifecycle_weight_bound(caps: LifetimeCaps, credit: int,
                                  p: Fraction = IDEAL_TICKET_PROBABILITY) -> dict:
    """Global lifetime bound, averaging padded prefix S BEFORE conditioning.

    All preprocessing, helpers, quantum memory and later restarts form ONE
    joint strategy from a terminal-oracle-independent initial state. Prefix
    stop time is <=C on every path; pad by gifting fresh unused revelations.
    Domain exhaustion is handled exactly, not by assuming an infinite oracle.
    """
    if type(caps) is not LifetimeCaps:
        raise ValueError("LIFETIME_CAPS_TYPE")
    caps.check()
    integer(credit, "CREDIT_THRESHOLD", (1 << 64) - 1)
    mu1_probability(p)
    c = min(caps.classical_prefix_C, caps.domain_size)
    q, m, domain = caps.post_prefix_Q, caps.complete_outputs_M, caps.domain_size
    k = (credit + MAX_CREDIT - 1) // MAX_CREDIT
    rows = []
    if k == 0:
        convolution = all_coherent = Fraction(1)
    elif k > m or k > domain:
        convolution = all_coherent = Fraction(0)
    else:
        # s>=k contributes one; retain its exact binomial tail as one row.
        known_sufficient = binomial_tail(c, k, p)
        convolution = known_sufficient
        for s in range(min(c, k - 1) + 1):
            mass = Fraction(comb(c, s)) * p ** s * (1 - p) ** (c - s)
            given = _continuation(distinct_seen=c, marked_seen=s, post_queries=q,
                                  output_slots=m, required=k, domain_size=domain, p=p)
            convolution += mass * given["bound"]
            rows.append({"known_successes_s": s, "global_prefix_probability": mass,
                         **given})
        rows.append({"known_successes_at_least": k,
                     "global_prefix_probability": known_sufficient, "bound": Fraction(1)})
        all_coherent = fixed_list_bound(2 * (c + q), min(m, domain), k, p)
    return {
        "model": "mu1-ideal-lifetime-prefix-list-v1",
        "probability_scope": "global_unconditioned_from_independent_joint_initial_state",
        "p": p, "maximum_identity_credit": MAX_CREDIT,
        "credit_threshold": credit, "required_distinct_successes": k,
        "classical_prefix_cap_C": caps.classical_prefix_C,
        "padded_distinct_prefix_C_effective": c,
        "post_prefix_cap_Q": q, "complete_outputs_cap_M": m,
        "terminal_domain_size": domain,
        "prefix_convolution_bound": convolution,
        "all_coherent_list_bound": all_coherent,
        "bound": min(convolution, all_coherent),
        "prefix_cases": rows,
        "virtual_output_queries_added": 0,
        "global_prefix_law_may_be_reused_at_observed_start": False,
        **UNATTESTED,
    }


UNATTESTED = {
    "input_parameters_attest_full_lifetime_query_coverage": False,
    "input_parameters_attest_complete_joint_initial_state": False,
    "hidden_inventory_output_extraction_and_cap_attested": False,
    "actual_sha_independent_uniform_tickets_proved": False,
    "mandatory_u_minimum_gate_cost_proved": False,
    "physical_resource_tail_proved": False,
    "native_identity_and_weight_bridge_proved": False,
    "native_six_successor_risk_certified": False,
    "production_qualified": False,
}
