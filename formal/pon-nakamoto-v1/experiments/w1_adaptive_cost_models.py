"""Exact finite controls for W1 cost-game premises, not a W1 cost lower bound.

All costs below are declared abstract units. No native timing, hash-call physical
cost, GPU work, task eligibility or new protocol is inferred from them. The small
models deliberately allow shortcuts that a proposed reduction must account for.
They do not allege that current W1 has an unbound nonce or reusable hash floor.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from math import comb
from typing import Callable, Iterable
import json


MAX_EXACT_UNITS = 128


def _integer(value: int, name: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive):
        raise ValueError(f"{name} must be a {'positive' if positive else 'nonnegative'} integer")
    return value


def _small(value: int, name: str) -> int:
    _integer(value, name)
    if value > MAX_EXACT_UNITS:
        raise ValueError(f"{name} exceeds the finite exact-model cap")
    return value


def _rational(value: Fraction | int, name: str) -> Fraction:
    if type(value) not in (int, Fraction):
        raise ValueError(f"{name} must be exact: int or Fraction")
    return Fraction(value)


def _probability(value: Fraction | int, name: str = "probability") -> Fraction:
    result = _rational(value, name)
    if not 0 <= result <= 1:
        raise ValueError(f"{name} must lie in [0, 1]")
    return result


def binomial_pmf(queries: int, probability: Fraction) -> tuple[Fraction, ...]:
    """Finite exact independent-query distribution; no budget reduction supplied."""
    _small(queries, "queries")
    p = _probability(probability)
    return tuple(Fraction(comb(queries, k)) * p**k * (1 - p)**(queries - k)
                 for k in range(queries + 1))


def tail(pmf: tuple[Fraction, ...], winners_required: int) -> Fraction:
    _integer(winners_required, "winners_required")
    if not pmf or any(p < 0 for p in pmf) or sum(pmf) != 1:
        raise ValueError("pmf must be a normalized nonnegative finite distribution")
    return sum(pmf[winners_required:], Fraction())


def mean(pmf: tuple[Fraction, ...]) -> Fraction:
    tail(pmf, 0)
    return sum((k * p for k, p in enumerate(pmf)), Fraction())


def resource_query_cap(budget: int, query_cost: int,
                       finite_domain: int | None = None) -> int | None:
    """Declared scalar cost only; None means no finite resource-only cap.

    A zero observed/assumed charge cannot be silently replaced by one. A finite
    namespace can cap queries independently of resources, but supplies no lower
    bound on physical expenditure. This helper does not assert W1 has free work.
    """
    _integer(budget, "budget")
    _integer(query_cost, "query_cost")
    if finite_domain is not None:
        _integer(finite_domain, "finite_domain")
    if query_cost == 0:
        return finite_domain
    cap = budget // query_cost
    return min(cap, finite_domain) if finite_domain is not None else cap


def completed_query_bound(
    adversary_queries: int,
    unqueried_submissions: int,
    probability: Fraction,
    winners_required: int,
    *,
    fanout: int = 1,
    initial_credit_cap: int = 0,
) -> Fraction:
    """Conditional binomial bound after completing previously unqueried inputs.

    Q and G are deterministic caps on distinct fresh adversary queries and distinct
    unqueried output inputs. Each answer has conditional hit probability <= p.
    At most `fanout` counted outcomes map to each hit; `initial_credit_cap` bounds
    outcomes supported by already revealed winning inputs, including witnesses
    still to be completed online. It is a capacity bound, not a count of verified
    initial proofs. Already credited identities cannot be credited a second time.
    Binding/validity failures need their own additional error term. This function
    does not prove any of those premises, nor the physical cost of Q, G or the bank.
    """
    _small(adversary_queries, "adversary_queries")
    _small(unqueried_submissions, "unqueried_submissions")
    _integer(winners_required, "winners_required")
    _integer(initial_credit_cap, "initial_credit_cap")
    _integer(fanout, "fanout", positive=True)
    p = _probability(probability)
    queries = _small(adversary_queries + unqueried_submissions, "completed queries")
    needed = winners_required - initial_credit_cap
    if needed <= 0:
        return Fraction(1)
    return tail(binomial_pmf(queries, p), (needed + fanout - 1) // fanout)


def cached_context_lottery(
    queries_per_context: tuple[int, ...], probability: Fraction
) -> dict[str, Fraction | int]:
    """A bank of already paid queries, then uniform or adversarial context choice.

    The fresh context is uniform and independent of this bank. The selectable
    context may instead be chosen after seeing the bank's target outcomes. These
    are different games. Query costs and initial winning credits remain visible.
    """
    if not queries_per_context:
        raise ValueError("at least one context is required")
    for q in queries_per_context:
        _small(q, "cached queries")
    total = _small(sum(queries_per_context), "total cached queries")
    p = _probability(probability)
    count = len(queries_per_context)
    return {
        "prepaid_queries": total,
        "contexts": count,
        "uniform_fresh_context_at_least_one":
            sum((1 - (1 - p)**q for q in queries_per_context), Fraction()) / count,
        "uniform_fresh_context_expected_winners": Fraction(total, count) * p,
        "chosen_context_at_least_one": 1 - (1 - p)**total,
    }


def fresh_context_bank_overlap_bound(
    prequeried_contexts: int, min_entropy_bits: int, releases: int = 1
) -> Fraction:
    """Union bound ONLY under the stated conditional min-entropy premise.

    For each release, given the earlier information and the fixed preparation
    bank, every context has probability <= 2^-h. Choosing a previously seen
    favorable context does not satisfy that premise. This bounds overlap, not
    useful-work cost and not the success probability conditional on overlap.
    """
    _integer(prequeried_contexts, "prequeried_contexts")
    _small(min_entropy_bits, "min_entropy_bits")
    _integer(releases, "releases")
    return min(Fraction(1), Fraction(prequeried_contexts * releases, 2**min_entropy_bits))


def _mix(left: tuple[Fraction, ...], right: tuple[Fraction, ...], p: Fraction
         ) -> tuple[Fraction, ...]:
    size = max(len(left), len(right))
    return tuple(p * (left[k] if k < len(left) else 0)
                 + (1 - p) * (right[k] if k < len(right) else 0)
                 for k in range(size))


def hybrid_budget_distribution(
    budget: int,
    useful_cost: int,
    floor_cost: int,
    probability: Fraction,
    schedule: str,
) -> tuple[Fraction, ...]:
    """Exact declared schedules for a hypothetical AND construction.

    fresh-every-query recomputes useful work on every failed floor nonce.
    reuse-until-success consumes a useful statement after its first success, but
    reuses it on floor misses. reuse-many-credits lets new floor nonces credit
    many distinct statements backed by one useful computation. These schedules
    must not be assigned the same additive per-opportunity cost by assumption.
    """
    _small(budget, "budget")
    _integer(useful_cost, "useful_cost", positive=True)
    _integer(floor_cost, "floor_cost", positive=True)
    p = _probability(probability)
    if schedule == "fresh-every-query":
        return binomial_pmf(budget // (useful_cost + floor_cost), p)
    if schedule == "reuse-many-credits":
        queries = max(0, (budget - useful_cost) // floor_cost)
        return binomial_pmf(queries, p)
    if schedule != "reuse-until-success":
        raise ValueError("unknown hybrid schedule")
    # State is one available useful statement, or no available useful statement.
    # A win consumes it. Ascending budgets keep this exact DP acyclic.
    absent: list[tuple[Fraction, ...]] = []
    ready: list[tuple[Fraction, ...]] = []
    for b in range(budget + 1):
        absent.append(ready[b - useful_cost] if b >= useful_cost else (Fraction(1),))
        if b < floor_cost:
            ready.append((Fraction(1),))
        else:
            won = (Fraction(),) + absent[b - floor_cost]
            ready.append(_mix(won, ready[b - floor_cost], p))
    return absent[budget]


def hybrid_first_win_costs(useful_cost: int, floor_cost: int,
                          probability: Fraction) -> dict[str, Fraction]:
    """Untruncated mean cost, independent floor answers and positive success p."""
    _integer(useful_cost, "useful_cost", positive=True)
    _integer(floor_cost, "floor_cost", positive=True)
    p = _probability(probability)
    if p == 0:
        raise ValueError("zero success probability has no finite first-win mean")
    return {
        "fresh-every-query": Fraction(useful_cost + floor_cost) / p,
        "reuse-until-success": Fraction(useful_cost) + Fraction(floor_cost) / p,
    }


@dataclass(frozen=True)
class ScreenClass:
    """A cheap public signal, remaining completion cost and conditional hit rate.

    These are declared model parameters, not inferred W1 distributions. If the
    signal reveals the target outcome, the conditional rate can be zero or one;
    the query which produced that information still belongs to the ledger.
    """

    name: str
    frequency: Fraction
    completion_cost: int
    hit_probability: Fraction


def optimal_screening_value(
    budget: int,
    screen_cost: int,
    classes: tuple[ScreenClass, ...],
    *,
    winners_required: int | None = None,
) -> Fraction:
    """Exact optimal finite-policy value with paid screening and optional discard.

    Draws of a public class are independent, as are outcomes conditional on class.
    The adversary observes class before deciding to finish or discard. All later
    decisions may depend on remaining budget and winners still needed. For None
    optimize expected count; otherwise optimize the stated tail event. Different
    tail thresholds can have different optimal policies: results are not one PMF.
    """
    _small(budget, "budget")
    _integer(screen_cost, "screen_cost", positive=True)
    if not classes or len({c.name for c in classes}) != len(classes):
        raise ValueError("nonempty classes with unique names are required")
    for c in classes:
        if not isinstance(c.name, str) or not c.name:
            raise ValueError("class name must be nonempty")
        _probability(c.frequency, "class frequency")
        _probability(c.hit_probability, "conditional hit probability")
        _integer(c.completion_cost, "completion_cost")
    if sum(c.frequency for c in classes) != 1:
        raise ValueError("class frequencies must sum exactly to one")
    if winners_required is not None:
        _small(winners_required, "winners_required")
    width = 1 if winners_required is None else winners_required + 1
    values = [[Fraction() for _ in range(width)] for _ in range(budget + 1)]
    for b in range(budget + 1):
        if winners_required is not None:
            values[b][0] = Fraction(1)
        if b < screen_cost:
            continue
        after_screen = b - screen_cost
        for k in range(0 if winners_required is None else 1, width):
            result = Fraction()
            for c in classes:
                skip = values[after_screen][k]
                best = skip
                if c.completion_cost <= after_screen:
                    remaining = after_screen - c.completion_cost
                    if winners_required is None:
                        finish = c.hit_probability + values[remaining][0]
                    else:
                        finish = (c.hit_probability * values[remaining][k - 1]
                                  + (1 - c.hit_probability) * values[remaining][k])
                    best = max(skip, finish)
                result += c.frequency * best
            values[b][k] = result
    return values[budget][-1]


@dataclass(frozen=True)
class PredictableReveal:
    """p and weight must be fixed before this fresh answer, given prior history.

    A serialized record alone cannot prove predictability. All screening queries
    and virtual verifier queries count; filtering out misses invalidates the game.
    """

    probability_bound: Fraction
    weight: int
    hit: bool


def e_process_prefixes(reveals: Iterable[PredictableReveal], z: Fraction
                      ) -> tuple[Fraction, ...]:
    """Nonnegative supermartingale under the stated conditional premises.

    M_t = product z^(w_i Y_i) / (1-p_i+p_i*z^w_i), M_0=1.
    Actual conditional success <= p_i and predictable nonnegative weights imply
    E[M_t|past] <= M_(t-1). Ville bounds ANY crossing of 1/alpha by alpha.
    This is not a physical budget-to-query reduction or a full DAA security proof.
    """
    z = _rational(z, "z")
    if z < 1:
        raise ValueError("z must be at least one")
    result = [Fraction(1)]
    for step in reveals:
        p = _probability(step.probability_bound)
        _small(step.weight, "weight")
        if type(step.hit) is not bool:
            raise ValueError("hit must be boolean")
        weighted_z = z**step.weight
        factor = (weighted_z if step.hit else 1) / (1 - p + p * weighted_z)
        result.append(result[-1] * factor)
    return tuple(result)


def enumerate_predictable_policy(
    horizon: int,
    policy: Callable[[tuple[bool, ...]], tuple[Fraction, Fraction, int]],
    *,
    z: Fraction,
    boundary: Fraction,
) -> dict[str, Fraction]:
    """Exhaust a small outcome tree; policy receives only earlier outcomes.

    Policy returns (actual success probability, predictable bound, weight).
    Enumeration verifies a specified finite tree, not all predictable processes.
    """
    _integer(horizon, "horizon")
    if horizon > 12:
        raise ValueError("horizon exceeds small exhaustive-control limit")
    z = _rational(z, "z")
    if z < 1:
        raise ValueError("z must be at least one")
    boundary = _rational(boundary, "boundary")
    if boundary < 1:
        raise ValueError("boundary must be at least one")
    mass = mean_terminal = crossing = Fraction()

    def visit(history: tuple[bool, ...], prob: Fraction, value: Fraction,
              crossed: bool) -> None:
        nonlocal mass, mean_terminal, crossing
        if len(history) == horizon:
            mass += prob
            mean_terminal += prob * value
            crossing += prob * crossed
            return
        actual, bound, weight = policy(history)
        actual, bound = _probability(actual), _probability(bound)
        if actual > bound:
            raise ValueError("policy violates its conditional probability premise")
        for hit, chance in ((False, 1 - actual), (True, actual)):
            if not chance:
                continue
            factor = e_process_prefixes((PredictableReveal(bound, weight, hit),), z)[-1]
            new_value = value * factor
            visit(history + (hit,), prob * chance, new_value,
                  crossed or new_value >= boundary)

    visit((), Fraction(1), Fraction(1), boundary <= 1)
    return {"total_probability": mass, "mean_terminal_e_value": mean_terminal,
            "any_crossing_probability": crossing, "ville_bound": 1 / boundary}


def _jsonable(value):
    if isinstance(value, Fraction):
        return str(value)
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def research_report() -> dict:
    p = Fraction(1, 2)
    schedules = {}
    for schedule in ("fresh-every-query", "reuse-until-success", "reuse-many-credits"):
        distribution = hybrid_budget_distribution(20, 9, 1, p, schedule)
        schedules[schedule] = {"distribution": distribution,
                               "expected_winners": mean(distribution),
                               "at_least_two": tail(distribution, 2)}
    selected_signal = (ScreenClass("revealed-miss", 1 - p, 8, Fraction()),
                       ScreenClass("revealed-hit", p, 8, Fraction(1)))
    cost_signal = (ScreenClass("cheap", p, 1, p),
                   ScreenClass("expensive", 1 - p, 9, p))

    def policy(history):
        probability = Fraction(1, 4) if sum(history) % 2 else Fraction(1, 2)
        weight = 2 if history and history[-1] else 1
        return probability, probability, weight

    return _jsonable({
        "schema": "pon-w1-adaptive-cost-models-v1",
        "scope": "exact finite abstract-resource models and conditional counterexamples",
        "native_measurement": False,
        "current_W1_vulnerability_demonstrated": False,
        "universal_cost_bound_established": False,
        "production_activation": False,
        "unqueried_submission": {
            "adversary_queries": 0, "distinct_unqueried_outputs": 1, "p": p,
            "correct_query_completed_bound": completed_query_bound(0, 1, p, 1),
            "incorrect_adversary_query_only_bound": completed_query_bound(0, 0, p, 1),
        },
        "floor_fanout": {
            "fresh_queries": 1, "outcomes_per_success": 3, "threshold": 2,
            "correct_tail": completed_query_bound(1, 0, p, 2, fanout=3),
            "incorrect_injective_tail": completed_query_bound(1, 0, p, 2),
        },
        "preprocessing_bank": cached_context_lottery((2, 0, 0, 0), p),
        "known_initial_credit_with_zero_online_queries": completed_query_bound(
            0, 0, p, 1, initial_credit_cap=1),
        "zero_cost_fresh_queries_without_namespace_cap": resource_query_cap(0, 0),
        "hypothetical_hybrid": {
            "budget": 20, "useful_cost": 9, "floor_cost": 1, "p": p,
            "first_win_mean_cost": hybrid_first_win_costs(9, 1, p),
            "finite_budget_schedules": schedules,
        },
        "screening": {
            "perfectly_revealed_target_budget_12_screen_1_completion_8":
                optimal_screening_value(12, 1, selected_signal, winners_required=1),
            "incorrect_one_completed_candidate_unconditional_p": p,
            "cost_signal_budget_6_expected_winners":
                optimal_screening_value(6, 1, cost_signal),
            "cost_signal_budget_6_at_least_two":
                optimal_screening_value(6, 1, cost_signal, winners_required=2),
        },
        "predictable_weighted_tail_control": enumerate_predictable_policy(
            5, policy, z=Fraction(3), boundary=Fraction(4)),
        "not_closed": [
            "W1 resource budget to fresh effective opportunities",
            "real conditional target-information leakage or seed-cost distribution",
            "preprocessing/advice and initial-credit limits for a real parent forest",
            "physical hash floor cost and composition with useful computation",
            "all adversaries/hardware, honest chain growth, DAA and network security",
        ],
    })


if __name__ == "__main__":
    print(json.dumps(research_report(), indent=2, sort_keys=True))
