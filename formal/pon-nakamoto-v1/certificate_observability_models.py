"""Exact observability countermodels and shared-lifetime risk accounting.

All laws and ready cuts in this module are explicit mathematical inputs. The
module does not authenticate a native clock, complete private inventory,
physical resource budget, or a joint quantum residual-state certificate.
See CERTIFICATE_OBSERVABILITY_V1.md for the proved implications and boundaries.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
from math import comb

from mandatory_units_query import (QueryBudget, bernoulli_bounds,
                                   quantum_weight_bound, residual_bernoulli_bound)


BASE_COMMIT = "f8362822b406463ac3dfcc911a0c3eda1686e32d"
MAX_ROWS = 512
MAX_WINDOWS = 64


class ObservabilityError(ValueError):
    """A failed finite arithmetic/record claim, never a native Invalid verdict."""


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ObservabilityError(code)


def integer(value: int, code: str, *, minimum: int = 0) -> int:
    require(type(value) is int and value >= minimum, code)
    return value


def rational(value: Fraction, code: str, *, upper: Fraction | None = None) -> Fraction:
    require(type(value) is Fraction and value >= 0 and (upper is None or value <= upper), code)
    return value


def label(value: str, code: str) -> str:
    require(type(value) is str and 0 < len(value) <= 128, code)
    return value


def public_json(value):
    """Lossless rational encoding; no float is used to decide a certificate."""
    if type(value) is Fraction:
        return {"numerator": value.numerator, "denominator": value.denominator}
    if type(value) is dict:
        return {key: public_json(item) for key, item in value.items()}
    if type(value) in (tuple, list):
        return [public_json(item) for item in value]
    return value


def canonical(value) -> bytes:
    return json.dumps(public_json(value), sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


@dataclass(frozen=True)
class ReadyDelivery:
    identity: str
    cut: int
    credit: int


@dataclass(frozen=True)
class Window:
    name: str
    start: int
    end: int
    required_new_credit: Fraction


class UniqueReadyLedger:
    """Declared ancestor-complete ready accounting, not admission-time inference.

    A repeated delivery preserves the FIRST ready cut and adds no credit.
    Conflicting credit for an identity is refused. Actual work validity and
    completeness of the supplied global universe remain separate obligations.
    """
    def __init__(self, deliveries: tuple[ReadyDelivery, ...], maximum_credit: int = 128):
        integer(maximum_credit, "MAXIMUM_CREDIT", minimum=1)
        require(type(deliveries) is tuple and len(deliveries) <= MAX_ROWS, "DELIVERY_LIMIT")
        self.outputs: dict[str, ReadyDelivery] = {}
        previous = -1
        self.duplicate_deliveries = 0
        for row in deliveries:
            require(type(row) is ReadyDelivery, "DELIVERY_TYPE")
            label(row.identity, "OUTPUT_IDENTITY")
            integer(row.cut, "READY_CUT")
            integer(row.credit, "OUTPUT_CREDIT", minimum=1)
            require(row.credit <= maximum_credit, "OUTPUT_CREDIT_CAP")
            require(row.cut > previous, "DELIVERY_CAUSAL_ORDER")
            previous = row.cut
            prior = self.outputs.get(row.identity)
            if prior is not None:
                require(prior.credit == row.credit, "IDENTITY_CREDIT_CONFLICT")
                self.duplicate_deliveries += 1
            else:
                self.outputs[row.identity] = row
        self.maximum_credit = maximum_credit

    @property
    def total(self) -> int:
        return sum(row.credit for row in self.outputs.values())

    def new_credit(self, window: Window) -> int:
        return sum(row.credit for row in self.outputs.values()
                   if window.start < row.cut <= window.end)


def _windows(windows: tuple[Window, ...]) -> None:
    require(type(windows) is tuple and 0 < len(windows) <= MAX_WINDOWS, "WINDOW_LIMIT")
    names = set()
    for window in windows:
        require(type(window) is Window, "WINDOW_TYPE")
        label(window.name, "WINDOW_NAME")
        require(window.name not in names, "DUPLICATE_WINDOW_NAME")
        names.add(window.name)
        integer(window.start, "WINDOW_START")
        integer(window.end, "WINDOW_END")
        require(window.start < window.end, "WINDOW_ORDER")
        rational(window.required_new_credit, "WINDOW_THRESHOLD")


def interval_packing(windows: tuple[Window, ...], multipliers: tuple[Fraction, ...]) -> dict:
    """Check dual coverage over EVERY possible integer causal cut.

    For intervals (start,end], changes occur at start+1 and end+1. This sweep
    does not certify coverage merely by inspecting the observed output atoms.
    Multipliers may be selected retrospectively; a probability statement must
    compare their resulting margin with a fixed prior event threshold.
    """
    _windows(windows)
    require(type(multipliers) is tuple and len(multipliers) == len(windows), "MULTIPLIER_COUNT")
    changes: dict[int, Fraction] = {}
    for window, weight in zip(windows, multipliers):
        rational(weight, "NEGATIVE_MULTIPLIER")
        changes[window.start + 1] = changes.get(window.start + 1, Fraction(0)) + weight
        changes[window.end + 1] = changes.get(window.end + 1, Fraction(0)) - weight
    running = maximum = Fraction(0)
    segments = []
    for cut in sorted(changes):
        running += changes[cut]
        require(running >= 0, "INTERNAL_COVERAGE")
        maximum = max(maximum, running)
        segments.append({"from_cut": cut, "coverage": running})
    require(running == 0, "INTERNAL_COVERAGE")
    require(maximum <= 1, "OVERLAP_REUSES_GLOBAL_CREDIT")
    margin = sum((weight * window.required_new_credit
                  for window, weight in zip(windows, multipliers)), Fraction(0))
    return {"maximum_point_coverage": maximum, "global_credit_margin": margin,
            "coverage_segments": segments, "coverage_includes_unobserved_cuts": True}


def check_window_witness(ledger: UniqueReadyLedger, windows: tuple[Window, ...],
                         multipliers: tuple[Fraction, ...], fixed_threshold: Fraction) -> dict:
    rational(fixed_threshold, "FIXED_EVENT_THRESHOLD")
    packing = interval_packing(windows, multipliers)
    credits = tuple(ledger.new_credit(window) for window in windows)
    require(all(credit >= window.required_new_credit
                for credit, window in zip(credits, windows)), "WINDOW_REQUIREMENT_UNSATISFIED")
    weighted_actual = sum((weight * credit for weight, credit in zip(multipliers, credits)),
                          Fraction(0))
    require(packing["global_credit_margin"] <= weighted_actual <= ledger.total,
            "GLOBAL_LEDGER_INCLUSION")
    require(packing["global_credit_margin"] >= fixed_threshold, "FIXED_THRESHOLD_NOT_REACHED")
    return {**packing, "window_new_credits": credits,
            "weighted_actual_credit": weighted_actual, "global_unique_credit": ledger.total,
            "duplicate_deliveries_add_zero": ledger.duplicate_deliveries,
            "fixed_event_threshold": fixed_threshold, "pathwise_event_inclusion_checked": True,
            "actual_global_ready_coverage_attested": False,
            "native_work_identity_and_weight_attested": False}


def global_mu1_event_bound(budget: QueryBudget, fixed_threshold: Fraction) -> dict:
    """Fresh-lifetime bound for the unconditioned existence of a valid witness.

    It bounds ANY adaptively selected checked window packing with margin at
    least fixed_threshold, if the same MU1 identity/weight/global-budget law
    holds. It is not a new conditional theorem at each window's start.
    """
    rational(fixed_threshold, "FIXED_EVENT_THRESHOLD")
    integer_threshold = ((fixed_threshold.numerator + fixed_threshold.denominator - 1)
                         // fixed_threshold.denominator)
    return {"event": "exists valid shared-lifetime window witness above fixed threshold",
            "fixed_event_threshold": fixed_threshold,
            "fresh_global_bound": quantum_weight_bound(budget, integer_threshold),
            "window_count_union_factor": 1,
            "independence_between_windows_required": False,
            "post_selection_conditional_probability": False,
            "actual_physical_budget_attested": False,
            "native_confirmation_risk_qualified": False}


@dataclass(frozen=True)
class Leaf:
    name: str
    path: tuple[str, ...]
    probability: Fraction


@dataclass(frozen=True)
class Attempt:
    name: str
    start_history: tuple[str, ...]
    failure_leaves: tuple[str, ...]
    allowance: Fraction


def _prefix(prefix: tuple[str, ...], path: tuple[str, ...]) -> bool:
    return path[:len(prefix)] == prefix


class ProbabilityTree:
    """A complete declared finite probability law, not fitted native evidence."""
    def __init__(self, leaves: tuple[Leaf, ...]):
        require(type(leaves) is tuple and 0 < len(leaves) <= MAX_ROWS, "PROBABILITY_TREE_LIMIT")
        self.leaves: dict[str, Leaf] = {}
        self.nodes: set[tuple[str, ...]] = {()}
        paths = []
        for leaf in leaves:
            require(type(leaf) is Leaf, "LEAF_TYPE")
            label(leaf.name, "LEAF_NAME")
            require(leaf.name not in self.leaves, "DUPLICATE_LEAF")
            require(type(leaf.path) is tuple and 0 < len(leaf.path) <= 129, "HISTORY_PATH")
            for token in leaf.path:
                label(token, "HISTORY_TOKEN")
            rational(leaf.probability, "LEAF_PROBABILITY", upper=Fraction(1))
            require(leaf.probability > 0, "ZERO_PROBABILITY_LEAF")
            require(all(not _prefix(prior, leaf.path) and not _prefix(leaf.path, prior)
                        for prior in paths), "HISTORIES_NOT_PREFIX_FREE")
            paths.append(leaf.path)
            self.leaves[leaf.name] = leaf
            self.nodes.update(leaf.path[:i] for i in range(len(leaf.path) + 1))
        require(sum((leaf.probability for leaf in leaves), Fraction(0)) == 1,
                "PROBABILITY_MASS_NOT_ONE")

    def mass(self, history: tuple[str, ...]) -> Fraction:
        require(history in self.nodes, "UNKNOWN_START_HISTORY")
        return sum((leaf.probability for leaf in self.leaves.values()
                    if _prefix(history, leaf.path)), Fraction(0))


def check_predictable_risk_bank(law: ProbabilityTree, attempts: tuple[Attempt, ...],
                                total_allowance: Fraction) -> dict:
    """Compute conditional risks from the entire finite joint law.

    An allowance is fixed at a tree prefix, before its descendant outcome.
    Check every path's aggregate expenditure. Overlapping/correlated failure
    events are allowed; their union is measured under this original law.
    A self-declared conditional probability is not an accepted input.
    """
    rational(total_allowance, "TOTAL_ALLOWANCE", upper=Fraction(1))
    require(type(attempts) is tuple and len(attempts) <= MAX_WINDOWS, "ATTEMPT_LIMIT")
    names, union, rows = set(), set(), []
    for attempt in attempts:
        require(type(attempt) is Attempt, "ATTEMPT_TYPE")
        label(attempt.name, "ATTEMPT_NAME")
        require(attempt.name not in names, "DUPLICATE_ATTEMPT")
        names.add(attempt.name)
        require(type(attempt.start_history) is tuple, "START_HISTORY_TYPE")
        start_mass = law.mass(attempt.start_history)
        rational(attempt.allowance, "ATTEMPT_ALLOWANCE", upper=Fraction(1))
        require(type(attempt.failure_leaves) is tuple
                and len(set(attempt.failure_leaves)) == len(attempt.failure_leaves), "FAILURE_EVENT")
        failure_mass = Fraction(0)
        for name in attempt.failure_leaves:
            require(name in law.leaves, "UNKNOWN_FAILURE_LEAF")
            leaf = law.leaves[name]
            require(_prefix(attempt.start_history, leaf.path), "FAILURE_BEFORE_OR_OUTSIDE_START")
            failure_mass += leaf.probability
        conditional = failure_mass / start_mass
        require(conditional <= attempt.allowance, "INVALID_CONDITIONAL_RISK_AT_START")
        union.update(attempt.failure_leaves)
        rows.append({"attempt": attempt.name, "start_mass": start_mass,
                     "conditional_failure_probability": conditional, "allowance": attempt.allowance})
    path_spending = {
        leaf.name: sum((attempt.allowance for attempt in attempts
                       if _prefix(attempt.start_history, leaf.path)), Fraction(0))
        for leaf in law.leaves.values()
    }
    maximum_spent = max(path_spending.values())
    require(maximum_spent <= total_allowance, "PREDICTABLE_RISK_BUDGET_OVERSPENT")
    expected_spent = sum((law.mass(attempt.start_history) * attempt.allowance
                          for attempt in attempts), Fraction(0))
    union_probability = sum((law.leaves[name].probability for name in union), Fraction(0))
    require(union_probability <= expected_spent <= maximum_spent <= total_allowance,
            "JOINT_RISK_BANK_INEQUALITY")
    return {"conditional_checks": rows, "failure_union_probability": union_probability,
            "expected_allowance_spent": expected_spent,
            "maximum_path_allowance_spent": maximum_spent,
            "total_allowance": total_allowance,
            "all_declared_history_cells_checked": True,
            "independence_between_attempts_required": False,
            "actual_probability_law_authenticated": False,
            "actual_conditional_residual_potential_attested": False,
            "native_confirmation_risk_qualified": False}


def first_success_restart_counterexample(limit: int = 16,
                                          p: Fraction = Fraction(1, 16)) -> dict:
    """Exact stopped Bernoulli law: a known winner is not a fresh zero-query start."""
    integer(limit, "SEARCH_LIMIT", minimum=1)
    require(limit <= 64, "SEARCH_LIMIT")
    rational(p, "PROBABILITY", upper=Fraction(1))
    require(0 < p < 1, "PROBABILITY")
    leaves = tuple(Leaf("first_" + str(j + 1), ("miss",) * j + ("hit", "emit"),
                        (1 - p) ** j * p) for j in range(limit))
    leaves += (Leaf("abort", ("miss",) * limit + ("abort",), (1 - p) ** limit),)
    law = ProbabilityTree(leaves)
    wrong_fresh = bernoulli_bounds(1, 1, p)["bound"]  # zero full queries, one virtual output check
    wrong_attempts = tuple(Attempt("reset_" + leaf.name, leaf.path[:-1], (leaf.name,), wrong_fresh)
                           for leaf in leaves[:-1])
    refusal = None
    try:
        check_predictable_risk_bank(law, wrong_attempts, Fraction(1))
    except ObservabilityError as error:
        refusal = str(error)
    require(refusal == "INVALID_CONDITIONAL_RISK_AT_START", "MISSING_RESTART_COUNTEREXAMPLE")
    success = 1 - (1 - p) ** limit
    residual = residual_bernoulli_bound(0, 1, (Fraction(1), 1 - p), p)
    return {"model": "exact finite stopped Bernoulli search, not native SHA sampling",
            "preprocessing_query_cap": limit, "online_queries_after_selected_start": 0,
            "probability_a_start_exists": success,
            "conditional_success_at_every_selected_start": Fraction(1),
            "unpaid_fresh_restart_bound": wrong_fresh,
            "even_unconditional_reset_claim_violated": success > wrong_fresh,
            "risk_bank_refusal": refusal,
            "known_winner_joint_squared_tail": (Fraction(1), 1 - p),
            "proper_conditional_residual_bound": residual["bound"],
            "global_lifetime_query_bound": bernoulli_bounds(2 * limit + 1, 1, p)["bound"],
            "actual_physical_or_native_risk_estimate": False}


def binomial_tail(trials: int, successes: int, p: Fraction) -> Fraction:
    integer(trials, "FINITE_DOMAIN_SIZE")
    integer(successes, "SUCCESS_COUNT")
    require(trials <= 512 and successes <= 64, "FINITE_BINOMIAL_LIMIT")
    rational(p, "PROBABILITY", upper=Fraction(1))
    return sum((Fraction(comb(trials, j)) * p ** j * (1 - p) ** (trials - j)
                for j in range(successes, trials + 1)), Fraction(0))


def full_table_advice_countermodel(domain_size: int = 64, successes: int = 1,
                                    p: Fraction = Fraction(1, 16)) -> dict:
    """A sharp finite-advice obstruction and its explicit joint record profile.

    Coherently copy each Bernoulli truth-table bit into a classical advice
    register. In the joint purification, each dual-table bit is one with
    squared norm 2p(1-p), independently across coordinates. No actual W1
    state is being estimated or certified by this constructive model.
    """
    integer(domain_size, "FINITE_DOMAIN_SIZE", minimum=1)
    integer(successes, "SUCCESS_COUNT", minimum=1)
    require(successes <= min(domain_size, 64) and domain_size <= 512, "FINITE_ADVICE_LIMIT")
    rational(p, "PROBABILITY", upper=Fraction(1))
    require(0 < p < 1, "PROBABILITY")
    q = 2 * p * (1 - p)
    profile = tuple(binomial_tail(domain_size, i, q) for i in range(successes + 1))
    actual = binomial_tail(domain_size, successes, p)
    propagated = residual_bernoulli_bound(0, successes, profile, p)
    require(actual <= propagated["bound"], "EXPLICIT_ADVICE_STATE_BOUND")
    return {"model": "finite Bernoulli oracle with coherent classical truth-table advice",
            "domain_size": domain_size, "classical_advice_bits": domain_size,
            "new_queries": 0, "distinct_successes": successes,
            "sharp_worst_case_success_with_unrestricted_finite_advice": actual,
            "joint_record_bit_probability": q, "joint_initial_squared_tail": profile,
            "conditional_arithmetic_bound": propagated["bound"],
            "profile_derived_for_this_explicit_model": True,
            "actual_w1_residual_profile_attested": False,
            "finite_state_space_implies_small_risk": False}


def synthetic_counterpair() -> dict:
    """Same entire declared local state; strict native score rule, two extensions.

    The score-tree model has no native proof-validation authority. Real owner
    replay evidence is separately bound by the evidence reader.
    """
    public = [{"id": "g", "parent": None, "score": 0}]
    for height in range(1, 8):
        public.append({"id": "a" + str(height),
                       "parent": "g" if height == 1 else "a" + str(height - 1),
                       "score": height})
    local = {"owner": "same-local-owner", "active": "a7", "generation": 7,
             "admitted": public, "observed_now": 100, "target": "a1"}
    local_hash = hashlib.sha256(canonical(local)).hexdigest()
    hidden = [{"id": "b" + str(height),
               "parent": "g" if height == 1 else "b" + str(height - 1),
               "score": height} for height in range(1, 9)]
    low_tip = local["active"]
    high_tip = hidden[-1]["id"] if hidden[-1]["score"] > public[-1]["score"] else local["active"]
    low_failure = low_tip not in {row["id"] for row in public[1:]}
    high_failure = high_tip in {row["id"] for row in hidden}
    require(not low_failure and high_failure, "COUNTERPAIR_SELECTION")
    return {"model": "declared positive additive score tree; not native work replay",
            "common_local_state": local,
            "common_local_state_sha256": local_hash,
            "world_without_private_chain": {"local_projection_sha256": local_hash,
                                             "private_ready_weight": 0, "future_selected": low_tip,
                                             "failure_probability_under_this_dirac_law": Fraction(int(low_failure))},
            "world_with_private_chain": {"local_projection_sha256": local_hash,
                                          "hidden_chain": hidden, "private_ready_weight": 8,
                                          "future_selected": high_tip,
                                          "failure_probability_under_this_dirac_law": Fraction(int(high_failure))},
            "worst_case_sound_local_risk_upper_bound": Fraction(1),
            "balanced_world_guessing_success_at_most": Fraction(1, 2),
            "native_validation_performed_by_this_model": False,
            "native_failure_probability_estimated": False}
