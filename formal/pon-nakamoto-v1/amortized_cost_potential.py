#!/usr/bin/env python3
"""Exact synthesis of additive lifecycle cost potentials for finite models.

Frozen credits and resource prices are inputs.  This module can certify a
finite Bellman supersolution or a Farkas contradiction; it never promotes a
finite action menu to an all-algorithm W1 or quantum cost theorem.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
from itertools import combinations
import json
from math import comb
from typing import Mapping, Sequence

F = Fraction


@dataclass(frozen=True)
class Outcome:
    probability: Fraction
    next_state: str
    resource: Fraction
    credits: tuple[tuple[int, int], ...] = ()
    eta_debit: Fraction = F(0)


@dataclass(frozen=True)
class Action:
    name: str
    outcomes: tuple[Outcome, ...]


@dataclass(frozen=True)
class Model:
    name: str
    actions: Mapping[str, tuple[Action, ...]]
    weights: Mapping[int, Fraction]
    kappa: Fraction
    eta_remaining: Mapping[str, Fraction]
    initial_potential_caps: Mapping[str, Fraction]


@dataclass(frozen=True)
class Inequality:
    """coefficients dot Phi >= bound."""
    label: str
    coefficients: tuple[Fraction, ...]
    bound: Fraction
    kind: str


def _nonnegative_fraction(value: object, label: str) -> None:
    if type(value) is not Fraction or value < 0:
        raise ValueError(f"{label} must be an exact nonnegative Fraction")


def _name(value: object, label: str) -> None:
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be an exact nonempty str")


def validate(model: Model) -> None:
    # Shape checks must precede any traversal that could consume user input.
    # Dataclass annotations alone do not prevent generators or duck-typed data.
    if type(model) is not Model:
        raise ValueError("model must be an exact Model")
    _name(model.name, "model name")
    for label, value in (("actions", model.actions), ("weights", model.weights),
                         ("eta_remaining", model.eta_remaining),
                         ("initial_potential_caps", model.initial_potential_caps)):
        if type(value) is not dict:
            raise ValueError(f"{label} must be an exact dict")
    if not model.actions or not model.weights:
        raise ValueError("states and frozen weights are required")
    _nonnegative_fraction(model.kappa, "kappa")
    for units, weight in model.weights.items():
        if type(units) is not int or units < 1:
            raise ValueError("work scales must be positive integers")
        _nonnegative_fraction(weight, "weight")
        if weight == 0:
            raise ValueError("a zero credit is not a repair of a frozen schedule")
    for state, balance in model.eta_remaining.items():
        _name(state, "eta state name")
        _nonnegative_fraction(balance, "eta balance")
    for state, cap in model.initial_potential_caps.items():
        _name(state, "initial state name")
        _nonnegative_fraction(cap, "initial potential budget")
    for state, actions in model.actions.items():
        _name(state, "state name")
        if type(actions) is not tuple:
            raise ValueError("each state's actions must be an exact tuple")
        for action in actions:
            if type(action) is not Action:
                raise ValueError("action elements must be exact Action records")
            _name(action.name, "action name")
            if type(action.outcomes) is not tuple or not action.outcomes:
                raise ValueError("action outcomes must be a nonempty exact tuple")
            for outcome in action.outcomes:
                if type(outcome) is not Outcome:
                    raise ValueError("outcome elements must be exact Outcome records")
                _name(outcome.next_state, "successor state name")
                if type(outcome.probability) is not Fraction or outcome.probability <= 0:
                    raise ValueError("listed outcome probabilities must be positive exact Fractions")
                _nonnegative_fraction(outcome.resource, "resource")
                _nonnegative_fraction(outcome.eta_debit, "eta debit")
                if type(outcome.credits) is not tuple:
                    raise ValueError("outcome credits must be an exact tuple")
                for credit in outcome.credits:
                    if type(credit) is not tuple or len(credit) != 2:
                        raise ValueError("credit entries must be exact two-item tuples")
                    units, count = credit
                    if type(units) is not int or type(count) is not int or count < 0:
                        raise ValueError("invalid credited scale or count")
    # All containers and elements are now reusable, exact built-in/record types.
    # Relational checks and subsequent certificate construction cannot exhaust
    # a hidden iterator or invoke a custom mapping's traversal semantics.
    if set(model.eta_remaining) != set(model.actions):
        raise ValueError("each state requires an explicit eta balance")
    if not model.initial_potential_caps:
        raise ValueError("at least one initial potential budget is required")
    if not set(model.initial_potential_caps) <= set(model.actions):
        raise ValueError("unknown initial state")
    for state, actions in model.actions.items():
        names = [action.name for action in actions]
        if len(names) != len(set(names)) or "stop" in names:
            raise ValueError("action names must be unique; stop has zero payoff")
        for action in actions:
            if sum((outcome.probability for outcome in action.outcomes), F(0)) != 1:
                raise ValueError("outcome probabilities must sum to one exactly")
            for outcome in action.outcomes:
                if outcome.next_state not in model.actions:
                    raise ValueError("unknown successor state")
                if (model.eta_remaining[outcome.next_state] + outcome.eta_debit
                        != model.eta_remaining[state]):
                    raise ValueError("eta ledger must debit exactly; restart cannot refill it")
                credited_scales = [units for units, _ in outcome.credits]
                if len(credited_scales) != len(set(credited_scales)):
                    raise ValueError("credit counts require one entry per scale")
                if any(units not in model.weights for units, _ in outcome.credits):
                    raise ValueError("invalid credited scale or count")
    reachable = set(model.initial_potential_caps)
    todo = list(reachable)
    while todo:
        state = todo.pop()
        for action in model.actions[state]:
            for outcome in action.outcomes:
                if outcome.next_state not in reachable:
                    reachable.add(outcome.next_state)
                    todo.append(outcome.next_state)
    if reachable != set(model.actions):
        raise ValueError("remove unreachable states or declare their initial budgets")


def constraint_label(kind: str, *names: str) -> str:
    """Injective, canonical row identity; delimiters inside names stay data."""
    arity = {"action": 2, "nonnegative": 1, "initial_cap": 1}
    if type(kind) is not str or kind not in arity or len(names) != arity[kind]:
        raise ValueError("unknown constraint kind or label arity")
    for name in names:
        _name(name, "constraint label component")
    return kind + ":" + json.dumps(names, ensure_ascii=True, separators=(",", ":"))


def credited_weight(model: Model, outcome: Outcome) -> Fraction:
    return sum((model.weights[u] * count for u, count in outcome.credits), F(0))


def mean_excess(model: Model, action: Action) -> Fraction:
    return sum((o.probability * (credited_weight(model, o)
                - model.kappa * o.resource - o.eta_debit)
                for o in action.outcomes), F(0))


def inequalities(model: Model) -> tuple[tuple[str, ...], tuple[Inequality, ...]]:
    validate(model)
    states = tuple(sorted(model.actions))
    index = {state: i for i, state in enumerate(states)}
    rows = []
    for state in states:
        for action in model.actions[state]:
            coefficients = [F(0)] * len(states)
            coefficients[index[state]] = F(1)
            for outcome in action.outcomes:
                coefficients[index[outcome.next_state]] -= outcome.probability
            rows.append(Inequality(constraint_label("action", state, action.name), tuple(coefficients),
                                   mean_excess(model, action), "action"))
    for state in states:
        coefficients = tuple(F(int(i == index[state])) for i in range(len(states)))
        rows.append(Inequality(constraint_label("nonnegative", state), coefficients, F(0), "nonnegative"))
    for state, cap in sorted(model.initial_potential_caps.items()):
        coefficients = tuple(F(-int(i == index[state])) for i in range(len(states)))
        rows.append(Inequality(constraint_label("initial_cap", state), coefficients, -cap, "initial_cap"))
    return states, tuple(rows)


def _dot(left: Sequence[Fraction], right: Sequence[Fraction]) -> Fraction:
    return sum((x * y for x, y in zip(left, right)), F(0))


def verify_potential(model: Model, potential: Mapping[str, Fraction]) -> dict[str, object]:
    states, rows = inequalities(model)
    if type(potential) is not dict:
        raise ValueError("potential must be an exact dict")
    if (any(type(state) is not str for state in potential)
            or set(potential) != set(states)
            or any(type(value) is not Fraction for value in potential.values())):
        raise ValueError("provide one exact Fraction potential per state")
    values = tuple(potential[s] for s in states)
    residuals = [{"constraint": row.label,
                  "slack": _dot(row.coefficients, values) - row.bound}
                 for row in rows]
    return {"valid": all(r["slack"] >= 0 for r in residuals), "residuals": residuals}


def verify_dual(model: Model, multipliers: Mapping[str, Fraction]) -> dict[str, object]:
    """Check lambda >= 0, lambda^T A = 0, lambda^T b > 0 independently."""
    states, rows = inequalities(model)
    labels = {row.label for row in rows}
    if type(multipliers) is not dict:
        raise ValueError("dual multipliers must be an exact dict")
    if any(type(label) is not str for label in multipliers):
        raise ValueError("dual constraint labels must be exact str values")
    if not set(multipliers) <= labels:
        raise ValueError("unknown dual constraint label")
    for value in multipliers.values():
        _nonnegative_fraction(value, "dual multiplier")
    balance = tuple(sum((multipliers.get(row.label, F(0)) * row.coefficients[i]
                         for row in rows), F(0)) for i in range(len(states)))
    contradiction = sum((multipliers.get(row.label, F(0)) * row.bound for row in rows), F(0))
    action_only = all(row.kind == "action" or not multipliers.get(row.label, F(0)) for row in rows)
    return {"valid": all(value == 0 for value in balance) and contradiction > 0,
            "state_balance": dict(zip(states, balance)),
            "contradiction": contradiction,
            "kind": "stationary_action_flow" if action_only else "budget_or_state_constraint"}


def _unique_solution(matrix: Sequence[Sequence[Fraction]], rhs: Sequence[Fraction],
                     variables: int) -> tuple[Fraction, ...] | None:
    """Rectangular exact elimination; dependent or inconsistent systems return None."""
    augmented = [list(row) + [value] for row, value in zip(matrix, rhs)]
    pivot_row = 0
    pivot_for_column = {}
    for column in range(variables):
        pivot = next((i for i in range(pivot_row, len(augmented))
                      if augmented[i][column] != 0), None)
        if pivot is None:
            continue
        augmented[pivot_row], augmented[pivot] = augmented[pivot], augmented[pivot_row]
        scale = augmented[pivot_row][column]
        augmented[pivot_row] = [value / scale for value in augmented[pivot_row]]
        for i in range(len(augmented)):
            if i != pivot_row and augmented[i][column] != 0:
                scale = augmented[i][column]
                augmented[i] = [x - scale * y for x, y in zip(augmented[i], augmented[pivot_row])]
        pivot_for_column[column] = pivot_row
        pivot_row += 1
    if any(all(value == 0 for value in row[:variables]) and row[-1] != 0 for row in augmented):
        return None
    if len(pivot_for_column) != variables:
        return None
    return tuple(augmented[pivot_for_column[column]][-1] for column in range(variables))


def synthesize(model: Model, *, max_basis_checks: int = 100_000) -> dict[str, object]:
    """Enumerate small rational LP bases, then seek an exact Farkas witness.

    Feasibility is never inferred from solver tolerance.  An unfinished search
    without a certificate returns unknown, never infeasible.  Exhaustive primal
    enumeration minimizes sum(Phi), hence returns the least Bellman potential.
    """
    if type(max_basis_checks) is not int or max_basis_checks < 0:
        raise ValueError("max_basis_checks must be a nonnegative integer")
    states, rows = inequalities(model)
    dimension = len(states)
    checked = 0
    best = None
    primal_exhausted = True
    for selected in combinations(range(len(rows)), dimension):
        if checked == max_basis_checks:
            primal_exhausted = False
            break
        checked += 1
        candidate = _unique_solution([rows[i].coefficients for i in selected],
                                     [rows[i].bound for i in selected], dimension)
        if candidate is not None and all(_dot(row.coefficients, candidate) >= row.bound for row in rows):
            if best is None or sum(candidate) < sum(best):
                best = candidate
    common = {"model": model.name, "basis_checks": checked,
              "primal_basis_total": comb(len(rows), dimension),
              "primal_search_exhausted": primal_exhausted,
              "all_algorithm_cost_qualified": False, "quantum_cost_qualified": False,
              "native_consensus_qualified": False, "tail_qualified": False}
    if best is not None:
        potential = dict(zip(states, best))
        receipt = verify_potential(model, potential)
        if not receipt["valid"]:
            raise AssertionError("internal primal verification failed")
        return {**common, "status": "feasible", "potential": potential,
                "least_potential_proved": primal_exhausted, "verification": receipt,
                "initial_eta_budgets": {s: model.eta_remaining[s] for s in model.initial_potential_caps}}
    # Normalize the strict Farkas inequality to lambda dot b = 1.  A minimal
    # support solution has at most dimension+1 independent columns.
    dual_exhausted = True
    for size in range(1, min(dimension + 1, len(rows)) + 1):
        for selected in combinations(range(len(rows)), size):
            if checked == max_basis_checks:
                dual_exhausted = False
                break
            checked += 1
            matrix = [[rows[i].coefficients[j] for i in selected] for j in range(dimension)]
            matrix.append([rows[i].bound for i in selected])
            solution = _unique_solution(matrix, [F(0)] * dimension + [F(1)], size)
            if solution is not None and all(value >= 0 for value in solution):
                multipliers = {rows[i].label: value for i, value in zip(selected, solution) if value > 0}
                receipt = verify_dual(model, multipliers)
                if not receipt["valid"]:
                    raise AssertionError("internal dual verification failed")
                return {**common, "basis_checks": checked, "status": "infeasible",
                        "dual_multipliers": multipliers, "verification": receipt}
        if not dual_exhausted:
            break
    return {**common, "basis_checks": checked, "status": "unknown",
            "dual_search_exhausted": dual_exhausted,
            "reason": "no certificate within the exact search budget" if not dual_exhausted
                      else "no certificate found; do not infer infeasibility"}


def finite_horizon_value(model: Model, horizon: int) -> Mapping[str, Fraction]:
    """Independent adaptive-policy DP with an explicit zero-payoff stopping option."""
    validate(model)
    if type(horizon) is not int or horizon < 0:
        raise ValueError("horizon must be a nonnegative integer")
    values = {state: F(0) for state in model.actions}
    for _ in range(horizon):
        values = {state: max([F(0)] + [sum((o.probability * (
                    credited_weight(model, o) - model.kappa * o.resource - o.eta_debit
                    + values[o.next_state]) for o in action.outcomes), F(0))
                    for action in actions]) for state, actions in model.actions.items()}
    return values


def verify_regenerative_cycle(model: Model, path: Sequence[tuple[str, str]]) -> dict[str, object]:
    """Verify a named closed action path with deterministic successor states.

    Credit and cost may be random on an edge.  This is an expected-cost witness,
    not a physical attack and not a deterministic winning transcript.
    """
    validate(model)
    if not path:
        raise ValueError("provide a nonempty cycle")
    gain = resource = reward = F(0)
    for i, (state, name) in enumerate(path):
        action = next((a for a in model.actions.get(state, ()) if a.name == name), None)
        if action is None:
            raise ValueError("unknown cycle action")
        successors = {o.next_state for o in action.outcomes}
        if successors != {path[(i + 1) % len(path)][0]}:
            raise ValueError("each edge must reach exactly the next cycle state")
        gain += mean_excess(model, action)
        resource += sum((o.probability * o.resource for o in action.outcomes), F(0))
        reward += sum((o.probability * credited_weight(model, o) for o in action.outcomes), F(0))
    return {"strict_contradiction": gain > 0, "net_expected_gain": gain,
            "expected_resource": resource, "expected_credit": reward,
            "all_edges_have_positive_resource": all(
                all(o.resource > 0 for o in next(a for a in model.actions[s] if a.name == n).outcomes)
                for s, n in path), "path": tuple(path)}


def _check(units: int, successor: str) -> Action:
    return Action(f"check_{units}", (
        Outcome(F(1, 4), successor, F(1, 4), ((units, 1),)),
        Outcome(F(3, 4), successor, F(1, 4)),
    ))


def shared_cache_model(*, promotion: Fraction = F(3), batch_setup: Fraction = F(9, 2),
                       kappa: Fraction = F(1)) -> Model:
    """Counterfactual fixed-p menu, with u=1 and u=4 and distinct fresh checks.

    Its promotions/profile choices are hypotheses, not established MU1 or native
    DAA transitions.  Literal counted-identity refinement remains external.
    """
    actions = {
        "empty": (
            Action("prepare_1", (Outcome(F(1), "cache_1", F(3, 4)),)),
            Action("prepare_4", (Outcome(F(1), "cache_4", F(15, 4)),)),
            Action("prepare_pair", (Outcome(F(1), "pair", batch_setup),)),
        ),
        "cache_1": (_check(1, "empty"),
                    Action("promote_1_to_4", (Outcome(F(1), "cache_4", promotion),))),
        "cache_4": (_check(4, "empty"),),
        "pair": (
            _check(1, "cache_4"), _check(4, "cache_1"),
            Action("check_pair", (
                Outcome(F(9, 16), "empty", F(1, 2)),
                Outcome(F(3, 16), "empty", F(1, 2), ((1, 1),)),
                Outcome(F(3, 16), "empty", F(1, 2), ((4, 1),)),
                Outcome(F(1, 16), "empty", F(1, 2), ((1, 1), (4, 1))),
            )),
            Action("restart_retaining_pair", (Outcome(F(1), "pair", F(0)),)),
        ),
    }
    return Model("fixed_p_multi_scale_shared_cache", actions, {1: F(4), 4: F(16)},
                 kappa, {state: F(0) for state in actions}, {"empty": F(0)})


def retained_failure_model(*, marginal: Fraction = F(3, 4), kappa: Fraction = F(1)) -> Model:
    actions = {
        "empty": (Action("prepare", (Outcome(F(1), "cache", F(1)),)),),
        "cache": (Action("try", (
            Outcome(F(1, 4), "empty", marginal, ((1, 1),)),
            Outcome(F(3, 4), "cache", marginal),
        )),),
    }
    return Model("failure_retains_preparation", actions, {1: F(4)}, kappa,
                 {state: F(0) for state in actions}, {"empty": F(0)})


def eta_budget_model() -> Model:
    actions = {"funded": (Action("one_funded_credit", (
        Outcome(F(1), "spent", F(0), ((1, 1),), F(4)),)),), "spent": ()}
    return Model("finite_eta_allowance", actions, {1: F(4)}, F(1),
                 {"funded": F(4), "spent": F(0)}, {"funded": F(0)})


def build_report() -> dict[str, object]:
    safe = shared_cache_model()
    cheap_promotion = shared_cache_model(promotion=F(1))
    cheap_batch = shared_cache_model(batch_setup=F(5, 2))
    repaired = shared_cache_model(promotion=F(1), kappa=F(2))
    models = {"safe_shared_cache": safe, "cheap_cross_scale_conversion": cheap_promotion,
              "cheap_batch": cheap_batch, "calibrated_kappa_2": repaired,
              "retained_failure_safe": retained_failure_model(),
              "retained_failure_cheap": retained_failure_model(marginal=F(1, 2)),
              "bounded_eta": eta_budget_model()}
    results = {name: synthesize(model) for name, model in models.items()}
    expected = {name: ("infeasible" if name in {
        "cheap_cross_scale_conversion", "cheap_batch", "retained_failure_cheap"} else "feasible")
        for name in models}
    if any(results[name]["status"] != status for name, status in expected.items()):
        raise AssertionError("a demonstration certificate is missing or changed")
    cycles = {
        "promotion": verify_regenerative_cycle(cheap_promotion, (
            ("empty", "prepare_1"), ("cache_1", "promote_1_to_4"), ("cache_4", "check_4"))),
        "batch": verify_regenerative_cycle(cheap_batch, (("empty", "prepare_pair"), ("pair", "check_pair"))),
    }
    return {"schema": "pon-amortized-cost-potential-v1", "results": results,
            "regenerative_certificates": cycles,
            "interpretation": "Exact certificates for the declared finite models only",
            "all_algorithm_cost_qualified": False, "quantum_cost_qualified": False,
            "native_consensus_qualified": False, "tail_qualified": False}


def _json_default(value: object):
    if isinstance(value, Fraction):
        return str(value)
    raise TypeError(f"unsupported JSON value {type(value).__name__}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build_report(), default=_json_default, indent=None if args.compact else 2, sort_keys=True))


if __name__ == "__main__":
    main()
