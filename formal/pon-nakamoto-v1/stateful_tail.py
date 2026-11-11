#!/usr/bin/env python3
"""Exact finite-state checks for a residual-state exponential potential.

This is an abstract inventory model and a finite certificate checker.  Neither
its transition law nor its resource price is a claim about W1, SHA-256,
quantum gate complexity, physical time, or the native fork-choice rule.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache
import json
from math import comb
from pathlib import Path
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class Transition:
    probability: Fraction
    next_state: str
    credit: int
    resource: int


@dataclass(frozen=True)
class Action:
    name: str
    outcomes: tuple[Transition, ...]


@dataclass(frozen=True)
class Model:
    actions: Mapping[str, tuple[Action, ...]]
    potential: Mapping[str, Fraction]
    z: Fraction
    gamma: Fraction


def _nonnegative_integer(value: object, name: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer, excluding bool")


def validate(model: Model) -> None:
    if not isinstance(model.z, Fraction) or model.z <= 1:
        raise ValueError("z must be an exact Fraction greater than one")
    if not isinstance(model.gamma, Fraction) or model.gamma < 1:
        raise ValueError("gamma must be an exact Fraction at least one")
    if not model.actions or set(model.actions) != set(model.potential):
        raise ValueError("nonempty action and potential state sets must agree")
    for state, actions in model.actions.items():
        if not isinstance(state, str) or not state:
            raise ValueError("state names must be nonempty strings")
        v = model.potential[state]
        if not isinstance(v, Fraction) or v < 1:
            raise ValueError("every potential must be an exact Fraction at least one")
        names = [action.name for action in actions]
        if len(names) != len(set(names)):
            raise ValueError("action names must be unique within each state")
        for action in actions:
            if not action.name or not action.outcomes:
                raise ValueError("actions require a name and a nonempty outcome law")
            if sum((t.probability for t in action.outcomes), Fraction(0)) != 1:
                raise ValueError("each outcome law must sum to one exactly")
            for t in action.outcomes:
                if not isinstance(t.probability, Fraction) or t.probability < 0:
                    raise ValueError("outcome probabilities must be nonnegative Fractions")
                if t.next_state not in model.actions:
                    raise ValueError("unknown next state")
                _nonnegative_integer(t.credit, "credit")
                _nonnegative_integer(t.resource, "resource")


def tilted_value(model: Model, action: Action) -> Fraction:
    return sum((
        t.probability * model.z ** t.credit / model.gamma ** t.resource
        * model.potential[t.next_state]
        for t in action.outcomes
    ), Fraction(0))


def certificate(model: Model) -> list[dict[str, object]]:
    """Check every declared state/action; completeness of that set is external."""
    validate(model)
    return [
        {
            "state": state,
            "action": action.name,
            "lhs": tilted_value(model, action),
            "rhs": model.potential[state],
            "valid": tilted_value(model, action) <= model.potential[state],
        }
        for state, actions in model.actions.items() for action in actions
    ]


def inventory_model(capacity: int = 3, *, omit_potential: bool = False) -> Model:
    _nonnegative_integer(capacity, "capacity")
    if capacity == 0:
        raise ValueError("the inventory toy requires positive capacity")
    p, z = Fraction(1, 4), Fraction(2)
    gamma = 1 + p * (z - 1)
    actions: dict[str, tuple[Action, ...]] = {}
    potential: dict[str, Fraction] = {}
    for stash in range(capacity + 1):
        state = f"stash_{stash}"
        current = []
        if stash < capacity:
            current.append(Action("generate", (
                Transition(p, f"stash_{stash + 1}", 0, 1),
                Transition(1 - p, state, 0, 1),
            )))
        if stash > 0:
            current.append(Action("release", (
                Transition(Fraction(1), f"stash_{stash - 1}", 1, 0),
            )))
        # Stopping is always available. It is represented as a zero-value
        # alternative in the event-probability DP rather than a self-loop.
        actions[state] = tuple(current)
        potential[state] = Fraction(1) if omit_potential else z ** stash
    return Model(actions, potential, z, gamma)


def make_optimal_tail(model: Model):
    """Independent finite Bellman maximization over all adaptive policies.

    A policy may select a different action after each observed outcome. A path
    crossing its resource budget is killed. Credit already reaching the target
    counts as success, so the event is a crossing by the stated horizon.

    The returned query uses a private immutable snapshot captured here. Later
    changes to caller-owned mappings or nested sequences require a new query;
    they cannot change either cached or previously unqueried results.
    The caller must keep the model stable until construction returns.
    """
    model = Model(
        actions=MappingProxyType({
            state: tuple(Action(action.name, tuple(
                Transition(t.probability, t.next_state, t.credit, t.resource)
                for t in action.outcomes
            )) for action in actions)
            for state, actions in model.actions.items()
        }),
        potential=MappingProxyType(dict(model.potential)),
        z=model.z,
        gamma=model.gamma,
    )
    validate(model)

    @lru_cache(maxsize=None)
    def dp(state: str, budget: int, steps: int, needed: int) -> Fraction:
        if needed <= 0:
            return Fraction(1)
        if steps == 0:
            return Fraction(0)
        best = Fraction(0)  # stop
        for action in model.actions[state]:
            value = sum((
                t.probability * dp(t.next_state, budget - t.resource,
                                   steps - 1, needed - t.credit)
                for t in action.outcomes if t.resource <= budget
            ), Fraction(0))
            best = max(best, value)
        return best

    def query(state: str, budget: int, horizon: int, threshold: int) -> Fraction:
        if state not in model.actions:
            raise ValueError("unknown initial state")
        for value, label in ((budget, "budget"), (horizon, "horizon"),
                             (threshold, "threshold")):
            _nonnegative_integer(value, label)
        return dp(state, budget, horizon, threshold)
    return query


def potential_bound(model: Model, state: str, budget: int,
                    threshold: int) -> Fraction:
    if not all(row["valid"] for row in certificate(model)):
        raise ValueError("a failed transition certificate cannot certify a tail")
    if state not in model.actions:
        raise ValueError("unknown initial state")
    _nonnegative_integer(budget, "budget")
    _nonnegative_integer(threshold, "threshold")
    return min(Fraction(1), model.potential[state]
               * model.gamma ** budget / model.z ** threshold)


def binomial_tail(trials: int, needed: int, p: Fraction) -> Fraction:
    if needed <= 0:
        return Fraction(1)
    return sum((Fraction(comb(trials, k)) * p ** k * (1 - p) ** (trials - k)
                for k in range(needed, trials + 1)), Fraction(0))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def build_report() -> dict[str, object]:
    model = inventory_model()
    rows = certificate(model)
    _require(all(row["valid"] for row in rows), "inventory certificate failed")
    _require(all(row["lhs"] == row["rhs"] for row in rows),
             "inventory certificate should attain equality")
    erased = inventory_model(omit_potential=True)
    erased_rows = certificate(erased)
    failures = [row for row in erased_rows if not row["valid"]]
    _require(len(failures) == 3 and all(row["action"] == "release" for row in failures),
             "erasing residual potential must fail every release action")
    try:
        potential_bound(erased, "stash_1", 0, 1)
    except ValueError:
        refused_invalid_certificate = True
    else:
        raise AssertionError("an invalid certificate was accepted")

    dp = make_optimal_tail(model)
    checked = 0
    strict_cases = 0
    maximum_probability_over_bound = Fraction(0)
    for stash in range(4):
        state = f"stash_{stash}"
        for budget in range(9):
            for horizon in range(19):
                for threshold in range(1, 10):
                    actual = dp(state, budget, horizon, threshold)
                    bound = potential_bound(model, state, budget, threshold)
                    _require(actual <= bound, "adaptive DP violates certified bound")
                    checked += 1
                    strict_cases += actual < bound
                    maximum_probability_over_bound = max(maximum_probability_over_bound,
                                                         actual / bound)
    # Once B+x transitions are allowed, generating B trials and releasing up to
    # x items realizes the exact binomial threshold. This checks the adaptive DP
    # against a second, closed-form calculation, not just its own certificate.
    binomial_cases = 0
    for stash in range(4):
        for budget in range(9):
            for threshold in range(1, 10):
                actual = dp(f"stash_{stash}", budget, budget + threshold, threshold)
                exact = binomial_tail(budget, threshold - stash, Fraction(1, 4))
                _require(actual == exact, "DP disagrees with independent binomial law")
                binomial_cases += 1

    zero_budget_probability = dp("stash_1", 0, 1, 1)
    _require(zero_budget_probability == 1, "stored work should release without new cost")
    return {
        "schema": "stateful-tail-finite-toy-v1",
        "status": "ABSTRACT_CERTIFICATE_ONLY_HOLD_FOR_W1",
        "law": {"p": Fraction(1, 4), "z": model.z, "gamma": model.gamma,
                "capacity": 3, "potential": dict(model.potential)},
        "transition_checks": rows,
        "erased_potential_failures": failures,
        "invalid_certificate_refused": refused_invalid_certificate,
        "adaptive_policy_checks": {"cases": checked, "strict_cases": strict_cases,
                                   "max_probability_over_bound": maximum_probability_over_bound},
        "independent_binomial_checks": {"cases": binomial_cases, "all_equal": True},
        "zero_new_resource_counterexample": {
            "initial_stash": 1, "budget": 0, "horizon": 1, "threshold": 1,
            "actual_probability": zero_budget_probability,
            "certified_bound_with_potential": potential_bound(model, "stash_1", 0, 1),
            "invalid_bound_after_reset_to_one": Fraction(1, 2),
        },
        "claim_flags": {
            "actual_w1_resource_tail": False,
            "actual_w1_quantum_transition_certificate": False,
            "cheapest_legal_work_lower_bound": False,
            "physical_time_bound": False,
            "native_consensus_failure_mapping": False,
            "six_successor_risk_bound": False,
            "production_qualification": False,
        },
    }


def _json_default(value: object):
    if isinstance(value, Fraction):
        return {"numerator": value.numerator, "denominator": value.denominator}
    raise TypeError(type(value).__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="write a new JSON file; refuses overwrite")
    args = parser.parse_args()
    payload = json.dumps(build_report(), default=_json_default, indent=2, sort_keys=True) + "\n"
    if args.out:
        with args.out.open("x", encoding="utf-8") as handle:
            handle.write(payload)
        print(str(args.out))
    else:
        print(payload, end="")


if __name__ == "__main__":
    main()
