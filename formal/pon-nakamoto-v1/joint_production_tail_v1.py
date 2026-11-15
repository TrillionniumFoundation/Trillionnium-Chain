#!/usr/bin/env python3
"""Exact finite joint-law controls; no native consensus probability is certified.

Every transition row is a supplied joint conditional law at one finite state.
All declared actions are checked, allowing adaptation and arbitrary stopping
inside that model. Completeness of the real policy/state space is not inferred.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache
import json
from math import lcm
from pathlib import Path
import re
from typing import Any

SCHEMA = "pon-joint-production-tail-v1"
LAW_SCOPE = "declared-finite-model-unconditioned"
MAX_INPUT_BYTES = 1024 * 1024
MAX_STATES = 32
MAX_ACTIONS = 128
MAX_BRANCHES = 1024
MAX_RATIONAL_PART = 1000000
MAX_PROBABILITY_DENOMINATOR_LCM = 1000000
MAX_RATIONAL_BITS = 8192
MAX_CREDIT = 32
MAX_GAP = 256
MAX_HORIZON = 32
MAX_DP_CELLS = 200000
MAX_DP_TRANSITIONS = 1000000
MODES = {"direct", "conditional-cauchy-schwarz"}


class TailError(ValueError):
    """Malformed or insufficient finite model, never a native rejection."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise TailError(code)


def fields(value: Any, expected: set[str], code: str) -> dict:
    require(type(value) is dict and set(value) == expected, code)
    return value


def integer(value: Any, code: str, *, minimum: int = 0,
            maximum: int = MAX_RATIONAL_PART) -> int:
    require(type(value) is int and minimum <= value <= maximum, code)
    return value


def label(value: Any, code: str) -> str:
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", value) is not None,
            code)
    return value


def bounded(value: Fraction) -> Fraction:
    require(value.numerator.bit_length() <= MAX_RATIONAL_BITS and
            value.denominator.bit_length() <= MAX_RATIONAL_BITS, "RATIONAL_BIT_LIMIT")
    return value


def rational(value: Any, code: str) -> Fraction:
    fields(value, {"num", "den"}, code)
    num = integer(value["num"], code, minimum=1)
    den = integer(value["den"], code, minimum=1)
    return bounded(Fraction(num, den))


def encoded(value: Fraction) -> dict:
    value = bounded(value)
    return {"num": value.numerator, "den": value.denominator}


def strict_json(body: str) -> Any:
    require(type(body) is str and len(body.encode("utf-8")) <= MAX_INPUT_BYTES,
            "INPUT_SIZE")

    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def no_float(_value):
        raise TailError("NONRATIONAL_JSON_NUMBER")

    def bounded_integer(value):
        require(len(value.lstrip("-")) <= 12, "JSON_INTEGER_SIZE")
        return int(value)

    return json.loads(body, object_pairs_hook=pairs, parse_float=no_float,
                      parse_constant=no_float, parse_int=bounded_integer)


@dataclass(frozen=True)
class Branch:
    probability: Fraction
    adversarial: int
    entry_debt: int
    honest_pacer: int
    successor: str

    @property
    def net(self) -> int:
        return self.adversarial + self.entry_debt - self.honest_pacer


@dataclass(frozen=True)
class Action:
    name: str
    branches: tuple[Branch, ...]


@dataclass(frozen=True)
class State:
    potential: Fraction
    actions: tuple[Action, ...]


@dataclass(frozen=True)
class Model:
    z: Fraction
    initial_state: str
    mode: str
    states: dict[str, State]


def parse_model(document: dict) -> Model:
    fields(document, {"schema", "law_scope", "coverage", "mode", "z",
                      "initial_state", "states"}, "DOCUMENT_FIELDS")
    require(document["schema"] == SCHEMA, "SCHEMA")
    require(document["law_scope"] == LAW_SCOPE, "UNCONDITIONAL_LAW_SCOPE_REQUIRED")
    require(document["coverage"] == "all-declared-state-actions-only", "COVERAGE_SCOPE")
    require(type(document["mode"]) is str and document["mode"] in MODES, "MODE")
    z = rational(document["z"], "Z")
    require(z > 1, "Z_MUST_EXCEED_ONE")
    initial_state = label(document["initial_state"], "INITIAL_STATE")
    require(type(document["states"]) is list and
            1 <= len(document["states"]) <= MAX_STATES, "STATE_COUNT")
    states: dict[str, State] = {}
    action_count = 0
    branch_count = 0
    probability_denominator_lcm = 1
    for row in document["states"]:
        fields(row, {"id", "potential", "actions"}, "STATE_FIELDS")
        name = label(row["id"], "STATE_ID")
        require(name not in states, "DUPLICATE_STATE")
        potential = rational(row["potential"], "POTENTIAL")
        require(potential >= 1, "POTENTIAL_MUST_DOMINATE_ONE")
        require(type(row["actions"]) is list and 1 <= len(row["actions"]) <= MAX_ACTIONS,
                "STATE_ACTION_COUNT")
        actions = []
        action_names: set[str] = set()
        for action in row["actions"]:
            fields(action, {"id", "branches"}, "ACTION_FIELDS")
            action_name = label(action["id"], "ACTION_ID")
            require(action_name not in action_names, "DUPLICATE_ACTION")
            action_names.add(action_name)
            action_count += 1
            require(action_count <= MAX_ACTIONS, "TOTAL_ACTION_LIMIT")
            require(type(action["branches"]) is list and
                    1 <= len(action["branches"]) <= MAX_BRANCHES, "ACTION_BRANCH_COUNT")
            branches = []
            outcomes: set[tuple] = set()
            probability_sum = Fraction()
            for branch in action["branches"]:
                fields(branch, {"p", "a", "e", "j", "next"}, "BRANCH_FIELDS")
                branch_count += 1
                require(branch_count <= MAX_BRANCHES, "TOTAL_BRANCH_LIMIT")
                probability = rational(branch["p"], "PROBABILITY")
                require(probability <= 1, "PROBABILITY")
                probability_denominator_lcm = lcm(probability_denominator_lcm,
                                                probability.denominator)
                require(probability_denominator_lcm <= MAX_PROBABILITY_DENOMINATOR_LCM,
                        "PROBABILITY_DENOMINATOR_LIMIT")
                probability_sum = bounded(probability_sum + probability)
                adversarial = integer(branch["a"], "ADVERSARIAL_CREDIT", maximum=MAX_CREDIT)
                debt = integer(branch["e"], "ENTRY_DEBT", maximum=MAX_CREDIT)
                honest = integer(branch["j"], "HONEST_PACER", maximum=MAX_CREDIT)
                successor = label(branch["next"], "SUCCESSOR")
                outcome = (adversarial, debt, honest, successor)
                require(outcome not in outcomes, "DUPLICATE_BRANCH_OUTCOME")
                outcomes.add(outcome)
                branches.append(Branch(probability, adversarial, debt, honest, successor))
            require(probability_sum == 1, "PROBABILITIES_MUST_SUM_TO_ONE")
            actions.append(Action(action_name, tuple(branches)))
        states[name] = State(potential, tuple(actions))
    require(initial_state in states, "MISSING_INITIAL_STATE")
    for state in states.values():
        for action in state.actions:
            for branch in action.branches:
                require(branch.successor in states, "MISSING_SUCCESSOR_STATE")
    return Model(z, initial_state, document["mode"], states)


def _native_scope() -> dict:
    return {
        "qualification": "HOLD_NO_GO",
        "complete_legal_strategy_coverage_proved": False,
        "native_to_model_reduction_proved": False,
        "physical_filtration_authenticated": False,
        "native_common_prefix_qualified": False,
        "native_chain_growth_qualified": False,
        "native_chain_quality_qualified": False,
        "native_six_successor_risk_bound": None,
        "native_common_prefix_failure_bound": None,
        "native_chain_growth_bound": None,
        "native_chain_quality_bound": None,
        "actual_lifetime_failure_bound": None,
        "production_activation": False,
        "finalized": False,
        "execution_authority": False,
    }


def _audit(model: Model) -> dict:
    rows = []
    for name, state in model.states.items():
        for action in state.actions:
            direct = Fraction()
            adverse_square = Fraction()
            honest_square = Fraction()
            for branch in action.branches:
                ratio = bounded(model.states[branch.successor].potential / state.potential)
                adverse = bounded(bounded(model.z ** (branch.adversarial + branch.entry_debt)) * ratio)
                honest = bounded(model.z ** (-branch.honest_pacer))
                direct = bounded(direct + bounded(bounded(branch.probability * adverse) * honest))
                adverse_square = bounded(adverse_square + bounded(branch.probability * bounded(adverse ** 2)))
                honest_square = bounded(honest_square + bounded(branch.probability * bounded(honest ** 2)))
            product = bounded(adverse_square * honest_square)
            passed = direct <= 1 if model.mode == "direct" else product <= 1
            rows.append({"state": name, "action": action.name,
                         "joint_conditional_moment": encoded(direct),
                         "adverse_squared_moment": encoded(adverse_square),
                         "honest_squared_moment": encoded(honest_square),
                         "cauchy_schwarz_product": encoded(product),
                         "passed": passed})
    return {"schema": SCHEMA, "law_scope": LAW_SCOPE, "mode": model.mode,
            "finite_model_certificate_valid": all(row["passed"] for row in rows),
            "checked_states": len(model.states), "checked_actions": len(rows),
            "actions": rows, **_native_scope()}


def audit_model(document: dict) -> dict:
    """Validate every action at every declared state, including unreachable states."""
    return _audit(parse_model(document))


def crossing_bound(document: dict, gap: int) -> Fraction:
    """Anytime bound only for the supplied finite model and its chosen initial state."""
    integer(gap, "GAP", maximum=MAX_GAP)
    model = parse_model(document)
    require(_audit(model)["finite_model_certificate_valid"], "INVALID_FINITE_CERTIFICATE")
    return min(Fraction(1), bounded(model.states[model.initial_state].potential *
                                    bounded(model.z ** (-gap))))


def maximal_crossing_probability(document: dict, gap: int, horizon: int) -> Fraction:
    """Independent Bellman maximum over all finite-model adaptive policies.

    Crossing is absorbing even if later increments would remove the crossing.
    Structural validation is required; an invalid potential may still be used to
    diagnose the finite law. No invalid certificate can issue crossing_bound().
    """
    integer(gap, "GAP", maximum=MAX_GAP)
    integer(horizon, "HORIZON", maximum=MAX_HORIZON)
    model = parse_model(document)
    cells = 0
    transitions = 0

    @lru_cache(maxsize=None)
    def value(state_name: str, remaining: int, steps: int) -> Fraction:
        nonlocal cells, transitions
        cells += 1
        require(cells <= MAX_DP_CELLS, "DP_CELL_LIMIT")
        if remaining <= 0:
            return Fraction(1)
        if steps == 0:
            return Fraction(0)
        values = []
        for action in model.states[state_name].actions:
            total = Fraction()
            for branch in action.branches:
                transitions += 1
                require(transitions <= MAX_DP_TRANSITIONS, "DP_TRANSITION_LIMIT")
                term = bounded(branch.probability * value(branch.successor,
                                                        remaining - branch.net, steps - 1))
                total = bounded(total + term)
            values.append(total)
        return max(values)

    return bounded(value(model.initial_state, gap, horizon))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", required=True, type=Path)
    parser.add_argument("--gap", type=int)
    parser.add_argument("--horizon", type=int)
    parser.add_argument("--require-native-qualification", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.gap is not None:
            integer(args.gap, "GAP", maximum=MAX_GAP)
        if args.horizon is not None:
            integer(args.horizon, "HORIZON", maximum=MAX_HORIZON)
        require(args.horizon is None or args.gap is not None, "HORIZON_REQUIRES_GAP")
        with args.check.open("rb") as stream:
            body = stream.read(MAX_INPUT_BYTES + 1)
        require(len(body) <= MAX_INPUT_BYTES, "INPUT_SIZE")
        document = strict_json(body.decode("utf-8"))
        report = audit_model(document)
        if args.gap is not None:
            if report["finite_model_certificate_valid"]:
                report["finite_model_anytime_crossing_bound"] = encoded(crossing_bound(document, args.gap))
            else:
                report["finite_model_anytime_crossing_bound"] = None
            if args.horizon is not None:
                report["finite_model_maximal_crossing_probability"] = encoded(
                    maximal_crossing_probability(document, args.gap, args.horizon))
        print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
        if args.require_native_qualification:
            return 3
        return 0 if report["finite_model_certificate_valid"] else 2
    except (TailError, OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        print(json.dumps({"error": str(error), **_native_scope()}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
