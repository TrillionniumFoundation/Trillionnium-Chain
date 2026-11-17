#!/usr/bin/env python3
"""Exact finite lifetime/service composition; never a native risk certificate.

The supplied model keeps target, time, required credit, dynamic participation,
entry debt, complete delivery/service, residual potential and non-refundable
lifetime spending in one conditional history. Every declared action is checked.
The checker neither proves that the declared actions cover every legal strategy
nor authenticates probabilities, clocks, resources or a native event mapping.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache
import json
from math import lcm
import os
from pathlib import Path
import re
import stat
from typing import Any

SCHEMA = "pon-joint-lifetime-service-v1"
LAW_SCOPE = "declared-finite-joint-history-unconditioned"
SPACE = 1 << 256
POW_LIMIT = (1 << 255) - 1
MAX_INPUT_BYTES = 1024 * 1024
MAX_STATES = 64
MAX_ACTIONS = 256
MAX_BRANCHES = 2048
MAX_RATIONAL_PART = 1_000_000
MAX_DENOMINATOR_LCM = 1_000_000
MAX_RATIONAL_BITS = 8192
MAX_HEIGHT = 1_000_000
MAX_TIME = (1 << 63) - 1
MAX_COMPONENT = 1_000_000
MAX_CREDIT_COMPONENT = 64
MAX_GAP = 256
MAX_HORIZON = 64
MAX_DP_CELLS = 500_000
MAX_DP_TRANSITIONS = 2_000_000
BAD_LABELS = {
    "none", "crossing", "delivery", "service", "clock", "target",
    "eligibility", "environment", "cryptographic",
}


class JointLifetimeError(ValueError):
    """Malformed or insufficient declared model, never native invalidity."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise JointLifetimeError(code)


def fields(value: Any, expected: set[str], code: str) -> dict:
    require(type(value) is dict and set(value) == expected, code)
    return value


def integer(value: Any, code: str, *, minimum: int = 0,
            maximum: int = MAX_COMPONENT) -> int:
    require(type(value) is int and minimum <= value <= maximum, code)
    return value


def boolean(value: Any, code: str) -> bool:
    require(type(value) is bool, code)
    return value


def label(value: Any, code: str) -> str:
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", value), code)
    return value


def bounded(value: Fraction) -> Fraction:
    require(value.numerator.bit_length() <= MAX_RATIONAL_BITS and
            value.denominator.bit_length() <= MAX_RATIONAL_BITS,
            "RATIONAL_BIT_LIMIT")
    return value


def rational(value: Any, code: str, *, allow_zero: bool = False) -> Fraction:
    fields(value, {"num", "den"}, code)
    num = integer(value["num"], code, minimum=0 if allow_zero else 1,
                  maximum=MAX_RATIONAL_PART)
    den = integer(value["den"], code, minimum=1, maximum=MAX_RATIONAL_PART)
    return bounded(Fraction(num, den))


def encoded(value: Fraction) -> dict[str, int]:
    value = bounded(value)
    return {"num": value.numerator, "den": value.denominator}


def bounded_power(base: Fraction, exponent: int) -> Fraction:
    require(type(exponent) is int, "EXPONENT_TYPE")
    estimate = abs(exponent) * max(base.numerator.bit_length(),
                                   base.denominator.bit_length())
    require(estimate <= MAX_RATIONAL_BITS, "EXPONENT_BIT_LIMIT")
    return bounded(base ** exponent)


def required_credit(target: int) -> int:
    integer(target, "TARGET", minimum=1, maximum=POW_LIMIT)
    return SPACE // (target + 1)


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
        raise JointLifetimeError("NONRATIONAL_JSON_NUMBER")

    def bounded_integer(value):
        require(len(value.lstrip("-")) <= 160, "JSON_INTEGER_SIZE")
        return int(value)

    return json.loads(body, object_pairs_hook=pairs, parse_float=no_float,
                      parse_constant=no_float, parse_int=bounded_integer)


def read_bounded_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode), "INPUT_NOT_REGULAR")
        require(metadata.st_size <= MAX_INPUT_BYTES, "INPUT_SIZE")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            body = stream.read(MAX_INPUT_BYTES + 1)
        require(len(body) <= MAX_INPUT_BYTES, "INPUT_SIZE")
        return body
    finally:
        os.close(descriptor)


@dataclass(frozen=True, order=True)
class ActiveStart:
    name: str
    gap: int
    horizon: int
    charged: Fraction


@dataclass(frozen=True)
class Branch:
    probability: Fraction
    adversarial_ready: int
    new_debt: int
    debt_served: int
    honest_pacer: int
    joins: int
    leaves: int
    parent_height: int
    parent_target: int
    child_target: int
    child_time: int
    next_mtp: int
    next_observed_now: int
    credited_work: int
    delivery_complete: bool
    service_complete: bool
    bad: str
    successor: str

    @property
    def net(self) -> int:
        return (self.adversarial_ready + self.new_debt - self.debt_served -
                self.honest_pacer)


@dataclass(frozen=True)
class Action:
    name: str
    bad_allowance: Fraction
    register: ActiveStart | None
    branches: tuple[Branch, ...]

    @property
    def charge(self) -> Fraction:
        return self.bad_allowance + (Fraction() if self.register is None else
                                     self.register.charged)


@dataclass(frozen=True)
class State:
    name: str
    potential: Fraction
    spent: Fraction
    starts: int
    active_starts: tuple[ActiveStart, ...]
    height: int
    target: int
    mtp: int
    observed_now: int
    cumulative_credit: int
    qualified_units: int
    entry_debt: int
    terminal_bad: bool
    safe_absorbing: bool
    actions: tuple[Action, ...]


@dataclass(frozen=True)
class Model:
    z: Fraction
    future_skew: int
    lifetime_budget: Fraction
    initial_state: str
    states: dict[str, State]


STATE_FIELDS = {
    "id", "potential", "spent", "starts", "active_starts", "height", "target",
    "mtp", "observed_now", "cumulative_credit", "qualified_units", "entry_debt",
    "terminal_bad", "safe_absorbing", "actions",
}
BRANCH_FIELDS = {
    "p", "a", "new_debt", "debt_served", "j", "joins", "leaves",
    "parent_height", "parent_target", "child_target", "child_time", "next_mtp",
    "next_observed_now", "credited_work", "delivery_complete",
    "service_complete", "bad", "next",
}
START_FIELDS = {"id", "gap", "horizon", "charged_crossing_allowance"}


def _start(value: Any, code: str) -> ActiveStart:
    fields(value, START_FIELDS, code)
    return ActiveStart(
        label(value["id"], code),
        integer(value["gap"], code, minimum=1, maximum=MAX_GAP),
        integer(value["horizon"], code, minimum=1, maximum=MAX_HORIZON),
        rational(value["charged_crossing_allowance"], code, allow_zero=True),
    )


def _updated_starts(state: State, action: Action, net: int) -> tuple[tuple[ActiveStart, ...], bool]:
    active = list(state.active_starts)
    if action.register is not None:
        require(action.register.name not in {row.name for row in active},
                "ACTIVE_START_REPLAY")
        active.append(action.register)
    updated = []
    crossed = False
    for row in active:
        remaining_gap = row.gap - net
        remaining_horizon = row.horizon - 1
        crossed |= remaining_gap <= 0
        if remaining_gap > 0 and remaining_horizon > 0:
            updated.append(ActiveStart(row.name, remaining_gap, remaining_horizon,
                                       row.charged))
    return tuple(sorted(updated)), crossed


def parse_model(document: dict) -> Model:
    fields(document, {"schema", "law_scope", "coverage", "z", "future_skew",
                      "lifetime_budget", "initial_state", "states"},
           "DOCUMENT_FIELDS")
    require(document["schema"] == SCHEMA, "SCHEMA")
    require(document["law_scope"] == LAW_SCOPE, "LAW_SCOPE")
    require(document["coverage"] == "all-declared-state-actions-only", "COVERAGE")
    z = rational(document["z"], "Z")
    require(z > 1, "Z_MUST_EXCEED_ONE")
    future_skew = integer(document["future_skew"], "FUTURE_SKEW", maximum=MAX_TIME)
    lifetime_budget = rational(document["lifetime_budget"], "LIFETIME_BUDGET",
                               allow_zero=True)
    require(lifetime_budget <= 1, "LIFETIME_BUDGET_RANGE")
    initial_state = label(document["initial_state"], "INITIAL_STATE")
    require(type(document["states"]) is list and
            1 <= len(document["states"]) <= MAX_STATES, "STATE_COUNT")

    states: dict[str, State] = {}
    action_count = 0
    branch_count = 0
    denominator_lcm = 1
    for row in document["states"]:
        fields(row, STATE_FIELDS, "STATE_FIELDS")
        name = label(row["id"], "STATE_ID")
        require(name not in states, "DUPLICATE_STATE")
        potential = rational(row["potential"], "POTENTIAL")
        require(potential >= 1, "POTENTIAL_DOMINATES_ONE")
        spent = rational(row["spent"], "SPENT", allow_zero=True)
        require(spent <= lifetime_budget, "LIFETIME_BUDGET_EXCEEDED")
        starts = integer(row["starts"], "STARTS", maximum=MAX_STATES)
        terminal_bad = boolean(row["terminal_bad"], "TERMINAL_BAD")
        safe_absorbing = boolean(row["safe_absorbing"], "SAFE_ABSORBING")
        require(not (terminal_bad and safe_absorbing), "TERMINAL_STATE_KIND")
        require(type(row["active_starts"]) is list and
                len(row["active_starts"]) <= MAX_STATES, "ACTIVE_STARTS")
        active_starts = tuple(sorted(_start(value, "ACTIVE_START")
                                     for value in row["active_starts"]))
        require(len({value.name for value in active_starts}) == len(active_starts),
                "DUPLICATE_ACTIVE_START")
        require(starts >= len(active_starts), "ACTIVE_START_COUNT")
        require(not safe_absorbing or not active_starts, "SAFE_ACTIVE_STARTS")
        require(sum((value.charged for value in active_starts), Fraction()) <= spent,
                "ACTIVE_STARTS_NOT_CHARGED")
        for value in active_starts:
            require(value.charged >= bounded(potential * bounded_power(z, -value.gap)),
                    "ACTIVE_START_RESIDUAL_UNDERCHARGED")
        raw_actions = row["actions"]
        require(type(raw_actions) is list and len(raw_actions) <= MAX_ACTIONS,
                "STATE_ACTIONS")
        require((not raw_actions if terminal_bad or safe_absorbing else bool(raw_actions)),
                "STATE_ACTIONS")
        actions = []
        action_names: set[str] = set()
        for raw_action in raw_actions:
            fields(raw_action, {"id", "bad_allowance", "register", "branches"},
                   "ACTION_FIELDS")
            action_name = label(raw_action["id"], "ACTION_ID")
            require(action_name not in action_names, "DUPLICATE_ACTION")
            action_names.add(action_name)
            bad_allowance = rational(raw_action["bad_allowance"], "BAD_ALLOWANCE",
                                     allow_zero=True)
            require(bad_allowance <= 1, "BAD_ALLOWANCE_RANGE")
            register = None if raw_action["register"] is None else _start(
                raw_action["register"], "REGISTER")
            if register is not None:
                require(register.charged >= bounded(
                    potential * bounded_power(z, -register.gap)),
                        "REGISTER_CROSSING_ALLOWANCE")
                require(register.name not in {value.name for value in active_starts},
                        "ACTIVE_START_REPLAY")
            charge = bad_allowance + (Fraction() if register is None else register.charged)
            require(spent + charge <= lifetime_budget, "ACTION_LIFETIME_BUDGET")
            require(type(raw_action["branches"]) is list and raw_action["branches"],
                    "ACTION_BRANCHES")
            action_count += 1
            require(action_count <= MAX_ACTIONS, "TOTAL_ACTION_LIMIT")
            branches = []
            probability_sum = Fraction()
            outcomes: set[str] = set()
            for raw_branch in raw_action["branches"]:
                fields(raw_branch, BRANCH_FIELDS, "BRANCH_FIELDS")
                branch_count += 1
                require(branch_count <= MAX_BRANCHES, "TOTAL_BRANCH_LIMIT")
                probability = rational(raw_branch["p"], "PROBABILITY")
                require(probability <= 1, "PROBABILITY")
                denominator_lcm = lcm(denominator_lcm, probability.denominator,
                                      bad_allowance.denominator, spent.denominator)
                require(denominator_lcm <= MAX_DENOMINATOR_LCM,
                        "PROBABILITY_DENOMINATOR_LIMIT")
                probability_sum = bounded(probability_sum + probability)
                bad = label(raw_branch["bad"], "BAD_LABEL")
                require(bad in BAD_LABELS, "BAD_LABEL")
                branch = Branch(
                    probability,
                    integer(raw_branch["a"], "ADVERSARIAL_READY",
                            maximum=MAX_CREDIT_COMPONENT),
                    integer(raw_branch["new_debt"], "NEW_DEBT",
                            maximum=MAX_CREDIT_COMPONENT),
                    integer(raw_branch["debt_served"], "DEBT_SERVED",
                            maximum=MAX_CREDIT_COMPONENT),
                    integer(raw_branch["j"], "HONEST_PACER",
                            maximum=MAX_CREDIT_COMPONENT),
                    integer(raw_branch["joins"], "JOINS", maximum=MAX_COMPONENT),
                    integer(raw_branch["leaves"], "LEAVES", maximum=MAX_COMPONENT),
                    integer(raw_branch["parent_height"], "PARENT_HEIGHT", maximum=MAX_HEIGHT),
                    integer(raw_branch["parent_target"], "PARENT_TARGET", minimum=1,
                            maximum=POW_LIMIT),
                    integer(raw_branch["child_target"], "CHILD_TARGET", minimum=1,
                            maximum=POW_LIMIT),
                    integer(raw_branch["child_time"], "CHILD_TIME", maximum=MAX_TIME),
                    integer(raw_branch["next_mtp"], "NEXT_MTP", maximum=MAX_TIME),
                    integer(raw_branch["next_observed_now"], "NEXT_OBSERVED_NOW",
                            maximum=MAX_TIME),
                    integer(raw_branch["credited_work"], "CREDITED_WORK", maximum=SPACE),
                    boolean(raw_branch["delivery_complete"], "DELIVERY_COMPLETE"),
                    boolean(raw_branch["service_complete"], "SERVICE_COMPLETE"),
                    bad,
                    label(raw_branch["next"], "SUCCESSOR"),
                )
                fingerprint = json.dumps(raw_branch, sort_keys=True, separators=(",", ":"))
                require(fingerprint not in outcomes, "DUPLICATE_BRANCH_OUTCOME")
                outcomes.add(fingerprint)
                branches.append(branch)
            require(probability_sum == 1, "PROBABILITIES_SUM")
            actions.append(Action(action_name, bad_allowance, register, tuple(branches)))
        states[name] = State(
            name, potential, spent,
            starts, active_starts,
            integer(row["height"], "HEIGHT", maximum=MAX_HEIGHT),
            integer(row["target"], "TARGET", minimum=1, maximum=POW_LIMIT),
            integer(row["mtp"], "MTP", maximum=MAX_TIME),
            integer(row["observed_now"], "OBSERVED_NOW", maximum=MAX_TIME),
            integer(row["cumulative_credit"], "CUMULATIVE_CREDIT",
                    maximum=SPACE * MAX_HEIGHT),
            integer(row["qualified_units"], "QUALIFIED_UNITS", maximum=MAX_COMPONENT),
            integer(row["entry_debt"], "ENTRY_DEBT", maximum=MAX_COMPONENT),
            terminal_bad, safe_absorbing, tuple(actions),
        )
    require(initial_state in states and not states[initial_state].terminal_bad and
            not states[initial_state].safe_absorbing,
            "INITIAL_STATE")
    require(states[initial_state].actions, "INITIAL_ACTIONS")
    model = Model(z, future_skew, lifetime_budget, initial_state, states)
    _validate_transitions(model)
    return model


def _validate_transitions(model: Model) -> None:
    for state in model.states.values():
        require(state.mtp <= state.observed_now + model.future_skew, "STATE_CLOCK_SCOPE")
        for action in state.actions:
            bad_mass = Fraction()
            for branch in action.branches:
                require(branch.successor in model.states, "MISSING_SUCCESSOR")
                successor = model.states[branch.successor]
                require(successor.spent == state.spent + action.charge and
                        successor.starts == state.starts + (action.register is not None),
                        "NONREFUNDABLE_START_CHARGE")
                require(branch.parent_height == state.height and
                        branch.parent_target == state.target, "PARENT_BINDING")
                require(branch.next_observed_now >= state.observed_now,
                        "OBSERVED_CLOCK_REGRESSION")
                updated, crossed = _updated_starts(state, action, branch.net)
                require(successor.active_starts == updated, "ACTIVE_START_TRANSITION")
                if branch.bad == "none":
                    require(not crossed, "UNLABELED_CROSSING")
                    require(not successor.terminal_bad, "GOOD_TO_BAD_STATE")
                    require(branch.delivery_complete and branch.service_complete,
                            "GOOD_REQUIRES_COMPLETE_SERVICE")
                    require(branch.child_time > state.mtp and
                            branch.child_time <= state.observed_now + model.future_skew,
                            "GOOD_TIME_ELIGIBILITY")
                    require(state.mtp <= branch.next_mtp <= branch.child_time,
                            "GOOD_NEXT_MTP")
                    credit = required_credit(branch.child_target)
                    require(branch.credited_work == credit, "REQUIRED_CREDIT")
                    require(successor.height == state.height + 1 and
                            successor.target == branch.child_target and
                            successor.cumulative_credit == state.cumulative_credit + credit and
                            successor.mtp == branch.next_mtp and
                            successor.observed_now == branch.next_observed_now,
                            "GOOD_CHAIN_TRANSITION")
                    require(branch.leaves <= state.qualified_units and
                            successor.qualified_units == state.qualified_units +
                            branch.joins - branch.leaves,
                            "PARTICIPATION_TRANSITION")
                    require(branch.debt_served <= state.entry_debt + branch.new_debt and
                            successor.entry_debt == state.entry_debt +
                            branch.new_debt - branch.debt_served,
                            "ENTRY_DEBT_TRANSITION")
                else:
                    require(successor.terminal_bad, "BAD_NOT_TERMINAL")
                    require(branch.credited_work == 0, "BAD_CREDIT_MUST_BE_ZERO")
                    require((branch.bad != "crossing" or crossed) and
                            (branch.bad == "crossing" or not crossed), "CROSSING_LABEL")
                    require((branch.bad != "delivery" or not branch.delivery_complete) and
                            (branch.bad != "service" or not branch.service_complete),
                            "BAD_SERVICE_LABEL")
                    require(successor.height == state.height and
                            successor.target == state.target and
                            successor.cumulative_credit == state.cumulative_credit and
                            successor.mtp == state.mtp and
                            successor.observed_now == branch.next_observed_now and
                            successor.qualified_units == state.qualified_units and
                            successor.entry_debt == state.entry_debt,
                            "BAD_KILLED_TRANSITION")
                    if branch.bad != "crossing":
                        bad_mass = bounded(bad_mass + branch.probability)
            require(bad_mass <= action.bad_allowance, "BAD_MASS_EXCEEDS_ALLOWANCE")


def _native_scope() -> dict[str, Any]:
    return {
        "qualification": "HOLD_NO_GO",
        "conditional_finite_theorem_only": True,
        "actual_probability_law_authenticated": False,
        "complete_legal_strategy_coverage_proved": False,
        "native_to_model_reduction_proved": False,
        "physical_resource_cost_proved": False,
        "wall_clock_authenticated": False,
        "complete_delivery_law_authenticated": False,
        "dynamic_participation_law_authenticated": False,
        "parent_target_history_authenticated": False,
        "native_mtp_recomputed_from_full_ancestry": False,
        "world_confirmation_starts_covered": False,
        "active_quantum_memory_covered": False,
        "native_common_prefix_qualified": False,
        "native_chain_growth_qualified": False,
        "native_chain_quality_qualified": False,
        "native_common_prefix_failure_bound": None,
        "native_chain_growth_bound": None,
        "native_chain_quality_bound": None,
        "native_six_successor_risk_bound": None,
        "actual_lifetime_failure_bound": None,
        "production_activation": False,
        "finalized": False,
        "execution_authority": False,
    }


def audit_model(document: dict) -> dict[str, Any]:
    model = parse_model(document)
    rows = []
    for state in model.states.values():
        for action in state.actions:
            good_moment = Fraction()
            bad_mass = Fraction()
            for branch in action.branches:
                # A threshold crossing is evaluated by the good-kernel
                # exponential moment before it becomes absorbing. External
                # bad events are killed and paid from the separate allowance.
                if branch.bad in {"none", "crossing"}:
                    successor = model.states[branch.successor]
                    ratio = bounded(successor.potential / state.potential)
                    good_moment = bounded(good_moment + bounded(
                        branch.probability * bounded_power(model.z, branch.net) * ratio))
                elif branch.bad != "crossing":
                    bad_mass = bounded(bad_mass + branch.probability)
            rows.append({
                "state": state.name,
                "action": action.name,
                "good_joint_moment": encoded(good_moment),
                "first_bad_mass_excluding_crossing": encoded(bad_mass),
                "charged_bad_allowance": encoded(action.bad_allowance),
                "registered_crossing_allowance": encoded(
                    Fraction() if action.register is None else action.register.charged),
                "good_moment_passed": good_moment <= 1,
                "bad_allowance_passed": bad_mass <= action.bad_allowance,
            })
    return {
        "schema": SCHEMA,
        "law_scope": LAW_SCOPE,
        "finite_model_certificate_valid": all(
            row["good_moment_passed"] and row["bad_allowance_passed"] for row in rows),
        "checked_states": len(model.states),
        "checked_actions": len(rows),
        "initial_residual_potential": encoded(model.states[model.initial_state].potential),
        "initial_spent_allowance": encoded(model.states[model.initial_state].spent),
        "lifetime_budget": encoded(model.lifetime_budget),
        "actions": rows,
        **_native_scope(),
    }


def combined_bound(document: dict) -> Fraction:
    """Union bound for future bad-or-crossing events in this declared model.

    Existing active starts retain their residual crossing allowances. Future
    registration and bad-event allowances come from the remaining budget. The
    terms are added; marginal probabilities are never multiplied.
    """
    model = parse_model(document)
    report = audit_model(document)
    require(report["finite_model_certificate_valid"], "INVALID_FINITE_CERTIFICATE")
    initial = model.states[model.initial_state]
    active = sum((bounded(initial.potential * bounded_power(model.z, -row.gap))
                  for row in initial.active_starts), Fraction())
    return min(Fraction(1), bounded(active + model.lifetime_budget - initial.spent))


def maximal_failure_probability(document: dict, horizon: int) -> Fraction:
    """Exact Bellman maximum over adaptive actions in the declared finite model."""
    integer(horizon, "HORIZON", maximum=MAX_HORIZON)
    model = parse_model(document)
    cells = 0
    transitions = 0

    @lru_cache(maxsize=None)
    def value(state_name: str, steps: int) -> Fraction:
        nonlocal cells, transitions
        cells += 1
        require(cells <= MAX_DP_CELLS, "DP_CELL_LIMIT")
        state = model.states[state_name]
        if state.terminal_bad:
            return Fraction(1)
        if state.safe_absorbing or steps == 0:
            return Fraction(0)
        require(state.actions, "RIGHT_CENSORED_STATE")
        candidates = []
        for action in state.actions:
            total = Fraction()
            for branch in action.branches:
                transitions += 1
                require(transitions <= MAX_DP_TRANSITIONS, "DP_TRANSITION_LIMIT")
                total = bounded(total + bounded(
                    branch.probability * value(branch.successor, steps - 1)))
            candidates.append(total)
        return max(candidates)

    return bounded(value(model.initial_state, horizon))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", required=True, type=Path)
    parser.add_argument("--horizon", type=int)
    parser.add_argument("--require-native-qualification", action="store_true")
    args = parser.parse_args(argv)
    try:
        body = read_bounded_regular(args.check)
        document = strict_json(body.decode("utf-8"))
        report = audit_model(document)
        report["finite_model_lifetime_union_bound"] = (
            encoded(combined_bound(document)) if report["finite_model_certificate_valid"] else None)
        if args.horizon is not None:
            report["finite_model_exact_maximal_failure_probability"] = encoded(
                maximal_failure_probability(document, args.horizon))
        print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
        if args.require_native_qualification:
            return 3
        return 0 if report["finite_model_certificate_valid"] else 2
    except (JointLifetimeError, OSError, UnicodeError, json.JSONDecodeError,
            RecursionError) as error:
        print(json.dumps({"error": str(error), **_native_scope()}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
