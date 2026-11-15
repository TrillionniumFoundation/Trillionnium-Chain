#!/usr/bin/env python3
"""Exact finite lifecycle-cost certificates; no actual-W1 hardness claim.

The caller owns the finite game and its prices/probabilities.  A certificate
never authenticates those premises, proves physical work, or enables chainwork.
Only the standard library is used; all certificate checks use Fraction.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256
import json
from math import lcm
from pathlib import Path

Q = Fraction
MAX_STATES = 512
MAX_ACTIONS = 64
MAX_OUTCOMES = 64
MAX_ITERATIONS = 512
MAX_EXPONENT = 4096
MAX_SCALE = 1_000_000
SCOPE = "declared-finite-classical-MDP-only"


def require(condition, code):
    if not condition:
        raise ValueError(code)


def rational(value, code="RATIONAL_REQUIRED"):
    require(type(value) in (int, Fraction), code)
    return Q(value)


def read_rational(value):
    require(type(value) is str and 0 < len(value) <= 32768, "RATIONAL_ENCODING")
    try:
        result = Q(value)
    except (ValueError, ZeroDivisionError):
        raise ValueError("RATIONAL_ENCODING") from None
    require(str(result) == value, "RATIONAL_CANONICAL")
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return sha256(canonical(value)).hexdigest()


@dataclass(frozen=True)
class Outcome:
    probability: Fraction
    next_state: str
    reward: Fraction = Q(0)
    cost: Fraction = Q(0)


@dataclass(frozen=True)
class Action:
    name: str
    outcomes: tuple[Outcome, ...]
    # Predictable credit deficit, selected before the outcome and accumulated.
    eta: Fraction = Q(0)


@dataclass(frozen=True)
class Game:
    name: str
    states: tuple[str, ...]
    initial: tuple[tuple[str, Fraction], ...]
    actions: dict[str, tuple[Action, ...]]
    cost_model: str


def validate_game(game):
    require(type(game) is Game, "GAME_TYPE")
    for name in (game.name, game.cost_model):
        require(type(name) is str and 0 < len(name) <= 1024, "GAME_DESCRIPTION")
    require(type(game.states) is tuple and 0 < len(game.states) <= MAX_STATES,
            "STATE_LIMIT")
    require(all(type(s) is str and 0 < len(s) <= 128 for s in game.states)
            and len(set(game.states)) == len(game.states), "STATE_IDENTITY")
    require(type(game.actions) is dict and set(game.actions) == set(game.states),
            "ACTION_COVERAGE")
    require(type(game.initial) is tuple and 0 < len(game.initial) <= len(game.states),
            "INITIAL_LAW")
    seen, total = set(), Q(0)
    for state, probability in game.initial:
        require(state in game.actions and state not in seen, "INITIAL_STATE")
        seen.add(state)
        probability = rational(probability)
        require(probability > 0, "INITIAL_PROBABILITY")
        total += probability
    require(total == 1, "INITIAL_NORMALIZATION")
    for state in game.states:
        actions = game.actions[state]
        require(type(actions) is tuple and 0 < len(actions) <= MAX_ACTIONS,
                "ACTION_LIMIT")
        names = set()
        for action in actions:
            require(type(action) is Action and type(action.name) is str
                    and 0 < len(action.name) <= 128 and action.name not in names,
                    "ACTION_IDENTITY")
            names.add(action.name)
            require(rational(action.eta) >= 0, "NEGATIVE_ETA")
            require(type(action.outcomes) is tuple
                    and 0 < len(action.outcomes) <= MAX_OUTCOMES, "OUTCOME_LIMIT")
            probability = Q(0)
            for outcome in action.outcomes:
                require(type(outcome) is Outcome and outcome.next_state in game.actions,
                        "OUTCOME_STATE")
                require(rational(outcome.probability) > 0, "OUTCOME_PROBABILITY")
                require(rational(outcome.reward) >= 0, "NEGATIVE_REWARD")
                require(rational(outcome.cost) >= 0, "NEGATIVE_COST")
                probability += outcome.probability
            require(probability == 1, "OUTCOME_NORMALIZATION")


def game_data(game):
    validate_game(game)
    return {
        "schema": "pon-lifecycle-finite-game-v1", "name": game.name,
        "scope": SCOPE, "cost_model": game.cost_model,
        "states": list(game.states),
        "initial": [[s, str(p)] for s, p in game.initial],
        "actions": {s: [{"name": a.name, "eta": str(a.eta), "outcomes": [
            {"p": str(o.probability), "next": o.next_state,
             "reward": str(o.reward), "cost": str(o.cost)} for o in a.outcomes]}
            for a in game.actions[s]] for s in game.states},
    }


def game_digest(game):
    return digest(game_data(game))


def parameters(kappa, initial_budget_cap):
    kappa, initial_budget_cap = rational(kappa), rational(initial_budget_cap)
    require(kappa >= 0 and initial_budget_cap >= 0, "ACCOUNTING_PARAMETERS")
    return kappa, initial_budget_cap


def gain(outcome, action, kappa):
    return outcome.reward - kappa * outcome.cost - action.eta


def potential_certificate(game, kappa, potential):
    """Package an untrusted candidate; the independent checker must accept it."""
    return {"schema": "pon-lifecycle-potential-certificate-v1",
            "game_sha256": game_digest(game), "kappa": str(rational(kappa)),
            "potential": {s: str(rational(potential[s])) for s in game.states}}


def verify_potential(game, certificate, *, expected_kappa, initial_budget_cap):
    """Check every declared action, not one sampled or optimizing policy.

    expected_kappa and initial_budget_cap belong to the verifier, independently
    of the submitted certificate.  Nonnegative Phi and its initial cap forbid
    hiding free credit in an arbitrary constant shift or a negative terminal.
    """
    validate_game(game)
    kappa, cap = parameters(expected_kappa, initial_budget_cap)
    require(type(certificate) is dict and set(certificate) == {
        "schema", "game_sha256", "kappa", "potential"}, "POTENTIAL_FIELDS")
    require(certificate["schema"] == "pon-lifecycle-potential-certificate-v1"
            and certificate["game_sha256"] == game_digest(game), "POTENTIAL_GAME")
    require(read_rational(certificate["kappa"]) == kappa, "KAPPA_BINDING")
    raw = certificate["potential"]
    require(type(raw) is dict and set(raw) == set(game.states), "POTENTIAL_COVERAGE")
    phi = {s: read_rational(raw[s]) for s in game.states}
    require(all(v >= 0 for v in phi.values()), "NEGATIVE_POTENTIAL")
    initial = sum((p * phi[s] for s, p in game.initial), Q(0))
    require(initial <= cap, "INITIAL_POTENTIAL_BUDGET")
    checked = 0
    for state in game.states:
        for action in game.actions[state]:
            excess = sum((o.probability * (o.reward + phi[o.next_state]
                          - kappa * o.cost) for o in action.outcomes), Q(0))
            require(excess <= phi[state] + action.eta,
                    "POTENTIAL_ACTION:" + state + ":" + action.name)
            checked += 1
    return {"scope": SCOPE, "checked_states": len(game.states),
            "checked_actions": checked, "initial_expected_potential": str(initial),
            "initial_budget_cap": str(cap),
            "max_eta_per_step": str(max(a.eta for actions in game.actions.values()
                                        for a in actions)),
            "actual_work_lower_bound_proven": False, "production_qualified": False}


def synthesize_potential(game, *, kappa, initial_budget_cap, max_iterations=128):
    """Monotone exact Bellman search, with no convergence tolerance or fallback.

    A fixed point is independently checked.  A finite-horizon policy can refute
    the supplied initial cap.  Exhausting the iteration limit is INCONCLUSIVE,
    even if floating-point value iteration would appear to have converged.
    """
    validate_game(game)
    kappa, cap = parameters(kappa, initial_budget_cap)
    require(type(max_iterations) is int and 1 <= max_iterations <= MAX_ITERATIONS,
            "ITERATION_LIMIT")
    values = {s: Q(0) for s in game.states}
    policies = []
    for iteration in range(1, max_iterations + 1):
        following, policy = {}, {}
        for state in game.states:
            best, choice = Q(0), None  # Stopping is always allowed.
            for action in game.actions[state]:
                candidate = sum((o.probability * (gain(o, action, kappa)
                                + values[o.next_state]) for o in action.outcomes), Q(0))
                if candidate > best:
                    best, choice = candidate, action.name
            following[state], policy[state] = best, choice
        policies.append(policy)
        initial = sum((p * following[s] for s, p in game.initial), Q(0))
        if initial > cap:
            witness = {"schema": "pon-lifecycle-budget-refutation-v1",
                       "game_sha256": game_digest(game), "kappa": str(kappa),
                       "policies_by_remaining_steps": policies}
            checked = verify_budget_refutation(game, witness, expected_kappa=kappa,
                                                initial_budget_cap=cap)
            return {"status": "INITIAL_BUDGET_REFUTED", "iterations": iteration,
                    "witness": witness, "verification": checked}
        if following == values:
            certificate = potential_certificate(game, kappa, following)
            checked = verify_potential(game, certificate, expected_kappa=kappa,
                                       initial_budget_cap=cap)
            return {"status": "CERTIFIED_FINITE_MODEL", "iterations": iteration,
                    "certificate": certificate, "verification": checked}
        values = following
    return {"status": "INCONCLUSIVE", "iterations": max_iterations,
            "finite_horizon_initial_excess": str(initial),
            "reason": "no-exact-stationary-fixed-point-within-limit",
            "scope": SCOPE, "production_qualified": False}


def verify_budget_refutation(game, witness, *, expected_kappa, initial_budget_cap):
    """Forward-propagate a submitted policy; do not rerun Bellman maximization."""
    validate_game(game)
    kappa, cap = parameters(expected_kappa, initial_budget_cap)
    require(type(witness) is dict and set(witness) == {
        "schema", "game_sha256", "kappa", "policies_by_remaining_steps"},
        "REFUTATION_FIELDS")
    require(witness["schema"] == "pon-lifecycle-budget-refutation-v1"
            and witness["game_sha256"] == game_digest(game), "REFUTATION_GAME")
    require(read_rational(witness["kappa"]) == kappa, "KAPPA_BINDING")
    policies = witness["policies_by_remaining_steps"]
    require(type(policies) is list and 0 < len(policies) <= MAX_ITERATIONS,
            "POLICY_HORIZON")
    actions = {s: {a.name: a for a in game.actions[s]} for s in game.states}
    for policy in policies:
        require(type(policy) is dict and set(policy) == set(game.states), "POLICY_COVERAGE")
        require(all(choice is None or choice in actions[s]
                    for s, choice in policy.items()), "POLICY_ACTION")
    mass, excess = dict(game.initial), Q(0)
    for policy in reversed(policies):
        following = {}
        for state, probability in mass.items():
            choice = policy[state]
            if choice is None:
                continue
            action = actions[state][choice]
            for outcome in action.outcomes:
                weight = probability * outcome.probability
                excess += weight * gain(outcome, action, kappa)
                following[outcome.next_state] = following.get(outcome.next_state, Q(0)) + weight
        mass = following
    require(excess > cap, "NOT_AN_INITIAL_BUDGET_REFUTATION")
    return {"scope": SCOPE, "horizon": len(policies),
            "expected_reward_minus_cost_and_eta": str(excess),
            "initial_budget_cap": str(cap), "strict_excess": str(excess - cap)}


def reachable(game):
    seen = {s for s, _ in game.initial}
    pending = list(seen)
    while pending:
        state = pending.pop()
        for action in game.actions[state]:
            for outcome in action.outcomes:
                if outcome.next_state not in seen:
                    seen.add(outcome.next_state)
                    pending.append(outcome.next_state)
    return seen


def find_positive_cycle(game, *, kappa):
    """Bellman-Ford on deterministic actions only; None is not a safety proof."""
    validate_game(game)
    kappa, _ = parameters(kappa, 0)
    states = sorted(reachable(game))
    edges = [(s, a.name, a.outcomes[0].next_state, gain(a.outcomes[0], a, kappa))
             for s in states for a in game.actions[s] if len(a.outcomes) == 1]
    distance, predecessor = {s: Q(0) for s in states}, {}
    changed = None
    for _ in states:
        changed = None
        for state, action, dest, weight in edges:
            if distance[dest] < distance[state] + weight:
                distance[dest] = distance[state] + weight
                predecessor[dest] = (state, action)
                changed = dest
        if changed is None:
            return None
    state = changed
    for _ in states:
        state = predecessor[state][0]
    start, reverse = state, []
    while True:
        source, action = predecessor[state]
        reverse.append({"state": source, "action": action})
        state = source
        if state == start:
            break
    witness = {"schema": "pon-lifecycle-positive-cycle-v1",
               "game_sha256": game_digest(game), "kappa": str(kappa),
               "cycle": list(reversed(reverse))}
    verify_positive_cycle(game, witness, expected_kappa=kappa)
    return witness


def verify_positive_cycle(game, witness, *, expected_kappa):
    validate_game(game)
    kappa, _ = parameters(expected_kappa, 0)
    require(type(witness) is dict and set(witness) == {
        "schema", "game_sha256", "kappa", "cycle"}, "CYCLE_FIELDS")
    require(witness["schema"] == "pon-lifecycle-positive-cycle-v1"
            and witness["game_sha256"] == game_digest(game), "CYCLE_GAME")
    require(read_rational(witness["kappa"]) == kappa, "KAPPA_BINDING")
    cycle = witness["cycle"]
    require(type(cycle) is list and 0 < len(cycle) <= len(game.states), "CYCLE_LIMIT")
    live, total = reachable(game), Q(0)
    for index, row in enumerate(cycle):
        require(type(row) is dict and set(row) == {"state", "action"}, "CYCLE_ROW")
        state = row["state"]
        require(state in live, "CYCLE_UNREACHABLE")
        matches = [a for a in game.actions[state] if a.name == row["action"]]
        require(len(matches) == 1 and len(matches[0].outcomes) == 1, "CYCLE_ACTION")
        action = matches[0]
        outcome = action.outcomes[0]
        require(outcome.next_state == cycle[(index + 1) % len(cycle)]["state"],
                "CYCLE_EDGE")
        total += gain(outcome, action, kappa)
    require(total > 0, "CYCLE_NOT_POSITIVE")
    return {"scope": SCOPE, "net_credit_per_cycle": str(total),
            "consequence": "no-finite-stationary-potential-for-this-game"}


def verify_occupation_witness(game, weights, *, expected_kappa):
    """Exact dual contradiction, including stochastic recurrent actions.

    weights maps (state, action) to rational occupation mass.  Stationary flow
    cancels every potential term.  Positive net gain then refutes feasibility.
    This checks a supplied witness, not a complete general-MDP LP solver.
    """
    validate_game(game)
    kappa, _ = parameters(expected_kappa, 0)
    require(type(weights) is dict and weights, "OCCUPATION_FIELDS")
    flow, net, mass, live = {s: Q(0) for s in game.states}, Q(0), Q(0), reachable(game)
    for key, weight in weights.items():
        require(type(key) is tuple and len(key) == 2, "OCCUPATION_KEY")
        state, name = key
        require(state in live, "OCCUPATION_UNREACHABLE")
        action = next((a for a in game.actions[state] if a.name == name), None)
        require(action is not None, "OCCUPATION_ACTION")
        weight = rational(weight)
        require(weight > 0, "OCCUPATION_WEIGHT")
        mass += weight
        flow[state] += weight
        for outcome in action.outcomes:
            flow[outcome.next_state] -= weight * outcome.probability
            net += weight * outcome.probability * gain(outcome, action, kappa)
    require(mass == 1, "OCCUPATION_NORMALIZATION")
    require(all(value == 0 for value in flow.values()), "OCCUPATION_FLOW")
    require(net > 0, "OCCUPATION_NOT_POSITIVE")
    return {"scope": SCOPE, "net_credit_per_step": str(net),
            "consequence": "no-finite-stationary-potential-for-this-game"}


def integer_exponent(value, scale):
    exponent = value * scale
    require(exponent.denominator == 1 and abs(exponent.numerator) <= MAX_EXPONENT,
            "EXPONENT_DOMAIN")
    return exponent.numerator


def synthesize_tail_certificate(game, potential, *, expected_kappa,
                                initial_budget_cap, tilt=Q(9, 8)):
    """Exact rational exponential envelope; a loose envelope may equal one."""
    verify_potential(game, potential, expected_kappa=expected_kappa,
                     initial_budget_cap=initial_budget_cap)
    kappa, _ = parameters(expected_kappa, initial_budget_cap)
    q = rational(tilt)
    require(q > 1, "TAIL_TILT")
    phi = {s: read_rational(potential["potential"][s]) for s in game.states}
    scale = 1
    for value in phi.values():
        scale = lcm(scale, value.denominator)
    for state in game.states:
        for action in game.actions[state]:
            for outcome in action.outcomes:
                delta = gain(outcome, action, kappa) + phi[outcome.next_state] - phi[state]
                scale = lcm(scale, delta.denominator)
    require(scale <= MAX_SCALE, "TAIL_SCALE_LIMIT")
    # Match the independent verifier's supported initial-moment domain.
    # A constant potential shift leaves every delta unchanged, but can make
    # the initial exponential moment too large for this bounded checker.
    for state, _ in game.initial:
        integer_exponent(phi[state], scale)
    rho = Q(1)
    for state in game.states:
        for action in game.actions[state]:
            moment = sum((o.probability * q ** integer_exponent(
                gain(o, action, kappa) + phi[o.next_state] - phi[state], scale)
                for o in action.outcomes), Q(0))
            rho = max(rho, moment)
    return {"schema": "pon-lifecycle-rational-tail-v1", "game_sha256": game_digest(game),
            "potential_sha256": digest(potential), "tilt": str(q),
            "scale": scale, "normalizer": str(rho)}


def verify_tail_bound(game, potential, tail, *, expected_kappa, initial_budget_cap,
                      horizon, threshold):
    """Ville bound for any crossing time <= horizon in the declared game.

    Event: exists t <= N with R_t - kappa*C_t - sum(eta)_t >= threshold.
    Initial exponential moment is retained; E[Phi_0] is NOT an a.s. cap.
    """
    verify_potential(game, potential, expected_kappa=expected_kappa,
                     initial_budget_cap=initial_budget_cap)
    kappa, _ = parameters(expected_kappa, initial_budget_cap)
    require(type(tail) is dict and set(tail) == {
        "schema", "game_sha256", "potential_sha256", "tilt", "scale", "normalizer"},
        "TAIL_FIELDS")
    require(tail["schema"] == "pon-lifecycle-rational-tail-v1"
            and tail["game_sha256"] == game_digest(game)
            and tail["potential_sha256"] == digest(potential), "TAIL_BINDING")
    q, rho, scale = read_rational(tail["tilt"]), read_rational(tail["normalizer"]), tail["scale"]
    require(q > 1 and rho >= 1, "TAIL_PARAMETERS")
    require(type(scale) is int and 1 <= scale <= MAX_SCALE, "TAIL_SCALE")
    require(type(horizon) is int and 0 <= horizon <= 1024, "TAIL_HORIZON")
    threshold = rational(threshold)
    require(threshold >= 0, "TAIL_THRESHOLD")
    boundary = integer_exponent(threshold, scale)
    phi = {s: read_rational(potential["potential"][s]) for s in game.states}
    for state in game.states:
        for action in game.actions[state]:
            moment = sum((o.probability * q ** integer_exponent(
                gain(o, action, kappa) + phi[o.next_state] - phi[state], scale)
                for o in action.outcomes), Q(0))
            require(moment <= rho, "TAIL_ACTION:" + state + ":" + action.name)
    initial_moment = sum((p * q ** integer_exponent(phi[s], scale)
                          for s, p in game.initial), Q(0))
    bound = min(Q(1), rho ** horizon * initial_moment / q ** boundary)
    return {"schema": "pon-lifecycle-tail-result-v1", "scope": SCOPE,
            "horizon": horizon, "threshold": str(threshold),
            "initial_exponential_moment": str(initial_moment),
            "probability_upper_bound": str(bound),
            "event": "exists-t<=horizon:R-kappa*C-cumulative_eta>=threshold",
            "arbitrary_adaptive_policy_and_bounded_stopping": True,
            "native_chain_security_probability": None,
            "quantum_security_proven": False, "production_qualified": False}


def nonce_bank_game(*, initial_records=("u", "u"), initial_cache=-1,
                    reset_spent_on_restart=False):
    """Two priced nonce selectors, two coordinates, one reusable result slot.

    u: unpurchased; p0/p1: paid deferred selector; h: unclaimed hit;
    m: attempted miss/discarded; r: credit redeemed once.  The two context
    labels name the SAME work namespace.  They cannot create new identities.
    Independent selectors/tickets and atomic prices are explicit assumptions.
    """
    require(type(initial_records) is tuple and len(initial_records) == 2
            and all(x in {"u", "p0", "p1", "h", "m", "r"} for x in initial_records),
            "BANK_RECORDS")
    require(type(initial_cache) is int and initial_cache in {-1, 0, 1}, "BANK_CACHE")
    require(type(reset_spent_on_restart) is bool, "BANK_MUTANT")
    initial = (0, initial_cache, initial_records)
    pending, seen, graph = deque([initial]), {initial}, {}

    def identity(state):
        alias, cache, records = state
        return f"alias{alias}/cache{cache}/" + ",".join(records)

    while pending:
        state = pending.popleft()
        alias, cache, records = state
        actions = []

        def add(name, rows):
            outcomes = []
            for probability, dest, reward, cost in rows:
                outcomes.append(Outcome(Q(probability), identity(dest), Q(reward), Q(cost)))
                if dest not in seen:
                    require(len(seen) < MAX_STATES, "BANK_STATE_LIMIT")
                    seen.add(dest)
                    pending.append(dest)
            actions.append(Action(name, tuple(outcomes)))

        def deterministic(name, dest, reward=0, cost=0):
            add(name, [(1, dest, reward, cost)])

        deterministic("stop", state)
        deterministic("restart_preserve_all_accounts", state)
        deterministic("relabel_context_same_work", (1 - alias, cache, records))
        deterministic("evict_result_cache", (alias, -1, records))
        dropped = tuple("m" if x in {"p0", "p1", "h"} else x for x in records)
        deterministic("retire_context_discard_unspent", (1 - alias, -1, dropped))
        for coordinate in range(2):
            if cache != coordinate:
                deterministic(f"acquire_result:{coordinate}", (alias, coordinate, records), cost=2)
        for index, status in enumerate(records):
            def replace(value):
                return records[:index] + (value,) + records[index + 1:]
            if status == "u":
                add(f"prepay_nonce:{index}", [
                    (Q(1, 2), (alias, cache, replace(f"p{coordinate}")), 0, 1)
                    for coordinate in range(2)])
            if status == f"p{cache}":
                add(f"continue_nonce:{index}", [
                    (Q(1, 4), (alias, cache, replace("h")), 0, 1),
                    (Q(3, 4), (alias, cache, replace("m")), 0, 1)])
            if status in {"p0", "p1", "h"}:
                deterministic(f"abort_or_withhold:{index}", (alias, cache, replace("m")))
            if status == "h":
                deterministic(f"publish_once:{index}", (alias, cache, replace("r")), reward=1)
            if status == "r":
                deterministic(f"duplicate_publication:{index}", state)
                if reset_spent_on_restart:
                    deterministic(f"BUG_restart_restores_credit:{index}",
                                  (alias, cache, replace("h")))
        graph[identity(state)] = tuple(actions)
    game = Game("paid-nonce-bank-v1" + ("-restart-mutant" if reset_spent_on_restart else ""),
                tuple(sorted(graph)), ((identity(initial), Q(1)),), graph,
                "assumed scalar oracle prices: selector=1, result=2, continuation=1; "
                "uniform independent 2-coordinate selectors and independent Bernoulli(1/4) tickets; "
                "public model/input initially free; no concrete SHA or physical-cost reduction")
    validate_game(game)
    return game


def demo():
    game = nonce_bank_game()
    result = synthesize_potential(game, kappa=Q(1, 8), initial_budget_cap=0)
    warm = nonce_bank_game(initial_records=("p0", "p0"), initial_cache=0)
    warm_refutation = synthesize_potential(warm, kappa=Q(1, 8), initial_budget_cap=0)
    warm_accounting = synthesize_potential(warm, kappa=Q(1, 8), initial_budget_cap=Q(1, 4))
    # A strictly enlarged strategy class: two continuations share one charge.
    # This is a declared countermodel, not a measured native implementation.
    shared_actions = dict(warm.actions)
    shared_rows = []
    for first in ("h", "m"):
        for second in ("h", "m"):
            probability = (Q(1, 4) if first == "h" else Q(3, 4)) * (
                Q(1, 4) if second == "h" else Q(3, 4))
            shared_rows.append(Outcome(probability, f"alias0/cache0/{first},{second}",
                                       Q(0), Q(1)))
    shared_actions["alias0/cache0/p0,p0"] += (
        Action("shared_continuation_for_two_nonces", tuple(shared_rows)),)
    shared = Game("warm-bank-shared-continuation-countermodel-v1", warm.states,
                  warm.initial, shared_actions, warm.cost_model +
                  "; countermodel additionally permits two continuations for one cost unit")
    shared_upper = synthesize_potential(shared, kappa=Q(1, 8), initial_budget_cap=Q(3, 8))
    # At 5/16 the search continues until a policy realizes 3/8.  Forward
    # validation against the original 1/4 cap then exhibits the full 1/8 gap.
    shared_policy = synthesize_potential(shared, kappa=Q(1, 8),
                                         initial_budget_cap=Q(5, 16))["witness"]
    shared_lower = verify_budget_refutation(shared, shared_policy,
                                            expected_kappa=Q(1, 8), initial_budget_cap=Q(1, 4))
    mutant = nonce_bank_game(reset_spent_on_restart=True)
    cycle = find_positive_cycle(mutant, kappa=Q(1, 8))
    tail_game = Game("paid-fair-coin-tail-control-v1", ("s",), (("s", Q(1)),), {
        "s": (Action("paid_coin", (Outcome(Q(1, 2), "s", Q(1), Q(1)),
                                    Outcome(Q(1, 2), "s", Q(0), Q(1)))),)},
        "iid fair paid coins; unit cost and at most one fresh unique credit per step; not SHA")
    tail_phi = potential_certificate(tail_game, Q(1, 2), {"s": Q(0)})
    tail = synthesize_tail_certificate(tail_game, tail_phi, expected_kappa=Q(1, 2),
                                        initial_budget_cap=0, tilt=Q(2))
    tail_result = verify_tail_bound(tail_game, tail_phi, tail, expected_kappa=Q(1, 2),
                                    initial_budget_cap=0, horizon=10, threshold=4)
    report = {"schema": "pon-lifecycle-cost-demo-v1", "game": game_data(game),
              "accounting": result, "warm_bank": {
                  "game": game_data(warm), "zero_initial_cap": warm_refutation,
                  "one_quarter_initial_cap": warm_accounting}, "restart_mutant": {
                  "game": game_data(mutant), "witness": cycle,
                  "verification": verify_positive_cycle(mutant, cycle, expected_kappa=Q(1, 8))},
              "strategy_expansion": {"game": game_data(shared),
                  "old_initial_cap": "1/4", "new_exact_initial_excess": "3/8",
                  "strict_gap": "1/8", "upper_certificate": shared_upper,
                  "lower_policy_witness": shared_policy, "lower_verification": shared_lower},
              "finite_tail_control": {"game": game_data(tail_game),
                  "potential": tail_phi, "tail_certificate": tail, "result": tail_result},
              "actual_W1_all_algorithm_lower_bound": None,
              "quantum_lifecycle_certificate": None, "qualification": "HOLD_NO_GO"}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        help="New report path; existing evidence is never overwritten")
    args = parser.parse_args()
    data = json.dumps(demo(), indent=2, sort_keys=True) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(data)
    else:
        print(data, end="")


if __name__ == "__main__":
    main()
