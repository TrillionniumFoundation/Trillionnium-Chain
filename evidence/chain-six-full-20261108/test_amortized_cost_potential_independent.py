#!/usr/bin/env python3
"""Independent 3,625-model oracles and adversarial input regressions for AC1.

The reference algorithms below do not use the module's inequality builder,
Gaussian elimination, Bellman recursion, or Farkas search. They solve two small
families directly: bounded integer difference inequalities and a one-dimensional
Markov interval. These remain synthetic finite models, not native cost bounds.
"""
from __future__ import annotations

from dataclasses import replace
from fractions import Fraction as F
from itertools import product
import unittest

from amortized_cost_potential import (
    Action, Model, Outcome, synthesize, verify_dual, verify_potential,
)


STATES = ("a", "b")


def deterministic_model(transitions, caps) -> Model:
    """Represent each declared integer gain as credit minus nonnegative cost."""
    actions = {}
    for state, (successor, gain) in zip(STATES, transitions):
        outcome = Outcome(F(1), successor, F(max(0, -gain)), ((1, max(0, gain)),))
        actions[state] = (Action("step", (outcome,)),)
    return Model("independent-integer-control", actions, {1: F(1)}, F(1),
                 {state: F(0) for state in STATES},
                 {state: F(cap) for state, cap in zip(STATES, caps)})


def enumerate_integer_potentials(transitions, caps):
    """Enumerate every integer candidate within the two declared initial caps.

    This is complete for these particular instances: every constraint is
    Phi(source) >= gain + Phi(target) with integer gain, and all caps are
    nonnegative integers. Flooring every coordinate of a feasible real vector
    preserves each inequality, nonnegativity, and the caps. Consequently a
    feasible instance has an enumerated integer witness. The least solution
    also has integral coordinates; otherwise flooring would strictly lower it.
    """
    solutions = []
    for values in product(*(range(cap + 1) for cap in caps)):
        candidate = dict(zip(STATES, values))
        if all(candidate[state] >= gain + candidate[successor]
               for state, (successor, gain) in zip(STATES, transitions)):
            solutions.append(candidate)
    return solutions


def markov_model(a: F, b: F, gain_a: int, gain_b: int, caps) -> Model:
    """Two states, one action each, with explicit positive switching chances."""
    actions = {}
    for state, other, probability, gain in (
            ("a", "b", a, gain_a), ("b", "a", b, gain_b)):
        outcomes = tuple(
            Outcome(chance, target, F(max(0, -gain)), ((1, max(0, gain)),))
            for chance, target in ((probability, other), (1 - probability, state))
            if chance > 0
        )
        actions[state] = (Action("step", outcomes),)
    return Model("independent-markov-interval-control", actions, {1: F(1)}, F(1),
                 {state: F(0) for state in STATES},
                 {state: F(cap) for state, cap in zip(STATES, caps)})


def markov_interval_solution(a: F, b: F, gain_a: int, gain_b: int, caps):
    """Eliminate both Bellman rows by hand, without a generic LP operation.

    Setting d = Phi(a)-Phi(b) gives gain_a/a <= d <= -gain_b/b.
    Nonnegative potentials within their caps permit -cap_b <= d <= cap_a.
    The intersection is feasible iff nonempty. Its point closest to zero gives
    the pointwise least potential pair (max(d,0), max(-d,0)).
    """
    lower = max(F(gain_a) / a, -F(caps[1]))
    upper = min(-F(gain_b) / b, F(caps[0]))
    if lower > upper:
        return None
    difference = lower if lower > 0 else upper if upper < 0 else F(0)
    return {"a": max(difference, F(0)), "b": max(-difference, F(0))}


def profitable_self_loop() -> Model:
    """A finite zero-cost positive-credit cycle cannot have any finite Phi."""
    actions = {"s": (Action("free_credit", (Outcome(F(1), "s", F(0), ((1, 1),)),)),)}
    return Model("input-regression-positive-loop", actions, {1: F(1)}, F(1),
                 {"s": F(0)}, {"s": F(0)})


class IndependentFiniteOracles(unittest.TestCase):
    def assert_certificate(self, model, result, expected_potential):
        """Check both reported feasibility and a separately reconstructed witness."""
        self.assertEqual(result["status"],
                         "feasible" if expected_potential is not None else "infeasible")
        if expected_potential is not None:
            self.assertTrue(result["least_potential_proved"])
            self.assertEqual(result["potential"], expected_potential)
            self.assertTrue(verify_potential(model, result["potential"])["valid"])
        else:
            receipt = verify_dual(model, result["dual_multipliers"])
            self.assertTrue(receipt["valid"])
            self.assertEqual(receipt["contradiction"], 1)
        for claim in ("all_algorithm_cost_qualified", "quantum_cost_qualified",
                      "native_consensus_qualified", "tail_qualified"):
            self.assertIs(result[claim], False)

    def test_1600_deterministic_models_against_complete_integer_grid(self):
        cases = feasible = infeasible = 0
        choices = tuple(product(STATES, range(-2, 3)))
        for transitions in product(choices, repeat=2):
            for caps in product(range(4), repeat=2):
                with self.subTest(transitions=transitions, caps=caps):
                    solutions = enumerate_integer_potentials(transitions, caps)
                    expected = (min(solutions, key=lambda row: sum(row.values()))
                                if solutions else None)
                    model = deterministic_model(transitions, caps)
                    self.assert_certificate(model, synthesize(model), expected)
                    cases += 1
                    feasible += expected is not None
                    infeasible += expected is None
        self.assertEqual((cases, feasible, infeasible), (1600, 760, 840))

    def test_2025_stochastic_models_against_exact_difference_interval(self):
        cases = feasible = infeasible = 0
        probabilities = (F(1, 4), F(1, 2), F(1))
        for a, b, gain_a, gain_b, cap_a, cap_b in product(
                probabilities, probabilities, range(-2, 3), range(-2, 3),
                (0, 1, 3), (0, 1, 3)):
            caps = (cap_a, cap_b)
            with self.subTest(a=a, b=b, gain_a=gain_a, gain_b=gain_b, caps=caps):
                expected = markov_interval_solution(a, b, gain_a, gain_b, caps)
                model = markov_model(a, b, gain_a, gain_b, caps)
                self.assert_certificate(model, synthesize(model), expected)
                cases += 1
                feasible += expected is not None
                infeasible += expected is None
        self.assertEqual((cases, feasible, infeasible), (2025, 861, 1164))


class AdversarialInputRegressions(unittest.TestCase):
    def test_typed_positive_credit_loop_has_an_exact_contradiction(self):
        model = profitable_self_loop()
        result = synthesize(model)
        self.assertEqual(result["status"], "infeasible")
        self.assertTrue(verify_dual(model, result["dual_multipliers"])["valid"])

    def test_iterators_cannot_erase_actions_outcomes_or_credit(self):
        """Reject before iteration, so validation cannot consume the declaration.

        Before the input hardening, actions and credits iterators were consumed
        by validation and produced a false feasible zero potential. An outcomes
        iterator failed only during a later revalidation after being consumed.
        """
        for location in ("actions", "outcomes", "credits"):
            with self.subTest(location=location):
                original = profitable_self_loop()
                action = original.actions["s"][0]
                outcome = action.outcomes[0]
                if location == "actions":
                    contents = original.actions["s"]
                    iterator = iter(contents)
                    malformed = replace(original, actions={"s": iterator})
                elif location == "outcomes":
                    contents = action.outcomes
                    iterator = iter(contents)
                    malformed_action = replace(action, outcomes=iterator)
                    malformed = replace(original, actions={"s": (malformed_action,)})
                else:
                    contents = outcome.credits
                    iterator = iter(contents)
                    malformed_outcome = replace(outcome, credits=iterator)
                    malformed_action = replace(action, outcomes=(malformed_outcome,))
                    malformed = replace(original, actions={"s": (malformed_action,)})
                with self.assertRaises(ValueError):
                    synthesize(malformed)
                self.assertEqual(tuple(iterator), contents,
                                 "shape rejection must precede consuming the iterator")

    def test_delimiter_collision_cannot_alias_distinct_constraint_rows(self):
        """Old action:a:b:c labels merged two distinct state/action identities."""
        model = Model(
            "constraint-identity-collision-control",
            {
                "a": (Action("b:c", (Outcome(F(1), "a", F(0), ((1, 1),)),)),),
                "a:b": (Action("c", (Outcome(F(1), "a", F(1)),)),),
            },
            {1: F(1)}, F(1), {"a": F(0), "a:b": F(0)}, {"a": F(0), "a:b": F(0)},
        )
        result = synthesize(model)
        self.assertEqual(result["status"], "infeasible")
        receipt = verify_dual(model, result["dual_multipliers"])
        self.assertTrue(receipt["valid"])
        self.assertEqual(receipt["contradiction"], 1)

    def test_model_name_boolean_and_integer_are_rejected(self):
        for name in (True, 1):
            with self.subTest(name=name), self.assertRaises(ValueError):
                synthesize(replace(profitable_self_loop(), name=name))


if __name__ == "__main__":
    unittest.main()
