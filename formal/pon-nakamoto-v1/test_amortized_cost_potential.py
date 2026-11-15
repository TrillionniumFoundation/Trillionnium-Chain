#!/usr/bin/env python3
"""Independent identities and exact rejection witnesses for additive synthesis."""
from dataclasses import replace
from fractions import Fraction as F
import unittest

from amortized_cost_potential import (
    Action, Model, Outcome, build_report, constraint_label, eta_budget_model, finite_horizon_value,
    inequalities,
    retained_failure_model, shared_cache_model, synthesize, validate,
    verify_dual, verify_potential, verify_regenerative_cycle,
)


class AdditivePotentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.safe = shared_cache_model()
        cls.safe_result = synthesize(cls.safe)
        cls.cheap = shared_cache_model(promotion=F(1))
        cls.cheap_result = synthesize(cls.cheap)

    def test_synthesizes_known_multi_scale_potential(self):
        self.assertEqual(self.safe_result["status"], "feasible")
        self.assertTrue(self.safe_result["least_potential_proved"])
        self.assertEqual(self.safe_result["potential"], {
            "empty": F(0), "cache_1": F(3, 4), "cache_4": F(15, 4), "pair": F(9, 2)})

    def test_independent_adaptive_dp_is_bounded(self):
        potential = self.safe_result["potential"]
        for horizon in (0, 1, 2, 4, 8, 16):
            values = finite_horizon_value(self.safe, horizon)
            self.assertTrue(all(values[s] <= potential[s] for s in values))
        self.assertEqual(finite_horizon_value(self.safe, 2), potential)

    def test_zero_horizon_stop_never_pays_potential(self):
        self.assertEqual(finite_horizon_value(self.safe, 0), {s: F(0) for s in self.safe.actions})
        self.assertGreater(self.safe_result["potential"]["pair"], 0)

    def test_cross_scale_positive_cost_cycle(self):
        witness = verify_regenerative_cycle(self.cheap, (
            ("empty", "prepare_1"), ("cache_1", "promote_1_to_4"), ("cache_4", "check_4")))
        self.assertTrue(witness["strict_contradiction"])
        self.assertTrue(witness["all_edges_have_positive_resource"])
        self.assertEqual(witness["expected_resource"], 2)
        self.assertEqual(witness["expected_credit"], 4)
        self.assertEqual(witness["net_expected_gain"], 2)
        self.assertGreaterEqual(finite_horizon_value(self.cheap, 6)["empty"], 4)

    def test_infeasibility_has_a_verified_exact_dual(self):
        self.assertEqual(self.cheap_result["status"], "infeasible")
        proof = verify_dual(self.cheap, self.cheap_result["dual_multipliers"])
        self.assertTrue(proof["valid"])
        self.assertEqual(proof["contradiction"], 1)
        self.assertEqual(proof["kind"], "stationary_action_flow")

    def test_the_omitted_conversion_is_the_only_new_violation(self):
        receipt = verify_potential(self.cheap, self.safe_result["potential"])
        bad = [row for row in receipt["residuals"] if row["slack"] < 0]
        self.assertEqual(bad, [{"constraint": constraint_label("action", "cache_1", "promote_1_to_4"), "slack": F(-2)}])

    def test_calibrated_kappa_two_passes_without_changing_credit(self):
        repaired = shared_cache_model(promotion=F(1), kappa=F(2))
        result = synthesize(repaired)
        self.assertEqual(result["status"], "feasible")
        self.assertEqual(result["potential"], {
            "empty": F(0), "cache_1": F(3, 2), "cache_4": F(7, 2), "pair": F(5)})
        self.assertEqual(repaired.weights, self.cheap.weights)

    def test_exact_boundary_below_kappa_two_is_rejected(self):
        model = shared_cache_model(promotion=F(1), kappa=F(1999, 1000))
        result = synthesize(model)
        self.assertEqual(result["status"], "infeasible")
        self.assertTrue(verify_dual(model, result["dual_multipliers"])["valid"])

    def test_batch_cycle_prices_all_outcomes(self):
        model = shared_cache_model(batch_setup=F(5, 2))
        cycle = verify_regenerative_cycle(model, (("empty", "prepare_pair"), ("pair", "check_pair")))
        self.assertEqual((cycle["expected_credit"], cycle["expected_resource"]), (5, 3))
        self.assertTrue(cycle["strict_contradiction"])
        self.assertEqual(synthesize(model)["status"], "infeasible")
        at_boundary = shared_cache_model(batch_setup=F(5, 2), kappa=F(5, 3))
        self.assertEqual(synthesize(at_boundary)["status"], "feasible")

    def test_stochastic_failure_cache_has_exact_noniterative_solution(self):
        model = retained_failure_model()
        result = synthesize(model)
        self.assertEqual(result["status"], "feasible")
        self.assertEqual(result["potential"], {"cache": F(1), "empty": F(0)})
        for horizon in (0, 1, 3, 16, 32):
            # The Bellman iterate never reaches its limit at a finite horizon.
            # A convergence timeout must not mean infeasible.
            value = finite_horizon_value(model, horizon)
            self.assertEqual(value["cache"], 1 - F(3, 4) ** horizon)
            self.assertEqual(value["empty"], 0)
            self.assertLess(value["cache"], 1)

    def test_stochastic_dual_is_an_occupation_certificate(self):
        model = retained_failure_model(marginal=F(1, 2))
        witness = {constraint_label("action", "empty", "prepare"): F(1),
                   constraint_label("action", "cache", "try"): F(4)}
        self.assertTrue(verify_dual(model, witness)["valid"])
        # One paid setup plus four expected retries: cost 3, credit 4.
        self.assertEqual(verify_dual(model, witness)["contradiction"], 1)
        result = synthesize(model)
        self.assertEqual(result["status"], "infeasible")
        self.assertTrue(result["verification"]["valid"])

    def test_unfinished_search_returns_unknown(self):
        result = synthesize(self.cheap, max_basis_checks=0)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["primal_search_exhausted"])
        self.assertFalse(result["dual_search_exhausted"])
        self.assertNotIn("dual_multipliers", result)

    def test_partial_search_may_return_a_valid_nonminimal_certificate(self):
        model = Model("partial", {"s": (Action("wait", (Outcome(F(1), "s", F(1)),)),)},
                      {1: F(1)}, F(1), {"s": F(0)}, {"s": F(0)})
        result = synthesize(model, max_basis_checks=2)
        self.assertEqual(result["status"], "feasible")
        self.assertFalse(result["least_potential_proved"])
        self.assertTrue(verify_potential(model, result["potential"])["valid"])

    def test_prefilled_initial_state_needs_its_own_budget(self):
        model = replace(retained_failure_model(), initial_potential_caps={"cache": F(1)})
        self.assertEqual(synthesize(model)["status"], "feasible")
        underfunded = replace(model, initial_potential_caps={"cache": F(99, 100)})
        result = synthesize(underfunded)
        self.assertEqual(result["status"], "infeasible")
        self.assertEqual(result["verification"]["kind"], "budget_or_state_constraint")

    def test_eta_is_a_finite_consumed_ledger(self):
        model = eta_budget_model()
        result = synthesize(model)
        self.assertEqual(result["status"], "feasible")
        self.assertEqual(result["potential"], {"funded": F(0), "spent": F(0)})
        self.assertEqual(result["initial_eta_budgets"], {"funded": F(4)})
        self.assertEqual(finite_horizon_value(model, 20), {"funded": F(0), "spent": F(0)})

    def test_eta_cannot_refill_on_restart(self):
        model = eta_budget_model()
        actions = dict(model.actions)
        actions["spent"] = (Action("restart", (Outcome(F(1), "funded", F(0)),)),)
        with self.assertRaisesRegex(ValueError, "eta ledger"):
            synthesize(replace(model, actions=actions))

    def test_eta_debit_cannot_be_omitted(self):
        model = eta_budget_model()
        actions = dict(model.actions)
        actions["funded"] = (Action("forgot_debit", (Outcome(F(1), "spent", F(0), ((1, 1),)),)),)
        with self.assertRaisesRegex(ValueError, "eta ledger"):
            validate(replace(model, actions=actions))

    def test_creation_and_release_cannot_be_counted_twice_at_same_cost(self):
        actions = {
            "empty": (Action("create_and_credit", (Outcome(F(1), "stored", F(1), ((1, 1),)),)),),
            "stored": (Action("credit_again", (Outcome(F(1), "empty", F(0), ((1, 1),)),)),),
        }
        model = Model("double_credit", actions, {1: F(1)}, F(1),
                      {s: F(0) for s in actions}, {"empty": F(0)})
        self.assertEqual(synthesize(model)["status"], "infeasible")

    def test_invalid_potential_and_dual_do_not_pass(self):
        potential = dict(self.safe_result["potential"])
        potential["cache_4"] -= F(1, 10**20)
        self.assertFalse(verify_potential(self.safe, potential)["valid"])
        dual = dict(self.cheap_result["dual_multipliers"])
        first = next(iter(dual))
        dual[first] += F(1, 10**20)
        self.assertFalse(verify_dual(self.cheap, dual)["valid"])
        with self.assertRaisesRegex(ValueError, "unknown dual"):
            verify_dual(self.cheap, {"invented": F(1)})

    def test_exact_probability_and_resource_validation(self):
        model = retained_failure_model()
        bad = Action("bad", (Outcome(F(1, 2), "cache", F(0)),))
        with self.assertRaisesRegex(ValueError, "sum to one"):
            validate(replace(model, actions={**model.actions, "empty": (bad,)}))
        bad = Action("float", (Outcome(F(1), "cache", 0.5),))
        with self.assertRaisesRegex(ValueError, "exact nonnegative"):
            validate(replace(model, actions={**model.actions, "empty": (bad,)}))
        with self.assertRaisesRegex(ValueError, "zero credit"):
            validate(replace(model, weights={1: F(0)}))
        bad = Action("boolean_scale", (Outcome(F(1), "cache", F(0), ((True, 1),)),))
        with self.assertRaisesRegex(ValueError, "invalid credited scale"):
            validate(replace(model, actions={**model.actions, "empty": (bad,)}))

    def test_stop_name_cannot_hide_an_extra_terminal_reward(self):
        model = retained_failure_model()
        actions = {**model.actions, "cache": (Action("stop", (Outcome(F(1), "empty", F(0), ((1, 1),)),)),)}
        with self.assertRaisesRegex(ValueError, "stop has zero payoff"):
            validate(replace(model, actions=actions))

    @staticmethod
    def positive_loop():
        action = Action("win", (Outcome(F(1), "s", F(0), ((1, 1),)),))
        return Model("positive_loop", {"s": (action,)}, {1: F(1)}, F(1),
                     {"s": F(0)}, {"s": F(0)})

    def test_action_iterator_cannot_erase_a_profitable_loop(self):
        model = self.positive_loop()
        self.assertEqual(synthesize(model)["status"], "infeasible")
        action = model.actions["s"][0]
        iterator = iter((action,))
        malformed = replace(model, actions={"s": iterator})
        for check in (lambda: synthesize(malformed),
                      lambda: verify_potential(malformed, {"s": F(0)}),
                      lambda: verify_dual(malformed, {}),
                      lambda: finite_horizon_value(malformed, 1)):
            with self.assertRaisesRegex(ValueError, "actions must be an exact tuple"):
                check()
        self.assertIs(next(iterator), action)
        # Even an already exhausted iterator must be rejected, not treated as an
        # empty action tuple on the next verification call.
        with self.assertRaisesRegex(ValueError, "actions must be an exact tuple"):
            synthesize(malformed)

    def test_outcome_iterator_is_refused_before_probability_sum(self):
        model = self.positive_loop()
        action = model.actions["s"][0]
        outcome = action.outcomes[0]
        iterator = iter((outcome,))
        malformed = replace(model, actions={"s": (replace(action, outcomes=iterator),)})
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "outcomes must be a nonempty exact tuple"):
                synthesize(malformed)
        self.assertIs(next(iterator), outcome)

    def test_credit_iterator_cannot_erase_positive_reward(self):
        model = self.positive_loop()
        action = model.actions["s"][0]
        outcome = action.outcomes[0]
        iterator = iter(((1, 1),))
        malformed = replace(model, actions={"s": (replace(action, outcomes=(
            replace(outcome, credits=iterator),)),)})
        with self.assertRaisesRegex(ValueError, "credits must be an exact tuple"):
            synthesize(malformed)
        with self.assertRaisesRegex(ValueError, "credits must be an exact tuple"):
            verify_potential(malformed, {"s": F(0)})
        self.assertEqual(next(iterator), (1, 1))

    def test_credit_entry_iterator_is_not_unpacked(self):
        model = self.positive_loop()
        action = model.actions["s"][0]
        outcome = action.outcomes[0]
        iterator = iter((1, 1))
        malformed = replace(model, actions={"s": (replace(action, outcomes=(
            replace(outcome, credits=(iterator,)),)),)})
        with self.assertRaisesRegex(ValueError, "credit entries must be exact two-item tuples"):
            validate(malformed)
        self.assertEqual(tuple(iterator), (1, 1))

    def test_list_containers_and_wrong_record_elements_are_rejected(self):
        model = self.positive_loop()
        action = model.actions["s"][0]
        outcome = action.outcomes[0]
        malformed_actions = (
            [action],
            (None,),
            (replace(action, outcomes=[outcome]),),
            (replace(action, outcomes=(None,)),),
            (replace(action, outcomes=(replace(outcome, credits=[(1, 1)]),)),),
            (replace(action, outcomes=(replace(outcome, credits=([1, 1],)),)),),
            (replace(action, outcomes=(replace(outcome, credits=((1,),)),)),),
            (replace(action, outcomes=(replace(outcome, credits=((1, 1, 1),)),)),),
        )
        for actions in malformed_actions:
            with self.subTest(actions=actions), self.assertRaises(ValueError):
                synthesize(replace(model, actions={"s": actions}))

    def test_model_and_certificate_mappings_require_exact_dicts(self):
        class DictSubclass(dict):
            pass

        model = self.positive_loop()
        for field in ("actions", "weights", "eta_remaining", "initial_potential_caps"):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "exact dict"):
                validate(replace(model, **{field: DictSubclass(getattr(model, field))}))
        with self.assertRaisesRegex(ValueError, "potential must be an exact dict"):
            verify_potential(model, DictSubclass({"s": F(0)}))
        with self.assertRaisesRegex(ValueError, "dual multipliers must be an exact dict"):
            verify_dual(model, DictSubclass({}))

    def test_model_name_requires_an_exact_nonempty_string(self):
        class StringSubclass(str):
            pass

        model = self.positive_loop()
        for name in (True, 1, None, "", StringSubclass("name")):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "model name"):
                synthesize(replace(model, name=name))

    def test_all_other_names_require_exact_strings(self):
        class StringSubclass(str):
            pass

        model = self.positive_loop()
        action = model.actions["s"][0]
        outcome = action.outcomes[0]
        malformed = (
            replace(model, actions={StringSubclass("s"): (action,)}),
            replace(model, actions={"s": (replace(action, name=True),)}),
            replace(model, actions={"s": (replace(action, name=StringSubclass("win")),)}),
            replace(model, actions={"s": (replace(action, outcomes=(
                replace(outcome, next_state=StringSubclass("s")),)),)}),
            replace(model, eta_remaining={StringSubclass("s"): F(0)}),
            replace(model, initial_potential_caps={StringSubclass("s"): F(0)}),
        )
        for candidate in malformed:
            with self.subTest(candidate=candidate), self.assertRaisesRegex(ValueError, "exact nonempty str"):
                validate(candidate)

    def test_constraint_labels_cannot_collide_at_colons(self):
        self.assertEqual(constraint_label("action", "a", "b:c"), 'action:["a","b:c"]')
        self.assertEqual(constraint_label("action", "a:b", "c"), 'action:["a:b","c"]')
        actions = {
            "a": (Action("b:c", (Outcome(F(1), "a", F(0), ((1, 1),)),)),
                  Action("go", (Outcome(F(1), "a:b", F(0)),))),
            "a:b": (Action("c", (Outcome(F(1), "a:b", F(1)),)),),
        }
        model = Model("colon_collision", actions, {1: F(1)}, F(1),
                      {state: F(0) for state in actions}, {"a": F(0)})
        _, rows = inequalities(model)
        self.assertEqual(len({row.label for row in rows}), len(rows))
        result = synthesize(model)
        self.assertEqual(result["status"], "infeasible")
        self.assertTrue(verify_dual(model, result["dual_multipliers"])["valid"])
        # This literal witness targets only the profitable self-loop. The old
        # label also selected the negative-cost self-loop at a:b, canceling it.
        self.assertTrue(verify_dual(model, {'action:["a","b:c"]': F(1)})["valid"])
        with self.assertRaisesRegex(ValueError, "unknown dual constraint"):
            verify_dual(model, {"action:a:b:c": F(1)})

    def test_label_kinds_arity_and_components_are_checked(self):
        for args in (("unknown", "s"), ("action", "s"), ("nonnegative", "s", "t"),
                     (True, "s"), ("action", "s", 1), ("initial_cap", "")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                constraint_label(*args)

    def test_fraction_subclasses_are_not_exact_rational_inputs(self):
        class FractionSubclass(F):
            pass

        model = self.positive_loop()
        with self.assertRaisesRegex(ValueError, "exact nonnegative Fraction"):
            validate(replace(model, kappa=FractionSubclass(1)))
        with self.assertRaisesRegex(ValueError, "exact Fraction potential"):
            verify_potential(model, {"s": FractionSubclass(0)})
        with self.assertRaisesRegex(ValueError, "exact nonnegative Fraction"):
            verify_dual(model, {constraint_label("action", "s", "win"): FractionSubclass(1)})

    def test_dataclass_records_cannot_be_replaced_by_subclasses(self):
        class ModelSubclass(Model):
            pass
        class ActionSubclass(Action):
            pass
        class OutcomeSubclass(Outcome):
            pass

        model = self.positive_loop()
        with self.assertRaisesRegex(ValueError, "exact Model"):
            validate(ModelSubclass(model.name, model.actions, model.weights, model.kappa,
                                   model.eta_remaining, model.initial_potential_caps))
        action = model.actions["s"][0]
        with self.assertRaisesRegex(ValueError, "exact Action"):
            validate(replace(model, actions={"s": (ActionSubclass(action.name, action.outcomes),)}))
        outcome = OutcomeSubclass(F(1), "s", F(0), ((1, 1),))
        with self.assertRaisesRegex(ValueError, "exact Outcome"):
            validate(replace(model, actions={"s": (replace(action, outcomes=(outcome,)),)}))

    def test_false_native_and_quantum_claims_are_retained(self):
        report = build_report()
        for key in ("all_algorithm_cost_qualified", "quantum_cost_qualified", "native_consensus_qualified", "tail_qualified"):
            self.assertIs(report[key], False)
            for result in report["results"].values():
                self.assertIs(result[key], False)


if __name__ == "__main__":
    unittest.main()
