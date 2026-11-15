#!/usr/bin/env python3
"""Independent finite-law controls, not a native W1 or networking experiment."""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
from math import comb
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import joint_production_tail_v1 as tail


def rat(num, den=1):
    return {"num": num, "den": den}


def branch(p, a=0, e=0, j=0, nxt="s"):
    return {"p": rat(p.numerator, p.denominator), "a": a, "e": e, "j": j, "next": nxt}


def action(name, *branches):
    return {"id": name, "branches": list(branches)}


def state(name, potential, *actions):
    return {"id": name, "potential": rat(potential), "actions": list(actions)}


def document(states, *, initial="s", z=3, mode="direct"):
    return {"schema": tail.SCHEMA, "law_scope": tail.LAW_SCOPE,
            "coverage": "all-declared-state-actions-only", "mode": mode,
            "z": rat(z), "initial_state": initial, "states": states}


def walk(*, mode="direct", z=3, probability=Fraction(1, 4), debt=False):
    return document([state("s", 1, action("walk",
        branch(probability, a=0 if debt else 1, e=1 if debt else 0),
        branch(1-probability, j=1)))], z=z, mode=mode)


def inventory(*, reset=False):
    return document([
        state("stash", 2,
              action("release", branch(Fraction(1), a=1,
                                       nxt="stash" if reset else "empty")),
              action("restart", branch(Fraction(1), nxt="stash"))),
        state("empty", 1, action("idle", branch(Fraction(1), nxt="empty")))
    ], initial="stash", z=2)


class JointTailTests(unittest.TestCase):
    def test_direct_certificate_and_exact_anytime_bound(self):
        model = walk()
        report = tail.audit_model(model)
        self.assertTrue(report["finite_model_certificate_valid"])
        self.assertEqual(report["actions"][0]["joint_conditional_moment"], rat(1))
        self.assertEqual(tail.crossing_bound(model, 1), Fraction(1, 3))
        self.assertEqual(tail.crossing_bound(model, 4), Fraction(1, 81))

    def test_conditional_cs_certificate_is_exact(self):
        report = tail.audit_model(walk(mode="conditional-cauchy-schwarz"))
        self.assertTrue(report["finite_model_certificate_valid"])
        self.assertEqual(report["actions"][0]["adverse_squared_moment"], rat(3))
        self.assertEqual(report["actions"][0]["honest_squared_moment"], rat(1, 3))
        self.assertEqual(report["actions"][0]["cauchy_schwarz_product"], rat(1))

    def test_correlated_marginal_product_cannot_replace_joint_moment(self):
        model = walk(z=2, probability=Fraction(2, 5))
        adverse_marginal = Fraction(2, 5)*2 + Fraction(3, 5)
        honest_marginal = Fraction(2, 5) + Fraction(3, 5)*Fraction(1, 2)
        self.assertEqual(adverse_marginal*honest_marginal, Fraction(49, 50))
        report = tail.audit_model(model)
        self.assertEqual(report["actions"][0]["joint_conditional_moment"], rat(11, 10))
        self.assertFalse(report["finite_model_certificate_valid"])
        model["mode"] = "conditional-cauchy-schwarz"
        report = tail.audit_model(model)
        self.assertEqual(report["actions"][0]["cauchy_schwarz_product"], rat(121, 100))
        self.assertFalse(report["finite_model_certificate_valid"])
        with self.assertRaisesRegex(tail.TailError, "INVALID_FINITE_CERTIFICATE"):
            tail.crossing_bound(model, 1)

    def test_cs_is_sufficient_but_not_necessary(self):
        model = document([
            state("s", 2, action("mix",
                branch(Fraction(2, 3), nxt="low"), branch(Fraction(1, 3), nxt="high"))),
            state("low", 1, action("idle", branch(Fraction(1), nxt="low"))),
            state("high", 4, action("idle", branch(Fraction(1), nxt="high")))])
        report = tail.audit_model(model)
        self.assertTrue(report["finite_model_certificate_valid"])
        self.assertEqual(report["actions"][0]["joint_conditional_moment"], rat(1))
        model["mode"] = "conditional-cauchy-schwarz"
        report = tail.audit_model(model)
        self.assertEqual(report["actions"][0]["cauchy_schwarz_product"], rat(3, 2))
        self.assertFalse(report["finite_model_certificate_valid"])

    def test_bellman_matches_independent_catalan_first_passage_law(self):
        model = walk()
        p, q = Fraction(1, 4), Fraction(3, 4)
        for horizon in range(16):
            # First crossing of +1 at time 2k+1 has Catalan(k) possible prefixes.
            exact = sum((Fraction(comb(2*k, k), k+1)*p**(k+1)*q**k
                         for k in range((horizon+1)//2)), Fraction())
            observed = tail.maximal_crossing_probability(model, 1, horizon)
            self.assertEqual(observed, exact, horizon)
            self.assertLessEqual(observed, tail.crossing_bound(model, 1))

    def test_crossing_remains_absorbed_after_later_negative_credit(self):
        model = document([
            state("s", 2, action("first", branch(Fraction(1), a=1, nxt="down"))),
            state("down", 1, action("later", branch(Fraction(1), j=1, nxt="down")))
        ], z=2)
        self.assertTrue(tail.audit_model(model)["finite_model_certificate_valid"])
        self.assertEqual(tail.maximal_crossing_probability(model, 1, 2), 1)

    def test_adaptive_policy_beats_both_fixed_action_policies(self):
        model = walk()
        model["states"][0]["actions"].append(action("rare",
            branch(Fraction(1, 20), a=2), branch(Fraction(19, 20), j=1)))
        self.assertTrue(tail.audit_model(model)["finite_model_certificate_valid"])
        adaptive = tail.maximal_crossing_probability(model, 1, 2)
        self.assertEqual(adaptive, Fraction(23, 80))
        self.assertGreater(adaptive, Fraction(1, 4))
        self.assertGreater(adaptive, Fraction(39, 400))
        self.assertLessEqual(adaptive, tail.crossing_bound(model, 1))

    def test_horizon_monotonicity_and_gap_monotonicity(self):
        model = walk()
        for gap in (1, 2, 3):
            probabilities = [tail.maximal_crossing_probability(model, gap, n) for n in range(9)]
            self.assertEqual(probabilities, sorted(probabilities))
        self.assertGreaterEqual(tail.maximal_crossing_probability(model, 1, 8),
                                tail.maximal_crossing_probability(model, 2, 8))

    def test_entry_debt_is_charged_in_the_same_joint_increment(self):
        self.assertEqual(tail.maximal_crossing_probability(walk(debt=True), 1, 9),
                         tail.maximal_crossing_probability(walk(), 1, 9))
        model = walk(debt=True)
        model["states"][0]["actions"][0]["branches"][0]["a"] = 1
        self.assertFalse(tail.audit_model(model)["finite_model_certificate_valid"])

    def test_inventory_potential_and_restart_remain_charged(self):
        model = inventory()
        self.assertTrue(tail.audit_model(model)["finite_model_certificate_valid"])
        self.assertEqual(tail.crossing_bound(model, 1), 1)
        self.assertEqual(tail.maximal_crossing_probability(model, 1, 5), 1)
        self.assertEqual(tail.maximal_crossing_probability(model, 2, 5), 0)
        model["states"][0]["potential"] = rat(1)
        self.assertFalse(tail.audit_model(model)["finite_model_certificate_valid"])

    def test_duplicate_credit_regeneration_rejects_finite_potential(self):
        model = inventory(reset=True)
        self.assertFalse(tail.audit_model(model)["finite_model_certificate_valid"])
        self.assertEqual(tail.maximal_crossing_probability(model, 3, 3), 1)
        with self.assertRaises(tail.TailError):
            tail.crossing_bound(model, 3)

    def test_unreachable_state_and_unselected_action_are_still_checked(self):
        model = walk()
        model["states"].append(state("unreachable", 1,
            action("bad", branch(Fraction(1), a=1, nxt="unreachable"))))
        self.assertFalse(tail.audit_model(model)["finite_model_certificate_valid"])
        model = walk()
        model["states"][0]["actions"].append(action("bad", branch(Fraction(1), a=1)))
        self.assertFalse(tail.audit_model(model)["finite_model_certificate_valid"])

    def test_native_flags_and_risks_never_promoted(self):
        report = tail.audit_model(walk())
        self.assertEqual(report["qualification"], "HOLD_NO_GO")
        for key in ("native_common_prefix_qualified", "native_chain_growth_qualified",
                    "native_chain_quality_qualified", "production_activation",
                    "complete_legal_strategy_coverage_proved", "native_to_model_reduction_proved"):
            self.assertIs(report[key], False)
        for key in ("native_six_successor_risk_bound", "native_common_prefix_failure_bound",
                    "native_chain_growth_bound", "native_chain_quality_bound",
                    "actual_lifetime_failure_bound"):
            self.assertIsNone(report[key])

    def test_probability_sum_missing_successor_and_duplicate_outcome_refused(self):
        for mutation, code in (
            (lambda m: m["states"][0]["actions"][0]["branches"][0].update(p=rat(1, 3)), "SUM_TO_ONE"),
            (lambda m: m["states"][0]["actions"][0]["branches"][0].update(next="absent"), "SUCCESSOR"),
            (lambda m: m["states"][0]["actions"][0]["branches"][1].update(a=1, j=0), "DUPLICATE_BRANCH"),
        ):
            model = walk()
            mutation(model)
            with self.assertRaisesRegex(tail.TailError, code):
                tail.audit_model(model)

    def test_duplicate_state_and_action_ids_refused(self):
        model = walk()
        model["states"].append(deepcopy(model["states"][0]))
        with self.assertRaisesRegex(tail.TailError, "DUPLICATE_STATE"):
            tail.audit_model(model)
        model = walk()
        model["states"][0]["actions"].append(deepcopy(model["states"][0]["actions"][0]))
        with self.assertRaisesRegex(tail.TailError, "DUPLICATE_ACTION"):
            tail.audit_model(model)

    def test_future_conditioned_or_selected_scope_is_refused(self):
        for value in ("conditioned-on-no-delay-failure", "selected-successful-window",
                      "fresh-start-after-restart", None):
            model = walk()
            model["law_scope"] = value
            with self.assertRaisesRegex(tail.TailError, "UNCONDITIONAL_LAW_SCOPE_REQUIRED"):
                tail.audit_model(model)

    def test_unknown_fields_and_unknown_numerical_values_refused(self):
        model = walk()
        model["future_good_event"] = True
        with self.assertRaisesRegex(tail.TailError, "DOCUMENT_FIELDS"):
            tail.audit_model(model)
        for value in (None, True, 0.25, -1):
            model = walk()
            model["states"][0]["actions"][0]["branches"][0]["a"] = value
            with self.assertRaisesRegex(tail.TailError, "ADVERSARIAL_CREDIT"):
                tail.audit_model(model)

    def test_nonpositive_probabilities_and_small_potential_refused(self):
        for bad in (rat(0), rat(1, 0), rat(-1, 2), rat(2, 1)):
            model = walk()
            model["states"][0]["actions"][0]["branches"][0]["p"] = bad
            with self.assertRaises(tail.TailError):
                tail.audit_model(model)
        model = walk()
        model["states"][0]["potential"] = rat(1, 2)
        with self.assertRaisesRegex(tail.TailError, "DOMINATE_ONE"):
            tail.audit_model(model)

    def test_nonpositive_or_unit_z_refused(self):
        for value in (rat(0), rat(1), rat(1, 2)):
            model = walk()
            model["z"] = value
            with self.assertRaises(tail.TailError):
                tail.audit_model(model)

    def test_json_duplicates_floats_and_nonfinite_refused(self):
        for body in ('{"a":1,"a":2}', '{"x":0.5}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(tail.TailError):
                tail.strict_json(body)
        self.assertEqual(tail.strict_json(json.dumps(walk())), walk())

    def test_resource_limits_are_refusals(self):
        model = walk()
        model["states"][0]["actions"][0]["branches"][0]["e"] = tail.MAX_CREDIT+1
        with self.assertRaisesRegex(tail.TailError, "ENTRY_DEBT"):
            tail.audit_model(model)
        with self.assertRaisesRegex(tail.TailError, "HORIZON"):
            tail.maximal_crossing_probability(walk(), 1, tail.MAX_HORIZON+1)
        with self.assertRaisesRegex(tail.TailError, "GAP"):
            tail.crossing_bound(walk(), True)
        with self.assertRaisesRegex(tail.TailError, "INPUT_SIZE"):
            tail.strict_json(" "*(tail.MAX_INPUT_BYTES+1))

    def test_zero_horizon_and_already_crossed(self):
        self.assertEqual(tail.maximal_crossing_probability(walk(), 1, 0), 0)
        self.assertEqual(tail.maximal_crossing_probability(walk(), 0, 0), 1)
        self.assertEqual(tail.crossing_bound(walk(), 0), 1)

    def test_cli_model_pass_and_native_refusal_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"law.json"
            path.write_text(json.dumps(walk()), encoding="utf-8")
            command = [sys.executable, str(Path(tail.__file__)), "--check", str(path),
                       "--gap", "1", "--horizon", "3"]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["finite_model_anytime_crossing_bound"], rat(1, 3))
            self.assertEqual(report["finite_model_maximal_crossing_probability"], rat(19, 64))
            refused = subprocess.run(command+["--require-native-qualification"],
                                     capture_output=True, text=True, check=False)
            self.assertEqual(refused.returncode, 3)
            self.assertIsNone(json.loads(refused.stdout)["native_six_successor_risk_bound"])

    def test_cli_invalid_certificate_emits_no_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"law.json"
            path.write_text(json.dumps(walk(z=2, probability=Fraction(2, 5))), encoding="utf-8")
            result = subprocess.run([sys.executable, str(Path(tail.__file__)), "--check", str(path),
                                     "--gap", "1", "--horizon", "1"],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIsNone(json.loads(result.stdout)["finite_model_anytime_crossing_bound"])

    def test_cli_invalid_certificate_does_not_bypass_gap_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"law.json"
            path.write_text(json.dumps(walk(z=2, probability=Fraction(2, 5))), encoding="utf-8")
            for gap in (-1, tail.MAX_GAP+1):
                result = subprocess.run([sys.executable, str(Path(tail.__file__)), "--check", str(path),
                                         "--gap", str(gap)], capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)["error"], "GAP")

    def test_denominator_and_dp_work_limits_are_explicit_refusals(self):
        with patch.object(tail, "MAX_PROBABILITY_DENOMINATOR_LCM", 3):
            with self.assertRaisesRegex(tail.TailError, "PROBABILITY_DENOMINATOR_LIMIT"):
                tail.audit_model(walk())
        with patch.object(tail, "MAX_DP_CELLS", 1):
            with self.assertRaisesRegex(tail.TailError, "DP_CELL_LIMIT"):
                tail.maximal_crossing_probability(walk(), 1, 2)
        with patch.object(tail, "MAX_DP_TRANSITIONS", 1):
            with self.assertRaisesRegex(tail.TailError, "DP_TRANSITION_LIMIT"):
                tail.maximal_crossing_probability(walk(), 1, 2)

    def test_rational_complexity_guards_moments_bound_dp_and_encoding(self):
        with patch.object(tail, "MAX_RATIONAL_BITS", 4):
            model = walk()
            model["states"][0]["actions"][0]["branches"][0]["a"] = 4
            with self.assertRaisesRegex(tail.TailError, "RATIONAL_BIT_LIMIT"):
                tail.audit_model(model)
            with self.assertRaisesRegex(tail.TailError, "RATIONAL_BIT_LIMIT"):
                tail.crossing_bound(walk(), 8)
            with self.assertRaisesRegex(tail.TailError, "RATIONAL_BIT_LIMIT"):
                tail.maximal_crossing_probability(walk(), 1, 3)
            with self.assertRaisesRegex(tail.TailError, "RATIONAL_BIT_LIMIT"):
                tail.encoded(Fraction(1, 32))


if __name__ == "__main__":
    unittest.main()
