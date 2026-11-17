#!/usr/bin/env python3
"""Independent exact controls for the declared joint lifetime/service model."""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import joint_lifetime_service_v1 as joint


def rat(num, den=1):
    return {"num": num, "den": den}


def active(name, gap, horizon, charged_num, charged_den=1):
    return {"id": name, "gap": gap, "horizon": horizon,
            "charged_crossing_allowance": rat(charged_num, charged_den)}


def state(name, *, spent=(0, 1), starts=0, active_starts=(), height=0,
          target=joint.POW_LIMIT, mtp=0, now=100, credit=0, qualified=2,
          debt=0, terminal=False, safe=False, potential=1, actions=()):
    return {
        "id": name, "potential": rat(potential), "spent": rat(*spent),
        "starts": starts, "active_starts": list(active_starts), "height": height,
        "target": target, "mtp": mtp, "observed_now": now,
        "cumulative_credit": credit, "qualified_units": qualified,
        "entry_debt": debt, "terminal_bad": terminal, "safe_absorbing": safe,
        "actions": list(actions),
    }


def branch(p, successor, *, bad="none", a=0, new_debt=0, debt_served=0, j=0,
           joins=0, leaves=0, parent_height=0, parent_target=joint.POW_LIMIT,
           child_target=joint.POW_LIMIT, child_time=1, next_mtp=0, next_now=100,
           credited_work=0, delivery=True, service=True):
    return {
        "p": rat(p.numerator, p.denominator), "a": a, "new_debt": new_debt,
        "debt_served": debt_served, "j": j, "joins": joins, "leaves": leaves,
        "parent_height": parent_height, "parent_target": parent_target,
        "child_target": child_target, "child_time": child_time,
        "next_mtp": next_mtp, "next_observed_now": next_now,
        "credited_work": credited_work, "delivery_complete": delivery,
        "service_complete": service, "bad": bad, "next": successor,
    }


def action(name, branches, *, bad=(0, 1), register=None):
    return {"id": name, "bad_allowance": rat(*bad), "register": register,
            "branches": list(branches)}


def finite_model():
    target = joint.POW_LIMIT
    credit = joint.required_credit(target)
    registered = active("q0", 1, 2, 1, 2)
    start = action("register-q0", [
        branch(Fraction(1, 4), "cross", bad="crossing", a=1),
        branch(Fraction(1, 4), "delivery", bad="delivery", delivery=False),
        branch(Fraction(1, 2), "s1", j=1, child_time=10, next_mtp=10,
               credited_work=credit),
    ], bad=(1, 4), register=registered)
    finish = action("finish-q0", [
        branch(Fraction(1), "done", j=1, parent_height=1,
               child_time=11, next_mtp=11, credited_work=credit),
    ])
    return {
        "schema": joint.SCHEMA, "law_scope": joint.LAW_SCOPE,
        "coverage": "all-declared-state-actions-only", "z": rat(2),
        "future_skew": 120, "lifetime_budget": rat(3, 4), "initial_state": "s0",
        "states": [
            state("s0", actions=[start]),
            state("cross", spent=(3, 4), starts=1, terminal=True),
            state("delivery", spent=(3, 4), starts=1,
                  active_starts=[active("q0", 1, 1, 1, 2)], terminal=True),
            state("s1", spent=(3, 4), starts=1,
                  active_starts=[active("q0", 2, 1, 1, 2)], height=1, mtp=10,
                  credit=credit, actions=[finish]),
            state("done", spent=(3, 4), starts=1, height=2, mtp=11,
                  credit=2 * credit, safe=True),
        ],
    }


class JointLifetimeServiceTests(unittest.TestCase):
    def test_exact_joint_certificate_and_finite_bounds(self):
        model = finite_model()
        report = joint.audit_model(model)
        self.assertTrue(report["finite_model_certificate_valid"])
        self.assertEqual(report["actions"][0]["good_joint_moment"], rat(3, 4))
        self.assertEqual(report["actions"][0]["first_bad_mass_excluding_crossing"],
                         rat(1, 4))
        self.assertEqual(joint.combined_bound(model), Fraction(3, 4))
        self.assertEqual(joint.maximal_failure_probability(model, 1), Fraction(1, 2))
        self.assertEqual(joint.maximal_failure_probability(model, 2), Fraction(1, 2))

    def test_bad_or_crossing_union_is_not_a_marginal_product(self):
        probability = joint.maximal_failure_probability(finite_model(), 1)
        self.assertEqual(probability, Fraction(1, 2))
        self.assertNotEqual(probability, Fraction(1, 4) * Fraction(1, 4))

    def test_bad_mass_remains_in_original_denominator(self):
        report = joint.audit_model(finite_model())["actions"][0]
        # The killed-good moment is 3/4 on the original law. Renormalizing away
        # delivery failure would incorrectly divide it by 3/4.
        self.assertEqual(report["good_joint_moment"], rat(3, 4))
        self.assertEqual(Fraction(3, 4) / Fraction(3, 4), 1)

    def test_nonrefundable_start_and_residual_gap_survive_good_transition(self):
        model = joint.parse_model(finite_model())
        successor = model.states["s1"]
        self.assertEqual(successor.spent, Fraction(3, 4))
        self.assertEqual(successor.starts, 1)
        self.assertEqual(successor.active_starts,
                         (joint.ActiveStart("q0", 2, 1, Fraction(1, 2)),))

    def test_residual_initial_state_is_counted_once_at_analysis_cut(self):
        model = finite_model()
        model["initial_state"] = "s1"
        self.assertEqual(joint.combined_bound(model), Fraction(1, 4))
        model["states"][3]["starts"] = 0
        with self.assertRaisesRegex(joint.JointLifetimeError, "ACTIVE_START_COUNT"):
            joint.audit_model(model)

    def test_inclusive_target_plus_one_credit_is_recomputed(self):
        self.assertEqual(joint.required_credit(joint.POW_LIMIT), 2)
        self.assertEqual(joint.required_credit(1), 1 << 255)
        self.assertNotEqual(joint.required_credit(7), joint.SPACE // 7)

    def test_parent_target_and_height_are_same_history_bindings(self):
        for field, changed in (("parent_height", 1), ("parent_target", joint.POW_LIMIT - 1)):
            model = finite_model()
            model["states"][0]["actions"][0]["branches"][2][field] = changed
            with self.subTest(field=field), self.assertRaisesRegex(
                    joint.JointLifetimeError, "PARENT_BINDING"):
                joint.audit_model(model)

    def test_good_timestamp_must_be_strictly_above_mtp(self):
        model = finite_model()
        model["states"][0]["actions"][0]["branches"][2]["child_time"] = 0
        with self.assertRaisesRegex(joint.JointLifetimeError, "GOOD_TIME_ELIGIBILITY"):
            joint.audit_model(model)

    def test_good_timestamp_cannot_exceed_observed_clock_plus_skew(self):
        model = finite_model()
        model["states"][0]["actions"][0]["branches"][2]["child_time"] = 221
        with self.assertRaisesRegex(joint.JointLifetimeError, "GOOD_TIME_ELIGIBILITY"):
            joint.audit_model(model)

    def test_claimed_credit_cannot_replace_required_credit(self):
        model = finite_model()
        model["states"][0]["actions"][0]["branches"][2]["credited_work"] = 3
        with self.assertRaisesRegex(joint.JointLifetimeError, "REQUIRED_CREDIT"):
            joint.audit_model(model)

    def test_receiver_delivery_or_service_deficit_cannot_be_good(self):
        for field in ("delivery_complete", "service_complete"):
            model = finite_model()
            model["states"][0]["actions"][0]["branches"][2][field] = False
            with self.subTest(field=field), self.assertRaisesRegex(
                    joint.JointLifetimeError, "GOOD_REQUIRES_COMPLETE_SERVICE"):
                joint.audit_model(model)

    def test_bad_event_requires_nonrefundable_allowance(self):
        model = finite_model()
        model["states"][0]["actions"][0]["bad_allowance"] = rat(1, 8)
        for successor in model["states"][1:]:
            successor["spent"] = rat(5, 8)
        with self.assertRaisesRegex(joint.JointLifetimeError, "BAD_MASS_EXCEEDS_ALLOWANCE"):
            joint.audit_model(model)

    def test_second_adaptive_start_is_charged_before_its_outcome(self):
        model = finite_model()
        model["lifetime_budget"] = rat(1)
        second = active("q1", 2, 2, 1, 4)
        model["states"][3]["actions"][0]["register"] = second
        model["states"][4]["spent"] = rat(1)
        model["states"][4]["starts"] = 2
        model["states"][4]["active_starts"] = [active("q1", 3, 1, 1, 4)]
        model["states"][4]["safe_absorbing"] = False
        model["states"][4]["actions"] = [action("finish-q1", [
            branch(Fraction(1), "final", j=1, parent_height=2,
                   child_time=12, next_mtp=12,
                   credited_work=joint.required_credit(joint.POW_LIMIT)),
        ])]
        model["states"].append(state(
            "final", spent=(1, 1), starts=2, height=3, mtp=12,
            credit=3 * joint.required_credit(joint.POW_LIMIT), safe=True,
        ))
        parsed = joint.parse_model(model)
        self.assertEqual(parsed.states["done"].spent, 1)
        self.assertEqual(parsed.states["done"].starts, 2)
        self.assertEqual(parsed.states["done"].active_starts,
                         (joint.ActiveStart("q1", 3, 1, Fraction(1, 4)),))

    def test_active_start_identity_cannot_be_replayed(self):
        model = finite_model()
        model["lifetime_budget"] = rat(1)
        model["states"][3]["actions"][0]["register"] = active("q0", 2, 2, 1, 4)
        with self.assertRaisesRegex(joint.JointLifetimeError, "ACTIVE_START_REPLAY"):
            joint.audit_model(model)

    def test_restart_cannot_refund_spend_or_erase_active_start(self):
        for field, changed, code in (
                ("spent", rat(1, 2), "NONREFUNDABLE_START_CHARGE"),
                ("active_starts", [], "ACTIVE_START_TRANSITION"),
                ("starts", 0, "ACTIVE_START_COUNT")):
            model = finite_model()
            model["states"][3][field] = changed
            with self.subTest(field=field), self.assertRaisesRegex(
                    joint.JointLifetimeError, code):
                joint.audit_model(model)

    def test_dynamic_participation_and_entry_debt_are_not_dropped(self):
        for field, changed, code in (
                ("qualified_units", 1, "PARTICIPATION_TRANSITION"),
                ("entry_debt", 1, "ENTRY_DEBT_TRANSITION")):
            model = finite_model()
            model["states"][3][field] = changed
            with self.subTest(field=field), self.assertRaisesRegex(
                    joint.JointLifetimeError, code):
                joint.audit_model(model)

    def test_crossing_must_be_explicit_and_absorbing(self):
        model = finite_model()
        model["states"][0]["actions"][0]["branches"][0]["bad"] = "none"
        with self.assertRaisesRegex(joint.JointLifetimeError, "UNLABELED_CROSSING"):
            joint.audit_model(model)
        model = finite_model()
        model["states"][0]["actions"][0]["branches"][0]["bad"] = "environment"
        with self.assertRaisesRegex(joint.JointLifetimeError, "CROSSING_LABEL"):
            joint.audit_model(model)
        model = finite_model()
        model["states"][1]["terminal_bad"] = False
        model["states"][1]["actions"] = [action("continue", [
            branch(Fraction(1), "after-cross", j=1, child_time=1,
                   credited_work=joint.required_credit(joint.POW_LIMIT)),
        ])]
        model["states"].append(state(
            "after-cross", spent=(3, 4), starts=1, height=1,
            credit=joint.required_credit(joint.POW_LIMIT), safe=True,
        ))
        with self.assertRaisesRegex(joint.JointLifetimeError, "BAD_NOT_TERMINAL"):
            joint.audit_model(model)

    def test_invalid_exponential_moment_cannot_issue_union_bound(self):
        model = finite_model()
        branches = model["states"][0]["actions"][0]["branches"]
        branches[0]["p"], branches[2]["p"] = rat(1, 2), rat(1, 4)
        report = joint.audit_model(model)
        self.assertFalse(report["finite_model_certificate_valid"])
        self.assertEqual(report["actions"][0]["good_joint_moment"], rat(9, 8))
        with self.assertRaisesRegex(joint.JointLifetimeError, "INVALID_FINITE_CERTIFICATE"):
            joint.combined_bound(model)

    def test_unreachable_actions_are_still_checked(self):
        model = finite_model()
        unreachable = state("unreachable", actions=[action("bad-law", [
            branch(Fraction(1), "unreachable", bad="environment")
        ])])
        model["states"].append(unreachable)
        with self.assertRaisesRegex(joint.JointLifetimeError,
                                    "BAD_NOT_TERMINAL|BAD_MASS_EXCEEDS_ALLOWANCE"):
            joint.audit_model(model)

    def test_strict_json_rejects_duplicate_keys_and_floats(self):
        with self.assertRaisesRegex(joint.JointLifetimeError, "DUPLICATE_JSON_KEY"):
            joint.strict_json('{"x":1,"x":2}')
        with self.assertRaisesRegex(joint.JointLifetimeError, "NONRATIONAL_JSON_NUMBER"):
            joint.strict_json('{"x":0.5}')

    def test_unmarked_right_censoring_is_refused(self):
        model = finite_model()
        model["states"][4]["safe_absorbing"] = False
        with self.assertRaisesRegex(joint.JointLifetimeError, "STATE_ACTIONS"):
            joint.audit_model(model)
        model = finite_model()
        model["states"][4]["active_starts"] = [active("pending", 1, 1, 1, 2)]
        with self.assertRaisesRegex(joint.JointLifetimeError, "SAFE_ACTIVE_STARTS"):
            joint.audit_model(model)

    def test_exponent_is_bounded_before_power_construction(self):
        with self.assertRaisesRegex(joint.JointLifetimeError, "EXPONENT_BIT_LIMIT"):
            joint.bounded_power(Fraction(1_000_000, 1), 1000)

    def test_cli_refuses_symlink_and_oversize_without_unbounded_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "model.json"
            target.write_text(json.dumps(finite_model(), sort_keys=True), encoding="utf-8")
            alias = root / "alias.json"
            alias.symlink_to(target)
            run = subprocess.run([sys.executable, str(Path(joint.__file__)),
                                  "--check", str(alias)], text=True,
                                 capture_output=True, check=False)
            self.assertEqual(run.returncode, 2)
            fifo = root / "fifo.json"
            os.mkfifo(fifo)
            run = subprocess.run([sys.executable, str(Path(joint.__file__)),
                                  "--check", str(fifo)], text=True,
                                 capture_output=True, check=False, timeout=2)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(json.loads(run.stdout)["error"], "INPUT_NOT_REGULAR")
            oversized = root / "oversized.json"
            with oversized.open("wb") as stream:
                stream.seek(joint.MAX_INPUT_BYTES)
                stream.write(b"x")
            run = subprocess.run([sys.executable, str(Path(joint.__file__)),
                                  "--check", str(oversized)], text=True,
                                 capture_output=True, check=False)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(json.loads(run.stdout)["error"], "INPUT_SIZE")

    def test_report_never_promotes_native_qualification(self):
        report = joint.audit_model(finite_model())
        for field in (
                "actual_probability_law_authenticated",
                "complete_legal_strategy_coverage_proved",
                "native_to_model_reduction_proved", "physical_resource_cost_proved",
                "wall_clock_authenticated", "complete_delivery_law_authenticated",
                "dynamic_participation_law_authenticated",
                "world_confirmation_starts_covered", "active_quantum_memory_covered",
                "native_common_prefix_qualified", "native_chain_growth_qualified",
                "native_chain_quality_qualified", "production_activation", "finalized",
                "execution_authority"):
            self.assertIs(report[field], False, field)
        for field in ("native_common_prefix_failure_bound", "native_chain_growth_bound",
                      "native_chain_quality_bound", "native_six_successor_risk_bound",
                      "actual_lifetime_failure_bound"):
            self.assertIsNone(report[field], field)

    def test_cli_preserves_hold_and_refuses_native_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.json"
            path.write_text(json.dumps(finite_model(), sort_keys=True), encoding="utf-8")
            command = [sys.executable, str(Path(joint.__file__)), "--check", str(path),
                       "--horizon", "2", "--require-native-qualification"]
            run = subprocess.run(command, text=True, capture_output=True, check=False)
        self.assertEqual(run.returncode, 3, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["qualification"], "HOLD_NO_GO")
        self.assertEqual(report["finite_model_exact_maximal_failure_probability"], rat(1, 2))
        self.assertIsNone(report["actual_lifetime_failure_bound"])


if __name__ == "__main__":
    unittest.main()
