"""Independent finite checks for the scoped credit/cost contract."""

import copy
import hashlib
import itertools
import json
import subprocess
import sys
import tempfile
import unittest
from fractions import Fraction
from pathlib import Path

from cost_envelope_contract_v1 import (
    BATCH_SCHEMA, BATCH_WINDOW, BUDGET_SCHEMA, CATALOG_SCHEMA, PROBABILITY_SCOPE,
    SCHEMA, SUCCESS_STANDARD,
    _unique_pairs, check_contract, failure_budget, rational, rational_json,
)


def q(n, d=1):
    return rational_json(Fraction(n, d))


def contract(costs=None):
    costs = costs or {"classical": {1: 1, 4: 4}, "quantum": {1: 7, 4: 28}}
    levels = sorted(next(iter(costs.values())))
    return {
        "schema": SCHEMA,
        "profile_sha256": "1" * 64,
        "p0": q(1, 16),
        "success_standard": SUCCESS_STANDARD,
        "probability_scope": PROBABILITY_SCOPE,
        "success_probability_target": q(1, 2),
        "deadline_ms": 1000,
        "horizon_rounds": 10,
        "work_levels": levels,
        "class_scales": {name: q(7 if name == "quantum" else 1) for name in costs},
        "max_distortion": q(1),
        "envelopes": [
            {"class": name, "u": u, "lower": q(cost), "upper": q(cost),
             "evidence": {"kind": "hypothesis", "reference": "declared-example-costs"}}
            for name, table in costs.items() for u, cost in table.items()
        ],
        "nondecreasing": True,
        "credit_quantum": None,
        "batches": [],
        "failure_budget": None,
    }


def finite_evidence(entries, witness):
    return {
        "kind": "finite_catalog", "schema": CATALOG_SCHEMA,
        "entries": [{"strategy_id": name, "total_lifecycle_cost": q(cost),
                     "success_probability": q(probability), "elapsed_ms": 100,
                     "rounds": 1} for name, cost, probability in entries],
        "minimum_strategy_id": witness,
    }


def batch(yields, cost, name="cache", scale_class="classical"):
    return {
        "schema": BATCH_SCHEMA, "id": name, "class": scale_class,
        "window_semantics": BATCH_WINDOW, "deadline_ms": 1000, "horizon_rounds": 10,
        "expected_accepts": [{"u": u, "count": q(count)} for u, count in yields.items()],
        "total_lifecycle_cost": q(cost), "credit_per_normalized_cost_cap": q(1),
        "basis": "declared_finite_strategy", "reference": "finite-cached-batch-example",
    }


def budget():
    return {
        "schema": BUDGET_SCHEMA, "target": q(1, 1024),
        "terms": [
            {"id": "work", "upper": q(1, 2**20), "occurrences": 10,
             "scope": "per_invocation", "reference": "conditional-work-bound"},
            {"id": "shared_hash", "upper": q(1, 2**18), "occurrences": 1,
             "scope": "joint_lifetime", "reference": "joint-query-budget-hypothesis"},
        ],
    }


class ExactEnvelopeTests(unittest.TestCase):
    def test_proportional_curves_admit_same_normalized_credit(self):
        result = check_contract(contract())
        self.assertEqual(result["arithmetic_status"], "FEASIBLE")
        self.assertEqual([rational(item["credit"]) for item in result["credit_witness"]],
                         [Fraction(1), Fraction(4)])
        self.assertEqual(result["evidence_scope"], "CONDITIONAL_HYPOTHESES")
        self.assertEqual(result["production_gate"], "HOLD_NO_GO")
        self.assertIsNone(result["all_legal_algorithms_lower_bound"])
        self.assertIsNone(result["mixed_consensus_proof"])
        self.assertFalse(result["profile_identity_verified"])

    def test_fixed_probability_does_not_make_nonproportional_curves_fair(self):
        value = contract({"classical": {1: 1, 4: 4, 16: 16},
                          "quantum": {1: 1, 4: 2, 16: 4}})
        value["class_scales"]["quantum"] = q(1)
        result = check_contract(value)
        self.assertEqual(result["arithmetic_status"], "INFEASIBLE")
        self.assertEqual({row["u"] for row in result["violations"]}, {4, 16})
        value["max_distortion"] = q(2)
        result = check_contract(value)
        self.assertEqual(result["arithmetic_status"], "FEASIBLE")
        self.assertEqual(result["credit_witness"][-1]["credit"], q(8))
        self.assertTrue(result["p0_is_input_hypothesis"])

    def test_robust_interval_uses_upper_for_lower_credit_and_lower_for_upper_credit(self):
        value = contract({"classical": {1: 3}})
        value["envelopes"][0].update(lower=q(1), upper=q(5))
        value["max_distortion"] = q(2)
        result = check_contract(value)
        self.assertEqual(result["arithmetic_status"], "INFEASIBLE")
        self.assertEqual(result["violations"][0]["required_lower"], q(5, 2))
        self.assertEqual(result["violations"][0]["permitted_upper"], q(2))

    def test_class_normalization_applies_to_batch_total_cost(self):
        value = contract()
        value["batches"] = [batch({1: 1, 4: 1}, 35, scale_class="quantum")]
        self.assertEqual(check_contract(value)["arithmetic_status"], "FEASIBLE")
        value["batches"][0]["total_lifecycle_cost"] = q(28)
        result = check_contract(value)
        self.assertEqual(result["arithmetic_status"], "INFEASIBLE")
        self.assertEqual(result["violations"][0]["minimum_expected_credit"], q(5))
        self.assertEqual(result["violations"][0]["permitted_credit"], q(4))

    def test_cache_batch_refutes_feasible_single_level_rows(self):
        value = contract({"classical": {1: 1, 2: 2}})
        self.assertEqual(check_contract(value)["arithmetic_status"], "FEASIBLE")
        value["batches"] = [batch({1: 1, 2: 1}, 2)]
        result = check_contract(value)
        self.assertEqual(result["arithmetic_status"], "INFEASIBLE")
        self.assertEqual(result["violations"][0]["kind"], "JOINT_BATCH_CAP")
        self.assertNotIn("credit_witness", result)

    def test_same_batch_cost_with_more_hidden_trials_is_not_free(self):
        value = contract({"classical": {1: 1}})
        value["batches"] = [batch({1: Fraction(3, 2)}, 1)]
        self.assertEqual(check_contract(value)["arithmetic_status"], "INFEASIBLE")
        value["batches"][0]["total_lifecycle_cost"] = q(3, 2)
        self.assertEqual(check_contract(value)["arithmetic_status"], "FEASIBLE")

    def test_monotonicity_is_a_cross_level_constraint(self):
        value = contract({"classical": {1: 4, 2: 1}})
        self.assertEqual(check_contract(value)["arithmetic_status"], "INFEASIBLE")
        value["nondecreasing"] = False
        self.assertEqual(check_contract(value)["arithmetic_status"], "FEASIBLE")

    def test_credit_lattice_has_exact_upward_rounding(self):
        value = contract({"classical": {1: 1}})
        value["envelopes"][0].update(lower=q(1, 3), upper=q(2, 3))
        value["max_distortion"] = q(2)
        value["credit_quantum"] = q(1)
        self.assertEqual(check_contract(value)["arithmetic_status"], "INFEASIBLE")
        value["credit_quantum"] = q(1, 2)
        result = check_contract(value)
        self.assertEqual(result["arithmetic_status"], "FEASIBLE")
        self.assertEqual(result["credit_witness"][0]["credit"], q(1, 2))

    def test_finite_catalog_certificate_is_recomputed_from_all_entries(self):
        value = contract({"classical": {1: 2}})
        evidence = finite_evidence([("slow", 3, 1), ("fast", 2, Fraction(1, 2))], "fast")
        value["envelopes"][0]["evidence"] = evidence
        result = check_contract(value)
        self.assertEqual(result["arithmetic_status"], "FEASIBLE")
        self.assertEqual(result["evidence_scope"], "DECLARED_FINITE_MODEL_ONLY")
        self.assertEqual(result["evidence"][0]["finite_model_minimum"], q(2))
        self.assertEqual(result["production_gate"], "HOLD_NO_GO")
        # A third, faster strategy invalidates the old claimed lower bound.
        evidence["entries"].append({"strategy_id": "reuse", "total_lifecycle_cost": q(1),
                                    "success_probability": q(1),
                                    "elapsed_ms": 100, "rounds": 1})
        evidence["minimum_strategy_id"] = "reuse"
        with self.assertRaisesRegex(ValueError, "contradicts finite catalog"):
            check_contract(value)

    def test_false_finite_witness_and_boolean_certificate_are_rejected(self):
        value = contract({"classical": {1: 2}})
        value["envelopes"][0]["evidence"] = finite_evidence([("slow", 3, 1), ("fast", 2, 1)], "slow")
        with self.assertRaisesRegex(ValueError, "minimum witness"):
            check_contract(value)
        for evidence in ({"kind": "certified", "certified": True},
                         {"kind": "hypothesis", "reference": "paper", "certified": True}):
            value["envelopes"][0]["evidence"] = evidence
            with self.assertRaises(ValueError):
                check_contract(value)

    def test_missing_pair_or_endpoint_remains_hold(self):
        for alteration in (lambda value: value["envelopes"].pop(),
                           lambda value: value["envelopes"][0].update(lower=None),
                           lambda value: value["envelopes"][0].update(upper=None)):
            value = contract()
            alteration(value)
            result = check_contract(value)
            self.assertEqual(result["arithmetic_status"], "HOLD_MISSING_BOUNDS")
            self.assertTrue(result["missing_bounds"])
            self.assertEqual(result["credit_witness"], [])
            self.assertEqual(result["production_gate"], "HOLD_NO_GO")

    def test_missing_endpoint_is_not_filled_from_finite_catalog(self):
        value = contract({"classical": {1: 2}})
        value["envelopes"][0]["evidence"] = finite_evidence([("a", 2, 1)], "a")
        value["envelopes"][0]["lower"] = None
        self.assertEqual(check_contract(value)["arithmetic_status"], "HOLD_MISSING_BOUNDS")

    def test_fixed_success_contract_excludes_cheap_low_probability_or_late_strategies(self):
        value = contract({"classical": {1: 2}})
        evidence = finite_evidence([
            ("weak_probability", Fraction(1, 10), Fraction(1, 10)),
            ("late", 1, 1), ("too_many_rounds", 1, 1), ("qualified", 2, Fraction(1, 2)),
        ], "qualified")
        evidence["entries"][1]["elapsed_ms"] = 1001
        evidence["entries"][2]["rounds"] = 11
        value["envelopes"][0]["evidence"] = evidence
        result = check_contract(value)
        self.assertEqual(result["arithmetic_status"], "FEASIBLE")
        self.assertEqual(result["evidence"][0]["finite_model_minimum"], q(2))
        self.assertEqual(result["evidence"][0]["qualifying_strategy_ids"], ["qualified"])
        # Cost divided by success probability would pick 1 here, a different
        # objective than the requested half-success-by-deadline cost of 2.
        evidence["minimum_strategy_id"] = "weak_probability"
        with self.assertRaisesRegex(ValueError, "minimum witness"):
            check_contract(value)

    def test_no_strategy_meets_success_window_is_hold_not_zero_cost(self):
        value = contract({"classical": {1: 2}})
        value["envelopes"][0]["evidence"] = finite_evidence([("weak", 1, Fraction(1, 4))], None)
        result = check_contract(value)
        self.assertEqual(result["arithmetic_status"], "HOLD_NO_QUALIFYING_STRATEGY")
        self.assertEqual(result["credit_witness"], [])
        self.assertIsNone(result["evidence"][0]["finite_model_minimum"])

    def test_tightening_success_target_or_window_never_adds_qualifying_strategies(self):
        value = contract({"classical": {1: 1}})
        value["envelopes"][0].update(lower=q(1), upper=q(3))
        evidence = finite_evidence([("quick_weak", 1, Fraction(1, 2)), ("slow_strong", 3, 1)], "quick_weak")
        evidence["entries"][0]["elapsed_ms"] = 20
        evidence["entries"][1]["elapsed_ms"] = 200
        value["envelopes"][0]["evidence"] = evidence
        baseline = set(check_contract(value)["evidence"][0]["qualifying_strategy_ids"])
        value["success_probability_target"] = q(3, 4)
        evidence["minimum_strategy_id"] = "slow_strong"
        narrowed = set(check_contract(value)["evidence"][0]["qualifying_strategy_ids"])
        self.assertLess(narrowed, baseline)
        value["deadline_ms"] = 100
        evidence["minimum_strategy_id"] = None
        self.assertEqual(check_contract(value)["arithmetic_status"], "HOLD_NO_QUALIFYING_STRATEGY")

    def test_batch_window_cannot_silently_change_probability_cost_standard(self):
        for field, changed in (("deadline_ms", 2000), ("horizon_rounds", 11),
                               ("window_semantics", "fixed_probability_cost")):
            value = contract()
            value["batches"] = [batch({1: 1}, 1)]
            value["batches"][0][field] = changed
            with self.assertRaises(ValueError):
                check_contract(value)

    def test_exhaustive_integer_credit_feasibility_against_independent_search(self):
        # Enumerate all candidate credits independently of prefix-max logic.
        # This checks the necessity as well as sufficiency of batch rejection.
        for costs in itertools.product((1, 2, 3), repeat=4):
            for distortion, monotone, cap in itertools.product((1, 2), (False, True), (2, 4, 6, 8)):
                value = contract({"classical": {1: costs[0], 2: costs[1]},
                                  "quantum": {1: costs[2], 2: costs[3]}})
                value["class_scales"]["quantum"] = q(1)
                value["max_distortion"] = q(distortion)
                value["nondecreasing"] = monotone
                value["credit_quantum"] = q(1)
                value["batches"] = [batch({1: 1, 2: 1}, cap)]
                witnesses = []
                for a, b in itertools.product(range(1, 7), repeat=2):
                    if monotone and a > b:
                        continue
                    if a + b > cap:
                        continue
                    if all(Fraction(c, distortion) <= s <= distortion * c
                           for c, s in zip(costs, (a, b, a, b))):
                        witnesses.append((a, b))
                result = check_contract(value)
                self.assertEqual(result["arithmetic_status"] == "FEASIBLE", bool(witnesses))
                if witnesses:
                    found = tuple(rational(row["credit"]) for row in result["credit_witness"])
                    self.assertIn(found, witnesses)

    def test_exact_fraction_parser_rejects_aliases_and_noncanonical_inputs(self):
        for value in (True, 1, 0.5, "1/2", {"n": True, "d": 1}, {"n": 1, "d": True},
                      {"n": 2, "d": 4}, {"n": 0, "d": 2}, {"n": 1, "d": -2},
                      {"n": 1, "d": 0}, {"n": 1.0, "d": 2}, {"n": 1, "d": 2, "ok": True}):
            with self.assertRaises(ValueError):
                rational(value)
        self.assertEqual(rational({"n": -1, "d": 2}), Fraction(-1, 2))
        self.assertEqual(rational({"n": 0, "d": 1}), 0)

    def test_boolean_counts_levels_and_catalog_inputs_do_not_pass_as_integers(self):
        variants = []
        value = contract()
        value["work_levels"][0] = True
        variants.append(value)
        value = contract()
        value["envelopes"][0]["u"] = True
        variants.append(value)
        value = contract()
        value["nondecreasing"] = 1
        variants.append(value)
        value = contract()
        value["class_scales"]["classical"] = {"n": True, "d": 1}
        variants.append(value)
        value = contract()
        value["batches"] = [batch({1: 1}, 1)]
        value["batches"][0]["expected_accepts"][0]["count"] = {"n": True, "d": 1}
        variants.append(value)
        for field in ("deadline_ms", "horizon_rounds"):
            value = contract()
            value[field] = True
            variants.append(value)
        for value in variants:
            with self.assertRaises(ValueError):
                check_contract(value)

    def test_unknown_fields_duplicate_rows_and_wrong_schema_are_rejected(self):
        mutations = [
            lambda value: value.update(production_qualified=True),
            lambda value: value.update(schema="pon.cost-envelope.contract.v0"),
            lambda value: value.update(success_standard="hash_only"),
            lambda value: value["envelopes"].append(copy.deepcopy(value["envelopes"][0])),
            lambda value: value.update(work_levels=[4, 1]),
            lambda value: value.update(profile_sha256="A" * 64),
            lambda value: value.update(p0=q(1)),
            lambda value: value.update(probability_scope="95_percent_measurement_confidence"),
            lambda value: value.update(success_probability_target=q(0)),
        ]
        for mutation in mutations:
            value = contract()
            mutation(value)
            with self.assertRaises(ValueError):
                check_contract(value)

    def test_digest_binds_probability_scales_costs_and_batch_contract(self):
        value = contract()
        original = check_contract(value)["contract_sha256"]
        for mutate in (lambda v: v.update(p0=q(1, 32)),
                       lambda v: v["class_scales"].update(quantum=q(8)),
                       lambda v: v.update(batches=[batch({1: 1}, 1)])):
            variant = copy.deepcopy(value)
            mutate(variant)
            self.assertNotEqual(check_contract(variant)["contract_sha256"], original)
        reordered = dict(reversed(list(value.items())))
        self.assertEqual(check_contract(reordered)["contract_sha256"], original)

    def test_cli_rejects_duplicate_json_and_does_not_default_to_success_exit(self):
        with self.assertRaises(ValueError):
            json.loads('{"n": 1, "n": 2, "d": 1}', object_pairs_hook=_unique_pairs)
        executable = Path(__file__).with_name("cost_envelope_contract_v1.py")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(contract()), encoding="utf-8")
            result = subprocess.run([sys.executable, str(executable), str(path)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 3)
            self.assertEqual(json.loads(result.stdout)["production_gate"], "HOLD_NO_GO")
            result = subprocess.run([sys.executable, str(executable), str(path), "--arithmetic-only"],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0)

    def test_checked_in_current_hold_and_paid_preparation_counterexample(self):
        directory = Path(__file__).parent
        profile_bytes = (directory.parents[1] / "config/pon/work-profile-v1.json").read_bytes()
        profile_digest = hashlib.sha256(profile_bytes).hexdigest()
        outcomes = []
        for filename in ("cost-envelope-current-hold-v1.json", "cost-envelope-counterexample-v1.json"):
            value = json.loads((directory / "contracts" / filename).read_text(encoding="utf-8"))
            self.assertEqual(value["profile_sha256"], profile_digest)
            self.assertEqual(value["success_probability_target"], q(1, 2))
            self.assertEqual((value["deadline_ms"], value["horizon_rounds"]), (120000, 1))
            self.assertIsNone(value["failure_budget"])
            outcomes.append(check_contract(value))
        self.assertEqual(outcomes[0]["arithmetic_status"], "HOLD_MISSING_BOUNDS")
        self.assertEqual(len(outcomes[0]["missing_bounds"]), 12)
        self.assertEqual(outcomes[1]["arithmetic_status"], "INFEASIBLE")
        self.assertEqual(outcomes[1]["violations"][0]["minimum_expected_credit"], q(7, 2))
        self.assertEqual(outcomes[1]["violations"][0]["permitted_credit"], q(3))


class LifetimeBudgetTests(unittest.TestCase):
    def test_exact_union_includes_every_occurrence_without_independence(self):
        result = failure_budget(budget())
        self.assertEqual(result["status"], "CONDITIONAL_WITHIN_TARGET")
        self.assertEqual(rational(result["total_failure_upper"]), Fraction(14, 2**20))
        self.assertIsNone(result["verified_security_bits"])

    def test_more_attempts_or_failures_cannot_improve_budget(self):
        previous = Fraction(0)
        for count in (0, 1, 2, 10, 1024, 2048):
            value = budget()
            value["terms"][0]["occurrences"] = count
            result = failure_budget(value)
            subtotal = rational(result["known_union_subtotal"])
            self.assertGreaterEqual(subtotal, previous)
            previous = subtotal
        self.assertEqual(result["status"], "TARGET_EXCEEDED")

    def test_unknown_probability_or_multiplicity_preserves_null(self):
        for key in ("upper", "occurrences"):
            value = budget()
            value["terms"][0][key] = None
            result = failure_budget(value)
            self.assertEqual(result["status"], "HOLD_MISSING_BOUND")
            self.assertIsNone(result["total_failure_upper"])
        value["terms"][0].update(upper=None, occurrences=0)
        self.assertEqual(failure_budget(value)["status"], "HOLD_MISSING_BOUND")

    def test_joint_lifetime_bound_cannot_be_reset_or_multiply_counted(self):
        for count in (0, 2, True):
            value = budget()
            value["terms"][1]["occurrences"] = count
            with self.assertRaises(ValueError):
                failure_budget(value)

    def test_lifetime_invalid_rates_and_duplicate_terms_fail_closed(self):
        for upper in (q(-1), q(2), 0.1, {"n": True, "d": 1}):
            value = budget()
            value["terms"][0]["upper"] = upper
            with self.assertRaises(ValueError):
                failure_budget(value)
        value = budget()
        value["terms"].append(copy.deepcopy(value["terms"][0]))
        with self.assertRaises(ValueError):
            failure_budget(value)

    def test_contract_never_upgrades_when_declared_budget_is_small(self):
        value = contract()
        value["failure_budget"] = budget()
        result = check_contract(value)
        self.assertEqual(result["arithmetic_status"], "FEASIBLE")
        self.assertEqual(result["failure_budget"]["status"], "CONDITIONAL_WITHIN_TARGET")
        self.assertEqual(result["production_gate"], "HOLD_NO_GO")
        value["failure_budget"]["terms"][0]["upper"] = None
        self.assertEqual(check_contract(value)["failure_budget"]["status"], "HOLD_MISSING_BOUND")


if __name__ == "__main__":
    unittest.main()
