"""Independent finite references and certificate tests; no native cost claim."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from fractions import Fraction
from itertools import permutations, product
import json
from pathlib import Path
from random import Random
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import credit_feasibility as model
from credit_feasibility import (
    Bound, CostModel, CostPoint, CreditProblem, Edge, Scale, Scope,
    SuccessStandard, integer_credit_schedule, load_document,
    problem_from_document, problem_sha256, problem_to_document, solve,
    verify_credit_schedule, verify_cycle, verify_result,
)

HERE = Path(__file__).resolve().parent
SCOPE = Scope("synthetic-relation-v1", "synthetic-fixed-p-v1",
              "lifetime-with-carried-inventory-v1",
              SuccessStandard("fixed_success_probability", Fraction(1, 2)))


def fixture(tables=(((1, 1), (16, 16)), ((1, 1), (4, 4))),
            gammas=(1, 1), units=None) -> CreditProblem:
    if units is None:
        units = tuple(range(1, len(tables[0]) + 1))
    scales = tuple(Scale(f"u{unit}", unit) for unit in units)
    models = []
    for index, table in enumerate(tables):
        family = "classical" if index == 0 else "quantum"
        resource = f"{family}-lifecycle-cost-v1"
        points = tuple(CostPoint(
            scale.id, SCOPE, resource,
            Bound(Fraction(low), "assumption", "synthetic lower assumption"),
            Bound(Fraction(high), "assumption", "synthetic upper assumption"))
            for scale, (low, high) in zip(scales, table))
        models.append(CostModel(f"model-{index}", family, Fraction(gammas[index]),
                                resource, points))
    return CreditProblem(SCOPE, scales, tuple(models))


def two_scale_interval_reference(problem: CreditProblem) -> bool:
    """Eliminate s0=1 by hand; this neither builds nor searches a graph."""
    lo, hi = Fraction(0), None
    for cost in problem.models:
        left, right = cost.points
        for point in (left, right):
            if point.upper.value > cost.gamma * point.lower.value:
                return False
        lo = max(lo, right.upper.value / (cost.gamma * left.lower.value))
        bound = cost.gamma * right.lower.value / left.upper.value
        hi = bound if hi is None else min(hi, bound)
    return lo <= hi


def enumerate_simple_cycles(problem: CreditProblem) -> bool:
    """Brute-force all vertex cycles and cost-model choices, without solver APIs."""
    costs = tuple({point.scale_id: (point.lower.value, point.upper.value)
                   for point in cost.points} for cost in problem.models)
    names = tuple(scale.id for scale in problem.scales)
    for length in range(1, len(names) + 1):
        for order in permutations(names, length):
            for choices in product(range(len(costs)), repeat=length):
                factor = Fraction(1)
                for index, choice in enumerate(choices):
                    source = order[index]
                    target = order[(index + 1) % length]
                    factor *= (problem.models[choice].gamma * costs[choice][target][0]
                               / costs[choice][source][1])
                if factor < 1:
                    return False
    return True


def brute_integer_grid(problem: CreditProblem, maximum: int) -> bool:
    """Enumerate all small positive integer schedules using only the definition."""
    for values in product(range(1, maximum + 1), repeat=len(problem.scales)):
        credits = dict(zip((scale.id for scale in problem.scales), values))
        if all(credits[a.scale_id] * b.upper.value
               <= cost.gamma * credits[b.scale_id] * a.lower.value
               for cost in problem.models for a, b in product(cost.points, repeat=2)):
            return True
    return False


def credits_from_result(result: dict) -> dict[str, Fraction]:
    return {row["scale_id"]: Fraction(row["value"]) for row in result["credits"]}


class MathematicalControls(unittest.TestCase):
    def test_linear_and_sqrt_costs_cannot_both_have_unit_distortion(self):
        problem = fixture(units=(1, 16))
        result = solve(problem)
        self.assertEqual(result["status"], "infeasible")
        self.assertEqual(Fraction(result["cycle_product"]), Fraction(1, 4))
        self.assertEqual(len(result["cycle"]), 2)
        self.assertEqual({edge["model_id"] for edge in result["cycle"]},
                         {"model-0", "model-1"})
        self.assertTrue(verify_result(problem, result))

    def test_exact_fairness_threshold_and_asymmetric_allowances(self):
        for gamma_c, gamma_q in product((Fraction(1), Fraction(3, 2),
                                         Fraction(2), Fraction(4)), repeat=2):
            with self.subTest(gamma_c=gamma_c, gamma_q=gamma_q):
                problem = fixture(gammas=(gamma_c, gamma_q), units=(1, 16))
                result = solve(problem)
                self.assertEqual(result["status"] == "feasible", gamma_c * gamma_q >= 4)
                self.assertTrue(verify_result(problem, result))
        result = solve(fixture(gammas=(2, 2), units=(1, 16)))
        self.assertEqual(credits_from_result(result), {"u1": Fraction(1), "u16": Fraction(8)})

    def test_fraction_arbitrarily_below_threshold_is_not_rounded_up(self):
        below = Fraction(2 * 10**80 - 1, 10**80)
        # This is deliberately a precision adversary for a log/float solver.
        self.assertEqual(float(below), 2.0)
        problem = fixture(gammas=(below, below), units=(1, 16))
        result = solve(problem)
        self.assertEqual(result["status"], "infeasible")
        self.assertEqual(Fraction(result["cycle_product"]), below * below / 4)
        exact = solve(fixture(gammas=(2, 2), units=(1, 16)))
        self.assertEqual(exact["status"], "feasible")

    def test_self_pair_uncertainty_and_exact_threshold(self):
        for gamma, expected in ((Fraction(2), "infeasible"),
                                (Fraction(3), "feasible")):
            problem = fixture(tables=(((2, 6),),), gammas=(gamma,))
            result = solve(problem)
            self.assertEqual(result["status"], expected)
            if expected == "infeasible":
                self.assertEqual(len(result["cycle"]), 1)
                self.assertEqual(Fraction(result["cycle_product"]), Fraction(2, 3))
            self.assertTrue(verify_result(problem, result))

    def test_loose_bounds_can_reject_even_if_real_costs_are_compatible(self):
        loose = fixture(tables=(((1, 4), (1, 4)),) * 2, gammas=(1, 1))
        exact = fixture(tables=(((2, 2), (2, 2)),) * 2, gammas=(1, 1))
        self.assertEqual(solve(loose)["status"], "infeasible")
        self.assertEqual(solve(exact)["status"], "feasible")

    def test_two_scale_interval_reference_exhaustive_exact_costs(self):
        cases = 0
        for costs in product((1, 2, 4), repeat=4):
            tables = tuple(tuple((value, value) for value in costs[i:i + 2])
                           for i in (0, 2))
            for gammas in product((1, Fraction(3, 2), 2), repeat=2):
                problem = fixture(tables=tables, gammas=gammas)
                result = solve(problem)
                self.assertEqual(result["status"] == "feasible",
                                 two_scale_interval_reference(problem))
                self.assertTrue(verify_result(problem, result))
                cases += 1
        self.assertEqual(cases, 729)

    def test_uncertain_intervals_match_brute_integer_schedule_search(self):
        cases = 0
        for choices in product(((1, 1), (1, 2), (2, 2)), repeat=4):
            for gammas in product((1, 2), repeat=2):
                problem = fixture(tables=(choices[:2], choices[2:]), gammas=gammas)
                result = solve(problem)
                # Endpoints are ratios of integers <=4, so any nonempty
                # feasible interval has a witness with both integers <=4.
                expected = brute_integer_grid(problem, 4)
                self.assertEqual(two_scale_interval_reference(problem), expected)
                self.assertEqual(result["status"] == "feasible", expected)
                cases += 1
        self.assertEqual(cases, 324)

    def test_three_scale_simple_cycle_reference(self):
        random = Random(20261108)
        feasible = infeasible = 0
        for _ in range(256):
            tables = []
            for _family in range(2):
                costs = []
                for _unit in range(3):
                    low = Fraction(random.randint(1, 6), random.randint(1, 3))
                    high = low * Fraction(random.randint(3, 6), 3)
                    costs.append((low, high))
                tables.append(tuple(costs))
            gammas = tuple(Fraction(random.randint(1, 4)) for _family in range(2))
            problem = fixture(tables=tuple(tables), gammas=gammas)
            result = solve(problem)
            expected = enumerate_simple_cycles(problem)
            self.assertEqual(result["status"] == "feasible", expected)
            self.assertTrue(verify_result(problem, result))
            feasible += expected
            infeasible += not expected
        self.assertGreater(feasible, 0)
        self.assertGreater(infeasible, 0)

    def test_three_models_need_a_genuine_three_edge_contradiction(self):
        problem = fixture(tables=(((4, 4), (1, 1), (2, 2)),
                                  ((2, 2), (4, 4), (1, 1)),
                                  ((1, 1), (2, 2), (4, 4))), gammas=(3, 3, 3))
        edges = model.constraints(problem)
        for edge in edges:
            if edge.source == edge.target:
                self.assertGreaterEqual(edge.multiplier, 1)
            for back in edges:
                if edge.target == back.source and edge.source == back.target:
                    self.assertGreaterEqual(edge.multiplier * back.multiplier, 1)
        result = solve(problem)
        self.assertEqual(result["status"], "infeasible")
        self.assertEqual(len(result["cycle"]), 3)
        self.assertEqual(Fraction(result["cycle_product"]), Fraction(27, 64))
        self.assertFalse(enumerate_simple_cycles(problem))
        self.assertTrue(verify_result(problem, result))

    def test_single_class_is_supported_without_claiming_quantum_coverage(self):
        problem = fixture(tables=(((2, 2), (3, 3)),), gammas=(1,))
        result = solve(problem)
        self.assertEqual(result["status"], "feasible")
        self.assertEqual(result["qualification"]["native_consensus"], "not_qualified")

    def test_integer_scaling_preserves_ratios_but_flooring_does_not(self):
        problem = fixture(tables=(((2, 2), (3, 3)),) * 2)
        result = solve(problem)
        credits = credits_from_result(result)
        self.assertEqual(credits, {"u1": Fraction(1), "u2": Fraction(3, 2)})
        self.assertEqual(integer_credit_schedule(problem, credits), {"u1": 2, "u2": 3})
        floored = {key: Fraction(value.numerator // value.denominator)
                   for key, value in credits.items()}
        with self.assertRaisesRegex(ValueError, "CREDIT_CONSTRAINT_VIOLATION"):
            verify_credit_schedule(problem, floored)

    def test_per_model_resource_units_can_differ_but_constant_scaling_cancels(self):
        problem = fixture(gammas=(2, 2))
        altered = replace(problem, models=tuple(
            replace(cost, resource_model=f"new-unit-{index}", points=tuple(
                replace(point, resource_model=f"new-unit-{index}",
                        lower=replace(point.lower, value=point.lower.value * (index + 3)),
                        upper=replace(point.upper, value=point.upper.value * (index + 3)))
                for point in cost.points)) for index, cost in enumerate(problem.models)))
        a, b = solve(problem), solve(altered)
        self.assertEqual(a["credits"], b["credits"])
        self.assertNotEqual(a["problem_sha256"], b["problem_sha256"])

    def test_output_beyond_python_decimal_limit_is_exact_and_round_trips(self):
        huge = Fraction(2**4000)
        tiny = 1 / huge
        problem = fixture(tables=(((huge, huge), (tiny, tiny)),
                                  ((tiny, tiny), (huge, huge))))
        result = solve(problem)
        self.assertEqual(result["status"], "infeasible")
        self.assertGreater(len(result["cycle_product"]), 4300)
        self.assertTrue(verify_result(problem, result))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "certificate.json"
            path.write_text(json.dumps(result), encoding="utf-8")
            self.assertTrue(verify_result(problem, load_document(path)))


class CertificateVerificationTests(unittest.TestCase):
    def test_verifier_does_not_rerun_solver_or_trust_graph_builder(self):
        for gamma in (1, 2):
            problem = fixture(gammas=(gamma, gamma))
            result = solve(problem)
            with patch.object(model, "solve", side_effect=AssertionError("solver called")), \
                    patch.object(model, "constraints", side_effect=AssertionError("graph called")):
                self.assertTrue(verify_result(problem, result))

    def test_feasible_certificate_tampering(self):
        problem = fixture(gammas=(2, 2))
        original = solve(problem)
        for change in ("zero", "float", "bool", "unknown", "duplicate", "bad_ratio", "missing"):
            result = deepcopy(original)
            if change == "missing":
                result["credits"].pop()
            elif change == "duplicate":
                result["credits"][1]["scale_id"] = result["credits"][0]["scale_id"]
            elif change == "unknown":
                result["credits"][0]["scale_id"] = "other"
            else:
                result["credits"][1]["value"] = {
                    "zero": "0", "float": 8.0, "bool": True, "bad_ratio": "3"
                }[change]
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_result(problem, result)

    def test_cycle_certificate_tampering(self):
        problem = fixture()
        original = solve(problem)
        for change in ("factor", "product", "source", "model", "empty", "duplicate"):
            result = deepcopy(original)
            if change == "factor":
                result["cycle"][0]["multiplier"] = "1/1000"
                result["cycle_product"] = "1/1000"
            elif change == "product":
                result["cycle_product"] = "1/3"
            elif change == "source":
                result["cycle"][0]["source"] = result["cycle"][0]["target"]
            elif change == "model":
                result["cycle"][0]["model_id"] = "missing-model"
            elif change == "empty":
                result["cycle"] = []
            else:
                result["cycle"] *= 2
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_result(problem, result)

    def test_equal_one_cycle_is_not_a_contradiction(self):
        problem = fixture(gammas=(2, 2))
        cycle = (Edge("model-0", "u2", "u1", Fraction(1, 8)),
                 Edge("model-1", "u1", "u2", Fraction(8)))
        with self.assertRaisesRegex(ValueError, "NOT_STRICTLY_CONTRADICTORY"):
            verify_cycle(problem, cycle)

    def test_result_binds_every_input_and_cannot_upgrade_qualification(self):
        problem = fixture(gammas=(2, 2))
        certificate = solve(problem)
        changed = replace(problem, scope=replace(problem.scope, epoch_scope="new-epoch"),
                          models=tuple(replace(cost, points=tuple(
                              replace(point, scope=replace(point.scope, epoch_scope="new-epoch"))
                              for point in cost.points)) for cost in problem.models))
        with self.assertRaisesRegex(ValueError, "DIGEST_MISMATCH"):
            verify_result(changed, certificate)
        for field in model.QUALIFICATION:
            altered = deepcopy(certificate)
            altered["qualification"][field] = "proved"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "QUALIFICATION"):
                verify_result(problem, altered)
        for field in ("extra", "schema", "status"):
            altered = deepcopy(certificate)
            altered[field] = "unknown"
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_result(problem, altered)

    def test_direct_credit_types_and_grid_are_strict(self):
        problem = fixture(gammas=(2, 2))
        for credits in ([], {"u1": 1, "u2": 8}, {"u1": Fraction(1), "u2": True},
                        {"u1": Fraction(1)}, {"u1": Fraction(1), "u2": Fraction(0)}):
            with self.subTest(credits=credits), self.assertRaises(ValueError):
                verify_credit_schedule(problem, credits)


class InputContractTests(unittest.TestCase):
    def setUp(self):
        self.problem = fixture(gammas=(2, 2))
        self.document = problem_to_document(self.problem)

    def test_round_trip_and_fraction_normalization(self):
        self.assertEqual(problem_from_document(self.document), self.problem)
        normalized = deepcopy(self.document)
        normalized["models"][0]["gamma"] = "4/2"
        self.assertEqual(problem_sha256(problem_from_document(normalized)),
                         problem_sha256(self.problem))
        normalized["models"][0]["gamma"] = 2
        self.assertEqual(problem_from_document(normalized), self.problem)

    def test_unknown_zero_and_observed_lower_bounds_are_rejected(self):
        for low in (None, "unknown", "0", 0, False, 1.0):
            document = deepcopy(self.document)
            document["models"][0]["points"][0]["lower"]["value"] = low
            with self.subTest(low=low), self.assertRaises(ValueError):
                problem_from_document(document)
        for basis in ("measurement", "implementation"):
            document = deepcopy(self.document)
            document["models"][0]["points"][0]["lower"]["basis"] = basis
            with self.subTest(basis=basis), self.assertRaisesRegex(ValueError, "NOT_LOWER_BOUND"):
                problem_from_document(document)

    def test_upper_evidence_stays_upper_and_proof_reference_stays_unverified(self):
        for basis in ("measurement", "implementation", "proof_reference", "assumption"):
            document = deepcopy(self.document)
            for cost in document["models"]:
                for point in cost["points"]:
                    point["upper"]["basis"] = basis
                    point["lower"]["basis"] = "proof_reference"
            result = solve(problem_from_document(document))
            self.assertEqual(result["status"], "feasible")
            self.assertEqual(result["qualification"]["lower_bound_claims"], "unverified_declarations")
            self.assertEqual(result["qualification"]["native_consensus"], "not_qualified")

    def test_reversed_bounds_fail(self):
        document = deepcopy(self.document)
        document["models"][0]["points"][0]["lower"]["value"] = "2"
        with self.assertRaisesRegex(ValueError, "LOWER_EXCEEDS_UPPER"):
            problem_from_document(document)

    def test_scope_mismatch_is_detected_for_each_required_dimension(self):
        cases = (("epoch_scope", "epoch-reset-v1", "EPOCH_SCOPE_MISMATCH"),
                 ("relation_id", "another-relation", "RELATION_OR_PROFILE_MISMATCH"),
                 ("profile_id", "another-profile", "RELATION_OR_PROFILE_MISMATCH"))
        for field, value, message in cases:
            document = deepcopy(self.document)
            document["models"][1]["points"][0]["scope"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                problem_from_document(document)
        document = deepcopy(self.document)
        document["models"][0]["points"][1]["scope"]["success_standard"]["probability"] = "3/4"
        with self.assertRaisesRegex(ValueError, "SUCCESS_STANDARD_MISMATCH"):
            problem_from_document(document)
        document = deepcopy(self.document)
        document["models"][0]["points"][1]["resource_model"] = "free-setup-cost-model"
        with self.assertRaisesRegex(ValueError, "RESOURCE_MODEL_MISMATCH"):
            problem_from_document(document)

    def test_success_standard_shape_and_failure_accounting_are_strict(self):
        for change in ({"kind": "conditional_success_only"},
                       {"probability": "2"}, {"probability": None},
                       {"cost_accounting": "successful_attempt_only"},
                       {"kind": "almost_sure_first_success"}):
            document = deepcopy(self.document)
            document["scope"]["success_standard"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                problem_from_document(document)
        stopping = replace(SCOPE, success_standard=SuccessStandard("almost_sure_first_success"))
        problem = replace(self.problem, scope=stopping, models=tuple(
            replace(cost, points=tuple(replace(point, scope=stopping) for point in cost.points))
            for cost in self.problem.models))
        self.assertTrue(verify_result(problem, solve(problem)))
        self.assertEqual(problem_from_document(problem_to_document(problem)), problem)

    def test_duplicate_and_missing_ids_are_rejected(self):
        cases = ("scale", "units", "model", "point", "unknown_point", "missing_point")
        for case in cases:
            document = deepcopy(self.document)
            if case == "scale":
                document["scales"][1]["id"] = document["scales"][0]["id"]
            elif case == "units":
                document["scales"][1]["units"] = document["scales"][0]["units"]
            elif case == "model":
                document["models"][1]["id"] = document["models"][0]["id"]
            elif case == "point":
                document["models"][0]["points"][1]["scale_id"] = document["scales"][0]["id"]
            elif case == "unknown_point":
                document["models"][0]["points"][1]["scale_id"] = "unknown-scale"
            else:
                document["models"][0]["points"].pop()
            with self.subTest(case=case), self.assertRaises(ValueError):
                problem_from_document(document)

    def test_bool_float_bad_fraction_and_wrong_field_types_are_rejected(self):
        for value in (True, False, 2.0, "2.0", "2e0", "02", " 2", "2/0", "-1", "NaN", [], {}):
            document = deepcopy(self.document)
            document["models"][0]["gamma"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                problem_from_document(document)
        for value in (True, 1.0, "1", None, -1, 0):
            document = deepcopy(self.document)
            document["scales"][0]["units"] = value
            with self.subTest(units=value), self.assertRaises(ValueError):
                problem_from_document(document)
        for field in ("id", "family", "resource_model"):
            document = deepcopy(self.document)
            document["models"][0][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                problem_from_document(document)

    def test_schema_unknown_fields_empty_collections_and_size_limits(self):
        for field in ("scales", "models"):
            document = deepcopy(self.document)
            document[field] = []
            with self.subTest(field=field), self.assertRaises(ValueError):
                problem_from_document(document)
        for change in ({"extra": 1}, {"schema": "pon-credit-feasibility-v2"}):
            document = deepcopy(self.document)
            document.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                problem_from_document(document)
        document = deepcopy(self.document)
        document["models"][0]["gamma"] = "1/2"
        with self.assertRaisesRegex(ValueError, "GAMMA_BELOW_ONE"):
            problem_from_document(document)
        document["models"][0]["gamma"] = 2**model.MAX_RATIONAL_BITS
        with self.assertRaisesRegex(ValueError, "RATIONAL_TOO_LARGE"):
            problem_from_document(document)
        document = deepcopy(self.document)
        document["scales"] *= model.MAX_SCALES
        with self.assertRaises(ValueError):
            problem_from_document(document)

    def test_direct_dataclass_api_refuses_malformed_types(self):
        for call in (
            lambda: Bound(1, "assumption", "a"),
            lambda: Bound(True, "assumption", "a"),
            lambda: Bound(Fraction(0), "assumption", "a"),
            lambda: Bound(Fraction(1), "measurement", ""),
            lambda: Scale(True, 1),
            lambda: Scale("u1", True),
            lambda: replace(self.problem, scales=list(self.problem.scales)),
            lambda: replace(self.problem, models=(True,)),
            lambda: replace(self.problem.models[0], gamma=2.0),
            lambda: replace(self.problem.models[0], points=[self.problem.models[0].points[0]]),
            lambda: replace(self.problem.models[0].points[0], lower=None),
            lambda: replace(SCOPE, success_standard={}),
        ):
            with self.subTest(call=call), self.assertRaises(ValueError):
                call()

    def test_json_duplicate_keys_and_inexact_numbers_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            for text in ('{"value":1,"value":2}', '{"a":{"id":"x","id":"y"}}',
                         '{"value":1.0}', '{"value":1e0}', '{"value":NaN}', '{"value":Infinity}'):
                path.write_text(text, encoding="utf-8")
                with self.subTest(text=text), self.assertRaises(ValueError):
                    load_document(path)

    def test_cli_solve_verify_and_invalid_input_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            output = Path(directory) / "certificate.json"
            source.write_text(json.dumps(self.document), encoding="utf-8")
            command = [sys.executable, str(HERE / "credit_feasibility.py")]
            completed = subprocess.run(command + ["solve", str(source), "--output", str(output)],
                                       check=True, capture_output=True, text=True)
            self.assertEqual(completed.stdout, "")
            verified = subprocess.run(command + ["verify", str(source), str(output)],
                                      check=True, capture_output=True, text=True)
            self.assertEqual(json.loads(verified.stdout)["verification"], "passed")
            source.write_text('{"schema":1.0}', encoding="utf-8")
            rejected = subprocess.run(command + ["solve", str(source)],
                                      capture_output=True, text=True)
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INEXACT_JSON_NUMBER", rejected.stderr)
            self.assertEqual(rejected.stdout, "")


if __name__ == "__main__":
    unittest.main()
