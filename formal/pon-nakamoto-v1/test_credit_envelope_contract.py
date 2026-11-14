"""Independent finite controls for the conditional public-credit contract.

Endpoint enumeration and simple-cycle enumeration cross-check the solver;
passing these controls does not establish real W1 cost bounds or consensus.
"""
from __future__ import annotations

import copy
from fractions import Fraction as F
import itertools
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import credit_envelope_contract as c


SCOPE = c.Scope("same-complete-success-v1", "same-additive-resource-v1", "same-full-competition-v1")


def problem(rho, classical, quantum, scales=None):
    scales = list(range(1, len(classical) + 1)) if scales is None else scales
    return c.CreditProblem(F(rho), SCOPE, tuple(
        c.CostPoint(scale, c.CostEnvelope(F(a), F(b), SCOPE),
                    c.CostEnvelope(F(x), F(y), SCOPE))
        for scale, (a, b), (x, y) in zip(scales, classical, quantum)))


def simple_cycle_refusal(p):
    """Independent exponential oracle for tiny graphs, without BF or helpers."""
    points = p.points
    for length in range(2, len(points) + 1):
        for sequence in itertools.permutations(points, length):
            product = F(1)
            for index, source in enumerate(sequence):
                target = sequence[(index + 1) % length]
                product *= min(p.rho * getattr(target, kind).lower
                               / getattr(source, kind).upper for kind in c.CLASSES)
            if product < 1:
                return True
    return False


class ExactFeasibilityControls(unittest.TestCase):
    def test_proportional_exact_costs_allow_common_credit(self):
        p = c.example_problems()["proportional-exact"]
        w = c.solve_credit(p)
        self.assertEqual(w["status"], c.FEASIBLE)
        self.assertEqual(w["credits"], [{"scale": 1, "credit": "1"},
                                        {"scale": 4, "credit": "4"},
                                        {"scale": 16, "credit": "16"}])
        self.assertEqual(w["worst_case_efficiency_spread"], {"classical": "1", "quantum": "1"})
        self.assertEqual(c.verify_witness(p, w)["inequalities_checked"], 12)

    def test_exact_boundary_rho_two_is_feasible(self):
        p = c.example_problems()["exponent-mismatch-rho-two"]
        w = c.solve_credit(p)
        self.assertEqual(w["credits"], [{"scale": 1, "credit": "1"},
                                        {"scale": 16, "credit": "8"}])
        self.assertEqual(w["worst_case_efficiency_spread"], {"classical": "2", "quantum": "2"})
        c.verify_witness(p, w)

    def test_below_boundary_supplies_exact_negative_cycle(self):
        p = c.example_problems()["exponent-mismatch-rho-three-halves"]
        w = c.solve_credit(p)
        self.assertEqual(w["status"], c.INFEASIBLE)
        self.assertEqual(w["cycle_product"], "9/16")
        self.assertEqual(c.verify_witness(p, w)["verified_cycle_product"], "9/16")

    def test_three_cycle_survives_every_two_point_check(self):
        p = c.example_problems()["three-cycle-without-negative-two-cycle"]
        products = []
        for a, b in itertools.combinations(p.points, 2):
            ab = min(p.rho * getattr(b, k).lower / getattr(a, k).upper for k in c.CLASSES)
            ba = min(p.rho * getattr(a, k).lower / getattr(b, k).upper for k in c.CLASSES)
            products.append(ab * ba)
        self.assertEqual(products, [F(4, 3), F(4, 3), F(1)])
        w = c.solve_credit(p)
        self.assertEqual(w["status"], c.INFEASIBLE)
        self.assertEqual(len(w["cycle"]), 3)
        self.assertEqual(w["cycle_product"], "8/9")
        c.verify_witness(p, w)

    def test_second_independent_three_cycle_fixture(self):
        p = problem(F(4), [(14, 14), (2, 2), (8, 32)], [(17, 85), (16, 16), (17, 51)])
        for a, b in itertools.combinations(p.points, 2):
            ab = min(p.rho * getattr(b, k).lower / getattr(a, k).upper for k in c.CLASSES)
            ba = min(p.rho * getattr(a, k).lower / getattr(b, k).upper for k in c.CLASSES)
            self.assertGreaterEqual(ab * ba, 1)
        w = c.solve_credit(p)
        self.assertEqual(w["status"], c.INFEASIBLE)
        self.assertEqual(w["cycle_product"], "17/20")
        c.verify_witness(p, w)

    def test_single_scale_wide_interval_has_no_self_comparison(self):
        p = c.example_problems()["wide-single-scale"]
        self.assertEqual(c.constraints(p), ())
        w = c.solve_credit(p)
        self.assertEqual(w["status"], c.FEASIBLE)
        self.assertEqual(w["credits"], [{"scale": 1, "credit": "1"}])
        self.assertEqual(w["worst_case_efficiency_spread"], {"classical": "1", "quantum": "1"})
        self.assertEqual(c.verify_witness(p, w)["inequalities_checked"], 0)

    def test_robust_refusal_is_not_impossibility_for_unknown_actual_costs(self):
        uncertain = c.example_problems()["robust-uncertainty-only-refusal"]
        self.assertEqual(c.solve_credit(uncertain)["status"], c.INFEASIBLE)
        actual = problem(F(1), [(F(3, 2), F(3, 2))] * 2, [(F(3, 2), F(3, 2))] * 2)
        self.assertEqual(c.solve_credit(actual)["status"], c.FEASIBLE)

    def test_endpoint_enumeration_checks_worst_case_spreads(self):
        p = c.example_problems()["proportional-intervals"]
        w = c.solve_credit(p)
        credits = {row["scale"]: F(row["credit"]) for row in w["credits"]}
        for kind in c.CLASSES:
            observed = []
            for endpoints in itertools.product(*[(getattr(point, kind).lower,
                                                   getattr(point, kind).upper) for point in p.points]):
                efficiencies = [credits[point.scale] / cost for point, cost in zip(p.points, endpoints)]
                observed.append(max(efficiencies) / min(efficiencies))
            self.assertEqual(max(observed), F(w["worst_case_efficiency_spread"][kind]))
            self.assertLessEqual(max(observed), p.rho)

    def test_deterministic_tiny_graphs_match_simple_cycle_enumeration(self):
        rng = random.Random(20261108)
        statuses = set()
        for size in (2, 3, 4):
            for trial in range(40):
                def intervals():
                    rows = []
                    for _ in range(size):
                        low = rng.randint(1, 9)
                        rows.append((low, low + rng.randint(0, 6)))
                    return rows
                p = problem(F(rng.randint(2, 12), 2), intervals(), intervals())
                with self.subTest(size=size, trial=trial):
                    w = c.solve_credit(p)
                    self.assertEqual(w["status"] == c.INFEASIBLE, simple_cycle_refusal(p))
                    c.verify_witness(p, w)
                    statuses.add(w["status"])
        self.assertEqual(statuses, {c.FEASIBLE, c.INFEASIBLE})

    def test_input_order_does_not_change_normalized_credit(self):
        p = c.example_problems()["proportional-exact"]
        reversed_p = c.CreditProblem(p.rho, p.scope, tuple(reversed(p.points)))
        self.assertEqual(c.solve_credit(p), c.solve_credit(reversed_p))

    def test_large_exact_values_preserve_equality_without_float_logs(self):
        amount = (1 << (c.MAX_INPUT_BITS - 1)) - 1
        p = problem(F(1), [(1, 1), (amount, amount)], [(1, 1), (amount, amount)])
        w = c.solve_credit(p)
        self.assertEqual(w["credits"][1]["credit"], str(amount))
        c.verify_witness(p, w)

    def test_maximum_admitted_point_count_is_bounded_and_valid(self):
        p = problem(F(1), [(i, i) for i in range(1, c.MAX_POINTS + 1)],
                    [(3 * i, 3 * i) for i in range(1, c.MAX_POINTS + 1)])
        self.assertEqual(c.verify_witness(p, c.solve_credit(p))["inequalities_checked"],
                         2 * c.MAX_POINTS * (c.MAX_POINTS - 1))


class InputRefusalControls(unittest.TestCase):
    def setUp(self):
        self.document = c.problem_document(c.example_problems()["exponent-mismatch-rho-two"])

    def test_roundtrip_uses_exact_canonical_rationals(self):
        self.assertEqual(c.problem_document(c.problem_from_document(self.document)), self.document)

    def test_non_fraction_python_inputs_fail(self):
        for value in (True, False, 1, 1.0, "1", None):
            with self.subTest(value=value), self.assertRaises(c.ContractError):
                c.CostEnvelope(value, F(2), SCOPE)
            with self.subTest(rho=value), self.assertRaises(c.ContractError):
                c.CreditProblem(value, SCOPE, (c.CostPoint(1, c.CostEnvelope(F(1), F(2), SCOPE),
                                                                      c.CostEnvelope(F(1), F(2), SCOPE)),))

    def test_zero_negative_and_reversed_intervals_fail(self):
        for low, high in ((0, 1), (-1, 1), (1, 0), (2, 1)):
            with self.subTest(low=low, high=high), self.assertRaises(c.ContractError):
                c.CostEnvelope(F(low), F(high), SCOPE)

    def test_rho_below_one_fails(self):
        self.document["rho"] = "1/2"
        with self.assertRaisesRegex(c.ContractError, "RHO_BELOW_ONE"):
            c.problem_from_document(self.document)

    def test_all_rational_fields_reject_bool_float_null_and_noncanonical_text(self):
        bad = (True, 1.0, 1, None, "0", "-1", "1.0", "2/4", "1/1", "+1", "01", "1/0", " 1", "nan")
        for value in bad:
            for field in ("lower", "upper"):
                mutant = copy.deepcopy(self.document)
                mutant["points"][0]["classical"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(c.ContractError):
                    c.problem_from_document(mutant)

    def test_scale_bool_float_zero_duplicate_and_unbounded_fail(self):
        for scale in (True, 1.0, 0, -1, "1", 1 << 64, None):
            mutant = copy.deepcopy(self.document)
            mutant["points"][0]["scale"] = scale
            with self.subTest(scale=scale), self.assertRaises(c.ContractError):
                c.problem_from_document(mutant)
        self.document["points"][1]["scale"] = self.document["points"][0]["scale"]
        with self.assertRaisesRegex(c.ContractError, "DUPLICATE_SCALE"):
            c.problem_from_document(self.document)

    def test_resource_success_and_competitive_scope_mismatch_fail(self):
        for key in ("success_contract", "resource_model", "competitive_scope"):
            mutant = copy.deepcopy(self.document)
            mutant["points"][1]["quantum"]["scope"][key] = "different-v1"
            with self.subTest(key=key), self.assertRaisesRegex(c.ContractError, "SCOPE_MISMATCH"):
                c.problem_from_document(mutant)

    def test_empty_and_overlarge_point_sets_fail_before_solving(self):
        for count in (0, c.MAX_POINTS + 1):
            mutant = copy.deepcopy(self.document)
            mutant["points"] = [copy.deepcopy(mutant["points"][0]) for _ in range(count)]
            with self.subTest(count=count), self.assertRaisesRegex(c.ContractError, "POINT_COUNT"):
                c.problem_from_document(mutant)

    def test_input_bit_limits_cover_numerator_and_denominator(self):
        for value in (str(1 << c.MAX_INPUT_BITS), "1/" + str(1 << c.MAX_INPUT_BITS)):
            mutant = copy.deepcopy(self.document)
            mutant["points"][0]["classical"]["lower"] = value
            with self.subTest(value=value), self.assertRaisesRegex(c.ContractError, "BIT_LIMIT"):
                c.problem_from_document(mutant)

    def test_unknown_and_missing_fields_cannot_enable_qualification(self):
        for change in ("qualified", "missing-rho", "missing-class"):
            mutant = copy.deepcopy(self.document)
            if change == "qualified":
                mutant["qualified"] = True
            elif change == "missing-rho":
                del mutant["rho"]
            else:
                del mutant["points"][0]["quantum"]
            with self.subTest(change=change), self.assertRaises(c.ContractError):
                c.problem_from_document(mutant)

    def test_labels_are_bounded_and_cannot_hide_whitespace(self):
        for label in ("", "contains space", "\nshadow", "a" * 161, True, None):
            with self.subTest(label=label), self.assertRaises(c.ContractError):
                c.Scope(label, "resource", "scope")


class IndependentWitnessControls(unittest.TestCase):
    def test_verifiers_do_not_call_solver_or_constraint_builder(self):
        examples = c.example_problems()
        witnesses = {name: c.solve_credit(p) for name, p in examples.items()}
        report = c.build_report()
        with patch.object(c, "solve_credit", side_effect=AssertionError("solver must not run")), \
                patch.object(c, "constraints", side_effect=AssertionError("builder must not run")):
            for name, p in examples.items():
                c.verify_witness(p, witnesses[name])
            self.assertEqual(c.verify_report(report)["verification"], "PASS")

    def test_mutated_positive_credit_fails_all_pair_check(self):
        p = c.example_problems()["proportional-exact"]
        w = c.solve_credit(p)
        w["credits"][1]["credit"] = "5"
        with self.assertRaisesRegex(c.ContractError, "CREDIT_INEQUALITY"):
            c.verify_witness(p, w)

    def test_missing_duplicate_and_bool_credit_identities_fail(self):
        p = c.example_problems()["proportional-exact"]
        for mode in ("missing", "duplicate", "bool"):
            w = c.solve_credit(p)
            if mode == "missing":
                w["credits"].pop()
            elif mode == "duplicate":
                w["credits"][1]["scale"] = 1
            else:
                w["credits"][0]["scale"] = True
            with self.subTest(mode=mode), self.assertRaises(c.ContractError):
                c.verify_witness(p, w)

    def test_fake_normalization_or_spread_is_refused(self):
        p = c.example_problems()["exponent-mismatch-rho-two"]
        for mode in ("normalization", "spread"):
            w = c.solve_credit(p)
            if mode == "normalization":
                for row in w["credits"]:
                    row["credit"] = str(2 * F(row["credit"]))
            else:
                w["worst_case_efficiency_spread"]["quantum"] = "1"
            with self.subTest(mode=mode), self.assertRaises(c.ContractError):
                c.verify_witness(p, w)

    def test_edge_weights_and_products_are_recomputed(self):
        p = c.example_problems()["exponent-mismatch-rho-three-halves"]
        for mode in ("edge", "class", "product"):
            w = c.solve_credit(p)
            if mode == "edge":
                w["cycle"][0]["bound"] = "1/1000"
                w["cycle_product"] = "1/1000000"
            elif mode == "class":
                w["cycle"][0]["miner_class"] = ("quantum" if w["cycle"][0]["miner_class"] == "classical" else "classical")
            else:
                w["cycle_product"] = "1/1000000"
            with self.subTest(mode=mode), self.assertRaises(c.ContractError):
                c.verify_witness(p, w)

    def test_negative_edge_list_must_be_a_closed_walk(self):
        p = c.example_problems()["three-cycle-without-negative-two-cycle"]
        w = c.solve_credit(p)
        w["cycle"][0], w["cycle"][1] = w["cycle"][1], w["cycle"][0]
        with self.assertRaisesRegex(c.ContractError, "CYCLE_NOT_CLOSED"):
            c.verify_witness(p, w)

    def test_unit_product_cycle_does_not_certify_infeasibility(self):
        p = c.example_problems()["exponent-mismatch-rho-two"]
        edges = [c.Edge(16, 1, "classical", F(1, 8)), c.Edge(1, 16, "quantum", F(8))]
        w = {"status": c.INFEASIBLE, "cycle": [c.edge_document(e) for e in edges], "cycle_product": "1"}
        with self.assertRaisesRegex(c.ContractError, "CYCLE_NOT_NEGATIVE"):
            c.verify_witness(p, w)

    def test_single_point_cannot_be_falsely_refused_by_a_self_edge(self):
        p = c.example_problems()["wide-single-scale"]
        w = {"status": c.INFEASIBLE, "cycle": [{"source_scale": 1, "target_scale": 1,
               "miner_class": "classical", "bound": "1/1000000"}], "cycle_product": "1/1000000"}
        with self.assertRaises(c.ContractError):
            c.verify_witness(p, w)

    def test_forged_status_and_extra_witness_fields_fail(self):
        p = c.example_problems()["proportional-exact"]
        for key, value in (("status", "QUALIFIED"), ("w1_cost_lower_bound_proved", True)):
            w = c.solve_credit(p)
            w[key] = value
            with self.subTest(key=key), self.assertRaises(c.ContractError):
                c.verify_witness(p, w)

    def test_certificate_rational_bit_limit_is_checked_before_arithmetic(self):
        p = c.example_problems()["proportional-exact"]
        w = c.solve_credit(p)
        w["credits"][1]["credit"] = str(1 << c.MAX_CERT_BITS)
        with self.assertRaisesRegex(c.ContractError, "CREDIT_BIT_LIMIT"):
            c.verify_witness(p, w)


class ReportAndEncodingControls(unittest.TestCase):
    def test_report_roundtrip_and_all_qualification_flags_remain_false(self):
        report = c.build_report()
        self.assertTrue(all(value is False for value in report["qualification"].values()))
        checked = c.verify_report(json.loads(json.dumps(report)))
        self.assertEqual(checked["verification"], "PASS")
        self.assertTrue(all(value is False for value in checked["qualification"].values()))
        self.assertNotIn("test_count", report)

    def test_true_or_zero_qualification_flags_are_rejected(self):
        for replacement in (True, 0, None):
            report = c.build_report()
            report["qualification"]["mixed_mining_consensus_qualified"] = replacement
            with self.subTest(replacement=replacement), self.assertRaisesRegex(c.ContractError, "QUALIFICATION_UPGRADE"):
                c.verify_report(report)

    def test_source_binding_input_and_case_roster_mutations_are_rejected(self):
        for mode in ("source", "input", "roster", "limits"):
            report = c.build_report()
            if mode == "source":
                report["source_binding"][0]["sha256"] = "0" * 64
            elif mode == "input":
                report["cases"][0]["input"]["rho"] = "2"
            elif mode == "roster":
                report["cases"][1]["case_id"] = report["cases"][0]["case_id"]
            else:
                report["limitations"].pop()
            with self.subTest(mode=mode), self.assertRaises(c.ContractError):
                c.verify_report(report)

    def test_json_duplicate_keys_floats_and_nonfinite_values_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            for payload in ('{"rho":"1","rho":"2"}', '{"a":1.0}', '{"a":NaN}', '{"a":Infinity}'):
                path.write_text(payload, encoding="utf-8")
                with self.subTest(payload=payload), self.assertRaises(c.ContractError):
                    c.load_json(path)

    def test_json_byte_limit_is_enforced_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            path.write_bytes(b" " * (c.MAX_JSON_BYTES + 1))
            with self.assertRaisesRegex(c.ContractError, "JSON_BYTE_LIMIT"):
                c.load_json(path)

    def test_json_integer_limit_precedes_decimal_conversion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "integer.json"
            for value in (str(1 << 64), "9" * 10000):
                path.write_text('{"scale":' + value + '}', encoding="utf-8")
                with self.subTest(length=len(value)), self.assertRaisesRegex(c.ContractError, "JSON_INTEGER_LIMIT"):
                    c.load_json(path)

    def test_cli_creates_and_independently_rechecks_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            command = [sys.executable, str(Path(c.__file__).resolve())]
            written = subprocess.run(command + ["--output", str(path)], capture_output=True, text=True, timeout=20)
            self.assertEqual(written.returncode, 0, written.stderr)
            checked = subprocess.run(command + ["--verify", str(path)], capture_output=True, text=True, timeout=20)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(json.loads(checked.stdout)["verification"], "PASS")
            overwrite = subprocess.run(command + ["--output", str(path)], capture_output=True, text=True, timeout=20)
            self.assertNotEqual(overwrite.returncode, 0)
            c.verify_report(c.load_json(path))


if __name__ == "__main__":
    unittest.main()
