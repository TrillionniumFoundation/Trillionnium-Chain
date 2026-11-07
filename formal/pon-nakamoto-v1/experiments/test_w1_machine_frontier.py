"""Finite-family and outward-interval ordering controls, not hardware results."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import w1_machine_frontier as frontier
from quantum_oracle_resources import example
from test_w1_quantum_oracle import fixture
from w1_machine_envelope import illustrative_lifecycle_model


def cell(lower, upper, cost=1):
    return {"status": "CONSTRUCTED", "resources": {name: cost for name in frontier.RESOURCE_FIELDS},
        "conditional_delivery_probability": {"lower": {"numerator": lower, "denominator": 100},
                                             "upper": {"numerator": upper, "denominator": 100}}}


class MachineFrontierTests(unittest.TestCase):
    def test_uncertain_overlap_cannot_prove_probability_dominance(self):
        self.assertFalse(frontier.dominates(cell(40, 60, 1), cell(50, 55, 2)))

    def test_strict_resource_improvement_with_certified_probability_order(self):
        self.assertTrue(frontier.dominates(cell(60, 70, 1), cell(40, 60, 2)))

    def test_one_more_expensive_dimension_prevents_dominance(self):
        a, b = cell(80, 90, 1), cell(40, 50, 2)
        a["resources"]["planned_input_bytes"] = 3
        self.assertFalse(frontier.dominates(a, b))

    def test_identical_exact_cell_does_not_dominate_itself(self):
        a = cell(50, 50)
        self.assertFalse(frontier.dominates(a, deepcopy(a)))

    def test_refusal_is_retained_for_each_predeclared_grid_cell(self):
        with patch.object(frontier, "build_machine_envelope", side_effect=ValueError("DECLARED_CAP")) as build:
            baseline = example()
            report = frontier.compare(frontier.enumerate_domain(fixture(nonce_bits=1)),
                baseline.classical, baseline.physical_models[1], illustrative_lifecycle_model())
        self.assertEqual(build.call_count, 18)
        self.assertEqual(report["planned_cells"], report["observed_model_cells"])
        self.assertEqual(report["undominated_with_certified_interval_order"], [])
        self.assertTrue(all(row["reason"] == "DECLARED_CAP" for row in report["cells"]))
        self.assertEqual(report["declared_grid"]["horizon_seconds"], "4")
        self.assertFalse(report["claims"]["same_total_economic_budget_proved"])
        self.assertFalse(report["claims"]["minimum_attacker_cost_proved"])
        self.assertFalse(report["native_shape"])
        self.assertIn("reduced-shape", report["comparison_scope"]["domain"])
        self.assertEqual(report["common_model_premises"]["classical_costs_ns"]["per_winner_proof_ns"],
                         baseline.classical.per_winner_proof_ns)


if __name__ == "__main__":
    unittest.main()
