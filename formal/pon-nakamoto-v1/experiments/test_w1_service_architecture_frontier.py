"""Predeclared denominator and complete-resource interval dominance controls."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import w1_service_architecture_frontier as frontier
from quantum_oracle_resources import example
from test_w1_quantum_oracle import fixture
from w1_machine_envelope import illustrative_lifecycle_model


def cell(lower, upper, cost=1):
    return {"status": "CONSTRUCTED_CONDITIONAL_MODEL",
        "resources": {key: cost for key in frontier.RESOURCE_FIELDS},
        "conditional_delivery_probability": {"lower": {"numerator": lower, "denominator": 100},
                                             "upper": {"numerator": upper, "denominator": 100}}}


class ArchitectureFrontierTests(unittest.TestCase):
    def test_uncertain_probability_overlap_does_not_prove_an_advantage(self):
        self.assertFalse(frontier.dominates(cell(40, 60, 1), cell(50, 55, 2)))

    def test_port_count_tradeoff_prevents_unpriced_free_parallelism(self):
        a, b = cell(80, 90, 1), cell(40, 50, 2)
        a["resources"]["initialization_service_ports"] = 3
        self.assertFalse(frontier.dominates(a, b))

    def test_fractional_reservation_times_use_exact_order(self):
        a, b = cell(80, 90, 1), cell(40, 50, 2)
        a["resources"]["physical_qubit_seconds_reserved"] = {"numerator": 5, "denominator": 3}
        self.assertTrue(frontier.dominates(a, b))
        a["resources"]["physical_qubit_seconds_reserved"] = {"numerator": 7, "denominator": 3}
        self.assertFalse(frontier.dominates(a, b))

    def test_identical_exact_resources_and_probability_do_not_dominate_self(self):
        exact = cell(50, 50)
        self.assertFalse(frontier.dominates(exact, deepcopy(exact)))

    def test_all_54_refused_cells_remain_with_original_limits_and_explicit_service_costs(self):
        domain = frontier.enumerate_domain(fixture(nonce_bits=1))
        baseline = example()
        with patch.object(frontier, "build_service_architecture", side_effect=ValueError("DECLARED_CAP")) as build:
            report = frontier.compare(domain, baseline.classical, baseline.physical_models[1],
                                      illustrative_lifecycle_model())
        self.assertEqual(build.call_count, 54)
        self.assertEqual(report["planned_cells"], 54)
        self.assertEqual(report["retained_cells"], 54)
        self.assertEqual(len(report["cells"]), 54)
        self.assertTrue(all(row["reason"] == "DECLARED_CAP" for row in report["cells"]))
        self.assertEqual(report["declared_grid"]["horizon_seconds"], "4")
        self.assertEqual(report["declared_grid"]["physical_qubit_budget"], 10**16)
        self.assertEqual(report["undominated_with_certified_interval_order"], [])
        self.assertEqual([row["initialization_ports"] for row in report["declared_grid"]["architectures"]], [1, 1024, 65536])
        self.assertTrue(all(row["patches_per_initialization_port"] > 0 for row in report["declared_grid"]["architectures"]))
        self.assertTrue(all(value is False for value in report["claims"].values()))


if __name__ == "__main__":
    unittest.main()
