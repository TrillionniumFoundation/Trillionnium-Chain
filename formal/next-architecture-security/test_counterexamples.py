"""Independent hand witnesses and exhaustive toy sampler controls."""
from contextlib import redirect_stdout
from fractions import Fraction as F
import io
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import counterexamples as C


class ResourceControls(unittest.TestCase):
    def test_timed_product_has_exact_degree_two_counterexample(self):
        self.assertEqual(C.homogeneity_pair("timed_product", (F(2), F(2), F(3)), F(2)),
                         (F(24), F(12)))

    def test_sum_of_squares_has_independent_hand_counterexample(self):
        self.assertEqual(C.homogeneity_pair("timed_sum_squares", (F(2), F(2), F(3)), F(2)),
                         (F(52), F(26)))

    def test_static_capacity_is_not_scaled_with_work(self):
        state = (F(2), F(2), F(3))
        self.assertEqual(C.homogeneity_pair("static_multiplier", state, F(2)), (F(8), F(8)))
        self.assertEqual(C.homogeneity_pair("static_additive_bonus", state, F(2)), (F(6), F(8)))
        self.assertEqual(C.homogeneity_pair("timed_product", state, F(1, 2)), (F(3, 2), F(3)))

    def test_fractional_and_zero_boundaries_remain_exact(self):
        state = (F(0), F(1, 3), F(1, 2))
        self.assertEqual(C.homogeneity_pair("timed_sum", state, F(3, 2)), (F(5, 4), F(5, 4)))
        self.assertEqual(C.homogeneity_pair("timed_bottleneck", state, F(3, 2)), (F(1, 2), F(1, 2)))
        self.assertEqual(C.weight("timed_bottleneck", F(1), F(0), F(3)), 0)

    def test_no_expression_evaluation_or_silent_numeric_coercion(self):
        with self.assertRaisesRegex(ValueError, "UNKNOWN_FIXED_CANDIDATE"):
            C.weight("W * U", F(1), F(1), F(1))
        for bad in (True, 1, 0.5, "1/2", F(-1)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                C.weight("timed_sum", F(1), bad, F(1))
        for bad in (F(0), F(-1), True, 2.0):
            with self.subTest(alpha=bad), self.assertRaises(ValueError):
                C.homogeneity_pair("timed_sum", (F(1), F(1), F(1)), bad)

    def test_finite_grid_results_retain_exact_scope_and_all_cases(self):
        self.assertEqual((len(C.STATES), len(set(C.STATES))), (125, 125))
        records = {r["candidate"]: r for r in C.report()["candidate_checks"]}
        rejected = {name for name, r in records.items()
                    if r["homogeneity"]["status"] == "COUNTEREXAMPLE_FOUND"}
        self.assertEqual(rejected, {"timed_product", "timed_sum_squares", "static_additive_bonus"})
        for record in records.values():
            self.assertEqual(record["homogeneity"]["comparisons"], 375)
            self.assertEqual(record["coordinatewise_monotonicity"]["comparisons"], 375)
            self.assertEqual(record["coordinatewise_monotonicity"]["counterexamples"], 0)
            self.assertEqual(record["real_resource_interpretation"], "UNKNOWN")
            self.assertEqual(record["security_qualification"], "HOLD_NO_GO")


class SamplerControls(unittest.TestCase):
    def test_eight_element_witness_matches_independent_enumeration(self):
        for replacement, samples, expected in (
            (True, list(itertools.product(range(8), repeat=3)), F(1, 8)),
            (False, list(itertools.permutations(range(8), 3)), F(1, 14)),
        ):
            counted = F(sum(all(x < 4 for x in row) for row in samples), len(samples))
            self.assertEqual(counted, expected)
            self.assertEqual(C.subset_probability(8, 4, 3, replacement=replacement), counted)
        self.assertEqual(C.sampling_report(8, 4, 3)["understatement_if_distinct_bound_substituted"],
                         "3/56")

    def test_repetition_can_hit_more_times_than_subset_cardinality(self):
        self.assertEqual(C.subset_probability(8, 2, 3, replacement=True), F(1, 64))
        self.assertEqual(C.subset_probability(8, 2, 3, replacement=False), 0)

    def test_empty_event_and_full_or_empty_subsets(self):
        for replacement in (True, False):
            self.assertEqual(C.subset_probability(4, 0, 0, replacement=replacement), 1)
            self.assertEqual(C.subset_probability(4, 0, 3, replacement=replacement), 0)
            self.assertEqual(C.subset_probability(4, 4, 3, replacement=replacement), 1)

    def test_invalid_sampling_models_are_not_converted_to_zero_probability(self):
        with self.assertRaisesRegex(ValueError, "DISTINCT_DRAWS_EXCEED_POPULATION"):
            C.subset_probability(2, 1, 3, replacement=False)
        for n, b, q, replacement in (
            (True, 1, 1, True), (0, 0, 1, True), (2**32 + 1, 1, 1, True),
            (8, -1, 3, True), (8, 9, 3, True), (8, True, 3, True),
            (8, 4, 3.0, True), (8, 4, -1, True), (8, 4, 129, True), (8, 4, 3, 1),
        ):
            with self.subTest(parameters=(n, b, q, replacement)), self.assertRaises(ValueError):
                C.subset_probability(n, b, q, replacement=replacement)

    def test_small_domain_direction_and_strictness(self):
        for n in range(1, 9):
            for b in range(n + 1):
                for q in range(n + 1):
                    repeated = C.subset_probability(n, b, q, replacement=True)
                    distinct = C.subset_probability(n, b, q, replacement=False)
                    self.assertGreaterEqual(repeated, distinct)
                    self.assertEqual(repeated > distinct, 0 < b < n and q >= 2)


class EvidenceControls(unittest.TestCase):
    def test_retained_fixture_matches_exact_generator_bytes(self):
        self.assertEqual(C.FIXTURE.read_bytes(), C.report_bytes())

    def test_no_security_admission_or_cross_backend_inheritance(self):
        report = C.report()
        qualification = report["qualification"]
        for flag in ("consensus_admission", "production_qualified", "chainweight_changed",
                     "physical_cost_model_qualified", "complete_qrom_proof",
                     "universal_property_proved_by_finite_grid", "actual_sampler_distribution_qualified"):
            self.assertIs(qualification[flag], False)
        self.assertIsNone(qualification["security_bits_quantum"])
        items = report["risc0_obligations"]["items"]
        self.assertEqual((len(items), len({x["id"] for x in items})), (15, 15))
        self.assertTrue(all(item["status"] == "OPEN" for item in items))
        self.assertEqual(report["risc0_obligations"]["obligations_closed_by_this_checker"], 0)
        self.assertIs(report["plonky3_inherits_risc0_proof_or_profile_specific_obligations"], False)
        self.assertIsNone(report["sampling"]["actual_risc0_reference"]["actual_outer_domain_size"])

    def test_cli_reproduces_retained_report_and_checks_fixture(self):
        script = str(C.HERE / "counterexamples.py")
        generated = subprocess.run([sys.executable, "-B", script], capture_output=True, check=True)
        self.assertEqual(generated.stdout, C.FIXTURE.read_bytes())
        checked = subprocess.run([sys.executable, "-B", script, "--check-fixture"],
                                 capture_output=True, check=True)
        self.assertIs(json.loads(checked.stdout)["fixture_matches"], True)

    def test_corrupt_and_missing_fixtures_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            for data in (None, b'{"consensus_admission": true}\n'):
                if data is not None:
                    path.write_bytes(data)
                output = io.StringIO()
                with patch.object(C, "FIXTURE", path), redirect_stdout(output):
                    self.assertEqual(C.main(["--check-fixture"]), 1)
                result = json.loads(output.getvalue())
                self.assertIs(result["fixture_matches"], False)
                self.assertIs(result["consensus_admission"], False)


if __name__ == "__main__":
    unittest.main()
