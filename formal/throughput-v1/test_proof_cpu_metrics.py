"""Adversarial checks for pinned historical proof CPU accounting."""

from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import proof_cpu_metrics as metrics


EVIDENCE = Path(__file__).resolve().parents[2] / "evidence/pon-throughput-20261108/proof-cpu"


class ProofCpuMetricsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.texts = {name: (EVIDENCE / "originals" / name).read_text()
                     for name in metrics.PINNED_BLOBS}
        cls.manifest = metrics.load_json(cls.texts["manifest.json"])
        cls.summary = metrics.load_json(cls.texts["summary.json"])

    def analyze(self, manifest=None, summary=None, resources=None):
        return metrics.analyze_records(
            manifest if manifest is not None else deepcopy(self.manifest),
            summary if summary is not None else deepcopy(self.summary),
            resources if resources is not None else dict(self.texts),
        )

    def test_exact_published_corpus_reproduces_cpu_and_keeps_tps_unknown(self):
        report = metrics.build_report(EVIDENCE)
        self.assertEqual(report["result"], "COMPLETE_HISTORICAL_READBACK")
        self.assertEqual(report["source"]["blobs_verified"], 10)
        self.assertEqual(report["analysis"]["completed_count"], 8)
        self.assertEqual(report["analysis"]["source_reported_distinct_fixture_identities"], 2)
        b_rows = [row for row in report["analysis"]["rows"] if row["variant"] == "B"]
        self.assertEqual([row["verifier_cpu_seconds"] for row in b_rows],
                         ["2.43", "2.29", "2.56", "2.2"])
        expected = {"all": {"A": "5.93", "B": "2.36"},
                    "retained": {"A": "6.04", "B": "2.36"},
                    "dense": {"A": "5.915", "B": "2.38"}}
        for case, arms in expected.items():
            for arm, value in arms.items():
                self.assertEqual(report["analysis"]["cohorts"][case][arm]["verifier_cpu_seconds_median"], value)
        self.assertEqual(report["budget_comparison"]["tagged_completed_verifier_cpu_seconds_median"], "2.36")
        self.assertIsNone(report["qualified_tps"])
        self.assertIsNone(report["budget_comparison"]["extrapolated_wall_seconds"])
        self.assertIsNone(report["budget_comparison"]["universal_cpu_lower_bound"])
        self.assertEqual(report["fresh_proof_executions"], 0)
        self.assertFalse(report["original_resource_contract_replayed"])
        self.assertEqual(report["qualification"], "HOLD_NO_GO")
        self.assertFalse(report["combination_obligation"]["multiply_historical_speedups"])

    def test_resolved_merge_and_published_commit_are_not_relabelled(self):
        report = metrics.build_report(EVIDENCE)
        source = report["analysis"]["historical_measurement_source"]
        self.assertEqual(source["head"], "cfef87ff6e09f998cb8fc5d3165fce8ac9eb2da1")
        self.assertEqual(source["merge_head"], "09fbc0f45151a68a1bf205641171840fbf309882")
        self.assertNotEqual(source["head"], report["source"]["published_evidence_commit"])

    def test_tampered_receipt_cannot_repin_itself(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copytree(EVIDENCE / "originals", root / "originals")
            path = root / "originals/01-retained-B.resource.txt"
            path.write_text(path.read_text().replace("2.32", "0.02"))
            (root / "source-index.json").write_text(json.dumps({"sha256": "self-declared"}))
            report = metrics.build_report(root)
        self.assertEqual(report["result"], "INCOMPLETE_OR_INVALID_READBACK")
        self.assertEqual(report["planned_attempts"], 8)
        row = report["analysis"]["rows"][1]
        self.assertIsNone(row["verifier_cpu_seconds"])
        self.assertEqual(row["stage_outcomes"]["verify"]["exit_code"], 0)
        self.assertEqual(report["analysis"]["cohorts"]["all"]["B"]["planned_count"], 4)
        self.assertEqual(report["analysis"]["cohorts"]["all"]["B"]["completed_count"], 3)
        self.assertIsNone(report["budget_comparison"]["median_exceeds_nominal_one_cpu_second"])

    def test_missing_receipt_is_unknown_not_zero(self):
        resources = dict(self.texts)
        del resources["02-retained-B.resource.txt"]
        result = self.analyze(resources=resources)
        row = result["rows"][2]
        self.assertIsNone(row["verifier_cpu_seconds"])
        self.assertIsNone(row["resource_exit_code"])
        group = result["cohorts"]["retained"]["B"]
        self.assertEqual(group["planned_count"], 2)
        self.assertEqual(group["cpu_observed_count"], 1)
        self.assertEqual(group["completed_count"], 1)

    def test_missing_manifest_keeps_eight_unknown_slots(self):
        with tempfile.TemporaryDirectory() as temp:
            report = metrics.build_report(Path(temp))
        self.assertEqual(report["result"], "INCOMPLETE_OR_INVALID_READBACK")
        self.assertEqual(len(report["analysis"]["rows"]), 8)
        self.assertEqual(report["analysis"]["completed_count"], 0)
        self.assertIsNone(report["source_declared_distinct_input_tasks"])
        self.assertIsNone(report["analysis"]["source_reported_distinct_fixture_identities"])
        self.assertTrue(all(row["verifier_cpu_seconds"] is None for row in report["analysis"]["rows"]))

    def test_missing_run_keeps_original_plan_and_unknown_exit(self):
        manifest = deepcopy(self.manifest)
        manifest["runs"].pop(2)
        result = self.analyze(manifest=manifest)
        self.assertEqual(len(result["rows"]), 8)
        self.assertFalse(result["rows"][2]["record_present"])
        self.assertIsNone(result["rows"][2]["stage_outcomes"]["verify"]["exit_code"])
        self.assertEqual(result["cohorts"]["all"]["B"]["planned_count"], 4)
        self.assertEqual(result["cohorts"]["all"]["B"]["completed_count"], 3)

    def test_duplicate_record_does_not_increase_completion_count(self):
        manifest = deepcopy(self.manifest)
        manifest["runs"].append(deepcopy(manifest["runs"][1]))
        result = self.analyze(manifest=manifest)
        self.assertEqual(result["record_count"], 9)
        self.assertEqual(len(result["rows"]), 8)
        self.assertIn("duplicate record index", result["rows"][1]["issues"])
        self.assertEqual(result["completed_count"], 7)

    def test_wrong_case_or_variant_is_not_reclassified(self):
        manifest = deepcopy(self.manifest)
        manifest["runs"][1]["variant"] = "A"
        result = self.analyze(manifest=manifest)
        self.assertIn("case or variant mismatch", result["rows"][1]["issues"])
        self.assertEqual(result["cohorts"]["all"]["B"]["planned_count"], 4)
        self.assertEqual(result["cohorts"]["all"]["A"]["planned_count"], 4)

    def test_unplanned_record_is_retained_as_error(self):
        manifest = deepcopy(self.manifest)
        extra = deepcopy(manifest["runs"][0])
        extra["index"] = 8
        manifest["runs"].append(extra)
        result = self.analyze(manifest=manifest)
        self.assertEqual(result["unexpected_record_positions"], [8])
        self.assertEqual(result["record_count"], 9)
        self.assertEqual(len(result["rows"]), 8)
        self.assertTrue(result["issues"])

    def test_failed_verifier_cpu_is_retained_but_excluded_from_success_median(self):
        manifest = deepcopy(self.manifest)
        manifest["runs"][1]["stages"]["verify"]["exit_code"] = 1
        resources = dict(self.texts)
        name = "01-retained-B.resource.txt"
        resources[name] = resources[name].replace("Exit status: 0", "Exit status: 1")
        result = self.analyze(manifest=manifest, resources=resources)
        row = result["rows"][1]
        self.assertEqual(row["stage_outcomes"]["verify"]["exit_code"], 1)
        self.assertEqual(row["resource_exit_code"], 1)
        self.assertEqual(row["verifier_cpu_seconds"], Decimal("2.43"))
        self.assertFalse(row["eligible_completed_observation"])
        self.assertEqual(result["cohorts"]["all"]["B"]["cpu_observed_count"], 4)
        self.assertEqual(result["cohorts"]["all"]["B"]["completed_count"], 3)

    def test_timeout_and_unknown_timeout_remain_distinct(self):
        for timeout in (True, None):
            with self.subTest(timeout=timeout):
                manifest = deepcopy(self.manifest)
                manifest["runs"][1]["stages"]["verify"]["timeout"] = timeout
                row = self.analyze(manifest=manifest)["rows"][1]
                self.assertIs(row["stage_outcomes"]["verify"]["timeout"], timeout)
                self.assertFalse(row["eligible_completed_observation"])

    def test_boolean_false_is_not_a_success_exit_code(self):
        manifest = deepcopy(self.manifest)
        manifest["runs"][1]["stages"]["verify"]["exit_code"] = False
        row = self.analyze(manifest=manifest)["rows"][1]
        self.assertIsNone(row["stage_outcomes"]["verify"]["exit_code"])
        self.assertFalse(row["eligible_completed_observation"])

    def test_signal_with_gnu_time_exit_zero_is_not_success(self):
        resources = dict(self.texts)
        name = "01-retained-B.resource.txt"
        resources[name] += "Command terminated by signal 9\n"
        row = self.analyze(resources=resources)["rows"][1]
        self.assertEqual(row["resource_exit_code"], 0)
        self.assertEqual(row["resource_signal_observations"], ["Command terminated by signal 9"])
        self.assertFalse(row["eligible_completed_observation"])

    def test_nonzero_exit_diagnostic_overrides_contradictory_printed_zero(self):
        resources = dict(self.texts)
        name = "01-retained-B.resource.txt"
        resources[name] += "Command exited with non-zero status 9\n"
        row = self.analyze(resources=resources)["rows"][1]
        self.assertEqual(row["resource_exit_code"], 0)
        self.assertEqual(row["verifier_cpu_seconds"], Decimal("2.43"))
        self.assertEqual(row["resource_nonzero_exit_observations"],
                         ["Command exited with non-zero status 9"])
        self.assertFalse(row["eligible_completed_observation"])

    def test_nonstring_argv_is_invalid_without_attribute_error(self):
        manifest = deepcopy(self.manifest)
        manifest["runs"][1]["stages"]["verify"]["argv"][2] = 123
        row = self.analyze(manifest=manifest)["rows"][1]
        self.assertFalse(row["eligible_completed_observation"])
        self.assertIsNone(row["verifier_cpu_seconds"])
        self.assertIn("verifier argv not bound to campaign binary", row["issues"])

    def test_malformed_nested_objects_raise_controlled_value_error(self):
        for field in ("fixtures", "binaries"):
            with self.subTest(field=field):
                manifest = deepcopy(self.manifest)
                manifest["source_before"][field] = []
                with self.assertRaisesRegex(ValueError, "expected an object"):
                    self.analyze(manifest=manifest)
        summary = deepcopy(self.summary)
        summary["observed_medians"]["all"] = []
        with self.assertRaisesRegex(ValueError, "expected an object"):
            self.analyze(summary=summary)
        with self.assertRaisesRegex(ValueError, "expected an object"):
            metrics.analyze_records([], self.summary, self.texts)

    def test_extreme_decimal_and_duration_are_bounded_before_arithmetic(self):
        for value in (Decimal("1e999999999"), Decimal("1e-999999999"), Decimal("86401")):
            with self.subTest(value=str(value)):
                manifest = deepcopy(self.manifest)
                manifest["runs"][1]["stages"]["verify"]["outer_wall_s"] = value
                row = self.analyze(manifest=manifest)["rows"][1]
                self.assertIsNone(row["verifier_wall_seconds"])
                self.assertFalse(row["eligible_completed_observation"])

    def test_declared_counts_require_integer_json_types(self):
        for field in ("fresh_full_proofs_planned", "completed_full_proofs", "distinct_input_tasks"):
            with self.subTest(field=field):
                manifest = deepcopy(self.manifest)
                manifest[field] = Decimal(str(manifest[field]) + ".0")
                self.assertTrue(self.analyze(manifest=manifest)["issues"])
        for field in ("completed_full_proofs", "distinct_input_tasks"):
            with self.subTest(summary_field=field):
                summary = deepcopy(self.summary)
                summary[field] = Decimal(str(summary[field]) + ".0")
                self.assertTrue(self.analyze(summary=summary)["issues"])
        summary = deepcopy(self.summary)
        summary["observed_medians"]["all"]["B"]["count"] = Decimal("4.0")
        self.assertTrue(self.analyze(summary=summary)["issues"])

    def test_receipt_from_another_run_fails_command_binding(self):
        resources = dict(self.texts)
        resources["01-retained-B.resource.txt"] = resources["02-retained-B.resource.txt"]
        row = self.analyze(resources=resources)["rows"][1]
        self.assertIsNone(row["verifier_cpu_seconds"])
        self.assertTrue(any("command differs" in value for value in row["issues"]))

    def test_cpu_parse_rejects_missing_duplicate_negative_and_nonfinite_fields(self):
        original = self.texts["01-retained-B.resource.txt"]
        argv = self.manifest["runs"][1]["stages"]["verify"]["argv"]
        replacements = [
            original.replace("User time (seconds): 2.32", "Missing user time"),
            original + "\tUser time (seconds): 2.32\n",
            original.replace("User time (seconds): 2.32", "User time (seconds): -2.32"),
            original.replace("User time (seconds): 2.32", "User time (seconds): NaN"),
            original.replace("System time (seconds): 0.11", "System time (seconds): Infinity"),
        ]
        for text in replacements:
            with self.subTest(receipt=text[-80:]):
                with self.assertRaises(ValueError):
                    metrics.parse_resource(text, argv)

    def test_summary_tampering_is_detected_by_recomputed_median(self):
        manifest = deepcopy(self.manifest)
        summary = deepcopy(self.summary)
        for target in (manifest, summary):
            target["observed_medians"]["all"]["B"]["verify_outer_s"] = Decimal("0.01")
        result = self.analyze(manifest=manifest, summary=summary)
        self.assertTrue(any("summary median disagreement" in value for value in result["issues"]))
        self.assertEqual(result["cohorts"]["all"]["B"]["verifier_wall_seconds_median"], "0.544260107")

    def test_pipeline_does_not_substitute_one_fast_phase(self):
        manifest = deepcopy(self.manifest)
        manifest["runs"][1]["pipeline_outer_s"] = manifest["runs"][1]["stages"]["verify"]["outer_wall_s"]
        row = self.analyze(manifest=manifest)["rows"][1]
        self.assertIn("pipeline wall differs from sum of recorded stages", row["issues"])
        self.assertFalse(row["eligible_completed_observation"])

    def test_source_change_invalidates_completed_observations(self):
        manifest = deepcopy(self.manifest)
        manifest["source_after"]["binaries"]["B"]["sha256"] = "0" * 64
        result = self.analyze(manifest=manifest)
        self.assertFalse(result["source_snapshots_consistent"])
        self.assertEqual(result["completed_count"], 0)
        self.assertEqual(result["cohorts"]["all"]["B"]["cpu_observed_count"], 4)

    def test_same_fixture_is_not_two_distinct_inputs(self):
        manifest = deepcopy(self.manifest)
        for field in ("source_before", "source_after"):
            fixtures = manifest[field]["fixtures"]
            fixtures["dense"]["input"]["sha256"] = fixtures["retained"]["input"]["sha256"]
        result = self.analyze(manifest=manifest)
        self.assertEqual(result["source_reported_distinct_fixture_identities"], 1)
        self.assertIn("two distinct input-fixture identities are not established", result["issues"])

    def test_json_rejects_duplicate_keys_and_nonfinite_numbers(self):
        for text in ('{"count":8,"count":1}', '{"time":NaN}', '{"time":Infinity}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                metrics.load_json(text)

    def test_symlink_is_not_promoted_to_original_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "originals").symlink_to(EVIDENCE / "originals", target_is_directory=True)
            texts, index, issues = metrics.read_pinned_sources(root)
        self.assertFalse(texts)
        self.assertEqual(len(issues), 10)
        self.assertTrue(all(row["status"] == "invalid" for row in index))


if __name__ == "__main__":
    unittest.main()
