#!/usr/bin/env python3
"""Original retained costs and missing useful-task qualification stay separate."""
import copy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import cell_model_metrics as cell
import useful_task_metrics as useful

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "evidence/pon-throughput-20261108/cell-model/input-manifest.json"
MANIFEST_SHA = "9e3c64afcd03bb17ac8746d1146a98c78d214000ccaf71ed2aed0ea96a6a3d25"


class RetainedWorkObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_manifest, cls.original_raw = cell.load_bundle(FIXTURE, MANIFEST_SHA)

    def setUp(self):
        self.manifest = copy.deepcopy(self.original_manifest)
        self.raw = dict(self.original_raw)

    def change_and_repin(self, name, change):
        value = json.loads(self.raw[name])
        change(value)
        raw = (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()
        self.raw[name] = raw
        self.manifest["files"][name]["sha256"] = hashlib.sha256(raw).hexdigest()
        self.manifest["files"][name]["git_blob_sha1"] = hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

    def project(self):
        return useful.project_records(self.manifest, self.raw)

    def test_original_costs_and_all_retained_command_outcomes_are_present(self):
        result = self.project()
        self.assertEqual(result["raw_file_count"], 44)
        self.assertEqual(result["commands"]["retained_command_slots"], 18)
        self.assertEqual(result["commands"]["return_code_counts"], {"returned-zero": 16, "returned-nonzero": 2})
        self.assertEqual(result["training"]["retained_training_receipt_slots"], 3)
        self.assertEqual(result["training"]["retained_stage_slots"], 25)
        self.assertEqual(result["training"]["stage_cpu_ns"]["sum_known"], 130011484774)
        failed = next(row for row in result["commands"]["rows"] if row["kind"] == "failed-release-acquisition")
        self.assertEqual(failed["returncode"], 1)
        self.assertEqual(Fraction(**failed["reported_elapsed_seconds"]), Fraction("2.049700966999808"))
        self.assertIsNone(failed["full_process_family_cpu_ns"])

    def test_two_model_arms_and_correct_answers_do_not_create_useful_tasks(self):
        result = self.project()
        self.assertEqual(result["model_scoring"]["retained_forward_records"], 64)
        self.assertEqual(result["model_scoring"]["distinct_fixture_request_labels"], 32)
        self.assertEqual(result["model_scoring"]["component_metrics"]["selection_outcome"], "no-update")
        for name in ("unique_independently_accepted_tasks", "tasks_per_second", "common_window_ns", "global_planned_attempts"):
            self.assertIsNone(result["useful_task_throughput"][name])
        self.assertEqual(result["useful_task_throughput"]["unknown_reasons"]["independent_acceptance"],
                         "INDEPENDENT_FUTURE_TASK_ACCEPTANCE_NOT_SUPPLIED")
        self.assertIsNone(result["model_scoring"]["independent_future_task_acceptance"])
        self.assertIsNone(result["model_scoring"]["old_capability_retention"])
        self.assertIsNone(result["net_value"]["value"])

    def test_enclosing_intervals_and_missing_stages_cannot_complete_total_cost(self):
        result = self.project()
        self.assertFalse(result["training"]["enclosing_process_and_command_values_added_to_stage_sums"])
        self.assertIsNone(result["commands"]["combined_command_wall_seconds"])
        self.assertIsNone(result["commands"]["global_planned_attempts"])
        self.assertEqual(result["cost_coverage"]["proof"]["status"], "not_observed_in_supplied_corpus")
        self.assertEqual(result["cost_coverage"]["failed_cancelled_unpublished"]["status"], "partial")
        for key in ("cpu_ns", "gpu_ns", "wall_ns", "physical_network_bytes", "energy_joules", "money_minor"):
            self.assertIsNone(result["complete_task_cost"][key])

    def test_unchanged_pin_rejects_changed_raw_cost(self):
        name = useful.TRAINING[0]
        self.raw[name] = self.raw[name].replace(b'"cpu_ns":177109527', b'"cpu_ns":177109528')
        self.assertNotEqual(self.raw[name], self.original_raw[name])
        with self.assertRaisesRegex(ValueError, "FILE_SHA256"):
            self.project()

    def test_missing_failed_attempt_cannot_reduce_retained_denominator(self):
        self.raw.pop("failures/optimized-original/publisher-to-replica-command.json")
        with self.assertRaisesRegex(ValueError, "COMPLETE_RECORD_DENOMINATOR"):
            self.project()

    def test_reused_operation_label_never_erases_cost_or_establishes_task_identity(self):
        label = json.loads(self.raw[useful.TRAINING[0]])["operation_id"]
        self.change_and_repin(useful.TRAINING[1], lambda value: value.__setitem__("operation_id", label))
        def command(value):
            value["argv"][value["argv"].index("--operation-id") + 1] = label
        self.change_and_repin("training/gen2/command.json", command)
        result = self.project()
        self.assertEqual(result["training"]["distinct_declared_operation_ids"], 2)
        self.assertEqual(result["training"]["reused_operation_labels"], [label])
        self.assertEqual(result["training"]["retained_training_receipt_slots"], 3)
        self.assertEqual(result["training"]["stage_cpu_ns"]["sum_known"], 130011484774)
        self.assertIsNone(result["useful_task_throughput"]["unique_independently_accepted_tasks"])

    def test_missing_io_retains_partial_cost_and_does_not_become_observed_zero(self):
        self.change_and_repin(useful.TRAINING[0], lambda value: value["cost_events"][0].__setitem__("bytes_read", None))
        result = self.project()
        amount = result["training"]["stage_read_bytes"]
        self.assertEqual((amount["retained_slots"], amount["known_slots"], amount["unknown_slots"]), (25, 24, 1))
        self.assertGreater(amount["sum_known"], 0)
        self.assertIsNone(amount["complete_arithmetic_sum"])
        self.assertIsNone(result["training"]["rows"][0]["stages"][0]["bytes_read"])

    def test_unobserved_values_and_observed_zero_have_different_aggregates(self):
        self.assertEqual(useful.reported_sum([0, 0], "ns")["complete_arithmetic_sum"], 0)
        mixed = useful.reported_sum([0, None], "ns")
        self.assertEqual(mixed["sum_known"], 0)
        self.assertIsNone(mixed["complete_arithmetic_sum"])
        self.assertIsNone(useful.reported_sum([None], "ns")["sum_known"])
        self.assertIsNone(useful.reported_sum([], "ns")["complete_arithmetic_sum"])

    def test_self_declared_independent_acceptance_is_not_an_input_extension(self):
        self.raw["independent-acceptance.json"] = b'{"accepted":true}'
        with self.assertRaisesRegex(ValueError, "COMPLETE_RECORD_DENOMINATOR"):
            self.project()
        self.raw = dict(self.original_raw)
        self.change_and_repin(useful.RESEARCH, lambda value: value["authority"].__setitem__("independent_accepted", True))
        with self.assertRaisesRegex(ValueError, "AUTHORITY_ESCALATION"):
            self.project()

    def test_every_observed_cost_has_original_byte_and_pointer_provenance(self):
        result = self.project()
        origins = [row["origin"] for row in result["commands"]["rows"]]
        origins += [row["origin"] for row in result["model_scoring"]["rows"]]
        origins += [stage["origin"] for row in result["training"]["rows"] for stage in row["stages"]]
        self.assertEqual(len(origins), 107)
        for source in origins:
            self.assertTrue(source["source_path"].startswith(cell.PREFIX))
            self.assertEqual(len(source["sha256"]), 64)
            self.assertEqual(len(source["git_blob_sha1"]), 40)
        self.assertFalse(result["clock_or_meter_authenticated"])
        self.assertEqual(result["fresh_executions_by_reader"], 0)
        self.assertEqual(result["qualification"], "HOLD_NO_GO")
        self.assertFalse(result["production_activation"])

    def test_cli_valid_hold_and_bad_pin_have_distinct_exit_statuses(self):
        command = [sys.executable, "-B", str(Path(useful.__file__)), "--manifest", str(FIXTURE), "--manifest-sha256"]
        good = subprocess.run([*command, MANIFEST_SHA], capture_output=True, timeout=30)
        self.assertEqual(good.returncode, 1, good.stderr)
        output = json.loads(good.stdout)
        self.assertEqual(output["input_manifest_sha256"], MANIFEST_SHA)
        self.assertEqual(output["qualification"], "HOLD_NO_GO")
        bad = subprocess.run([*command, "0" * 64], capture_output=True, timeout=30)
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(bad.stdout, b"")
        self.assertIn(b"MANIFEST_PIN", bad.stderr)

    def test_report_output_is_create_only_and_outside_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "readback.json"
            useful.write_report(path, "first\n")
            with self.assertRaises(FileExistsError):
                useful.write_report(path, "second\n")
            self.assertEqual(path.read_text(), "first\n")
        with self.assertRaisesRegex(ValueError, "OUTPUT_MUST_BE_OUTSIDE_SOURCE"):
            useful.write_report(ROOT / "not-created-useful-readback.json", "{}\n")


if __name__ == "__main__":
    unittest.main()
