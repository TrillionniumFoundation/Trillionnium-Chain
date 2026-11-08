#!/usr/bin/env python3
"""Pinned historical positives and adversarial evidence-reader controls."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

import cell_model_metrics as metrics

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "evidence/pon-throughput-20261108/cell-model"
MANIFEST_SHA = "9e3c64afcd03bb17ac8746d1146a98c78d214000ccaf71ed2aed0ea96a6a3d25"
RESEARCH = "actual/research-result.json"


class HistoricalProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_manifest, cls.original_records = metrics.load_bundle(FIXTURE / "input-manifest.json", MANIFEST_SHA)

    def setUp(self):
        self.manifest = copy.deepcopy(self.original_manifest)
        self.raw = dict(self.original_records)

    def change(self, name, edit):
        value = json.loads(self.raw[name])
        edit(value)
        self.raw[name] = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

    def project(self):
        return metrics.project(self.manifest, self.raw)

    def test_original_files_project_with_complete_explicit_denominators(self):
        result = self.project()
        self.assertEqual(result["raw_file_count"], 44)
        cell = result["cell_distribution"]
        self.assertEqual(cell["cohort"]["payload_bytes"], 272190131)
        self.assertEqual(cell["recorded_transfer_commands"], 3)
        self.assertEqual(cell["reported_complete_release_acquisitions"], 2)
        self.assertEqual(cell["controlled_refusals"], 1)
        self.assertEqual(cell["complete_consumer_member_readbacks"], 11)
        self.assertEqual(result["training_and_loading"]["recorded_training_rounds"], 3)
        self.assertEqual(result["earlier_failed_attempt"]["outcome"], "failed-optimized-transfer")

    def test_historical_180_second_cohort_does_not_upgrade_original_35_seconds(self):
        result = self.project()["cell_distribution"]
        self.assertEqual([v["original_overall_budget_ms"] for v in result["observations"]], [180000, 2000, 180000])
        self.assertIs(result["original_35_second_cohort_retested"], False)
        self.assertIsNone(result["independent_version_recovery_rate"])
        self.assertIsNone(result["complete_pipeline_MB_per_second"])
        self.assertIs(result["native_bytes_rehashed_by_this_reader"], False)

    def test_single_token_score_forwards_never_become_generated_token_rate(self):
        result = self.project()["model_compute"]
        self.assertEqual(result["selection_outcome"], "no-update")
        self.assertEqual(result["accuracy_difference"], {"numerator": 0, "denominator": 1})
        self.assertIsNone(result["actual_adoption_rate"])
        for row in result["models"].values():
            self.assertEqual((row["planned_requests"], row["observed_forwards"], row["correct"]), (32, 32, 16))
            self.assertIsNone(row["generated_tokens_per_second"])
            self.assertIsNone(row["generated_tokens"])
            self.assertIsNone(row["execution_latency_p99_nearest_rank_ns"])
            self.assertIsNone(row["first_response_from_cold_start_ns"])
            self.assertIs(row["population_tail_latency_qualified"], False)

    def test_real_training_stage_scopes_do_not_supply_cold_first_response_or_full_cost(self):
        result = self.project()["training_and_loading"]
        for row in result["rounds"]:
            self.assertEqual(row["reported_training_steps"], 10)
            stages = row["stage_projection"]
            self.assertIs(stages["complete_original_stage_roster"], True)
            self.assertGreater(stages["stage_costs"]["model-load"]["wall_ns"], 0)
            self.assertIsNone(stages["gpu_transfer_ns"])
            self.assertIsNone(stages["complete_model_loading_latency_ns"])
            self.assertIsNone(row["full_process_family_cpu_ns"])
            self.assertIsNone(row["complete_iteration_cost_minor"])

    def test_every_qualification_flag_remains_false(self):
        result = self.project()
        self.assertEqual(result["qualification"], "HOLD_NO_GO")
        for key in ("native_origin_authenticated", "source_execution_authenticated", "public_throughput_qualified",
                    "independent_provider_custody_qualified", "model_adoption_qualified", "production_activation"):
            self.assertIs(result[key], False)

    def test_wrong_cohort_cannot_reuse_success(self):
        self.manifest["expected_release"]["payload_bytes"] = 272189990
        with self.assertRaisesRegex(ValueError, "RELEASE_CONTEXT"):
            self.project()

    def test_incomplete_version_members_rejected(self):
        self.change(RESEARCH, lambda x: x["transport"]["members"].pop())
        with self.assertRaisesRegex(ValueError, "COMPLETE_VERSION_MEMBERS"):
            self.project()

    def test_duplicate_member_and_completion_marker_tamper_rejected(self):
        self.change(RESEARCH, lambda x: x["transport"]["members"].__setitem__(1, copy.deepcopy(x["transport"]["members"][0])))
        with self.assertRaisesRegex(ValueError, "DUPLICATE_MEMBER"):
            self.project()
        self.raw = dict(self.original_records)
        self.raw["actual/transport/replica-to-consumer.tcr1"] += b"x"
        with self.assertRaisesRegex(ValueError, "FETCH_RAW_BINDING"):
            self.project()

    def test_bad_tcr1_length_and_order_refused(self):
        original = self.raw["actual/transport/source-release.tcr1"]
        with self.assertRaisesRegex(ValueError, "TCR1_COVERAGE"):
            metrics.release_members(original + b"x")
        changed = original[:-64] + original[-32:] + original[-64:-32]
        with self.assertRaisesRegex(ValueError, "TCR1_ORDER"):
            metrics.release_members(changed)

    def test_boolean_and_decimal_count_aliases_refused(self):
        for alias in (False, 0.0, "0"):
            with self.subTest(alias=alias):
                self.raw = dict(self.original_records)
                self.change("actual/transport/publisher-to-replica.log", lambda x: x.__setitem__("cached_chunks", alias))
                self.change(RESEARCH, lambda x: x["transport"]["replica_acquisition"].__setitem__("cached_chunks", alias))
                with self.assertRaisesRegex(ValueError, "FETCH_INTEGER"):
                    self.project()

    def test_native_returncode_alias_refused(self):
        self.change("actual/transport/publisher-to-replica-command.json", lambda x: x.__setitem__("returncode", False))
        with self.assertRaisesRegex(ValueError, "COMMAND_EXIT"):
            self.project()

    def test_native_command_cannot_be_replaced_by_successful_probe(self):
        self.change("actual/transport/publisher-to-replica-command.json", lambda x: x["argv"].__setitem__(1, "probe"))
        with self.assertRaisesRegex(ValueError, "TRANSFER_COMMAND"):
            self.project()

    def test_original_budget_cannot_be_silently_changed(self):
        def edit(value):
            value["argv"][value["argv"].index("--overall-ms") + 1] = "35000"
        self.change("actual/transport/publisher-to-replica-command.json", edit)
        with self.assertRaisesRegex(ValueError, "ORIGINAL_TRANSFER_BUDGET"):
            self.project()

    def test_duplicate_or_misplaced_member_destination_cannot_complete_version(self):
        original = json.loads(self.raw[RESEARCH])["transport"]["members"][0]["destination"]
        for destination in (original, "/another/directory/config.json"):
            with self.subTest(destination=destination):
                self.raw = dict(self.original_records)
                self.change(RESEARCH, lambda x: x["transport"]["members"][1].__setitem__("destination", destination))
                def edit(value):
                    value["argv"][value["argv"].index("--output") + 1] = destination
                self.change("actual/transport/materialize-1-command.json", edit)
                with self.assertRaisesRegex(ValueError, "MATERIALIZATION_DESTINATION"):
                    self.project()

    def test_transfer_peers_are_bound_to_original_provider_role(self):
        for name in metrics.TRANSFERS:
            with self.subTest(command=name):
                self.raw = dict(self.original_records)
                def edit(value):
                    value["argv"][value["argv"].index("--peers") + 1] = "127.0.0.1:1"
                self.change(f"actual/transport/{name}-command.json", edit)
                with self.assertRaisesRegex(ValueError, "TRANSFER_PEER_ROLE"):
                    self.project()

    def test_materialization_must_read_the_acquired_consumer_cache(self):
        def edit(value):
            value["argv"][value["argv"].index("--store") + 1] = "/another/cache.sqlite"
        self.change("actual/transport/materialize-1-command.json", edit)
        with self.assertRaisesRegex(ValueError, "CONSUMER_CACHE_BINDING"):
            self.project()

    def test_signalled_negative_command_is_not_normal_transport_refusal(self):
        self.change("actual/transport/offline-publisher-negative-command.json", lambda x: x.__setitem__("returncode", -9))
        self.change(RESEARCH, lambda x: x["transport"]["offline_publisher_negative"].__setitem__("returncode", -9))
        with self.assertRaisesRegex(ValueError, "OFFLINE_REFUSAL"):
            self.project()

    def test_incomplete_or_duplicate_forward_denominator_rejected(self):
        self.change(RESEARCH, lambda x: x["raw_forward_observations"].pop())
        with self.assertRaisesRegex(ValueError, "COMPLETE_FORWARD_DENOMINATOR"):
            self.project()
        self.raw = dict(self.original_records)
        self.change(RESEARCH, lambda x: x["raw_forward_observations"].__setitem__(1, copy.deepcopy(x["raw_forward_observations"][0])))
        with self.assertRaisesRegex(ValueError, "FORWARD_REQUEST"):
            self.project()

    def test_wrong_request_model_profile_and_clock_refused(self):
        for key, bad in (("input_sha256", "f" * 64), ("artifact", "f" * 64),
                         ("profile", "greedy-token-decode"), ("execution_ns", True)):
            with self.subTest(key=key):
                self.raw = dict(self.original_records)
                self.change(RESEARCH, lambda x: x["raw_forward_observations"][0]["observation"].__setitem__(key, bad))
                with self.assertRaises(ValueError):
                    self.project()

    def test_relabelled_adoption_and_fake_quality_rejected(self):
        self.change(RESEARCH, lambda x: x.__setitem__("decision", "adopted"))
        with self.assertRaisesRegex(ValueError, "RESEARCH_SCOPE"):
            self.project()
        self.raw = dict(self.original_records)
        self.change(RESEARCH, lambda x: x.__setitem__("candidate_correct", 32))
        with self.assertRaisesRegex(ValueError, "CORRECT_COUNT"):
            self.project()

    def test_native_authority_and_termination_flags_not_coerced(self):
        for field, bad in (("hepta_final_use", True), ("hepta_final_use", 0)):
            self.raw = dict(self.original_records)
            self.change(RESEARCH, lambda x: x["authority"].__setitem__(field, bad))
            with self.assertRaisesRegex(ValueError, "AUTHORITY_ESCALATION"):
                self.project()
        self.raw = dict(self.original_records)
        self.change(RESEARCH, lambda x: x["transport"]["publisher"].__setitem__("stopped", 1))
        with self.assertRaisesRegex(ValueError, "PEER_TERMINATION_RECORD"):
            self.project()

    def test_partial_stage_prefix_never_becomes_complete_load_metric(self):
        receipt = json.loads(self.raw["training/gen2/actual-receipt.json"])
        result = metrics.stage_metrics(receipt["cost_events"][:3], 2)
        self.assertIs(result["complete_original_stage_roster"], False)
        self.assertIsNone(result["stage_costs"])
        self.assertIsNone(result["complete_model_loading_latency_ns"])

    def test_failed_or_duplicate_stage_preserves_failure(self):
        receipt = json.loads(self.raw["training/gen2/actual-receipt.json"])
        events = copy.deepcopy(receipt["cost_events"])
        events[2].update(outcome="failed", error_type="MemoryError")
        result = metrics.stage_metrics(events, 2)
        self.assertIsNone(result["stage_costs"])
        events[2] = copy.deepcopy(events[1])
        with self.assertRaisesRegex(ValueError, "STAGE_IDENTITY"):
            metrics.stage_metrics(events, 2)

    def test_successful_training_cannot_omit_setup_or_report_a_gpu_cost(self):
        path = "training/gen2/actual-receipt.json"
        self.change(path, lambda x: x["cost_events"].pop(0))
        with self.assertRaisesRegex(ValueError, "INCOMPLETE_SUCCESSFUL_TRAINING_STAGES"):
            self.project()
        self.raw = dict(self.original_records)
        self.change(path, lambda x: x["cost_events"][0].__setitem__("gpu_ns", 1))
        with self.assertRaisesRegex(ValueError, "CPU_PROFILE_GPU"):
            self.project()


class BoundedFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cell-model-reader-")
        self.root = Path(self.temp.name) / "bundle"
        shutil.copytree(FIXTURE, self.root)
        self.path = self.root / "input-manifest.json"
        self.manifest = json.loads(self.path.read_bytes())

    def tearDown(self):
        self.temp.cleanup()

    def load(self, changed=False):
        if changed:
            self.path.write_text(json.dumps(self.manifest, sort_keys=True) + "\n")
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        return metrics.load_bundle(self.path, sha)

    def test_wrong_top_level_pin_and_raw_blob_mutation_fail(self):
        with self.assertRaisesRegex(ValueError, "MANIFEST_PIN"):
            metrics.load_bundle(self.path, "0" * 64)
        target = self.root / self.manifest["files"][RESEARCH]["path"]
        target.write_bytes(target.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "FILE_SHA256"):
            self.load()

    def test_failed_attempt_cannot_be_omitted_from_manifest(self):
        self.manifest["files"].pop("failures/optimized-original/publisher-to-replica-command.json")
        with self.assertRaisesRegex(ValueError, "COMPLETE_RECORD_DENOMINATOR"):
            self.load(changed=True)

    def test_duplicate_key_nonfinite_and_huge_number_refused(self):
        for raw in (b'{"n":1,"n":2}', b'{"n":NaN}', b'{"n":Infinity}',
                    b'{"n":1e100000000}', b'{"n":' + b"1" * 41 + b'}'):
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError):
                metrics.parse(raw)

    def test_path_traversal_absolute_and_noncanonical_paths_refused(self):
        for path in ("../outside.json", "/etc/passwd", "originals/./actual/research-result.json", "originals//a"):
            with self.subTest(path=path):
                self.manifest["files"][RESEARCH]["path"] = path
                with self.assertRaisesRegex(ValueError, "RECORD_PATH"):
                    self.load(changed=True)

    def test_symlink_leaf_refused(self):
        target = self.root / self.manifest["files"][RESEARCH]["path"]
        original = self.root / "original-copy.json"
        target.rename(original)
        target.symlink_to(original)
        with self.assertRaises(OSError):
            self.load()

    def test_symlink_directory_refused(self):
        original = self.root / "originals"
        moved = self.root / "originals-moved"
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(OSError):
            self.load()

    def test_hardlink_and_special_file_refused_before_read(self):
        target = self.root / self.manifest["files"][RESEARCH]["path"]
        os.link(target, self.root / "second-link")
        with self.assertRaisesRegex(ValueError, "REGULAR_SINGLE_LINK_REQUIRED"):
            self.load()
        (self.root / "second-link").unlink()
        target.unlink()
        os.mkfifo(target)
        with self.assertRaisesRegex(ValueError, "REGULAR_SINGLE_LINK_REQUIRED"):
            self.load()

    def test_file_size_bound_precedes_hashing(self):
        target = self.root / self.manifest["files"][RESEARCH]["path"]
        target.write_bytes(b"x" * (metrics.MAX_FILE + 1))
        with self.assertRaisesRegex(ValueError, "INPUT_LIMIT"):
            self.load()


if __name__ == "__main__":
    unittest.main()
