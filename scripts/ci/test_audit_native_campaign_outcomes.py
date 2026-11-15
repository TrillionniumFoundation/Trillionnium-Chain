"""Small parser controls; these fixtures never represent native acceptance."""
import hashlib
import copy
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

import audit_native_campaign_outcomes as reader


def wire(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


class ArtifactControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "records.zip"

    def archive(self, *, inconsistent_member=False, extra_member=False):
        payload = b"retained failed observation\n"
        manifest = wire({"files": [{"path": "failed.log", "bytes": len(payload),
                                    "sha256": hashlib.sha256(payload).hexdigest()}]})
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("artifact-files.json", manifest)
            archive.writestr("failed.log", b"x" * len(payload) if inconsistent_member else payload)
            if extra_member:
                archive.writestr("unlisted.txt", b"not in the producer inventory")
        return hashlib.sha256(self.path.read_bytes()).hexdigest(), hashlib.sha256(manifest).hexdigest()

    def test_complete_file_inventory_includes_failed_member(self):
        archive_hash, manifest_hash = self.archive()
        bundle = reader.Artifact(self.path, archive_hash, manifest_hash)
        try:
            self.assertEqual(bundle.raw("failed.log"), b"retained failed observation\n")
            self.assertEqual(len(bundle.files), 1)
            self.assertEqual(bundle.total_bytes, 28)
        finally:
            bundle.close()

    def test_wrong_archive_pin_is_refused(self):
        _, manifest_hash = self.archive()
        with self.assertRaisesRegex(ValueError, "ZIP SHA256 mismatch"):
            reader.Artifact(self.path, "0" * 64, manifest_hash)

    def test_wrong_manifest_pin_is_refused(self):
        archive_hash, _ = self.archive()
        with self.assertRaisesRegex(ValueError, "file-list SHA256 mismatch"):
            reader.Artifact(self.path, archive_hash, "0" * 64)

    def test_individually_inconsistent_member_is_refused(self):
        archive_hash, manifest_hash = self.archive(inconsistent_member=True)
        with self.assertRaisesRegex(ValueError, "artifact SHA256 mismatch"):
            reader.Artifact(self.path, archive_hash, manifest_hash)

    def test_unlisted_member_is_refused(self):
        archive_hash, manifest_hash = self.archive(extra_member=True)
        with self.assertRaisesRegex(ValueError, "inventory differ"):
            reader.Artifact(self.path, archive_hash, manifest_hash)

    def test_noncanonical_or_duplicate_json_is_refused(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            reader.strict_json(b'{"complete_success":false,"complete_success":true}')
        with self.assertRaisesRegex(ValueError, "nonfinite"):
            reader.strict_json(b'{"cpu_ns":NaN}')


class ObservationControls(unittest.TestCase):
    def import_fixture(self):
        host = [{"phase": name, "calls_started": 1, "calls_completed": 1,
                 "calls_accepted": 1, "calls_rejected": 0, "calls_unfinished": 0,
                 "first_started_ns": 1, "last_ended_ns": 11, "wall_ns": 10,
                 "thread_cpu_ns": 10, "wall_clock_unknown_calls": 0,
                 "cpu_clock_unknown_calls": 0, "last_error_code": None}
                for name in ("resolve", "initial", "checkpoint", "final")]
        names = ("decode", "context_owner_wait", "context", "work", "admission_owner_wait",
                 "admission", "submit_result", "admission_prepare", "execution", "commit_owner_wait",
                 "commit", "cpu_wait", "body_decode", "response_encoding", "history_epoch_open",
                 "history_epoch_close", "history_import", "cpu_settle", "root_commitment")
        phases = [{"phase": name, "parent_phase": None, "started": False, "completed": False,
                   "accepted": None, "error_code": None, "started_ns": None, "ended_ns": None,
                   "wall_ns": None, "thread_cpu_ns": None} for name in names]
        phases[16].update(started=True, completed=True, accepted=True, started_ns=1,
                          ended_ns=901, wall_ns=900, thread_cpu_ns=300)
        native = {"schema": "pon-local-history-import-observation-v1", "measurement_failures": 0,
                  "packet_capacity": 16, "supplied_packets": 0, "phases": phases, "packets": [],
                  "host_checks": host, "host_checks_are_nested_not_additive": True,
                  "cpu_intervals_are_nested_not_additive": True, "phase_cpu_excludes_scoped_workers": True,
                  "host_cpu_includes_each_calling_thread": True, "host_cpu_is_full_worker_cpu": False,
                  "observation_has_consensus_authority": False, "clock_scope": "synthetic parser fixture"}
        item = {"started_ns": 1, "ended_ns": 1001, "wall_ns": 1000, "thread_cpu_ns": 500,
                "thread_cpu_observation_available": True, "scope": "calling client thread",
                "succeeded": True, "error": None, "native_import_observation": native}
        return {"history": [{"elapsed_wall_ns": 100, "client_import": item}]}, item, native, host

    def phase(self):
        raw = {"mode": "baseline", "duration_seconds": 30, "attacker_processes_requested": 0,
               "confirmations": [{"round": 0, "started_ns": 1_000_000_000,
                                  "ended_ns": 23_000_000_000, "confirmed_inside_pressure_window": True},
                                 {"round": 1, "started_ns": 23_000_000_000,
                                  "ended_ns": 30_000_000_000, "confirmed_inside_pressure_window": False}],
               "all_signed_rounds_confirmed_in_window": False,
               "finite_phase_criteria_met": False, "genuine_budget_depletion_observed": False,
               "receiver_client_state_equal": False, "verifier_errors": ["PUBLIC_REQUEST_DEADLINE"],
               "service_outcome": {"Ok": {}}, "history": []}
        projection = {"mode": "baseline", "scheduled_confirmation_rounds": 3,
                      "observed_confirmation_rounds": 2, "confirmed_rounds": 1,
                      "unobserved_scheduled_rounds": 1, "window_seconds": 30,
                      "native_phase_criteria_met": False, "genuine_budget_depletion_observed": False,
                      "receiver_client_state_equal": False, "native_verifier_errors": ["PUBLIC_REQUEST_DEADLINE"],
                      "startup_or_campaign_error": None}
        return raw, projection

    def test_planned_rounds_are_not_replaced_by_observed_prefix(self):
        raw, projection = self.phase()
        value = reader.phase_observation(raw, projection, 0)
        self.assertEqual(value["scheduled_confirmation_rounds"], 3)
        self.assertEqual(value["observed_confirmation_rounds"], 2)
        self.assertEqual(value["confirmed_rounds"], 1)
        self.assertEqual(value["unobserved_scheduled_rounds"], 1)
        self.assertFalse(value["native_phase_criteria_met"])
        self.assertTrue(value["service_returned_ok"])

    def test_successful_service_return_cannot_change_phase_verdict(self):
        raw, projection = self.phase()
        projection["native_phase_criteria_met"] = True
        with self.assertRaisesRegex(ValueError, "projection contradicts"):
            reader.phase_observation(raw, projection, 0)

    def test_repeated_round_identity_cannot_inflate_denominator(self):
        raw, projection = self.phase()
        raw["confirmations"][1]["round"] = 0
        with self.assertRaisesRegex(ValueError, "ordered prefix"):
            reader.phase_observation(raw, projection, 0)

    def test_claimed_confirmation_cannot_hide_unobserved_round(self):
        raw, projection = self.phase()
        raw["all_signed_rounds_confirmed_in_window"] = True
        with self.assertRaisesRegex(ValueError, "original denominator"):
            reader.phase_observation(raw, projection, 0)

    def test_boolean_is_not_a_count(self):
        raw, projection = self.phase()
        raw["confirmations"][1]["round"] = True
        with self.assertRaisesRegex(ValueError, "integer required"):
            reader.phase_observation(raw, projection, 0)

    def test_unknown_cpu_retains_known_subtotal_without_complete_zero(self):
        phase, item, _, host = self.import_fixture()
        host[2].update(thread_cpu_ns=None, cpu_clock_unknown_calls=1)
        item.update(thread_cpu_ns=None, thread_cpu_observation_available=False,
                    succeeded=False, error="PUBLIC_REQUEST_DEADLINE")
        row = reader.import_observations(phase)[0]
        self.assertIsNone(row["host_cpu_ns"])
        self.assertIsNone(row["client_import_calling_thread_cpu_ns"])
        self.assertEqual(row["host_cpu_ns_known_sum"], 30)
        self.assertEqual(row["host_cpu_unknown_calls"], 1)

    def test_measurement_failure_or_missing_failure_count_keeps_complete_cpu_unknown(self):
        for value in (1, None, "missing"):
            phase, _, native, _ = self.import_fixture()
            if value == "missing":
                del native["measurement_failures"]
            else:
                native["measurement_failures"] = value
            with self.subTest(value=value):
                row = reader.import_observations(phase)[0]
                self.assertIsNone(row["host_cpu_ns"])
                self.assertEqual(row["host_cpu_ns_known_sum"], 40)
                self.assertFalse(row["native_measurement"]["lifecycle_complete"])
                self.assertEqual(row["native_measurement"]["measurement_failures"], None if value == "missing" else value)

    def test_live_host_call_preserves_started_completed_and_pending_counts(self):
        phase, _, _, host = self.import_fixture()
        host[2]["calls_started"] = 2
        row = reader.import_observations(phase)[0]
        self.assertIsNone(row["host_cpu_ns"])
        self.assertEqual(row["host_cpu_ns_known_sum"], 40)
        self.assertEqual(row["host_checks"][2]["calls_started"], 2)
        self.assertEqual(row["host_checks"][2]["calls_completed"], 1)
        self.assertEqual(row["host_checks"][2]["calls_not_ended"], 1)

    def test_unwound_host_call_preserves_measured_part_without_complete_total(self):
        phase, _, _, host = self.import_fixture()
        host[2].update(calls_started=2, calls_unfinished=1)
        row = reader.import_observations(phase)[0]
        self.assertIsNone(row["host_cpu_ns"])
        self.assertEqual(row["host_cpu_ns_known_sum"], 40)
        self.assertEqual(row["host_checks"][2]["calls_unfinished"], 1)
        self.assertEqual(row["host_checks"][2]["calls_not_ended"], 0)

    def test_missing_or_inconsistent_host_count_is_not_a_complete_measurement(self):
        for change in ("missing", "unbalanced"):
            phase, _, _, host = self.import_fixture()
            if change == "missing":
                del host[2]["calls_completed"]
            else:
                host[2]["calls_accepted"] = 0
            with self.subTest(change=change):
                row = reader.import_observations(phase)[0]
                self.assertIsNone(row["host_cpu_ns"])
                self.assertEqual(row["host_cpu_ns_known_sum"], 40)
                self.assertFalse(row["host_checks"][2]["counts_consistent"])

    def test_incomplete_page_or_packet_span_keeps_complete_host_cpu_unknown(self):
        for layer in ("page", "packet"):
            phase, _, native, _ = self.import_fixture()
            rows = native["phases"]
            if layer == "packet":
                rows = copy.deepcopy(rows)
                native.update(supplied_packets=1, packets=[{"packet_index": 0,
                    "packet_id": [1] * 32, "phases": rows}])
            rows[16].update(completed=False, accepted=None, ended_ns=None,
                            wall_ns=None, thread_cpu_ns=None)
            with self.subTest(layer=layer):
                row = reader.import_observations(phase)[0]
                self.assertIsNone(row["host_cpu_ns"])
                self.assertEqual(row["host_cpu_ns_known_sum"], 40)
                state = row["native_measurement"]["page_phase_measurements"] if layer == "page" else row["native_measurement"]["packet_phase_measurements"][0]["phase_measurements"]
                self.assertEqual(state["unfinished_spans"], 1)

    def test_missing_page_measurements_keep_complete_cpu_unknown(self):
        phase, _, native, _ = self.import_fixture()
        del native["phases"]
        row = reader.import_observations(phase)[0]
        self.assertIsNone(row["host_cpu_ns"])
        self.assertIsNone(row["native_measurement"]["page_phase_measurements"]["records"])
        self.assertEqual(row["host_cpu_ns_known_sum"], 40)

    def test_unentered_host_slot_remains_null_and_does_not_erase_other_measured_calls(self):
        phase, _, _, host = self.import_fixture()
        host[2].update(calls_started=0, calls_completed=0, calls_accepted=0,
                       first_started_ns=None, last_ended_ns=None, wall_ns=None, thread_cpu_ns=None)
        row = reader.import_observations(phase)[0]
        self.assertTrue(row["host_checks"][2]["unentered_slot"])
        self.assertIsNone(row["host_checks"][2]["thread_cpu_ns"])
        self.assertEqual(row["host_cpu_ns"], 30)
        self.assertEqual(row["host_cpu_known_slots"], 3)

    def test_no_observed_host_calls_do_not_create_measured_zero(self):
        phase, _, _, host = self.import_fixture()
        for entry in host:
            entry.update(calls_started=0, calls_completed=0, calls_accepted=0,
                         first_started_ns=None, last_ended_ns=None, wall_ns=None, thread_cpu_ns=None)
        row = reader.import_observations(phase)[0]
        self.assertIsNone(row["host_cpu_ns"])
        self.assertIsNone(row["host_cpu_ns_known_sum"])
        self.assertEqual(row["host_cpu_known_slots"], 0)

    def test_client_clock_unavailability_is_preserved_separately(self):
        phase, item, _, _ = self.import_fixture()
        item["thread_cpu_observation_available"] = False
        row = reader.import_observations(phase)[0]
        self.assertIsNone(row["client_import_calling_thread_cpu_ns"])
        self.assertEqual(row["client_import_measurement"]["thread_cpu_ns"], 500)
        self.assertFalse(row["client_import_measurement"]["cpu_measurement_complete"])
        self.assertEqual(row["host_cpu_ns"], 40)

    def test_nested_native_and_client_cpu_are_not_added_to_host_cpu(self):
        phase, _, _, _ = self.import_fixture()
        row = reader.import_observations(phase)[0]
        self.assertEqual(row["host_cpu_ns"], 40)
        self.assertEqual(row["client_import_calling_thread_cpu_ns"], 500)
        self.assertEqual(row["native_measurement"]["page_phase_measurements"]["records"][16]["thread_cpu_ns"], 300)

    def test_returned_failure_can_still_have_complete_cpu_observation(self):
        phase, item, _, host = self.import_fixture()
        item.update(succeeded=False, error="PUBLIC_REQUEST_DEADLINE")
        host[3].update(calls_accepted=0, calls_rejected=1, last_error_code="PUBLIC_REQUEST_DEADLINE")
        row = reader.import_observations(phase)[0]
        self.assertFalse(row["succeeded"])
        self.assertEqual(row["host_cpu_ns"], 40)
        self.assertEqual(row["host_checks"][3]["calls_rejected"], 1)


if __name__ == "__main__":
    unittest.main()
