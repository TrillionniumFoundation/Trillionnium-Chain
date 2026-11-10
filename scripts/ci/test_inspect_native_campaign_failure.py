"""No acceptance promotion or denominator contraction in failure inspection."""
import json
import tempfile
import unittest
from pathlib import Path

from inspect_native_campaign_failure import inspect, PHASES


def fixture():
    def phase(name, attackers):
        return {"mode": name, "duration_seconds": 30,
                "attacker_processes_requested": attackers,
                "attacker_processes_ready": attackers,
                "observer_complete": True,
                "all_signed_rounds_confirmed_in_window": False,
                "receiver_client_state_equal": False,
                "verifier_errors": ["PUBLIC_REQUEST_DEADLINE"],
                "finite_phase_criteria_met": False,
                "genuine_budget_depletion_observed": False,
                "actor_reports_successful_without_cap_or_kill": True,
                "submissions": [{"elapsed_wall_ns": 9}],
                "confirmations": [{"confirmed_inside_pressure_window": False}],
                "history": [{"elapsed_wall_ns": 2, "client_import": {
                    "wall_ns": 7, "thread_cpu_ns": 3,
                    "native_import_observation": {"host_checks": [
                        {"phase": "checkpoint", "calls_accepted": 11}]}}}],
                "full_work_accepted": 1, "full_work_failed": 0}
    return {"schema": "native-public-v3-separate-process-campaign-v2",
            "state_backend": "authenticated-v1",
            "preparation": {"actual_signed_seed_transfers": 1024,
                            "seed_blocks": 4, "business_blocks": 21},
            "finite_experiment_criteria_met": False,
            "economics_complete": True,
            "phases": [phase(name, attackers) for name, attackers in PHASES]}


class FailureInspectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def put(self, number, data):
        folder = self.root / f"run-{number}-raw"
        folder.mkdir(parents=True)
        (folder / "report.json").write_text(json.dumps(data), encoding="utf-8")

    def test_missing_runs_remain_in_three_run_denominator(self):
        self.put(1, fixture())
        summary = inspect(self.root)
        self.assertEqual(summary["original_run_denominator"], 3)
        self.assertEqual(summary["report_files_with_original_input_shape"], 1)
        self.assertTrue(summary["runs"][1]["error"])
        self.assertFalse(summary["grants_qualification_or_activation"])

    def test_nested_timings_remain_separate(self):
        for n in range(1, 4):
            self.put(n, fixture())
        summary = inspect(self.root)
        self.assertEqual(summary["report_files_with_original_input_shape"], 3)
        baseline = summary["runs"][0]["phases"][0]
        self.assertEqual(baseline["history_import_wall_ns"]["total"], 7)
        self.assertEqual(baseline["history_network_wall_ns"]["total"], 2)
        self.assertEqual(baseline["submit_client_wall_ns"]["total"], 9)
        self.assertEqual(baseline["history_checkpoint_host_calls"]["total"], 11)
        self.assertIn("no_verifier_errors", baseline["unmet_flags"])

    def test_native_admission_and_commit_intervals_are_nested_not_added(self):
        data = fixture()
        observation = data["phases"][0]["history"][0]["client_import"]["native_import_observation"]
        observation["packets"] = [{"phases": [
            {"phase": "admission", "wall_ns": 30, "thread_cpu_ns": 12},
            {"phase": "admission_prepare", "wall_ns": 10, "thread_cpu_ns": 5},
            {"phase": "commit", "wall_ns": 18, "thread_cpu_ns": 7},
        ]}]
        self.put(1, data)
        phases = inspect(self.root)["runs"][0]["phases"][0]["native_packet_stage_observations"]
        self.assertEqual(phases["native_packet_instances"], 1)
        self.assertEqual(phases["phases"]["admission"]["wall_ns"]["total"], 30)
        self.assertEqual(phases["phases"]["admission_prepare"]["wall_ns"]["total"], 10)
        self.assertEqual(phases["phases"]["commit"]["wall_ns"]["total"], 18)
        self.assertIsNone(phases["phases"]["work"]["wall_ns"]["total"])
        self.assertIn("no category totals should be summed", phases["non_additive"])

    def test_missing_native_packet_stage_list_is_not_zero_work(self):
        self.put(1, fixture())
        phases = inspect(self.root)["runs"][0]["phases"][0]["native_packet_stage_observations"]
        self.assertEqual(phases["history_calls_missing_packet_list"], 1)
        self.assertEqual(phases["native_packet_instances"], 0)
        self.assertIsNone(phases["phases"]["commit"]["wall_ns"]["total"])

    def test_changed_workload_is_detected_without_inheriting_reported_success(self):
        altered = fixture()
        altered["phases"][1]["attacker_processes_requested"] = 1
        altered["finite_experiment_criteria_met"] = True
        self.put(1, altered)
        observed = inspect(self.root)["runs"][0]
        self.assertFalse(observed["original_input_shape_valid"])
        self.assertTrue(observed["reported_finite_experiment_criteria_met"])
        self.assertFalse(observed["phases"][1]["flags"]["original_inputs"])

    def test_missing_import_cpu_is_null_not_zero(self):
        altered = fixture()
        altered["phases"][0]["history"][0]["client_import"].pop("thread_cpu_ns")
        self.put(1, altered)
        metric = inspect(self.root)["runs"][0]["phases"][0]["history_import_thread_cpu_ns"]
        self.assertIsNone(metric["total"])
        self.assertEqual(metric["observed"], 0)

    def test_host_checkpoint_cpu_fraction_is_nested_not_a_speedup(self):
        data = fixture()
        original = data["phases"][0]["history"][0]["client_import"]
        original["thread_cpu_ns"] = 200
        host = original["native_import_observation"]["host_checks"][0]
        host.update({"calls_started": 12, "calls_completed": 12,
                     "calls_accepted": 12, "calls_rejected": 0,
                     "calls_unfinished": 0, "cpu_clock_unknown_calls": 0,
                     "wall_clock_unknown_calls": 0,
                     "thread_cpu_ns": 160, "wall_ns": 640})
        self.put(1, data)
        phase = inspect(self.root)["runs"][0]["phases"][0]
        self.assertEqual(phase["history_checkpoint_host_calls"]["total"], 12)
        self.assertEqual(phase["history_checkpoint_cpu_fraction_ppm"], 800000)
        self.assertEqual(phase["history_checkpoint_host_observations"]["thread_cpu_ns"]["total"], 160)
        self.assertIn("kernel check each time", phase["history_checkpoint_scope"])

    def test_missing_duplicate_or_malformed_host_measurement_is_unknown(self):
        data = fixture()
        original = data["phases"][0]["history"][0]["client_import"]
        original["thread_cpu_ns"] = 200
        host = original["native_import_observation"]["host_checks"][0]
        host.update({"thread_cpu_ns": False, "wall_ns": "0"})
        self.put(1, data)
        phase = inspect(self.root)["runs"][0]["phases"][0]
        self.assertIsNone(phase["history_checkpoint_cpu_fraction_ppm"])
        self.assertIsNone(phase["history_checkpoint_host_observations"]["wall_ns"]["total"])
        other = fixture()
        checks = other["phases"][0]["history"][0]["client_import"]["native_import_observation"]["host_checks"]
        checks.append(dict(checks[0]))
        self.put(2, other)
        duplicate = inspect(self.root)["runs"][1]["phases"][0]
        self.assertIsNone(duplicate["history_checkpoint_host_calls"]["total"])
        self.assertEqual(duplicate["history_checkpoint_host_calls"]["observed"], 0)

    def test_report_symlink_and_duplicate_mode_are_refused(self):
        target = self.root / "external.json"
        target.write_text(json.dumps(fixture()))
        p = self.root / "run-1-raw"
        p.mkdir()
        (p / "report.json").symlink_to(target)
        self.assertIn("symlink", inspect(self.root)["runs"][0]["error"])
        changed = fixture()
        changed["phases"][1]["mode"] = "baseline"
        self.put(2, changed)
        self.assertFalse(inspect(self.root)["runs"][1]["original_input_shape_valid"])


    def test_terminal_admission_deadline_precedes_nested_commit_deadline(self):
        data = fixture()
        last = data["phases"][0]["history"][-1]
        last["status"] = "ok"
        last["client_import"].update({"succeeded": False, "error": "PUBLIC_REQUEST_DEADLINE"})
        last["client_import"]["native_import_observation"]["packets"] = [{"phases": [
            {"phase": "admission", "started": True, "completed": True,
             "accepted": False, "error_code": "PUBLIC_REQUEST_DEADLINE"},
            {"phase": "commit", "started": True, "completed": True,
             "accepted": False, "error_code": "PUBLIC_REQUEST_DEADLINE"},
            {"phase": "submit_result", "started": False, "completed": False,
             "accepted": None, "error_code": None},
            {"phase": "history_import", "started": True, "completed": True,
             "accepted": False, "error_code": "PUBLIC_REQUEST_DEADLINE"},
        ]}]
        self.put(1, data)
        result = inspect(self.root)["runs"][0]["phases"][0]["terminal_history_import_boundary"]
        self.assertEqual(result["network_status"], "ok")
        self.assertEqual(result["client_import_error"], "PUBLIC_REQUEST_DEADLINE")
        self.assertEqual(result["boundary_stage"], "admission")
        self.assertEqual(result["boundary_status"], "observed_deadline_at_stage")

    def test_terminal_submit_result_deadline_after_accepted_commit(self):
        data = fixture()
        last = data["phases"][1]["history"][-1]
        last["status"] = "ok"
        last["client_import"].update({"succeeded": False, "error": "PUBLIC_REQUEST_DEADLINE"})
        last["client_import"]["native_import_observation"]["packets"] = [{"phases": [
            {"phase": "admission", "started": True, "completed": True,
             "accepted": True, "error_code": None},
            {"phase": "commit", "started": True, "completed": True,
             "accepted": True, "error_code": None},
            {"phase": "submit_result", "started": True, "completed": True,
             "accepted": False, "error_code": "PUBLIC_REQUEST_DEADLINE"},
            {"phase": "history_import", "started": True, "completed": True,
             "accepted": False, "error_code": "PUBLIC_REQUEST_DEADLINE"},
        ]}]
        self.put(1, data)
        result = inspect(self.root)["runs"][0]["phases"][1]["terminal_history_import_boundary"]
        self.assertEqual(result["boundary_stage"], "submit_result")
        self.assertEqual(result["client_import_succeeded"], False)
        self.assertIn("not proof", result["warning"])

    def test_terminal_missing_or_duplicate_stage_does_not_infer_success(self):
        data = fixture()
        self.put(1, data)
        first = inspect(self.root)["runs"][0]["phases"][0]["terminal_history_import_boundary"]
        self.assertEqual(first["boundary_status"], "unknown")
        last = data["phases"][0]["history"][-1]
        last["client_import"].update({"succeeded": False, "error": "PUBLIC_REQUEST_DEADLINE"})
        stages = [{"phase": name, "started": True, "completed": True,
                   "accepted": False, "error_code": "PUBLIC_REQUEST_DEADLINE"}
                  for name in ("admission", "commit", "submit_result", "history_import")]
        stages.append(dict(stages[0]))
        last["client_import"]["native_import_observation"]["packets"] = [{"phases": stages}]
        self.put(2, data)
        second = inspect(self.root)["runs"][1]["phases"][0]["terminal_history_import_boundary"]
        self.assertEqual(second["boundary_status"], "unknown")
        self.assertIsNone(second["boundary_stage"])


class PostwindowNativeConfirmationTests(unittest.TestCase):
    def test_actual_native_depth_six_observation_after_deadline_is_not_a_pass(self):
        from inspect_native_campaign_failure import _phase
        data = fixture()["phases"][1]
        data["verifier_errors"] = []
        data["history"][-1]["client_import"]["succeeded"] = True
        data["confirmations"] = [{"round": 0, "ended_ns": 30_192_354_000,
            "confirmed_inside_pressure_window": False,
            "observation": {"confirmed": True, "finalized": False,
                            "execution_authority": False, "depth": 6}}]
        result = _phase(data, "from-zero", 24)
        details = result["reported_native_confirmation_timing"]
        self.assertEqual(details["native_confirmation_reported"], 1)
        self.assertEqual(details["native_confirmation_reported_after_deadline"], 1)
        self.assertEqual(details["after_deadline_rounds"][0]["over_deadline_ns"], 192_354_000)
        self.assertEqual(result["confirmed_round_observations"], 0)
        self.assertFalse(result["flags"]["signed_rounds_confirmed"])
        self.assertFalse(result["flags"]["reported_finite_phase_criteria_met"])

    def test_unknown_or_conflicting_clock_cannot_be_promoted_to_late_success(self):
        from inspect_native_campaign_failure import _phase
        data = fixture()["phases"][0]
        data["confirmations"] = [
            {"ended_ns": "30192354000", "confirmed_inside_pressure_window": False,
             "observation": {"confirmed": True, "finalized": False,
                             "execution_authority": False, "depth": 6}},
            {"ended_ns": 30_192_354_000, "confirmed_inside_pressure_window": True,
             "observation": {"confirmed": True, "finalized": False,
                             "execution_authority": False, "depth": 6}},
            {"ended_ns": 30_192_354_000, "confirmed_inside_pressure_window": False,
             "observation": {"confirmed": True, "finalized": False,
                             "execution_authority": True, "depth": 6}},
        ]
        result = _phase(data, "baseline", 0)
        details = result["reported_native_confirmation_timing"]
        self.assertEqual(details["native_confirmation_reported"], 2)
        self.assertEqual(details["native_confirmation_reported_after_deadline"], 0)
        self.assertEqual(details["qualifying_observations_with_unknown_timing"], 1)
        self.assertEqual(details["deadline_conflicts"], 1)
        self.assertFalse(result["flags"]["reported_finite_phase_criteria_met"])


class TerminalBoundaryIntegrityTests(unittest.TestCase):
    @staticmethod
    def history():
        return [{"status": "ok", "error": None, "client_import": {
            "succeeded": False, "error": "PUBLIC_REQUEST_DEADLINE",
            "native_import_observation": {"packets": [{"phases": [
                {"phase": name, "started": True, "completed": True,
                 "accepted": False, "error_code": "PUBLIC_REQUEST_DEADLINE"}
                for name in ("admission", "commit", "submit_result", "history_import")
            ]}]}}}]

    def test_missing_or_nonboolean_terminal_flags_remain_unknown(self):
        from inspect_native_campaign_failure import _terminal_import_boundary
        for key, value in (("started", None), ("started", "true"),
                           ("completed", 1), ("accepted", 0)):
            with self.subTest(key=key, value=value):
                history = self.history()
                stage = history[0]["client_import"]["native_import_observation"]["packets"][0]["phases"][0]
                if value is None:
                    stage.pop(key)
                else:
                    stage[key] = value
                result = _terminal_import_boundary(history)
                self.assertEqual(result["boundary_status"], "unknown")
                self.assertIsNone(result["boundary_stage"])

    def test_conflicting_import_success_does_not_hide_stage_failure(self):
        from inspect_native_campaign_failure import _terminal_import_boundary
        history = self.history()
        history[0]["client_import"]["succeeded"] = True
        result = _terminal_import_boundary(history)
        self.assertEqual(result["boundary_status"], "unknown")
        self.assertIsNone(result["boundary_stage"])
        imported = history[0]["client_import"]
        imported["error"] = None
        stages = imported["native_import_observation"]["packets"][0]["phases"]
        for stage in stages:
            stage.update(accepted=True, error_code=None)
        self.assertEqual(_terminal_import_boundary(history)["boundary_status"],
                         "no_terminal_import_failure")
        stages[0].update(accepted=False, error_code="PUBLIC_REQUEST_DEADLINE")
        self.assertEqual(_terminal_import_boundary(history)["boundary_status"], "unknown")

    def test_claimed_success_with_unexecuted_terminal_stage_is_unknown(self):
        from inspect_native_campaign_failure import _terminal_import_boundary
        history = self.history()
        row = history[0]["client_import"]
        row.update(succeeded=True, error=None)
        stages = row["native_import_observation"]["packets"][0]["phases"]
        for stage in stages:
            stage.update(started=False, completed=False, accepted=None, error_code=None)
        result = _terminal_import_boundary(history)
        self.assertEqual(result["boundary_status"], "unknown")
        self.assertIsNone(result["boundary_stage"])

    def test_claimed_success_with_network_failure_is_unknown(self):
        from inspect_native_campaign_failure import _terminal_import_boundary
        history = self.history()
        row = history[0]["client_import"]
        row.update(succeeded=True, error=None)
        for stage in row["native_import_observation"]["packets"][0]["phases"]:
            stage.update(accepted=True, error_code=None)
        history[0].update(status="error", error="PUBLIC_REQUEST_DEADLINE")
        result = _terminal_import_boundary(history)
        self.assertEqual(result["boundary_status"], "unknown")
        self.assertIsNone(result["boundary_stage"])

    def test_success_with_transport_error_and_ok_status_remains_unknown(self):
        from inspect_native_campaign_failure import _terminal_import_boundary
        history = self.history()
        imported = history[0]["client_import"]
        imported.update(succeeded=True, error=None)
        for stage in imported["native_import_observation"]["packets"][0]["phases"]:
            stage.update(accepted=True, error_code=None)
        history[0].update(status="ok", error="transport-lost")
        self.assertEqual(_terminal_import_boundary(history)["boundary_status"], "unknown")

    def test_unreturned_or_unstarted_stage_cannot_be_a_deadline_boundary(self):
        from inspect_native_campaign_failure import _terminal_import_boundary
        for key in ("started", "completed"):
            with self.subTest(key=key):
                history = self.history()
                history[0]["client_import"]["native_import_observation"]["packets"][0]["phases"][0][key] = False
                result = _terminal_import_boundary(history)
                self.assertEqual(result["boundary_status"], "unknown")
                self.assertIsNone(result["boundary_stage"])


if __name__ == "__main__":
    unittest.main()
