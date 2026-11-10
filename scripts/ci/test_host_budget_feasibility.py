"""Refuse denominator changes, wrong source and CPU accounting confusion."""
import unittest
from host_budget_feasibility import analyze, SOURCE_COMMIT, SOURCE_RUN, SOURCE_ZIP_SHA256


def fixture():
    observations = []
    for run in range(1, 4):
        for phase in ("baseline", "from-zero", "late-product"):
            observations.append({
                "run": run, "phase": phase,
                "original_input_shape_valid": True, "finite_phase_criteria_met": False,
                "host_checkpoint_calls": 100,
                "host_checkpoint_thread_cpu_ns": 4_750_000_000,
                "history_import_thread_cpu_ns": 5_500_000_000,
            })
    return {"schema": "pon-original-native-host-checkpoint-cost-v1",
            "source_commit": SOURCE_COMMIT, "source_ci_run": SOURCE_RUN,
            "zip_sha256": SOURCE_ZIP_SHA256, "planned_runs": 3,
            "original_stages_per_run": 3,
            "all_phase_criteria_met": False, "observations": observations}


class FixedHostAccountingTests(unittest.TestCase):
    def test_exact_nominal_budget_and_nonpromotion(self):
        output = analyze(fixture())
        self.assertEqual(len(output["rows"]), 9)
        row = output["rows"][0]
        self.assertEqual(row["nominal_30s_quarter_core_cpu_ns"], 7_500_000_000)
        self.assertEqual(row["host_share_of_nominal_window_ppm"], 633333)
        self.assertEqual(row["nominal_cpu_left_ns"], 2_750_000_000)
        self.assertFalse(row["is_a_future_optimization_lower_bound"])
        self.assertFalse(row["is_exact_quota_window_bound"])
        self.assertFalse(output["all_original_phase_gates_met"])
        self.assertFalse(output["production_qualified"])

    def test_missing_or_reordered_phase_refused(self):
        data = fixture()
        data["observations"].pop()
        with self.assertRaises(ValueError):
            analyze(data)
        data = fixture()
        data["observations"][1]["phase"] = "baseline"
        with self.assertRaises(ValueError):
            analyze(data)

    def test_bad_nested_cpu_and_zero_checks_refused(self):
        for field, value in (
            ("host_checkpoint_thread_cpu_ns", -1),
            ("host_checkpoint_thread_cpu_ns", 6_000_000_000),
            ("host_checkpoint_calls", 0),
        ):
            data = fixture()
            data["observations"][0][field] = value
            with self.assertRaises(ValueError):
                analyze(data)

    def test_source_change_or_original_success_refused(self):
        for key, value in (("source_commit", "bad"), ("zip_sha256", "bad"),
                           ("source_ci_run", 1), ("planned_runs", 2),
                           ("original_stages_per_run", 2),
                           ("all_phase_criteria_met", True)):
            data = fixture()
            data[key] = value
            with self.assertRaises(ValueError):
                analyze(data)

    def test_bool_string_and_missing_cpu_are_not_accepted_numbers(self):
        for value in (None, True, "4750000000"):
            data = fixture()
            data["observations"][0]["host_checkpoint_thread_cpu_ns"] = value
            with self.assertRaises(ValueError):
                analyze(data)


if __name__ == "__main__":
    unittest.main()
