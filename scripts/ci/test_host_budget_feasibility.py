"""Refuse denominator changes, wrong source and CPU accounting confusion."""
import tempfile
import unittest
from pathlib import Path
from host_budget_feasibility import (
    analyze, read_pinned_source, SOURCE_COMMIT, SOURCE_RUN, SOURCE_ZIP_SHA256,
    SOURCE_SUMMARY_SHA256, ORIGINAL_REPORT_SHA256,
)


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
                "raw_report_sha256": ORIGINAL_REPORT_SHA256[run-1],
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
        self.assertEqual(output["source_summary_sha256"], SOURCE_SUMMARY_SHA256)
        self.assertEqual(output["original_report_sha256"], list(ORIGINAL_REPORT_SHA256))

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

    def test_wrong_raw_report_digest_refused_even_if_self_declared_identity_matches(self):
        data = fixture()
        data["observations"][3]["raw_report_sha256"] = ORIGINAL_REPORT_SHA256[0]
        with self.assertRaisesRegex(ValueError, "changed or missing original phase"):
            analyze(data)

    def test_exact_github_evidence_passes_full_byte_pin(self):
        original = Path(__file__).resolve().parents[2] / "evidence/pon-original-host-cost-20261110/host-phase-summary.json"
        result = analyze(read_pinned_source(original))
        self.assertEqual(len(result["rows"]), 9)
        self.assertFalse(result["production_qualified"])
        self.assertTrue(all(not phase["original_phase_accepted"] for phase in result["rows"]))

    def test_tampered_summary_symlink_and_missing_file_refused(self):
        original = Path(__file__).resolve().parents[2] / "evidence/pon-original-host-cost-20261110/host-phase-summary.json"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            forged = root / "modified.json"
            forged.write_bytes(original.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "SHA256"):
                read_pinned_source(forged)
            alias = root / "alias.json"
            alias.symlink_to(original)
            with self.assertRaisesRegex(ValueError, "symlink"):
                read_pinned_source(alias)
            with self.assertRaises(ValueError):
                read_pinned_source(root / "missing.json")

    def test_bool_string_and_missing_cpu_are_not_accepted_numbers(self):
        for value in (None, True, "4750000000"):
            data = fixture()
            data["observations"][0]["host_checkpoint_thread_cpu_ns"] = value
            with self.assertRaises(ValueError):
                analyze(data)


if __name__ == "__main__":
    unittest.main()
