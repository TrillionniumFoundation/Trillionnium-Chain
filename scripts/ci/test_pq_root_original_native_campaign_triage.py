"""Unit tests for the read-only original campaign artifact triage contract."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).with_name("pq_root_original_native_campaign_triage.py")
SPEC = importlib.util.spec_from_file_location("pq_root_original_native_campaign_triage", SCRIPT)
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


def phase(mode):
    rounds = [
        dict(round=i, started_ns=i * 1000, ended_ns=(i + 1) * 1000,
             confirmed_inside_pressure_window=(i != 2), observation=None)
        for i in range(3)
    ] if mode == "baseline" else [
        dict(round=0, started_ns=1000, ended_ns=30_000_000_001,
             confirmed_inside_pressure_window=False, observation=None)
    ]
    return {
        "mode": mode, "duration_seconds": 30,
        "finite_phase_criteria_met": False,
        "confirmations": rounds,
        "all_signed_rounds_confirmed_in_window": False,
        "final_receiver_tip": "a", "final_client_tip": "b",
        "receiver_client_state_equal": False,
        "final_actual_flow": {
            "balance_identity_verified": True,
            "initial_credit_ns": 100,
            "credited_refill_ns": 20,
            "paid_cpu_debit_ns": 30,
            "remaining_paid_credit_ns": 90,
        },
        "verifier_errors": ["PUBLIC_REQUEST_DEADLINE"] if mode != "baseline" else [],
        "genuine_budget_depletion_observed": False,
        "attacker_processes_ready": 24 if mode != "baseline" else 0,
        "attacker_processes_requested": 24 if mode != "baseline" else 0,
        "actor_reports_successful_without_cap_or_kill": True,
        "full_work_accepted": 7,
        "full_work_failed": 10 if mode != "baseline" else 0,
        "observer_complete": True,
    }


def make_zip(path, mismatch=False, change_mode=False, result_padding_bytes=0):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(1, 4):
            p = [phase(mode) for mode in reader.MODES]
            if change_mode and i == 2:
                p[-1]["mode"] = "baseline"
            raw = json.dumps({
                "finite_experiment_criteria_met": False,
                "economics_complete": True, "phases": p,
            }).encode()
            z.writestr(f"run-{i}-raw/report.json", raw)
            result = {
                "complete_success": False,
                "step": {"returncode": 101},
                "report_sha256": ("0" * 64) if mismatch and i == 2 else hashlib.sha256(raw).hexdigest(),
                "report_validation_failure": None,
                "phase_startup_errors": [],
            }
            if result_padding_bytes and i == 2:
                result["unused_padding"] = "x" * result_padding_bytes
            z.writestr(f"run-{i}-result.json", json.dumps(result))
    return hashlib.sha256(path.read_bytes()).hexdigest()


class NativeTriageTests(unittest.TestCase):
    def test_preserves_negative_result_and_credit_details(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, "fixture.zip")
            digest = make_zip(path)
            result = reader.triage_zip(path, digest, 17, "source-sha")
            self.assertEqual(result["status"], "HOLD")
            self.assertEqual(result["original_runs_passed"], 0)
            self.assertIsNone(result["actual_lifetime_failure_bound"])
            self.assertFalse(result["production_activation"])
            self.assertEqual(len(result["runs"]), 3)
            for run in result["runs"]:
                self.assertEqual([p["mode"] for p in run["phases"]], list(reader.MODES))
                self.assertEqual(run["phases"][0]["signed_rounds_confirmed_in_window"], 2)
                self.assertEqual(run["phases"][1]["cpu_credit_ns"]["remaining_paid_credit_ns"], 90)

    def test_wrong_zip_digest_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, "fixture.zip")
            make_zip(path)
            with self.assertRaisesRegex(ValueError, "ZIP SHA-256"):
                reader.triage_zip(path, "f" * 64, 17, "head")

    def test_large_compressed_runner_result_fails_closed(self):
        # A tiny compressed member can expand beyond the reader's result cap.
        # Preserve the original 30-second campaign report and SHA binding.
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, "oversized-result.zip")
            digest = make_zip(path, result_padding_bytes=reader.MAX_RESULT_BYTES)
            with self.assertRaisesRegex(ValueError, "runner result exceeds parser bound"):
                reader.triage_zip(path, digest, 17, "head")

    def test_report_checksum_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, "fixture.zip")
            digest = make_zip(path, mismatch=True)
            with self.assertRaisesRegex(ValueError, "runner SHA"):
                reader.triage_zip(path, digest, 17, "head")

    def test_duplicate_mode_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, "fixture.zip")
            digest = make_zip(path, change_mode=True)
            with self.assertRaisesRegex(ValueError, "phase"):
                reader.triage_zip(path, digest, 17, "head")

    def test_credit_balance_tampering_fails_closed(self):
        p = phase("from-zero")
        p["final_actual_flow"]["remaining_paid_credit_ns"] = 91
        with self.assertRaisesRegex(ValueError, "CPU-credit balance"):
            reader.summarize_phase(p)

    def test_false_success_refused(self):
        p = phase("baseline")
        p["finite_phase_criteria_met"] = True
        with self.assertRaisesRegex(ValueError, "success contradicts"):
            reader.summarize_phase(p)


    def test_tip_parity_is_weaker_than_full_state_parity(self):
        p = phase("baseline")
        p["final_client_tip"] = p["final_receiver_tip"]
        result = reader.summarize_phase(p)
        self.assertTrue(result["receiver_client_tip_equal"])
        self.assertFalse(result["receiver_client_state_equal_reported"])
        self.assertIn("receiver_client_state_mismatch", result["failed_prerequisites_observable"])

    def test_original_30_second_window_cannot_be_replaced(self):
        p = phase("baseline")
        p["duration_seconds"] = 31
        with self.assertRaisesRegex(ValueError, "30 seconds"):
            reader.summarize_phase(p)


if __name__ == "__main__":
    unittest.main()
