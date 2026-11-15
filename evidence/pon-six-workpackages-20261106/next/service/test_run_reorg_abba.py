#!/usr/bin/env python3
"""Reject incomplete, mismatched or broadened native ABBA observations."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
import run_reorg_abba as runner


class ReadbackTests(unittest.TestCase):
    def fixture(self):
        receipt = {"observer_sha256": "a" * 64, "store_sha256": "b" * 64}
        report = {"schema": "native-reorg-query-cost-v1", "completed": True,
            "same_native_state": True, "cold_reopen_same_state": True,
            "planned_blocks": 512, "admitted_blocks": 512, "packet_bytes": 12345,
            "backend": "legacy", "task_profile": "consensus-maintenance-continuity-dev-v1",
            "observer_source_sha256": receipt["observer_sha256"], "store_source_sha256": receipt["store_sha256"],
            **{f: "c" * 64 for f in ("network", "parameters", "genesis", "target")},
            **{f: 100 for f in runner.NATIVE_COSTS},
            **{f: False for f in ("original_history_4105_accepted", "original_four_second_accepted", "public_network_ready", "production_activation")}}
        return report, receipt

    def attempts(self):
        report, _ = self.fixture()
        return [{"implementation": kind, "result": "COMPLETE_COMPONENT_OBSERVATION",
                 "report": copy.deepcopy(report),
                 "observation": {"wait4_cpu_ns": 200, "elapsed_ns": 300, "wait4_maxrss_kib": 1000}}
                for kind in runner.ORDER]

    def test_actual_report_bound_to_both_embedded_sources(self):
        report, receipt = self.fixture()
        runner.validate_report(report, receipt)
        for field in ("observer_source_sha256", "store_source_sha256"):
            changed = copy.deepcopy(report)
            changed[field] = "d" * 64
            with self.assertRaises(ValueError):
                runner.validate_report(changed, receipt)

    def test_missing_preparation_or_cold_state_or_widened_claim_is_rejected(self):
        report, receipt = self.fixture()
        for field, value in (("preparation_process_cpu_ns", None), ("preparation_wall_ns", 0),
                             ("cold_reopen_same_state", False), ("admitted_blocks", 511),
                             ("original_four_second_accepted", True)):
            changed = copy.deepcopy(report)
            changed[field] = value
            with self.assertRaises(ValueError):
                runner.validate_report(changed, receipt)

    def test_eight_complete_attempts_have_separate_preparation_and_process_scopes(self):
        result = runner.comparison(self.attempts())
        self.assertTrue(result["complete_comparison"])
        self.assertEqual(result["medians"]["report.preparation_process_cpu_ns"]["baseline"], 100)
        self.assertEqual(result["medians"]["observation.wait4_cpu_ns"]["baseline"], 200)

    def test_failed_or_missing_attempt_never_becomes_zero_or_success_subset(self):
        attempts = self.attempts()
        attempts[3]["result"] = "HOLD"
        attempts[3]["observation"]["wait4_cpu_ns"] = 987654
        for subset in (attempts, attempts[:3] + attempts[4:], []):
            result = runner.comparison(subset)
            self.assertFalse(result["complete_comparison"])
            self.assertNotIn("medians", result)
            self.assertFalse(result["failed_attempts_are_zero"])
        self.assertEqual(attempts[3]["observation"]["wait4_cpu_ns"], 987654)

    def test_changed_input_target_or_order_prevents_comparison(self):
        for field in ("packet_bytes", "target", "observer_source_sha256"):
            attempts = self.attempts()
            attempts[4]["report"][field] = "changed"
            self.assertFalse(runner.comparison(attempts)["complete_comparison"])
        attempts = self.attempts()
        attempts[0], attempts[1] = attempts[1], attempts[0]
        self.assertFalse(runner.comparison(attempts)["complete_comparison"])

    def test_actual_binary_mutation_and_symlink_substitution_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "retained-elf"
            raw = b"\x7fELF\x02\x01" + bytes(12) + (62).to_bytes(2, "little") + b"original"
            binary.write_bytes(raw)
            receipt = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
            runner.checked_binary(binary, receipt, 62)
            with self.assertRaises(ValueError):
                runner.checked_binary(binary, receipt, 183)
            binary.write_bytes(raw[:-1] + b"X")
            with self.assertRaises(ValueError):
                runner.checked_binary(binary, receipt, 62)
            linked = Path(directory) / "linked-elf"
            linked.symlink_to(binary)
            with self.assertRaises(ValueError):
                runner.checked_binary(linked, receipt, 62)


if __name__ == "__main__":
    unittest.main()
