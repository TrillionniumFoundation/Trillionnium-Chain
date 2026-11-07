"""Portable-input integrity controls; synthetic metadata is not native evidence."""
from copy import deepcopy
from pathlib import Path
import hashlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_w1_quantum_oracle import fixture
from w1_machine_architecture import build_service_architecture, declared_architectures
from w1_marked_domain import enumerate_domain
from w1_quantum_oracle import Shape, canonical
from w1_native_bridge import declared_models
from w1_machine_calibration_campaign import (
    INPUT_SCHEMA, PROFILE, digest, load_input, observe, sources, verify, write_new,
)


class PortableCalibrationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        domain = enumerate_domain(fixture(Shape(), nonce_bits=3))
        classical, physical, lifecycle = declared_models()
        architecture = build_service_architecture((domain,), ((0, 1), (0, 1)), 1,
            (classical,), physical, lifecycle, declared_architectures()[2], 10**16, "4")
        cls.plan = {"schema": INPUT_SCHEMA, "profile": PROFILE, "source_sha256": sources(),
            "native_fixture_sha256": "3" * 64, "native_packets_checked_at_export": 33,
            "native_source": {"git_head": "0" * 40, "binary_sha256": "1" * 64,
                              "source_inventory_sha256": "2" * 64},
            "domain": domain, "architecture": architecture,
            "export_observation": {"cpu_ns": 0, "wall_ns": 0, "scope": "synthetic test metadata only", "quantum_execution": False},
            "export_claims": {"full_native_fixture_checked_at_export": True,
                              "native_fixture_validation_repeated_by_portable_reader": False,
                              "physical_calibration_provided": False}}
        cls.plan["plan_sha256"] = digest(cls.plan)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "input.json"
        write_new(self.input, self.plan)
        self.input_sha = hashlib.sha256(self.input.read_bytes()).hexdigest()

    def replace_plan(self, plan):
        plan["plan_sha256"] = digest({k: v for k, v in plan.items() if k != "plan_sha256"})
        self.input.write_bytes(canonical(plan) + b"\n")
        return hashlib.sha256(self.input.read_bytes()).hexdigest()

    def test_scalar_gap_reconstruction_never_promotes_synthetic_native_metadata(self):
        report = observe(self.input, self.input_sha)
        self.assertEqual(report["status"], "OBSERVED_HOLD")
        self.assertEqual(report["analysis"]["status"], "HOLD")
        self.assertEqual(len(report["analysis"]["missing_active_event_components"]), 9)
        self.assertTrue(all(value is False for value in report["claims"].values()))
        output = self.root / "report.json"
        write_new(output, report)
        sha = hashlib.sha256(output.read_bytes()).hexdigest()
        self.assertEqual(verify(self.input, self.input_sha, output, sha)["status"], "VERIFIED_HOLD")

    def test_source_changes_or_changed_caller_digest_fail_before_use(self):
        changed = deepcopy(self.plan)
        changed["source_sha256"][next(iter(changed["source_sha256"]))] = "9" * 64
        new_sha = self.replace_plan(changed)
        with self.assertRaisesRegex(ValueError, "INPUT_DIGEST"):
            load_input(self.input, self.input_sha)
        with self.assertRaisesRegex(ValueError, "SOURCE_OR_BODY"):
            load_input(self.input, new_sha)

    def test_rehashed_relaxed_deadline_and_boolean_schedule_cannot_change_profile(self):
        for key, value in (("horizon_seconds", "8"), ("processors", True),
                           ("schedule", [[False, True], [False, True]])):
            changed = deepcopy(self.plan)
            changed["architecture"]["machine_record"]["premises"][key] = value
            sha = self.replace_plan(changed)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "FROZEN_ALLOCATION"):
                load_input(self.input, sha)

    def test_portable_reader_cannot_adopt_native_execution_or_unidentified_binary(self):
        changed = deepcopy(self.plan)
        changed["export_claims"]["native_fixture_validation_repeated_by_portable_reader"] = True
        with self.assertRaisesRegex(ValueError, "NATIVE_SCOPE"):
            load_input(self.input, self.replace_plan(changed))
        changed = deepcopy(self.plan)
        changed["native_source"]["binary_sha256"] = "unknown"
        with self.assertRaisesRegex(ValueError, "NATIVE_IDENTITY"):
            load_input(self.input, self.replace_plan(changed))

    def test_report_digest_and_rehashed_physical_claims_are_both_checked(self):
        report = observe(self.input, self.input_sha)
        output = self.root / "report.json"
        write_new(output, report)
        original_sha = hashlib.sha256(output.read_bytes()).hexdigest()
        report["QPU_executed"] = True
        report["report_sha256"] = digest({k: v for k, v in report.items() if k != "report_sha256"})
        output.write_bytes(canonical(report) + b"\n")
        with self.assertRaisesRegex(ValueError, "REPORT_DIGEST"):
            verify(self.input, self.input_sha, output, original_sha)
        new_sha = hashlib.sha256(output.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "REPORT_BINDING"):
            verify(self.input, self.input_sha, output, new_sha)


if __name__ == "__main__":
    unittest.main()
