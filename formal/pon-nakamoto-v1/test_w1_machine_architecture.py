"""Allocation, history-conditional error and calibration-provenance controls."""
from copy import deepcopy
from dataclasses import replace
from decimal import Decimal
from fractions import Fraction
import hashlib
import unittest
from unittest.mock import patch

from quantum_oracle_resources import ClassicalCosts, example
from test_w1_machine_envelope import lifecycle_fixture
from test_w1_quantum_oracle import fixture
from w1_machine_architecture import (
    CALIBRATION_REQUIREMENTS, CALIBRATION_SCHEMA, ServiceArchitecture,
    build_service_architecture, declared_architectures, validate_calibration_manifest,
    verify_service_architecture,
)
from w1_machine_envelope import (RESERVED_SERVICE_SCHEMA, SCHEMA as ORIGINAL_SCHEMA,
                                  build_machine_envelope, machine_action_clock,
                                  verify_machine_envelope)
from w1_marked_domain import enumerate_domain
from w1_quantum_oracle import canonical


def fraction(value):
    return Fraction(**value)


class MachineFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.domain = enumerate_domain(fixture(nonce_bits=3))
        cls.cost = ClassicalCosts(11, 13, 17, 19, 23, 29)
        cls.physical = replace(example(True).physical_models[0], magic_state_error="1e-50", cycle_ns="1")
        cls.lifecycle = lifecycle_fixture()
        cls.architecture = ServiceArchitecture("control-ports", 7, 2, 3, 5, 11, 2, 4096)

    def build(self, *, architecture=None, schedule=((0, 0), (0, 1)), processors=2,
              deadline="4", budget=10**16, winners=1):
        return build_service_architecture((self.domain,), schedule, processors, (self.cost,),
            self.physical, self.lifecycle, self.architecture if architecture is None else architecture,
            budget, deadline, reserved_maximum_winners=winners)


class ServiceArchitectureTests(MachineFixture):
    def test_original_v1_shape_and_default_lifecycle_are_preserved(self):
        args = ((self.domain,), ((0, 0),), 1, (self.cost,), self.physical, self.lifecycle, 10**16, "4")
        old = build_machine_envelope(*args)
        zero = build_machine_envelope(*args, reserved_service_patches_per_processor=0)
        self.assertEqual(old["schema"], ORIGINAL_SCHEMA)
        self.assertEqual(zero["schema"], RESERVED_SERVICE_SCHEMA)
        self.assertNotIn("reserved_service_patches_per_processor", old["premises"])
        self.assertEqual(old["planned_rounds"], zero["planned_rounds"])
        self.assertEqual(old["ideal_schedule_probability"], zero["ideal_schedule_probability"])
        self.assertEqual(verify_machine_envelope(zero, (self.domain,)), zero)

    def test_every_auxiliary_patch_enters_allocation_initialization_and_full_live_error(self):
        record = self.build()
        machine, resources = record["machine_record"], record["resources"]
        envelope = machine["envelope"]
        peak, distance = envelope["logical_patches_reserved_and_initialized_per_processor"], envelope["code_distance_for_whole_schedule"]
        self.assertEqual(self.architecture.service_patches, 42)
        self.assertEqual(peak, envelope["oracle_logical_patches_per_processor"] + 42)
        self.assertEqual(envelope["events_all_processors"]["initialization_patches"], 2 * 2 * peak)
        self.assertEqual(resources["service_logical_patches"], 84)
        self.assertEqual(envelope["data_physical_qubits_per_processor"],
            envelope["oracle_data_physical_qubits_per_processor"] + envelope["service_physical_qubits_per_processor"])
        self.assertEqual(envelope["service_physical_qubits_per_processor"], 42 * self.physical.data_physical_qubits_per_d2 * distance**2)
        cycles = sum(distance * sum(row["cycles_per_distance_per_processor"].values())
                     + row["controller_fixed_cycles_per_processor"] for row in machine["planned_rounds"])
        self.assertEqual(envelope["live_data_patch_cycles_all_processors"], 2 * peak * cycles)
        self.assertEqual(fraction(envelope["failure_union_components_upper"]["live_data_patch_cycles"]),
                         2 * peak * cycles * fraction(envelope["logical_patch_cycle_fault_upper"]))
        self.assertLessEqual(fraction(envelope["whole_plan_failure_union_upper"]), Fraction(Decimal(self.physical.total_failure_budget)))

    def test_parallel_batch_clock_includes_auxiliaries_and_padded_port_slots(self):
        record = self.build(processors=3)
        machine, resources = record["machine_record"], record["resources"]
        peak = machine["envelope"]["logical_patches_reserved_and_initialized_per_processor"]
        distance = machine["envelope"]["code_distance_for_whole_schedule"]
        init = ((peak + 6) // 7) * self.lifecycle.initialization_cycles_per_distance
        readout = 2 * self.lifecycle.readout_cycles_per_distance
        for row in machine["planned_rounds"]:
            self.assertEqual(row["cycles_per_distance_per_processor"]["initialize"], init)
            self.assertEqual(row["cycles_per_distance_per_processor"]["terminal_readout"], readout)
        self.assertEqual(resources["initialization_port_code_cycles_reserved"], 3 * 7 * 2 * init * distance)
        self.assertEqual(resources["readout_port_code_cycles_reserved"], 3 * 2 * 2 * readout * distance)

    def test_whole_plan_channel_memory_and_cpu_reservations_are_not_refunded_at_deadline(self):
        early, late = self.build(deadline="0", winners=2), self.build(deadline="1e25", winners=2)
        self.assertEqual(early["resources"], late["resources"])
        resources, machine = early["resources"], early["machine_record"]
        expected = sum(fraction(row["search_seconds_exact"]) for row in machine["planned_rounds"])
        expected += 2 * max(fraction(row["winner_seconds_exact"]) for row in machine["planned_rounds"])
        self.assertEqual(fraction(resources["complete_plan_seconds_reserved"]), expected)
        self.assertEqual(fraction(resources["initialization_port_seconds_reserved"]), expected * 14)
        self.assertEqual(fraction(resources["controller_core_seconds_reserved"]), expected * 4)
        self.assertEqual(fraction(resources["controller_memory_byte_seconds_reserved"]), expected * 8192)
        for key in ("measured_complete_machine_energy_joules", "calibrated_capital_and_operating_cost",
                    "compiled_controller_peak_memory_bytes"):
            self.assertIsNone(resources[key])

    def test_ports_do_not_change_factory_noise_budget_or_other_service_parameters(self):
        record = self.build(architecture=declared_architectures()[2])
        p = record["machine_record"]["premises"]
        self.assertEqual(p["physical_model"]["total_failure_budget"], self.physical.total_failure_budget)
        self.assertEqual(p["physical_qubit_budget"], 10**16)
        self.assertEqual(p["horizon_seconds"], "4")
        original = record["original_lifecycle_model"]
        for name in original:
            if name not in ("name", "initialization_parallel_patches", "readout_parallel_bits"):
                self.assertEqual(original[name], p["lifecycle_model"][name])
        self.assertTrue(all(value is False for value in record["claims"].values()))

    def test_action_clock_uses_same_auxiliary_peak_and_distance(self):
        record = self.build()["machine_record"]
        row = machine_action_clock(record, 0, 0, resident_setup=True)
        self.assertEqual(row["logical_patches_reserved_per_processor"],
                         record["envelope"]["logical_patches_reserved_and_initialized_per_processor"])
        self.assertEqual(row["code_distance_for_whole_schedule"], record["envelope"]["code_distance_for_whole_schedule"])

    def test_exact_qubit_cap_includes_service_hardware(self):
        required = self.build()["resources"]["physical_qubits"]
        self.assertEqual(self.build(budget=required)["resources"]["physical_qubits"], required)
        with self.assertRaisesRegex(ValueError, "INSUFFICIENT_PHYSICAL_QUBITS"):
            self.build(budget=required - 1)

    def test_reconstruction_rejects_rehashed_omitted_ports_memory_and_auxiliary_faults(self):
        record = self.build(schedule=((0, 0),))
        self.assertEqual(verify_service_architecture(record, (self.domain,)), record)
        for kind in ("ports", "memory", "service_fault", "hardware_claim", "binding"):
            altered = deepcopy(record)
            if kind == "ports":
                altered["resources"]["initialization_service_ports"] = 0
            elif kind == "memory":
                altered["resources"]["controller_memory_byte_seconds_reserved"] = {"numerator": 0, "denominator": 1}
            elif kind == "service_fault":
                altered["machine_record"]["envelope"]["service_logical_patches_per_processor"] = 0
            elif kind == "hardware_claim":
                altered["claims"]["physical_parameters_calibrated"] = True
            else:
                altered["calibration_binding_sha256"] = "0" * 64
            altered["record_sha256"] = hashlib.sha256(canonical({k: v for k, v in altered.items() if k != "record_sha256"})).hexdigest()
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "REPLAY_MISMATCH"):
                verify_service_architecture(altered, (self.domain,))

    def test_invalid_architecture_or_auxiliary_reservations_rejected_before_census(self):
        with patch("w1_machine_envelope.replay_domain", side_effect=AssertionError("census")):
            for name in ServiceArchitecture.__dataclass_fields__:
                if name == "name":
                    continue
                for value in (True, 0, -1, 1.0):
                    with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                        self.build(architecture=replace(self.architecture, **{name: value}))
            for reserve in (True, -1, 1.0, 10**12 + 1):
                with self.assertRaises(ValueError):
                    build_machine_envelope((self.domain,), ((0, 0),), 1, (self.cost,), self.physical,
                        self.lifecycle, 10**16, "4", reserved_service_patches_per_processor=reserve)


class CalibrationProvenanceTests(MachineFixture):
    def manifest(self):
        record = self.build(schedule=((0, 0),))
        raw = b"A unit-test statement; this is deliberately not measured hardware evidence."
        sha = hashlib.sha256(raw).hexdigest()
        manifest = {"schema": CALIBRATION_SCHEMA, "target_binding_sha256": record["calibration_binding_sha256"],
            "hardware_id": "unverified-test-fixture", "recorded_at_unix_seconds": 1000,
            "valid_until_unix_seconds": 2000,
            "artifacts": [{"sha256": sha, "bytes": len(raw), "provenance": "unit-test fixture"}],
            "coverage": [{"requirement": name, "artifact_sha256": sha,
                          "statement": "Unverified claim covering the declared target parameters."}
                         for name in CALIBRATION_REQUIREMENTS]}
        return record, manifest, {sha: raw}

    def check(self, record, manifest, artifacts, **kwargs):
        return validate_calibration_manifest(record, manifest, artifacts,
            now_unix_seconds=kwargs.get("now", 1500), maximum_age_seconds=kwargs.get("age", 1000))

    def test_complete_provenance_never_qualifies_unverified_physical_claims(self):
        result = self.check(*self.manifest())
        self.assertEqual(result["status"], "PROVENANCE_AND_COVERAGE_ONLY")
        self.assertEqual(set(result["coverage"]), set(CALIBRATION_REQUIREMENTS))
        for key in ("artifact_authenticity_or_claim_truth_verified", "conditional_error_bounds_established",
                    "calibrated_complete_machine_cost_closed", "quantum_hardware_executed_by_reader",
                    "quantum_mining_qualified"):
            self.assertIs(result[key], False)

    def test_missing_duplicate_wrong_and_unbound_coverage_refused(self):
        for kind in ("missing", "duplicate", "unknown", "unbound", "empty_statement"):
            record, manifest, artifacts = self.manifest()
            if kind == "missing":
                manifest["coverage"].pop()
            elif kind == "duplicate":
                manifest["coverage"][-1] = deepcopy(manifest["coverage"][0])
            elif kind == "unknown":
                manifest["coverage"][0]["requirement"] = "zero-failures-implies-zero-risk"
            elif kind == "unbound":
                manifest["coverage"][0]["artifact_sha256"] = "0" * 64
            else:
                manifest["coverage"][0]["statement"] = ""
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.check(record, manifest, artifacts)

    def test_wrong_target_stale_future_and_boolean_times_refused(self):
        for kind in ("target", "stale", "future", "expired", "bool"):
            record, manifest, artifacts = self.manifest()
            if kind == "target":
                manifest["target_binding_sha256"] = "0" * 64
            elif kind == "stale":
                manifest["recorded_at_unix_seconds"] = 1
            elif kind == "future":
                manifest["recorded_at_unix_seconds"] = 1501
            elif kind == "expired":
                manifest["valid_until_unix_seconds"] = 1499
            else:
                manifest["recorded_at_unix_seconds"] = True
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.check(record, manifest, artifacts)

    def test_changed_artifact_bytes_extra_artifacts_and_self_asserted_qualification_refused(self):
        for kind in ("bytes", "extra", "claim", "size"):
            record, manifest, artifacts = self.manifest()
            sha = next(iter(artifacts))
            if kind == "bytes":
                artifacts[sha] = b"x" * len(artifacts[sha])
            elif kind == "extra":
                artifacts["0" * 64] = b"not declared"
            elif kind == "claim":
                manifest["physical_parameters_calibrated"] = True
            else:
                manifest["artifacts"][0]["bytes"] += 1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.check(record, manifest, artifacts)

    def test_wrong_source_and_changed_architecture_report_refused(self):
        record, manifest, artifacts = self.manifest()
        for field in ("source_sha256", "resources"):
            altered = deepcopy(record)
            if field == "source_sha256":
                altered[field]["formal/pon-nakamoto-v1/w1_machine_architecture.py"] = "0" * 64
            else:
                altered[field]["physical_qubits"] += 1
            with self.assertRaisesRegex(ValueError, "TARGET_NOT_CURRENT"):
                self.check(altered, manifest, artifacts)


if __name__ == "__main__":
    unittest.main()
