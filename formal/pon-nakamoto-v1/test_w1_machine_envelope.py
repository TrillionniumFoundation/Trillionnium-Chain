"""Constructed-event, deadline, full-budget and replay controls for machine envelopes."""
from copy import deepcopy
from dataclasses import replace
from decimal import Decimal
from fractions import Fraction
import hashlib
import unittest
from unittest.mock import patch

from quantum_oracle_resources import ClassicalCosts, example
from test_w1_quantum_oracle import fixture
from w1_machine_envelope import (LifecycleModel, NOISE_CONTRACT, build_machine_envelope,
                                  machine_action_clock, verify_machine_envelope)
from w1_marked_domain import enumerate_domain
from w1_quantum_oracle import OracleProgram, canonical
from w1_quantum_restricted_oracle import PrefixRestrictedProgram


def fraction(value):
    return Fraction(**value)


def lifecycle_fixture():
    return LifecycleModel(
        name="hypothetical-lifecycle-control", noise_contract=NOISE_CONTRACT,
        initialization_cycles_per_distance=2, initialization_parallel_patches=7,
        readout_cycles_per_distance=3, readout_parallel_bits=2,
        controller_cycles_per_command=2, transfer_fixed_ns=5, transfer_ns_per_byte=3,
        factory_startup_cycles_per_distance=11, factory_attempts_per_state=16,
        factory_discard_reset_cycles_per_distance=13,
        factory_reject_probability_bound="0.01", initialization_failure_bound="1e-40",
        readout_failure_bound="1e-40", transfer_byte_failure_bound="1e-40",
        controller_command_failure_bound="1e-50", host_call_failure_bound="1e-30",
        propagation_failure_bound="1e-30")


class MachineEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.templates = (fixture(nonce_bits=3), fixture(profile="PGH2", nonce_bits=2))
        cls.domains = tuple(enumerate_domain(value) for value in cls.templates)
        cls.costs = ClassicalCosts(11, 13, 17, 19, 23, 29)
        cls.model = replace(example(True).physical_models[0], magic_state_error="1e-50", cycle_ns="1")
        cls.lifecycle = lifecycle_fixture()
        cls.budget = 1 << 120

    def build(self, *, domains=None, schedule=((0, 1),), processors=2,
              costs=None, model=None, lifecycle=None, budget=None, deadline="1e25", predicate="full",
              winners=1):
        domains = (self.domains[0],) if domains is None else domains
        return build_machine_envelope(
            domains, schedule, processors, tuple(self.costs for _ in domains) if costs is None else costs,
            self.model if model is None else model, self.lifecycle if lifecycle is None else lifecycle,
            self.budget if budget is None else budget, deadline, predicate=predicate,
            reserved_maximum_winners=winners)

    def test_resource_identity_and_both_accepted_sets_come_from_real_construction(self):
        for predicate, constructor, phase_count in (("full", OracleProgram, 8),
                                                   ("prefix-restricted", PrefixRestrictedProgram, 2)):
            record = self.build(predicate=predicate)
            row = record["domain_resources"][0]
            real = constructor(self.templates[0]).resources()
            self.assertEqual(row["construction_sha256"], real["construction_sha256"])
            self.assertEqual(row["logical_qubits"], real["logical_qubits"])
            self.assertEqual(row["phase_marked_count"], phase_count)
            self.assertEqual(row["full_w1_accepted_count"], 8)
            self.assertEqual(row["iteration_gate_commands"], real["phase_oracle_gate_count"] + real["diffusion"]["gate_count"])
            packet = canonical(self.templates[0].spec())
            self.assertEqual(row["controller_input_bytes"], len(packet))
            self.assertEqual(row["controller_input_sha256"], hashlib.sha256(packet).hexdigest())

    def test_all_processors_retries_discards_init_and_readout_are_charged_for_full_plan(self):
        processors = 3
        record = self.build(schedule=((0, 0), (0, 2)), processors=processors)
        envelope, rows = record["envelope"], record["planned_rounds"]
        events = envelope["events_all_processors"]
        peak = envelope["logical_patches_reserved_and_initialized_per_processor"]
        self.assertEqual(events["initialization_patches"], 2 * processors * peak)
        self.assertEqual(events["readout_bits"], 2 * processors * 3)
        self.assertEqual(events["factory_attempt_slots"], events["magic_state_services"] * 16)
        self.assertEqual(events["factory_discard_reset_slots"], events["factory_attempt_slots"])
        self.assertEqual(events["factory_startups"], processors)
        for row in rows:
            cycles = row["cycles_per_distance_per_processor"]
            self.assertEqual(cycles["initialize"], ((peak + 6) // 7) * 2)
            self.assertEqual(cycles["terminal_readout"], 6)
            self.assertEqual(cycles["factory_discard_reset"], row["factory_attempt_slots_per_processor"] * 13)
            self.assertEqual(cycles["factory_attempt_service"], row["factory_attempt_slots_per_processor"]
                             * self.model.factory_t_cycles_per_distance)
        self.assertEqual(events["propagations"], 1)
        self.assertEqual(events["host_calls_including_reserved_proofs"], (1 + processors) + 2 * processors * 2 + 1)

    def test_same_resident_reuses_input_but_not_quantum_initialization_or_nonce_transfer(self):
        domains = (self.domains[0], deepcopy(self.domains[0]), self.domains[1])
        record = self.build(domains=domains, schedule=((0, 0), (1, 0), (2, 0), (0, 0)), processors=3)
        rows = record["planned_rounds"]
        self.assertEqual([row["resident_setup_charged"] for row in rows], [True, False, True, True])
        self.assertEqual(rows[1]["classical_nanoseconds"]["input_transfer"], 0)
        self.assertEqual(rows[0]["classical_nanoseconds"]["processor_setup"], 39)
        for row in rows:
            self.assertGreater(row["cycles_per_distance_per_processor"]["initialize"], 0)
            self.assertGreater(row["classical_nanoseconds"]["output_transfer"], 0)
            self.assertEqual(row["classical_nanoseconds"]["candidate_checks"], 57)
            self.assertEqual(row["classical_nanoseconds"]["host_readout_turnaround"], 17)
        expected_bytes = sum(row["input_bytes_all_processors"] + row["output_bytes_all_processors"] for row in rows)
        self.assertEqual(record["envelope"]["events_all_processors"]["transfer_bytes"], expected_bytes)

    def test_error_union_includes_controller_waits_and_all_live_patch_cycles_at_one_distance(self):
        processors = 3
        record = self.build(domains=self.domains, schedule=((0, 0), (1, 1), (0, 3)), processors=processors)
        envelope = record["envelope"]
        distance = envelope["code_distance_for_whole_schedule"]
        peak = envelope["logical_patches_reserved_and_initialized_per_processor"]
        cycles = sum(sum(row["cycles_per_distance_per_processor"].values()) * distance
                     + row["controller_fixed_cycles_per_processor"] for row in record["planned_rounds"])
        self.assertEqual(envelope["live_data_patch_cycles_all_processors"], peak * cycles * processors)
        physical_ratio = Fraction(Decimal(self.model.physical_error)) / Fraction(Decimal(self.model.threshold))
        exact_patch_error = Fraction(Decimal(self.model.logical_error_prefactor)) * physical_ratio**((distance + 1)//2)
        self.assertGreaterEqual(fraction(envelope["logical_patch_cycle_fault_upper"]), exact_patch_error)
        pieces = {key: fraction(value) for key, value in envelope["failure_union_components_upper"].items()}
        self.assertEqual(sum(pieces.values()), fraction(envelope["whole_plan_failure_union_upper"]))
        self.assertLessEqual(sum(pieces.values()), Fraction(Decimal(self.model.total_failure_budget)))
        self.assertEqual(pieces["live_data_patch_cycles"], peak * cycles * processors
                         * fraction(envelope["logical_patch_cycle_fault_upper"]))
        services = envelope["events_all_processors"]["magic_state_services"]
        self.assertGreaterEqual(pieces["factory_attempts_exhausted"], services * Fraction(1, 100)**16)
        self.assertEqual(pieces["accepted_magic_state_service"], services * Fraction(1, 10**50))
        if distance > 3:
            prior = distance - 2
            prior_cycles = sum(sum(row["cycles_per_distance_per_processor"].values()) * prior
                               + row["controller_fixed_cycles_per_processor"] for row in record["planned_rounds"])
            prior_error = peak * prior_cycles * processors * Fraction(Decimal(self.model.logical_error_prefactor)) * physical_ratio**((prior + 1)//2)
            self.assertGreater(prior_error + sum(pieces.values()) - pieces["live_data_patch_cycles"],
                               Fraction(Decimal(self.model.total_failure_budget)))

    def test_all_lifecycle_quantum_seconds_and_serial_host_seconds_enter_deadline(self):
        record = self.build(schedule=((0, 0),), processors=3)
        row = record["planned_rounds"][0]
        quantum = sum(fraction(value) for value in row["quantum_phase_seconds_exact"].values())
        classical = sum(fraction(value) for value in row["classical_phase_seconds_exact"].values())
        self.assertEqual(fraction(row["search_seconds_exact"]) + fraction(row["winner_seconds_exact"]), quantum + classical)
        finish = quantum + classical
        ns = finish * 10**9
        self.assertEqual(ns.denominator, 1)
        exact_deadline = str(Decimal(ns.numerator) / Decimal(10**9))
        at = self.build(schedule=((0, 0),), processors=3, deadline=exact_deadline)
        before = self.build(schedule=((0, 0),), processors=3,
                            deadline=str(Decimal(ns.numerator - 1) / Decimal(10**9)))
        self.assertEqual(fraction(at["ideal_schedule_probability"]["delivery_probability"]["lower"]), 1)
        self.assertEqual(fraction(before["ideal_schedule_probability"]["delivery_probability"]["upper"]), 0)
        self.assertGreater(fraction(at["conditional_machine_delivery_probability"]["lower"]), 0)
        self.assertLess(fraction(at["conditional_machine_delivery_probability"]["lower"]), 1)

    def test_deadline_and_early_winner_never_shrink_full_plan_hardware_or_error_envelope(self):
        schedule = ((0, 0), (0, 100_000_000), (0, 1))
        early = self.build(schedule=schedule, deadline="0", predicate="prefix-restricted")
        later = self.build(schedule=schedule, deadline="1e25", predicate="prefix-restricted")
        for key in ("envelope", "planned_rounds", "domain_resources"):
            self.assertEqual(early[key], later[key])
        self.assertEqual(fraction(early["ideal_schedule_probability"]["delivery_probability"]["upper"]), 0)
        self.assertEqual(fraction(later["ideal_schedule_probability"]["delivery_probability"]["lower"]), 1)
        for key in ("physical_parameters_calibrated", "fault_tolerant_layout_and_controller_compiled",
                    "empirical_zero_failures_interpreted_as_zero_risk", "quantum_hardware_executed",
                    "native_block_admission_verified", "minimum_attacker_cost_proved",
                    "complete_energy_or_economic_machine_cost", "quantum_mining_qualified", "production_activation"):
            self.assertIs(later[key], False)

    def test_qubit_cap_exact_equality_and_one_below(self):
        required = self.build(processors=4)["envelope"]["physical_qubits_all_processors"]
        self.assertEqual(self.build(processors=4, budget=required)["envelope"]["physical_qubits_all_processors"], required)
        with self.assertRaisesRegex(ValueError, "MACHINE_INSUFFICIENT_PHYSICAL_QUBITS"):
            self.build(processors=4, budget=required - 1)

    def test_fixed_lifecycle_faults_and_factory_exhaustion_cannot_be_ignored_or_reset(self):
        for changes in ({"readout_failure_bound": "0.1"},
                        {"initialization_failure_bound": "0.01"},
                        {"controller_command_failure_bound": "0.1"},
                        {"host_call_failure_bound": "0.01"},
                        {"propagation_failure_bound": self.model.total_failure_budget},
                        {"factory_reject_probability_bound": "0.5", "factory_attempts_per_state": 1}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "FIXED_EVENT_ERROR_BUDGET"):
                self.build(lifecycle=replace(self.lifecycle, **changes))
        with self.assertRaisesRegex(ValueError, "NO_DISTANCE_FOR_WHOLE_PLAN"):
            self.build(model=replace(self.model, maximum_distance=3))

    def test_controller_waits_and_finite_retry_reset_latency_are_not_free(self):
        base = self.build()
        slower = self.build(lifecycle=replace(self.lifecycle, controller_cycles_per_command=500,
                                              factory_discard_reset_cycles_per_distance=1000))
        self.assertGreater(fraction(slower["planned_rounds"][0]["search_seconds_exact"]),
                           fraction(base["planned_rounds"][0]["search_seconds_exact"]))
        self.assertGreater(slower["envelope"]["live_data_patch_cycles_all_processors"],
                           base["envelope"]["live_data_patch_cycles_all_processors"])

    def test_multiple_winner_error_reservation_is_explicit_and_does_not_change_probability_policy(self):
        once = self.build(schedule=((0, 0), (0, 0)), winners=1)
        twice = self.build(schedule=((0, 0), (0, 0)), winners=2)
        a, b = once["envelope"], twice["envelope"]
        for key in ("proofs_reserved", "propagations", "host_calls_including_reserved_proofs"):
            self.assertEqual(b["events_all_processors"][key] - a["events_all_processors"][key], 1)
        increase = Fraction(Decimal(self.lifecycle.host_call_failure_bound)) + Fraction(Decimal(self.lifecycle.propagation_failure_bound))
        self.assertEqual(fraction(b["whole_plan_failure_union_upper"]) - fraction(a["whole_plan_failure_union_upper"]), increase)
        self.assertEqual(once["ideal_schedule_probability"], twice["ideal_schedule_probability"])
        self.assertTrue(b["probability_scope_remains_first_winner_delivery"])
        self.assertEqual(verify_machine_envelope(twice, (self.domains[0],)), twice)

    def test_action_clock_keeps_common_distance_and_prices_zero_iterations_without_factory_startup(self):
        record = self.build(schedule=((0, 3), (0, 3)), winners=2)
        zero = machine_action_clock(record, 0, 0, resident_setup=True)
        one = machine_action_clock(record, 0, 1, resident_setup=True)
        reused = machine_action_clock(record, 0, 1, resident_setup=False)
        whole = machine_action_clock(record, 0, 3, resident_setup=True)
        expected_distance = record["envelope"]["code_distance_for_whole_schedule"]
        self.assertEqual(zero["code_distance_for_whole_schedule"], expected_distance)
        self.assertEqual(one["code_distance_for_whole_schedule"], expected_distance)
        self.assertEqual(zero["t_states_per_processor"], 0)
        self.assertEqual(zero["cycles_per_distance_per_processor"]["factory_startup"], 0)
        self.assertEqual(zero["cycles_per_distance_per_processor"]["factory_discard_reset"], 0)
        self.assertGreater(one["cycles_per_distance_per_processor"]["factory_startup"], 0)
        self.assertEqual(reused["classical_nanoseconds"]["input_transfer"], 0)
        self.assertEqual(reused["cycles_per_distance_per_processor"]["initialize"], one["cycles_per_distance_per_processor"]["initialize"])
        self.assertLess(fraction(zero["search_seconds_exact"]), fraction(one["search_seconds_exact"]))
        self.assertLess(fraction(reused["search_seconds_exact"]), fraction(one["search_seconds_exact"]))
        self.assertEqual(whole["search_seconds_exact"], record["planned_rounds"][0]["search_seconds_exact"])
        self.assertFalse(one["cumulative_action_sequence_coverage_checked"])
        for index, count, residency in ((0, 4, True), (1, 0, True), (0, True, True), (0, 1, 1)):
            with self.assertRaises(ValueError):
                machine_action_clock(record, index, count, resident_setup=residency)
        changed = deepcopy(record)
        changed["envelope"]["code_distance_for_whole_schedule"] = 3
        with self.assertRaisesRegex(ValueError, "SOURCE_OR_RECORD_CHANGED"):
            machine_action_clock(changed, 0, 1, resident_setup=True)

    def test_record_replay_rejects_counts_probabilities_hardware_claims_and_rehashed_tampering(self):
        record = self.build(schedule=((0, 0),), predicate="prefix-restricted")
        self.assertEqual(verify_machine_envelope(record, (self.domains[0],)), record)
        for kind in ("events", "probability", "claims", "round", "source"):
            forged = deepcopy(record)
            if kind == "events":
                forged["envelope"]["events_all_processors"]["initialization_patches"] = 0
            elif kind == "probability":
                forged["conditional_machine_delivery_probability"]["lower"] = {"numerator": 1, "denominator": 1}
            elif kind == "claims":
                forged["physical_parameters_calibrated"] = True
            elif kind == "round":
                forged["planned_rounds"][0]["classical_nanoseconds"]["input_transfer"] = 0
            else:
                forged["source_sha256"]["formal/pon-nakamoto-v1/w1_machine_envelope.py"] = "0" * 64
            forged.pop("record_sha256")
            forged["record_sha256"] = hashlib.sha256(canonical(forged)).hexdigest()
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "MACHINE_REPLAY_MISMATCH"):
                verify_machine_envelope(forged, (self.domains[0],))

    def test_invalid_contract_shapes_probability_metadata_and_horizon_refused_before_census(self):
        with patch("w1_machine_envelope.replay_domain", side_effect=AssertionError("expensive census")):
            for changes in ({"noise_contract": "independent-marginal-rejections"},
                            {"factory_attempts_per_state": True}, {"readout_parallel_bits": 0},
                            {"factory_reject_probability_bound": "1"},
                            {"host_call_failure_bound": 0.0}, {"transfer_ns_per_byte": False}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    self.build(lifecycle=replace(self.lifecycle, **changes))
            for changes in ({"processors": True}, {"schedule": ((False, 0),)}, {"deadline": "NaN"},
                            {"predicate": False}, {"budget": False},
                            {"winners": True}, {"winners": 0}, {"winners": 2},
                            {"model": replace(self.model, t_per_toffoli=1, t_depth_per_toffoli=3)}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    self.build(**changes)


if __name__ == "__main__":
    unittest.main()
