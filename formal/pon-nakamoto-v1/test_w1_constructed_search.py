"""Actual constructed counts, whole-schedule provisioning and exact clock controls."""
from copy import deepcopy
from dataclasses import asdict, replace
from decimal import Decimal
from fractions import Fraction
import unittest
from unittest.mock import patch

from quantum_oracle_resources import ClassicalCosts, Workload, example
from quantum_resource_clock import stage_units
from test_w1_quantum_oracle import fixture
from w1_constructed_search import (
    bind_constructed_search, run_constructed_search, verify_constructed_binding,
    verify_constructed_search,
)
from w1_marked_domain import enumerate_domain
from w1_quantum_oracle import FixedTemplate, OracleProgram, Shape
from w1_quantum_restricted_oracle import PrefixRestrictedProgram


def fraction(value):
    return Fraction(value["numerator"], value["denominator"])


class ConstructedSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = fixture(nonce_bits=3)
        cls.domain = enumerate_domain(cls.template)
        header = bytearray(cls.template.header)
        header[118:150] = (1).to_bytes(32, "big")
        cls.empty_template = FixedTemplate.from_header(
            bytes(header), cls.template.a, cls.template.b, 3, cls.template.shape)
        cls.empty = enumerate_domain(cls.empty_template)
        cls.other_template = fixture(profile="PGH2", nonce_bits=2)
        cls.other = enumerate_domain(cls.other_template)
        cls.classical = ClassicalCosts(11, 13, 17, 19, 23, 29)
        cls.model = replace(example(True).physical_models[0], magic_state_error="0")
        cls.budget = 1 << 100
        assert cls.domain["marked_count"] == 8
        assert cls.domain["prefix_restricted_marked_count"] == 2
        assert cls.empty["marked_count"] == 0

    def binding(self, *, domains=None, schedule=((0, 1),), processors=2,
                classical=None, model=None, budget=None, predicate="full"):
        domains = (self.domain,) if domains is None else domains
        return bind_constructed_search(
            domains, schedule, processors,
            tuple(self.classical for _ in domains) if classical is None else classical,
            self.model if model is None else model,
            self.budget if budget is None else budget, predicate=predicate)

    def test_counts_come_from_full_and_restricted_constructors_and_preserve_both_sets(self):
        for predicate, constructor, marked in (("full", OracleProgram, 8),
                                               ("prefix-restricted", PrefixRestrictedProgram, 2)):
            with self.subTest(predicate=predicate):
                binding = self.binding(predicate=predicate)
                row = binding.certificate["domain_resources"][0]
                actual = constructor(self.template).resources()
                self.assertEqual(row["construction_sha256"], actual["construction_sha256"])
                self.assertEqual(row["forward_gate_count"], actual["forward_gate_count"])
                self.assertEqual(row["phase_oracle_gate_count"], actual["phase_oracle_gate_count"])
                self.assertEqual(row["logical_qubits"], actual["logical_qubits"])
                self.assertEqual(row["phase_marked_count"], marked)
                self.assertEqual(row["full_w1_accepted_count"], 8)
                self.assertEqual(row["phase_predicate"], predicate)
                self.assertEqual(binding.certificate["final_candidate_check_predicate"], "full-literal-W1")

    def test_whole_schedule_cycles_t_states_and_distance_match_independent_reconstruction(self):
        schedule = ((0, 0), (1, 3), (0, 2))
        processors = 3
        binding = self.binding(domains=(self.domain, self.other), schedule=schedule, processors=processors)
        certificate = binding.certificate
        expected_cycles = expected_states = 0
        peak = 0
        units = []
        for template in (self.template, self.other_template):
            program = OracleProgram(template)
            request = program.resource_request(Workload(1, 1, processors, 1, 0, (), 0), self.classical)
            actual = {name: stage_units(circuit, self.model) for name, circuit in request.circuits.items()}
            units.append(actual)
            peak = max(peak, program.resources()["logical_qubits"])
        for index, count in schedule:
            stages = units[index]
            expected_cycles += stages["prepare"]["serial_cycles_per_distance"] + count * (
                2 * stages["winner_compute"]["serial_cycles_per_distance"]
                + stages["phase_marker"]["serial_cycles_per_distance"]
                + stages["diffusion"]["serial_cycles_per_distance"])
            expected_states += stages["prepare"]["t_states"] + count * (
                2 * stages["winner_compute"]["t_states"] + stages["phase_marker"]["t_states"]
                + stages["diffusion"]["t_states"])
        distance = certificate["code_distance_for_whole_schedule"]
        self.assertEqual(certificate["envelope"]["serial_cycles_per_processor"], expected_cycles * distance)
        self.assertEqual(certificate["envelope"]["t_states_all_processors"], expected_states * processors)
        self.assertEqual(certificate["envelope"]["planned_iterations_per_processor"], 5)
        ratio = Fraction(Decimal(self.model.physical_error)) / Fraction(Decimal(self.model.threshold))
        prefactor = Fraction(Decimal(self.model.logical_error_prefactor))
        def error(d):
            return peak * expected_cycles * d * processors * prefactor * ratio ** ((d + 1) // 2)
        self.assertEqual(fraction(certificate["whole_schedule_failure_union_exact"]), error(distance))
        self.assertLessEqual(error(distance), Fraction(Decimal(self.model.total_failure_budget)))
        if distance > 3:
            self.assertGreater(error(distance - 2), Fraction(Decimal(self.model.total_failure_budget)))

    def test_upward_clocks_include_every_processor_setup_and_separate_propagation(self):
        binding = self.binding(processors=3, model=replace(self.model, cycle_ns="0.123456789012345678901"))
        row = binding.certificate["domain_resources"][0]
        self.assertEqual(fraction(row["clock_seconds_exact"]["domain_setup_seconds"]), Fraction(50, 10**9))
        self.assertEqual(fraction(row["clock_seconds_exact"]["propagation_seconds"]), Fraction(29, 10**9))
        for name, exact in row["clock_seconds_exact"].items():
            clock = row["clock_seconds_float_upper"][name]
            self.assertGreaterEqual(Fraction(clock), fraction(exact))
            if name != "propagation_seconds":
                self.assertEqual(getattr(binding.costs[0], name), clock)
        self.assertEqual(binding.propagation_seconds, (row["clock_seconds_float_upper"]["propagation_seconds"],))
        self.assertEqual(binding.costs[0].clock_rounding, "upward")

    def test_all_processor_qubits_budget_equality_and_one_below(self):
        binding = self.binding(processors=3)
        certificate = binding.certificate
        total = certificate["physical_qubits_all_processors"]
        self.assertEqual(total, 3 * (certificate["data_physical_qubits_per_processor"]
                                   + certificate["factory_physical_qubits_per_processor"]))
        self.assertEqual(self.binding(processors=3, budget=total).certificate["physical_qubits_all_processors"], total)
        with self.assertRaisesRegex(ValueError, "INSUFFICIENT_PHYSICAL_QUBITS"):
            self.binding(processors=3, budget=total - 1)

    def test_magic_budget_and_maximum_distance_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "SCHEDULE_MAGIC_STATE_ERROR_BUDGET"):
            self.binding(model=replace(self.model, magic_state_error="0.001"))
        with self.assertRaisesRegex(ValueError, "NO_DISTANCE_FOR_PLANNED_SCHEDULE"):
            self.binding(model=replace(self.model, maximum_distance=3))

    def test_constructed_clock_rejects_t_layers_exceeding_count_before_replay(self):
        with patch("w1_constructed_search.replay_domain", side_effect=AssertionError("expensive replay")):
            with self.assertRaisesRegex(ValueError, "TOFFOLI_T_DEPTH_EXCEEDS_T_COUNT"):
                self.binding(model=replace(self.model, t_per_toffoli=1, t_depth_per_toffoli=3))

    def test_declared_classical_waits_do_not_claim_coherent_error_coverage(self):
        original = self.binding()
        slow = self.binding(classical=(replace(self.classical, per_winner_proof_ns=10**18),))
        for key in ("whole_schedule_failure_union_exact", "code_distance_for_whole_schedule", "envelope"):
            self.assertEqual(original.certificate[key], slow.certificate[key])
        self.assertNotEqual(original.costs[0].proof_seconds, slow.costs[0].proof_seconds)
        for key in ("coherent_state_during_classical_waits", "physical_model_is_calibration",
                    "fault_tolerant_schedule_verified", "end_to_end_machine_failure_bound",
                    "attacker_minimum_cost_proved", "native_node_admission_checked",
                    "quantum_mining_qualified", "production_activation"):
            self.assertFalse(original.certificate[key])
        self.assertIn("readout", original.certificate["failure_budget_scope"])
        self.assertFalse(original.certificate["census_replay_and_observer_cost_charged_to_miner"])

    def test_source_bound_literal_census_and_cost_binding_tampering_are_rejected(self):
        forged = deepcopy(self.domain)
        forged["marked_count"] = 0
        with self.assertRaisesRegex(ValueError, "CENSUS_REPLAY_MISMATCH"):
            self.binding(domains=(forged,))
        binding = self.binding()
        args = ((self.domain,), ((0, 1),), 2, (self.classical,), self.model, self.budget)
        verify_constructed_binding(binding, *args)
        changed = replace(binding, costs=(replace(binding.costs[0], iteration_seconds=1),))
        with self.assertRaisesRegex(ValueError, "CONSTRUCTED_BINDING_MISMATCH"):
            verify_constructed_binding(changed, *args)
        changed = deepcopy(binding)
        changed.certificate["quantum_mining_qualified"] = True
        with self.assertRaisesRegex(ValueError, "CONSTRUCTED_BINDING_MISMATCH"):
            verify_constructed_binding(changed, *args)

    def test_input_shapes_rejected_before_census_or_construction(self):
        with patch("w1_constructed_search.replay_domain", side_effect=AssertionError("expensive replay")):
            for kwargs in ({"processors": True}, {"schedule": ((True, 0),)},
                           {"schedule": ((0, False),)}, {"schedule": [[0, 0]]},
                           {"predicate": True}, {"classical": (asdict(self.classical),)},
                           {"classical": (replace(self.classical, per_trial_reset_readout_ns=0),)},
                           {"budget": True}):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    self.binding(**kwargs)
            for seed, deadline in ((True, "1"), (1, 1), (1, "NaN"), (-1, "1")):
                with self.subTest(seed=seed, deadline=deadline), self.assertRaises(ValueError):
                    run_constructed_search((self.domain,), ((0, 0),), 1, seed,
                                           (self.classical,), self.model, self.budget, deadline)

    def test_horizon_and_early_success_leave_full_plan_provisioning_unchanged(self):
        schedule = ((0, 0), (0, 10**8), (0, 100))
        args = ((self.domain,), schedule, 2, 7, (self.classical,), self.model, self.budget)
        stopped = run_constructed_search(*args, "0", predicate="prefix-restricted")
        delivered = run_constructed_search(*args, "1e25", predicate="prefix-restricted")
        self.assertEqual(stopped["binding"], delivered["binding"])
        self.assertEqual(stopped["observation"]["trials_started"], 0)
        self.assertTrue(delivered["observation"]["success"])
        self.assertEqual(delivered["observation"]["trials_started"], 1)
        self.assertEqual(delivered["binding"]["envelope"]["planned_iterations_per_processor"], 10**8 + 100)
        trial = delivered["observation"]["trials"][0]
        self.assertEqual(trial["conditional_batch_valid_candidate_probability"], 1)
        self.assertEqual(trial["evaluator_marked_count"], 2)
        self.assertEqual(trial["evaluator_legal_winner_count"], 8)
        self.assertEqual(delivered["observation"]["native_blocks_admitted"], 0)

    def test_single_resident_setup_is_reused_but_every_preparation_is_paid(self):
        schedule = ((0, 0), (0, 0), (0, 1))
        result = run_constructed_search((self.empty,), schedule, 2, 8, (self.classical,),
                                        self.model, self.budget, "1e25")
        observation = result["observation"]
        self.assertEqual(observation["domain_setup_charges"], 1)
        self.assertEqual(observation["candidate_checks_completed"], 6)
        self.assertFalse(observation["success"])
        costs = result["binding"]["domain_resources"][0]["clock_seconds_float_upper"]
        self.assertEqual(fraction(observation["phase_paid_seconds_exact"]["domain_setup"]),
                         Fraction(costs["domain_setup_seconds"]))
        self.assertEqual(fraction(observation["phase_paid_seconds_exact"]["prepare"]),
                         3 * Fraction(costs["prepare_seconds"]))
        self.assertEqual(fraction(observation["phase_paid_seconds_exact"]["candidate_checks"]),
                         6 * Fraction(costs["candidate_check_seconds"]))

    def test_seeded_record_replay_rederives_clocks_counts_observation_and_qualification(self):
        record = run_constructed_search((self.domain,), ((0, 0),), 2, 9, (self.classical,),
                                        self.model, self.budget, "1e25", predicate="prefix-restricted")
        self.assertEqual(verify_constructed_search(record, (self.domain,)), record)
        for kind in ("binding", "clock", "observation", "qualification", "source"):
            changed = deepcopy(record)
            if kind == "binding":
                changed["binding"]["envelope"]["t_states_all_processors"] += 1
            elif kind == "clock":
                changed["observation"]["plan"]["costs"][0]["prepare_seconds"] = 1
            elif kind == "observation":
                changed["observation"]["success"] = False
            elif kind == "qualification":
                changed["quantum_mining_qualified"] = True
            else:
                changed["binding"]["source_sha256"]["formal/pon-nakamoto-v1/w1_constructed_search.py"] = "0" * 64
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "CONSTRUCTED_SEARCH_REPLAY_MISMATCH"):
                verify_constructed_search(changed, (self.domain,))

    def test_serialized_verifier_rejects_malformed_premises(self):
        record = run_constructed_search((self.domain,), ((0, 0),), 1, 7, (self.classical,),
                                        self.model, self.budget, "0")
        for field, value in (("schedule", [[False, 0]]), ("processors", True),
                             ("physical_model", {}), ("domain_resources", [])):
            changed = deepcopy(record)
            changed["binding"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_constructed_search(changed, (self.domain,))

    def test_native_shape_is_charged_as_native_construction_without_promoting_qualification(self):
        native = enumerate_domain(fixture(shape=Shape(), nonce_bits=1))
        binding = self.binding(domains=(native,), schedule=((0, 0),), processors=1)
        row = binding.certificate["domain_resources"][0]
        self.assertEqual(row["construction_scope"], "NATIVE_W1_FIXED_TEMPLATE_CONSTRUCTION")
        self.assertGreater(row["forward_gate_count"], 10**9)
        self.assertGreater(row["logical_qubits"], 10**7)
        self.assertFalse(binding.certificate["quantum_mining_qualified"])


if __name__ == "__main__":
    unittest.main()
