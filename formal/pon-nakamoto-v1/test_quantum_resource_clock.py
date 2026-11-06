"""Whole-campaign resource bounds, serial clocks and their negative controls."""
from copy import deepcopy
from dataclasses import asdict, replace
from fractions import Fraction
import math
import unittest
from unittest.mock import patch

import quantum_oracle_resources as resources
import quantum_resource_clock as clock
from quantum_network_sim import NetworkScenario, ParticipationShock
from experiments import quantum_resource_clock_campaign as campaign


def premise(processors=1, **changes):
    case = NetworkScenario("resource_binding_control", duration_seconds=2,
                           quantum_fixed_iterations=0, quantum_processors=processors,
                           propagation_seconds=0.1, max_events=100, max_blocks=20,
                           max_trace_rows=3000, **changes)
    request = resources.example(True)
    request = replace(request, workload=replace(request.workload, independent_instances=processors))
    return case, request


def bind(case, request, budget=10**30):
    return clock.bind_resource_clock(case, request, request.physical_models[0].name, budget)


class ResourceClockControls(unittest.TestCase):
    def test_fixed_distance_uses_whole_event_envelope(self):
        case, request = premise()
        result = bind(case, request).certificate
        self.assertEqual(result["envelope"]["trial_starts_per_processor"], 2001)
        self.assertGreater(result["envelope"]["trial_starts_per_processor"], case.max_events + 1)
        self.assertEqual(result["envelope"]["iterations_per_processor"], 0)
        self.assertTrue(result["original_workload_replaced_by_event_envelope"])
        self.assertFalse(result["cheapest_miner_or_lower_bound"])
        # An understated caller workload cannot reduce the event envelope.
        other = replace(request, workload=resources.Workload(1, 1, 1, 1, 0, (), 0))
        changed = bind(case, other).certificate
        self.assertEqual(changed["code_distance_for_whole_campaign"], result["code_distance_for_whole_campaign"])
        self.assertEqual(changed["envelope"], result["envelope"])

    def test_larger_campaign_can_require_larger_distance(self):
        case, request = premise()
        model = replace(request.physical_models[0], physical_error="0.001", magic_state_error="0")
        request = replace(request, physical_models=(model,))
        small = bind(replace(case, max_events=2, max_blocks=2), request).certificate
        large = bind(replace(case, max_events=100000, max_blocks=10000,
                             quantum_fixed_iterations=1000000), request).certificate
        self.assertGreater(large["code_distance_for_whole_campaign"], small["code_distance_for_whole_campaign"])

    def test_campaign_magic_state_budget_is_not_reset_per_trial(self):
        case, request = premise()
        model = replace(request.physical_models[0], magic_state_error="0.00001")
        request = replace(request, physical_models=(model,))
        bind(replace(case, max_events=1, max_blocks=1), request)
        with self.assertRaisesRegex(ValueError, "CAMPAIGN_MAGIC"):
            bind(case, request)

    def test_all_processors_pay_data_and_factories(self):
        case, request = premise(1)
        one = bind(case, request).certificate
        case4, request4 = premise(4)
        four = bind(case4, request4).certificate
        d1, d4 = one["code_distance_for_whole_campaign"], four["code_distance_for_whole_campaign"]
        self.assertGreaterEqual(d4, d1)
        self.assertEqual(four["physical_qubits_all_processors"] * d1**2,
                         one["physical_qubits_all_processors"] * 4 * d4**2)
        with self.assertRaisesRegex(ValueError, "INSUFFICIENT_PHYSICAL_QUBITS"):
            bind(case4, request4, four["physical_qubits_all_processors"] - 1)
        bind(case4, request4, four["physical_qubits_all_processors"])

    def test_serial_stage_cost_is_not_max_after_aggregation(self):
        # Complementary stages reveal why max(sum(depth),sum(Tdepth)) would
        # underestimate a schedule that explicitly serializes stage boundaries.
        case, request = premise()
        depth = resources.Circuit(100, 100, 100, 0, 0, 0, 0, "depth-control")
        magic = resources.Circuit(100, 100, 1, 0, 0, 100, 1, "magic-control")
        model = replace(request.physical_models[0], toffoli_decomposition_depth=1,
                        t_depth_per_toffoli=1, logical_gate_cycles_per_distance=1,
                        factory_t_cycles_per_distance=1)
        request = replace(request, circuits={"prepare": depth, "winner_compute": depth,
                                            "phase_marker": magic, "diffusion": depth},
                          physical_models=(model,))
        units = bind(case, request).certificate["iteration_cycle_units"]
        self.assertEqual(units["serial_cycles_per_distance"], 401)
        self.assertEqual(units["t_states"], 100)

    def test_clock_refuses_inconsistent_decomposition_and_t_layer_depth(self):
        case, request = premise()
        model = replace(request.physical_models[0], toffoli_decomposition_depth=1,
                        t_depth_per_toffoli=3)
        request = replace(request, physical_models=(model,))
        with self.assertRaisesRegex(ValueError, "TOFFOLI_DECOMPOSITION_BELOW_T_DEPTH"):
            bind(case, request)

    def test_full_compute_inverse_and_readout_all_paid(self):
        case, request = premise()
        result = bind(case, request)
        c = result.certificate
        units = c["stage_cycle_units"]
        iteration = c["iteration_cycle_units"]["serial_cycles_per_distance"]
        expected = (2 * units["winner_compute"]["serial_cycles_per_distance"]
                    + units["phase_marker"]["serial_cycles_per_distance"]
                    + units["diffusion"]["serial_cycles_per_distance"])
        self.assertEqual(iteration, expected)
        setup = request.classical.task_preprocessing_ns + request.classical.per_search_setup_ns
        exact = c["clock_seconds_exact"]["quantum_prepare_seconds"]
        expected_prepare = Fraction(units["prepare"]["serial_cycles_per_distance"]
                                    * c["code_distance_for_whole_campaign"] * 1000 + setup, 10**9)
        self.assertEqual(Fraction(exact["numerator"], exact["denominator"]), expected_prepare)
        self.assertGreaterEqual(result.scenario.quantum_measure_seconds,
                                request.classical.per_trial_reset_readout_ns / 10**9)

    def test_proof_and_classical_check_do_not_change_quantum_gate_budget(self):
        case, request = premise()
        first = bind(case, request)
        changed = replace(request, classical=replace(request.classical,
                            per_winner_proof_ns=17 * 10**9,
                            per_completed_trial_candidate_check_ns=7 * 10**9))
        second = bind(case, changed)
        self.assertEqual(first.certificate["envelope"], second.certificate["envelope"])
        self.assertEqual(first.certificate["physical_qubits_all_processors"], second.certificate["physical_qubits_all_processors"])
        self.assertEqual(second.scenario.quantum_proof_seconds, 17)
        self.assertEqual(second.scenario.quantum_candidate_check_seconds, 7)

    def test_clock_rounds_up_never_down(self):
        for value in (Fraction(1, 3), Fraction(1, 10**9), Fraction(2**54 + 1), Fraction(0)):
            result = clock.float_upper(value)
            self.assertGreaterEqual(Fraction.from_float(result), value)
            if result and Fraction.from_float(result) != value:
                self.assertLess(Fraction.from_float(math.nextafter(result, -math.inf)), value)
        self.assertGreaterEqual(clock.float_upper(Fraction(1, 10**20), positive=True), 1e-9)

    def test_unknown_complete_oracle_and_zero_readout_are_refused(self):
        case, request = premise()
        with self.assertRaisesRegex(ValueError, "UNKNOWN_COMPLETE"):
            bind(case, replace(request, circuits={**request.circuits, "winner_compute": None}))
        with self.assertRaisesRegex(ValueError, "POSITIVE_RESET_READOUT"):
            bind(case, replace(request, classical=replace(request.classical, per_trial_reset_readout_ns=0)))

    def test_unbudgeted_processors_speed_and_propagation_refused(self):
        case, request = premise()
        with self.assertRaisesRegex(ValueError, "PROCESSOR_COUNT"):
            bind(replace(case, quantum_processors=2), request)
        for modified in (replace(case, quantum_initial_factor=2),
                         replace(case, shocks=(ParticipationShock(1, 1, 0.5),))):
            with self.assertRaisesRegex(ValueError, "UNBUDGETED_QUANTUM_SPEED"):
                bind(modified, request)
        with self.assertRaisesRegex(ValueError, "PROPAGATION_PREMISE"):
            bind(replace(case, propagation_seconds=0.2), request)
        bind(replace(case, shocks=(ParticipationShock(1, 1, 0),)), request)

    def test_certificate_and_bound_clock_mutation_rejected(self):
        case, request = premise()
        binding = bind(case, request)
        clock.verify_binding(binding, case, request)
        modified = replace(binding, scenario=replace(binding.scenario, quantum_iteration_seconds=1e-9))
        with self.assertRaisesRegex(ValueError, "BINDING_MISMATCH"):
            clock.verify_binding(modified, case, request)
        data = deepcopy(binding.certificate)
        data["code_distance_for_whole_campaign"] -= 2
        with self.assertRaisesRegex(ValueError, "BINDING_MISMATCH"):
            clock.verify_binding(replace(binding, certificate=data), case, request)

    def test_real_event_run_has_checked_resource_envelope(self):
        case, request = premise()
        case = replace(case, max_events=10000)
        summary, trace, report = clock.run_resource_bound(case, request, request.physical_models[0].name, 10**30)
        self.assertEqual(report["execution"]["status"], "CONDITIONAL_RESOURCE_BOUND_OBSERVATION")
        self.assertGreater(summary["miners"]["q"]["searches_started"], 1)
        self.assertGreater(summary["miners"]["q"]["candidate_checks_completed"], 0)
        self.assertFalse(report["execution"]["release_ready"])
        binding = bind(case, request)
        bad = deepcopy(summary)
        bad["miners"]["q"]["searches_started"] = binding.certificate["envelope"]["trial_starts_per_processor"] + 1
        with self.assertRaisesRegex(ValueError, "OBSERVED_TRIALS"):
            clock.audit_execution(binding, bad, trace)
        with patch.object(clock, "source_fingerprint", return_value={}):
            with self.assertRaisesRegex(ValueError, "STALE_RESOURCE"):
                clock.audit_execution(binding, summary, trace)

    def test_truncation_is_preserved_as_incomplete(self):
        case, request = premise()
        case = replace(case, max_events=1)
        summary, trace, report = clock.run_resource_bound(case, request, request.physical_models[0].name, 10**30)
        self.assertNotEqual(summary["termination"], "horizon")
        self.assertEqual(report["execution"]["status"], "INCOMPLETE_OBSERVATION")

    def test_clock_cannot_be_forged_with_new_checksum(self):
        case, request = premise()
        result = bind(case, request)
        data = deepcopy(result.certificate)
        data["clock_seconds_float_upper"]["quantum_iteration_seconds"] = 1e-9
        data["binding_sha256"] = clock.digest({k: v for k, v in data.items() if k != "binding_sha256"})
        with self.assertRaisesRegex(ValueError, "BINDING_MISMATCH"):
            clock.verify_binding(replace(result, certificate=data), case, request)

    def test_invalid_budget_and_model_refused(self):
        case, request = premise()
        for value in (0, True, -1, 1.5, 2**256):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bind(case, request, value)
        with self.assertRaisesRegex(ValueError, "PHYSICAL_MODEL_NOT_FOUND"):
            clock.bind_resource_clock(case, request, "missing", 10**30)
        model = replace(request.physical_models[0], physical_error="0.009", maximum_distance=3)
        with self.assertRaisesRegex(ValueError, "NO_DISTANCE_FOR_CAMPAIGN"):
            bind(case, replace(request, physical_models=(model,)))

    def test_campaign_rederives_clocks_and_replays_trace(self):
        _, request = premise()
        record = campaign.observe(request, request.physical_models[0].name, 10**30, 17, 2)
        replay = campaign.verify(record)
        self.assertEqual(replay["replayed_cases"], 3)
        self.assertTrue(replay["resource_clocks_rederived"])
        self.assertTrue(replay["full_trace_digests_recomputed"])
        bad = deepcopy(record)
        bad["observations"][0]["resources"]["binding"]["code_distance_for_whole_campaign"] -= 2
        with self.assertRaisesRegex(ValueError, "REPLAY_MISMATCH"):
            campaign.verify(bad)
        bad = deepcopy(record)
        bad["observations"][0]["trace_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "REPLAY_MISMATCH"):
            campaign.verify(bad)

    def test_campaign_source_head_cannot_be_invented(self):
        _, request = premise()
        record = campaign.observe(request, request.physical_models[0].name, 10**30, 17, 2)
        bad = deepcopy(record)
        bad["source"]["git_head"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "SOURCE_HEAD"):
            campaign.verify(bad)
        bad = deepcopy(record)
        bad["source"]["source_sha256"]["formal/pon-nakamoto-v1/quantum_network_sim.py"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "CAMPAIGN_SOURCE"):
            campaign.verify(bad)

    def test_construction_mode_replaces_forged_circuit_inputs_and_replays(self):
        # Reduced shape is a compiler control, never a native W1 resource claim.
        from test_w1_quantum_oracle import fixture
        _, request = premise()
        model = replace(request.physical_models[0], magic_state_error="1e-60")
        request = replace(request, physical_models=(model,))
        record = campaign.observe(request, model.name, 10**30, 17, 2, fixture().spec())
        self.assertTrue(record["circuit_budgets_rederived_from_construction"])
        self.assertEqual(record["construction"]["scope"], "REDUCED_SHAPE_CIRCUIT_CONTROL")
        self.assertNotEqual(record["request"]["circuits"], asdict(request)["circuits"])
        self.assertTrue(campaign.verify(record)["circuit_budgets_rederived_from_construction"])
        bad = deepcopy(record)
        bad["request"]["circuits"]["winner_compute"]["gate_count"] += 1
        with self.assertRaisesRegex(ValueError, "REPLAY_MISMATCH"):
            campaign.verify(bad)


if __name__ == "__main__":
    unittest.main()
