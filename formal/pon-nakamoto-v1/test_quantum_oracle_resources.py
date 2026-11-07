"""Independent arithmetic controls for conditional quantum resource accounting."""
from dataclasses import asdict, replace
from decimal import Decimal
from fractions import Fraction
import json
from pathlib import Path
import subprocess
import sys
import unittest

import quantum_oracle_resources as q


def wire(request):
    value = asdict(request)
    value["schema"] = q.SCHEMA
    return json.dumps(value).encode()


class ResourceAccounting(unittest.TestCase):
    def test_unknown_w1_never_invents_component_counts(self):
        result = q.account(q.example())
        self.assertEqual(result["status"], "UNKNOWN_COMPLETE_ORACLE_COST")
        self.assertIsNone(result["complete_quantum_cost"])
        self.assertTrue(all(m["estimate"] is None for m in result["physical_sensitivity"]))
        self.assertFalse(result["full_W1_oracle_constructed"])
        self.assertFalse(result["production_activation"])

    def test_forward_inverse_phase_and_diffusion_are_distinct(self):
        request = q.example(True)
        report = q.account(request)
        per_iter = report["complete_quantum_cost"]["per_grover_iteration"]
        # Example uses four equal stage budgets. A Grover iteration uses two
        # winner-computes (forward + inverse), phase, diffusion: 4 * 40.
        self.assertEqual(per_iter["gate_count"], 160)
        self.assertEqual(per_iter["toffoli_count"], 32)
        self.assertEqual(per_iter["gate_depth"], 40)
        # 4 search groups, 8 full trials at 32, plus aborted 7 and 11.
        self.assertEqual(report["per_instance_total_grover_iterations_including_interrupted"], 1096)
        # 40 trial preparations * 40 gates + 1096 iterations * 160.
        self.assertEqual(report["complete_quantum_cost"]["per_instance_workload"]["gate_count"], 176960)
        self.assertEqual(report["complete_quantum_cost"]["all_instances_gate_counts"]["gate_count"], 353920)

    def test_proof_cost_charged_only_after_completed_winner(self):
        request = q.example(True)
        changed = replace(request, classical=replace(request.classical, per_winner_proof_ns=17 * 10**9))
        before, after = q.account(request), q.account(changed)
        self.assertEqual(before["complete_quantum_cost"], after["complete_quantum_cost"])
        self.assertEqual(before["physical_sensitivity"], after["physical_sensitivity"])
        self.assertEqual(after["classical_costs"]["winner_proof_ns_total"], 17 * 10**9)
        failed = q.account(replace(changed, workload=replace(changed.workload, completed_winners=0)))
        self.assertEqual(failed["classical_costs"]["winner_proof_ns_total"], 0)

    def test_zero_iteration_failed_trials_still_pay_complete_candidate_recheck(self):
        # Two tasks, three searches each, five processors, seven measured
        # random candidates per search: all 210 candidates fail. Two abandoned
        # zero-iteration attempts per search pay preparation/reset, no recheck.
        request = q.example(True)
        request = replace(request, workload=q.Workload(2, 3, 5, 7, 0, (0, 0), 0),
                          classical=replace(request.classical,
                                            per_completed_trial_candidate_check_ns=37))
        report = q.account(request)
        self.assertEqual(report["all_instances_completed_measured_trials"], 210)
        self.assertEqual(report["classical_costs"]["completed_trial_candidate_check_ns_total"], 7770)
        self.assertEqual(report["classical_costs"]["winner_proof_ns_total"], 0)
        self.assertEqual(report["per_instance_total_grover_iterations_including_interrupted"], 0)
        winner = q.account(replace(request, workload=replace(request.workload, completed_winners=1)))
        self.assertEqual(winner["classical_costs"]["completed_trial_candidate_check_ns_total"], 7770)
        self.assertEqual(winner["complete_quantum_cost"], report["complete_quantum_cost"])

    def test_candidate_recheck_is_mandatory_explicit_validated_input(self):
        request = q.example(True)
        for value in (True, 0, -1, 1.0, 2**64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                q.account(replace(request, classical=replace(
                    request.classical, per_completed_trial_candidate_check_ns=value)))
        value = json.loads(wire(request))
        del value["classical"]["per_completed_trial_candidate_check_ns"]
        with self.assertRaisesRegex(ValueError, "CLASSICAL_SCHEMA"):
            q.load_request(json.dumps(value).encode())

    def test_preprocessing_shared_once_per_task_and_amortized_exactly(self):
        request = replace(q.example(True), workload=q.Workload(3, 5, 2, 1, 0, (), 0))
        report = q.account(request)
        self.assertEqual(report["classical_costs"]["task_preprocessing_ns_total"], 3_000_000)
        self.assertEqual(report["classical_costs"]["amortized_preprocessing_ns_per_search_instance"],
                         {"numerator": 100000, "denominator": 1})
        self.assertEqual(report["classical_costs"]["per_search_setup_ns_total"], 300000)

    def test_aborted_search_has_no_free_prepare_or_compute(self):
        request = replace(q.example(True), workload=q.Workload(1, 1, 1, 0, 32, (0, 7), 0))
        report = q.account(request)
        counts = report["complete_quantum_cost"]["per_instance_workload"]
        self.assertEqual(counts["gate_count"], 2 * 40 + 7 * 160)
        self.assertEqual(report["classical_costs"]["trial_reset_readout_ns_total"], 2000)
        self.assertEqual(report["classical_costs"]["completed_trial_candidate_check_ns_total"], 0)

    def test_parallel_instances_pay_replicated_registers_and_gates(self):
        request = q.example(True)
        one = q.account(replace(request, workload=replace(request.workload, independent_instances=1)))
        four = q.account(replace(request, workload=replace(request.workload, independent_instances=4)))
        self.assertEqual(one["complete_quantum_cost"]["per_instance_workload"],
                         four["complete_quantum_cost"]["per_instance_workload"])
        self.assertEqual(four["complete_quantum_cost"]["logical_qubits_peak_all_instances"], 400)
        self.assertEqual(four["complete_quantum_cost"]["all_instances_gate_counts"]["gate_count"],
                         one["complete_quantum_cost"]["all_instances_gate_counts"]["gate_count"] * 4)

    def test_any_missing_stage_preserves_unknown_complete_cost(self):
        request = q.example(True)
        for stage in q.STAGES:
            with self.subTest(stage=stage):
                report = q.account(replace(request, circuits={**request.circuits, stage: None}))
                self.assertIsNone(report["complete_quantum_cost"])
                self.assertEqual(report["missing_circuit_stages"], [stage])

    def test_costed_manifest_never_claims_verified_w1_or_lower_bound(self):
        request = replace(q.example(True), scope="CALLER_SUPPLIED_UNVERIFIED_PREDICATE")
        report = q.account(request)
        self.assertFalse(report["full_W1_oracle_constructed"])
        self.assertFalse(report["quantum_work_lower_bound_proved"])
        self.assertFalse(report["quantum_mining_qualified"])
        self.assertFalse(report["winner_probability_or_security_threshold_inferred"])

    def test_incomplete_w1_cannot_be_promoted_by_supplied_compute(self):
        request = q.example()
        with self.assertRaisesRegex(ValueError, "INCOMPLETE_W1"):
            q.account(replace(request, circuits={**request.circuits, "winner_compute": q.example(True).circuits["winner_compute"]}))

    def test_physical_error_worsening_cannot_reduce_selected_distance(self):
        report = q.account(q.example(True))
        estimates = [row["estimate"] for row in report["physical_sensitivity"]]
        distances = [row["code_distance"] for row in estimates]
        self.assertEqual(distances, sorted(distances))
        self.assertEqual(len(set(distances)), 3)
        for row in estimates:
            self.assertLessEqual(Decimal(row["whole_workload_failure_union_estimate"]), Decimal("0.01"))
            self.assertLessEqual(Decimal(row["quantum_wall_seconds_ideal_overlap_lower_bound"]),
                                 Decimal(row["quantum_wall_seconds_serial_magic_delivery_schedule"]))

    def test_full_decomposition_depth_cannot_be_shorter_than_t_layers(self):
        # A sequential X;Toffoli;X stage needs the declared T layers between
        # its two Clifford steps. Accepting total decomposition depth 1 with
        # T depth 3 makes max(3*1, 1*3) charge only three data layers. A total
        # decomposition depth must cover its own T-layer declaration before
        # any gate budget can be converted into a conditional clock.
        request = q.example(True)
        model = replace(request.physical_models[0], toffoli_decomposition_depth=1,
                        t_depth_per_toffoli=3)
        stage = q.Circuit(3, 3, 3, 1, 1, 0, 0, "serial-x-toffoli-x-control")
        changed = replace(request, physical_models=(model,),
                          circuits={key: stage for key in q.STAGES})
        with self.assertRaisesRegex(ValueError, "TOFFOLI_DECOMPOSITION_BELOW_T_DEPTH"):
            q.account(changed)
        with self.assertRaisesRegex(ValueError, "TOFFOLI_DECOMPOSITION_BELOW_T_DEPTH"):
            q.load_request(wire(changed))
        counts = {key: getattr(stage, key) for key in (
            "gate_count", "gate_depth", "toffoli_count", "toffoli_depth",
            "direct_t_count", "direct_t_depth")}
        with self.assertRaisesRegex(ValueError, "TOFFOLI_DECOMPOSITION_BELOW_T_DEPTH"):
            q.physical_estimate(counts, stage.logical_qubits, 1, model)
        # Equality is a valid conservative declaration and remains accepted.
        valid = replace(model, toffoli_decomposition_depth=3)
        self.assertEqual(q.account(replace(changed, physical_models=(valid,)))["status"],
                         "CALLER_CONDITIONAL_ACCOUNTING_ONLY")

    def test_surface_code_union_formula_independent(self):
        request = q.example(True)
        report = q.account(request)
        row = report["physical_sensitivity"][1]
        estimate = row["estimate"]
        distance = estimate["code_distance"]
        logical_error = Decimal("0.1") * Decimal("0.1") ** ((distance + 1) // 2)
        expected = (Decimal(100 * 2 * estimate["allocated_code_cycles_per_instance"]) * logical_error
                    + Decimal(row["t_count_per_instance_conditional"] * 2) * Decimal("1e-15"))
        self.assertEqual(Decimal(estimate["whole_workload_failure_union_estimate"]), expected)
        # Data = 2*d^2*100, two factories = 100*d^2*2, two processors.
        self.assertEqual(estimate["total_physical_qubits_all_instances"], 800 * distance**2)
        if distance > 3:
            previous = distance - 2
            cycles = estimate["allocated_code_cycles_per_instance"] // distance * previous
            prior = Decimal(100 * 2 * cycles) * Decimal("0.1") * Decimal("0.1")**((previous + 1)//2)
            prior += Decimal(row["t_count_per_instance_conditional"] * 2) * Decimal("1e-15")
            self.assertGreater(prior, Decimal("0.01"))


    def test_distance_budget_uses_exact_failure_not_rounded_equality(self):
        # Negative Pell solutions put 30 * .01 * (y/x)^2 exactly
        # 3/(20*x*x) above .15. Both decimal inputs satisfy the 100-char
        # bound, while Decimal precision 100 erases the positive excess.
        x = y = 1
        for _ in range(123):
            x, y = 3*x + 4*y, 2*x + 3*y
        self.assertEqual(x*x - 2*y*y, -1)
        model = replace(q.example(True).physical_models[0],
                        physical_error=f"0.{y:098d}", threshold=f"0.{x:098d}",
                        logical_error_prefactor="0.01", magic_state_error="0",
                        total_failure_budget="0.15", maximum_distance=3)
        counts = {"gate_count": 1, "gate_depth": 1, "toffoli_count": 0,
                  "toffoli_depth": 0, "direct_t_count": 0, "direct_t_depth": 0}
        budget = Fraction(3, 20)
        ratio = Fraction(y, x)

        def exact_failure(distance):
            return Fraction(distance, 10) * ratio ** ((distance + 1) // 2)

        self.assertEqual(exact_failure(3), budget + Fraction(3, 20*x*x))
        rejected = q.physical_estimate(counts, 1, 1, model)
        self.assertEqual(rejected["status"], "NO_DISTANCE_IN_DECLARED_RANGE")
        self.assertIsNone(rejected["estimate"])
        accepted = q.physical_estimate(counts, 1, 1, replace(model, maximum_distance=11))
        self.assertEqual(accepted["status"], "CONDITIONAL_ESTIMATE")
        self.assertEqual(accepted["estimate"]["code_distance"], 11)
        self.assertTrue(all(exact_failure(d) > budget for d in range(3, 11, 2)))
        self.assertLessEqual(exact_failure(11), budget)

    def test_exact_total_failure_budget_equality_remains_accepted(self):
        model = replace(q.example(True).physical_models[0],
                        physical_error="0.001", threshold="0.01",
                        logical_error_prefactor="0.1", magic_state_error="0",
                        total_failure_budget="0.03", maximum_distance=3)
        counts = {"gate_count": 1, "gate_depth": 1, "toffoli_count": 0,
                  "toffoli_depth": 0, "direct_t_count": 0, "direct_t_depth": 0}
        self.assertEqual(30 * Fraction(1, 10) * Fraction(1, 10)**2, Fraction(3, 100))
        report = q.physical_estimate(counts, 1, 1, model)
        self.assertEqual(report["status"], "CONDITIONAL_ESTIMATE")
        self.assertEqual(report["estimate"]["code_distance"], 3)
        self.assertEqual(Decimal(report["estimate"]["whole_workload_failure_union_estimate"]),
                         Decimal("0.03"))
        self.assertFalse(report["model_is_physical_calibration"])

    def test_magic_budget_does_not_round_away_positive_headroom(self):
        t_count = 10**60 + 1
        model = replace(q.example(True).physical_models[0],
                        physical_error="1e-100", threshold="0.01",
                        logical_error_prefactor="1e-100",
                        magic_state_error="9"*60 + "e-121",
                        total_failure_budget="0.1", maximum_distance=3)
        counts = {"gate_count": t_count, "gate_depth": 1, "toffoli_count": 0,
                  "toffoli_depth": 0, "direct_t_count": t_count, "direct_t_depth": 1}
        exact_magic = t_count * Fraction(model.magic_state_error)
        budget = Fraction(1, 10)
        self.assertEqual(budget - exact_magic, Fraction(1, 10**121))
        cycles = 3 * (10 + 10*t_count)
        exact_failure = (cycles * Fraction(model.logical_error_prefactor)
                         * (Fraction(model.physical_error) / Fraction(model.threshold))**2
                         + exact_magic)
        self.assertLess(exact_failure, budget)
        report = q.physical_estimate(counts, 1, 1, model)
        self.assertEqual(report["status"], "CONDITIONAL_ESTIMATE")
        self.assertEqual(report["estimate"]["code_distance"], 3)
        # The documented Decimal presentation remains rounded; it is not
        # the value used to decide whether this exact model meets its budget.
        self.assertEqual(Decimal(report["whole_workload_magic_error_union_estimate"]),
                         Decimal("0.1"))

    def test_distillation_failure_cannot_be_fixed_by_code_distance(self):
        request = q.example(True)
        model = replace(request.physical_models[0], magic_state_error="0.001")
        report = q.account(replace(request, physical_models=(model,)))
        self.assertEqual(report["physical_sensitivity"][0]["status"], "UNSATISFIED_MAGIC_STATE_ERROR_BUDGET")
        self.assertIsNone(report["physical_sensitivity"][0]["estimate"])

    def test_distance_cap_is_a_failure_not_best_effort_success(self):
        request = q.example(True)
        model = replace(request.physical_models[-1], maximum_distance=3)
        report = q.account(replace(request, physical_models=(model,)))
        self.assertEqual(report["physical_sensitivity"][0]["status"], "NO_DISTANCE_IN_DECLARED_RANGE")

    def test_threshold_and_nonfinite_errors_refused(self):
        request = q.example(True)
        for error in ("0.01", "0.1", "NaN", "Infinity", "-0.1", "1e-100000", True, 0.001):
            with self.subTest(error=error), self.assertRaises(ValueError):
                q.account(replace(request, physical_models=(replace(request.physical_models[0], physical_error=error),)))

    def test_integer_bool_negative_and_huge_counts_refused(self):
        request = q.example(True)
        for value in (True, -1, 1.0, 2**64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                q.account(replace(request, workload=replace(request.workload, independent_instances=value)))
        with self.assertRaisesRegex(ValueError, "OVERFLOW"):
            q.account(replace(request, workload=q.Workload(2**64-1, 2**64-1, 2**64-1, 2**64-1,
                                                         2**64-1, (), 0)))

    def test_invalid_stage_subtotals_and_depths_refused(self):
        request = q.example(True)
        original = request.circuits["winner_compute"]
        for stage in (replace(original, toffoli_count=41), replace(original, gate_depth=41),
                      replace(original, direct_t_depth=1), replace(original, logical_qubits=True)):
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                q.account(replace(request, circuits={**request.circuits, "winner_compute": stage}))

    def test_workload_failures_and_schema_fail_closed(self):
        request = q.example(True)
        for work in (replace(request.workload, completed_winners=100000),
                     replace(request.workload, interrupted_iterations_per_search_instance=(33,)),
                     replace(request.workload, full_trials_per_search_instance=0,
                             interrupted_iterations_per_search_instance=(), completed_winners=0)):
            with self.subTest(work=work), self.assertRaises(ValueError):
                q.account(replace(request, workload=work))
        value = json.loads(wire(request))
        value["ignored_field"] = 1
        with self.assertRaisesRegex(ValueError, "REQUEST_SCHEMA"):
            q.load_request(json.dumps(value).encode())

    def test_json_roundtrip_duplicate_nonfinite_and_size(self):
        request = q.example(True)
        self.assertEqual(q.account(q.load_request(wire(request))), q.account(request))
        for raw in (b'{"schema":"a","schema":"b"}', b'{"x":NaN}', b'x'*(q.MAX_INPUT_BYTES+1)):
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError):
                q.load_request(raw)

    def test_model_and_preprocessing_duplicates_refused(self):
        request = q.example(True)
        for changed in (replace(request, physical_models=(request.physical_models[0],)*2),
                        replace(request, classical_preprocessing=("AB", "AB")),
                        replace(request, classical_preprocessing=([],))):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                q.account(changed)

    def test_command_demo_explicitly_separates_unknown_w1(self):
        run = subprocess.run([sys.executable, str(Path(q.__file__)), "--demo"],
                             check=True, text=True, capture_output=True)
        report = json.loads(run.stdout)
        self.assertEqual(report["W1"]["status"], "UNKNOWN_COMPLETE_ORACLE_COST")
        self.assertEqual(report["hypothetical_arithmetic_example"]["scope"], "HYPOTHETICAL_NON_W1_EXAMPLE")


if __name__ == "__main__":
    unittest.main()
