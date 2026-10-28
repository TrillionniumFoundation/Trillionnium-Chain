"""Research arithmetic and counterexamples, not quantum/native qualification."""
from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest

from quantum_daa_model import (
    ASSUMPTIONS, Header, POW_LIMIT, Scenario, U256, asert_target, common_history,
    cost_ratio, next_work_budget, probability, required, run_scenario,
    standard_scenarios, trunc_div,
)
from reference import retarget
from experiments.quantum_daa_campaign import (
    canonical, check_row_arithmetic, digest, load_json, run_campaign, verify_campaign,
)

HERE = Path(__file__).resolve().parent


def compact(target: int) -> int:
    """Independent test encoding; the PoN research algorithm keeps raw u256."""
    size = (target.bit_length() + 7) // 8
    mantissa = target << (8 * (3 - size)) if size <= 3 else target >> (8 * (size - 3))
    if mantissa & 0x00800000:
        mantissa >>= 8
        size += 1
    return mantissa | size << 24


class IntegerRulesTests(unittest.TestCase):
    def test_modeled_constants_match_frozen_development_profile(self):
        profile = json.loads((HERE.parents[1] / "config/pon/devnet-v1.json").read_text())
        self.assertEqual(int(profile["pow_limit_hex"], 16), POW_LIMIT)
        self.assertEqual(profile["retarget_interval"], 16)
        self.assertEqual(profile["target_spacing_seconds"], 10)
        self.assertEqual(profile["retarget_factor"], 4)
        self.assertEqual(profile["median_time_width"], 11)
        self.assertEqual(profile["future_skew_seconds"], 120)
        self.assertIs(profile["production_activation"], False)

    def test_pinned_bchn_calculate_asert_vectors(self):
        fixture = json.loads((HERE / "vectors/quantum-daa-asert-bchn-v1.json").read_text())
        self.assertEqual(fixture["source_commit"], "07576013c91ff4a3a74acd85f189c69121cdad1b")
        self.assertEqual(len(fixture["vectors"]), 18)
        limit = int(fixture["pow_limit_hex"], 16)
        for vector in fixture["vectors"]:
            with self.subTest(upstream_line=vector["source_line"]):
                actual = asert_target(int(vector["anchor_target_hex"], 16),
                                      vector["time_delta"], vector["intervals"],
                                      fixture["spacing"], fixture["half_life"], limit)
                self.assertEqual(f"{actual:064x}", vector["expected_target_hex"])
                self.assertEqual(f"{compact(actual):08x}", vector["upstream_expected_nbits_hex"])

    def test_signed_division_rounding_and_extreme_target_clamps(self):
        self.assertEqual(trunc_div(-65536, 3), -21845)
        self.assertNotEqual(trunc_div(-65536, 3), -65536 // 3)
        self.assertEqual(trunc_div(65536, 3), 21845)
        self.assertEqual(asert_target(1, (1 << 64) - 1, 1, 1, 1, POW_LIMIT), POW_LIMIT)
        self.assertEqual(asert_target(POW_LIMIT, -((1 << 64) - 1), 1, 1, 1, POW_LIMIT), 1)

    def test_asert_rejects_noninteger_and_out_of_range_parameters(self):
        for args in [(0, 10, 1, 10, 160, POW_LIMIT),
                     (1, 10, 0, 10, 160, POW_LIMIT),
                     (1, True, 1, 10, 160, POW_LIMIT),
                     (True, 10, 1, 10, 160, POW_LIMIT),
                     (1, 10, 1, 10, 0, POW_LIMIT),
                     (1, 1 << 64, 1, 10, 160, POW_LIMIT),
                     (1, 0, (1 << 64) - 1, (1 << 64) - 1, 1, POW_LIMIT)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                asert_target(*args)

    def test_fixed_probability_budget_clamps_ceilings_and_minimum(self):
        self.assertEqual(next_work_budget(1024, 0, 150, 16, 10, 1 << 20), 1024)
        self.assertEqual(next_work_budget(1024, 0, 75, 16, 10, 1 << 20), 2048)
        self.assertEqual(next_work_budget(1024, 0, 0, 16, 10, 1 << 20), 4043)
        self.assertEqual(next_work_budget(1024, 0, 10000, 16, 10, 1 << 20), 256)
        self.assertEqual(next_work_budget(1024, 0, 75, 16, 10, 1500), 1500)
        self.assertEqual(next_work_budget(1, 0, 10000, 16, 10, 1500), 1)
        for args in [(0, 0, 1, 16, 10, 1), (1, 0, 1, 15, 10, 1),
                     (1, 0, 1, 16, 0, 1), (True, 0, 1, 16, 10, 1)]:
            with self.assertRaises(ValueError):
                next_work_budget(*args)

    def test_uniform_ticket_probability_keeps_inclusive_target(self):
        self.assertEqual(probability(1).denominator, 1 << 255)
        self.assertEqual(probability(POW_LIMIT), Decimal("0.5"))
        with self.assertRaises(ValueError):
            probability(0)

    def test_steady_honest_control_identical_across_clock_variants(self):
        for policy in ("periodic-target", "asert-raw", "asert-mtp11", "fixed-p-work"):
            history = common_history()
            initial = retarget(history[-1].target, history[-16].timestamp,
                               history[-1].timestamp, 16, 10, POW_LIMIT)
            case = Scenario("steady", policy, "linear-work" if policy == "fixed-p-work" else "classical")
            anchor = Header(history[-1].height + 1, history[-1].timestamp + 10, initial)
            anchor_clock = history[-1].timestamp if policy != "asert-mtp11" else sorted(
                h.timestamp for h in history[-11:])[5]
            for _ in range(64):
                target, units = required(history, case, anchor, anchor_clock, initial)
                self.assertEqual((target, units), (initial, 1024), policy)
                parent = history[-1]
                history.append(Header(parent.height + 1, parent.timestamp + 10, target, units))

    def test_cost_ratio_assumptions_have_the_required_counterexample(self):
        baseline, hard = (1 << 240) - 1, (1 << 236) - 1
        classic = Scenario("c", "periodic-target", "classical")
        quantum = replace(classic, cost="quantum-search")
        self.assertEqual(cost_ratio(classic, hard, baseline, 1024), 16)
        self.assertEqual(cost_ratio(quantum, hard, baseline, 1024), 4)
        linear = Scenario("l", "fixed-p-work", "linear-work")
        sublinear = replace(linear, cost="sublinear-work")
        self.assertEqual(cost_ratio(linear, baseline, baseline, 16 * 1024), 16)
        self.assertEqual(cost_ratio(sublinear, baseline, baseline, 16 * 1024), 4)

    def test_scenario_bounds_and_no_cost_policy_substitution(self):
        good = Scenario("test", "periodic-target", "classical")
        changes = [
            {"attacker_rate": "NaN"}, {"attacker_rate": "0"}, {"attacker_rate": "1.01"},
            {"attacker_rate": "invalid"}, {"proof_delay_seconds": "-1"},
            {"proof_delay_seconds": "Infinity"}, {"cost": "linear-work"},
            {"policy": "unknown"}, {"max_tail_blocks": 100000}, {"ramp_blocks": True},
            {"initial_units": 0}, {"initial_units": 2, "max_units": 1},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(good, **change).validate()

    def test_future_timestamp_wait_is_charged_not_assumed_away(self):
        case = Scenario("future-wait", "periodic-target", "classical", attacker_rate="1",
                        ramp_blocks=0, hold_blocks=0, down_blocks=48, max_tail_blocks=1)
        summary, rows = run_scenario(case)
        self.assertGreater(Decimal(summary["modeled_wait_seconds"]), 0)
        for row in rows:
            self.assertLessEqual(row["timestamp"], row["modeled_completion_time"] + 120)
        check_row_arithmetic(case, rows)


class ConditionalScheduleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outputs = {case.name: (case, *run_scenario(case)) for case in standard_scenarios()}

    def summary(self, name):
        return self.outputs[name][1]

    def test_periodic_classical_control_and_quantum_hypothesis_diverge(self):
        classical = self.summary("periodic_classical_control")
        quantum = self.summary("periodic_quantum_query_hypothesis")
        self.assertLess(Decimal(classical["work_ratio"]), Decimal("0.251"))
        self.assertFalse(classical["conditional_reorg_schedule"])
        self.assertGreater(Decimal(quantum["work_ratio"]), Decimal("2.44"))
        self.assertTrue(quantum["caught_up_tip_time"])
        self.assertTrue(quantum["conditional_reorg_schedule"])
        self.assertLessEqual(Decimal(quantum["tip_timestamp_lag_seconds"]), 10)

    def test_asert_failures_retained_and_longer_model_budgets_can_catch_up(self):
        for prefix in ("asert_raw", "asert_mtp"):
            bounded = self.summary(prefix + "_hl160_query_hypothesis")
            extended = self.summary(prefix + "_hl160_extended_schedule")
            self.assertGreater(Decimal(bounded["work_ratio"]), 2)
            self.assertTrue(bounded["tail_budget_exhausted"])
            self.assertFalse(bounded["conditional_reorg_schedule"])
            self.assertTrue(extended["conditional_reorg_schedule"])
            self.assertGreater(extended["rows"], bounded["rows"])
        slow = self.summary("asert_raw_hl7200_bounded_schedule")
        self.assertFalse(slow["more_work_than_honest_model"])
        self.assertFalse(slow["conditional_reorg_schedule"])

    def test_fixed_probability_is_conditional_on_linear_winner_cost(self):
        linear = self.summary("fixed_p_linear_cost_hypothesis")
        sublinear = self.summary("fixed_p_sublinear_cost_counterexample")
        for result in (linear, sublinear):
            self.assertEqual(result["minimum_target_hex"], result["maximum_target_hex"])
            self.assertGreater(result["maximum_units"], result["initial_units"])
        self.assertLess(Decimal(linear["work_ratio"]), Decimal("0.251"))
        self.assertFalse(linear["conditional_reorg_schedule"])
        self.assertTrue(sublinear["conditional_reorg_schedule"])
        self.assertGreater(Decimal(sublinear["work_ratio"]), 2)

    def test_proof_delay_is_charged_and_budget_failure_is_preserved(self):
        bounded = self.summary("periodic_quantum_proof_latency_sensitivity")
        extended = self.summary("periodic_quantum_proof_latency_extended")
        self.assertEqual(Decimal(bounded["modeled_proof_delay_seconds"]), 5 * bounded["rows"])
        self.assertTrue(bounded["tail_budget_exhausted"])
        self.assertFalse(bounded["conditional_reorg_schedule"])
        self.assertTrue(extended["conditional_reorg_schedule"])
        self.assertGreater(extended["rows"], bounded["rows"])

    def test_separate_integer_readback_all_rows_and_no_quantum_claim(self):
        for case, summary, rows in self.outputs.values():
            check_row_arithmetic(case, rows)
            self.assertEqual(summary["native_packets_generated"], 0)
            for flag in ("w1_cost_measured", "quantum_circuit_executed",
                         "production_consensus_activation", "security_theorem"):
                self.assertIs(summary[flag], False)
        self.assertIsNone(ASSUMPTIONS["quantum_oracle_gate_depth"])
        self.assertIsNone(ASSUMPTIONS["quantum_logical_qubits"])
        self.assertIsNone(ASSUMPTIONS["quantum_error_correction_cost"])
        self.assertIs(ASSUMPTIONS["release_ready"], False)

    def test_separate_readback_rejects_chainwork_and_timestamp_mutations(self):
        case, _, rows = self.outputs["periodic_quantum_query_hypothesis"]
        for patch in ({"cumulative_work": "1"}, {"timestamp": 0},
                      {"timestamp": 1 << 63}, {"height": 1}, {"mandatory_units": True}):
            changed = [dict(rows[0], **patch)]
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                check_row_arithmetic(case, changed)


class ReceiptIntegrityTests(unittest.TestCase):
    def test_full_campaign_roundtrip_and_artifact_source_scope_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "fresh"
            produced = run_campaign(out, ["unittest", "--out", "fresh"])
            self.assertEqual(produced["scenarios"], 11)
            self.assertFalse(produced["release_ready"])
            self.assertEqual(verify_campaign(out)["result"], "ARITHMETIC_READBACK_PASS")
            with self.assertRaises(FileExistsError):
                run_campaign(out, ["must-not-overwrite"])
            report_bytes = (out / "report.json").read_bytes()
            manifest_bytes = (out / "manifest.json").read_bytes()
            report = json.loads(report_bytes)
            # A new manifest hash does not authorize a stronger qualification.
            for field in ("actual_native_or_quantum_attack", "release_ready"):
                report["assumptions"][field] = True
                (out / "report.json").write_bytes(canonical(report))
                manifest = json.loads(manifest_bytes)
                manifest["files_sha256"]["report.json"] = digest(out / "report.json")
                (out / "manifest.json").write_bytes(canonical(manifest))
                with self.assertRaisesRegex(ValueError, "ASSUMPTION_SUBSTITUTION"):
                    verify_campaign(out)
                report = json.loads(report_bytes)
            report["source"]["source_sha256"]["formal/pon-nakamoto-v1/reference.py"] = "0" * 64
            (out / "report.json").write_bytes(canonical(report))
            manifest["files_sha256"]["report.json"] = digest(out / "report.json")
            (out / "manifest.json").write_bytes(canonical(manifest))
            with self.assertRaisesRegex(ValueError, "SOURCE_DIGEST"):
                verify_campaign(out)
            (out / "manifest.json").write_bytes(manifest_bytes)
            with self.assertRaisesRegex(ValueError, "ARTIFACT_DIGEST"):
                verify_campaign(out)
            (out / "report.json").write_bytes(report_bytes)
            extra = out / "unexpected"
            extra.write_text("not included")
            with self.assertRaisesRegex(ValueError, "OUTPUT_INVENTORY"):
                verify_campaign(out)

    def test_duplicate_json_keys_are_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"release_ready": false, "release_ready": true}')
            with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
                load_json(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
