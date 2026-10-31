#!/usr/bin/env python3
"""Counterexamples for paired accounting, not synthetic mining evidence."""
import copy
import unittest

from check_legal_ticket_cost_v5 import RECURRING, summed
from legal_ticket_cost_diagnostics_v1 import SCHEMA, derive
from test_legal_ticket_cost_v5 import control, exhausted_control, fixture_challenge


def pair(report, horizon=1, reuse=False, strategy="maintenance-limb"):
    return next(row for row in report["fixed_strategy_pairs"]
                if (row["horizon"], row["reuse"], row["alternative_strategy"]) ==
                (horizon, reuse, strategy))


class PairedDiagnostics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = control()

    def test_complete_fixed_grid_keeps_original_rounds_and_no_population_claim(self):
        report = derive(copy.deepcopy(self.original))
        self.assertEqual(report["schema"], SCHEMA)
        self.assertEqual(len(report["cohorts"]), 144)
        self.assertEqual(len(report["fixed_strategy_pairs"]), 64)
        self.assertEqual(len(report["actual_setup_reuse_pairs"]), 36)
        self.assertEqual([row["round"] for row in pair(report)["paired_rounds"]], [0, 1])
        for field in ("per_round_fastest_strategies_combined", "two_rounds_are_independent_host_samples",
                      "population_confidence_interval_qualified", "global_minimum_proved",
                      "winning_only_proof_assembly_measured", "fresh_native_execution",
                      "calibrates_conditional_daa_model", "production_qualified"):
            self.assertIs(report["boundaries"][field], False)

    def test_ratio_of_sums_and_sign_reversal_are_not_average_of_ratios_or_fastest_round(self):
        rows = copy.deepcopy(self.original)
        for row in rows[1:-1]:
            if row["strategy"] == "maintenance-limb":
                row["observed_outer"]["process_cpu_ns"] = 5000 if row["round"] == 0 else 15000
        compared = pair(derive(rows))
        cpu = compared["aggregate"]["outer"]["process_cpu_ns"]
        self.assertEqual(cpu["ratio_of_complete_totals"], {"numerator": 1, "denominator": 1, "value": 1.0})
        self.assertEqual(cpu["paired_alternative_minus_reference_ns"], [-5000, 5000])
        self.assertFalse(cpu["alternative_lower_in_both_rounds"])
        self.assertIsNone(cpu["population_confidence_interval"])
        self.assertEqual(compared["conditional_full_outer_cpu_work_share"]
                         ["modeled_budget_share_at_half_valid_work"]["value"], 0.5)

    def test_unknown_cpu_cannot_drop_one_round_or_qualify_work_share(self):
        rows = copy.deepcopy(self.original)
        row = next(row for row in rows[1:-1] if row["strategy"] == "maintenance-limb" and row["round"] == 0)
        row["observed_outer"]["process_cpu_ns"] = None
        compared = pair(derive(rows))
        cpu = compared["aggregate"]["outer"]["process_cpu_ns"]
        self.assertEqual(len(compared["paired_rounds"]), 2)
        self.assertEqual(cpu["paired_alternative_minus_reference_ns"], [None, 0])
        self.assertIsNone(cpu["alternative_total_ns"])
        self.assertIsNone(cpu["ratio_of_complete_totals"])
        self.assertIsNone(compared["conditional_full_outer_cpu_work_share"])

    def test_all_exhausted_searches_keep_cost_but_have_no_per_winner_ratio(self):
        report = derive(exhausted_control(rounds=(0, 1)))
        compared = pair(report)
        self.assertEqual(compared["winning_first_admissions"], 0)
        self.assertEqual(compared["attempts"], 16)
        self.assertEqual(compared["exhausted_searches"], 2)
        self.assertIsNone(compared["conditional_full_outer_cpu_work_share"])
        cpu = compared["aggregate"]["outer"]["process_cpu_ns"]
        self.assertEqual(cpu["reference_total_ns"], 20000)
        self.assertIsNone(cpu["reference_ns_per_first_admission"])
        self.assertIsNone(cpu["ratio_of_complete_totals"])
        first = report["cohorts"][0]["generation_partition"]
        self.assertEqual(first["exhausted_search_trials"], {
            "attempts": 8, "timing": {"wall_ns": 8, "process_cpu_ns": 8}})
        self.assertEqual(first["winning_trials"]["attempts"], 0)
        self.assertEqual(first["misses_before_winner"]["attempts"], 0)

    def test_miss_before_winner_is_separate_from_exhaustion_and_still_charged(self):
        rows = copy.deepcopy(self.original)
        for row in rows[1:-1]:
            if row["round"] != 0 or row["search_horizon"] != 1:
                continue
            winner = row["searches"][0]["trials"][0]
            miss = {key: copy.deepcopy(value) for key, value in winner.items()
                    if key not in ("native_admission", "packet_id", "packet_bytes")}
            miss.update(ticket="ff" * 32, target_hit=False)
            winner["trial"] = 1
            winner["nonce"] += 1
            winner["challenge"] = fixture_challenge(winner["nonce"])
            row["searches"][0]["trials"] = [miss, winner]
            row.update(attempts=2)
            row["phases"]["all_attempt_generation"] = {"wall_ns": 2, "process_cpu_ns": 2}
            row["all_exclusive_phases"] = summed(row["phases"].values())
            row["recurring_producer_encode_admission"] = summed(row["phases"][name] for name in RECURRING)
        report = derive(rows)
        first = report["cohorts"][0]["generation_partition"]
        self.assertEqual([first[name]["attempts"] for name in
                         ("winning_trials", "misses_before_winner", "exhausted_search_trials")], [1, 1, 0])
        self.assertEqual(pair(report)["attempts"], 3)
        self.assertEqual(pair(report)["winning_first_admissions"], 2)

    def test_actual_setup_calls_are_not_a_synthetic_divisor(self):
        report = derive(copy.deepcopy(self.original))
        compared = next(row for row in report["actual_setup_reuse_pairs"]
                        if row["horizon"] == 8 and row["strategy"] == "prepared-generic")
        self.assertEqual([(row["reference_setup_calls"], row["alternative_setup_calls"])
                          for row in compared["paired_rounds"]], [(8, 1), (8, 1)])
        cohort = next(row for row in report["cohorts"] if row["horizon"] == 8 and row["reuse"])
        # The synthetic control actually records one ns of setup in both modes.
        # A model must not fabricate an eightfold speedup from the call counts.
        self.assertEqual(cohort["observed_setup_per_search_ns"]["process_cpu_ns"],
                         {"numerator": 1, "denominator": 8, "value": 0.125})
        self.assertEqual(compared["aggregate"]["outer"]["process_cpu_ns"]
                         ["ratio_of_complete_totals"]["value"], 1)

    def test_existing_conditional_work_share_uses_complete_outer_cpu(self):
        rows = copy.deepcopy(self.original)
        for row in rows[1:-1]:
            if row["strategy"] == "maintenance-limb":
                row["observed_outer"]["process_cpu_ns"] = 5000
        compared = pair(derive(rows))
        model = compared["conditional_full_outer_cpu_work_share"]
        share = model["assumed_same_hardware_cpu_budget_shares"][1]
        self.assertEqual(share["budget_share"]["value"], 0.1)
        self.assertEqual(share["modeled_effective_valid_work_share"]["numerator"], 2)
        self.assertEqual(share["modeled_effective_valid_work_share"]["denominator"], 11)
        self.assertEqual(model["modeled_budget_share_at_half_valid_work"]["denominator"], 3)
        self.assertIsNone(model["measured_network_adversary_share"])
        self.assertFalse(model["invalid_from_zero_tickets_count_as_work"])

    def test_existing_v5_reader_validation_cannot_be_bypassed(self):
        rows = copy.deepcopy(self.original)
        rows[2]["searches"][0]["trials"][0]["proof_sha256"] = "ab" * 32
        with self.assertRaisesRegex(ValueError, "paired attempted"):
            derive(rows)


if __name__ == "__main__":
    unittest.main(verbosity=2)
