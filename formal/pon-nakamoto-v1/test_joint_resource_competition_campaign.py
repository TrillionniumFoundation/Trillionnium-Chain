"""Adversarial controls for paired resource-premise experiments and readback."""
from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path
import tempfile
import unittest

from quantum_network_sim import NetworkScenario, ParticipationShock, Simulator
from experiments import joint_resource_competition_campaign as campaign


def renumber(rows):
    for index, row in enumerate(rows):
        row["row"] = index


class RosterControls(unittest.TestCase):
    def test_full_roster_retains_every_declared_factor_and_seed(self):
        cases = campaign.cases_for()
        self.assertEqual(len(cases), 128)
        self.assertEqual(len({campaign.case_id(case) for case in cases}), 128)
        self.assertEqual({case.seed for case in cases}, set(campaign.DEFAULT_SEEDS))
        self.assertEqual({case.duration_seconds for case in cases}, {3600.0})
        for offset in range(0, len(cases), 2):
            campaign.check_pair(*cases[offset:offset + 2])
        for seed in campaign.DEFAULT_SEEDS:
            self.assertEqual(sum(case.seed == seed for case in cases), 32)

    def test_resource_change_cannot_masquerade_as_strategy_change(self):
        honest, private = campaign.cases_for((6101,), 10)[:2]
        changes = [dict(seed=6102), dict(duration_seconds=11), dict(quantum_processors=2),
                   dict(quantum_iteration_seconds=0.14), dict(quantum_proof_seconds=0.9),
                   dict(classical_proof_seconds=0.2), dict(classical_shares=(0.25, 0.75)),
                   dict(classical_block_rate_at_initial_target=0.11), dict(propagation_seconds=0.1),
                   dict(shocks=(ParticipationShock(2, 0.9, 1),)), dict(max_events=1000),
                   dict(quantum_clock_rounding="nearest"), dict(policy="periodic-target")]
        for change in changes:
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "UNEQUAL|PAIR_STRATEGY"):
                campaign.check_pair(honest, replace(private, **change))

    def test_fixed_and_periodic_arms_share_the_same_declared_resources(self):
        cases = campaign.cases_for((6101,), 10)
        for offset in range(0, len(cases), 4):
            fixed, periodic = cases[offset], cases[offset + 2]
            a = {key: value for key, value in asdict(fixed).items() if key not in {"policy", "name"}}
            b = {key: value for key, value in asdict(periodic).items() if key not in {"policy", "name"}}
            self.assertTrue(campaign.same(a, b))

    def test_invalid_denominators_and_nonfinite_horizons_refuse(self):
        for seeds in ((), (1, 1), (True,), (1.0,), (-1,), tuple(range(5))):
            with self.subTest(seeds=seeds), self.assertRaises(ValueError):
                campaign.cases_for(seeds, 10)
        for duration in (True, 9, 3601, float("nan"), float("inf")):
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                campaign.cases_for((6101,), duration)

    def test_unknown_physics_network_and_task_supply_are_not_qualified(self):
        self.assertFalse(campaign.CONTRACT["physical_resource_fairness_qualified"])
        self.assertFalse(campaign.CONTRACT["network_byte_budget_qualified"])
        self.assertIn("UNIMPLEMENTED", campaign.CONTRACT["task_supply"])
        for key in ("common_prefix_failure_bound", "chain_growth_failure_bound",
                    "chain_quality_failure_bound", "installed_confirmation_failure_bound"):
            self.assertIsNone(campaign.CONTRACT[key])


class IndependentReadbackControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = NetworkScenario("reader_control", seed=6101, duration_seconds=90.0,
                                  quantum_iteration_seconds=0.05, quantum_clock_rounding="upward",
                                  classical_block_rate_at_initial_target=0.2)
        cls.summary, cls.rows = Simulator(cls.case).run()
        cls.checked = campaign.readback(cls.case, cls.summary, cls.rows)

    def test_paid_tail_attempts_are_retained_at_the_shared_horizon(self):
        self.assertTrue(self.checked["all_declared_capacity_checks_pass"])
        charges = self.checked["resource_charges"]
        self.assertTrue(any(value["right_censored_searches"] > 0 for value in charges.values()))
        self.assertGreater(charges["q"]["search_seconds_charged"], 0)
        self.assertEqual(int(self.checked["quantum_adopted_credit"])
                         + int(self.checked["classical_adopted_credit"]),
                         int(self.summary["observer_added_chainwork"]))

    def test_changed_or_missing_losing_cost_refuses(self):
        changed = deepcopy(self.summary)
        changed["miners"]["q"]["search_seconds"] = 0.0
        with self.assertRaisesRegex(ValueError, "CHARGED_CLOCK"):
            campaign.readback(self.case, changed, self.rows)

    def test_zeroed_classical_query_cost_refuses_below_the_capacity_cap(self):
        changed = deepcopy(self.summary)
        self.assertGreater(changed["miners"]["c0"]["classical_query_equivalents"], 0)
        changed["miners"]["c0"]["classical_query_equivalents"] = 0.0
        with self.assertRaisesRegex(ValueError, "CHARGED_CLOCK"):
            campaign.readback(self.case, changed, self.rows)

    def test_forged_logical_iteration_rows_refuse_even_with_matching_summary(self):
        rows, summary = deepcopy(self.rows), deepcopy(self.summary)
        row = next(item for item in rows if item.get("miner") == "q"
                   and item["kind"].startswith("search-") and "logical_iterations" in item)
        row["logical_iterations"] += 1
        summary["miners"]["q"]["logical_iterations_completed"] += 1
        with self.assertRaisesRegex(ValueError, "LOGICAL_ITERATION_CHARGE"):
            campaign.readback(self.case, summary, rows)

    def test_rewritten_quantum_stage_clock_refuses(self):
        rows = deepcopy(self.rows)
        row = next(item for item in rows if item["kind"] == "search-start" and item["miner"] == "q")
        row["iteration_seconds_upper"] /= 2
        with self.assertRaisesRegex(ValueError, "QUANTUM_STAGE_CLOCK"):
            campaign.readback(self.case, self.summary, rows)

    def test_unpaid_candidate_check_alias_refuses(self):
        summary = deepcopy(self.summary)
        self.assertGreater(summary["miners"]["q"]["candidate_check_processor_seconds"], 0)
        summary["miners"]["q"]["candidate_check_processor_seconds"] = 0.0
        with self.assertRaisesRegex(ValueError, "CANDIDATE_PROCESSOR_CLOCK"):
            campaign.readback(self.case, summary, self.rows)

    def test_missing_censored_terminal_cannot_erase_an_open_attempt(self):
        rows, summary = deepcopy(self.rows), deepcopy(self.summary)
        index = next(i for i, row in enumerate(rows) if row["kind"] == "search-censored")
        del rows[index]
        renumber(rows)
        summary["trace_rows"] = len(rows)
        with self.assertRaisesRegex(ValueError, "UNCLOSED_SEARCH_COST"):
            campaign.readback(self.case, summary, rows)

    def test_blocks_require_a_matching_paid_search_and_proof(self):
        rows, summary = deepcopy(self.rows), deepcopy(self.summary)
        index = next(i for i, row in enumerate(rows) if row["kind"] == "proof-start")
        del rows[index]
        renumber(rows)
        summary["trace_rows"] = len(rows)
        with self.assertRaisesRegex(ValueError, "BLOCK_WITHOUT_PAID_PROOF"):
            campaign.readback(self.case, summary, rows)

    def test_wrong_required_target_is_rejected_before_credit_comparison(self):
        rows = deepcopy(self.rows)
        row = next(item for item in rows if item["kind"] == "search-start")
        row["target_hex"] = f"{int(row['target_hex'], 16) + 1:064x}"
        with self.assertRaisesRegex(ValueError, "REQUIRED_TARGET"):
            campaign.check_target_policy(rows, self.case)

    def test_typed_counts_and_credit_claims_cannot_alias(self):
        for field, value in (("trace_rows", float(len(self.rows))),
                             ("blocks_created", float(self.summary["blocks_created"]))):
            summary = deepcopy(self.summary)
            summary[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                campaign.readback(self.case, summary, self.rows)
        self.assertFalse(campaign.same({"closed": False}, {"closed": 0}))
        self.assertFalse(campaign.same({"count": 1}, {"count": 1.0}))

    def test_early_termination_is_not_a_complete_horizon(self):
        for change in ({"termination": "cpu-limit"}, {"trace_limit_reached": True},
                       {"observation_seconds": 89.0}):
            summary = {**self.summary, **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                campaign.readback(self.case, summary, self.rows)

    def test_legitimate_fast_honest_epochs_keep_the_original_clamp(self):
        case = NetworkScenario("fast_honest", seed=6101, duration_seconds=60.0,
                               quantum_initial_factor=0, classical_block_rate_at_initial_target=10.0,
                               classical_proof_seconds=0, propagation_seconds=0)
        summary, rows = Simulator(case).run()
        checked = campaign.readback(case, summary, rows)
        self.assertGreater(checked["integer_policy_readback"]["positive_short_epochs_accepted"], 0)
        self.assertGreater(summary["blocks_created"], 16)

    def test_fixed_target_stays_constant_across_more_than_two_epochs(self):
        case = NetworkScenario("fixed_fast_honest", seed=6101, duration_seconds=10.0,
                               policy="fixed-target", quantum_initial_factor=0,
                               classical_block_rate_at_initial_target=10.0,
                               classical_proof_seconds=0, propagation_seconds=0)
        simulator = Simulator(case)
        summary, rows = simulator.run()
        checked = campaign.readback(case, summary, rows)
        block_rows = [row for row in rows if row["kind"] == "block"]
        self.assertGreater(len(block_rows), 32)
        self.assertEqual({row["target_hex"] for row in block_rows}, {f"{simulator.initial_target:064x}"})
        self.assertEqual(checked["integer_policy_readback"]["periodic_retargets_checked"], 0)
        self.assertTrue(checked["all_declared_capacity_checks_pass"])

    def test_shock_dependent_query_rates_are_independently_accounted(self):
        case = replace(self.case, name="shock_reader", shocks=(
            ParticipationShock(15, 0.1, 0.5), ParticipationShock(55, 2.0, 1.0)))
        summary, rows = Simulator(case).run()
        checked = campaign.readback(case, summary, rows)
        self.assertTrue(checked["all_declared_capacity_checks_pass"])
        altered = replace(case, shocks=(ParticipationShock(15, 0.2, 0.5), ParticipationShock(55, 2.0, 1.0)))
        with self.assertRaisesRegex(ValueError, "SHOCK_BINDING"):
            campaign.readback(altered, summary, rows)

    def test_initial_time_shock_obeys_trace_order_at_equal_clocks(self):
        case = replace(self.case, name="time_zero_shock", duration_seconds=20.0,
                       policy="fixed-target", shocks=(ParticipationShock(0, 0.5, 0.5),))
        summary, rows = Simulator(case).run()
        checked = campaign.readback(case, summary, rows)
        self.assertTrue(checked["all_declared_capacity_checks_pass"])
        first_shock = next(index for index, row in enumerate(rows) if row["kind"] == "shock")
        self.assertTrue(all(row["at_seconds"] == 0 for row in rows[:first_shock]))


class CampaignArtifactControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.original = Path(cls.temp.name) / "original"
        cls.result = campaign.run_campaign(cls.original, ["test-scope"], (6101,), 10.0)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def changed_copy(self, name):
        import shutil
        destination = Path(self.temp.name) / name
        shutil.copytree(self.original, destination)
        return destination

    def reseal(self, out, filename):
        manifest = json.loads((out / "manifest.json").read_text())
        manifest["files_sha256"][filename] = campaign.digest(out / filename)
        (out / "manifest.json").write_bytes(campaign.canonical(manifest))

    def test_complete_original_replays_and_keeps_all_denominators(self):
        self.assertEqual(self.result["planned_runs"], 32)
        self.assertEqual(self.result["complete_readback_runs"], 32)
        self.assertEqual(campaign.verify_campaign(self.original)["pairs"], 16)

    def test_rehashed_resource_substitution_still_refuses(self):
        out = self.changed_copy("resource")
        report = json.loads((out / "report.json").read_text())
        filename = report["observations"][1]
        record = json.loads((out / filename).read_text())
        record["parameters"]["quantum_processors"] = 2
        (out / filename).write_bytes(campaign.canonical(record))
        self.reseal(out, filename)
        with self.assertRaisesRegex(ValueError, "SCENARIO_SUBSTITUTION"):
            campaign.verify_campaign(out)

    def test_rehashed_policy_substitution_still_refuses(self):
        out = self.changed_copy("policy")
        roster = json.loads((out / "roster.json").read_text())
        roster["cases"][0]["policy"] = "periodic-target"
        (out / "roster.json").write_bytes(campaign.canonical(roster))
        self.reseal(out, "roster.json")
        with self.assertRaisesRegex(ValueError, "ROSTER_SUBSTITUTION"):
            campaign.verify_campaign(out)

    def test_rehashed_truncated_trace_cannot_claim_completion(self):
        out = self.changed_copy("truncated")
        report = json.loads((out / "report.json").read_text())
        record = json.loads((out / report["observations"][0]).read_text())
        path = out / record["trace_file"]
        rows = campaign.read_rows(path)
        path.unlink()
        campaign.write_rows(path, rows[:-1])
        self.reseal(out, path.name)
        with self.assertRaisesRegex(ValueError, "TRACE_ROW_COUNT"):
            campaign.verify_campaign(out)

    def test_rehashed_summary_credit_alias_refuses(self):
        out = self.changed_copy("credit_alias")
        report = json.loads((out / "report.json").read_text())
        report["comparison"]["security_probability_estimated"] = 0
        (out / "report.json").write_bytes(campaign.canonical(report))
        self.reseal(out, "report.json")
        with self.assertRaisesRegex(ValueError, "COMPARISON_SUBSTITUTION"):
            campaign.verify_campaign(out)

    def test_selected_pair_or_seed_deletion_cannot_change_the_denominator(self):
        out = self.changed_copy("missing_pair")
        report = json.loads((out / "report.json").read_text())
        report["observations"] = report["observations"][2:]
        (out / "report.json").write_bytes(campaign.canonical(report))
        self.reseal(out, "report.json")
        with self.assertRaisesRegex(ValueError, "OBSERVATION_INVENTORY"):
            campaign.verify_campaign(out)

    def test_incomplete_pair_is_retained_with_unknown_credit_delta(self):
        cases = campaign.cases_for((6101,), 10.0)
        report = json.loads((self.original / "report.json").read_text())
        records = [json.loads((self.original / name).read_text()) for name in report["observations"]]
        records[1]["summary"]["termination"] = "event-limit"
        records[1]["readback"] = None
        records[1]["readback_error"] = {"type": "ValueError", "message": "INCOMPLETE_HORIZON"}
        comparison = campaign.observations_comparison(cases, records)
        self.assertEqual(comparison["planned_pairs"], 16)
        self.assertEqual(comparison["complete_pairs"], 15)
        self.assertIsNone(comparison["pairs"][0]["private_minus_honest_quantum_adopted_credit"])
        self.assertEqual(comparison["by_policy"][0]["incomplete_pairs"], 1)
        self.assertIsNone(comparison["by_policy"][0]["paired_credit_delta_sum"])


if __name__ == "__main__":
    unittest.main()
