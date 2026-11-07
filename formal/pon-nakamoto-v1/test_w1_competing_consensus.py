"""Finite continuing-public-branch controls; reduced predicates are not native evidence."""
from copy import deepcopy
from dataclasses import replace
from fractions import Fraction
import unittest
from unittest.mock import patch

import contract_wire as wire
from quantum_oracle_resources import ClassicalCosts, example
from reference import work
from test_w1_finite_consensus import reduced_native_shaped_dag, resign
import w1_competing_consensus as competing
from w1_finite_consensus import _parameters, digest, rational, ratio


def reduced_competition(fixture):
    parent = fixture["public_tip"]
    network = wire.header_decode(bytes.fromhex(parent["header_hex"]))
    blocks = []
    for index in (1, 2):
        fields = {**network, "parent": bytes.fromhex(parent["block_id"]),
                  "height": parent["height"] + 1, "timestamp": 1160 + index, "nonce": index}
        raw, trace = wire.header_encode(fields), bytes([index + 10]) * 32
        credit = int(parent["chainwork_hex"], 16) + work(int(parent["target_hex"], 16))
        block = {"block_id": wire.H("block", raw, trace).hex(), "parent_id": parent["block_id"],
                 "height": fields["height"], "timestamp": fields["timestamp"],
                 "target_hex": parent["target_hex"], "chainwork_hex": f"{credit:0128x}",
                 "header_hex": raw.hex(), "trace": trace.hex()}
        blocks.append(block)
        parent = block
    return {"schema": competing.FIXTURE_SCHEMA, "base_fixture_canonical_sha256": digest(fixture),
            "public_producer_view": "isolated-public-branch-until-horizon",
            "equal_time_order": "honest-before-private-parent-first", "honest_blocks": blocks,
            "initial_resources": {"scope": "reduced unit metadata, no native work or admission claim"},
            "scenarios": [{"scenario_id": name, "arrivals": [
                {"block_id": block["block_id"], "at_seconds": ratio(at)}
                for block, at in zip(blocks, times)]}
                for name, times in (("early", (Fraction(1), Fraction(3))),
                                    ("late", (Fraction(5, 2), Fraction(7, 2))))]}


class CompetingConsensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = reduced_native_shaped_dag()
        cls.competition = reduced_competition(cls.fixture)
        costs = tuple(ClassicalCosts(1000, 1000, 1000, 1000, 10**9, 10**8)
                      for _ in cls.fixture["contexts"])
        physical = replace(example(True).physical_models[0], magic_state_error="0")
        cls.parameters = _parameters(costs, physical, 1 << 100, "4", (0,), 2, "full", 10000,
                                     None, "classical-uniform-q0")
        cls.parameters.update(scenario_id="late", risk_event=competing.RISK_EVENTS[0])
        cls.report = competing.analyze_competing_consensus(cls.fixture, cls.competition, cls.parameters)

    def build(self, *, scenario="late", event=competing.RISK_EVENTS[0], competition=None, **changes):
        parameters = {**self.parameters, "scenario_id": scenario, "risk_event": event, **changes}
        return competing.analyze_competing_consensus(self.fixture, self.competition if competition is None else competition,
                                                     parameters)

    def test_late_transient_probability_matches_independent_nonce_path_count(self):
        contexts = {row["context_id"]: row for row in self.fixture["contexts"]}
        root = contexts[self.fixture["root_context_id"]]
        expected = sum((Fraction(len(contexts[row["child_context_id"]]["winner_children"]), 16 * 16)
                        for row in root["winner_children"]), Fraction(0))
        self.assertGreater(expected, 0)
        self.assertEqual(rational(self.report["risk_upper"]), expected)
        self.assertEqual(rational(self.report["fixed_policy_risks"]["0"]), expected)
        result = competing.verify_competing_certificate(self.report, self.fixture, self.competition)
        self.assertTrue(result["bellman_checked"])
        self.assertEqual(result["honest_arrivals_checked"], 2)

    def test_early_honest_work_prevents_private_replacement(self):
        report = self.build(scenario="early")
        self.assertEqual(rational(report["risk_upper"]), 0)
        self.assertEqual(rational(report["fixed_policy_risks"]["0"]), 0)
        self.assertIsNone(report["positive_path"])
        witness = competing.observer_selected_path(report, self.fixture, self.competition)
        terminal = witness["trajectory"][-1]["edge"]["observation"]
        self.assertTrue(terminal["publication_complete"])
        self.assertFalse(terminal["ever_private_replacement"])
        self.assertFalse(witness["sampled_execution"])

    def test_transient_replacement_and_deadline_selection_are_distinct(self):
        witness = competing.observer_selected_path(self.report, self.fixture, self.competition)
        terminal = witness["trajectory"][-1]["edge"]["observation"]
        self.assertTrue(terminal["ever_private_replacement"])
        self.assertFalse(terminal["private_active_at_horizon"])
        self.assertEqual([row["owner"] for row in terminal["receiver_events"]],
                         ["private", "private", "honest", "honest"])
        for scenario in ("early", "late"):
            report = self.build(scenario=scenario, event=competing.RISK_EVENTS[1])
            self.assertEqual(rational(report["risk_upper"]), 0)
            self.assertTrue(competing.verify_competing_certificate(report, self.fixture,
                                                                  self.competition)["bellman_checked"])

    def test_exact_equal_time_is_honest_first_and_equal_work_preserves_tip(self):
        model = competing.CompetingModel(self.fixture, self.competition, self.parameters)
        control = competing.observer_selected_path(self.report, self.fixture, self.competition)
        chain = control["trajectory"][-1]["edge"]["observation"]["private_chain"]
        at = Fraction(5, 2)
        tied = model.receiver_trace(chain, at)
        before = model.receiver_trace(chain, at - Fraction(1, 10**30))
        self.assertFalse(tied["ever_private_replacement"])
        self.assertTrue(before["ever_private_replacement"])
        self.assertEqual(tied["receiver_events"][0]["owner"], "honest")
        self.assertFalse(tied["receiver_events"][2]["selection_changed"])
        self.assertEqual(before["receiver_events"][2]["selected_tip"], chain[-1])
        self.assertFalse(before["receiver_events"][2]["selection_changed"])

    def test_honest_arrivals_continue_after_stop_or_private_publication(self):
        model = competing.CompetingModel(self.fixture, self.competition, self.parameters)
        edge = model.transition(model.initial(), {"kind": "stop"})[0]
        self.assertEqual(edge["observation"]["time"], ratio(Fraction(0)))
        self.assertEqual(len(edge["observation"]["receiver_events"]), 2)
        self.assertEqual(edge["observation"]["receiver_observed_until_seconds"], ratio(Fraction(4)))
        self.assertEqual(edge["observation"]["selected_tip_at_horizon"], self.competition["honest_blocks"][-1]["block_id"])

    def test_wait_progresses_to_next_arrival_without_new_attempt(self):
        model = competing.CompetingModel(self.fixture, self.competition, self.parameters)
        state = model.initial()
        for at in (Fraction(5, 2), Fraction(7, 2)):
            edge = model.transition(state, {"kind": "wait-next-honest"})[0]
            state = edge["next_state"]
            self.assertEqual(state["time"], ratio(at))
            self.assertEqual(state["attempts"], 0)
        self.assertNotIn({"kind": "wait-next-honest"}, model.actions(state))

    def test_seeded_samples_are_reproducible_and_keep_unsuccessful_outcomes(self):
        first = competing.sample_competing_policy(self.report, self.fixture, self.competition, seed=9)
        self.assertEqual(first, competing.sample_competing_policy(self.report, self.fixture, self.competition, seed=9))
        self.assertFalse(first["policy_reads_marked_count_or_bellman_values"])
        self.assertFalse(first["policy_reads_future_honest_arrivals"])
        self.assertFalse(first["quantum_hardware_executed"])
        self.assertEqual(first["schema"], competing.SAMPLE_SCHEMA)

    def test_native_safety_and_cost_claims_are_not_inferred_from_schedule(self):
        scope = self.report["scope"]
        for key in ("whole_network_machine_error_bound_composed", "public_producer_reacts_to_private_publication",
                    "mid_action_abort_restart_or_public_branch_switch_covered",
                    "stochastic_continuing_honest_mining_covered", "long_horizon_settlement_security_proved",
                    "physical_clock_calibrated", "quantum_hardware_executed", "quantum_mining_qualified"):
            self.assertIs(scope[key], False)
        self.assertIn("not bounded", scope["external_honest_schedule_condition"])
        self.assertIn("complete-future-public-schedule-aware", scope["maximum_value_policy"])
        self.assertEqual(self.report["parameters"]["horizon_seconds"], "4")
        self.assertEqual(self.report["parameters"]["max_attempts"], 2)
        self.assertIsNone(self.report["machine_envelope"])

    def test_source_or_base_fixture_rebinding_refused(self):
        changed = deepcopy(self.competition)
        changed["base_fixture_canonical_sha256"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "BASE_FIXTURE_BINDING"):
            self.build(competition=changed)
        report = deepcopy(self.report)
        report["source_sha256"][next(iter(report["source_sha256"]))] = "00" * 32
        resign(report)
        with self.assertRaisesRegex(ValueError, "PREMISE: source_sha256"):
            competing.verify_competing_certificate(report, self.fixture, self.competition)

    def test_schedule_and_metric_tampering_refused(self):
        for key, value in (("risk_event", "settlement"), ("scenario_id", "unknown")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                competing.CompetingModel(self.fixture, self.competition, {**self.parameters, key: value})
        for mutation in ("omit", "time", "order", "tie", "view"):
            changed = deepcopy(self.competition)
            if mutation == "omit":
                changed["scenarios"][0]["arrivals"].pop()
            elif mutation == "time":
                changed["scenarios"][0]["arrivals"][0]["at_seconds"] = ratio(Fraction(5))
            elif mutation == "order":
                changed["scenarios"][0]["arrivals"].reverse()
            elif mutation == "tie":
                changed["equal_time_order"] = "private-first"
            else:
                changed["public_producer_view"] = "global-synchronous-honest-miner"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.build(competition=changed)

    def test_honest_metadata_daa_chainwork_and_identity_checked(self):
        for field, value in (("chainwork_hex", "ff" * 64), ("parent_id", "ab" * 32),
                             ("target_hex", "01" * 32), ("trace", "cd" * 32)):
            changed = deepcopy(self.competition)
            changed["honest_blocks"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.build(competition=changed)

    def test_checker_recomputes_graph_without_invoking_optimizer(self):
        with patch("w1_finite_consensus._analyze_model", side_effect=AssertionError("optimizer forbidden")):
            self.assertTrue(competing.verify_competing_certificate(self.report, self.fixture,
                                                                  self.competition)["bellman_checked"])

    def test_resigned_omitted_arrival_or_forged_tip_rejected(self):
        for mutation in ("omit-event", "tip", "risk"):
            report = deepcopy(self.report)
            initial = report["nodes"][digest(competing.CompetingModel(self.fixture, self.competition,
                                                                     self.parameters).initial())]
            edge = initial["actions"][0]["edges"][0]
            if mutation == "omit-event":
                edge["observation"]["receiver_events"].pop()
            elif mutation == "tip":
                edge["observation"]["selected_tip_at_horizon"] = self.fixture["public_tip"]["block_id"]
            else:
                edge["terminal_risk"] = 1
            resign(report)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "TRANSITION_MISMATCH"):
                competing.verify_competing_certificate(report, self.fixture, self.competition)

    def test_incomplete_graph_remains_unknown_not_zero(self):
        report = self.build(max_states=1)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertIsNone(report["risk_upper"])
        self.assertFalse(competing.verify_competing_certificate(report, self.fixture,
                                                               self.competition)["bellman_checked"])
        report["risk_upper"] = ratio(Fraction(0))
        resign(report)
        with self.assertRaisesRegex(ValueError, "INCOMPLETE_CANNOT_CERTIFY"):
            competing.verify_competing_certificate(report, self.fixture, self.competition)


if __name__ == "__main__":
    unittest.main()
