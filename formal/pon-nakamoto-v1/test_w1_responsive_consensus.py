"""Checks for the conditional model, including complete-denominator failures."""
from copy import deepcopy
from fractions import Fraction
import unittest
from unittest.mock import patch

import w1_responsive_consensus as model


def resign(report):
    report["certificate_sha256"] = model.digest({key: value for key, value in report.items()
                                               if key != "certificate_sha256"})
    return report


class ResponsiveCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parameters = model.declared_parameters()
        cls.certificate = model.analyze_responsive_consensus(cls.parameters)
        cls.fast_parameters = model.declared_parameters(private_winner_proof_ticks=1)
        cls.fast_certificate = model.analyze_responsive_consensus(cls.fast_parameters)

    def test_complete_four_second_six_start_graph_and_independent_forward_probability(self):
        result = model.verify_responsive_certificate(self.certificate)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual((result["states"], result["edges"]), (3361, 5236))
        self.assertEqual(model.rational(self.parameters["tick_seconds"]) * self.parameters["horizon_ticks"], 4)
        self.assertEqual(self.parameters["max_honest_attempts"], 6)
        forward = model.fixed_policy_probability(self.parameters)
        self.assertEqual(forward["fixed_policy_risks"], self.certificate["fixed_policy_risks"])
        self.assertEqual(set(map(model.rational, forward["fixed_policy_risks"].values())), {Fraction(343, 32768)})
        self.assertFalse(result["native_W1_probabilities_certified"])

    def test_checker_does_not_call_optimizer(self):
        with patch.object(model, "analyze_responsive_consensus", side_effect=AssertionError("optimizer forbidden")):
            self.assertTrue(model.verify_responsive_certificate(self.certificate)["bellman_checked"])

    def test_ancestry_survival_differs_from_final_private_ownership(self):
        self.assertEqual(model.verify_responsive_certificate(self.fast_certificate)["states"], 2828)
        risks = self.fast_certificate["maximum_risks"]
        self.assertEqual(model.rational(risks["private_ancestor_at_horizon"]), Fraction(7, 512))
        self.assertEqual(model.rational(risks["private_tip_at_horizon"]), Fraction(343, 32768))
        self.assertGreater(model.rational(risks["private_ancestor_at_horizon"]),
                           model.rational(risks["private_tip_at_horizon"]))
        forward = model.fixed_policy_probability(self.fast_parameters)
        self.assertEqual(forward["fixed_policy_risks"], self.fast_certificate["fixed_policy_risks"])

    def test_forged_root_value_rejected_after_digest_is_recomputed(self):
        corrupt = deepcopy(self.certificate)
        corrupt["maximum_risks"] = {**corrupt["maximum_risks"], model.RISK_EVENTS[0]: model.ratio(Fraction(1))}
        with self.assertRaisesRegex(ValueError, "RESPONSIVE_ROOT_VALUE"):
            model.verify_responsive_certificate(resign(corrupt))

    def test_missing_action_rejected_after_digest_is_recomputed(self):
        corrupt = deepcopy(self.certificate)
        root = corrupt["nodes"][model.digest(corrupt["initial_state"])]
        root["actions"].pop()
        with self.assertRaisesRegex(ValueError, "COMPLETE_ACTION_INVENTORY"):
            model.verify_responsive_certificate(resign(corrupt))

    def test_missing_reachable_state_rejected_after_digest_is_recomputed(self):
        corrupt = deepcopy(self.certificate)
        root = corrupt["nodes"][model.digest(corrupt["initial_state"])]
        del corrupt["nodes"][root["actions"][0]["edges"][0]["next"]]
        with self.assertRaisesRegex(ValueError, "FINITE_TIME_OR_CHILD"):
            model.verify_responsive_certificate(resign(corrupt))

    def test_forged_transition_probability_rejected_after_digest_is_recomputed(self):
        corrupt = deepcopy(self.certificate)
        root = corrupt["nodes"][model.digest(corrupt["initial_state"])]
        root["actions"][0]["edges"][0]["probability"] = model.ratio(Fraction(1, 2))
        with self.assertRaisesRegex(ValueError, "TRANSITION_MISMATCH"):
            model.verify_responsive_certificate(resign(corrupt))

    def test_changed_scope_and_source_rejected(self):
        for key in ("scope", "source_sha256"):
            corrupt = deepcopy(self.certificate)
            corrupt[key] = {}
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "RESPONSIVE_PREMISE"):
                model.verify_responsive_certificate(resign(corrupt))

    def test_state_and_edge_caps_never_report_a_risk_bound(self):
        for changes in ({"max_states": 1}, {"max_edges": 1}):
            report = model.analyze_responsive_consensus(model.declared_parameters(**changes))
            self.assertEqual(report["status"], "INCOMPLETE")
            self.assertIsNone(report["maximum_risks"])
            self.assertIsNone(report["conditional_fault_risk_bounds"])
            self.assertFalse(model.verify_responsive_certificate(report)["bellman_checked"])
            corrupt = deepcopy(report)
            corrupt["maximum_risks"] = {name: model.ratio(Fraction(0)) for name in model.RISK_EVENTS}
            with self.assertRaisesRegex(ValueError, "INCOMPLETE_CANNOT_CERTIFY"):
                model.verify_responsive_certificate(resign(corrupt))

    def test_fault_perturbation_bound_is_a_stated_hypothesis(self):
        p = model.declared_parameters(max_honest_attempts=1, fault_union_upper=model.ratio(Fraction(1, 100)))
        report = model.analyze_responsive_consensus(p)
        self.assertEqual(model.verify_responsive_certificate(report)["status"], "VERIFIED")
        for name, value in report["maximum_risks"].items():
            bound = report["conditional_fault_risk_bounds"][name]
            self.assertEqual(model.rational(bound["upper"]), min(Fraction(1), model.rational(value) + Fraction(1, 100)))
        self.assertIn("assumption", p["fault_coupling_scope"])
        self.assertFalse(report["scope"]["physical_clock_calibrated"])
        self.assertFalse(report["scope"]["quantum_mining_qualified"])


class ResponsiveExecutionTests(unittest.TestCase):
    def test_cancellation_rebind_stale_arrival_and_all_started_costs(self):
        parameters = model.declared_parameters(private_winner_proof_ticks=1)
        sample = model.sample_responsive_policy(parameters, 401)
        self.assertEqual(model.verify_responsive_sample(sample)["status"], "VERIFIED")
        events = [event for row in sample["trajectory"] for event in row["edge"]["events"]]
        cancelled = [event for event in events if event["kind"] == "honest-cancel"]
        self.assertEqual([event["charged_elapsed_ticks"] for event in cancelled], [1, 2])
        rebound = next(event for event in events if event["kind"] == "honest-start" and event["tick"] == 7)
        self.assertEqual(rebound["parent"], "p2")
        stale = next(event for event in events if event["kind"] == "receiver-admit" and event["block"] == "h2")
        self.assertEqual((stale["tick"], stale["selected_before"], stale["selected_after"]), (7, "p2", "p2"))
        terminal = sample["trajectory"][-1]["edge"]["next_state"]
        self.assertEqual(terminal["honest_elapsed_ticks"], 4 * 3 + 1 + 2)
        self.assertEqual(terminal["honest_started"], terminal["honest_completed"] + terminal["honest_cancelled"])
        self.assertEqual(sample["outcomes"], dict(zip(model.RISK_EVENTS, (1, 0, 1, 1))))

    def test_completed_packet_survives_notification_at_its_completion_tick(self):
        parameters = model.declared_parameters(private_winner_proof_ticks=1, honest_delivery_ticks=3,
                                              honest_tip_notification_ticks=0)
        m = model.ResponsiveModel(parameters)
        state = m.initial()
        # Two private wins deliver at5/6. Honest h2 completes at6 before notice,
        # so its already completed packet must remain scheduled to arrive at9.
        for _ in range(6):
            edges = m.transition(state, model.fixed_action(m, state))
            edge = next(edge for edge in edges if all(event.get("success") is (event["kind"] != "honest-complete" or event["tick"] == 6)
                        for event in edge["events"] if "success" in event))
            state = edge["next_state"]
        self.assertTrue(any(row["block"] == "h2" and row["due"] == 9 for row in state["deliveries"]))
        self.assertEqual(state["honest_view"], "p2")
        self.assertEqual(state["honest_cancelled"], 0)
        self.assertEqual(state["honest_active"]["parent"], "p2")

    def test_stop_private_does_not_stop_honest_clock_or_erase_pending_work(self):
        p = model.declared_parameters(honest_attempt_ticks=20)
        m = model.ResponsiveModel(p)
        state = m.transition(m.initial(), {"kind": "stop"})[0]["next_state"]
        while state["tick"] < m.limit:
            state = m.transition(state, {"kind": "wait"})[0]["next_state"]
        self.assertEqual(state["honest_elapsed_ticks"], 16)
        self.assertEqual(state["honest_active"]["due"], 20)
        self.assertEqual(state["honest_started"], 1)
        self.assertEqual(state["private_started"], 0)

    def test_equal_time_arrivals_are_honest_first_and_exact_work_ties_keep_tip(self):
        m = model.ResponsiveModel(model.declared_parameters())
        state = m.initial()
        state["nodes"]["h-test"] = {"parent": "public", "owner": "honest", "work": 2}
        state["nodes"]["p-test"] = {"parent": "base", "owner": "private", "work": 2}
        state["deliveries"] = [{"owner": "private", "block": "p-test", "due": 1},
                               {"owner": "honest", "block": "h-test", "due": 1}]
        result = m.transition(state, {"kind": "wait"})[0]
        arrivals = [event for event in result["events"] if event["kind"] == "receiver-admit"]
        self.assertEqual([event["owner"] for event in arrivals], ["honest", "private"])
        self.assertEqual(result["next_state"]["selected"], "h-test")

    def test_private_deadline_censor_keeps_elapsed_candidate_cost(self):
        p = model.declared_parameters(private_candidate_ticks=40)
        sample = model.sample_responsive_policy(p, 9)
        final = sample["trajectory"][-1]["edge"]["next_state"]
        self.assertEqual(final["private_elapsed_ticks"], 16)
        self.assertEqual(final["private_started"], 1)
        self.assertEqual(final["private_checks_completed"], 0)
        self.assertEqual(final["private_active"]["due"], 40)
        self.assertFalse(any(sample["outcomes"].values()))

    def test_fixed_policy_sample_checker_does_not_call_sample_writer(self):
        sample = model.sample_responsive_policy(model.declared_parameters(), 73)
        with patch.object(model, "sample_responsive_policy", side_effect=AssertionError("writer forbidden")):
            self.assertEqual(model.verify_responsive_sample(sample)["status"], "VERIFIED")

    def test_resigned_trajectory_with_future_advice_is_rejected(self):
        sample = model.sample_responsive_policy(model.declared_parameters(), 73)
        sample["trajectory"][0]["action"] = {"kind": "wait"}
        sample["sample_sha256"] = model.digest(sample["trajectory"])
        with self.assertRaisesRegex(ValueError, "SAMPLE_CAUSAL_POLICY"):
            model.verify_responsive_sample(sample)

    def test_invalid_or_silently_extended_premises_are_rejected(self):
        for changes in ({"horizon_ticks": 17}, {"horizon_ticks": "16"},
                        {"max_honest_attempts": True}, {"private_winner_proof_ticks": 0},
                        {"tick_seconds": {"numerator": 1, "denominator": 0}},
                        {"fault_union_upper": model.ratio(Fraction(2))}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                model.ResponsiveModel(model.declared_parameters(**changes))
        with self.assertRaisesRegex(ValueError, "CANONICAL_TYPE"):
            model.canonical({"elapsed_seconds": 0.25})

    def test_source_drift_prevents_certification(self):
        with patch.object(model, "source_hashes", side_effect=[{"first": "0"}, {"second": "1"}]):
            with self.assertRaisesRegex(ValueError, "SOURCE_CHANGED"):
                model.analyze_responsive_consensus(model.declared_parameters(max_states=1))


if __name__ == "__main__":
    unittest.main()
