"""Exact scope counterexamples and real ML-DSA/full-W1 statement controls.

The retained W1 bytes must exist and are fully recomputed. These tests do not
invoke a native producer or impersonate a native journal. A separate required
evidence command binds an actual fresh journal and its packet artifacts.
"""
from __future__ import annotations

import copy
from fractions import Fraction as F
from itertools import product
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import certificate_composition as cc
import certificate_observability_models as co
import lifecycle_query_bound as lqc
import work_lifecycle_certificate as wlc


REPO = Path(__file__).resolve().parents[2]
RETAINED_WLC = REPO / "evidence/pon-actual-certificates-20261107/work_lifecycle/run-02-final"
P = F(1, 16)


def two_bit_law():
    return co.ProbabilityTree((
        co.Leaf("hit_hit", ("hit", "hit"), P ** 2),
        co.Leaf("hit_miss", ("hit", "miss"), P * (1 - P)),
        co.Leaf("miss_hit", ("miss", "hit"), (1 - P) * P),
        co.Leaf("miss_miss", ("miss", "miss"), (1 - P) ** 2),
    ))


class QueryScopeCompositionTests(unittest.TestCase):
    def test_both_reports_round_trip_as_exact_rationals_and_are_recomputed(self):
        reports = (
            lqc.global_lifecycle_weight_bound(lqc.LifetimeCaps(1, 0, 1), 128),
            lqc.continuation_given_complete_prefix(distinct_seen=1, marked_seen=1,
                                                   post_queries=0, output_slots=1, credit=128),
        )
        for report in reports:
            wire = json.loads(json.dumps(cc.public_json(report)))
            self.assertEqual(cc.recheck_query_model(wire), report)

    def test_relabeling_global_report_as_conditional_does_not_change_its_theorem(self):
        report = lqc.global_lifecycle_weight_bound(lqc.LifetimeCaps(1, 0, 1), 128)
        report["probability_scope"] = cc.PREFIX_SCOPE
        with self.assertRaisesRegex(cc.CompositionError, "QUERY_MODEL_REPORT_MISMATCH"):
            cc.recheck_query_model(report)

    def test_supplied_small_bound_and_fake_attestation_flags_are_not_trusted(self):
        original = lqc.global_lifecycle_weight_bound(lqc.LifetimeCaps(1, 0, 1), 128)
        for field, value in (("bound", F(0)), ("native_six_successor_risk_certified", True),
                             ("input_parameters_attest_complete_joint_initial_state", True),
                             ("virtual_output_queries_added", True)):
            report = copy.deepcopy(original)
            report[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(cc.CompositionError, "QUERY_MODEL_REPORT_MISMATCH"):
                cc.recheck_query_model(report)

    def test_matching_model_tag_with_changed_mu1_probability_is_refused(self):
        report = lqc.global_lifecycle_weight_bound(lqc.LifetimeCaps(0, 0, 1), 128)
        report["p"] = F(1, 32)
        with self.assertRaisesRegex(cc.CompositionError, "FROZEN_MU1_PROBABILITY"):
            cc.recheck_query_model(report)

    def test_paid_complete_prefix_still_has_different_global_and_observed_hit_risk(self):
        global_report = lqc.global_lifecycle_weight_bound(lqc.LifetimeCaps(1, 0, 1), 128)
        conditional = lqc.continuation_given_complete_prefix(
            distinct_seen=1, marked_seen=1, post_queries=0, output_slots=1, credit=128)
        self.assertEqual(global_report["bound"], F(31, 256))
        self.assertEqual(conditional["bound"], 1)
        law = two_bit_law()
        root = cc.ModelRiskUse("whole_lifetime", (), ("hit_hit", "hit_miss", "miss_hit"), global_report)
        checked = cc.check_model_risk_bank(law, (root,), F(31, 256))
        self.assertEqual(checked["finite_declared_joint_law"]["failure_union_probability"], F(31, 256))
        restarted = cc.ModelRiskUse("selected_hit", ("hit",), ("hit_hit", "hit_miss"), global_report)
        with self.assertRaisesRegex(cc.CompositionError, "GLOBAL_BOUND_IS_NOT_CONDITIONAL"):
            cc.check_model_risk_bank(law, (restarted,), F(31, 256))

    def test_valid_conditional_arithmetic_does_not_authenticate_a_false_prefix_count(self):
        # The model report itself is valid. The declared joint law reveals
        # that the selected history already knows one winner, so risk is one.
        forged_prefix = lqc.continuation_given_complete_prefix(
            distinct_seen=1, marked_seen=0, post_queries=0, output_slots=1, credit=128)
        use = cc.ModelRiskUse("hide_known_winner", ("hit",), ("hit_hit", "hit_miss"), forged_prefix)
        self.assertEqual(cc.recheck_query_model(forged_prefix)["bound"], P)
        with self.assertRaisesRegex(co.ObservabilityError, "INVALID_CONDITIONAL_RISK_AT_START"):
            cc.check_model_risk_bank(two_bit_law(), (use,), F(1))

    def test_correct_known_winner_condition_can_only_spend_its_actual_allowance(self):
        conditional = lqc.continuation_given_complete_prefix(
            distinct_seen=1, marked_seen=1, post_queries=0, output_slots=1, credit=128)
        use = cc.ModelRiskUse("selected_hit", ("hit",), ("hit_hit", "hit_miss"), conditional)
        with self.assertRaisesRegex(co.ObservabilityError, "PREDICTABLE_RISK_BUDGET_OVERSPENT"):
            cc.check_model_risk_bank(two_bit_law(), (use,), F(31, 256))
        actual = cc.check_model_risk_bank(two_bit_law(), (use,), F(1))
        self.assertEqual(actual["finite_declared_joint_law"]["failure_union_probability"], P)
        self.assertEqual(actual["finite_declared_joint_law"]["expected_allowance_spent"], P)
        self.assertFalse(actual["actual_native_probability_law_authenticated"])

    def test_two_attempts_cannot_both_spend_one_shared_risk_allocation(self):
        fresh = lqc.global_lifecycle_weight_bound(lqc.LifetimeCaps(0, 0, 1), 128)
        uses = (cc.ModelRiskUse("first", (), ("hit_hit", "hit_miss"), fresh),
                cc.ModelRiskUse("second", (), ("hit_hit", "miss_hit"), fresh))
        with self.assertRaisesRegex(co.ObservabilityError, "PREDICTABLE_RISK_BUDGET_OVERSPENT"):
            cc.check_model_risk_bank(two_bit_law(), uses, P)
        checked = cc.check_model_risk_bank(two_bit_law(), uses, 2 * P)
        self.assertEqual(checked["finite_declared_joint_law"]["failure_union_probability"], F(31, 256))


class QueryPhaseAndInformationTests(unittest.TestCase):
    def test_after_quantum_search_a_new_classical_reveal_is_not_a_fresh_prefix_trial(self):
        result = cc.post_quantum_classical_reveal_counterexample()
        self.assertEqual(result["actual_reveal_hit_probability_in_model"], F(13073, 32768))
        self.assertGreater(result["actual_reveal_hit_probability_in_model"], P)
        self.assertEqual(sum((row["probability"] for row in result["oracle_count_cases"]), F(0)), 1)
        self.assertFalse(result["actual_quantum_hardware_executed"])

    def test_phase_counterexample_also_defeats_a_falsely_declared_fresh_start_law(self):
        q = cc.post_quantum_classical_reveal_counterexample()["actual_reveal_hit_probability_in_model"]
        law = co.ProbabilityTree((co.Leaf("hit", ("after_quantum", "hit"), q),
                                  co.Leaf("miss", ("after_quantum", "miss"), 1 - q)))
        false_fresh = lqc.continuation_given_complete_prefix(
            distinct_seen=0, marked_seen=0, post_queries=0, output_slots=1, credit=128)
        use = cc.ModelRiskUse("new_local_owner", ("after_quantum",), ("hit",), false_fresh)
        with self.assertRaisesRegex(co.ObservabilityError, "INVALID_CONDITIONAL_RISK_AT_START"):
            cc.check_model_risk_bank(law, (use,), F(1))

    def test_constant_empty_payload_can_have_sixteen_informative_visible_times(self):
        result = cc.empty_payload_timing_counterexample()
        self.assertEqual(result["success_probability"], 1 - F(15, 16) ** 16)
        self.assertEqual(result["distinct_payload_values"], 1)
        self.assertEqual(result["complete_policy_support_including_absence"], 17)
        self.assertGreater(result["success_probability"], F(529, 1024))
        self.assertEqual(result["unpaid_helper_fresh_bound"], P)
        self.assertTrue(result["coarse_record_can_fit_policy_without_complete_mediation"])
        self.assertFalse(result["record_fit_authenticates_complete_observable_alphabet"])

    def test_known_winner_replacement_is_pointwise_without_querying_unknown_marks(self):
        for known in range(4):
            for slots in range(known, 6):
                for used_known in range(known + 1):
                    for unknown in range(slots - used_known + 1):
                        for bits in product((0, 1), repeat=unknown):
                            before = used_known + sum(bits)
                            after = known + sum(bits[:slots - known])
                            self.assertGreaterEqual(after, before)


class SignedExecutionAttributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Full W1 replay validates the retained input. No producer is invoked.
        cls.verify_input, cls.program = cc.retained_unit_verify_input(RETAINED_WLC)
        with patch("subprocess.Popen", side_effect=AssertionError("native producer launched")):
            cls.control = cc.signed_valid_proof_without_producer(cls.verify_input, cls.program)
            cls.checked = wlc.verify_collection(cls.control["documents"], cls.control["pins"],
                                                cls.control["artifacts"], cls.control["root"])

    def test_real_signature_and_valid_full_proof_do_not_prove_claimed_producer_invocation(self):
        result = self.checked["root"]
        self.assertTrue(result["signatures_verified_against_supplied_external_pin"])
        self.assertTrue(result["anchored_observation_fragment_complete"])
        self.assertEqual(result["counters"]["reported_native_calls"], 1)
        self.assertEqual(result["counters"]["full_W1_artifact_predicates_rechecked"], 1)
        self.assertEqual(self.control["native_producer_invocations_while_constructing_statement"], 0)
        self.assertFalse(result["recorder_execution_attested"])

    def test_signer_and_program_hash_are_not_a_global_query_meter(self):
        with self.assertRaisesRegex(wlc.LifecycleError, "LIFECYCLE_COVERAGE_AND_INITIAL_STATE_UNATTESTED"):
            wlc.query_budget_from_observation(self.checked)

    def test_execution_attribution_control_still_requires_the_actual_signature(self):
        documents = copy.deepcopy(self.control["documents"])
        doc = documents[self.control["root"]]
        signature = bytearray.fromhex(doc["end"]["signature"])
        signature[-1] ^= 1
        doc["end"]["signature"] = signature.hex()
        with self.assertRaisesRegex(wlc.LifecycleError, "SIGNATURE_REJECTED"):
            wlc.verify_collection(documents, self.control["pins"], self.control["artifacts"], self.control["root"])

    def test_locally_successful_or_self_promoted_documents_cannot_request_native_risk(self):
        for candidate in (self.checked, {"production_qualified": True, "all_world_events_covered": True,
                                         "joint_initial_state_established": True, "verified": True}):
            with self.subTest(candidate_type=type(candidate).__name__), self.assertRaisesRegex(
                    cc.CompositionError, "NATIVE_RELATION_RESOURCE_STATE_AND_WORLD_BRIDGES_UNPROVED"):
                cc.native_risk_from_join(candidate)


if __name__ == "__main__":
    unittest.main(verbosity=2)
