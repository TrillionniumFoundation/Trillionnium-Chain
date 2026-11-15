"""Isolated declaration/reader controls, with no native workload or effects.

The small JSON inputs below are invented parser fixtures, including the 27/12/3/15
arithmetic example. They are not copies of authenticated native evidence.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import unittest

import chain_hepta_qualification as original
import chain_system_security as security
import test_chain_hepta_qualification as shared_controls


def cost_fixture():
    return dict(schema="pon-fixed-probability-cost-contract-v1",
                cost_envelopes={kind: [dict(units=u, lower=None, upper=None, status="unproved")
                                      for u in range(1, 9)] for kind in ("classical", "quantum")},
                unclosed_obligations=["synthetic-obligation-" + str(i) for i in range(10)],
                accounting=dict(initial_potential_bound=None),
                relation=dict(ideal_probability=dict(numerator=1, denominator=16), native_consensus_credit=False))


def daa_fixture():
    return dict(schema="trnm-joint-consensus-boundaries-v1", scope="synthetic limitations only",
                limitations=dict(uniform_iid_ticket_premise_proved_for_w1=False,
                                 w1_oracle_cost_measured_or_synthesized=False,
                                 native_w1_proofs_generated=0, native_node_activation_executed=False,
                                 network_profitability_or_consensus_safety_theorem=False,
                                 production_consensus_activation=False,
                                 proof_latency_propagation_availability_and_reorg_state_priced=False))


def resource_fixture():
    return dict(schema="trnm-local-resource-owner-contract-v1", status="synthetic-local-component",
                native_integration="synthetic-observer", observer_actual_cpu_measured=False,
                observer_actual_io_measured=False, whole_entry_coverage_qualified=False,
                physical_resource_bound_qualified=False, honest_service_bound_qualified=False,
                independent_rollback_anchor_qualified=False, production_activation=False)


def campaign_fixture(source):
    phases = []
    for run in range(1, 4):
        for mode in ("baseline", "from-zero", "late-product"):
            phases.append(dict(run=run, mode=mode, scheduled_confirmation_rounds=3,
                               observed_confirmation_rounds=2 if mode == "baseline" else 1,
                               confirmed_rounds=1 if mode == "baseline" else 0,
                               unobserved_scheduled_rounds=1 if mode == "baseline" else 2,
                               submission_acks_on_time=14 if mode == "baseline" else 7))
    totals = {name: sum(p[name] for p in phases) for name in
              ("scheduled_confirmation_rounds", "observed_confirmation_rounds",
               "confirmed_rounds", "unobserved_scheduled_rounds")}
    return dict(schema="pon-root-original-campaign-crosscheck-v1", source=source["sha"], tree=source["tree"],
                complete_campaigns=0, actual_campaigns=3, planned_campaigns=3, build_returncode=0,
                all_reports_valid=True, failure="ORIGINAL_THREE_RUN_CAMPAIGN_FAILED", phases=phases, totals=totals,
                controller_resources=dict(cpu_max="400000 100000", memory_max="17179869184"),
                measured_public_phase_placement=dict(profile="fixed-public-phase-external-actors-v1",
                    receiver_and_verifier_cpu_max="25000 100000", receiver_and_verifier_memory_max="2147483648"))


class SystemSecurityTests(unittest.TestCase):
    def setUp(self):
        # Reuse the original reviewer's structural fixture without inheriting and
        # accidentally rerunning/counting its existing test methods.
        self.fixture = shared_controls.QualificationTests("test_consistent_structural_materials_never_grant_production_or_final_use")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.complete()
        self.inputs = dict(schema=security.INPUT_SCHEMA, artifacts=[])

    def add(self, payload, source="current", name=None):
        if source == "current":
            source = self.fixture.plan["source_pair"]["chain"]
        if source is None:
            source = dict(sha=None, tree=None)
        descriptor = dict(id=name or "security-" + str(len(self.inputs["artifacts"]) + 1),
                          source_commit=source["sha"], source_tree=source["tree"],
                          source_url="https://github.com/TrillionniumFoundation/Trillionnium-Chain",
                          evidence=self.fixture.artifact(payload))
        self.inputs["artifacts"].append(descriptor)
        return descriptor

    def review(self):
        plan = original.canonical(self.fixture.plan)
        self.fixture.packet["plan_sha256"] = original.sha(plan)
        return security.review(plan, original.sha(plan), original.canonical(self.fixture.packet),
                               self.fixture.root, original.canonical(self.inputs))

    def test_eight_priorities_and_original_vetoes_remain_open(self):
        result = self.review()
        self.assertEqual(len(result["system_blockers"]), 8)
        self.assertEqual(sum(x["priority"] == "P0" for x in result["system_blockers"].values()), 6)
        self.assertEqual(sum(x["priority"] == "P1" for x in result["system_blockers"].values()), 2)
        self.assertEqual(result["qualification"], "HOLD_NO_GO")
        self.assertEqual(result["authority"], "DENY_ALL")
        self.assertFalse(result["all_blockers_closed"])
        self.assertEqual(set(result["original_review"]["gates"]), set(original.GATES))
        self.assertTrue(all(not row["qualified"] and row["material_status"] == "BLOCKED"
                            for row in result["system_blockers"].values()))
        for flag in ("same_source_acceptance", "production_activation", "production_final_use_qualified",
                     "settlement_verified", "native_outcome_verified", "original_evidence_authenticated"):
            self.assertIs(result[flag], False)

    def test_original_plan_pin_refusal_is_reused(self):
        with self.assertRaisesRegex(original.Refusal, "PLAN_PIN_MISMATCH"):
            security.review(original.canonical(self.fixture.plan), shared_controls.pin("wrong-plan"),
                            original.canonical(self.fixture.packet), self.fixture.root)

    def test_sixteen_null_points_are_preserved_as_unknown(self):
        self.add(cost_fixture())
        result = self.review()
        item = result["artifacts"][0]
        self.assertEqual(item["input_diagnostics"], [])
        self.assertEqual(item["facts"]["unknown_cost_point_count"], 16)
        self.assertEqual(len(item["facts"]["observed_cost_rows"]), 16)
        self.assertIsNone(item["facts"]["initial_potential_bound_declaration"])
        self.assertFalse(item["facts"]["cost_bound_verified"])

    def test_missing_duplicate_and_boolean_cost_points_are_diagnosed(self):
        for mode, expected in (("missing", "COST_GRID_MISSING_POINTS"),
                               ("duplicate", "COST_GRID_DUPLICATE_POINTS"),
                               ("boolean", "COST_POINT_IDENTITY:0")):
            with self.subTest(mode=mode):
                self.inputs["artifacts"] = []
                value = cost_fixture()
                if mode == "missing":
                    value["cost_envelopes"]["classical"].pop()
                elif mode == "duplicate":
                    value["cost_envelopes"]["classical"][-1] = copy.deepcopy(value["cost_envelopes"]["classical"][0])
                else:
                    value["cost_envelopes"]["classical"][0]["units"] = True
                self.add(value)
                result = self.review()
                self.assertIn(expected, result["artifacts"][0]["input_diagnostics"])
                self.assertTrue(result["input_refused"])

    def test_supplied_cost_bound_cannot_become_a_certificate(self):
        value = cost_fixture()
        value["cost_envelopes"]["quantum"][0].update(lower=1, upper=2, status="proved")
        self.add(value)
        item = self.review()["artifacts"][0]
        self.assertIn("UNSUPPORTED_V1_COST_CERTIFICATE:quantum:1", item["input_diagnostics"])
        self.assertFalse(item["facts"]["cost_bound_verified"])

    def test_one_half_diagnostic_cannot_fill_one_sixteenth_contract(self):
        value = cost_fixture()
        value["relation"]["ideal_probability"]["denominator"] = 2
        self.add(value)
        self.assertIn("FIXED_PROBABILITY_CONTEXT_MISMATCH", self.review()["artifacts"][0]["input_diagnostics"])

    def test_binding_pass_and_true_cost_flags_remain_declarations(self):
        value = dict(schema="pon-fixed-probability-cost-audit-result-v1", binding_validation="PASS",
                     qualification="PASS", source_binding_scope="four_relation_source_files_only",
                     ideal_probability=dict(numerator=1, denominator=16),
                     unknown_cost_points=[dict(zip(("class", "units"), point)) for point in sorted(security.EXPECTED_COST_POINTS)],
                     unclosed_obligations=["synthetic-unclosed"], full_execution_identity_verified=True,
                     finite_model_certificate_is_actual_w1_lower_bound=True, production_activation=True)
        self.add(value)
        item = self.review()["artifacts"][0]
        self.assertEqual(item["facts"]["binding_validation_declaration"], "PASS")
        self.assertEqual(item["facts"]["indicators"]["finite_model_certificate_is_actual_w1_lower_bound"]["declaration_status"],
                         "DECLARED_UNVERIFIED")
        self.assertFalse(item["qualified"])

    def test_daa_true_flags_supply_no_theorem_or_authority(self):
        value = daa_fixture()
        for name in value["limitations"]:
            if type(value["limitations"][name]) is bool:
                value["limitations"][name] = True
        self.add(value)
        item = self.review()["artifacts"][0]
        self.assertEqual(item["facts"]["indicators"]["network_profitability_or_consensus_safety_theorem"]["declaration_status"],
                         "DECLARED_UNVERIFIED")
        self.assertFalse(item["facts"]["security_theorem_verified"])

    def test_daa_extract_stays_explicitly_partial_and_unverified(self):
        value = dict(schema="trnm-joint-consensus-limitations-extract-v1",
                     source_schema="trnm-joint-consensus-boundaries-v1",
                     original_sha256=shared_controls.pin("original-daa"), extraction="limitations-only",
                     limitations=daa_fixture()["limitations"])
        self.add(value)
        item = self.review()["artifacts"][0]
        self.assertEqual(item["input_diagnostics"], [])
        self.assertIn("EXTRACTED_FIELDS_NOT_FULL_ORIGINAL", item["blockers"])
        self.assertFalse(item["facts"]["original_report_authenticated"])
        self.assertFalse(item["facts"]["extraction_completeness_verified"])

    def test_daa_extract_cannot_change_scope_or_impersonate_original(self):
        value = dict(schema="trnm-joint-consensus-limitations-extract-v1", source_schema="different",
                     original_sha256="not-a-digest", extraction="complete-native-proof", limitations=daa_fixture()["limitations"])
        self.add(value)
        errors = self.review()["artifacts"][0]["input_diagnostics"]
        self.assertIn("DAA_EXTRACT_SOURCE_SCHEMA", errors)
        self.assertIn("DAA_EXTRACT_ORIGINAL_DIGEST", errors)
        self.assertIn("DAA_EXTRACT_SCOPE", errors)

    def test_campaign_keeps_planned_observed_confirmed_and_unknown_separate(self):
        self.add(campaign_fixture(self.fixture.plan["source_pair"]["chain"]))
        item = self.review()["artifacts"][0]
        self.assertEqual(item["input_diagnostics"], [])
        facts = item["facts"]
        self.assertEqual((facts["complete_campaigns"], facts["actual_campaigns"], facts["planned_campaigns"]), (0, 3, 3))
        self.assertEqual(facts["totals"], dict(scheduled_confirmation_rounds=27, observed_confirmation_rounds=12,
                                              confirmed_rounds=3, unobserved_scheduled_rounds=15))
        self.assertIsNone(facts["unobserved_cost"])
        self.assertFalse(facts["acceptance_verified"])
        self.assertEqual(facts["controller_resources_declaration"]["cpu_max"], "400000 100000")
        self.assertEqual(facts["public_phase_placement_declaration"]["receiver_and_verifier_cpu_max"], "25000 100000")

    def test_campaign_total_and_phase_denominator_conflicts_are_retained(self):
        value = campaign_fixture(self.fixture.plan["source_pair"]["chain"])
        value["totals"]["confirmed_rounds"] = 13
        value["phases"][0]["unobserved_scheduled_rounds"] = 0
        self.add(value)
        errors = self.review()["artifacts"][0]["input_diagnostics"]
        self.assertIn("CAMPAIGN_TOTAL_DENOMINATOR_INCONSISTENT", errors)
        self.assertIn("CAMPAIGN_PHASE_DENOMINATOR_INCONSISTENT:0", errors)
        self.assertIn("CAMPAIGN_TOTALS_DO_NOT_MATCH_PHASES", errors)

    def test_arithmetically_consistent_smaller_campaign_does_not_replace_original(self):
        value = campaign_fixture(self.fixture.plan["source_pair"]["chain"])
        for phase in value["phases"]:
            phase.update(scheduled_confirmation_rounds=1, observed_confirmation_rounds=1,
                         confirmed_rounds=1, unobserved_scheduled_rounds=0)
        value["totals"] = dict(scheduled_confirmation_rounds=9, observed_confirmation_rounds=9,
                               confirmed_rounds=9, unobserved_scheduled_rounds=0)
        self.add(value)
        errors = self.review()["artifacts"][0]["input_diagnostics"]
        self.assertIn("ORIGINAL_PHASE_CONFIRMATION_COUNT_CHANGED:0", errors)
        self.assertIn("ORIGINAL_CAMPAIGN_CONFIRMATION_COUNT_CHANGED", errors)

    def test_started_campaign_without_phase_observation_remains_incomplete(self):
        value = campaign_fixture(self.fixture.plan["source_pair"]["chain"])
        value["phases"] = []
        value["totals"] = dict(scheduled_confirmation_rounds=27, observed_confirmation_rounds=0,
                               confirmed_rounds=0, unobserved_scheduled_rounds=27)
        self.add(value)
        item = self.review()["artifacts"][0]
        self.assertEqual(item["input_diagnostics"], [])
        self.assertIn("ATTEMPT_PHASE_COVERAGE_INCOMPLETE", item["blockers"])
        self.assertEqual(len(item["facts"]["missing_original_phases"]), 9)
        self.assertIsNone(item["facts"]["unobserved_cost"])

    def test_duplicate_campaign_phase_and_boolean_counts_are_not_normalized(self):
        value = campaign_fixture(self.fixture.plan["source_pair"]["chain"])
        value["phases"][1] = copy.deepcopy(value["phases"][0])
        value["actual_campaigns"] = True
        self.add(value)
        errors = self.review()["artifacts"][0]["input_diagnostics"]
        self.assertIn("DUPLICATE_CAMPAIGN_PHASE:1", errors)
        self.assertIn("INVALID_INTEGER:actual_campaigns", errors)

    def test_controller_resources_cannot_replace_receiver_contract(self):
        value = campaign_fixture(self.fixture.plan["source_pair"]["chain"])
        value["measured_public_phase_placement"]["receiver_and_verifier_cpu_max"] = value["controller_resources"]["cpu_max"]
        self.add(value)
        self.assertIn("ORIGINAL_PUBLIC_PHASE_RESOURCE_CHANGED:receiver_and_verifier_cpu_max",
                      self.review()["artifacts"][0]["input_diagnostics"])

    def test_local_owner_true_flags_are_still_unverified(self):
        value = resource_fixture()
        for name in value:
            if type(value[name]) is bool:
                value[name] = True
        self.add(value)
        item = self.review()["artifacts"][0]
        self.assertEqual(item["facts"]["indicators"]["honest_service_bound_qualified"]["declaration_status"], "DECLARED_UNVERIFIED")
        self.assertFalse(item["facts"]["physical_cost_bound_verified"])

    def test_missing_and_invalid_boolean_declarations_are_separate(self):
        value = resource_fixture()
        del value["observer_actual_cpu_measured"]
        value["observer_actual_io_measured"] = 1
        self.add(value)
        facts = self.review()["artifacts"][0]["facts"]["indicators"]
        self.assertEqual(facts["observer_actual_cpu_measured"]["declaration_status"], "NOT_REPORTED")
        self.assertEqual(facts["observer_actual_io_measured"]["declaration_status"], "INVALID_DECLARATION")

    def test_same_declared_identity_cannot_claim_same_source_acceptance(self):
        self.add(cost_fixture())
        item = self.review()["artifacts"][0]
        self.assertEqual(item["source"]["classification"], "SAME_DECLARED_SOURCE_UNAUTHENTICATED")
        self.assertFalse(item["source"]["source_verified"])
        self.assertFalse(item["same_source_acceptance"])

    def test_same_tree_different_commit_is_historical(self):
        source = copy.deepcopy(self.fixture.plan["source_pair"]["chain"])
        source["sha"] = shared_controls.pin("old-execution", 40)
        self.add(cost_fixture(), source=source)
        item = self.review()["artifacts"][0]
        self.assertEqual(item["source"]["classification"], "HISTORICAL_SOURCE")
        self.assertIn("HISTORICAL_EVIDENCE_NOT_CURRENT_ACCEPTANCE", item["blockers"])

    def test_embedded_historical_source_cannot_be_overwritten_by_current_descriptor(self):
        source = copy.deepcopy(self.fixture.plan["source_pair"]["chain"])
        source["sha"] = shared_controls.pin("native-original", 40)
        self.add(campaign_fixture(source))
        item = self.review()["artifacts"][0]
        self.assertEqual(item["source"]["classification"], "HISTORICAL_SOURCE")
        self.assertEqual(item["source"]["embedded"]["sha"], source["sha"])
        self.assertIn("DECLARED_EMBEDDED_SOURCE_MISMATCH", item["input_diagnostics"])

    def test_absent_source_is_not_inferred_from_url_or_current_plan(self):
        self.add(resource_fixture(), source=None)
        item = self.review()["artifacts"][0]
        self.assertEqual(item["source"]["classification"], "SOURCE_UNOBSERVED_OR_INCOMPLETE")
        self.assertFalse(item["same_source_acceptance"])

    def test_unknown_schema_with_pass_claim_does_not_supply_evidence(self):
        self.add(dict(schema="unrecognized-proof", result="PASS", production_activation=True))
        item = self.review()["artifacts"][0]
        self.assertEqual(item["projection_status"], "UNSUPPORTED")
        self.assertFalse(item["qualified"])

    def test_invalid_schema_type_is_not_treated_as_supported_or_empty_evidence(self):
        self.add(dict(schema=True, result="PASS"))
        item = self.review()["artifacts"][0]
        self.assertIn("INVALID_SECURITY_ARTIFACT_SCHEMA", item["input_diagnostics"])
        self.assertEqual(item["projection_status"], "INPUT_REFUSED")

    def test_changed_raw_artifact_is_refused_by_existing_hash_reader(self):
        descriptor = self.add(cost_fixture())
        (self.fixture.root / descriptor["evidence"]["path"]).write_bytes(b"{}\n")
        result = self.review()
        self.assertTrue(result["input_refused"])
        self.assertIn("EVIDENCE_HASH_MISMATCH", result["artifacts"][0]["input_diagnostics"])

    def test_duplicate_artifact_identity_is_not_another_observation(self):
        descriptor = self.add(cost_fixture())
        self.inputs["artifacts"].append(copy.deepcopy(descriptor))
        with self.assertRaisesRegex(original.Refusal, "DUPLICATE_SECURITY_ARTIFACT_ID"):
            self.review()

    def test_stage_and_effect_gaps_are_retained_without_modifying_original_inputs(self):
        effect = self.fixture.effect_unknown()
        # A later authoritative QUERY in the shared fixture would reconcile the
        # Unknown correctly. Omit that step to test an unresolved effect here.
        effect["steps"] = effect["steps"][:1]
        before = copy.deepcopy((self.fixture.plan, self.inputs))
        result = self.review()
        self.assertTrue(result["stage_review"]["stages"]["evaluation"]["blockers"])
        self.assertTrue(any("STAGE:evaluation:" in issue for issue in
                            result["system_blockers"]["P0_MODEL_EVALUATION_POISONING"]["blockers"]))
        self.assertTrue(any("EFFECT:" in issue for issue in
                            result["system_blockers"]["P0_AUTHORIZATION_EXTERNAL_EFFECTS"]["blockers"]))
        self.assertEqual((self.fixture.plan, self.inputs), before)

    def test_cli_returns_hold_and_refuses_malformed_input(self):
        plan = original.canonical(self.fixture.plan)
        self.fixture.packet["plan_sha256"] = original.sha(plan)
        paths = {name: self.fixture.root / (name + ".json") for name in ("plan", "packet", "inputs")}
        paths["plan"].write_bytes(plan)
        paths["packet"].write_bytes(original.canonical(self.fixture.packet))
        paths["inputs"].write_bytes(original.canonical(self.inputs))
        args = ["--plan", str(paths["plan"]), "--plan-sha256", original.sha(plan),
                "--packet", str(paths["packet"]), "--evidence-root", str(self.fixture.root),
                "--security-inputs", str(paths["inputs"])]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = security.main(args)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["authority"], "DENY_ALL")
        paths["inputs"].write_text('{"schema":"x","schema":"y"}')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = security.main(args)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["input_refused"], "DUPLICATE_JSON_FIELD")


if __name__ == "__main__":
    unittest.main()
