"""Structural controls only: no model, provider, payment, deployment or PQ proof.

Historical subsets below are SANITIZED summaries with upstream provenance. They
are not original native receipt bytes and are never labelled production evidence.
#787 acked can report terminal_episode_observed=true while every FinalUse/settlement
qualification is false. #5045 preserves two 60-second timeouts and the failed
15-pass/1-fail/4-ignored integration scope even when its collector exits zero.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import chain_hepta_qualification as gate


CHAIN_787 = "e02126dabef04f13792dec45d96ac5d6916d0651"
READBACK_URL = ("https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/" +
                CHAIN_787 + "/evidence/cell-adoption-20261108/native-readbacks/adopted_acked.review.json")
HEPTA_5045_URL = "https://github.com/TrillionniumFoundation/hepta-private-ci/pull/5045"
ACKED_SUBSET = {
    "sanitized_historical_subset": True, "source_url": READBACK_URL,
    "first_use_bindings_consistent": True, "terminal_episode_observed": True,
    "model_stop_observed": True, "pending_delivery": False, "pending_work": False,
    "full_learning_iteration_completed": False, "real_model_training_verified": False,
    "physical_installation_accepted": False, "settlement_verified": False,
    "hepta_final_use_accepted": False, "production_activation": False,
    "qualification": "HOLD_NO_GO",
}
HEPTA_5045_SUBSET = {
    "sanitized_historical_subset": True, "source_url": HEPTA_5045_URL,
    "hepta_source": "7758798f628ebe86e0cbf3c177559edab96cf5ab",
    "hepta_tree": "e60a39fa288da7056cdc0e8b2cd60fe21d96be44",
    "chain_source": "a4b2de3c35e4e688db3e93c73a46eb957632c0b5",
    "chain_tree": "cc244ceaf38b0095a48e8a12fc574de68de7883b",
    "daemon_native_exit": 100, "daemon_attempt_seconds": [60.005, 60.004],
    "six_target_native_exit": 100, "six_target_passed": 15,
    "six_target_failed": 1, "six_target_ignored": 4, "collector_exit": 0,
    "six_target_retained_text_blob": "c2e9e88b94c57f287851a85ec631527015116366",
}


def pin(name, size=64):
    return hashlib.sha256(("synthetic-structural-fixture:" + name).encode()).hexdigest()[:size]


def fixture_plan():
    """Invented IDs for isolated parser tests, never a candidate source identity."""
    pair = {repo: dict(sha=pin(repo + "-sha", 40), tree=pin(repo + "-tree", 40),
                       locks={path: pin(repo + path) for path in sorted(gate.LOCKS[repo])})
            for repo in ("chain", "hepta")}
    identities = {repo: {field: pin(repo + field) for field in fields}
                  for repo, fields in gate.IDENTITY_FIELDS.items()}
    for item in identities.values():
        item["load_sha256"] = item["build_sha256"]
    return dict(schema=gate.PLAN_SCHEMA, campaign_id="synthetic-campaign",
                profile_sha256=pin("profile"), source_pair=pair, build_load=identities,
                identity_observation_sha256=None,
                cases={o: [o + ":main"] for o in sorted(gate.OBLIGATIONS)},
                effect_intents=[dict(intent_sha256=pin("effect"), operation_id="original-operation",
                                     provider_id="synthetic-provider", idempotency_key="stable-key")])


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.plan = fixture_plan()
        self.packet = dict(schema=gate.PACKET_SCHEMA, plan_sha256=None,
                           identity_observation=None, records=[], learning=None, effects=[])
        self.counter = 0
        details = {}
        for repo, source in self.plan["source_pair"].items():
            entries = []
            for path, digest in sorted(source["locks"].items()):
                expected = dict(mode="100644", kind="blob", blob=pin(path, 40), bytes=1)
                entries.append(dict(path=path, expected=expected, matches=True,
                                    observed=dict(mode="100644", blob=expected["blob"], bytes=1, sha256=digest)))
            details[repo] = dict(source_status="VERIFIED", expected_sha=source["sha"],
                                 tracked_worktree_verified=True, raw_tracked_entries_match=True,
                                 index_matches=True, dirty=False, errors=[], untracked_paths_including_ignored=[],
                                 mismatched_entries=[],
                                 tracked_entries=len(entries), tracked_bytes=len(entries), entries=entries,
                                 tracked_manifest_sha256=gate.sha(gate.canonical(entries)), lock_paths=sorted(source["locks"]))
        self.observation = dict(schema="trnm-chain-hepta-identity-observation-v1", status="HOLD_NO_GO",
                                source_pair=copy.deepcopy(self.plan["source_pair"]), source_observations=details,
                                build_load=copy.deepcopy(self.plan["build_load"]), production_qualified=False,
                                actual_model_execution_proved=False, tests_executed_by_identity_check=False)
        self.pin_identity()

    def pin_identity(self):
        reference = self.artifact(self.observation)
        self.packet["identity_observation"] = reference
        self.plan["identity_observation_sha256"] = reference["sha256"]

    def artifact(self, payload):
        self.counter += 1
        raw = gate.canonical(payload) + b"\n"
        name = "artifact-%d.json" % self.counter
        (self.root / name).write_bytes(raw)
        return dict(path=name, sha256=gate.sha(raw))

    def record(self, obligation, case_id=None, **changes):
        case_id = case_id or self.plan["cases"][obligation][0]
        value = dict(id="record-%d" % (len(self.packet["records"]) + 1), obligation=obligation,
                     case_id=case_id, attempt=1, source_pair=copy.deepcopy(self.plan["source_pair"]),
                     campaign_id=self.plan["campaign_id"], profile_sha256=self.plan["profile_sha256"],
                     build_load_sha256=gate.build_load_digest(self.plan), iteration_id=None, stage=None,
                     manifest_sha256=None, bundle_sha256=None, effect_intent_sha256=None,
                     operation_id=None, effect_outcome=None, outcome="PASS", native_exit=0,
                     collector_exit=0, counts=dict.fromkeys(gate.COUNTS, 0), scope="native-owner",
                     evidence=self.artifact({"synthetic_structural_control": True, "case": case_id}),
                     source_url="https://github.com/TrillionniumFoundation/Trillionnium-Chain")
        value.update(changes)
        self.packet["records"].append(value)
        return value

    def complete(self, no_update=False):
        self.plan["cases"]["same_iteration"] = ["stage:" + s for s in gate.STAGES
                                                if not no_update or s not in ("cold_fetch", "installation")]
        for obligation in sorted(gate.OBLIGATIONS - {"same_iteration"}):
            self.record(obligation)
        effect = copy.deepcopy(self.plan["effect_intents"][0])
        selected_manifest = pin("parent-manifest" if no_update else "selected-manifest")
        selected_bundle = pin("parent-bundle" if no_update else "selected-bundle")
        stages = {}
        for stage in gate.STAGES:
            if no_update and stage in ("cold_fetch", "installation"):
                stages[stage] = None
                continue
            row = self.record("same_iteration", "stage:" + stage, iteration_id="iteration-1", stage=stage,
                              manifest_sha256=selected_manifest, bundle_sha256=selected_bundle)
            if stage == "payment":
                row.update(effect_intent_sha256=effect["intent_sha256"], operation_id=effect["operation_id"],
                           effect_outcome="COMMITTED")
            stages[stage] = row["id"]
        self.packet["learning"] = dict(
            iteration_id="iteration-1", decision="NO_UPDATE" if no_update else "UPDATE",
            evaluation_status="COMPLETED", parent_manifest=pin("parent-manifest"),
            selected_manifest=selected_manifest, parent_bundle=pin("parent-bundle"),
            selected_bundle=selected_bundle, reset_receipt_sha256=None if no_update else pin("reset"),
            payment_intent_sha256=effect["intent_sha256"], stages=stages)
        self.plan["cases"]["recovery_effects"].extend(["effect:dispatch", "effect:query"])
        steps = []
        for action, case in (("DISPATCH", "effect:dispatch"), ("QUERY", "effect:query")):
            row = self.record("recovery_effects", case, effect_intent_sha256=effect["intent_sha256"],
                              operation_id=effect["operation_id"], effect_outcome="COMMITTED",
                              scope="provider-readback" if action == "QUERY" else "native-owner")
            steps.append(dict(action=action, outcome="COMMITTED", record_id=row["id"]))
        effect["steps"] = steps
        self.packet["effects"] = [effect]

    def run_review(self):
        raw = gate.canonical(self.plan)
        self.packet["plan_sha256"] = gate.sha(raw)
        return gate.review(raw, gate.sha(raw), gate.canonical(self.packet), self.root)

    def row(self, record_id):
        return next(row for row in self.packet["records"] if row["id"] == record_id)

    def effect_unknown(self):
        effect = self.packet["effects"][0]
        step = effect["steps"][0]
        step["outcome"] = "UNKNOWN"
        self.row(step["record_id"]).update(outcome="TIMEOUT", native_exit=100, effect_outcome="UNKNOWN")
        return effect

    def test_consistent_structural_materials_never_grant_production_or_final_use(self):
        self.complete()
        result = self.run_review()
        self.assertEqual(result["qualification"], "HOLD_NO_GO")
        self.assertEqual(result["authority"], "DENY_ALL")
        for key in ("actual_model_execution", "original_evidence_authenticated", "source_objects_verified",
                    "original_attempt_inventory_verified", "loaded_bytes_verified", "settlement_verified",
                    "independent_control_accepted", "independent_wan_accepted", "full_pq_security_qualified",
                    "production_final_use_qualified", "production_activation"):
            self.assertIs(result[key], False)
        self.assertTrue(result["identity_observation_consistent"])
        self.assertTrue(all(row["declared_result_consistent"] for row in result["records"]))
        self.assertTrue(all("RAW_OUTCOME_UNVERIFIED" in row["issues"] for row in result["records"]))
        self.assertEqual({g["material_status"] for g in result["gates"].values()}, {"BLOCKED"})

    def test_empty_cases_are_missing_not_waived(self):
        self.plan["cases"] = {key: [] for key in gate.OBLIGATIONS}
        result = self.run_review()
        self.assertTrue(all(g["material_status"] == "BLOCKED" for g in result["gates"].values()))
        self.assertIn("UNCONFIGURED_CASE_ROSTER:no_update", result["gates"]["P0_HEPTA"]["blockers"])

    def test_missing_build_load_and_lock_identities_stay_null(self):
        self.plan["build_load"]["hepta"]["load_sha256"] = None
        self.plan["source_pair"]["chain"]["locks"]["trillionnium/Cargo.lock"] = None
        self.record("source_locks")
        result = self.run_review()
        self.assertIsNone(result["build_load"]["hepta"]["load_sha256"])
        self.assertIn("MISSING_LOCK:chain:trillionnium/Cargo.lock", result["gates"]["P0_INTEGRATION"]["blockers"])
        self.assertFalse(result["records"][0]["current_materials_consistent"])

    def test_loaded_executable_must_equal_built_executable(self):
        self.plan["build_load"]["chain"]["load_sha256"] = pin("other-binary")
        self.assertIn("BUILD_LOAD_MISMATCH:chain", self.run_review()["gates"]["P0_INTEGRATION"]["blockers"])

    def test_matching_head_does_not_hide_dirty_or_partial_source_observation(self):
        fields = {"source_status": "MISMATCH", "tracked_worktree_verified": False,
                  "raw_tracked_entries_match": False, "index_matches": False, "dirty": True,
                  "errors": [{"reason": "RAW_CHANGED"}], "untracked_paths_including_ignored": ["hidden.py"]}
        original = copy.deepcopy(self.observation)
        for name, value in fields.items():
            with self.subTest(field=name):
                self.observation = copy.deepcopy(original)
                self.observation["source_observations"]["chain"][name] = value
                self.pin_identity()
                result = self.run_review()
                self.assertFalse(result["identity_observation_consistent"])
                self.assertIn("SOURCE_NOT_CLEAN:chain", result["gates"]["P0_INTEGRATION"]["blockers"])

    def test_source_summary_true_cannot_hide_retained_mismatch_or_lock_omission(self):
        self.observation["source_observations"]["hepta"]["mismatched_entries"] = [{"path": "changed.rs"}]
        self.pin_identity()
        self.assertIn("SOURCE_ENTRY_MISMATCH:hepta", self.run_review()["gates"]["P0_INTEGRATION"]["blockers"])
        self.observation["source_observations"]["hepta"]["mismatched_entries"] = []
        self.observation["source_observations"]["hepta"]["lock_paths"] = ["codex-rs/Cargo.lock"]
        self.pin_identity()
        self.assertIn("SOURCE_LOCK_BINDING:hepta", self.run_review()["gates"]["P0_INTEGRATION"]["blockers"])

    def test_packet_cannot_replace_independently_pinned_identity_observation(self):
        self.packet["identity_observation"] = self.artifact({"source_status": "VERIFIED"})
        self.assertIn("SOURCE_OBSERVATION_PIN_MISMATCH", self.run_review()["gates"]["P0_INTEGRATION"]["blockers"])

    def test_builder_preserves_unobserved_runtime_and_unconfigured_rosters(self):
        for values in self.observation["build_load"].values():
            values.update(dict.fromkeys(values))
        raw = gate.canonical(self.observation)
        plan = gate.plan_from_identity_observation(raw, "actual-capture-builder-test", pin("profile"))
        self.assertTrue(all(value is None for component in plan["build_load"].values() for value in component.values()))
        self.assertTrue(all(not cases for cases in plan["cases"].values()))
        self.assertEqual(plan["source_pair"], self.observation["source_pair"])
        packet = gate.packet_for_plan(gate.canonical(plan), None)
        self.assertEqual(packet["records"], [])
        self.assertIsNone(packet["learning"])

    def test_each_source_profile_campaign_and_build_binding_is_mandatory(self):
        for field in ("source_pair", "profile_sha256", "campaign_id", "build_load_sha256"):
            with self.subTest(field=field):
                self.packet["records"] = []
                row = self.record("native_registry")
                row[field] = None if field != "campaign_id" else "other-campaign"
                result = self.run_review()
                self.assertIn("CONTEXT_MISMATCH:" + field, result["records"][0]["issues"])

    def test_different_branch_score_cannot_be_counted_as_current(self):
        row = self.record("same_iteration")
        row["source_pair"]["hepta"]["sha"] = "f1785ca15e41e4e49509a5b211a659e3cbdbf60e"
        self.assertIn("CONTEXT_MISMATCH:source_pair", self.run_review()["records"][0]["issues"])

    def test_external_plan_pin_cannot_be_derived_from_changed_packet(self):
        raw = gate.canonical(self.plan)
        self.packet["plan_sha256"] = gate.sha(raw)
        with self.assertRaisesRegex(gate.Refusal, "PLAN_PIN_MISMATCH"):
            gate.review(raw + b" ", gate.sha(raw), gate.canonical(self.packet), self.root)

    def test_packet_cannot_choose_its_own_plan(self):
        raw = gate.canonical(self.plan)
        self.packet["plan_sha256"] = pin("other-plan")
        with self.assertRaisesRegex(gate.Refusal, "PACKET_PLAN_MISMATCH"):
            gate.review(raw, gate.sha(raw), gate.canonical(self.packet), self.root)

    def test_duplicate_json_keys_nonfinite_and_extra_authority_fields_are_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'{"x":-1e999}'):
            with self.subTest(raw=raw), self.assertRaises(gate.Refusal):
                gate.decode(raw)
        self.packet["production_activation"] = True
        with self.assertRaisesRegex(gate.Refusal, "PACKET_FIELDS"):
            self.run_review()

    def test_bool_and_float_cannot_impersonate_integer_counts_or_exit(self):
        for field, value in (("attempt", True), ("attempt", 1.0), ("native_exit", False)):
            with self.subTest(field=field, value=value):
                self.packet["records"] = []
                self.record("native_registry", **{field: value})
                with self.assertRaisesRegex(gate.Refusal, "INVALID_INTEGER"):
                    self.run_review()

    def test_unknown_obligation_cannot_change_denominator(self):
        self.record("native_registry")["obligation"] = "invented-proof"
        with self.assertRaisesRegex(gate.Refusal, "UNKNOWN_OBLIGATION"):
            self.run_review()

    def test_missing_or_duplicated_attempt_is_refused(self):
        for attempts in ((2,), (1, 1), (1, 3)):
            with self.subTest(attempts=attempts):
                self.packet["records"] = []
                for number in attempts:
                    self.record("native_registry", attempt=number)
                with self.assertRaisesRegex(gate.Refusal, "MISSING_OR_DUPLICATE_ATTEMPT"):
                    self.run_review()

    def test_successful_retry_preserves_earlier_native_failure(self):
        self.record("native_registry", outcome="FAIL", native_exit=100, counts=dict(passed=0, failed=1, ignored=0, filtered=0, unknown=0))
        self.record("native_registry", attempt=2)
        result = self.run_review()["gates"]["P0_INTEGRATION"]
        self.assertEqual(result["recorded_outcomes"]["FAIL"], 1)
        self.assertEqual(result["recorded_outcomes"]["PASS"], 1)
        self.assertEqual(result["material_status"], "BLOCKED")

    def test_collector_zero_cannot_override_nonzero_native_exit(self):
        self.record("native_registry", outcome="PASS", native_exit=100, collector_exit=0)
        row = self.run_review()["records"][0]
        self.assertEqual(row["record"]["collector_exit"], 0)
        self.assertIn("NATIVE_EXIT_NOT_ZERO_OR_UNKNOWN", row["issues"])

    def test_raw_native_failure_cannot_hide_behind_normalized_pass(self):
        self.record("native_registry", evidence=self.artifact({"native_exit": 100, "failed": 1}))
        row = self.run_review()["records"][0]
        self.assertEqual(row["raw_result_summary"]["native_exit"], 100)
        self.assertIn("RAW_NATIVE_EXIT_CONFLICT", row["issues"])
        self.assertIn("RAW_COUNT_CONFLICT:failed", row["issues"])
        self.assertFalse(row["declared_result_consistent"])

    def test_original_command_receipt_exit_is_native_not_collector_exit(self):
        self.record("native_registry", evidence=self.artifact({"schema": "trnm-pq-native-command-v1",
                    "exit_code": 100, "status": "command_failed"}))
        row = self.run_review()["records"][0]
        self.assertEqual(row["raw_result_summary"]["native_exit"], 100)
        self.assertIn("RAW_NATIVE_EXIT_CONFLICT", row["issues"])

    def test_unknown_raw_format_cannot_verify_reported_pass(self):
        self.record("native_registry", evidence=self.artifact({"success": True}))
        row = self.run_review()["records"][0]
        self.assertFalse(row["result_payload_verified"])
        self.assertFalse(row["current_materials_consistent"])
        self.assertIn("RAW_OUTCOME_UNVERIFIED", row["issues"])

    def test_failed_ignored_filtered_and_unknown_counts_are_preserved(self):
        counts = dict(passed=5, failed=1, ignored=4, filtered=744, unknown=2)
        self.record("native_registry", counts=counts)
        result = self.run_review()["gates"]["P0_INTEGRATION"]
        self.assertEqual(result["recorded_counts_across_attempts"], counts)
        self.assertEqual(result["material_status"], "BLOCKED")

    def test_engineering_and_sanitized_scopes_never_become_production_evidence(self):
        for scope in ("engineering-control", "sanitized-history"):
            with self.subTest(scope=scope):
                self.packet["records"] = []
                self.record("same_iteration", scope=scope)
                self.assertFalse(self.run_review()["records"][0]["retained_bindings_consistent"])

    def test_787_acked_terminal_success_still_has_no_settlement_or_final_use(self):
        row = self.record("same_iteration", scope="sanitized-history", source_url=READBACK_URL,
                          evidence=self.artifact(ACKED_SUBSET))
        result = self.run_review()
        self.assertFalse(result["production_final_use_qualified"])
        self.assertFalse(result["settlement_verified"])
        self.assertIn("NOT_PRODUCTION_EVIDENCE:sanitized-history", result["records"][0]["issues"])
        spoof = dict(ACKED_SUBSET, production_activation=True, hepta_final_use_accepted=True)
        row["evidence"] = self.artifact(spoof)
        self.assertFalse(self.run_review()["production_activation"])

    def test_5045_timeouts_and_failed_scope_are_not_merged_into_passes(self):
        self.plan["cases"]["native_registry"] = ["daemon32", "six-targets"]
        for index, elapsed in enumerate(HEPTA_5045_SUBSET["daemon_attempt_seconds"], 1):
            self.record("native_registry", "daemon32", attempt=index, outcome="TIMEOUT", native_exit=100,
                        scope="sanitized-history", source_url=HEPTA_5045_URL,
                        evidence=self.artifact(dict(HEPTA_5045_SUBSET, selected_attempt=index, elapsed_seconds=elapsed)))
        counts = dict(passed=15, failed=1, ignored=4, filtered=0, unknown=0)
        self.record("native_registry", "six-targets", outcome="FAIL", native_exit=100,
                    scope="sanitized-history", source_url=HEPTA_5045_URL, counts=counts,
                    evidence=self.artifact(HEPTA_5045_SUBSET))
        result = self.run_review()["gates"]["P0_INTEGRATION"]
        self.assertEqual(result["recorded_outcomes"]["TIMEOUT"], 2)
        self.assertEqual(result["recorded_outcomes"]["FAIL"], 1)
        self.assertEqual(result["recorded_counts_across_attempts"], counts)
        self.assertEqual(result["qualification"], "HOLD_NO_GO")

    def test_legal_no_update_retains_complete_parent_without_fabricated_install_or_reset(self):
        self.complete(no_update=True)
        result = self.run_review()
        self.assertEqual(result["learning_blockers"], [])
        self.assertIsNone(result["learning"]["stages"]["installation"])
        self.assertEqual(result["learning"]["selected_manifest"], result["learning"]["parent_manifest"])
        self.assertFalse(result["production_final_use_qualified"])

    def test_unknown_evaluation_cannot_be_relabeled_no_update(self):
        self.complete(no_update=True)
        self.packet["learning"]["evaluation_status"] = "UNKNOWN"
        self.assertIn("EVALUATION_NOT_COMPLETED", self.run_review()["learning_blockers"])

    def test_no_update_requires_manifest_and_bundle_equality(self):
        self.complete(no_update=True)
        self.packet["learning"]["selected_manifest"] = pin("runtime-changed-but-same-weights")
        self.assertIn("NO_UPDATE_CHANGED_COMPLETE_PARENT", self.run_review()["learning_blockers"])

    def test_no_update_forbids_reset_receipt(self):
        self.complete(no_update=True)
        self.packet["learning"]["reset_receipt_sha256"] = pin("fabricated-reset")
        self.assertIn("NO_UPDATE_FABRICATED_RESET", self.run_review()["learning_blockers"])

    def test_no_update_cannot_hide_missing_evaluator(self):
        self.complete(no_update=True)
        self.packet["learning"]["stages"]["evaluation"] = None
        self.assertIn("MISSING_STAGE:evaluation", self.run_review()["learning_blockers"])

    def test_same_source_but_different_iteration_is_not_same_learning_cycle(self):
        self.complete()
        self.row(self.packet["learning"]["stages"]["training"])["iteration_id"] = "older-iteration"
        self.assertIn("ITERATION_MISMATCH:training", self.run_review()["learning_blockers"])

    def test_loaded_version_must_equal_selected_complete_version(self):
        self.complete()
        self.row(self.packet["learning"]["stages"]["load"])["bundle_sha256"] = pin("different-loaded-bundle")
        self.assertIn("STAGE_VERSION_MISMATCH:load", self.run_review()["learning_blockers"])

    def test_readback_for_one_stage_cannot_stand_in_for_another(self):
        self.complete()
        self.packet["learning"]["stages"]["installation"] = self.packet["learning"]["stages"]["load"]
        result = self.run_review()["learning_blockers"]
        self.assertIn("STAGE_KIND_MISMATCH:installation", result)
        self.assertIn("REUSED_STAGE_RECORD", result)

    def test_payment_must_bind_original_operation(self):
        self.complete()
        self.row(self.packet["learning"]["stages"]["payment"])["operation_id"] = "new-operation"
        self.assertIn("PAYMENT_NOT_BOUND_TO_ORIGINAL_EFFECT", self.run_review()["learning_blockers"])

    def test_unknown_then_authoritative_query_retains_timeout_without_redispatch(self):
        self.complete()
        self.effect_unknown()
        result = self.run_review()
        effect = result["effects"][0]
        self.assertEqual(effect["reported_terminal_state"], "COMMITTED")
        self.assertEqual(effect["issues"], [])
        self.assertFalse(effect["effects_verified"])
        self.assertEqual(result["gates"]["P0_PERMISSION"]["recorded_outcomes"]["TIMEOUT"], 1)

    def test_unknown_forbids_redispatch_even_with_same_idempotency_key(self):
        self.complete()
        effect = self.effect_unknown()
        effect["steps"][1]["action"] = "DISPATCH"
        self.assertIn("REDISPATCH_AFTER_UNKNOWN_COMMIT_OR_REVOCATION", self.run_review()["effects"][0]["issues"])

    def test_unknown_cannot_escape_through_new_operation_id(self):
        self.complete()
        effect = self.effect_unknown()
        second = copy.deepcopy(effect)
        second["operation_id"] = "replacement-operation"
        self.packet["effects"].append(second)
        issues = self.run_review()["effects"][1]["issues"]
        self.assertIn("SAME_INTENT_MULTIPLE_OPERATIONS", issues)
        self.assertIn("EFFECT_IDENTITY_NOT_PLANNED", issues)

    def test_nonprovider_not_applied_cannot_clear_unknown(self):
        self.complete()
        effect = self.effect_unknown()
        query = effect["steps"][1]
        query["outcome"] = "NOT_APPLIED"
        self.row(query["record_id"]).update(effect_outcome="NOT_APPLIED", scope="native-owner")
        result = self.run_review()["effects"][0]
        self.assertEqual(result["reported_terminal_state"], "UNKNOWN")
        self.assertIn("MISSING_PROVIDER_READBACK", result["issues"])

    def test_revocation_or_cancellation_does_not_prove_unknown_effect_absent(self):
        self.complete()
        effect = self.effect_unknown()
        query = effect["steps"][1]
        for value in ("REVOKED", "CANCELLED"):
            with self.subTest(value=value):
                query["outcome"] = value
                self.row(query["record_id"])["effect_outcome"] = value
                self.assertIn("UNRESOLVED_EXTERNAL_EFFECT", self.run_review()["effects"][0]["issues"])

    def test_query_from_other_operation_cannot_resolve_this_effect(self):
        self.complete()
        effect = self.effect_unknown()
        self.row(effect["steps"][1]["record_id"])["operation_id"] = "other-operation"
        self.assertIn("UNRESOLVED_EXTERNAL_EFFECT", self.run_review()["effects"][0]["issues"])

    def test_committed_effect_cannot_be_erased_by_later_not_applied(self):
        self.complete()
        query = self.packet["effects"][0]["steps"][1]
        query["outcome"] = "NOT_APPLIED"
        self.row(query["record_id"])["effect_outcome"] = "NOT_APPLIED"
        result = self.run_review()["effects"][0]
        self.assertEqual(result["reported_terminal_state"], "COMMITTED")
        self.assertIn("COMMITTED_EFFECT_CANNOT_BE_ERASED", result["issues"])

    def test_commit_remains_monotone_through_unknown_not_applied_and_redispatch(self):
        self.complete()
        effect = self.packet["effects"][0]
        query = effect["steps"][1]
        query["outcome"] = "UNKNOWN"
        self.row(query["record_id"])["effect_outcome"] = "UNKNOWN"
        for action, outcome, case in (("QUERY", "NOT_APPLIED", "effect:contradiction"),
                                      ("DISPATCH", "COMMITTED", "effect:forbidden-redispatch")):
            self.plan["cases"]["recovery_effects"].append(case)
            row = self.record("recovery_effects", case, effect_intent_sha256=effect["intent_sha256"],
                              operation_id=effect["operation_id"], effect_outcome=outcome,
                              scope="provider-readback" if action == "QUERY" else "native-owner")
            effect["steps"].append(dict(action=action, outcome=outcome, record_id=row["id"]))
        result = self.run_review()["effects"][0]
        self.assertEqual(result["reported_terminal_state"], "COMMITTED")
        self.assertTrue(result["reported_commit_observed"])
        self.assertIn("COMMITTED_EFFECT_CANNOT_BE_ERASED", result["issues"])
        self.assertIn("REDISPATCH_AFTER_UNKNOWN_COMMIT_OR_REVOCATION", result["issues"])

    def test_omitting_effect_or_required_pq_class_cannot_close_gate(self):
        self.complete()
        self.packet["effects"] = []
        self.plan["cases"]["lifetime_composition"] = []
        result = self.run_review()
        self.assertTrue(result["effect_blockers"])
        self.assertIn("UNCONFIGURED_CASE_ROSTER:lifetime_composition", result["gates"]["P3_PQ"]["blockers"])

    def test_missing_tampered_and_symlink_evidence_fail_closed(self):
        row = self.record("native_registry")
        artifact = self.root / row["evidence"]["path"]
        artifact.write_bytes(b"changed")
        self.assertIn("EVIDENCE_HASH_MISMATCH", self.run_review()["records"][0]["issues"])
        artifact.unlink()
        self.assertIn("EVIDENCE_UNAVAILABLE", self.run_review()["records"][0]["issues"])
        target = self.root / "untrusted-target.json"
        target.write_bytes(b"changed")
        artifact.symlink_to(target)
        self.assertIn("EVIDENCE_UNAVAILABLE", self.run_review()["records"][0]["issues"])

    def test_parent_symlink_and_traversal_are_refused(self):
        row = self.record("native_registry")
        (self.root / "alias").symlink_to(self.root, target_is_directory=True)
        row["evidence"]["path"] = "alias/" + row["evidence"]["path"]
        self.assertIn("EVIDENCE_UNAVAILABLE", self.run_review()["records"][0]["issues"])
        row["evidence"]["path"] = "../outside.json"
        with self.assertRaisesRegex(gate.Refusal, "EVIDENCE_PATH"):
            self.run_review()

    def test_total_evidence_budget_cannot_be_reset_for_each_reference(self):
        ref = self.artifact({"x": 1})
        with self.assertRaisesRegex(gate.Refusal, "EVIDENCE_TOTAL_BOUND"):
            gate.evidence_hash(self.root, ref, [0])

    def test_review_does_not_mutate_inputs(self):
        self.complete()
        plan = copy.deepcopy(self.plan)
        self.packet["plan_sha256"] = gate.sha(gate.canonical(self.plan))
        packet = copy.deepcopy(self.packet)
        self.run_review()
        self.assertEqual(self.plan, plan)
        self.assertEqual(self.packet, packet)

    def test_stage_projection_exposes_missing_qualification_without_changing_review(self):
        self.complete()
        original = self.run_review()
        before = copy.deepcopy(original)
        result = gate.stage_qualification_gaps(original)
        self.assertEqual(original, before)
        self.assertEqual(result["schema"], "trnm-chain-hepta-stage-qualification-v1")
        self.assertEqual(result["qualification"], "HOLD_NO_GO")
        self.assertEqual(result["authority"], "DENY_ALL")
        self.assertEqual(result["source_pair"], original["source_pair"])
        self.assertEqual(result["plan_sha256"], original["plan_sha256"])
        self.assertEqual(set(result["stages"]), set(gate.STAGES))
        for stage in result["stages"].values():
            self.assertIs(stage["declared_result_consistent"], True)
            self.assertIs(stage["qualified"], False)
            self.assertIn("ORIGINAL_STAGE_QUALIFICATION_UNVERIFIED", stage["blockers"])
            self.assertTrue(all(value["declaration_status"] == "NOT_REPORTED"
                                for value in stage["indicators"].values()))
        self.assertIn("MATCHED_STRONG_CONTROLS_UNVERIFIED",
                      result["stages"]["evaluation"]["blockers"])

    def test_native_zero_and_complete_structure_preserve_explicit_qualification_false(self):
        self.complete()
        # Minimal declared facts from the existing completion-reader vocabulary;
        # these synthetic local parser inputs are not original native receipts.
        declarations = {"real_model_training_verified": False, "settlement_verified": False,
                        "physical_installation_accepted": False, "hepta_final_use_accepted": False}
        for stage in ("training", "payment", "installation", "next_task"):
            self.row(self.packet["learning"]["stages"][stage])["evidence"] = self.artifact(declarations)
        original = self.run_review()
        result = gate.stage_qualification_gaps(original)
        self.assertEqual(original["learning_blockers"], [])
        for stage, field in (("training", "real_model_training_verified"),
                             ("payment", "settlement_verified"),
                             ("installation", "physical_installation_accepted"),
                             ("next_task", "hepta_final_use_accepted")):
            row = result["stages"][stage]
            self.assertIs(row["declared_result_consistent"], True)
            self.assertEqual(row["indicators"][field]["declaration_status"], "NOT_ESTABLISHED")
            self.assertIs(row["indicators"][field]["observed"], False)
            self.assertIs(row["qualified"], False)

    def test_every_affirmative_stage_declaration_stays_unauthenticated(self):
        self.complete()
        for stage in gate.STAGES:
            payload = {**gate.STAGE_COMMON_QUALIFICATION_INDICATORS,
                       **gate.STAGE_QUALIFICATION_INDICATORS[stage], "matched_strong_controls": True}
            self.row(self.packet["learning"]["stages"][stage])["evidence"] = self.artifact(payload)
        result = gate.stage_qualification_gaps(self.run_review())
        for row in result["stages"].values():
            self.assertIs(row["qualified"], False)
            self.assertTrue(all(value["declaration_status"] == "DECLARED_UNVERIFIED"
                                for value in row["indicators"].values()))
        self.assertIn("MATCHED_STRONG_CONTROLS_UNVERIFIED", result["stages"]["evaluation"]["blockers"])
        for field in ("stage_qualification_verified", "original_evidence_authenticated",
                      "production_final_use_qualified", "production_activation"):
            self.assertIs(result[field], False)

    def test_stage_qualification_distinguishes_absence_false_and_nonboolean_declarations(self):
        self.complete()
        row = self.row(self.packet["learning"]["stages"]["evaluation"])
        row["evidence"] = self.artifact({"independent_evaluation": 1,
                                        "independent_control_accepted": "true",
                                        "future_window_accepted": None,
                                        "prior_tasks_and_outcomes_exposed": True,
                                        "nested": {"evaluation_profile_semantics_verified": True}})
        report = gate.stage_qualification_gaps(self.run_review())["stages"]["evaluation"]
        for field in ("independent_evaluation", "independent_control_accepted", "future_window_accepted"):
            self.assertEqual(report["indicators"][field]["declaration_status"], "INVALID_DECLARATION")
            self.assertIsNone(report["indicators"][field]["observed"])
        self.assertEqual(report["indicators"]["prior_tasks_and_outcomes_exposed"]["declaration_status"],
                         "NOT_ESTABLISHED")
        self.assertEqual(report["indicators"]["evaluation_profile_semantics_verified"]["declaration_status"],
                         "NOT_REPORTED")

    def test_stage_projection_keeps_other_source_and_iteration_observations_ineligible(self):
        self.complete()
        row = self.row(self.packet["learning"]["stages"]["training"])
        row["source_pair"]["chain"]["sha"] = pin("other-branch", 40)
        row["iteration_id"] = "other-iteration"
        row["evidence"] = self.artifact({"real_model_training_verified": True})
        report = gate.stage_qualification_gaps(self.run_review())["stages"]["training"]
        self.assertIs(report["stage_context_consistent"], False)
        self.assertIn("STAGE_CONTEXT_NOT_ESTABLISHED", report["blockers"])
        self.assertIn("CONTEXT_MISMATCH:source_pair", report["record_issues"])
        self.assertEqual(report["indicators"]["real_model_training_verified"]["declaration_status"],
                         "DECLARED_UNVERIFIED")
        self.assertIs(report["qualified"], False)
        row["source_pair"] = copy.deepcopy(self.plan["source_pair"])
        row["iteration_id"] = self.packet["learning"]["iteration_id"]
        row["evidence"] = self.artifact({"schema": "trnm-pq-native-command-v1",
                                        "status": "command_succeeded", "exit_code": 0,
                                        "before": {}, "after": {}})
        report = gate.stage_qualification_gaps(self.run_review())["stages"]["training"]
        self.assertIn("RAW_COMMAND_SOURCE_UNVERIFIED", report["record_issues"])
        self.assertIs(report["stage_context_consistent"], False)

    def test_retained_parent_structure_omits_only_cold_fetch_and_installation(self):
        self.complete(no_update=True)
        result = gate.stage_qualification_gaps(self.run_review())
        for stage, row in result["stages"].items():
            optional = stage in ("cold_fetch", "installation")
            self.assertEqual(row["required_for_declared_path"], not optional)
            self.assertIs(row["qualified"], False)
            if optional:
                self.assertEqual(row["applicability"], "NOT_REQUIRED_RETAINED_PARENT_STRUCTURE")
                self.assertEqual(row["blockers"], [])
        self.packet["learning"]["evaluation_status"] = "UNKNOWN"
        blocked = gate.stage_qualification_gaps(self.run_review())
        for stage in ("cold_fetch", "installation"):
            self.assertIs(blocked["stages"][stage]["required_for_declared_path"], True)
            self.assertIn("MISSING_STAGE_RECORD", blocked["stages"][stage]["blockers"])

    def test_absent_learning_and_non_deny_all_report_cannot_grant_stage_qualification(self):
        original = self.run_review()
        report = gate.stage_qualification_gaps(original)
        self.assertIsNone(report["iteration_id"])
        self.assertTrue(all("MISSING_STAGE_RECORD" in row["blockers"]
                            for row in report["stages"].values()))
        original["authority"] = "ALLOW"
        with self.assertRaisesRegex(gate.Refusal, "STAGE_REVIEW_SCOPE"):
            gate.stage_qualification_gaps(original)

    def test_cli_returns_hold_not_success_exit_and_refuses_wrong_pin(self):
        plan_raw = gate.canonical(self.plan)
        self.packet["plan_sha256"] = gate.sha(plan_raw)
        plan_file, packet_file = self.root / "plan.json", self.root / "packet.json"
        plan_file.write_bytes(plan_raw)
        packet_file.write_bytes(gate.canonical(self.packet))
        base = [sys.executable, "-B", str(Path(gate.__file__)), "--plan", str(plan_file),
                "--packet", str(packet_file), "--evidence-root", str(self.root), "--plan-sha256"]
        valid = subprocess.run(base + [gate.sha(plan_raw)], capture_output=True, text=True, check=False)
        self.assertEqual(valid.returncode, 2)
        self.assertEqual(json.loads(valid.stdout)["qualification"], "HOLD_NO_GO")
        invalid = subprocess.run(base + [pin("wrong-pin")], capture_output=True, text=True, check=False)
        self.assertEqual(invalid.returncode, 1)
        self.assertEqual(json.loads(invalid.stdout)["input_refused"], "PLAN_PIN_MISMATCH")


if __name__ == "__main__":
    unittest.main()
