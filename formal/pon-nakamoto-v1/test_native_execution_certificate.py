"""Finite-model evidence checks; none is a native execution or probability test."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import native_execution_certificate as cert


HERE = Path(__file__).resolve().parent


def fixture(name="early_unseen_anchor"):
    return copy.deepcopy(cert.model_fixtures()[name])


def reindex(document):
    for i, event in enumerate(document["events"], 1):
        event["seq"] = i
    document["scope"]["last_seq"] = len(document["events"])
    document["scope"]["end_time"] = max([document["scope"]["start_time"]]
                                        + [event["time"] for event in document["events"]])
    return document


def window_model():
    model = cert.ModelBuilder("delivered_finite_window")
    tip = model.base()
    model.available(7, tip, "h1")
    model.select(7, tip, "h1")
    for name, binding, completion in (("p0", 8, 9), ("p1", 12, 13)):
        block = model.block(name, tip, 3)
        model.bind(binding, block, tip)
        model.ready(completion, block)
        model.available(completion, block)
        model.select(completion, block)
        model.available(completion + 1, block, "h1")
        model.select(completion + 1, block, "h1")
        tip = block
    model.observe(15, "window_end")
    model.compare("window_end")
    return model.document()


def window_check(document, **kwargs):
    params = dict(delta_pub=1, gamma=1, parent_lag=1, observer_lag=1, maximum_weight=3)
    params.update(kwargs)
    return cert.Execution(document).check_window_contract("confirmed", **params)


class PaidDeficitMathematicsTests(unittest.TestCase):
    def test_exact_capped_split_exhaustive_2601_score_triples(self):
        count = 0
        for reference in range(17):
            for maximum in range(17):
                for selected in range(maximum + 1):
                    result = cert.view_deficits(reference, maximum, selected)
                    count += 1
                    self.assertEqual(result["availability_score_deficit"]
                                     + result["selection_score_deficit"], max(0, reference - selected))
                    self.assertEqual(result["raw_selection_score_deficit"], maximum - selected)
                    self.assertLessEqual(result["selection_score_deficit"], maximum - selected)
        self.assertEqual(count, 2601)

    def test_no_maximum_from_selected_tip_or_missing_candidate(self):
        with self.assertRaisesRegex(cert.CertificateError, "SELECTED_EXCEEDS"):
            cert.view_deficits(100, 7, 8)
        result = cert.view_deficits(10, 100, 8)
        self.assertEqual(result["selection_score_deficit"], 2)
        self.assertEqual(result["raw_selection_score_deficit"], 92)

    def test_cross_view_without_b_is_all_availability_loss(self):
        result = cert.Execution(fixture()).report()["comparisons"][0]
        self.assertEqual(result["availability_score_deficit"], 7)
        self.assertEqual(result["new_adversarial_all_branch_weight"], 0)
        self.assertIsNone(result["first_local_removal_seq"])
        self.assertIsNone(result["early_required_new_attack_weight"])

    def test_early_partial_delivery_has_positive_gap_without_full_anchor(self):
        result = cert.Execution(fixture("early_partial_view_positive_gap")).report()["comparisons"][0]
        self.assertEqual(result["early_known_b_reference_score"], 1)
        self.assertEqual(result["reference_score"], 7)
        self.assertEqual(result["availability_score_deficit"], 6)
        self.assertEqual(result["early_required_new_attack_weight"], 1)
        self.assertEqual(result["new_adversarial_all_branch_weight"], 1)
        self.assertTrue(result["early_threshold_is_positive"])
        self.assertIsNone(result["probability_bound"])

    def test_strict_single_target_activation_can_leave_known_100_chain_unselected(self):
        result = cert.Execution(fixture("known_heavier_b_chain_selection_backlog")).report()["comparisons"][0]
        self.assertEqual((result["selected_score"], result["view_maximum_score"]), (8, 100))
        self.assertEqual(result["selection_score_deficit"], 92)
        self.assertEqual(result["availability_score_deficit"], 0)
        self.assertEqual(result["new_adversarial_all_branch_weight"], 8)
        self.assertEqual((result["global_left"], result["global_right"]), (100, 100))
        self.assertIsNotNone(result["first_local_removal_seq"])

    def test_ready_inventory_is_not_new_attack_resource(self):
        result = cert.Execution(fixture("hidden_complete_inventory")).report()["comparisons"][0]
        self.assertEqual(result["relative_initial_inventory_all_branches"], 8)
        self.assertEqual(result["competing_suffix_inventory_all_producers"], 8)
        self.assertEqual(result["new_adversarial_all_branch_weight"], 0)
        self.assertFalse(result["early_threshold_is_positive"])

    def test_old_honest_parent_can_complete_long_after_confirmation(self):
        document = fixture("honest_stale_parent_pipeline")
        result = cert.Execution(document).report()["comparisons"][0]
        self.assertEqual(result["new_honest_all_b_free_weight"], 8)
        self.assertEqual(result["new_adversarial_all_branch_weight"], 0)
        failures = window_check(document, maximum_weight=8)["failures"]
        self.assertIn("STALE_PARENT_COMPLETION_LAG", {f["code"] for f in failures})

    def test_all_honest_burst_with_finite_eight_tick_delivery_bound(self):
        execution = cert.Execution(fixture("all_honest_bounded_delay_burst"))
        result = execution.report()["comparisons"][0]
        self.assertEqual(result["new_adversarial_all_branch_weight"], 0)
        self.assertEqual(result["relative_initial_inventory_all_branches"], 6)
        self.assertEqual(result["new_honest_all_b_free_weight"], 2)
        for block, (_, ready_time) in execution.ready_at.items():
            for node in execution.owners:
                delivery = next(cut.time for cut in execution.cuts if block in cut.views[node])
                self.assertLessEqual(delivery - ready_time, 8)

    def test_same_timestamp_future_completion_not_in_earlier_causal_cut(self):
        before, after = cert.Execution(fixture("same_timestamp_after_crossing_is_not_prior_progress")).report()["comparisons"]
        self.assertEqual(before["comparison_time"], after["comparison_time"])
        self.assertLess(before["comparison_seq"], after["comparison_seq"])
        self.assertEqual((before["reference_score"], after["reference_score"]), (7, 100))
        self.assertEqual((before["selection_score_deficit"], after["selection_score_deficit"]), (0, 92))

    def test_unit_weight_cap_does_not_cap_batch_or_short_time_score_jump(self):
        document = fixture("unit_weight_batch_ready")
        self.assertTrue(all(block["weight"] == 1 for block in document["blocks"]))
        ready = [event for event in document["events"] if event["kind"] == "ready" and event["time"] == 8]
        self.assertEqual(len(ready), 8)
        result = cert.Execution(document).report()["comparisons"][0]
        self.assertEqual(result["new_adversarial_all_branch_weight"], 8)

    def test_six_successors_and_work_are_separate_and_inclusion_makes_seven(self):
        execution = cert.Execution(fixture())
        self.assertFalse(execution.observation("a6", "a1")["confirmed"])
        self.assertTrue(execution.observation("a7", "a1")["confirmed"])
        self.assertEqual(execution.report()["comparisons"][0]["confirmation_cut_from_parent"], 7)
        model = cert.ModelBuilder("six_light_successors")
        parent = model.block("heavy", "g", 10, "A")
        model.ready(0, parent)
        for i in range(6):
            parent = model.block("light" + str(i), parent, 1, "A")
            model.ready(0, parent)
        model.available(0, parent)
        model.select(0, parent)
        model.observe(0, "six", included="heavy", confirmed=False)
        observed = cert.Execution(model.document()).observations["six"]
        self.assertEqual(observed["depth"], 6)
        self.assertEqual(observed["work_delta"], 6)
        self.assertEqual(observed["work_threshold"], 60)
        self.assertFalse(observed["confirmed"])
        self.assertFalse(observed["native_weight_relation_validated"])

    def test_all_eight_models_have_nine_deterministic_pair_witnesses(self):
        models = cert.model_fixtures()
        self.assertEqual(len(models), 8)
        witnesses = 0
        for document in models.values():
            for row in cert.Execution(document).report()["comparisons"]:
                witnesses += 1
                self.assertGreaterEqual(row["exact_cut_left"], row["exact_cut_right"])
                self.assertGreaterEqual(row["global_left"], row["global_right"])
                self.assertIsNone(row["probability_bound"])
        self.assertEqual(witnesses, 9)


class EventRecordTests(unittest.TestCase):
    def assert_refused(self, document, error):
        with self.assertRaisesRegex(cert.CertificateError, error):
            cert.Execution(document).report()

    def test_strict_tie_keeps_incumbent(self):
        model = cert.ModelBuilder("tie")
        model.base()
        rival = model.block("equal", "g", 7, "A")
        model.ready(8, rival)
        model.available(8, rival)
        model.select(8, rival)
        model.observe(8, "tie_observation", included="a1", confirmed=True)
        execution = cert.Execution(model.document())
        self.assertEqual(execution.observations["tie_observation"]["tip"], "a7")
        tampered = model.document()
        tampered["events"][-2]["selected"] = rival
        self.assert_refused(tampered, "NATIVE_STRICT_SELECTION_MISMATCH")

    def test_owner_configuration_and_generation_bindings_fail_closed(self):
        bad = fixture()
        bad["events"][0]["owner_instance"] = "another-owner"
        self.assert_refused(bad, "OWNER_INSTANCE_MISMATCH")
        bad = fixture()
        bad["events"][0]["generation"] = 8
        self.assert_refused(bad, "STALE_BIND_GENERATION")
        bad = fixture()
        bad["owners"][1]["configuration_digest"] = "1" * 64
        self.assert_refused(bad, "INCOMPATIBLE_MODEL_CONFIGURATION")
        bad = fixture()
        bad["owners"].pop()
        self.assert_refused(bad, "OWNER_SCOPE_MISMATCH")

    def test_header_is_not_full_available_candidate(self):
        document = fixture("early_partial_view_positive_gap")
        rival_delivery = next(event for event in document["events"]
                              if event["kind"] == "available" and event["block"] == "rival")
        rival_delivery["kind"] = "header"
        self.assert_refused(document, "SELECT_CANDIDATE_UNAVAILABLE")

    def test_ready_needs_body_proof_application_and_complete_ancestors(self):
        for field in ("body", "proof", "application"):
            document = fixture()
            document["events"][1]["complete_material"][field] = False
            self.assert_refused(document, "READY_INCOMPLETE_MATERIAL")
        document = fixture("unit_weight_batch_ready")
        positions = [i for i, event in enumerate(document["events"])
                     if event["kind"] == "ready" and event["block"] in ("r0", "r1")]
        a, b = positions
        document["events"][a], document["events"][b] = document["events"][b], document["events"][a]
        self.assert_refused(reindex(document), "READY_ANCESTRY_INCOMPLETE")

    def test_ready_credit_never_reissued_for_publication(self):
        document = fixture()
        repeat = copy.deepcopy(document["events"][1])
        repeat["time"] = 7
        document["events"].append(repeat)
        self.assert_refused(reindex(document), "READY_ID_OR_DUPLICATE_CREDIT")

    def test_initial_inventory_must_be_prefix_closed(self):
        document = fixture()
        document["initial"]["ready"].append("a2")
        self.assert_refused(document, "INITIAL_READY_NOT_PREFIX_CLOSED")

    def test_honest_ready_requires_final_parent_binding(self):
        document = fixture()
        document["events"].pop(0)
        self.assert_refused(reindex(document), "HONEST_READY_WITHOUT_PARENT_BINDING")

    def test_eligible_data_loss_is_not_erasure_of_ready_history(self):
        model = cert.ModelBuilder("retained_credit")
        model.base()
        model.available(8, "a7", "h1")
        model.emit(9, "lose_available", **model.owner("h1"), generation=0, block="a1")
        execution = cert.Execution(model.document())
        self.assertIn("a7", execution.cuts[-1].ready)
        self.assertNotIn("a7", execution.cuts[-1].views["h1"])

    def test_clock_order_and_gap_are_not_replaced_by_header_time(self):
        document = fixture()
        document["events"][0].pop("time")
        self.assert_refused(document, "EVENT_CLOCK_MISSING")
        document = fixture()
        document["events"][-1]["time"] = 0
        self.assert_refused(document, "EVENT_CLOCK_ORDER")
        document = fixture()
        document["events"][2]["seq"] = 99
        self.assert_refused(document, "EVENT_TOTAL_ORDER_OR_GAP")
        document = fixture()
        for block in document["blocks"]:
            block["header_timestamp"] = 10**30
        report = cert.Execution(document).report()
        self.assertFalse(report["physical_clock_authenticated"])
        self.assertEqual(report["comparisons"][0]["tau_time"], 7)

    def test_missing_initial_clock_owner_and_coverage_fields_are_refused(self):
        for section, field, error in ((None, "initial", "CERTIFICATE_FIELDS"),
                                      ("clock", "domain", "CLOCK_FIELDS"),
                                      ("scope", "declared_all_branches", "SCOPE_FIELDS"),
                                      ("initial", "residual_state", "INITIAL_FIELDS")):
            document = fixture()
            del (document if section is None else document[section])[field]
            self.assert_refused(document, error)

    def test_partial_window_is_explicit_and_never_qualified(self):
        document = fixture()
        document["scope"]["declared_all_branches"] = False
        document["scope"]["declared_no_missing_events"] = False
        document["initial"]["residual_state"]["status"] = "unknown"
        document["clock"] = {"domain": "unknown", "unit": "unknown", "binding_receipt": None}
        report = cert.Execution(document).report()
        self.assertFalse(report["complete_declared_model_checked"])
        self.assertFalse(report["native_execution_qualified"])
        self.assertIn("UNKNOWN_INITIAL_RESIDUAL_STATE", report["qualification_refusals"])
        self.assertFalse(window_check(document)["model_contracts_hold_on_checked_complete_window"])

    def test_declared_complete_model_cannot_omit_catalogued_outputs(self):
        document = fixture()
        document["blocks"].append({"id": "unaccounted", "parent": "g", "weight": 1,
                                   "producer": "A", "miner": "adversary", "header_timestamp": 0})
        self.assert_refused(document, "DECLARED_MODEL_HAS_UNACCOUNTED_OUTPUTS")

    def test_bools_unknown_fields_duplicate_keys_and_nonfinite_are_rejected(self):
        document = fixture()
        document["blocks"][0]["weight"] = True
        self.assert_refused(document, "POSITIVE_BLOCK_WEIGHT")
        document = fixture()
        document["events"][0]["claimed_signature_valid"] = True
        self.assert_refused(document, "BIND_FIELDS")
        for text in ('{"a":1,"a":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(cert.CertificateError):
                cert.strict_json(text)

    def test_resource_dimensions_remain_separate_and_do_not_certify_cost(self):
        document = fixture()
        for account, amount in (("logical_gates", 11), ("cpu_ns", 23), ("bytes", 19)):
            document["events"].insert(-1, {"time": 7, "kind": "resource", "actor": "adversary",
                                           "account": account, "amount": amount})
        result = cert.Execution(reindex(document)).report()["comparisons"][0]
        self.assertEqual(result["adversarial_resource_accounts_as_declared"],
                         {"logical_gates": 11, "cpu_ns": 23, "bytes": 19})
        self.assertFalse(result["physical_cost_authenticated"])


class EnvironmentAndQualificationTests(unittest.TestCase):
    def test_complete_model_publication_and_retention_check_with_paid_pacer(self):
        result = window_check(window_model())
        self.assertTrue(result["model_contracts_hold_on_checked_complete_window"])
        self.assertEqual(result["pacers"], [{"block": "p1", "seq": 39, "time": 13,
                                           "weight": 3, "paid_progress": 2}])
        self.assertFalse(result["physical_slo_qualified"])
        self.assertIsNone(result["probabilistic_failure_bound"])

    def test_deadline_not_vacuously_successful_without_later_event(self):
        document = fixture()
        document["scope"]["end_time"] = 8
        result = window_check(document, maximum_weight=1)
        self.assertIn("FULL_VIEW_DELIVERY_OR_RETENTION_DEFICIT", {x["code"] for x in result["failures"]})

    def test_censored_deadline_is_explicit_not_a_success(self):
        result = window_check(fixture(), delta_pub=100, maximum_weight=1)
        self.assertIn("DELIVERY_DEADLINE_CENSORED", {x["code"] for x in result["failures"]})
        self.assertFalse(result["model_contracts_hold_on_checked_complete_window"])

    def test_data_delivery_at_boundary_does_not_rewrite_earlier_comparison_cut(self):
        model = cert.ModelBuilder("deadline_order")
        tip = model.base()
        model.observe(8, "before_delivery", node="h1")
        model.available(8, tip, "h1")
        model.compare("before_delivery")
        execution = cert.Execution(model.document())
        result = execution.check_window_contract("confirmed", delta_pub=1, gamma=1,
                                                parent_lag=0, observer_lag=0, maximum_weight=1)
        self.assertTrue(result["model_contracts_hold_on_checked_complete_window"])
        self.assertEqual(execution.report()["comparisons"][0]["availability_score_deficit"], 7)

    def test_retention_loss_and_score_lag_have_explicit_failure_codes(self):
        document = window_model()
        document["events"].append({"time": 16, "kind": "lose_available", "node": "h1",
                                   "owner_instance": "model-owner-h1", "generation": 3, "block": "a1"})
        result = window_check(reindex(document))
        self.assertIn("FULL_VIEW_DELIVERY_OR_RETENTION_DEFICIT", {x["code"] for x in result["failures"]})
        result = window_check(fixture("known_heavier_b_chain_selection_backlog"), maximum_weight=100)
        self.assertIn("OBSERVATION_SELECTION_SCORE_LAG", {x["code"] for x in result["failures"]})

    def test_self_declared_native_clock_owners_and_hashes_never_authenticate_runtime(self):
        document = fixture()
        document["provenance"]["origin"] = "observed_native"
        document["provenance"]["role"] = "unattested_native_record_conversion"
        document["provenance"]["raw_artifact_hashes"] = {"untrusted_log": "a" * 64}
        document["clock"] = {"domain": "physical_monotonic", "unit": "ns", "binding_receipt": "untrusted-sig"}
        report = cert.Execution(document).report()
        for field in ("physical_clock_authenticated", "native_runtime_attested", "all_branch_world_coverage_attested",
                      "initial_residual_state_attested", "probabilistic_environment_bound",
                      "six_successor_risk_qualified", "native_execution_qualified"):
            self.assertIs(report[field], False)
        self.assertTrue(report["record_schema_and_finite_algebra_valid"])

    def test_false_origin_role_pair_is_not_accepted(self):
        document = fixture()
        document["provenance"]["origin"] = "observed_native"
        with self.assertRaisesRegex(cert.CertificateError, "ORIGIN_ROLE_MISMATCH"):
            cert.Execution(document)

    def test_source_bound_evidence_recomputed_and_report_or_source_mutation_refused(self):
        evidence = cert.build_evidence()
        cert.verify_evidence(evidence)
        self.assertEqual(len(evidence["source_bindings"]), len(cert.SOURCE_FILES))
        changed = copy.deepcopy(evidence)
        changed["native_six_successor_risk_bound"] = 1e-6
        with self.assertRaisesRegex(cert.CertificateError, "EVIDENCE_OR_SOURCE_MISMATCH"):
            cert.verify_evidence(changed)
        changed = copy.deepcopy(evidence)
        changed["source_bindings"][cert.SOURCE_FILES[0]] = "0" * 64
        with self.assertRaisesRegex(cert.CertificateError, "EVIDENCE_OR_SOURCE_MISMATCH"):
            cert.verify_evidence(changed)

    def test_cli_native_requirement_and_overwrite_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_text(json.dumps(fixture()), encoding="utf-8")
            run = subprocess.run([sys.executable, str(HERE / "native_execution_certificate.py"),
                                  "--check", str(path), "--require-native-qualification"],
                                 capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 2)
            self.assertIn("NO_AUTHENTICATED_NATIVE_EXECUTION_ADAPTER", run.stdout)
            target = Path(directory) / "evidence.json"
            target.write_text("preserve original", encoding="utf-8")
            run = subprocess.run([sys.executable, str(HERE / "native_execution_certificate.py"),
                                  "--write-evidence", str(target)], capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(target.read_text(encoding="utf-8"), "preserve original")


if __name__ == "__main__":
    unittest.main()
