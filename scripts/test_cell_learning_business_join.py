"""Original learning bytes plus explicitly synthetic funding-mapping controls.

Replaying an archived research run is not a new model, payment or recovery run.
The synthetic funded mappings exercise this parser only and confer no authority.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import cell_adoption_readback as native
import cell_learning_completion_join as completion
import cell_learning_iteration_join as iteration
import cell_learning_business_join as business
import test_cell_learning_business_economics as fixtures

ROOT = Path(__file__).resolve().parents[1]
RECORDED = ROOT / "evidence/hepta-real-native-adoption-20261108/chain-reader"
SOURCE_PAIR = dict(
    chain=dict(commit="9129e65b3255439593e44a0ba39578f220c27087",
               tree="3362f33fc1eb16bb1aa168f237065e4d15252bcc"),
    hepta=dict(commit="edf03ecb8a814a0f5e86b1d6a752aeac80b1a978",
               tree="c7588a07d20310059d4016559fa550d397b7eb09"))


def original_case(phase="adopt-v1"):
    directory = RECORDED / phase
    names = dict(selection="selection.bin", completed="completed.bin", readback="readback.json",
                 freeze="freeze.json", expected="expected.json")
    materials = {name: (directory / path).read_bytes() for name, path in names.items()}
    snapshot, _ = iteration.decode_native_learning_checkpoint(materials["completed"])
    original = json.loads((directory / "stdout.json").read_bytes())
    request = snapshot["request"]
    final = original["final_observation"]
    use = original["selection_use_review"]["native_readback_review"]
    bindings = dict(
        schema=business.BINDINGS_SCHEMA, operation_id=request["operation_id"],
        invocation_id="archived-" + phase, capture_basis="retrospective-research-readback",
        source_pair=copy.deepcopy(SOURCE_PAIR), root_envelope_schema=None,
        materials={name: dict(sha256=native.sha(raw), operation_id=request["operation_id"],
                              source_pair=copy.deepcopy(SOURCE_PAIR)) for name, raw in materials.items()},
        learning=dict(initial_head=original["frozen_initial_head"],
                      evaluation_profile=request["evaluation_profile"],
                      baseline_bundle=iteration.bundle_digest(request["selected_bundle"]),
                      selected_bundle=final["retained_bundle" if original["no_update"] else "candidate_bundle"],
                      source_run_id=request["source_run_id"], next_run_id=final["state_partition"]["run_id"],
                      next_task_digest=use["task_digest"], next_input_digest=use["input_digest"],
                      cost_source_digest=use["cost_source_digest"]),
        consumer={name: final["state_partition"][name] for name in ("principal_id", "agent_id", "cell_id")},
        economics=[])
    return materials, bindings


def run_review(materials, bindings, *native_tasks):
    raw = fixtures.encode(bindings)
    return business.review_business_iteration(materials, bindings_raw=raw,
        expected_bindings_sha256=native.sha(raw), native_task_raws=native_tasks)


def synthetic_funded_mapping(materials, bindings):
    prior = run_review(materials, bindings)
    report, expected = fixtures.synthetic_fixture(prior["decision"])
    service = expected["service"]
    service["terms"]["request"] = prior["funded_request_digest"]
    service["output"] = prior["funded_result_digest"]
    service["contract_digest"], service["task"] = fixtures.identities(
        service["terms"], expected["context"], service["payer"], service["reservation_nonce"])
    record = report["original_full_contract"]
    record["contract_digest"] = list(bytes.fromhex(service["contract_digest"]))
    record["terms"]["request"] = list(bytes.fromhex(service["terms"]["request"]))
    record["delivered_output"] = list(bytes.fromhex(service["output"]))
    report["task"], report["output"] = service["task"], service["output"]
    for key in ("historical_payment", "current_payment"):
        report[key]["source"] = "task:" + service["task"]
        report[key]["subject"] = service["output"]
    return report, expected


def attach(bindings, report, expected):
    raw = fixtures.encode(report)
    bindings["economics"].append(dict(material=dict(sha256=native.sha(raw),
        operation_id=bindings["operation_id"], source_pair=copy.deepcopy(bindings["source_pair"])),
        expected=expected))
    return raw


class BusinessJoinTests(unittest.TestCase):
    def test_archived_adopt_and_no_update_are_replayed_without_promoting_qualification(self):
        for phase, decision, count in (("adopt-v1", "Selection", 7), ("no-update-v9", "NoUpdate", 6)):
            with self.subTest(phase=phase):
                result = run_review(*original_case(phase))
                self.assertEqual((result["decision"], result["receipt_count"]), (decision, count))
                self.assertEqual(result["checkpoint_codec"], "HEPLCP02")
                self.assertEqual(result["authority"], "DENY_ALL")
                self.assertEqual(result["qualification"], "HOLD_NO_GO")
                self.assertEqual(result["declared_costs"]["training_steps"], 10)
                self.assertEqual(result["completion_review"], json.loads((RECORDED / phase / "stdout.json").read_bytes()))
                for name in ("source_execution_authenticated", "pre_dispatch_freeze_authenticated",
                             "complete_version_custody_verified", "physical_installation_accepted",
                             "independent_consumer_verified", "funded_mapping_authenticated",
                             "full_learning_iteration_completed", "real_model_training_verified",
                             "settlement_verified", "hepta_final_use_accepted", "production_activation"):
                    self.assertIs(result[name], False, name)

    def test_no_update_retains_complete_incumbent_and_unknown_financial_amounts(self):
        materials, bindings = original_case("no-update-v9")
        result = run_review(materials, bindings)
        snapshot, _ = iteration.decode_native_learning_checkpoint(materials["completed"])
        self.assertEqual(result["complete_version_descriptor"], snapshot["request"]["selected_bundle"])
        self.assertFalse(result["economic_categories"]["service_fee"]["no_update_forces_zero"])
        self.assertIsNone(result["economic_categories"]["service_fee"]["actual_external_amount"])
        self.assertFalse(result["economic_categories"]["improvement_reward"]["no_update_eligible"])
        self.assertIsNone(result["economic_categories"]["consensus_credit"]["actual_qualified_credit"])

    def test_source_declaration_does_not_authenticate_historical_execution(self):
        materials, bindings = original_case()
        bindings["capture_basis"] = "original-owner-export"
        bindings["source_pair"]["hepta"]["commit"] = "ab" * 20
        for pin in bindings["materials"].values():
            pin["source_pair"] = copy.deepcopy(bindings["source_pair"])
        result = run_review(materials, bindings)
        self.assertFalse(result["source_execution_authenticated"])
        self.assertFalse(result["real_model_training_verified"])

    def test_distinct_source_pair_in_one_material_is_refused(self):
        materials, bindings = original_case()
        bindings["materials"]["completed"]["source_pair"]["hepta"]["commit"] = "ab" * 20
        with self.assertRaisesRegex(ValueError, "BUSINESS_SOURCE_PAIR"):
            run_review(materials, bindings)

    def test_operation_identity_must_match_every_material_and_original_checkpoint(self):
        materials, original = original_case()
        bindings = copy.deepcopy(original)
        bindings["materials"]["readback"]["operation_id"] = "different-operation"
        with self.assertRaisesRegex(ValueError, "BUSINESS_OPERATION"):
            run_review(materials, bindings)
        bindings = copy.deepcopy(original)
        bindings["operation_id"] = "different-operation"
        for value in bindings["materials"].values():
            value["operation_id"] = bindings["operation_id"]
        with self.assertRaisesRegex(ValueError, "BUSINESS_OPERATION"):
            run_review(materials, bindings)

    def test_independent_manifest_pin_and_each_original_file_pin_are_required(self):
        materials, bindings = original_case()
        raw = fixtures.encode(bindings)
        with self.assertRaisesRegex(ValueError, "BUSINESS_BINDINGS_PIN"):
            business.review_business_iteration(materials, bindings_raw=raw,
                expected_bindings_sha256="ab" * 32)
        for name in business.MATERIAL_NAMES:
            changed = dict(materials)
            changed[name] += b"\n"
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "BUSINESS_MATERIAL_PIN"):
                run_review(changed, bindings)

    def test_outer_root_schema_cannot_relabel_a_legacy_inner_checkpoint(self):
        materials, bindings = original_case()
        bindings["root_envelope_schema"] = 2
        materials["completed"] = b"HEPLCP01" + materials["completed"][8:]
        bindings["materials"]["completed"]["sha256"] = native.sha(materials["completed"])
        with self.assertRaisesRegex(ValueError, "LEARNING_CHECKPOINT_VERSION"):
            run_review(materials, bindings)

    def test_consumer_next_task_bundle_and_cost_pins_cannot_be_relabelled(self):
        materials, original = original_case()
        for field in original["learning"]:
            bindings = copy.deepcopy(original)
            bindings["learning"][field] = "different" if field.endswith("run_id") else "ab" * 32
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "BUSINESS_LEARNING_BINDINGS"):
                run_review(materials, bindings)
        bindings = copy.deepcopy(original)
        bindings["consumer"]["principal_id"] = "ab" * 32
        with self.assertRaisesRegex(ValueError, "BUSINESS_CONSUMER_BINDING"):
            run_review(materials, bindings)

    def test_no_update_synthetic_contract_service_fee_is_not_improvement_or_consensus_credit(self):
        materials, bindings = original_case("no-update-v9")
        report, expected = synthetic_funded_mapping(materials, bindings)
        raw = attach(bindings, report, expected)
        result = run_review(materials, bindings, raw)
        self.assertTrue(result["funded_mapping_observed"])
        self.assertFalse(result["funded_mapping_authenticated"])
        self.assertEqual(result["economic_observations"][0]["service_fee"]["current"]["beneficiary_credit"], 7)
        self.assertFalse(result["settlement_verified"])

    def test_unrelated_valid_native_payment_does_not_match_learning_request_result(self):
        materials, bindings = original_case()
        report, expected = fixtures.synthetic_fixture("Selection")
        raw = attach(bindings, report, expected)
        with self.assertRaisesRegex(ValueError, "BUSINESS_FUNDED_REQUEST_RESULT"):
            run_review(materials, bindings, raw)

    def test_mislabelled_financial_decision_is_refused(self):
        materials, bindings = original_case("no-update-v9")
        report, expected = synthetic_funded_mapping(materials, bindings)
        expected["decision"] = "Selection"
        raw = attach(bindings, report, expected)
        with self.assertRaisesRegex(ValueError, "BUSINESS_DECISION_BINDING"):
            run_review(materials, bindings, raw)

    def test_missing_latest_owner_read_preserves_prior_observation_and_unknown_status(self):
        materials, bindings = original_case()
        report, expected = synthetic_funded_mapping(materials, bindings)
        raw = attach(bindings, report, expected)
        bindings["economics"].append(None)
        result = run_review(materials, bindings, raw)
        self.assertEqual(result["recovery"]["status"], "LATEST_OBSERVATION_MISSING")
        self.assertEqual(result["recovery"]["current_payment_status"], "UNKNOWN")
        self.assertEqual(result["economic_observations"][0]["service_fee"]["current"]["beneficiary_credit"], 7)
        self.assertIsNone(result["economic_observations"][1]["service_fee"]["current"])
        self.assertFalse(result["recovery"]["repayment_authorized"])
        self.assertFalse(result["recovery"]["redispatch_authorized"])

    def test_repeated_exact_observation_never_sums_payments_or_grants_replay(self):
        materials, bindings = original_case()
        report, expected = synthetic_funded_mapping(materials, bindings)
        raws = [attach(bindings, report, copy.deepcopy(expected)) for _ in range(2)]
        result = run_review(materials, bindings, *raws)
        self.assertEqual(result["recovery"]["status"], "DECLARED_HEADS_CONSISTENT_ONLY")
        self.assertFalse(result["recovery"]["recovery_authenticated"])
        self.assertIsNone(result["economic_categories"]["service_fee"]["actual_external_amount"])

    def test_recovery_cannot_rewrite_retained_cost_or_payment_facts(self):
        for field in ("declared_costs", "historical_payment", "historical_delivery_anchor"):
            materials, bindings = original_case()
            first, expected = synthetic_funded_mapping(materials, bindings)
            second = copy.deepcopy(first)
            if field == "declared_costs":
                second[field]["training_units"] += 1
            elif field == "historical_payment":
                second[field]["anchor"]["generation"] -= 1
            else:
                second[field]["block"] = [90] * 32
            raws = [attach(bindings, report, copy.deepcopy(expected)) for report in (first, second)]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "BUSINESS_RECOVERY_RETAINED_FACTS"):
                run_review(materials, bindings, *raws)

    def test_paid_missing_recovered_three_cut_sequence_preserves_gap_and_never_replays(self):
        materials, bindings = original_case()
        report, expected = synthetic_funded_mapping(materials, bindings)
        first = attach(bindings, report, copy.deepcopy(expected))
        bindings["economics"].append(None)
        last = attach(bindings, report, copy.deepcopy(expected))
        result = run_review(materials, bindings, first, last)
        self.assertEqual(result["recovery"]["observation_count"], 3)
        self.assertEqual(result["recovery"]["missing_observations"], 1)
        self.assertTrue(result["recovery"]["retained_facts_preserved"])
        self.assertFalse(result["recovery"]["missing_observation_recovery_verified"])
        self.assertFalse(result["recovery"]["redispatch_authorized"])

    def test_observation_limit_and_unmatched_raw_cannot_hide_extra_reads(self):
        materials, bindings = original_case()
        bindings["economics"] = [None] * 17
        with self.assertRaisesRegex(ValueError, "BUSINESS_ECONOMICS_INPUTS"):
            run_review(materials, bindings)
        bindings["economics"] = []
        with self.assertRaisesRegex(ValueError, "BUSINESS_ECONOMICS_INPUTS"):
            run_review(materials, bindings, b"unexpected")

    def test_recovery_rejects_rewind_changed_same_sequence_or_changed_original_operation(self):
        report, expected = fixtures.synthetic_fixture()
        retained = business._retained_facts(fixtures.encode(report))
        first = dict(expected=expected)
        for field, value, error in (
            ("declared_reconciliation_epoch", 0, "BUSINESS_RECOVERY_REWIND"),
            ("retained_reconciliation_root", "ab" * 32, "BUSINESS_RECOVERY_SAME_SEQUENCE"),
        ):
            second = copy.deepcopy(first)
            second["expected"]["observation"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, error):
                business._recovery([first, second], [retained, retained])
        second = copy.deepcopy(first)
        second["expected"]["service"]["operation"] = "ab" * 32
        with self.assertRaisesRegex(ValueError, "BUSINESS_RECOVERY_IDENTITY"):
            business._recovery([first, second], [retained, retained])

    def test_advancing_anchor_in_same_epoch_requires_sequence_and_generation_progress(self):
        report, expected = fixtures.synthetic_fixture()
        retained = business._retained_facts(fixtures.encode(report))
        first = dict(expected=expected)
        second = copy.deepcopy(first)
        new = second["expected"]["observation"]
        new["retained_reconciliation_sequence"] += 1
        new["retained_reconciliation_root"] = "ab" * 32
        new["observed_anchor"]["generation"] += 1
        new["observed_anchor"]["block"] = [90] * 32
        self.assertTrue(business._recovery([first, second], [retained, retained])["reconciliation_heads_monotonic"])
        new["observed_anchor"]["generation"] -= 1
        with self.assertRaisesRegex(ValueError, "BUSINESS_RECOVERY_SAME_GENERATION_ANCHOR"):
            business._recovery([first, second], [retained, retained])

    def test_m12_checkpoint_rewind_or_same_sequence_root_change_is_refused(self):
        report, expected = fixtures.synthetic_fixture()
        retained = business._retained_facts(fixtures.encode(report))
        first = dict(expected=expected)
        for field, value, error in (("sequence", 5, "BUSINESS_RECOVERY_CHECKPOINT"),
                                    ("max_records", 9, "BUSINESS_RECOVERY_CHECKPOINT"),
                                    ("root", [90] * 32, "BUSINESS_RECOVERY_SAME_CHECKPOINT")):
            second = copy.deepcopy(first)
            second["expected"]["observation"]["retained_reconciliation_sequence"] += 1
            second["expected"]["observation"]["m12_checkpoint"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, error):
                business._recovery([first, second], [retained, retained])

    def test_closed_manifest_rejects_unverified_authority_flags_duplicates_and_integer_aliases(self):
        materials, original = original_case()
        bindings = copy.deepcopy(original)
        bindings["hepta_final_use_accepted"] = True
        with self.assertRaisesRegex(ValueError, "BUSINESS_BINDINGS_FIELDS"):
            run_review(materials, bindings)
        raw = fixtures.encode(original)
        duplicate = b'{"schema":"duplicate",' + raw[1:]
        with self.assertRaisesRegex(ValueError, "NATIVE_DUPLICATE_FIELD"):
            business.review_business_iteration(materials, bindings_raw=duplicate,
                expected_bindings_sha256=native.sha(duplicate))
        for invalid in (True, 2.0, 0, 3):
            bindings = copy.deepcopy(original)
            bindings["root_envelope_schema"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                run_review(materials, bindings)

    def test_cli_replays_original_bytes_and_has_no_output_write_path(self):
        materials, bindings = original_case()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bindings.json"
            path.write_bytes(fixtures.encode(bindings))
            command = [sys.executable, "-B", str(ROOT / "scripts/cell_learning_business_join.py"),
                       "--bindings", str(path), "--bindings-sha256", native.sha(path.read_bytes())]
            names = dict(selection="selection.bin", completed="completed.bin", readback="readback.json",
                         freeze="freeze.json", expected="expected.json")
            for name, filename in names.items():
                command.extend(("--" + name, str(RECORDED / "adopt-v1" / filename)))
            result = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(result.stdout), run_review(materials, bindings))
            self.assertEqual(list(Path(tmp).iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
