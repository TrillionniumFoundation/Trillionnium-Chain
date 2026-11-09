"""Synthetic structural controls, never native execution or real payment evidence.

Only the fixed digest vector is copied from the original protocol's Rust unit
test. All paid-report samples below are explicitly constructed local fixtures.
"""
from __future__ import annotations

import copy
import hashlib
import json
import unittest

import cell_adoption_readback as native
import cell_learning_business_economics as economics


def h(value):
    return bytes([value] * 32).hex()


def wire_hash(tag, *parts):
    # Original pon_wire framing, independently assembled for synthetic inputs.
    chunks = [b"TRNM-PON1\0", len(tag).to_bytes(2, "little"), tag]
    for part in parts:
        chunks.extend((len(part).to_bytes(4, "little"), part))
    return hashlib.sha256(b"".join(chunks)).hexdigest()


def identities(terms, context, payer, nonce):
    terms_bytes = b"".join(bytes.fromhex(terms[name]) for name in economics.TERM_DIGESTS)
    terms_bytes += b"".join(terms[name].to_bytes(8, "little") for name in economics.TERM_NUMBERS)
    prefix = [bytes.fromhex(context["network"]), bytes.fromhex(context["parameters"]),
              bytes.fromhex(payer)]
    contract = wire_hash(b"funded-service-contract-v1", *prefix, terms_bytes)
    task = wire_hash(b"funded-service-task-instance-v1", *prefix, nonce.to_bytes(8, "little"),
                     bytes.fromhex(contract))
    return contract, task


def encode(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False).encode()


def synthetic_fixture(decision="NoUpdate", *, outcome="NoGain", changed_generation=False):
    """A schema fixture with no native owner, customer, funds or signatures."""
    context = dict(network=h(20), parameters=h(21), genesis=h(23))
    terms = dict(zip(economics.TERM_DIGESTS, [h(i) for i in range(1, 11)]))
    terms.update(budget=7, delivery_deadline=12, dispute_deadline=20)
    contract, task = identities(terms, context, h(22), 1)
    service = dict(claim=h(30), task=task, binding=h(31), operation=h(32),
                   target_scope_commitment=h(33), target_receipt_commitment=h(34),
                   output=h(35), payer=h(22), reservation_nonce=1,
                   contract_digest=contract, terms=terms, original_delivery_operation=h(36),
                   payment_operation=h(37), cost_unit=h(38), cost_measurement_receipt=h(39))

    def anchor(block, state, height, generation):
        value = {key: list(bytes.fromhex(digest)) for key, digest in context.items()}
        value.update(block=list(bytes.fromhex(h(block))), state_root=list(bytes.fromhex(h(state))),
                     height=height, generation=generation)
        return value

    observed = anchor(43, 44, 9, 9)
    historical_anchor = anchor(41, 42, 8, 8) if changed_generation else copy.deepcopy(observed)
    observation = dict(declared_reconciliation_epoch=1, retained_reconciliation_sequence=1,
                       retained_reconciliation_root=h(45),
                       m12_checkpoint=dict(max_records=8, sequence=6, root=list(bytes.fromhex(h(46)))),
                       observed_anchor=observed)
    expected = dict(schema=economics.EXPECTED_SCHEMA, ledger_profile=economics.LEDGER_PROFILE,
                    monetary_unit=economics.MONETARY_UNIT, decision=decision, context=context,
                    service=service, observation=observation)
    wire_terms = {key: list(bytes.fromhex(value)) if key in economics.TERM_DIGESTS else value
                  for key, value in terms.items()}
    record = dict(schema="funded-service-task-record-v1", network=[20] * 32, parameters=[21] * 32,
                  payer=[22] * 32, reservation_nonce=1, contract_digest=list(bytes.fromhex(contract)),
                  terms=wire_terms, reserved_at=2, receipt_height=5,
                  delivered_output=list(bytes.fromhex(service["output"])),
                  resolution=dict(kind="customer_accepted", actor=[22] * 32, nonce=2,
                                  height=6, evidence=None))
    payment = dict(anchor=copy.deepcopy(observed), source="task:" + task,
                   subject=service["output"], beneficiary=terms["provider"], operation=h(37),
                   gross_escrow_debit=7, beneficiary_credit=7)
    historical_payment = copy.deepcopy(payment)
    historical_payment["anchor"] = historical_anchor
    report = {key: False for key in economics.FALSE_NATIVE_FIELDS}
    report.update(schema=economics.NATIVE_SCHEMA, scope="CURRENT_PAID_NATIVE_TASK_OBSERVATION",
                  **{key: service[key] for key in ("claim", "task", "binding", "operation",
                     "target_scope_commitment", "target_receipt_commitment", "output",
                     "original_delivery_operation")},
                  **copy.deepcopy(observation), original_full_contract=record,
                  native_status="settled", remaining_native_escrow=0,
                  historical_delivery_anchor=anchor(51, 52, 5, 8),
                  current_delivery_anchor=anchor(51, 52, 5, 9),
                  historical_payment=historical_payment, current_payment=payment,
                  current_branch_delivery_membership=True, current_branch_payment_membership=True,
                  chainwork_awarded=0,
                  declared_costs=dict(outcome=outcome, training_units=3, evaluation_units=2,
                                      storage_units=1, serving_units=4, unit=h(38),
                                      measurement_receipt=h(39)))
    return report, expected


class BusinessEconomicsTests(unittest.TestCase):
    def review(self, report, expected):
        raw = encode(report)
        return economics.review_native_economics(raw, expected_sha256=native.sha(raw), expected=expected)

    def test_original_native_contract_digest_and_task_vector(self):
        terms = dict(zip(economics.TERM_DIGESTS, [h(i) for i in range(1, 11)]))
        terms.update(budget=2000, delivery_deadline=12, dispute_deadline=20)
        contract, task = economics._contract_identities(
            terms, dict(network=h(20), parameters=h(21), genesis=h(23)), h(22), 1)
        self.assertEqual(contract, "665bae88cf42e5a697ad91c84678cb439771d9b9eb9bf5524e8d85e46d805277")
        self.assertEqual(task, "4892e76755db0d7e0b4769dc52c8d8f70d641aa2450fb072676cb843f158acec")

    def test_no_update_retains_declared_service_fee_without_reward_authority(self):
        report, expected = synthetic_fixture()
        result = self.review(report, expected)
        self.assertEqual(result["service_fee"]["current"]["beneficiary_credit"], 7)
        self.assertFalse(result["improvement_reward"]["no_update_bonus_permitted"])
        self.assertIsNone(result["improvement_reward"]["observed_external_units"])
        self.assertEqual(result["improvement_reward"]["authorized_units_by_this_reader"], 0)
        self.assertEqual(result["authority"], "DENY_ALL")
        self.assertEqual(result["monetary_unit"], "native-development-ledger-unit")
        self.assertFalse(result["settlement_verified"])
        self.assertFalse(result["real_customer_payment_verified"])

    def test_service_positive_is_not_a_model_gain_claim(self):
        result = self.review(*synthetic_fixture(outcome="Positive"))
        self.assertEqual(result["learning_decision"], "NoUpdate")
        self.assertEqual(result["service_fee"]["current"]["gross_escrow_debit"], 7)
        self.assertFalse(result["independent_evaluation_verified"])

    def test_selection_is_not_reward_or_consensus_credit_evidence(self):
        result = self.review(*synthetic_fixture("Selection"))
        self.assertIsNone(result["improvement_reward"]["observed_external_units"])
        self.assertIsNone(result["consensus_credit"]["observed_external_units"])
        self.assertEqual(result["consensus_credit"]["native_report_declared_chainwork"], 0)
        self.assertEqual(result["consensus_credit"]["awarded_units_by_this_reader"], 0)

    def test_missing_mapping_and_payment_stay_unknown(self):
        result = economics.review_native_economics(None, expected_sha256=None, expected=None)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["service_fee"]["historical"])
        self.assertIsNone(result["service_fee"]["current"])
        self.assertIsNone(result["service_fee"]["actual_external_payment_units"])
        self.assertIsNone(result["consensus_credit"]["native_report_declared_chainwork"])
        self.assertFalse(result["expected_contract_available"])

    def test_expected_contract_without_payment_does_not_invent_amounts(self):
        _, expected = synthetic_fixture()
        result = economics.review_native_economics(None, expected_sha256=None, expected=expected)
        self.assertEqual(result["service_fee"]["observation"], "MISSING")
        self.assertIsNone(result["service_fee"]["current"])

    def test_missing_pinned_file_is_refused(self):
        _, expected = synthetic_fixture()
        with self.assertRaisesRegex(ValueError, "ECONOMICS_MISSING_PINNED_REPORT"):
            economics.review_native_economics(None, expected_sha256=h(1), expected=expected)

    def test_unexpected_or_unpinned_bytes_are_refused(self):
        report, expected = synthetic_fixture()
        raw = encode(report)
        with self.assertRaisesRegex(ValueError, "ECONOMICS_EXPECTATIONS_REQUIRED"):
            economics.review_native_economics(raw, expected_sha256=native.sha(raw), expected=None)
        with self.assertRaisesRegex(ValueError, "ECONOMICS_REPORT_PIN"):
            economics.review_native_economics(raw, expected_sha256=h(1), expected=expected)

    def test_partial_paid_export_is_not_a_payment_observation(self):
        report, expected = synthetic_fixture()
        del report["current_payment"]
        with self.assertRaisesRegex(ValueError, "ECONOMICS_REPORT_FIELDS"):
            self.review(report, expected)

    def test_original_operation_scope_and_target_receipt_are_bound(self):
        for name in ("operation", "target_scope_commitment", "target_receipt_commitment", "binding"):
            report, expected = synthetic_fixture()
            report[name] = h(100)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "ECONOMICS_OPERATION_BINDING"):
                self.review(report, expected)

    def test_every_frozen_native_term_is_checked(self):
        for name in economics.TERM_DIGESTS:
            report, expected = synthetic_fixture()
            report["original_full_contract"]["terms"][name] = [100] * 32
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "ECONOMICS_FROZEN_CONTRACT"):
                self.review(report, expected)

    def test_payer_and_provider_are_not_replaceable(self):
        report, expected = synthetic_fixture()
        report["original_full_contract"]["payer"] = [101] * 32
        with self.assertRaisesRegex(ValueError, "ECONOMICS_FROZEN_CONTRACT"):
            self.review(report, expected)
        report, expected = synthetic_fixture()
        report["current_payment"]["beneficiary"] = h(102)
        with self.assertRaisesRegex(ValueError, "ECONOMICS_PAYMENT_BINDING"):
            self.review(report, expected)

    def test_native_contract_digest_is_recomputed(self):
        report, expected = synthetic_fixture()
        report["original_full_contract"]["contract_digest"] = [103] * 32
        with self.assertRaisesRegex(ValueError, "ECONOMICS_NATIVE_IDENTITIES"):
            self.review(report, expected)

    def test_native_task_identity_is_recomputed_for_expectations(self):
        report, expected = synthetic_fixture()
        expected["service"]["task"] = h(104)
        with self.assertRaisesRegex(ValueError, "ECONOMICS_EXPECTED_NATIVE_IDENTITIES"):
            self.review(report, expected)

    def test_no_paid_result_is_inferred_from_unknown_cost_outcome(self):
        for outcome in ("Unknown", "Invalid", "Cancelled"):
            with self.subTest(outcome=outcome), self.assertRaisesRegex(ValueError, "ECONOMICS_PAID_OUTCOME"):
                self.review(*synthetic_fixture(outcome=outcome))

    def test_historical_and_current_payment_identities_must_match_expectations(self):
        for which in ("historical_payment", "current_payment"):
            for field in ("operation", "subject", "beneficiary"):
                report, expected = synthetic_fixture()
                report[which][field] = h(105)
                with self.subTest(which=which, field=field), self.assertRaisesRegex(
                        ValueError, "ECONOMICS_PAYMENT_BINDING"):
                    self.review(report, expected)

    def test_native_task_debit_and_beneficiary_credit_are_both_bound(self):
        for which in ("historical_payment", "current_payment"):
            for field in ("gross_escrow_debit", "beneficiary_credit"):
                report, expected = synthetic_fixture()
                report[which][field] += 1
                with self.subTest(which=which, field=field), self.assertRaisesRegex(
                        ValueError, "ECONOMICS_PAYMENT_BINDING"):
                    self.review(report, expected)

    def test_generation_change_retains_two_observations_without_double_counting(self):
        result = self.review(*synthetic_fixture(changed_generation=True))
        fee = result["service_fee"]
        self.assertNotEqual(fee["historical"]["anchor"], fee["current"]["anchor"])
        self.assertEqual(fee["historical"]["beneficiary_credit"], 7)
        self.assertEqual(fee["current"]["beneficiary_credit"], 7)
        self.assertNotIn("total_paid", fee)
        self.assertFalse(result["execution_dispatch_authorized"])
        self.assertFalse(result["journal_prefix_verified_by_this_reader"])
        self.assertFalse(result["common_restore_protection_verified"])

    def test_same_generation_cannot_change_payment_anchor(self):
        report, expected = synthetic_fixture()
        report["historical_payment"]["anchor"]["block"] = [106] * 32
        with self.assertRaisesRegex(ValueError, "ECONOMICS_PAYMENT_ANCHOR"):
            self.review(report, expected)

    def test_exact_observation_and_checkpoint_expectations_are_required(self):
        for name in ("declared_reconciliation_epoch", "retained_reconciliation_sequence"):
            report, expected = synthetic_fixture()
            report[name] += 1
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "ECONOMICS_OBSERVATION_BINDING"):
                self.review(report, expected)

    def test_native_journal_and_reconciliation_capacity_bounds(self):
        report, expected = synthetic_fixture()
        report["m12_checkpoint"]["max_records"] = 65536
        expected["observation"]["m12_checkpoint"]["max_records"] = 65536
        report["retained_reconciliation_sequence"] = 128
        expected["observation"]["retained_reconciliation_sequence"] = 128
        self.assertTrue(self.review(report, expected)["native_report_bindings_consistent"])
        for capacity, sequence in ((65537, 128), (65536, 129)):
            changed, pin = copy.deepcopy((report, expected))
            changed["m12_checkpoint"]["max_records"] = capacity
            pin["observation"]["m12_checkpoint"]["max_records"] = capacity
            changed["retained_reconciliation_sequence"] = sequence
            pin["observation"]["retained_reconciliation_sequence"] = sequence
            with self.subTest(capacity=capacity, sequence=sequence), self.assertRaisesRegex(
                    ValueError, "NATIVE_INTEGER"):
                self.review(changed, pin)
        report, expected = synthetic_fixture()
        report["m12_checkpoint"]["sequence"] = 5
        expected["observation"]["m12_checkpoint"]["sequence"] = 5
        with self.assertRaisesRegex(ValueError, "NATIVE_INTEGER"):
            self.review(report, expected)

    def test_current_delivery_at_observed_height_has_one_block_and_root(self):
        report, expected = synthetic_fixture()
        report["original_full_contract"]["receipt_height"] = 9
        report["original_full_contract"]["resolution"]["height"] = 9
        report["current_delivery_anchor"]["height"] = 9
        with self.assertRaisesRegex(ValueError, "ECONOMICS_DELIVERY_ANCHOR"):
            self.review(report, expected)
        report["current_delivery_anchor"] = copy.deepcopy(report["observed_anchor"])
        self.assertTrue(self.review(report, expected)["native_report_bindings_consistent"])

    def test_cost_measurement_and_unit_are_separate_bound_claims(self):
        result = self.review(*synthetic_fixture())
        self.assertEqual(result["declared_cost_total_units"], 10)
        self.assertFalse(result["physical_costs_verified"])
        self.assertFalse(result["cost_completeness_verified"])
        for name in ("unit", "measurement_receipt"):
            report, expected = synthetic_fixture()
            report["declared_costs"][name] = h(107)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "ECONOMICS_COST_BINDING"):
                self.review(report, expected)

    def test_native_authority_flags_cannot_be_promoted(self):
        for name in economics.FALSE_NATIVE_FIELDS:
            report, expected = synthetic_fixture()
            report[name] = True
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "ECONOMICS_NATIVE_SCOPE_ESCALATION"):
                self.review(report, expected)

    def test_funding_profile_and_money_units_are_explicit_development_context(self):
        for field, value in (("ledger_profile", "production"), ("monetary_unit", "USD")):
            report, expected = synthetic_fixture()
            expected[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "ECONOMICS_EXPECTED_SCOPE"):
                self.review(report, expected)

    def test_refund_is_not_provider_service_revenue(self):
        report, expected = synthetic_fixture()
        report["original_full_contract"]["resolution"]["kind"] = "arbitrator_refunded"
        with self.assertRaisesRegex(ValueError, "ECONOMICS_PAID_RESOLUTION_REQUIRED"):
            self.review(report, expected)

    def test_duplicate_keys_extra_fields_and_boolean_numeric_aliases_refuse(self):
        report, expected = synthetic_fixture()
        raw = encode(report)
        duplicate = b'{"schema":"other",' + raw[1:]
        with self.assertRaisesRegex(ValueError, "NATIVE_DUPLICATE_FIELD"):
            economics.review_native_economics(duplicate, expected_sha256=native.sha(duplicate), expected=expected)
        report["authority"] = "ALLOW"
        with self.assertRaisesRegex(ValueError, "ECONOMICS_REPORT_FIELDS"):
            self.review(report, expected)
        report, expected = synthetic_fixture()
        report["chainwork_awarded"] = False
        with self.assertRaisesRegex(ValueError, "NATIVE_INTEGER"):
            self.review(report, expected)

    def test_cost_overflow_and_report_limit_refuse(self):
        report, expected = synthetic_fixture()
        report["declared_costs"]["training_units"] = (1 << 64) - 1
        with self.assertRaisesRegex(ValueError, "NATIVE_INTEGER"):
            self.review(report, expected)
        raw = b" " * (economics.MAX_REPORT + 1)
        with self.assertRaisesRegex(ValueError, "ECONOMICS_REPORT_LIMIT"):
            economics.review_native_economics(raw, expected_sha256=native.sha(raw), expected=expected)

    def test_read_only_input_objects_remain_unchanged(self):
        report, expected = synthetic_fixture()
        before = copy.deepcopy((report, expected))
        result = self.review(report, expected)
        self.assertEqual((report, expected), before)
        self.assertFalse(result["native_origin_authenticated"])
        self.assertFalse(result["native_payment_signatures_verified"])
        self.assertFalse(result["native_transition_replayed_by_this_reader"])


if __name__ == "__main__":
    unittest.main()
