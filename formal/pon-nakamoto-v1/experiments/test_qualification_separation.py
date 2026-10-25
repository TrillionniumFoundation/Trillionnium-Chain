"""Cross-layer adversarial controls using retained codecs, signatures and ledger."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import qualification_separation as research


class QualificationSeparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = research.work_boundaries()
        cls.signatures = research.signature_boundaries()
        cls.service = research.settled_contract_boundary()
        cls.hepta = research.historical_hepta_boundary()

    def test_committed_vector_and_exact_threshold_are_the_only_accepted_cases(self):
        accepted = {row["name"] for row in self.work["cases"] if row["accepted"]}
        self.assertEqual(accepted, {"committed-accepted-block", "exact-ticket-threshold"})
        errors = {row["name"]: row["error"] for row in self.work["cases"]}
        self.assertEqual(errors["one-below-ticket-threshold"], "TARGET")
        self.assertEqual(errors["product-canonical-wrong-value"], "PRODUCT")
        for name in ("A", "B", "product"):
            self.assertEqual(errors[name + "-noncanonical-field"], "FIELD")

    def test_every_real_header_field_is_bound_and_rejected_without_new_chainwork(self):
        expected = {field["name"] for field in research.wire.SCHEMA["header"]}
        actual = {row["field"] for row in self.work["header_admission_cases"]}
        self.assertEqual(actual, expected)
        self.assertTrue(all(row["admission_error"] for row in self.work["header_admission_cases"]))
        self.assertEqual(self.work["retained_blocks_including_genesis"], 2)

    def test_passing_fake_ticket_and_duplicate_packets_do_not_add_work(self):
        self.assertEqual(self.work["full_forgery_rejection"], "TRANSCRIPT")
        self.assertGreater(self.work["passing_forgery_search_attempts"], 0)
        self.assertEqual(self.work["duplicate_admissions"], 3)
        self.assertEqual(self.work["credited_chainwork"], 2)

    def test_two_valid_signatures_are_one_command_but_require_different_W1(self):
        self.assertEqual(self.signatures["valid_signature_count"], 2)
        self.assertEqual(self.signatures["raw_tx_id_count"], 2)
        self.assertEqual(self.signatures["canonical_unsigned_command_count"], 1)
        self.assertTrue(self.signatures["same_application_state"])
        self.assertTrue(self.signatures["different_transaction_and_receipt_roots"])
        self.assertEqual(self.signatures["old_work_for_new_body_error"], "TRANSCRIPT")
        self.assertEqual(self.signatures["second_command_effect_error"], "NONCE")
        self.assertEqual(self.signatures["same_block_replay_error"], "NONCE")

    def test_key_holder_variants_use_the_existing_strict_verifier(self):
        _, transaction, _, _, _ = research.fixture()
        decoded = research.wire.tx_decode(transaction)
        message = research.wire.H("tx-sign", decoded["unsigned"])
        signatures = {decoded["signature"]}
        for variant in (1, 2, 3):
            signature = research.development_alternate_signature(message, variant)
            research.strict_signature.verify(decoded["sender"], signature, message)
            signatures.add(signature)
            with self.assertRaisesRegex(ValueError, "SIGNATURE"):
                research.strict_signature.verify(decoded["sender"], signature, message[:-1])
        self.assertEqual(len(signatures), 4)
        self.assertEqual(self.signatures["S_plus_L_error"], "SIGNATURE")

    def test_actual_service_settlement_does_not_install_or_evaluate_a_model(self):
        self.assertEqual(self.service["transaction_tags"], [2, 4, 5])
        self.assertEqual(self.service["status"], "settled")
        self.assertEqual(self.service["remaining"], 0)
        self.assertEqual(self.service["model_evaluation_records"], 0)
        self.assertEqual(self.service["model_current"], "00" * 32)
        self.assertEqual(self.service["chainwork_increment_from_required_target"], 2)

    def test_real_historical_success_zero_gain_and_partial_install_are_distinct(self):
        self.assertEqual(self.hepta["successful_controlled_phases"], self.hepta["total_controlled_phases"])
        self.assertEqual(self.hepta["candidate_evaluation"], [1, 2])
        self.assertEqual(self.hepta["strongest_control_evaluation"], [1, 2])
        self.assertEqual(self.hepta["recomputed_gain"], [0, 1])
        self.assertEqual(self.hepta["original_owner_peer_weight_read"]["outcome"], "PASS")
        self.assertFalse(self.hepta["reported_CURRENT_updated"])
        self.assertFalse(self.hepta["reported_installed"])
        self.assertFalse(self.hepta["reported_public_reward_eligible"])

    def test_hidden_execution_or_policy_overrides_fail_before_a_report(self):
        for name in ("TRNM_NATIVE_WORK", "TRNM_NATIVE_EXECUTOR", "TRNM_PON_EVALUATION_POLICY"):
            with self.subTest(name=name), patch.dict(os.environ, {name: "unexpected"}):
                with self.assertRaisesRegex(AssertionError, "research-incompatible override"):
                    research.run()


if __name__ == "__main__":
    unittest.main(verbosity=2)
