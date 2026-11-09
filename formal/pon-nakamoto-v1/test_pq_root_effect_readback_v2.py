"""Readback binding tests with a verifier double; never native crypto evidence.

The separate test_pq_root_effect_readback_native_v2 suite uses real signatures.
Here the double isolates rejection ordering, identity and reconciliation rules.
"""
import copy
import hashlib
import time
import unittest
from unittest.mock import patch

from pq_operation_budget import BudgetExpired, OperationBudget
import pq_root_effect_readback_v2 as r


def request(orphaned_at="7"):
    return r.request_for("11" * 64, "22" * 64, "33" * 64,
                         "provider-fixture", orphaned_at)


def response(req, outcome="applied", reconciliation="liability-retained"):
    return {"receipt": r.receipt_for(req, receipt_id="receipt-fixture", outcome=outcome,
                                     reconciliation=reconciliation), "approvals": []}


def budget():
    return OperationBudget(time.monotonic() + 30)


def verifier_result(_policy, _keys, message, _approvals, **_kwargs):
    return {"signatures_verified": True, "verified_signatures": 4,
            "message_sha512": hashlib.sha512(message).hexdigest()}


class ProviderReadbackStructureTests(unittest.TestCase):
    def verify(self, req, answer, operation_budget=None):
        with patch.object(r.signatures, "verify_quorum", side_effect=verifier_result) as verifier:
            result = r.verify_readback({}, {}, req, answer, operation_budget or budget())
            verifier.assert_called_once()
            return result

    def reject_before_crypto(self, req, answer):
        with patch.object(r.signatures, "verify_quorum") as verifier:
            with self.assertRaises(r.Reject):
                r.verify_readback({}, {}, req, answer, budget())
            verifier.assert_not_called()

    def test_construction_generates_a_new_challenge_and_hashes_complete_request(self):
        first, second = request(), request()
        self.assertNotEqual(first["challenge"], second["challenge"])
        self.assertNotEqual(r.request_sha512(first), r.request_sha512(second))
        for field, value in (("scope", "44" * 64), ("operation_id", "55" * 64),
                             ("intent_sha512", "66" * 64), ("provider", "other-provider"),
                             ("orphaned_at", "8")):
            changed = dict(first, **{field: value})
            self.assertNotEqual(r.request_sha512(first), r.request_sha512(changed))

    def test_every_outcome_has_exact_explicit_reconciliation_semantics(self):
        for outcome, reconciliation in r.RECONCILIATION.items():
            with self.subTest(outcome=outcome):
                req = request()
                result = self.verify(req, response(req, outcome, reconciliation))
                self.assertTrue(result["outcome_known"])
                self.assertTrue(result["reorg_reconciliation_verified"])
                self.assertEqual(result["receipt"]["reconciled_reorg"], "7")

    def test_known_success_without_explicit_reconciliation_cannot_clear_orphan(self):
        for outcome in ("applied", "not-applied", "compensated"):
            req = request()
            result = self.verify(req, response(req, outcome, None))
            self.assertTrue(result["outcome_known"])
            self.assertFalse(result["reorg_reconciliation_verified"])
            self.assertIsNone(result["receipt"]["reconciled_reorg"])

    def test_unknown_is_not_a_terminal_observation_or_a_reconciliation(self):
        req = request()
        result = self.verify(req, response(req, "unknown", None))
        self.assertFalse(result["outcome_known"])
        self.assertFalse(result["reorg_reconciliation_verified"])
        for reconciliation in r.RECONCILIATION.values():
            with self.assertRaises(r.Reject):
                response(req, "unknown", reconciliation)

    def test_readback_without_orphan_epoch_cannot_invent_reconciliation(self):
        req = request(None)
        result = self.verify(req, response(req, "applied", None))
        self.assertTrue(result["outcome_known"])
        self.assertFalse(result["reorg_reconciliation_verified"])
        with self.assertRaisesRegex(r.Reject, "reconciliation-without-epoch"):
            response(req)

    def test_outcome_and_reconciliation_cannot_be_mixed(self):
        for outcome in r.OUTCOMES:
            for reconciliation in r.RECONCILIATION.values():
                if r.RECONCILIATION.get(outcome) == reconciliation:
                    continue
                with self.subTest(outcome=outcome, reconciliation=reconciliation):
                    with self.assertRaises(r.Reject):
                        response(request(), outcome, reconciliation)

    def test_every_expected_receipt_field_and_complete_request_are_bound(self):
        req = request()
        for field, value in (("schema", "legacy"), ("scope", "44" * 64),
                             ("challenge", "55" * 32), ("request_sha512", "66" * 64),
                             ("operation_id", "77" * 64), ("intent_sha512", "88" * 64),
                             ("provider", "different-provider")):
            changed = response(req)
            changed["receipt"][field] = value
            self.reject_before_crypto(req, changed)

    def test_replay_under_fresh_challenge_or_new_orphan_epoch_is_refused(self):
        old = request()
        answer = response(old)
        self.reject_before_crypto(request(), answer)
        self.reject_before_crypto(dict(old, orphaned_at="8"), answer)

    def test_reconciled_epoch_must_match_even_with_updated_request_hash(self):
        req = request()
        answer = response(req)
        answer["receipt"]["reconciled_reorg"] = "6"
        self.reject_before_crypto(req, answer)
        answer = response(req)
        answer["receipt"]["reconciliation"] = None
        self.reject_before_crypto(req, answer)

    def test_closed_request_response_and_receipt_fields(self):
        req = request()
        for candidate in (dict(req, trusted=True), {k: v for k, v in req.items() if k != "provider"}):
            self.reject_before_crypto(candidate, response(req))
        for answer in (dict(response(req), verified=True), {"receipt": response(req)["receipt"]}):
            self.reject_before_crypto(req, answer)
        for field in r.RECEIPT_FIELDS:
            answer = response(req)
            answer["receipt"].pop(field)
            self.reject_before_crypto(req, answer)
        answer = response(req)
        answer["receipt"]["authenticated"] = True
        self.reject_before_crypto(req, answer)

    def test_identifiers_epochs_and_digests_have_strict_types_and_bounds(self):
        for value in (None, True, 7, "", "has space", "line\nbreak", "nonascii-é", "x" * 257):
            with self.subTest(identity=value):
                with self.assertRaises(r.Reject):
                    r.request_for("11" * 64, "22" * 64, "33" * 64, value, "7")
        for value in (True, 7, -1, "-1", "01", "1.0", str(1 << 64), []):
            with self.subTest(epoch=value):
                with self.assertRaises(r.Reject):
                    request(value)
        for value in ("AA" * 64, "11" * 63, "11" * 65, b"11" * 64, None):
            with self.assertRaises(r.Reject):
                r.request_for(value, "22" * 64, "33" * 64, "provider", "7")

    def test_complete_receipt_message_has_distinct_domain_and_bounded_encoding(self):
        req = r.request_for("11" * 64, "22" * 64, "33" * 64, "p" * 256, str((1 << 64) - 1))
        receipt = r.receipt_for(req, receipt_id="r" * 256, outcome="compensated", reconciliation="compensated")
        raw = r.model.canonical(receipt)
        self.assertEqual(r.receipt_message(receipt), r.DOMAIN + len(raw).to_bytes(8, "big") + raw)
        self.assertLessEqual(len(r.receipt_message(receipt)), r.MAX_MESSAGE)
        self.assertNotEqual(r.DOMAIN, r.signatures.APPROVAL_DOMAIN)
        self.assertNotEqual(r.DOMAIN, r.signatures.POSSESSION_DOMAIN)

    def test_original_budget_cancellation_or_expiry_refuses(self):
        req = request()
        operation_budget = budget()
        operation_budget.cancel()
        with patch.object(r.signatures, "verify_quorum") as verifier:
            with self.assertRaises(BudgetExpired):
                r.verify_readback({}, {}, req, response(req), operation_budget)
            verifier.assert_not_called()
        operation_budget = budget()

        def cancelled(*args, **kwargs):
            self.assertIs(kwargs["budget"], operation_budget)
            result = verifier_result(*args, **kwargs)
            operation_budget.cancel()
            return result

        with patch.object(r.signatures, "verify_quorum", side_effect=cancelled):
            with self.assertRaises(BudgetExpired):
                r.verify_readback({}, {}, req, response(req), operation_budget)

    def test_mutated_caller_containers_do_not_change_verified_declaration(self):
        req = request()
        answer = response(req)
        expected = copy.deepcopy(answer["receipt"])

        def mutate(*args, **kwargs):
            result = verifier_result(*args, **kwargs)
            req["provider"] = "mutated"
            answer["receipt"]["outcome"] = "unknown"
            return result

        with patch.object(r.signatures, "verify_quorum", side_effect=mutate):
            result = r.verify_readback({}, {}, req, answer, budget())
        self.assertEqual(result["receipt"], expected)

    def test_no_provider_observation_claims_actual_effect_or_authorizes_retry(self):
        req = request()
        result = self.verify(req, response(req))
        for field in ("authorization_granted", "redispatch_permitted", "activation_performed",
                      "production_qualified", "custody_verified", "actual_external_effects_verified",
                      "whole_chain_pq_qualified", "composition_coverage_proved"):
            self.assertIs(result[field], False)
        self.assertEqual(result["status"], "HOLD")
        self.assertIsNone(result["actual_lifetime_failure_bound"])


if __name__ == "__main__":
    unittest.main()
