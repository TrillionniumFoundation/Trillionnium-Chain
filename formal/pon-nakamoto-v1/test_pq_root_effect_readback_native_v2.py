"""Actual dual-family provider readback checks; no verifier doubles or skips."""
import copy
import time
import unittest

import pq_openssl_backend as backend
from pq_operation_budget import OperationBudget
import pq_root_effect_readback_v2 as r
from test_pq_root_recovery_signatures_native_v2 import NativeFixture


class ProviderReadbackNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = NativeFixture()
        cls.addClassCleanup(cls.fixture.close)
        cls.request = r.request_for("11" * 64, "22" * 64, "33" * 64, "provider-fixture", "7")
        cls.receipt = r.receipt_for(cls.request, receipt_id="native-fixture",
                                    outcome="applied", reconciliation="liability-retained")
        cls.approvals = cls.fixture.sign_quorum(r.receipt_message(cls.receipt))

    def verify(self, req=None, receipt=None, approvals=None, policy=None, keys=None):
        return r.verify_readback(self.fixture.policy if policy is None else policy,
                                 self.fixture.public_keys if keys is None else keys,
                                 self.request if req is None else req,
                                 {"receipt": self.receipt if receipt is None else receipt,
                                  "approvals": self.approvals if approvals is None else approvals},
                                 OperationBudget(time.monotonic() + 60))

    def test_real_both_family_signatures_authenticate_exact_reconciliation(self):
        result = self.verify()
        self.assertTrue(result["provider_declaration_verified"])
        self.assertTrue(result["reorg_reconciliation_verified"])
        self.assertEqual(result["verified_signatures"], 4)
        self.assertFalse(result["actual_external_effects_verified"])
        self.assertFalse(result["redispatch_permitted"])
        self.assertEqual(result["status"], "HOLD")

    def test_each_family_bitflip_or_absence_refuses(self):
        for index in (0, 2):
            approvals = copy.deepcopy(self.approvals)
            raw = bytes.fromhex(approvals[index]["signature_hex"])
            approvals[index]["signature_hex"] = (raw[:-1] + bytes([raw[-1] ^ 1])).hex()
            with self.assertRaises(backend.BackendError):
                self.verify(approvals=approvals)
        for approvals in (self.approvals[:2], self.approvals[2:]):
            with self.assertRaises(r.Reject):
                self.verify(approvals=approvals)

    def test_original_signatures_cannot_authenticate_rebound_request(self):
        fresh = r.request_for("11" * 64, "22" * 64, "33" * 64, "provider-fixture", "7")
        receipt = r.receipt_for(fresh, receipt_id="native-fixture",
                                outcome="applied", reconciliation="liability-retained")
        with self.assertRaises(backend.BackendError):
            self.verify(req=fresh, receipt=receipt)

    def test_original_signatures_cannot_clear_later_orphan_epoch(self):
        newer = dict(self.request, orphaned_at="8")
        receipt = r.receipt_for(newer, receipt_id="native-fixture",
                                outcome="applied", reconciliation="liability-retained")
        with self.assertRaises(backend.BackendError):
            self.verify(req=newer, receipt=receipt)

    def test_other_pinned_provider_roster_cannot_verify_the_receipt(self):
        with self.assertRaises(r.Reject):
            self.verify(policy=self.fixture.next_policy, keys=self.fixture.next_public_keys)

    def test_root_approval_domain_cannot_be_used_as_provider_receipt(self):
        scenario = self.fixture.scenario()
        root_approvals = self.fixture.approvals(scenario["statement"])
        with self.assertRaises(backend.BackendError):
            self.verify(approvals=root_approvals)


if __name__ == "__main__":
    unittest.main()
