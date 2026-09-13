"""Retained liveness counterexamples; arithmetic model, not production evidence."""
from copy import deepcopy
import unittest

from model import MAX_U128, ResourceLedger


def admit(ledger, identity, nonce, funds=1):
    ledger.admit(identity, "owner", 0, nonce, funds, (1, 1, 1),
                 ledger.height + 1, ledger.height + 2, "p")


def refund_and_release(ledger, identity, nonce, funds=1):
    admit(ledger, identity, nonce, funds)
    ledger.resolve(identity, "p", False)
    for _ in range(3):
        ledger.begin_block(ledger.height + 1)


class ResourceLivenessTests(unittest.TestCase):
    def test_recycled_maximum_principal_never_poison_mandatory_service(self):
        ledger = ResourceLedger(funds=MAX_U128, max_tasks=1, service_cap=1)
        refund_and_release(ledger, "a", 1, MAX_U128)
        self.assertEqual(ledger.refunded, MAX_U128)
        self.assertFalse(ledger.refund_counter_saturated)
        refund_and_release(ledger, "b", 2, MAX_U128)
        self.assertTrue(ledger.refund_counter_saturated)
        self.assertEqual(ledger.refunded, MAX_U128)
        self.assertEqual((ledger.available, ledger.escrow, ledger.paid), (MAX_U128, 0, 0))
        self.assertEqual(ledger.height, 6)
        self.assertEqual(ledger.active_task_count(), 0)

    def test_task_cap_is_live_responsibility_not_lifetime_admissions(self):
        ledger = ResourceLedger(max_tasks=1, service_cap=1)
        for nonce in range(1, 9):
            refund_and_release(ledger, str(nonce), nonce)
            self.assertEqual(ledger.active_task_count(), 0)
        self.assertEqual(len(ledger.tasks), 8)  # History preserved, not eight active slots.
        self.assertEqual(ledger.available, 100)
        self.assertEqual(ledger.reserved, [0, 0, 0])

    def test_settlement_does_not_release_task_slot_before_retention(self):
        ledger = ResourceLedger(max_tasks=1)
        admit(ledger, "a", 1)
        ledger.resolve("a", "p", False)
        ledger.begin_block(1)
        before = ledger.snapshot()
        with self.assertRaises(ValueError):
            admit(ledger, "b", 2)
        self.assertEqual(before, ledger.snapshot())
        ledger.begin_block(2)
        self.assertEqual(ledger.active_task_count(), 1)
        with self.assertRaises(ValueError):
            admit(ledger, "b", 2)
        ledger.begin_block(3)
        admit(ledger, "b", 2)
        self.assertEqual(ledger.active_task_count(), 1)

    def test_released_identity_and_nonce_cannot_reauthorize_old_task(self):
        ledger = ResourceLedger(max_tasks=1)
        refund_and_release(ledger, "a", 1)
        for identity, nonce in (("a", 2), ("new", 1)):
            before = ledger.snapshot()
            with self.assertRaises(ValueError):
                admit(ledger, identity, nonce)
            self.assertEqual(before, ledger.snapshot())
        admit(ledger, "new", 2)

    def test_duplicate_old_settlement_cannot_free_new_tasks_slot(self):
        ledger = ResourceLedger(max_tasks=1)
        refund_and_release(ledger, "a", 1)
        admit(ledger, "b", 2)
        before = ledger.snapshot()
        ledger.settle("a")
        self.assertEqual(before, ledger.snapshot())
        self.assertEqual(ledger.active_task_count(), 1)
        with self.assertRaises(ValueError):
            admit(ledger, "c", 3)

    def test_recovery_after_saturated_refund_preserves_exact_retry(self):
        ledger = ResourceLedger(funds=MAX_U128, max_tasks=1)
        refund_and_release(ledger, "a", 1, MAX_U128)
        refund_and_release(ledger, "b", 2, MAX_U128)
        recovered = deepcopy(ledger)
        recovered.settle("b")
        self.assertEqual(recovered.snapshot(), ledger.snapshot())
        refund_and_release(recovered, "c", 3, MAX_U128)
        self.assertEqual(recovered.available, MAX_U128)
        self.assertTrue(recovered.refund_counter_saturated)

    def test_saturated_diagnostic_cannot_starve_next_ready_task(self):
        ledger = ResourceLedger(funds=MAX_U128, max_tasks=2, service_cap=1)
        refund_and_release(ledger, "a", 1, MAX_U128)
        refund_and_release(ledger, "b", 2, MAX_U128)
        admit(ledger, "c", 3)
        admit(ledger, "d", 4)
        ledger.resolve("c", "p", False)
        ledger.resolve("d", "p", False)
        ledger.begin_block(7)
        ledger.begin_block(8)
        self.assertEqual(ledger.tasks["c"].phase, "Settled")
        self.assertEqual(ledger.tasks["d"].phase, "Settled")
        self.assertEqual(ledger.available, MAX_U128)
        self.assertEqual(ledger.escrow, 0)

    def test_expiry_and_retention_progress_without_new_user_traffic(self):
        ledger = ResourceLedger(max_tasks=1, service_cap=1)
        for nonce in range(1, 5):
            admit(ledger, str(nonce), nonce)
            for _ in range(3):
                ledger.begin_block(ledger.height + 1)
            self.assertEqual(ledger.active_task_count(), 0)
            self.assertEqual(ledger.tasks[str(nonce)].outcome, "timeout-not-fraud")
        self.assertEqual(ledger.available, 100)


if __name__ == "__main__":
    unittest.main(verbosity=2)
