"""W2-C local crash/replay research; tests a real SQLite paid-spend owner only."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from multiprocessing import get_context
from pathlib import Path
import tempfile
import unittest

from contract_wire import H
from w2c_durable_spend import SQLiteSpentOwner
from w2c_receiver_admission import solve
from w2c_stateless_receiver import StatelessReceiverAdmission as Receiver


RECEIVER = b'R' * 32
SECRET = b'S' * 32
EPOCH = b'E' * 32
CALLER = b'A' * 32
PROPOSAL = H('w2c-durable-invariant-proposal')


def independent_consumer(path, grant, nonce):
    # Spawned separate process: its own Python lock and SQLite connection.
    store = SQLiteSpentOwner(path, RECEIVER, EPOCH, 8, 64)
    try:
        issuer = Receiver(RECEIVER, SECRET, EPOCH,
                          required_bits=8, durable_spend=store)
        return issuer.consume(grant, PROPOSAL, CALLER, nonce, 120)
    finally:
        store.close()


class DurablePaidSpendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str((Path(self.temp.name) / 'spent.sqlite').resolve())

    def owner(self, **kwargs):
        owner = SQLiteSpentOwner(self.path, RECEIVER, EPOCH, 8,
                                 kwargs.pop('capacity', 64), **kwargs)
        self.addCleanup(owner.close)
        return owner

    def issuer(self, owner, *, capacity=64):
        return Receiver(RECEIVER, SECRET, EPOCH, required_bits=8,
                        capacity=capacity, durable_spend=owner)

    def grant(self, issuer):
        grant = issuer.offer(PROPOSAL, CALLER, 8, 100)
        nonce, cost = solve(grant, 65536)
        self.assertIsNotNone(nonce)
        self.assertEqual(cost['status'], 'TARGET_HIT_UNVERIFIED')
        return grant, nonce

    def test_two_clones_one_real_shared_ledger_replay_refused(self):
        a, b = self.owner(), self.owner()
        original, clone = self.issuer(a), self.issuer(b)
        grant, nonce = self.grant(original)
        self.assertEqual(original.consume(grant, PROPOSAL, CALLER, nonce, 120),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(clone.consume(grant, PROPOSAL, CALLER, nonce, 120),
                         'REPLAY')
        self.assertEqual(a.pending_paid(), 1)
        self.assertEqual(b.pending_paid(), 1)

    def test_restart_reopens_durable_spend_before_old_grant(self):
        a = self.owner()
        original = self.issuer(a)
        grant, nonce = self.grant(original)
        self.assertEqual(original.consume(grant, PROPOSAL, CALLER, nonce, 120),
                         'READY_RESOURCE_ONLY')
        a.close()
        restarted = self.owner()
        self.assertEqual(self.issuer(restarted).consume(
            grant, PROPOSAL, CALLER, nonce, 125), 'REPLAY')

    def test_distinct_processes_one_sqlite_winner(self):
        a = self.owner()
        grant, nonce = self.grant(self.issuer(a))
        with get_context('spawn').Pool(4) as pool:
            results = pool.starmap(independent_consumer,
                                   [(self.path, grant, nonce)] * 4)
        self.assertEqual(results.count('READY_RESOURCE_ONLY'), 1)
        self.assertEqual(results.count('REPLAY'), 3)
        self.assertEqual(a.pending_paid(), 1)

    def test_durable_time_watermark_refuses_clock_rollback_across_clones(self):
        a, b = self.owner(), self.owner()
        self.assertEqual(a.spend(H('durable-key-1'), 2000, 300),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(b.spend(H('durable-key-2'), 2000, 299),
                         'SPEND_CLOCK_REGRESSION')
        self.assertEqual(a.pending_paid(), 1)

    def test_capacity_expiration_and_atomic_no_refund(self):
        a = self.owner(capacity=1)
        issuer = self.issuer(a, capacity=1)
        first, n1 = self.grant(issuer)
        second, n2 = self.grant(issuer)
        self.assertEqual(issuer.consume(first, PROPOSAL, CALLER, n1, 120),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(issuer.consume(second, PROPOSAL, CALLER, n2, 120),
                         'PAID_CAPACITY_BUSY')
        self.assertEqual(a.pending_paid(), 1)
        next_grant = issuer.offer(PROPOSAL, CALLER, 8, 2100)
        n3, _ = solve(next_grant, 65536)
        self.assertIsNotNone(n3)
        self.assertEqual(issuer.consume(next_grant, PROPOSAL, CALLER, n3, 2120),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(a.pending_paid(), 1)

    def test_wrong_receiver_epoch_bits_and_capacity_cannot_share_file(self):
        original = self.owner()
        for receiver, epoch, bits, capacity in (
                (bytes([4])*32, EPOCH, 8, 64),
                (RECEIVER, bytes([5])*32, 8, 64),
                (RECEIVER, EPOCH, 12, 64),
                (RECEIVER, EPOCH, 8, 65)):
            with self.assertRaisesRegex(ValueError, 'SPEND_OWNER_CONTEXT'):
                SQLiteSpentOwner(self.path, receiver, epoch, bits, capacity)
        bad_context = self.owner()
        with self.assertRaisesRegex(ValueError, 'SPEND_OWNER_CONTEXT'):
            Receiver(RECEIVER, SECRET, EPOCH, required_bits=12,
                     durable_spend=bad_context)

    def test_db_error_cannot_grant_ticket(self):
        a = self.owner()
        issuer = self.issuer(a)
        grant, nonce = self.grant(issuer)
        a.close()
        self.assertEqual(issuer.consume(grant, PROPOSAL, CALLER, nonce, 120),
                         'SPEND_UNAVAILABLE')

    def test_issuer_still_does_not_grant_verified_work(self):
        store = self.owner()
        issuer = self.issuer(store)
        grant, nonce = self.grant(issuer)
        self.assertEqual(issuer.consume(grant, PROPOSAL, CALLER, nonce, 120),
                         'READY_RESOURCE_ONLY')
        self.assertFalse(hasattr(issuer, 'VerifiedWork'))
        self.assertEqual(issuer.consume(grant, PROPOSAL, CALLER, nonce, 120),
                         'REPLAY')


if __name__ == '__main__':
    unittest.main(verbosity=2)
