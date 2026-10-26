"""Research-only W2-C full grant validation before durable once-only spend."""
from dataclasses import replace
from pathlib import Path
import os
import sqlite3
import tempfile
import unittest
from contract_wire import H
from w2c_durable_spent import DurablePaidSpendOwner, OwnerUnavailable
from w2c_receiver_admission import solve
from w2c_stateless_receiver import StatelessReceiverAdmission

RECEIVER = b'R'*32
SECRET = b'S'*32
EPOCH = b'E'*32
CALLER = b'C'*32
PROPOSAL = H('w2c-shared-spent-original-proposal')


class DurableStatelessIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        os.chmod(self.directory, 0o700)
        self.path = self.directory/'paid.sqlite'

    def tearDown(self):
        self.tmp.cleanup()

    def issuer(self, **kwargs):
        writer = DurablePaidSpendOwner(self.path, RECEIVER, EPOCH, capacity=4)
        return StatelessReceiverAdmission(
            RECEIVER, SECRET, EPOCH, capacity=4, required_bits=8,
            spent_owner=writer, entropy=lambda n:b'T'*n, **kwargs)

    def test_two_cloned_same_epoch_issuers_share_exact_spent_ledger(self):
        original = self.issuer()
        copied = self.issuer()
        grant = original.offer(PROPOSAL, CALLER, 8, 100)
        nonce, obs = solve(grant, 65536)
        self.assertIsNotNone(nonce)
        self.assertEqual(obs['status'], 'TARGET_HIT_UNVERIFIED')
        self.assertEqual(original.consume(grant, PROPOSAL, CALLER, nonce, 120),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(copied.consume(grant, PROPOSAL, CALLER, nonce, 121),
                         'REPLAY')
        self.assertEqual(original.pending_paid(), 1)
        self.assertEqual(copied.pending_paid(), 1)

    def test_policy_16_cannot_be_downgraded_by_caller_or_grant(self):
        issuer = StatelessReceiverAdmission(
            RECEIVER, SECRET, EPOCH, required_bits=16)
        with self.assertRaisesRegex(ValueError, 'BITS_POLICY'):
            issuer.offer(PROPOSAL, CALLER, 8, 100)
        strong = issuer.offer(PROPOSAL, CALLER, 16, 101)
        self.assertEqual(issuer.consume(replace(strong,bits=8),
                                        PROPOSAL,CALLER,0,120), 'BITS_POLICY')

    def test_stored_owner_context_mismatch_is_not_silent_new_budget(self):
        writer = DurablePaidSpendOwner(self.path, RECEIVER, EPOCH, 4)
        with self.assertRaisesRegex(ValueError, 'OWNER_CONTEXT'):
            StatelessReceiverAdmission(RECEIVER,SECRET,b'X'*32,
                                       capacity=4,spent_owner=writer)
        with self.assertRaises(OwnerUnavailable):
            DurablePaidSpendOwner(self.path,RECEIVER,b'X'*32,4)
        with self.assertRaisesRegex(ValueError, 'OWNER_CONTEXT'):
            StatelessReceiverAdmission(RECEIVER, SECRET, EPOCH, capacity=4,
                                       required_bits=16, spent_owner=writer)

    def test_durable_owner_error_does_not_turn_into_w1_validity(self):
        issuer = self.issuer()
        grant = issuer.offer(PROPOSAL,CALLER,8,100)
        nonce,_ = solve(grant,65536)
        self.assertIsNotNone(nonce)
        # Simulate same-UID/admin corruption; this is NOT evidence of
        # adversarial-tamper resistance, merely a fail-closed outcome.
        db = sqlite3.connect(self.path)
        db.execute('DROP TABLE spent')
        db.commit()
        db.close()
        with self.assertRaises(OwnerUnavailable):
            issuer.consume(grant, PROPOSAL, CALLER, nonce, 120)


if __name__=='__main__':
    unittest.main(verbosity=2)
