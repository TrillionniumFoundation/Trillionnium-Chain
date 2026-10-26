"""Real local durable spent ownership for W2-C research. NO chainwork/production."""
import multiprocessing as mp
import tempfile
import unittest
from pathlib import Path
from contract_wire import H
from w2c_receiver_admission import solve
from w2c_stateless_receiver import StatelessReceiverAdmission as Receiver
from w2c_sqlite_spend_owner import SqlitePaidSpendOwner


def claimed_in_child(path, receiver, secret, epoch, grant, caller, proposal, nonce, queue):
    context = H('w2c-stored-owner-v1', receiver, epoch, secret)
    owner = SqlitePaidSpendOwner(path, context, capacity=4)
    local = Receiver(receiver, secret, epoch, capacity=4, paid_spends=owner)
    queue.put(local.consume(grant, proposal, caller, nonce, 120))


class DurableResearchIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / 'paid.sqlite')
        self.receiver = bytes([0x41]) * 32
        self.secret = bytes([0x42]) * 32
        self.epoch = bytes([0x43]) * 32
        self.caller = bytes([0x44]) * 32
        self.proposal = H('w2c-durable-proposal')
        self.context = H('w2c-stored-owner-v1', self.receiver, self.epoch, self.secret)
        self.owner = SqlitePaidSpendOwner(self.path, self.context, capacity=4)
        self.service = Receiver(self.receiver, self.secret, self.epoch,
                                capacity=4, paid_spends=self.owner,
                                entropy=lambda n: bytes([0x19]) * n)

    def grant(self):
        grant = self.service.offer(self.proposal, self.caller, 8, 100)
        nonce, cost = solve(grant, 65536)
        self.assertIsNotNone(nonce)
        self.assertEqual(cost['status'], 'TARGET_HIT_UNVERIFIED')
        return grant, nonce

    def test_paid_nonce_exactly_once_across_cloned_instances_and_reopen(self):
        grant, nonce = self.grant()
        self.assertEqual(self.service.consume(grant, self.proposal, self.caller, nonce, 120),
                         'READY_RESOURCE_ONLY')
        reopened = SqlitePaidSpendOwner(self.path, self.context, capacity=4)
        clone = Receiver(self.receiver, self.secret, self.epoch,
                         capacity=4, paid_spends=reopened)
        self.assertEqual(clone.consume(grant, self.proposal, self.caller, nonce, 120),
                         'REPLAY')
        self.assertEqual(clone.pending_paid(), 1)
        self.assertFalse(hasattr(clone, 'VerifiedWork'))

    def test_six_real_processes_with_same_grant_one_paid_claim(self):
        grant, nonce = self.grant()
        ctx = mp.get_context('spawn')
        queue = ctx.Queue()
        processes = [ctx.Process(target=claimed_in_child,
                       args=(self.path, self.receiver, self.secret, self.epoch,
                             grant, self.caller, self.proposal, nonce, queue))
                     for _ in range(6)]
        for process in processes:
            process.start()
        actual = [queue.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(timeout=20)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(actual.count('READY_RESOURCE_ONLY'), 1)
        self.assertEqual(actual.count('REPLAY'), 5)

    def test_mismatched_epoch_capacity_and_owner_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'OWNER_CONTEXT_MISMATCH'):
            Receiver(self.receiver, self.secret, bytes([0x48]) * 32,
                     capacity=4, paid_spends=self.owner)
        with self.assertRaisesRegex(ValueError, 'OWNER_CONTEXT_MISMATCH'):
            Receiver(self.receiver, self.secret, self.epoch,
                     capacity=5, paid_spends=self.owner)
        self.assertEqual(self.service.pending_paid(), 0)

    def test_paid_local_acceptance_still_rejects_false_w1_math(self):
        import work_oracle as W
        zeros = [0] * W.CELLS
        header = H('w2c-durable-header') * 9 + bytes(30)
        challenge = H('challenge', header)
        false = b'PNW1' + W.field_bytes(zeros) * 3 + H('not-a-real-trace', challenge)
        proposal = H('w2c-proposal', b'w2c-research-security-v0', header, false)
        grant = self.service.offer(proposal, self.caller, 8, 100)
        nonce, _ = solve(grant, 65536)
        self.assertIsNotNone(nonce)
        self.assertEqual(self.service.consume(grant, proposal, self.caller, nonce, 120),
                         'READY_RESOURCE_ONLY')
        with self.assertRaisesRegex(ValueError, '^TRANSCRIPT$'):
            W.verify(challenge, W.task_id(zeros, zeros), bytes([255])*32, false)
        self.assertEqual(self.service.pending_paid(), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
