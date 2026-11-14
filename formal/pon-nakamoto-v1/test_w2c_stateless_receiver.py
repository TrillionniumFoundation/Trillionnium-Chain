"""Stateless W2-C early admission negative tests. No Node/Chainwork privilege."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import unittest
from contract_wire import H
from w2c_receiver_admission import solve, ticket, qualifies
from w2c_stateless_receiver import StatelessReceiverAdmission as Receiver


class StatelessAdmissionControls(unittest.TestCase):
    def setUp(self):
        self.proposal = H('w2c-pinned-proposal')
        self.alice = bytes([0x41]) * 32
        self.bob = bytes([0x42]) * 32
        self.receiver = bytes([0x52]) * 32
        self.secret = bytes([0x53]) * 32
        self.epoch = bytes([0x45]) * 32
        self.count = 0

        def unique(n):
            self.assertEqual(n, 32)
            self.count += 1
            return self.count.to_bytes(8, 'little') + bytes(24)

        self.issuer = Receiver(self.receiver, self.secret, self.epoch,
                               capacity=2, entropy=unique)

    def grant(self, caller=None, now=100):
        result = self.issuer.offer(self.proposal, caller or self.alice, 8, now)
        nonce, cost = solve(result, 65536)
        self.assertIsNotNone(nonce)
        self.assertEqual(cost['status'], 'TARGET_HIT_UNVERIFIED')
        return result, nonce

    def test_unpaid_issued_grants_do_not_fill_any_spent_slots(self):
        issued = {self.issuer.offer(self.proposal, self.alice, 8, 100).token
                  for _ in range(4096)}
        self.assertEqual(len(issued), 4096)
        self.assertEqual(self.issuer.pending_paid(), 0)
        # No one has received W1/Node authority, regardless of challenge count.
        self.assertFalse(hasattr(self.issuer, 'verified_work'))

    def test_paid_capacity_and_no_free_w1_when_full(self):
        a, na = self.grant()
        b, nb = self.grant()
        c, nc = self.grant()
        self.assertEqual(self.issuer.consume(a, self.proposal, self.alice, na, 150),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(self.issuer.consume(b, self.proposal, self.alice, nb, 150),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(self.issuer.consume(c, self.proposal, self.alice, nc, 150),
                         'PAID_CAPACITY_BUSY')
        self.assertEqual(self.issuer.pending_paid(), 2)
        # After expiration a fresh grant is permitted, no old ticket is honored.
        self.issuer.clock(2100)
        d, nd = self.grant(now=2100)
        self.assertEqual(self.issuer.consume(d, self.proposal, self.alice, nd, 2120),
                         'READY_RESOURCE_ONLY')

    def test_same_paid_ticket_thirty_two_concurrent_consumers_exactly_one(self):
        grant, nonce = self.grant()
        with ThreadPoolExecutor(max_workers=8) as workers:
            rows = list(workers.map(
                lambda _: self.issuer.consume(
                    grant, self.proposal, self.alice, nonce, 120),
                range(32)))
        self.assertEqual(rows.count('READY_RESOURCE_ONLY'), 1)
        self.assertEqual(rows.count('REPLAY'), 31)
        self.assertEqual(self.issuer.pending_paid(), 1)

    def test_caller_identity_and_proposal_are_both_bound(self):
        grant, nonce = self.grant()
        self.assertEqual(self.issuer.consume(
            grant, self.proposal, self.bob, nonce, 120), 'CONTEXT')
        self.assertEqual(self.issuer.consume(
            grant, H('different-proposal'), self.alice, nonce, 120), 'CONTEXT')
        self.assertEqual(self.issuer.consume(
            grant, self.proposal, self.alice, nonce, 120), 'READY_RESOURCE_ONLY')

    def test_distinct_receivers_cannot_replay_same_paid_nonce(self):
        grant, nonce = self.grant()
        other = Receiver(bytes([0x54])*32, self.secret, self.epoch)
        self.assertEqual(other.consume(grant, self.proposal, self.alice,
                                       nonce, 120), 'CONTEXT')
        self.assertEqual(self.issuer.consume(grant, self.proposal, self.alice,
                                             nonce, 120), 'READY_RESOURCE_ONLY')

    def test_new_epoch_makes_old_grant_unusable(self):
        grant, nonce = self.grant()
        restarted = Receiver(self.receiver, self.secret, bytes([0x46])*32)
        self.assertEqual(restarted.consume(grant, self.proposal, self.alice,
                                           nonce, 120), 'CONTEXT')

    def test_copying_same_secret_and_epoch_cannot_be_called_safe_restart(self):
        # Explicit counterexample: a *cloned* secret/epoch starts with no
        # spent table and could grant fresh expensive work. Real deployment
        # needs a unique server epoch or a durable shared spent owner.
        grant, nonce = self.grant()
        self.assertEqual(self.issuer.consume(grant, self.proposal, self.alice,
                                             nonce, 120), 'READY_RESOURCE_ONLY')
        clone = Receiver(self.receiver, self.secret, self.epoch)
        self.assertEqual(clone.consume(grant, self.proposal, self.alice,
                                       nonce, 120), 'READY_RESOURCE_ONLY')

    def test_tamper_bad_nonce_and_strict_types(self):
        grant, nonce = self.grant()
        bad = next(n for n in range(100) if not qualifies(ticket(grant, n), 8))
        self.assertEqual(self.issuer.consume(grant, self.proposal, self.alice,
                                             bad, 120), 'TARGET')
        self.assertEqual(self.issuer.consume(
            replace(grant, bits=9), self.proposal, self.alice, nonce, 120),
            'GRANT_MAC')
        self.assertEqual(self.issuer.consume(
            replace(grant, mac=bytes(32)), self.proposal, self.alice, nonce, 120),
            'GRANT_MAC')
        self.assertEqual(self.issuer.consume(grant, self.proposal, self.alice,
                                             -1, 120), 'GRANT_ENCODING')
        self.assertEqual(self.issuer.consume(grant, self.proposal, self.alice,
                                             nonce, 120), 'READY_RESOURCE_ONLY')
        with self.assertRaisesRegex(ValueError, 'CALLER'):
            self.issuer.offer(self.proposal, bytes(1), 8, 130)

    def test_expiration_and_clock_regression_fail_closed(self):
        grant, nonce = self.grant()
        self.assertEqual(self.issuer.consume(grant, self.proposal, self.alice,
                                             nonce, 2100), 'EXPIRED_OR_FUTURE')
        self.assertEqual(self.issuer.pending_paid(), 0)
        with self.assertRaisesRegex(ValueError, 'CLOCK_REGRESSION'):
            self.issuer.offer(self.proposal, self.alice, 8, 2000)

    def test_paid_research_ticket_still_rejects_false_w1_transcript(self):
        import work_oracle as W
        zeros = [0] * W.CELLS
        header = H('stateless-w2c-header') * 9 + bytes(30)
        self.assertEqual(len(header), 318)
        challenge = H('challenge', header)
        false = b'PNW1' + W.field_bytes(zeros)*3 + H('fake-transcript', challenge)
        proposal = H('w2c-proposal', b'w2c-research-security-v0', header, false)
        grant = self.issuer.offer(proposal, self.alice, 8, 100)
        nonce, _ = solve(grant, 65536)
        self.assertIsNotNone(nonce)
        self.assertEqual(self.issuer.consume(grant, proposal, self.alice, nonce, 120),
                         'READY_RESOURCE_ONLY')
        with self.assertRaisesRegex(ValueError, '^TRANSCRIPT$'):
            W.verify(challenge, W.task_id(zeros, zeros), bytes([255])*32, false)
        self.assertEqual(self.issuer.pending_paid(), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
