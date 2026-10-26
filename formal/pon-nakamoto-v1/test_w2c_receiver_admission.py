"""Negative receiver-scoped W2-C work-service controls; no consensus acceptance."""
from dataclasses import replace
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import w2c_receiver_admission as R
from contract_wire import H


class ReceiverScopedCostTests(unittest.TestCase):
    def setUp(self):
        self.proposal = H('fixed-research-proposal')
        self.issuer = R.ReceiverAdmission(bytes([1])*32,bytes([3])*32,
                                          bytes([5])*32, capacity=2,
                                          entropy=lambda n:bytes([7])*n)
        self.other = R.ReceiverAdmission(bytes([2])*32,bytes([3])*32,
                                         bytes([5])*32, capacity=2,
                                         entropy=lambda n:bytes([7])*n)

    def minted(self, issuer=None):
        issuer = issuer or self.issuer
        grant = issuer.offer(self.proposal, 8, 100)
        self.assertIsNotNone(grant)
        nonce,cost = R.solve(grant, 8192)
        self.assertIsNotNone(nonce)
        self.assertEqual(cost['status'],'TARGET_HIT_UNVERIFIED')
        return grant,nonce

    def test_one_ticket_cannot_charge_two_receivers(self):
        grant,nonce = self.minted()
        self.assertEqual(self.other.consume(grant,self.proposal,nonce,120),'CONTEXT')
        self.assertEqual(self.issuer.consume(grant,self.proposal,nonce,120),'READY_RESOURCE_ONLY')
        self.assertEqual(self.issuer.consume(grant,self.proposal,nonce,120),'REPLAY')

    def test_concurrent_same_grant_has_exactly_one_resource_owner(self):
        grant, nonce = self.minted()
        with ThreadPoolExecutor(max_workers=8) as workers:
            replies = list(workers.map(
                lambda _: self.issuer.consume(grant, self.proposal, nonce, 130),
                range(32)))
        self.assertEqual(replies.count('READY_RESOURCE_ONLY'), 1)
        self.assertEqual(replies.count('REPLAY'), 31)

    def test_changed_proposal_and_grant_downgrades(self):
        grant,nonce = self.minted()
        self.assertEqual(self.issuer.consume(grant,H('changed'),nonce,130),'CONTEXT')
        self.assertEqual(self.issuer.consume(replace(grant,bits=9),self.proposal,nonce,130),'GRANT_MAC')
        self.assertEqual(self.issuer.consume(replace(grant,mac=bytes(32)),self.proposal,nonce,130),'GRANT_MAC')
        self.assertEqual(self.issuer.consume(grant,self.proposal,nonce,130),'READY_RESOURCE_ONLY')

    def test_expiry_and_process_epoch_change_refuse_replay(self):
        grant,nonce = self.minted()
        new_epoch=R.ReceiverAdmission(self.issuer.receiver,self.issuer.secret,
                                     bytes([6])*32,entropy=lambda n:bytes([7])*n)
        self.assertEqual(new_epoch.consume(grant,self.proposal,nonce,120),'CONTEXT')
        self.assertEqual(self.issuer.consume(grant,self.proposal,nonce,2100),'EXPIRED_OR_FUTURE')
        with self.assertRaisesRegex(ValueError,'CLOCK_REGRESSION'):
            self.issuer.offer(self.proposal,8,2000)

    def test_paid_false_transcript_still_fails_complete_w1_replay(self):
        import work_oracle as W
        zeros = [0] * W.CELLS
        header = H('receiver-research-header') * 9 + bytes(30)
        self.assertEqual(len(header), 318)
        challenge = H('challenge', header)
        false_proof = (b'PNW1' + W.field_bytes(zeros) * 3
                       + H('receiver-forged-trace', challenge))
        proposal = H('w2c-proposal', b'w2c-research-security-v0', header, false_proof)
        issuer = R.ReceiverAdmission(bytes([1]) * 32, bytes([3]) * 32,
                                     bytes([5]) * 32,
                                     entropy=lambda n: bytes([7]) * n)
        grant = issuer.offer(proposal, 8, 100)
        nonce, _ = R.solve(grant, 8192)
        self.assertIsNotNone(nonce)
        self.assertEqual(issuer.consume(grant, proposal, nonce, 110),
                         'READY_RESOURCE_ONLY')
        task = W.task_id(zeros, zeros)
        with self.assertRaisesRegex(ValueError, '^TRANSCRIPT$'):
            W.verify(challenge, task, bytes([255]) * 32, false_proof)

    def test_invalid_cost_ticket_is_not_valid_work(self):
        grant,_ = self.minted()
        miss = next(n for n in range(32) if not R.qualifies(R.ticket(grant,n),grant.bits))
        self.assertEqual(self.issuer.consume(grant,self.proposal,miss,125),'TARGET')
        nonce,_=R.solve(grant,8192)
        self.assertEqual(self.issuer.consume(grant,self.proposal,nonce,125),'READY_RESOURCE_ONLY')
        # This module intentionally has no W1 verifier, mining or Chainwork API.
        self.assertFalse(hasattr(R, 'VerifiedWork'))

    def test_issuance_capacity_exhaustion_does_not_create_free_ticket(self):
        issuer=R.ReceiverAdmission(bytes([1])*32,bytes([2])*32,bytes([3])*32,
                                   capacity=1, entropy=lambda n:bytes([7])*n)
        grant=issuer.offer(self.proposal,8,100)
        self.assertIsNotNone(grant)
        self.assertIsNone(issuer.offer(self.proposal,8,101))
        n,_=R.solve(grant,8192)
        self.assertEqual(issuer.consume(grant,self.proposal,n,120),'READY_RESOURCE_ONLY')
        self.assertIsNone(issuer.offer(self.proposal,8,121))
        issuer.clock(2100)
        self.assertIsNotNone(issuer.offer(self.proposal,8,2100))

    def test_invalid_bounds_and_wrong_nonce(self):
        grant,nonce=self.minted()
        for bits in (7,25,0):
            with self.assertRaisesRegex(ValueError,'BITS'):
                self.issuer.offer(self.proposal,bits,120)
        with self.assertRaisesRegex(ValueError,'NONCE'):
            R.ticket(grant,-1)
        self.assertEqual(self.issuer.consume(grant,self.proposal,-1,120),'GRANT_ENCODING')


    def test_epoch_issuance_not_refunded_by_expiry_spend_or_identity_rotation(self):
        serial = iter((bytes([1])*32, bytes([2])*32, bytes([3])*32))
        owner = R.ReceiverAdmission(
            bytes([1])*32, bytes([9])*32, bytes([4])*32,
            capacity=1, epoch_issue_limit=2, entropy=lambda n: next(serial))
        first=owner.offer(self.proposal,8,100)
        self.assertIsNotNone(first)
        nonce,_=R.solve(first,8192)
        self.assertEqual(owner.consume(first,self.proposal,nonce,120),'READY_RESOURCE_ONLY')
        self.assertIsNone(owner.offer(H('rotated-identity'),8,121))
        second=owner.offer(H('another-payload'),8,2101)
        self.assertIsNotNone(second)
        self.assertEqual(owner.issued_total,2)
        owner.clock(5000)
        self.assertIsNone(owner.offer(H('fresh-identity'),8,5001))
        self.assertEqual(owner.issued_total,2)
        self.assertEqual(owner.issued,{})
        # Only an independent process epoch could receive another budget;
        # no caller key/body/expiry or redeemed token can reset this instance.

    def test_epoch_limit_has_strict_bounded_constructor(self):
        for bad in (0,65537,-1,1.0,True):
            with self.assertRaises(ValueError):
                R.ReceiverAdmission(bytes(32),bytes(32),bytes(32),epoch_issue_limit=bad)


if __name__=='__main__':
    unittest.main(verbosity=2)
