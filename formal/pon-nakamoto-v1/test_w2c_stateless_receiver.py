"""Research negatives for W2-C unsigned challenge capacity and paid replay."""
import hashlib
import hmac
import unittest
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from contract_wire import H
import w2c_receiver_admission as R
import w2c_stateless_receiver as S


def entropy():
    counter = iter(range(1, 65536))
    return lambda n: next(counter).to_bytes(n, 'little')


class StatelessReceiverResearchTests(unittest.TestCase):
    def setUp(self):
        self.proposal = H('stateless-research-packet')
        self.server = S.StatelessReceiverAdmission(
            bytes([1]) * 32, bytes([3]) * 32, bytes([5]) * 32,
            spent_capacity=2, entropy=entropy(),
        )

    def valid(self, server=None, now=100, proposal=None):
        server = server or self.server
        grant = server.offer(proposal or self.proposal, now)
        nonce, sample = R.solve(grant, 65536)
        self.assertIsNotNone(nonce)
        self.assertEqual(sample['status'], 'TARGET_HIT_UNVERIFIED')
        return grant, nonce

    def test_unpaid_issuance_cannot_fill_paid_resource_table(self):
        for i in range(256):
            self.server.offer(H('unpaid-offer', i.to_bytes(8, 'little')), 100)
        self.assertEqual(self.server.spent, {})
        grant, nonce = self.valid()
        self.assertEqual(self.server.consume(grant,self.proposal,nonce,120),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(len(self.server.spent),1)

    def test_concurrent_ticket_consumption_is_atomic(self):
        grant, nonce = self.valid()
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(
                lambda _: self.server.consume(grant,self.proposal,nonce,120),
                range(32)))
        self.assertEqual(results.count('READY_RESOURCE_ONLY'),1)
        self.assertEqual(results.count('REPLAY'),31)
        self.assertEqual(len(self.server.spent),1)

    def test_two_receivers_must_pay_separately(self):
        other = S.StatelessReceiverAdmission(
            bytes([2])*32,bytes([3])*32,bytes([5])*32,entropy=entropy())
        grant, nonce = self.valid()
        self.assertEqual(other.consume(grant,self.proposal,nonce,120),'CONTEXT')
        self.assertEqual(self.server.consume(grant,self.proposal,nonce,120),
                         'READY_RESOURCE_ONLY')

    def test_paid_capacity_busy_does_not_refund_or_turn_into_consensus_invalid(self):
        issuer = S.StatelessReceiverAdmission(
            bytes([1])*32,bytes([3])*32,bytes([5])*32,
            spent_capacity=1,entropy=entropy())
        first,n0 = self.valid(issuer)
        second,n1 = self.valid(issuer)
        self.assertEqual(issuer.consume(first,self.proposal,n0,110),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(issuer.consume(second,self.proposal,n1,110),
                         'PAID_CAPACITY_BUSY')
        self.assertEqual(len(issuer.spent),1)
        # A second challenge can be issued even when the paid claim table is
        # temporarily full. Expired claims are reclaimed only for paid tickets.
        last,n2 = self.valid(issuer,2100)
        self.assertEqual(issuer.consume(last,self.proposal,n2,2110),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(len(issuer.spent),1)

    def test_already_paid_tickets_stay_spent_after_failed_w1_and_replay(self):
        import work_oracle as W
        zeros = [0] * W.CELLS
        challenge = H('stateless-false-W1-challenge')
        false_proof = b'PNW1' + W.field_bytes(zeros)*3 + H('false-trace',challenge)
        grant,nonce=self.valid()
        self.assertEqual(self.server.consume(grant,self.proposal,nonce,110),
                         'READY_RESOURCE_ONLY')
        with self.assertRaisesRegex(ValueError,'^TRANSCRIPT$'):
            W.verify(challenge,W.task_id(zeros,zeros),bytes([255])*32,false_proof)
        self.assertEqual(self.server.consume(grant,self.proposal,nonce,110),'REPLAY')

    def test_signed_weaker_difficulty_cannot_pass_original_receiver_policy(self):
        issuer = S.StatelessReceiverAdmission(
            bytes([1])*32,bytes([3])*32,bytes([5])*32,
            bits=12,entropy=entropy())
        hard = issuer.offer(self.proposal,100)
        weak = replace(hard,bits=8,mac=bytes(32))
        weak = replace(weak,mac=hmac.new(issuer.secret,weak.unsigned(),hashlib.sha256).digest())
        nonce,_=R.solve(weak,16384)
        self.assertIsNotNone(nonce)
        self.assertEqual(issuer.consume(weak,self.proposal,nonce,120),'BITS_POLICY')
        self.assertEqual(issuer.spent,{})

    def test_tampered_context_mac_epoch_and_false_nonce_do_not_spend(self):
        grant,nonce=self.valid()
        miss=next(i for i in range(50)
                  if not R.qualifies(R.ticket(grant,i),grant.bits))
        self.assertEqual(self.server.consume(grant,self.proposal,miss,120),'TARGET')
        self.assertEqual(self.server.consume(grant,H('wrong'),nonce,120),'CONTEXT')
        self.assertEqual(self.server.consume(
            replace(grant,mac=bytes(32)),self.proposal,nonce,120),'GRANT_MAC')
        self.assertEqual(self.server.consume(
            replace(grant,epoch=bytes([6])*32),self.proposal,nonce,120),'CONTEXT')
        self.assertEqual(self.server.spent,{})
        self.assertEqual(self.server.consume(grant,self.proposal,nonce,120),
                         'READY_RESOURCE_ONLY')

    def test_expiry_monotonic_clock_and_invalid_type_are_fenced(self):
        grant,nonce=self.valid()
        self.assertEqual(self.server.consume(grant,self.proposal,nonce,2100),
                         'EXPIRED_OR_FUTURE')
        with self.assertRaisesRegex(ValueError,'CLOCK_REGRESSION'):
            self.server.offer(self.proposal,2000)
        with self.assertRaisesRegex(ValueError,'NONCE'):
            R.ticket(grant,-1)
        self.assertEqual(self.server.spent,{})


if __name__ == '__main__':
    unittest.main(verbosity=2)
