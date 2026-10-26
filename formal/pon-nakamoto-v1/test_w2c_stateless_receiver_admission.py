"""P5 negative controls; independent receiver-local cost != W1 proof validity."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import unittest
from contract_wire import H
import w2c_stateless_receiver_admission as S

class StatelessW2CResearchTests(unittest.TestCase):
    def setUp(self):
        self.proposal = H('w2c-v2-pinned-proposal')
        self.s = S.StatelessReceiver(bytes([1])*32,bytes([2])*32,
                                     bytes([3])*32,capacity=2,
                                     entropy=lambda n:bytes([5])*n)
    def paid(self, issuer=None, proposal=None):
        issuer=issuer or self.s
        proposal=proposal or self.proposal
        grant=issuer.offer(proposal,8,max(issuer.now_ms,100))
        nonce,cost=S.solve(grant,4096)
        self.assertIsNotNone(nonce)
        self.assertEqual(cost['status'],'TARGET_HIT_UNVERIFIED')
        return grant,nonce

    def test_cheap_unsigned_grant_issuance_cannot_exhaust_pending_slots(self):
        for i in range(5000):
            self.s.offer(H('offer-proposal',i.to_bytes(8,'little')),8,100)
        self.assertEqual(len(self.s.spent),0)
        g,n=self.paid()
        self.assertEqual(self.s.consume(g,self.proposal,n,101),'READY_RESOURCE_ONLY')

    def test_concurrent_replay_has_exactly_one_ready(self):
        grant,nonce=self.paid()
        with ThreadPoolExecutor(max_workers=8) as pool:
            result=list(pool.map(lambda _:self.s.consume(grant,self.proposal,nonce,120),range(32)))
        self.assertEqual(result.count('READY_RESOURCE_ONLY'),1)
        self.assertEqual(result.count('REPLAY'),31)
        self.assertEqual(len(self.s.spent),1)

    def test_copy_to_another_receiver_is_not_payment(self):
        grant,nonce=self.paid()
        other=S.StatelessReceiver(bytes([4])*32,self.s.secret,self.s.epoch)
        self.assertEqual(other.consume(grant,self.proposal,nonce,120),'CONTEXT')
        self.assertEqual(self.s.consume(grant,self.proposal,nonce,120),'READY_RESOURCE_ONLY')

    def test_old_epoch_rejected_even_with_identical_secret(self):
        grant,nonce=self.paid()
        restarted=S.StatelessReceiver(self.s.receiver,self.s.secret,bytes([6])*32)
        self.assertEqual(restarted.consume(grant,self.proposal,nonce,120),'CONTEXT')

    def test_expiry_and_monotonic_clock(self):
        grant,nonce=self.paid()
        self.assertEqual(self.s.consume(grant,self.proposal,nonce,2100),'EXPIRED')
        with self.assertRaisesRegex(ValueError,'CLOCK_REGRESSION'):
            self.s.offer(self.proposal,8,1500)
        self.assertEqual(len(self.s.spent),0)

    def test_mac_tamper_and_false_cost_are_not_validated(self):
        grant,nonce=self.paid()
        self.assertEqual(self.s.consume(replace(grant,bits=12),self.proposal,nonce,110),'MAC')
        self.assertEqual(self.s.consume(replace(grant,mac=bytes(32)),self.proposal,nonce,110),'MAC')
        miss=next(i for i in range(32) if not S.qualifies(S.ticket(grant,i),8))
        self.assertEqual(self.s.consume(grant,self.proposal,miss,110),'TARGET')
        self.assertEqual(len(self.s.spent),0)

    def test_paid_capacity_full_fails_closed_and_preserves_spent_replay(self):
        a,n=self.paid()
        self.assertEqual(self.s.consume(a,self.proposal,n,120),'READY_RESOURCE_ONLY')
        b,n2=self.paid(proposal=H('other'))
        # For capacity 2, two tokens are admitted and third is Busy.
        self.assertEqual(self.s.consume(b,H('other'),n2,121),'READY_RESOURCE_ONLY')
        c,n3=self.paid(proposal=H('third'))
        self.assertEqual(self.s.consume(c,H('third'),n3,122),'BUSY_RESOURCE_ONLY')
        self.assertEqual(self.s.consume(a,self.proposal,n,122),'REPLAY')
        self.assertEqual(len(self.s.spent),2)
        self.assertEqual(self.s.consume(c,H('third'),n3,2121),'EXPIRED')
        self.assertEqual(len(self.s.spent),0)

    def test_context_and_numeric_bounds(self):
        grant,nonce=self.paid()
        self.assertEqual(self.s.consume(grant,H('wrong'),nonce,120),'CONTEXT')
        self.assertEqual(self.s.consume(grant,self.proposal,-1,120),'MALFORMED')
        for bits in (0,7,25):
            with self.assertRaisesRegex(ValueError,'BITS'):
                self.s.offer(self.proposal,bits,121)
        for cap in (0,1025):
            with self.assertRaisesRegex(ValueError,'CAPACITY'):
                S.StatelessReceiver(bytes(32),bytes(32),bytes(32),capacity=cap)

if __name__=='__main__':unittest.main(verbosity=2)
