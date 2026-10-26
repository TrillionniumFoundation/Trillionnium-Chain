"""Executable receiver-bound paid-only state tests; no W1 or production authority."""
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from contract_wire import H
from w2c_stateless_admission import Issuer, PaidReplayOwner, solve, ticket, qualifies


def make(receiver=1, epoch=3, owner=None, bits=8, cap=32, entropy_byte=5):
    owner=owner if owner is not None else PaidReplayOwner(capacity=4)
    issuer=Issuer(bytes([receiver])*32,bytes([2])*32,bytes([7])*32,
                  bytes([epoch])*32,owner,bits=bits,mint_capacity=cap,
                  entropy=lambda count:bytes([entropy_byte])*count)
    return issuer,owner


class StatelessTests(unittest.TestCase):
    def setUp(self):
        self.proposal=H('untrusted-full-w1-proposal')
        self.issuer,self.owner=make()

    def paid(self,issuer=None,now=100):
        issuer=issuer or self.issuer
        offer=issuer.issue(self.proposal,now)
        self.assertIsNotNone(offer)
        nonce,attempts=solve(offer,4096)
        self.assertIsNotNone(nonce)
        self.assertGreater(attempts,0)
        return offer,nonce

    def test_unpaid_grants_never_take_replay_memory(self):
        issuer,owner=make(cap=16)
        grants=[issuer.issue(self.proposal,100) for _ in range(16)]
        self.assertTrue(all(grants))
        self.assertEqual(len(owner.paid),0)
        self.assertIsNone(issuer.issue(self.proposal,100))
        self.assertEqual(len(owner.paid),0)
        self.assertIsNotNone(issuer.issue(self.proposal,1100))
        self.assertEqual(len(owner.paid),0)

    def test_concurrent_exact_replay_one_paid_grant(self):
        offer,nonce=self.paid()
        with ThreadPoolExecutor(max_workers=16) as pool:
            seen=list(pool.map(lambda _:self.issuer.pay(offer,self.proposal,nonce,150),range(64)))
        self.assertEqual(seen.count('READY_RESOURCE_ONLY'),1)
        self.assertEqual(seen.count('REPLAY'),63)
        self.assertEqual(len(self.owner.paid),1)

    def test_separately_constructed_issuers_share_one_replay_owner(self):
        issuer2,_=make(owner=self.owner)
        offer,nonce=self.paid()
        self.assertEqual(self.issuer.pay(offer,self.proposal,nonce,160),'READY_RESOURCE_ONLY')
        self.assertEqual(issuer2.pay(offer,self.proposal,nonce,160),'REPLAY')

    def test_other_receiver_epoch_network_context_refused(self):
        offer,nonce=self.paid()
        second,_=make(receiver=9)
        self.assertEqual(second.pay(offer,self.proposal,nonce,150),'CONTEXT')
        restarted,_=make(epoch=13)
        self.assertEqual(restarted.pay(offer,self.proposal,nonce,150),'CONTEXT')
        self.assertEqual(self.issuer.pay(offer,H('changed'),nonce,150),'CONTEXT')

    def test_no_client_difficulty_downgrade_or_mac_tamper(self):
        offer,nonce=self.paid()
        self.assertEqual(self.issuer.pay(replace(offer,bits=12),self.proposal,nonce,150),'CONTEXT')
        self.assertEqual(self.issuer.pay(replace(offer,mac=bytes(32)),self.proposal,nonce,150),'MAC')
        self.assertEqual(self.issuer.pay(offer,self.proposal,nonce,150),'READY_RESOURCE_ONLY')

    def test_no_unpaid_cpu_admission_with_bad_nonce(self):
        offer,nonce=self.paid()
        bad=next(n for n in range(32) if not qualifies(ticket(offer,n),offer.bits))
        self.assertEqual(self.issuer.pay(offer,self.proposal,bad,160),'TARGET')
        self.assertEqual(len(self.owner.paid),0)
        self.assertEqual(self.issuer.pay(offer,self.proposal,nonce,160),'READY_RESOURCE_ONLY')

    def test_pending_paid_store_full_fails_closed_until_expiry(self):
        issuer,owner=make(cap=64,entropy_byte=12)
        for i in range(4):
            offer=issuer.issue(H('distinct',bytes([i])),100+i*20)
            nonce,_=solve(offer,4096)
            self.assertEqual(issuer.pay(offer,offer.proposal,nonce,110+i*20),'READY_RESOURCE_ONLY')
        self.assertEqual(len(owner.paid),4)
        other=issuer.issue(H('another'),200)
        n,_=solve(other,4096)
        self.assertEqual(issuer.pay(other,other.proposal,n,210),'BUSY_PAID_STORE')
        owner.now(2400)
        self.assertEqual(len(owner.paid),0)
        self.assertEqual(issuer.pay(other,other.proposal,n,2400),'EXPIRED_OR_FUTURE')

    def test_clock_regression_expiry_and_overflow(self):
        offer,nonce=self.paid()
        self.assertEqual(self.issuer.pay(offer,self.proposal,nonce,2100),'EXPIRED_OR_FUTURE')
        with self.assertRaisesRegex(ValueError,'CLOCK_REGRESSION'):
            self.issuer.issue(self.proposal,2000)
        with self.assertRaisesRegex(ValueError,'CLOCK_OVERFLOW'):
            self.issuer.issue(self.proposal,(1<<64)-1)

    def test_secret_epoch_duplication_with_independent_stores_is_not_safe(self):
        # Explicit NEGATIVE control: two servers accidentally cloning secret
        # and epoch but using different PaidReplayOwner objects both grant.
        a,_=make()
        b,_=make()
        offer,nonce=self.paid(a)
        self.assertEqual(a.pay(offer,self.proposal,nonce,140),'READY_RESOURCE_ONLY')
        self.assertEqual(b.pay(offer,self.proposal,nonce,140),'READY_RESOURCE_ONLY')
        # Actual deployment must enforce one host-shared owner or unique epochs.

    def test_invalid_config_rejected(self):
        for bits in (7,25):
            with self.assertRaisesRegex(ValueError,'BITS'):
                make(bits=bits)
        with self.assertRaisesRegex(ValueError,'NONCE'):
            ticket(self.paid()[0],-1)

if __name__=='__main__':unittest.main(verbosity=2)
