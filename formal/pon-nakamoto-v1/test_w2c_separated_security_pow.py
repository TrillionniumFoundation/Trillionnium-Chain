"""Research W2-C negative tests: security ticket never grants chainwork."""
import unittest
from dataclasses import replace
from unittest.mock import patch
import w2c_separated_security_pow as S
import work_oracle as W
from contract_wire import H

class W2CResearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = H('w2c-research-header', b'A') * 9 + bytes(30)
        cls.challenge = H('challenge',cls.header)
        cls.a = [0] * W.CELLS
        cls.task = W.task_id(cls.a,cls.a)
        cls.proof = W.prove(cls.challenge,cls.a,cls.a)
        cls.bad = b'PNW1' + W.field_bytes(cls.a)*3 + H('w2c-false-trace',cls.challenge)

    def test_valid_w1_still_grants_zero_chainwork_authority(self):
        candidate,cost = S.search(self.header,self.proof,8,65536)
        self.assertIsNotNone(candidate)
        self.assertEqual(cost['status'],'FOUND')
        result=S.validate(candidate,self.task,8)
        self.assertEqual(result['outcome'],'VALID_W1_RESEARCH_ONLY')
        self.assertFalse(result['verified_work'])

    def test_false_w1_passes_security_but_fails_original_replay(self):
        candidate,_=S.search(self.header,self.bad,8,65536)
        self.assertIsNotNone(candidate)
        result=S.validate(candidate,self.task,8)
        self.assertEqual(result['outcome'],'W1_TRANSCRIPT')
        self.assertTrue(result['w1_replayed'])
        self.assertFalse(result['verified_work'])

    def test_failed_security_ticket_stops_before_work(self):
        candidate,_=S.search(self.header,self.bad,8,65536)
        self.assertIsNotNone(candidate)
        digest=S.proposal_digest(self.header,self.bad)
        bad=next(i for i in range(200)
                 if not S.qualifies(S.security_ticket(digest,i),8))
        with patch.object(W,'verify',side_effect=AssertionError('W1 not allowed')):
            result=S.validate(replace(candidate,nonce=bad),self.task,8)
        self.assertEqual(result['outcome'],'SECURITY_TARGET')
        self.assertFalse(result['w1_replayed'])

    def test_one_global_security_ticket_cannot_price_two_independent_receivers(self):
        # This is an intentional negative control, not a service admission test:
        # W2-C's globally transferable security ticket has no receiver, cookie
        # issuance epoch or single-use identity. The same ticket can be checked
        # on two different nodes and each pays full W1 replay CPU.
        candidate,_=S.search(self.header,self.bad,8,65536)
        self.assertIsNotNone(candidate)
        first=S.validate(candidate,self.task,8)
        second=S.validate(candidate,self.task,8)
        self.assertEqual(first['outcome'],'W1_TRANSCRIPT')
        self.assertEqual(second['outcome'],'W1_TRANSCRIPT')
        self.assertTrue(first['w1_replayed'])
        self.assertTrue(second['w1_replayed'])
        self.assertFalse(first['verified_work'])
        self.assertFalse(second['verified_work'])
        # Public V3's server-bound one-use Cookie is a SEPARATE admission
        # mechanism; it must not be replaced by this research ticket.

    def test_exact_header_and_proof_commitment_and_capped_search(self):
        changed_h=self.header[:-1]+bytes([self.header[-1]^1])
        changed_p=self.proof[:-1]+bytes([self.proof[-1]^1])
        digest=S.proposal_digest(self.header,self.proof)
        self.assertNotEqual(digest,S.proposal_digest(changed_h,self.proof))
        self.assertNotEqual(digest,S.proposal_digest(self.header,changed_p))
        candidate,cost=S.search(self.header,self.proof,28,1)
        self.assertEqual(cost['attempted_hashes'],1)
        self.assertEqual(cost['status'],'FOUND' if candidate else 'EXHAUSTED')
        for bits in (0,7,29):
            with self.assertRaises(ValueError):
                S.search(self.header,self.proof,bits,1)
if __name__ == '__main__':
    unittest.main(verbosity=2)
