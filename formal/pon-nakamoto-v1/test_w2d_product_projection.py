import unittest
from contract_wire import H
import work_oracle as W
import w2d_product_projection as S

class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.a=[(i*11+3)%97 for i in range(W.CELLS)]
  cls.b=[(i*17+7)%101 for i in range(W.CELLS)]
  cls.challenge=H('test-w2d')
  cls.task=W.task_id(cls.a,cls.b)
  cls.target=bytes([255])*32
  cls.base=S.precomputed_base(cls.a,cls.b)
  cls.proof=S.direct(cls.challenge,cls.a,cls.b,cls.base)
 def test_direct_factor_parity(self):
  self.assertEqual(self.proof,S.factored(self.challenge,self.a,self.b,self.base))
  self.assertEqual(S.verify(self.challenge,self.task,self.target,self.proof)['chainwork'],0)
 def test_challenge_binding(self):
  with self.assertRaisesRegex(ValueError,'TASK'):S.verify(self.challenge,H('wrong'),self.target,self.proof)
  with self.assertRaisesRegex(ValueError,'TARGET'):S.verify(self.challenge,self.task,bytes(32),self.proof)
 def test_base_fraud(self):
  p=bytearray(self.proof);p[4+2*W.CELLS*4]^=1
  with self.assertRaisesRegex(ValueError,'BASE_PROJECTION'):S.verify(self.challenge,self.task,self.target,bytes(p))
 def test_mask_fraud(self):
  p=bytearray(self.proof);p[-1]^=1
  with self.assertRaisesRegex(ValueError,'MASKED_PROJECTION'):S.verify(self.challenge,self.task,self.target,bytes(p))
 def test_malformed(self):
  with self.assertRaisesRegex(ValueError,'LENGTH'):S.verify(self.challenge,self.task,self.target,self.proof[:-1])
  with self.assertRaisesRegex(ValueError,'VERSION'):S.verify(self.challenge,self.task,self.target,b'PNA0'+self.proof[4:])
 def test_zero_easy_producer(self):
  a=[0]*W.CELLS;c=H('zero-W2D');b=a;base=S.precomputed_base(a,b)
  self.assertEqual(S.direct(c,a,b,base),S.factored(c,a,b,base))
  p=S.direct(c,a,b,base);self.assertFalse(S.verify(c,W.task_id(a,b),self.target,p)['verified_work'])
 def test_ticket_not_authority(self):
  self.assertNotIn('VerifiedWork',str(S.verify(self.challenge,self.task,self.target,self.proof)))
 def test_ticket_valid_false_product_does_not_earn_work(self):
  # A fake PND0 statement with correct base C=0 but false masked C'=0
  # can win the cheap ticket lottery without any legitimate masked product.
  import hashlib
  zeros=[0]*W.CELLS
  proof=b'PND0'+W.field_bytes(zeros)*4
  target=bytes.fromhex('7f'+'ff'*31)
  task=W.task_id(zeros,zeros)
  hits=0
  for nonce in range(64):
   challenge=H('w2d-forged-ticket-control',nonce.to_bytes(8,'little'))
   if S.ticket(challenge,proof)>target:continue
   hits+=1
   with self.assertRaisesRegex(ValueError,'MASKED_PROJECTION'):
    S.verify(challenge,task,target,proof)
   if hits==4:break
  self.assertEqual(hits,4)
