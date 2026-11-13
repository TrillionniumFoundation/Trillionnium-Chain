"""W2-E full-prefix polynomial identity regression, no work authority."""
import hashlib
import math
import struct
import unittest
import w2e_batched_polynomial as E
import w2d_full_tile_freivalds as D
import work_oracle as W
from contract_wire import H


class W2EBatchedPolyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.challenge=bytes(range(32))
        cls.a=[(i*11)%97 for i in range(W.CELLS)]
        cls.b=[(i*17)%101 for i in range(W.CELLS)]
        cls.task=W.task_id(cls.a,cls.b)
        cls.target=bytes([255])*32
        cls.proof=W.prove(cls.challenge,cls.a,cls.b)
        cls.sidecar=D.witness(cls.challenge,cls.a,cls.b)

    def test_valid_dense_full_trace_and_five_rounds(self):
        result=E.verify(self.challenge,self.task,self.target,self.proof,self.sidecar)
        self.assertEqual(result['rounds'],5)
        self.assertEqual(result['checked_steps'],512)
        self.assertEqual(result['witness_bytes'],131072)
        self.assertTrue(result['fixed_input_schwartz_zippel_bound'] < 2**-128)
        self.assertFalse(result['verified_work'])
        self.assertFalse(result['chainwork'])

    def test_zero_and_sparse_material(self):
        z=[0]*W.CELLS
        a=[(i*11)%97 if i%17==0 else 0 for i in range(W.CELLS)]
        b=[(i*17)%101 if i%19==0 else 0 for i in range(W.CELLS)]
        for left,right in ((z,z),(a,b)):
            proof=W.prove(self.challenge,left,right)
            sidecar=D.witness(self.challenge,left,right)
            result=E.verify(self.challenge,W.task_id(left,right),self.target,proof,sidecar)
            self.assertEqual(result['result'],'BATCHED_POLYNOMIAL_RESEARCH_ONLY')

    def test_bad_first_middle_last_committed_tile(self):
        for idx in (0,D.TILES//2,D.TILES-1):
            raw=bytearray(self.sidecar)
            at=idx*D.TILE_BYTES
            orig=int.from_bytes(raw[at:at+4],'little')
            raw[at:at+4]=struct.pack('<I',(orig+1)%W.Q)
            raw=bytes(raw)
            newtrace=hashlib.sha256(b'TRNM-PON-TRACE1\0'+self.challenge+raw).digest()
            altered=self.proof[:-32]+newtrace
            with self.subTest(index=idx):
                with self.assertRaisesRegex(ValueError,'^BATCHED_TILE_RELATION$'):
                    E.verify(self.challenge,self.task,self.target,altered,raw)

    def test_bad_final_c_rejected(self):
        wrong=bytearray(self.proof)
        at=4+2*W.CELLS*4
        orig=int.from_bytes(wrong[at:at+4],'little')
        wrong[at:at+4]=struct.pack('<I',(orig+1)%W.Q)
        with self.assertRaisesRegex(ValueError,'^PRODUCT_RELATION$'):
            E.verify(self.challenge,self.task,self.target,bytes(wrong),self.sidecar)

    def test_four_false_ticket_trace_claims_refuse_before_polynomial(self):
        for n in range(4):
            claimed=H('false-W2E',self.challenge,struct.pack('<Q',n))
            with self.assertRaisesRegex(ValueError,'^TRANSCRIPT$'):
                E.verify(self.challenge,self.task,self.target,self.proof[:-32]+claimed,self.sidecar)

    def test_shape_and_field_errors(self):
        for invalid in (self.sidecar[:-1],self.sidecar+b'\0'):
            with self.assertRaisesRegex(ValueError,'^WITNESS_LENGTH$'):
                E.verify(self.challenge,self.task,self.target,self.proof,invalid)
        wrong=bytearray(self.sidecar);wrong[:4]=struct.pack('<I',W.Q)
        with self.assertRaisesRegex(ValueError,'^WITNESS_FIELD$'):
            E.verify(self.challenge,self.task,self.target,self.proof,bytes(wrong))

    def test_wrong_task_target_and_challenge_refuse(self):
        with self.assertRaisesRegex(ValueError,'TASK'):
            E.verify(self.challenge,bytes([88])*32,self.target,self.proof,self.sidecar)
        with self.assertRaisesRegex(ValueError,'TARGET'):
            E.verify(self.challenge,self.task,bytes(32),self.proof,self.sidecar)
        with self.assertRaisesRegex(ValueError,'TRANSCRIPT'):
            E.verify(bytes([88])*32,self.task,self.target,self.proof,self.sidecar)


if __name__=='__main__':unittest.main(verbosity=2)
