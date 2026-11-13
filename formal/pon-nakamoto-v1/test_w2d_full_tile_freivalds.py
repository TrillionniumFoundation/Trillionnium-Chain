"""Source-level research-only negative W2-D tile checks, not work authority."""
import hashlib
import struct
import unittest
from contract_wire import H
import work_oracle as W
import w2d_full_tile_freivalds as D


class W2DFullTiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.challenge=bytes(range(32))
        cls.a=[(i*11)%97 for i in range(W.CELLS)]
        cls.b=[(i*17)%101 for i in range(W.CELLS)]
        cls.task=W.task_id(cls.a,cls.b)
        cls.target=bytes([255])*32
        cls.proof=W.prove(cls.challenge,cls.a,cls.b)
        cls.sidecar=D.witness(cls.challenge,cls.a,cls.b)

    def test_full_dense_relation_and_exact_oracle_trace(self):
        self.assertEqual(len(self.sidecar),131072)
        self.assertEqual(hashlib.sha256(b'TRNM-PON-TRACE1\0'+self.challenge+self.sidecar).digest(),self.proof[-32:])
        self.assertEqual(D.verify(self.challenge,self.task,self.target,self.proof,self.sidecar)['result'],
                         'PROBABILISTIC_RELATION_RESEARCH_ONLY')
        self.assertEqual(W.verify(self.challenge,self.task,self.target,self.proof)[1],
                         list(struct.unpack('<4096I',self.proof[32772:49156])))

    def test_zero_material_proof_and_witness(self):
        z=[0]*W.CELLS
        proof=W.prove(self.challenge,z,z)
        sidecar=D.witness(self.challenge,z,z)
        self.assertEqual(D.verify(self.challenge,W.task_id(z,z),self.target,proof,sidecar)['tiles'],512)

    def test_one_corrupted_tile_with_rebound_trace_rejected(self):
        modified=bytearray(self.sidecar)
        x=int.from_bytes(modified[4:8],'little')
        modified[4:8]=struct.pack('<I',(x+1)%W.Q)
        raw=bytes(modified)
        changed_trace=hashlib.sha256(b'TRNM-PON-TRACE1\0'+self.challenge+raw).digest()
        claim=self.proof[:-32]+changed_trace
        self.assertEqual(W.precheck(self.challenge,self.task,self.target,claim)[3],H('ticket',self.challenge,changed_trace))
        with self.assertRaisesRegex(ValueError,'^TILE_RELATION$'):
            D.verify(self.challenge,self.task,self.target,claim,raw)

    def test_every_prefix_region_first_middle_last_is_checked(self):
        # W2-A sampled openings can miss a forged location; W2-D checks every
        # committed tile, including the final state on the last block pair.
        for index in (0,D.TILES//2,D.TILES-1):
            raw=bytearray(self.sidecar)
            position=index*D.TILE_BYTES
            prior=int.from_bytes(raw[position:position+4],'little')
            raw[position:position+4]=struct.pack('<I',(prior+1)%W.Q)
            changed=bytes(raw)
            forged=self.proof[:-32]+hashlib.sha256(
                b'TRNM-PON-TRACE1\0'+self.challenge+changed).digest()
            with self.subTest(tile=index):
                with self.assertRaisesRegex(ValueError,'^TILE_RELATION$'):
                    D.verify(self.challenge,self.task,self.target,forged,changed)

    def test_claimed_product_fraud_with_real_trace_rejected(self):
        changed=bytearray(self.proof)
        i=4+2*W.CELLS*4
        original=int.from_bytes(changed[i:i+4],'little')
        changed[i:i+4]=struct.pack('<I',(original+1)%W.Q)
        with self.assertRaisesRegex(ValueError,'^PRODUCT_RELATION$'):
            D.verify(self.challenge,self.task,self.target,bytes(changed),self.sidecar)

    def test_four_cheap_fabricated_trace_claims_rejected_early(self):
        claims=set()
        for nonce in range(4):
            bogus=H('w2d-false-from-zero',self.challenge,struct.pack('<Q',nonce))
            claims.add(bogus)
            with self.assertRaisesRegex(ValueError,'^TRANSCRIPT$'):
                D.verify(self.challenge,self.task,self.target,self.proof[:-32]+bogus,self.sidecar)
        self.assertEqual(len(claims),4)

    def test_change_challenge_task_or_target_rejected(self):
        with self.assertRaisesRegex(ValueError,'TRANSCRIPT'):
            D.verify(bytes([1])*32,self.task,self.target,self.proof,self.sidecar)
        with self.assertRaisesRegex(ValueError,'TASK'):
            D.verify(self.challenge,bytes([2])*32,self.target,self.proof,self.sidecar)
        with self.assertRaisesRegex(ValueError,'TARGET'):
            D.verify(self.challenge,self.task,bytes(32),self.proof,self.sidecar)

    def test_noncanonical_or_ill_shaped_sidecar_rejected(self):
        for blob in (self.sidecar[:-1],self.sidecar+b'\x00'):
            with self.assertRaisesRegex(ValueError,'SIDECAR_LENGTH'):
                D.verify(self.challenge,self.task,self.target,self.proof,blob)
        blob=bytearray(self.sidecar)
        blob[:4]=struct.pack('<I',W.Q)
        with self.assertRaisesRegex(ValueError,'SIDECAR_FIELD'):
            D.verify(self.challenge,self.task,self.target,self.proof,bytes(blob))

    def test_randomized_checks_not_promoted_to_native_authority(self):
        result=D.verify(self.challenge,self.task,self.target,self.proof,self.sidecar)
        self.assertIs(result['verified_work'],False)
        self.assertIs(result['chainwork'],False)
        self.assertIs(result['production_activation'],False)
        self.assertEqual(result['freivalds_rounds'],2)
        self.assertEqual(len(D.field_vector(bytes(32),b'product',b'0',W.N)),64)


if __name__=='__main__':unittest.main(verbosity=2)
