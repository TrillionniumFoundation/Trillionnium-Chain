"""W2-D attack oracle: tested math, NOT independent cryptographic acceptance."""
import hashlib
import struct
import unittest
from dataclasses import replace
from contract_wire import H
import work_oracle as W
import w2d_transcript_freivalds as D

class W2DResearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = H('pinned-w2d-challenge')
        cls.a = [0]*W.CELLS
        cls.b = cls.a.copy()
        cls.task = W.task_id(cls.a,cls.b)
        cls.target = bytes([255])*32
        cls.candidate = D.produce(cls.c,cls.a,cls.b)

    def call(self, candidate, rounds=3):
        return D.verify(self.c,self.task,self.target,
                        candidate.proof,candidate.sidecar,rounds)

    def test_complete_valid_w1_proof_matches_existing_independent_scalar_oracle(self):
        self.assertEqual(self.candidate.proof,W.prove(self.c,self.a,self.b))
        self.assertEqual(len(self.candidate.proof),W.PROOF_BYTES)
        self.assertEqual(len(self.candidate.sidecar),D.SIDECAR_BYTES)
        result=self.call(self.candidate)
        self.assertFalse(result['verified_work'])
        self.assertEqual(result['chainwork'],0)
        self.assertEqual(result['rounds'],3)
        self.assertFalse(result['consensus_activated'])

    def test_dense_nonzero_a_b_c_proof_still_matches_full_w1(self):
        a=[i%31 for i in range(W.CELLS)]
        b=[i%17 for i in range(W.CELLS)]
        c=H('w2d-dense-independent')
        candidate=D.produce(c,a,b)
        self.assertEqual(candidate.proof,W.prove(c,a,b))
        result=D.verify(c,W.task_id(a,b),self.target,candidate.proof,candidate.sidecar)
        self.assertEqual(result['outcome'],'RESEARCH_PROBABILISTIC_RELATION_CHECKED')
        self.assertFalse(result['verified_work'])

    def test_single_tampered_tile_with_recomputed_trace_is_rejected(self):
        forged=bytearray(self.candidate.sidecar)
        first=4+4*17  # one intermediate word inside tile stream
        old=struct.unpack_from('<I',forged,first)[0]
        struct.pack_into('<I',forged,first,(old+1)%W.Q)
        trace=hashlib.sha256(b'TRNM-PON-TRACE1\0'+self.c+forged[4:]).digest()
        proof=self.candidate.proof[:-32]+trace
        with self.assertRaisesRegex(ValueError,'^PREFIX$'):
            self.call(D.Candidate(proof,bytes(forged)))

    def test_forged_all_zero_tape_even_with_matching_sha_ticket_is_rejected(self):
        forged=D.MAGIC+bytes(D.TAPE_BYTES)
        trace=hashlib.sha256(b'TRNM-PON-TRACE1\0'+self.c+forged[4:]).digest()
        proof=self.candidate.proof[:-32]+trace
        W.precheck(self.c,self.task,self.target,proof)
        with self.assertRaisesRegex(ValueError,'^PREFIX$'):
            self.call(D.Candidate(proof,forged))

    def test_claimed_product_mismatch_is_rejected_independently(self):
        proof=bytearray(self.candidate.proof)
        off=4+2*W.CELLS*4
        value=struct.unpack_from('<I',proof,off)[0]
        struct.pack_into('<I',proof,off,(value+1)%W.Q)
        with self.assertRaisesRegex(ValueError,'^PRODUCT$'):
            self.call(D.Candidate(bytes(proof),self.candidate.sidecar))

    def test_wrong_trace_digest_rejected_before_arithmetic_projection(self):
        proof=self.candidate.proof[:-32]+H('fake-trace-digest')
        with self.assertRaisesRegex(ValueError,'^TRACE_BIND$'):
            self.call(D.Candidate(proof,self.candidate.sidecar))

    def test_encoding_and_source_task_guards(self):
        for sidecar,reason in [(self.candidate.sidecar[:-1],'TAPE_LENGTH'),
                               (b'X'+self.candidate.sidecar[1:],'TAPE_VERSION')]:
            with self.assertRaisesRegex(ValueError,reason):
                self.call(D.Candidate(self.candidate.proof,sidecar))
        wrong=bytearray(self.candidate.sidecar)
        struct.pack_into('<I',wrong,4,W.Q)
        with self.assertRaisesRegex(ValueError,'^TAPE_FIELD$'):
            self.call(D.Candidate(self.candidate.proof,bytes(wrong)))
        with self.assertRaisesRegex(ValueError,'^TASK$'):
            D.verify(self.c,H('wrong-task'),self.target,
                     self.candidate.proof,self.candidate.sidecar)
        for rounds in (0,1,6):
            with self.assertRaisesRegex(ValueError,'ROUNDS'):
                self.call(self.candidate,rounds)

    def test_fiat_shamir_vectors_are_domain_and_round_separated(self):
        statement=H('test-w2d-statement')
        a=D.field_vector(statement,b'prefix',0)
        b=D.field_vector(statement,b'prefix',1)
        c=D.field_vector(statement,b'product',0)
        self.assertEqual(len(a),W.N)
        self.assertTrue(all(0<=x<W.Q for x in a))
        self.assertNotEqual(a,b)
        self.assertNotEqual(a,c)
        self.assertEqual(a,D.field_vector(statement,b'prefix',0))

if __name__=='__main__':unittest.main(verbosity=2)
