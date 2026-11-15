"""Research-only independent negative controls; a passing sample never accepts a block."""
import unittest
from dataclasses import replace
import w2a_merkle_sampling as S
import work_oracle as W


class W2ASamplingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c=bytes(range(32))
        cls.a=[i%97 for i in range(W.CELLS)]
        cls.b=[i%83 for i in range(W.CELLS)]
        cls.sidecar=S.make_sidecar(cls.c,cls.a,cls.b,8)

    def test_valid_same_transcript_reference(self):
        product, trace = W.evaluate(self.c,self.a,self.b)
        self.assertEqual(self.sidecar.reference_trace,trace)
        self.assertEqual(len(product),W.CELLS)
        self.assertTrue(S.verify_sidecar(self.c,self.a,self.b,self.sidecar,8))

    def test_merkle_tampering_is_rejected(self):
        op=self.sidecar.openings[0]
        forged=replace(op,raw=b'\0'*S.LEAF_BYTES)
        fake=replace(self.sidecar,openings=(forged,)+self.sidecar.openings[1:])
        self.assertFalse(S.verify_sidecar(self.c,self.a,self.b,fake,8))
        fake_order=replace(self.sidecar,openings=self.sidecar.openings[::-1])
        self.assertFalse(S.verify_sidecar(self.c,self.a,self.b,fake_order,8))
        changed_sibling=bytes([op.siblings[0][0]^1])+op.siblings[0][1:]
        altered=replace(op,siblings=(changed_sibling,)+op.siblings[1:])
        fake=replace(self.sidecar,openings=(altered,)+self.sidecar.openings[1:])
        self.assertFalse(S.verify_sidecar(self.c,self.a,self.b,fake,8))

    def test_single_false_tile_escapes_sampling(self):
        bad,sidecar=S.corrupted_sidecar(self.c,self.a,self.b,8)
        indices=S.sampled_indices(self.c,W.task_id(self.a,self.b),sidecar.root,8)
        self.assertNotIn(bad,indices)
        self.assertTrue(S.verify_sidecar(self.c,self.a,self.b,sidecar,8))
        self.assertNotEqual(sidecar.root,self.sidecar.root)
        # Passing does NOT establish original W1 trace or its canonical product.

    def test_changed_task_and_challenge_refuse(self):
        a=self.a.copy();a[0]+=1
        self.assertFalse(S.verify_sidecar(self.c,a,self.b,self.sidecar,8))
        self.assertFalse(S.verify_sidecar(bytes([71])*32,self.a,self.b,self.sidecar,8))

    def test_candidate_cost_report_never_claims_consensus_validity(self):
        rows=S.comparison(self.c,self.a,self.b,(1,4,16))
        self.assertEqual([r['count'] for r in rows],[1,4,16])
        self.assertTrue(all(not r['complete_consensus_validity'] for r in rows))
        self.assertTrue(all(r['unsampled_corruption_accepted_by_filter'] for r in rows))


if __name__=='__main__':unittest.main(verbosity=2)
