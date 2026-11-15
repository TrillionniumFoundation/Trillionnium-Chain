"""Negative tests for exact W1 relation witness; never cryptographic proof."""
import hashlib
import unittest
from dataclasses import replace
from contract_wire import H
import work_oracle as W
import w2b_relation_witness as S

class W2BRelationWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.challenge = bytes(range(32))
        cls.a = [i % 97 for i in range(W.CELLS)]
        cls.b = [i % 83 for i in range(W.CELLS)]
        cls.task = W.task_id(cls.a, cls.b)
        cls.target = bytes([255]) * 32
        cls.proof = W.prove(cls.challenge, cls.a, cls.b)
        cls.witness = S.construct(cls.challenge, cls.a, cls.b)

    def test_full_reference_relation_has_no_proof_or_chainwork_authority(self):
        result = S.check_relation(self.challenge, self.task, self.target,
                                  self.proof, self.witness)
        self.assertEqual(result['result'], 'EXACT_W1_RELATION_RESEARCH_ONLY')
        self.assertEqual(result['tile_count'], 512)
        self.assertEqual(result['witness_bytes'], 131072)
        for key in ('succinct_proof', 'cryptographic_proof',
                    'verified_work', 'consensus_chainwork'):
            self.assertIs(result[key], False)

    def test_corrupt_witness_tile_cannot_be_laundered_through_new_digest(self):
        for index in (0, S.WITNESS_BYTES // 2, S.WITNESS_BYTES - 1):
            changed = bytearray(self.witness.trace_tiles)
            changed[index] ^= 1
            trace = hashlib.sha256(b'TRNM-PON-TRACE1\x00' +
                                   self.challenge + changed).digest()
            proof = self.proof[:-32] + trace
            witness = replace(self.witness, trace_tiles=bytes(changed),
                              computed_trace=trace)
            with self.assertRaisesRegex(ValueError, '^WITNESS_ARITHMETIC$'):
                S.check_relation(self.challenge, self.task, self.target, proof, witness)

    def test_changed_product_and_task_reject(self):
        at = 4 + 2 * W.CELLS * 4
        old = int.from_bytes(self.proof[at:at+4], 'little')
        altered = (self.proof[:at] + ((old+1)%W.Q).to_bytes(4,'little')
                   + self.proof[at+4:])
        with self.assertRaisesRegex(ValueError, '^PRODUCT$'):
            S.check_relation(self.challenge, self.task, self.target, altered, self.witness)
        with self.assertRaisesRegex(ValueError, '^TASK$'):
            S.check_relation(self.challenge, H('wrong-task'),
                             self.target, self.proof, self.witness)

    def test_incomplete_witness_and_changed_challenge(self):
        with self.assertRaisesRegex(ValueError, '^WITNESS_LENGTH$'):
            S.check_relation(self.challenge, self.task, self.target, self.proof,
                             replace(self.witness, trace_tiles=self.witness.trace_tiles[:-1]))
        self.assertNotEqual(
            S.statement_id(self.challenge, self.task, self.target, self.proof),
            S.statement_id(bytes([99])*32, self.task, self.target, self.proof))
if __name__ == '__main__':
    unittest.main(verbosity=2)
