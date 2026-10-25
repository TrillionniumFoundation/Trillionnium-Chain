"""Frozen, non-authoritative W2 research vectors for third implementation work."""
import hashlib
import json
from pathlib import Path
import unittest

from contract_wire import H
import work_oracle as W
import w2a_merkle_sampling as A
import w2b_relation_witness as B
import w2c_separated_security_pow as C


def digest(value):
    return hashlib.sha256(value).hexdigest()


class W2IndependentImplementationInputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(
            Path(__file__).with_name('w2_research_vectors_v0.json').read_text())
        assert cls.fixture['schema'] == 'trnm-w2-research-vectors-v0'
        assert cls.fixture['authority'] == 'none'

    def test_w2a_and_w2b_full_transcript_public_vectors(self):
        expected = self.fixture['w2b']
        challenge = bytes.fromhex(expected['challenge_hex'])
        a = [i % 97 for i in range(W.CELLS)]
        b = [i % 83 for i in range(W.CELLS)]
        task = W.task_id(a, b)
        target = bytes.fromhex(expected['target_hex'])
        proof = W.prove(challenge, a, b)
        witness = B.construct(challenge, a, b)
        sidecar = A.make_sidecar(challenge, a, b, 8)
        self.assertEqual(task.hex(), expected['task_hex'])
        self.assertEqual(digest(proof), expected['w1_proof_sha256'])
        self.assertEqual(witness.computed_trace.hex(), expected['w1_trace_hex'])
        self.assertEqual(digest(witness.computed_product),
                         expected['w1_product_sha256'])
        self.assertEqual(digest(witness.trace_tiles),
                         expected['tile_witness_sha256'])
        self.assertEqual(len(witness.trace_tiles),
                         expected['tile_witness_bytes'])
        self.assertEqual(sidecar.root.hex(), expected['w2a_merkle_root_hex'])
        self.assertEqual(B.statement_id(challenge,task,target,proof).hex(),
                         expected['w2b_statement_hex'])
        result = B.check_relation(challenge,task,target,proof,witness)
        self.assertFalse(result['cryptographic_proof'])

    def test_w2c_fake_proof_security_hash_vectors(self):
        expected = self.fixture['w2c']
        header = H('w2c-research-header',b'A')*9+bytes(30)
        challenge = H('challenge',header)
        zeros = [0]*W.CELLS
        proof = b'PNW1'+W.field_bytes(zeros)*3+H('w2c-false-trace',challenge)
        commitment = C.proposal_digest(header,proof)
        self.assertEqual(digest(header),expected['header_sha256'])
        self.assertEqual(digest(proof),expected['fake_proof_sha256'])
        self.assertEqual(commitment.hex(),expected['proposal_hex'])
        self.assertEqual(C.security_ticket(commitment,0).hex(),
                         expected['security_ticket_nonce0_hex'])
        self.assertEqual(C.security_ticket(commitment,1).hex(),
                         expected['security_ticket_nonce1_hex'])
        self.assertEqual(C.qualifies(C.security_ticket(commitment,0),8),
                         expected['bits8_nonce0_hit'])
        self.assertEqual(len(proof),expected['w1_proof_bytes'])


if __name__=='__main__':
    unittest.main(verbosity=2)
