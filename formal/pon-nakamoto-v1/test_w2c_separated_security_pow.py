"""W2-C study: security Hashcash only buys full W1 replay; never chainwork."""
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
        cls.challenge = H('challenge', cls.header)
        cls.a = [0] * W.CELLS
        cls.task = W.task_id(cls.a, cls.a)
        cls.proof = W.prove(cls.challenge, cls.a, cls.a)
        cls.false_proof = (b'PNW1' + W.field_bytes(cls.a) * 3
                           + H('w2c-false-trace', cls.challenge))

    def test_valid_w1_requires_independent_security_work_but_grants_no_chainwork(self):
        ticket, cost = S.search(self.header, self.proof, 8, 65536)
        self.assertIsNotNone(ticket)
        self.assertEqual(cost['status'], 'FOUND')
        result = S.validate(ticket, self.task, 8)
        self.assertEqual(result['outcome'], 'VALID_W1_RESEARCH_ONLY')
        self.assertFalse(result['verified_work'])

    def test_false_w1_passes_security_but_fails_full_original_replay(self):
        ticket, _ = S.search(self.header, self.false_proof, 8, 65536)
        self.assertIsNotNone(ticket)
        result = S.validate(ticket, self.task, 8)
        self.assertEqual(result['outcome'], 'W1_TRANSCRIPT')
        self.assertTrue(result['w1_replayed'])
        self.assertFalse(result['verified_work'])

    def test_bad_security_ticket_cannot_trigger_w1_replay(self):
        real, _ = S.search(self.header, self.false_proof, 8, 65536)
        self.assertIsNotNone(real)
        commitment = S.proposal_digest(self.header, self.false_proof)
        bad = next(i for i in range(200)
                   if not S.qualifies(S.security_ticket(commitment, i), 8))
        with patch.object(W, 'verify', side_effect=AssertionError('W1 must not run')):
            result = S.validate(replace(real, nonce=bad), self.task, 8)
        self.assertEqual(result['outcome'], 'SECURITY_TARGET')
        self.assertFalse(result['w1_replayed'])

    def test_all_exact_bytes_are_committed_before_hash_search(self):
        altered_header = self.header[:-1] + bytes([self.header[-1] ^ 1])
        altered_proof = self.proof[:-1] + bytes([self.proof[-1] ^ 1])
        digest = S.proposal_digest(self.header, self.proof)
        self.assertNotEqual(digest, S.proposal_digest(altered_header, self.proof))
        self.assertNotEqual(digest, S.proposal_digest(self.header, altered_proof))
        self.assertNotEqual(S.security_ticket(digest, 0),
                            S.security_ticket(digest, 1))

    def test_bounded_exhaustion_and_invalid_profile_refuse(self):
        candidate, stats = S.search(self.header, self.proof, 28, 1)
        self.assertEqual(stats['attempted_hashes'], 1)
        self.assertEqual(stats['status'], 'FOUND' if candidate else 'EXHAUSTED')
        for bits in (0, 7, 29):
            with self.assertRaises(ValueError):
                S.search(self.header, self.proof, bits, 1)
        for cap in (0, S.MAX_ATTEMPTS + 1):
            with self.assertRaises(ValueError):
                S.search(self.header, self.proof, 8, cap)


if __name__ == '__main__':
    unittest.main(verbosity=2)
