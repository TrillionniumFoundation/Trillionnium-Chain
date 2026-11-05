#!/usr/bin/env python3
"""Pure reference controls for P2 CPU-only search, not native cost acceptance."""
import struct
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / 'scripts'))
sys.path.insert(0, str(root / 'formal/pon-nakamoto-v1'))
import pon_v3_cookie_cpu_study as study
from contract_wire import H


class CookieCpuStudyTests(unittest.TestCase):
    def test_ticket_math_matches_native_big_endian_leading_zero_rule(self):
        cookie = H('test-cookie')
        for bits in (8, 12, 16, 20):
            for nonce in (0, 1, 2, 5, 8, 21, 250):
                digest = H('public-ticket-v3', cookie, struct.pack('<Q', nonce))
                expected = int.from_bytes(digest[:4], 'big') >> (32 - bits) == 0
                self.assertEqual(study.attempt(cookie, nonce, bits), expected)

    def test_capped_result_is_never_fabricated_as_a_winner(self):
        row = study.sample(20, 1, 1)
        self.assertEqual(row['attempts'], 1)
        self.assertEqual(row['status'],
                         'WINNER' if row['winning_nonce'] == 0 else 'CAPPED')
        self.assertGreaterEqual(row['calling_process_cpu_ns'], 0)

    def test_input_beyond_development_policy_is_rejected(self):
        for bits in (0, 7, 21, 256):
            with self.assertRaises(ValueError):
                study.attempt(bytes(32), 0, bits)


if __name__ == '__main__':
    unittest.main(verbosity=2)
