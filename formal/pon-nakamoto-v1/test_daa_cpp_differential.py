"""Research-only executable cross-language and malformed-input controls."""
from __future__ import annotations
import hashlib
from pathlib import Path
import tempfile
import unittest
from daa_cpp_differential import (FROZEN_512_SHA, Case, adversarial_cases, compare,
                                  compile_oracle, run_cpp, xorshift_512)


class CppDaaOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.tmp.name) / "daa_cpp_oracle"
        compile_oracle(cls.binary)

    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()

    def test_independent_512_source_bound_digest(self):
        cases = xorshift_512()
        self.assertEqual(len(cases), 512)
        self.assertEqual(compare(self.binary, cases)["mismatches"], 0)
        digest = hashlib.sha256(b"".join(bytes.fromhex(x.python_result()) for x in cases)).hexdigest()
        self.assertEqual(digest, FROZEN_512_SHA)

    def test_2048_adversarial_full_width_valid_and_rejection_cases(self):
        result = compare(self.binary, adversarial_cases())
        self.assertEqual(result["cases"], 2048)
        self.assertGreater(result["rejected_ranges"], 0)
        self.assertGreater(result["rejected_parameters"], 0)
        self.assertGreater(result["accepted"], 0)

    def test_malformed_and_noncanonical_hex_refuse(self):
        c = Case(1<<220,(1<<240)-1,0,20,1,2,10,7200)
        a = c.wire().split(' ')
        lines = [" ", " ".join(a[:-1]), " ".join(a+["99"]),
                 " ".join(["x"+a[0][1:]]+a[1:]),
                 " ".join([a[0],a[1].upper()]+a[2:]),
                 " ".join(a[:3]+["-1"]+a[4:]),
                 " ".join(a[:3]+["18446744073709551616"]+a[4:]),
                 c.wire()]
        out = run_cpp(self.binary, lines)
        self.assertEqual(out[:3], ["ERR_FORMAT"]*3)
        self.assertEqual(out[3:7], ["ERR_PARAMETERS"]*4)
        self.assertEqual(out[7], c.python_result())

    def test_overflow_and_very_short_half_life(self):
        u = (1<<64)-1
        cap = (1<<240)-1
        cases = [Case(1<<220,cap,0,0,1,u,u,1),
                 Case(1<<220,cap,u,0,1,u,1<<62,1),
                 Case(1,cap,0,u,1,2,10,1),
                 Case(1,cap,u,0,1,2,10,1),
                 Case(cap,cap,0,10,1,2,10,7200)]
        self.assertEqual([c.python_result() for c in cases],
                         run_cpp(self.binary,[c.wire() for c in cases]))
        self.assertEqual(cases[0].python_result(), 'ERR_RANGE')
        self.assertEqual(cases[1].python_result(), 'ERR_RANGE')
        self.assertEqual(int(cases[2].python_result(),16),cap)
        self.assertEqual(int(cases[3].python_result(),16),1)

    def test_no_second_system_or_authority(self):
        source = Path(__file__).with_name("daa_cpp_oracle.cpp").read_text()
        self.assertIn("NON-CONSENSUS",source)
        self.assertNotIn("mainnet",source)
        self.assertNotIn("ed25519",source.lower())
        self.assertNotIn("sqlite",source.lower())

    def test_distinct_seed_reproducibility(self):
        self.assertEqual(adversarial_cases(0, 16), adversarial_cases(0, 16))
        self.assertNotEqual(adversarial_cases(0, 16), adversarial_cases(1, 16))
        self.assertEqual(compare(self.binary, adversarial_cases(0, 32))["mismatches"], 0)
        self.assertEqual(compare(self.binary, adversarial_cases(1, 32))["mismatches"], 0)


if __name__ == "__main__": unittest.main()
