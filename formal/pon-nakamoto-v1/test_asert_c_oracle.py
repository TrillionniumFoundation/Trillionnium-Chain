"""Independent C ASERT research oracle vs frozen Go/Python results.

NO activated consensus, native W1 work, network or mining qualification.
Run with GCC/Clang C11: python3 -m unittest -v test_asert_c_oracle
"""
import hashlib
import os
import random
import subprocess
import tempfile
import unittest
from pathlib import Path
from daa_research_oracle import asert_target

ROOT = Path(__file__).resolve().parent
MAX = (1 << 64) - 1
ANCHOR = 1 << 220
LIMIT = (1 << 240) - 1
FROZEN_GO_SHA256 = '6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97'


def frozen_cases():
    state = 0x62b7f30ac9851d4e
    def next_word():
        nonlocal state
        state ^= (state << 13) & MAX
        state ^= state >> 7
        state ^= (state << 17) & MAX
        state &= MAX
        return state
    for i in range(512):
        height = 2 + next_word() % 1000
        anchor_time = 1_000_000 + next_word() % 100_000
        deviation = next_word() % 100_000 - 50_000
        parent = anchor_time + (height - 1) * 10 + deviation
        if i % 17 == 0:
            parent = MAX
        if i % 19 == 0:
            parent = 0
        half_life = (3600, 7200, 14400, 28800, 1)[i % 5]
        yield (ANCHOR, LIMIT, anchor_time, parent, 1, height, 10, half_life)


class IndependentCOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='pon-asert-c-')
        cls.binary = Path(cls.directory.name) / 'asert-oracle-c'
        source = ROOT / 'daa_reference_c' / 'main.c'
        cls.compilation = subprocess.run(
            [os.environ.get('CC', 'cc'), '-std=gnu11', '-O2', '-Wall',
             '-Wextra', '-Wconversion', '-Werror', '-o', str(cls.binary), str(source)],
            capture_output=True, text=True, timeout=60, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def native(self, x):
        anchor, cap, at, pt, ah, height, spacing, half = x
        keys = ('--anchor', '--limit', '--anchor-parent-time', '--parent-time',
                '--anchor-height', '--height', '--spacing', '--half-life')
        values = (f'{anchor:064x}', f'{cap:064x}', *(str(value) for value in x[2:]))
        argv = [str(self.binary), *(v for pair in zip(keys, values) for v in pair)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            self.assertEqual(len(result.stdout.strip()), 64)
            self.assertEqual(result.stderr, '')
            return int(result.stdout.strip(), 16), None
        self.assertEqual(result.returncode, 2)
        return None, result.stderr.strip()

    @staticmethod
    def expected(x):
        try:
            return asert_target(x[0], x[2], x[3], x[4], x[5], x[6], x[7], x[1]), None
        except ValueError as error:
            kind = ('ASERT_RESEARCH_RANGE' if 'overflows i128' in str(error)
                    else 'ASERT_RESEARCH_PARAMETERS')
            return None, kind

    def test_frozen_512_case_go_hash_and_python_values(self):
        digest = hashlib.sha256()
        for case in frozen_cases():
            output = self.native(case)
            self.assertEqual(output, self.expected(case), case)
            self.assertIsNone(output[1])
            digest.update(output[0].to_bytes(32, 'big'))
        self.assertEqual(digest.hexdigest(), FROZEN_GO_SHA256)

    def test_full_width_random_and_i128_overflow_refusals(self):
        rng = random.Random(20261026)
        caps = ((1 << 256) - 1, (1 << 240) - 1, 1 << 255, 1 << 128)
        for i in range(1500):
            cap = rng.choice(caps)
            anchor = min(rng.choice((1, 1 << 220, cap, rng.randint(1, cap))), cap)
            at = rng.choice((0, 1_000_000, MAX, rng.getrandbits(64)))
            pt = rng.choice((0, 1_000_000, MAX, rng.getrandbits(64)))
            ah = rng.choice((1, 50, MAX - 100, 1000))
            height = min(MAX, ah + rng.choice((1, 2, 999, 1_000_000)))
            spacing = rng.choice((1, 10, 600, MAX))
            if i % 13 == 0:
                ah, height, spacing = 1, MAX, MAX
            elif i % 17 == 0:
                ah, height, spacing = 1, MAX, 1 << 62
            half = (1, 2, 3600, 7200, 14400, 28800, MAX)[i % 7]
            case = (anchor, cap, at, pt, ah, height, spacing, half)
            self.assertEqual(self.native(case), self.expected(case), case)

    def test_invalid_parameters_refuse(self):
        cases = (
            (0, LIMIT, 0, 1, 1, 2, 10, 1),
            (2, 1, 0, 1, 1, 2, 10, 1),
            (1, LIMIT, 0, 1, 0, 2, 10, 1),
            (1, LIMIT, 0, 1, 1, 1, 10, 1),
            (1, LIMIT, 0, 1, 1, 2, 0, 1),
            (1, LIMIT, 0, 1, 1, 2, 10, 0),
            (1, LIMIT, MAX, 0, 1, MAX, MAX, 1),
        )
        for case in cases:
            self.assertEqual(self.native(case), self.expected(case), case)


if __name__ == '__main__':
    unittest.main(verbosity=2)
