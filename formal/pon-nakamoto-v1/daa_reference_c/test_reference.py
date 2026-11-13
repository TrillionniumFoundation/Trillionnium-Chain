"""Opt-in third-language exact target differential; research only, requires gcc/GMP.

Neither independently administered security review nor actual native Rust/W1 admission.
"""
from __future__ import annotations
import random
import subprocess
import tempfile
import unittest
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from daa_research_oracle import asert_target, UINT64_MAX, UINT256_MAX

class CReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.directory.name) / 'asert_c'
        command = ['gcc', '-O2', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                   str(HERE/'target.c'), '-lgmp', '-o', str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(f'C compilation failed: {result.stderr}')

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_c(self, parameters):
        anchor, anchor_time, parent_time, ah, ch, spacing, half, limit = parameters
        args = [f'{anchor:064x}', str(anchor_time), str(parent_time), str(ah),
                str(ch), str(spacing), str(half), f'{limit:064x}']
        return subprocess.run([str(self.binary), *args], text=True,
                              capture_output=True, timeout=3)

    def test_frozen_512_adversarial_integer_vectors(self):
        rng = random.Random(20261027)
        halves = [1, 2, 10, 600, 3600, 7200, 14400, UINT64_MAX]
        anchors = [1, 2, UINT256_MAX >> 2, UINT256_MAX >> 1, UINT256_MAX]
        timestamps = [0, 1, 1_750_000_000, UINT64_MAX-1, UINT64_MAX]
        accepted = rejected = 0
        for i in range(512):
            a = anchors[i % len(anchors)] if i % 2 else rng.randrange(1, 1 << 256)
            maximum = max(a, rng.randrange(1, 1 << 256))
            t0 = timestamps[i % 5] if i % 3 else rng.randrange(0, 1 << 64)
            t1 = timestamps[(i + 1) % 5] if i % 7 else rng.randrange(0, 1 << 64)
            ah = rng.randrange(1, 1 << 64)
            ch = min(UINT64_MAX, ah + rng.choice([1, 2, 16, 1024, 1000000, UINT64_MAX]))
            if i % 31 == 0:
                ch = ah # strict rejection control
            spacing = rng.choice([1, 10, 1 << 32, UINT64_MAX])
            half = halves[i % len(halves)]
            args = (a, t0, t1, ah, ch, spacing, half, maximum)
            observed = self.run_c(args)
            try:
                expected = asert_target(*args)
            except ValueError:
                self.assertEqual(observed.returncode, 2, f'case {i}: {observed.stdout}')
                rejected += 1
            else:
                self.assertEqual(observed.returncode, 0, f'case {i}: {observed.stderr}')
                self.assertEqual(int(observed.stdout.strip(), 16), expected, f'case {i}')
                accepted += 1
        self.assertGreater(accepted, 100)
        self.assertGreater(rejected, 0)
        print(f'C reference 512 cases: accepted={accepted}, rejected={rejected}', flush=True)

    def test_fixed_target_legacy_unmodified(self):
        args=(1, 100, 110, 16, 17, 10, 7200, UINT256_MAX)
        observed=self.run_c(args)
        self.assertEqual(observed.returncode, 0)
        self.assertEqual(int(observed.stdout.strip(),16), asert_target(*args))

    def test_public_invalid_ranges(self):
        good=(1, 100, 110, 16, 17, 10, 7200, UINT256_MAX)
        for index, value in [(0,0), (3,0), (4,16), (5,0), (6,0), (7,0)]:
            bad=list(good); bad[index]=value
            self.assertEqual(self.run_c(tuple(bad)).returncode,2)

if __name__ == '__main__': unittest.main(verbosity=2)
