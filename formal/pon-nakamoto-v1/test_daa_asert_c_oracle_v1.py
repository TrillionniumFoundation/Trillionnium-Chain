"""Same-vector C/Python ASERT research regression; no native Rust consensus authority."""
from __future__ import annotations

import hashlib
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest

from daa_research_oracle import asert_target, UINT64_MAX, UINT256_MAX

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'daa_asert_c_oracle_v1.c'


def case_to_line(values):
    target, at, pt, ah, ch, spacing, half_life, pow_limit = values
    return (f'{target:064x} {pow_limit:064x} {at} {pt} '
            f'{ah} {ch} {spacing} {half_life}\n')


def expected(values):
    try:
        return f'{asert_target(*values):064x}'
    except ValueError:
        return 'ERR'


class COracleDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('cc')
        if compiler is None:
            raise AssertionError('native C compiler required for cross-language qualification')
        cls.tmp = tempfile.TemporaryDirectory(prefix='trnm-c-asert-')
        cls.binary = Path(cls.tmp.name) / 'asert-oracle'
        built = subprocess.run(
            [compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
             str(SOURCE), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=45, check=False)
        if built.returncode:
            raise AssertionError('C verifier did not compile: ' + built.stderr)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'tmp'):
            cls.tmp.cleanup()

    def verify(self, cases):
        wire = ''.join(case_to_line(case) for case in cases)
        proc = subprocess.run([str(self.binary)], input=wire, text=True,
                              capture_output=True, timeout=30, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        outputs = proc.stdout.splitlines()
        self.assertEqual(len(outputs), len(cases), 'C must account for every input')
        for index, (case, result) in enumerate(zip(cases, outputs)):
            self.assertEqual(result, expected(case), f'C/Python disagreement case {index}: {case}')
        return hashlib.sha256(('\n'.join(outputs) + '\n').encode()).hexdigest()

    def test_freeze_small_extreme_boundary_grid(self):
        max_u, max_t = UINT64_MAX, UINT256_MAX
        cases = []
        target_limit = [(1<<255)-1, max_t, (1<<65)-1, 1]
        for limit in target_limit:
            for target in (1, max(1,limit//2), limit):
                for at, pt in ((0,0), (0,max_u),(max_u,0), (1,2),(max_u,max_u)):
                    for half in (1,2,3600,7200,max_u):
                        cases.append((target,at,pt,1,2,10,half,limit))
        self.assertEqual(len(cases),300)
        self.assertEqual(self.verify(cases),
                         '2f2eee7b3540d91aa7857718975dfd04dbbcdbf5ecb49c265a85d680dd18d0fa')

    def test_exact_4096_deterministic_multiwidth_cases(self):
        rng = random.Random(20261026)
        cases = []
        limits = [UINT256_MAX, (1 << 255)-1, (1<<191)-1, (1<<127)-1, (1<<64)-1]
        temporal = [0, 1, 2, 120, 2**32, 2**48, UINT64_MAX-1, UINT64_MAX]
        spans = [1,10,16,100,600,3600,7200,86400,2**32, UINT64_MAX]
        for index in range(4096):
            limit = limits[index%len(limits)]
            width = 1+(index*43)%256
            target = max(1, min(limit,rng.getrandbits(width)))
            at = temporal[(index//5)%len(temporal)]
            pt = temporal[(index//7)%len(temporal)] if index % 9 < 5 else rng.getrandbits(64)
            ah = rng.randint(1,2**64-2)
            ch = min(UINT64_MAX,ah+rng.randint(1,1<<20))
            spacing = spans[(index//11)%len(spans)]
            half = spans[(index//17)%len(spans)]
            cases.append((target,at,pt,ah,ch,spacing,half,limit))
        self.assertEqual(len(cases),4096)
        self.assertEqual(self.verify(cases),
                         '01db959e9b902100257d873f6ee467bcad937a53a0738f2ad79650fdb45d636b')

    def test_invalid_parameters_reject_in_both_languages(self):
        target=1000
        base=(target, 100, 200, 1, 10, 10, 7200, (1<<255)-1)
        bad=[]
        for i, value in [(0,0),(3,0),(4,1),(5,0),(6,0),(7,0),
                         (1,-1),(2,-1),(1,UINT64_MAX+1),(2,UINT64_MAX+1),
                         (3,UINT64_MAX+1),(4,UINT64_MAX+1),
                         (0,UINT256_MAX+1),(7,UINT256_MAX+1)]:
            x=list(base);x[i]=value;bad.append(tuple(x))
        # The C command uses unsigned decimal and fixed 64-byte hex, so negative
        # input encodings and too-wide targets are syntactically refused.
        self.verify(bad)
        self.verify([(1000, UINT64_MAX, 0, 1, UINT64_MAX, UINT64_MAX, 1, (1<<255)-1)])

    def test_metamorphic_equal_parent_offset(self):
        # Since both observed times shift identically, the relative ASERT
        # exponent is unchanged as long as uint64 bounds are respected.
        base = (1 << 200, 10000, 10020, 25, 29, 10, 7200, (1 << 255)-1)
        same = (base[0], base[1]+123456789,base[2]+123456789,*base[3:])
        self.assertEqual(expected(base),expected(same))
        self.verify([base,same])


if __name__ == '__main__':
    unittest.main()
