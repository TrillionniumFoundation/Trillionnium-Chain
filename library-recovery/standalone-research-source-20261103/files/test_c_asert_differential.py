"""Local Go-frozen fixture parity, C sanitizer, range/refusal and random differential.
Independent C research implementation; no W1 or consensus activation.
"""
import hashlib
import importlib.util
import random
import subprocess
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('branch_oracle', HERE/'daa_research_oracle_branch.py')
oracle = importlib.util.module_from_spec(spec)
import sys
sys.modules['branch_oracle'] = oracle
spec.loader.exec_module(oracle)
BINARY = HERE/'asert_independent'
MAX = (1<<64)-1
LIMIT=(1<<240)-1
ANCHOR=1<<220
FROZEN_GO='6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97'


def native(x):
    anchor, cap, anchor_time, parent_time, anchor_h, height, spacing, half = x
    names=['--anchor','--limit','--anchor-parent-time','--parent-time',
           '--anchor-height','--height','--spacing','--half-life']
    values=[f'{anchor:064x}',f'{cap:064x}',*(str(i) for i in x[2:])]
    r=subprocess.run([str(BINARY),*(s for p in zip(names,values) for s in p)],
                     capture_output=True,text=True,timeout=2)
    if r.returncode == 0:
        assert len(r.stdout.strip())==64 and not r.stderr
        return int(r.stdout.strip(),16), None
    return None, r.stderr.strip()


def expected(x):
    try:
        return oracle.asert_target(x[0],x[2],x[3],x[4],x[5],x[6],x[7],x[1]),None
    except ValueError as e:
        return None,('ASERT_RESEARCH_RANGE' if 'overflows i128' in str(e) else 'ASERT_RESEARCH_PARAMETERS')


def frozen_cases():
    state=0x62b7f30ac9851d4e
    def nxt():
        nonlocal state
        state ^= (state << 13)&MAX
        state ^= state >> 7
        state ^= (state << 17)&MAX
        state &= MAX
        return state
    for i in range(512):
        height=2+nxt()%1000
        anchor_time=1_000_000+nxt()%100_000
        deviation=nxt()%100_000-50_000
        parent=anchor_time+(height-1)*10+deviation
        if i%17==0: parent=MAX
        if i%19==0: parent=0
        half=(3600,7200,14400,28800,1)[i%5]
        yield (ANCHOR,LIMIT,anchor_time,parent,1,height,10,half)


class IndependentC(unittest.TestCase):
    def test_512_go_frozen(self):
        digest=hashlib.sha256()
        for case in frozen_cases():
            got,err=native(case)
            self.assertIsNone(err, case)
            want,_=expected(case)
            self.assertEqual(got,want,case)
            digest.update(got.to_bytes(32,'big'))
        self.assertEqual(digest.hexdigest(),FROZEN_GO)

    def test_random_full_width_and_extreme_time(self):
        r=random.Random(20261026)
        caps=[(1<<256)-1, (1<<240)-1, 1<<255, 1<<128]
        for i in range(1500):
            cap=r.choice(caps)
            a=r.choice([1,1<<220,cap,r.randint(1,cap)])
            a=min(a,cap)
            at=r.choice([0,1_000_000,MAX,r.getrandbits(64)])
            pt=r.choice([0,1_000_000,MAX,r.getrandbits(64)])
            ah=r.choice([1,50,MAX-100,1000])
            height=min(MAX,ah+r.choice([1,2,999,1_000_000]))
            spacing=r.choice([1,10,600,MAX])
            if i%13==0: ah,height,spacing=1,MAX,MAX
            elif i%17==0:ah,height,spacing=1,MAX,1<<62
            half=(1,2,3600,7200,14400,28800,MAX)[i%7]
            x=(a,cap,at,pt,ah,height,spacing,half)
            self.assertEqual(native(x),expected(x),x)

    def test_invalid_scalar_domain(self):
        cases=[
            (0,LIMIT,0,1,1,2,10,1),
            (2,1,0,1,1,2,10,1),
            (1,LIMIT,0,1,0,2,10,1),
            (1,LIMIT,0,1,1,1,10,1),
            (1,LIMIT,0,1,1,2,0,1),
            (1,LIMIT,0,1,1,2,10,0),
            (1,LIMIT,MAX,0,1,MAX,MAX,1),
        ]
        for x in cases:
            self.assertEqual(native(x),expected(x),x)

if __name__=='__main__':unittest.main(verbosity=2)
