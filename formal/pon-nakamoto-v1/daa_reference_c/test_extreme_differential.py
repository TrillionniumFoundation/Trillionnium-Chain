#!/usr/bin/env python3
"""Deterministic original-byte C/GMP vs Python full-range ASERT differential; research only.
Neither implementation verifies native W1 or activates a consensus rule.
"""
from __future__ import annotations
from pathlib import Path
import tempfile
import hashlib
import json
import random
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from daa_research_oracle import asert_target, UINT64_MAX, UINT256_MAX
C_SOURCE = Path(__file__).with_name('target.c')
BINARY = None
SEED = 0x20261027
R = random.Random(SEED)
LIMITS = [1, 2, 0xffff, 1 << 128, (1 << 240) - 1, UINT256_MAX]
U64_CASES = [0, 1, 2, 10, 100, 65535, (1 << 32) - 1, (1 << 63) - 1, UINT64_MAX - 1, UINT64_MAX]
HEIGHTS = [1, 2, 15, 16, 100, 1000, 100000, UINT64_MAX - 1]
HALVES = [1, 2, 10, 3600, 7200, 14400, 28800, (1 << 63), UINT64_MAX]
SPACINGS = [1, 2, 10, 600, 3600, UINT64_MAX]

def draw(seq):
    return seq[R.randrange(len(seq))] if R.randrange(3) else R.randrange(UINT64_MAX + 1)

def one_case(i):
    limit = draw(LIMITS)
    if i % 5 == 0:
        limit = R.randrange(1, UINT256_MAX + 1)
    if i % 3 == 0:
        anchor = R.randrange(1, limit + 1)
    else:
        anchor = draw((1, min(limit, (1 << 220)), limit))
    anchor_height = draw(HEIGHTS)
    if anchor_height == 0 or anchor_height == UINT64_MAX:
        anchor_height = 1
    gap = draw([1, 2, 16, 256, 1000, UINT64_MAX - anchor_height])
    gap = max(1, min(gap, UINT64_MAX - anchor_height))
    cand = anchor_height + gap
    at = draw(U64_CASES)
    pt = draw(U64_CASES)
    spacing = draw(SPACINGS)
    half = draw(HALVES)
    return anchor, at, pt, anchor_height, cand, spacing, half, limit

def main(count=4096):
    global BINARY
    # Build the exact local C/GMP owner, never fetch remote binaries.
    with tempfile.TemporaryDirectory(prefix='trnm-asert-c-') as temp:
        BINARY = Path(temp) / 'asert-c'
        subprocess.run(['gcc', '-O2', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        str(C_SOURCE), '-lgmp', '-o', str(BINARY)],
                       check=True, capture_output=True, timeout=90)
        return _compare(count)

def _compare(count):
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    capture = hashlib.sha256()
    accepted = refused = 0
    mismatch = []
    for i in range(count):
        vals = one_case(i)
        args = [str(BINARY), f'{vals[0]:064x}'] + [str(x) for x in vals[1:7]] + [f'{vals[7]:064x}']
        run = subprocess.run(args, capture_output=True, text=True, timeout=2, check=False)
        try:
            py = asert_target(*vals)
            py_ok = True
        except ValueError as e:
            py_ok = False
            py = str(e)
        c_ok = run.returncode == 0
        if py_ok != c_ok or (py_ok and py != int(run.stdout.strip(), 16)):
            mismatch.append({'i':i,'input':list(map(str,vals)),'py':str(py),'c_rc':run.returncode,'c_stdout':run.stdout,'c_stderr':run.stderr})
        if py_ok: accepted += 1
        else: refused += 1
        capture.update(bytes.fromhex(f'{i:08x}'))
        for v in vals:
            capture.update(v.to_bytes(32, 'big'))
        capture.update(b'ACCEPTED' if py_ok else b'REJECTED')
        if py_ok:
            capture.update(py.to_bytes(32,'big'))
        if len(mismatch) >= 5: break
    report = {'schema':'trnm-daa-asert-c-python-extreme-differential-local-v1',
              'test_seed':SEED, 'cases_attempted':accepted+refused,
              'accepted':accepted, 'expected_refusals':refused,
              'mismatches':mismatch, 'result_digest':capture.hexdigest(),
              'input_source_python_sha256':sha(ROOT/'daa_research_oracle.py'),
              'input_source_c_sha256':sha(C_SOURCE),
              'binary_sha256':sha(BINARY), 'scope':'same-owner local C/GMP versus Python; no native Rust/W1/WAN/PoW hardness'}
    print(json.dumps(report,sort_keys=True))
    if mismatch: sys.exit(1)

if __name__=='__main__': main()
