#!/usr/bin/env python3
"""Optional exact W1 NumPy CPU prover; not mining hardness or PQ qualification.

Implements all 512 cumulative transcript tiles and a true product for any
legal input using modular products reduced BEFORE addition. No consensus change.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import work_oracle as w1

try:
    import numpy as np
except ImportError:
    np = None


def _matrix(values: list[int], rows: int, columns: int):
    return np.asarray(values, dtype=np.uint64).reshape((rows, columns))


def _mul_mod(left, right):
    """Accumulate modulo q per multiply; uint64 dot would overflow."""
    if left.shape[1] != right.shape[0]:
        raise ValueError("W1_MATRIX_SHAPE")
    result = np.zeros((left.shape[0], right.shape[1]), dtype=np.uint64)
    for k in range(left.shape[1]):
        term = (left[:, k, None] * right[k, None, :]) % w1.Q
        result = (result + term) % w1.Q
    return result


def prove(challenge: bytes, a: list[int], b: list[int]) -> bytes:
    if np is None:
        raise RuntimeError("optional NumPy dependency required; no solver ran")
    if type(challenge) is not bytes or len(challenge) != 32:
        raise ValueError("W1_CHALLENGE")
    w1.check(a)
    w1.check(b)
    n, r, q = w1.N, w1.R, w1.Q
    a_matrix = _matrix(a, n, n)
    b_matrix = _matrix(b, n, n)
    noise = [
        _matrix(w1.expand(challenge, label, n * r), *shape)
        for label, shape in enumerate(((n, r), (r, n), (n, r), (r, n)))
    ]
    aa = (a_matrix + _mul_mod(noise[0], noise[1])) % q
    bb = (b_matrix + _mul_mod(noise[2], noise[3])) % q
    cumulative = np.zeros((n, n), dtype=np.uint64)
    trace = hashlib.sha256(b"TRNM-PON-TRACE1\0" + challenge)
    for i0 in range(0, n, r):
        for j0 in range(0, n, r):
            for k0 in range(0, n, r):
                contribution = _mul_mod(
                    aa[i0:i0 + r, k0:k0 + r],
                    bb[k0:k0 + r, j0:j0 + r],
                )
                tile = cumulative[i0:i0 + r, j0:j0 + r]
                tile[:] = (tile + contribution) % q
                trace.update(tile.astype("<u4", copy=False).tobytes(order="C"))
    product = _mul_mod(a_matrix, b_matrix)
    return (b"PNW1" + w1.field_bytes(a) + w1.field_bytes(b)
            + product.astype("<u4", copy=False).tobytes(order="C")
            + trace.digest())
