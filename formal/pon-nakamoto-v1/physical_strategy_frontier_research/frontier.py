#!/usr/bin/env python3
"""Legal selected-event arithmetic strategies; no physical-work lower claim.

The upstream relation is byte-frozen. These producers only choose how to
compute its unchanged useful local product. All checks use exact F_q values.
"""
from dataclasses import dataclass
from pathlib import Path
import sys
sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE / 'upstream'))
import exact_cost as baseline
ref = baseline.ref


@dataclass
class Arithmetic:
    multiplications: int = 0
    additions: int = 0
    comparisons: int = 0
    recognition_words: int = 0

    def mul(self, x, y):
        self.multiplications += 1
        return (x * y) % ref.Q

    def add(self, x, y):
        self.additions += 1
        return (x + y) % ref.Q

    def sub(self, x, y):
        self.additions += 1
        return (x - y) % ref.Q

    def equal(self, x, y):
        self.comparisons += 1
        return x == y

    def snapshot(self):
        return {'multiplications': self.multiplications,
                'additions_including_subtractions': self.additions,
                'field_equality_checks': self.comparisons,
                'recognition_words': self.recognition_words}


def recognize_affine(block, meter):
    """Return (b00, row slope, column slope), or refuse exact mismatch.

    Recognition is charged: 64 field equalities, 63 additions, 2
    subtractions per block. Canonical field/range checks remain upstream.
    """
    ref.words(block)
    meter.recognition_words += len(block)
    origin = block[0]
    row_slope = meter.sub(block[8], origin)
    col_slope = meter.sub(block[1], origin)
    row_start = origin
    for i in range(8):
        value = row_start
        for j in range(8):
            if not meter.equal(value, block[8*i+j]):
                raise ValueError('NON_AFFINE_BLOCK')
            if j != 7:
                value = meter.add(value, col_slope)
        if i != 7:
            row_start = meter.add(row_start, row_slope)
    return origin, row_slope, col_slope


class AffineProducts:
    """Exact affine-block compiler; refuses non-affine materials.

    Retained compiled field payload: 128 * 4 * 4 = 2048 bytes.
    The two source matrices and Merkle trees are accounted separately.
    """
    def __init__(self, a, b, meter):
        self.meter = meter
        if len(a) != 64 or len(b) != 64:
            raise ValueError('MATRIX_BLOCKS')
        self.left = []
        self.right = []
        for block in a:
            a0, ar, ac = recognize_affine(block, meter)
            t0 = meter.add(meter.mul(8, a0), meter.mul(28, ac))
            t1 = meter.add(meter.mul(28, a0), meter.mul(140, ac))
            ar8 = meter.mul(8, ar)
            self.left.append((t0, t1, ar, ar8))
        for block in b:
            b0, br, bc = recognize_affine(block, meter)
            t2 = meter.add(meter.mul(8, b0), meter.mul(28, br))
            self.right.append((b0, br, bc, t2))

    def product(self, bi, bk, bj):
        t0, t1, ar, ar8 = self.left[bi*8+bk]
        b0, br, bc, t2 = self.right[bk*8+bj]
        m = self.meter
        row_start = m.add(m.mul(t0, b0), m.mul(t1, br))
        row_step = m.mul(ar, t2)
        col_step = m.mul(bc, t0)
        mixed_step = m.mul(ar8, bc)
        output = []
        for i in range(8):
            value = row_start
            for j in range(8):
                output.append(value)
                if j != 7:
                    value = m.add(value, col_step)
            if i != 7:
                row_start = m.add(row_start, row_step)
                col_step = m.add(col_step, mixed_step)
        return tuple(output)


class FrontierPrepared:
    """Prepared task with direct, eager, or bounded lazy useful products."""
    def __init__(self, a, b, *, arithmetic='dense', cache='none', capacity=512):
        if arithmetic not in ('dense', 'affine') or cache not in ('none', 'eager', 'lazy'):
            raise ValueError('STRATEGY')
        if type(capacity) is not int or not 0 <= capacity <= 512:
            raise ValueError('CAPACITY')
        if cache == 'eager' and capacity != 512:
            raise ValueError('EAGER_REQUIRES_COMPLETE_TABLE')
        self.a, self.b = a, b
        self.ta, self.tb = ref.tree(b'A', a), ref.tree(b'B', b)
        self.arithmetic = Arithmetic()
        self.compiled = AffineProducts(a, b, self.arithmetic) if arithmetic == 'affine' else None
        self.cache_mode, self.capacity = cache, capacity
        self.cache = {}
        self.lookups = self.misses = self.hits = self.computed_products = self.insertions = 0
        if cache == 'eager':
            for bi in range(8):
                for bk in range(8):
                    for bj in range(8):
                        key = bi*64+bk*8+bj
                        self.cache[key] = self._product(bi, bk, bj)
                        self.insertions += 1

    def _product(self, bi, bk, bj):
        self.computed_products += 1
        if self.compiled is not None:
            return self.compiled.product(bi, bk, bj)
        return ref.block_mul(self.a[bi*8+bk], self.b[bk*8+bj])

    def useful(self, bi, bk, bj):
        key = bi*64+bk*8+bj
        if self.cache_mode != 'none':
            self.lookups += 1
            if key in self.cache:
                self.hits += 1
                return self.cache[key]
            self.misses += 1
        value = self._product(bi, bk, bj)
        if self.cache_mode == 'lazy' and len(self.cache) < self.capacity:
            self.cache[key] = value
            self.insertions += 1
        return value

    def produce(self, ctx, nonce):
        s = ref.seed(ctx, nonce)
        bi, bk, bj = ref.selected_coordinates(s)
        if (self.ta[-1][0], self.tb[-1][0]) != (ctx.root_a, ctx.root_b):
            raise ValueError('TASK_ROOT')
        a, b = self.a[bi*8+bk], self.b[bk*8+bj]
        e, f = ref.noise_blocks(s, bi, bk, bj)
        noisy = ref.block_mul(ref.block_add(a, e), ref.block_add(b, f))
        useful = self.useful(bi, bk, bj)
        return ref.Witness(nonce, bi, bk, bj, a, b,
                           ref.opening(self.ta, bi*8+bk),
                           ref.opening(self.tb, bk*8+bj), noisy, useful)

    def cache_record(self):
        return {'lookups': self.lookups, 'hits': self.hits, 'misses': self.misses,
                'computed_useful_products': self.computed_products,
                'insertions': self.insertions, 'entries': len(self.cache),
                'capacity': self.capacity,
                'cached_result_payload_bytes': 256*len(self.cache),
                'coordinate_key_minimum_payload_bytes': 2*len(self.cache),
                'compiled_field_payload_bytes': 2048 if self.compiled else 0,
                'python_object_and_allocator_overhead_included': False}


def witness_bytes(w):
    return (w.nonce.to_bytes(8, 'little') + bytes((w.bi, w.bk, w.bj)) +
            ref.words(w.a) + ref.words(w.b) + b''.join(w.path_a) + b''.join(w.path_b) +
            ref.words(w.noisy_product) + ref.words(w.useful_product))
