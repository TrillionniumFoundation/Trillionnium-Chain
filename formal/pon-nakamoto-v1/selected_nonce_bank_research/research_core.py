#!/usr/bin/env python3
"""Exact lawful selected-local-event algorithms; never a physical lower bound."""
from dataclasses import dataclass
from pathlib import Path
from functools import cmp_to_key
import sys
sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE / 'upstream'))
import exact_cost as baseline
ref = baseline.ref


@dataclass
class FieldMeter:
    multiplications: int = 0
    additions: int = 0
    comparisons: int = 0
    recognition_words: int = 0
    input_coefficient_reads: int = 0
    table_field_reads: int = 0
    table_field_writes: int = 0

    def mul(self, x, y):
        self.multiplications += 1
        return x*y % ref.Q

    def add(self, x, y):
        self.additions += 1
        return (x+y) % ref.Q

    def sub(self, x, y):
        self.additions += 1
        return (x-y) % ref.Q

    def equal(self, x, y):
        self.comparisons += 1
        return x == y

    def snapshot(self):
        return dict(vars(self))


def recognize_global_affine(blocks, meter):
    """Recognize f(x0,x1,x2,x3)=origin+sum(slope_i*x_i), each xi in 0..7.

    All 4096 canonical field elements are checked. The flattening order is
    block row, block column, local row, local column. No sampling/fallback.
    """
    if type(blocks) not in (tuple, list) or len(blocks) != 64:
        raise ValueError('MATRIX_BLOCKS')
    for block in blocks:
        ref.words(block)
    flat = tuple(x for block in blocks for x in block)
    meter.recognition_words += len(flat)
    meter.input_coefficient_reads += 5
    origin = flat[0]
    slopes = tuple(meter.sub(flat[stride], origin) for stride in (512, 64, 8, 1))
    cursor = 0

    def visit(axis, start):
        nonlocal cursor
        if axis == 4:
            if not meter.equal(start, flat[cursor]):
                raise ValueError('NON_GLOBAL_AFFINE_INPUT')
            cursor += 1
            return
        value = start
        for index in range(8):
            visit(axis+1, value)
            if index != 7:
                value = meter.add(value, slopes[axis])

    visit(0, origin)
    assert cursor == 4096
    return (origin, *slopes)


class GlobalAffineProducts:
    """A 329-field-word exact compiled representation of all 512 local U.

    This is a narrower, fully recognized family than arbitrary per-block
    affine input. Source input/tree/bank storage is additional. Coefficients
    and temporary compiler tables are not retained by this object.
    """
    PAYLOAD_BYTES = 329*4

    def __init__(self, a, b, meter=None):
        self.meter = meter if meter is not None else FieldMeter()
        m = self.meter
        a0, ai, ak, ar, at = recognize_global_affine(a, m)
        b0, bk, bj, bt, bc = recognize_global_affine(b, m)
        t0 = m.add(m.mul(8, a0), m.mul(28, at))
        t1 = m.add(m.mul(28, a0), m.mul(140, at))
        v0 = m.add(m.mul(8, b0), m.mul(28, bt))
        base = m.add(m.mul(t0, b0), m.mul(t1, bt))
        di0, dj0 = m.mul(ai, v0), m.mul(bj, t0)
        ai8, ak8, ar8 = m.mul(8, ai), m.mul(8, ak), m.mul(8, ar)
        dk_linear = m.add(m.mul(ak, v0), m.mul(bk, t0))
        kk = m.mul(ak8, bk)
        dk0, dkk = m.add(dk_linear, kk), m.add(kk, kk)
        dik, dij, djk = m.mul(ai8, bk), m.mul(ai8, bj), m.mul(ak8, bj)
        row_base, row_k, row_j = m.mul(ar, v0), m.mul(ar8, bk), m.mul(ar8, bj)
        col_base, col_i, col_k = m.mul(bc, t0), m.mul(bc, ai8), m.mul(bc, ak8)
        self.mixed = m.mul(bc, ar8)

        z = []
        value, delta = base, dk0
        for k in range(8):
            z.append(value)
            if k != 7:
                value = m.add(value, delta)
            if k < 6:
                delta = m.add(delta, dkk)
        self.z = tuple(z)
        self.i_term = self._products_table(di0, dik)
        self.j_term = self._products_table(dj0, djk)
        self.ij_term = self._products_table(0, dij)
        self.row = self._linear_grid(row_base, row_k, row_j)
        self.col = self._linear_grid(col_base, col_i, col_k)
        m.table_field_writes += 329
        assert sum(len(t) for t in (self.z, self.i_term, self.j_term,
                                   self.ij_term, self.row, self.col))+1 == 329

    def _products_table(self, origin_step, difference):
        """table[row,column]=row*(origin_step+column*difference)."""
        out = [0]*64
        step = origin_step
        for column in range(8):
            value = 0
            for row in range(8):
                out[row*8+column] = value
                if row != 7:
                    value = self.meter.add(value, step)
            if column != 7:
                step = self.meter.add(step, difference)
        return tuple(out)

    def _linear_grid(self, origin, row_step, col_step):
        out = []
        start = origin
        for row in range(8):
            value = start
            for col in range(8):
                out.append(value)
                if col != 7:
                    value = self.meter.add(value, col_step)
            if row != 7:
                start = self.meter.add(start, row_step)
        return tuple(out)

    def product(self, bi, bk, bj):
        if any(type(x) is not int or not 0 <= x < 8 for x in (bi, bk, bj)):
            raise ValueError('COORDINATE')
        m = self.meter
        m.table_field_reads += 7
        start = m.add(m.add(m.add(self.z[bk], self.i_term[bi*8+bk]),
                            self.j_term[bj*8+bk]), self.ij_term[bi*8+bj])
        row_step, col_step = self.row[bk*8+bj], self.col[bi*8+bk]
        out = []
        for row in range(8):
            value = start
            for col in range(8):
                out.append(value)
                if col != 7:
                    value = m.add(value, col_step)
            if row != 7:
                start = m.add(start, row_step)
                col_step = m.add(col_step, self.mixed)
        return tuple(out)


@dataclass(frozen=True)
class Gate:
    nonce: int
    seed: bytes
    coordinate: tuple

    def encode(self):
        return self.nonce.to_bytes(8, 'little')+self.seed+bytes(self.coordinate)


def evaluate_gate(ctx, nonce):
    seed = ref.seed(ctx, nonce)
    return Gate(nonce, seed, ref.selected_coordinates(seed))


def bank_order(gates, operations=None):
    """No event/noise/ticket access. Keys contain only prepaid selector data."""
    op = operations if operations is not None else {}
    for name in ('bucket_dictionary_lookups', 'bucket_appends', 'bucket_order_comparisons',
                 'nonce_order_comparisons', 'emitted_bank_entries'):
        op.setdefault(name, 0)
    buckets = {}
    for gate in gates:
        op['bucket_dictionary_lookups'] += 1
        buckets.setdefault(gate.coordinate, []).append(gate)
        op['bucket_appends'] += 1

    def coord_compare(a, b):
        op['bucket_order_comparisons'] += 1
        a_key, b_key = (-len(buckets[a]), a), (-len(buckets[b]), b)
        return (a_key > b_key)-(a_key < b_key)

    def nonce_compare(a, b):
        op['nonce_order_comparisons'] += 1
        return (a.nonce > b.nonce)-(a.nonce < b.nonce)

    coordinates = sorted(buckets, key=cmp_to_key(coord_compare))
    result = tuple(gate for key in coordinates for gate in
                   sorted(buckets[key], key=cmp_to_key(nonce_compare)))
    op['emitted_bank_entries'] += len(result)
    return result, buckets


class PreparedBankTask:
    def __init__(self, a, b, global_affine=False):
        self.a, self.b = a, b
        self.ta, self.tb = ref.tree(b'A', a), ref.tree(b'B', b)
        self.field = FieldMeter()
        self.compiled = GlobalAffineProducts(a, b, self.field) if global_affine else None
        self.product_acquisitions = 0

    def product(self, coord):
        self.product_acquisitions += 1
        bi, bk, bj = coord
        if self.compiled is not None:
            return self.compiled.product(bi, bk, bj)
        return ref.block_mul(self.a[bi*8+bk], self.b[bk*8+bj])

    def continue_gate(self, ctx, gate, useful):
        if (self.ta[-1][0], self.tb[-1][0]) != (ctx.root_a, ctx.root_b):
            raise ValueError('TASK_ROOT')
        bi, bk, bj = gate.coordinate
        a, b = self.a[bi*8+bk], self.b[bk*8+bj]
        e, f = ref.noise_blocks(gate.seed, bi, bk, bj)
        noisy = ref.block_mul(ref.block_add(a, e), ref.block_add(b, f))
        return ref.Witness(gate.nonce, bi, bk, bj, a, b,
                           ref.opening(self.ta, bi*8+bk), ref.opening(self.tb, bk*8+bj),
                           noisy, useful)


def witness_bytes(w):
    return (w.nonce.to_bytes(8, 'little')+bytes((w.bi, w.bk, w.bj))+
            ref.words(w.a)+ref.words(w.b)+b''.join(w.path_a)+b''.join(w.path_b)+
            ref.words(w.noisy_product)+ref.words(w.useful_product))
