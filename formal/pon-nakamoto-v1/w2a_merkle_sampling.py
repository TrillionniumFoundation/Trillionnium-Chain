"""W2-A research-only Merkle sampled prefix filter; NEVER a consensus verifier.

Reproduces the 512 intermediate W1 tiles and commits them to a 512-leaf
Merkle tree. Sampled exact arithmetic may reject invalid openings early, but
passing says *only* sampled openings matched. A one-tile forgery is a negative
control showing why no chainwork or VerifiedWork may be granted by this code.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import struct
import time
from typing import Sequence
from contract_wire import H
import work_oracle as W

LEAVES = (W.N // W.R) ** 3
LEAF_BYTES = W.R * W.R * 4
TREE_DEPTH = 9

@dataclass(frozen=True)
class Opening:
    index: int
    raw: bytes
    siblings: tuple[bytes, ...]

@dataclass(frozen=True)
class Sidecar:
    root: bytes
    openings: tuple[Opening, ...]
    # Trace digest is a W1 reference measurement, NOT authenticated by sampling.
    reference_trace: bytes


def checked_context(challenge: bytes, a: Sequence[int], b: Sequence[int]) -> None:
    if not isinstance(challenge, bytes) or len(challenge) != 32:
        raise ValueError('CHALLENGE')
    W.check(a)
    W.check(b)


def encoded_operands(challenge: bytes, a: Sequence[int], b: Sequence[int]):
    checked_context(challenge, a, b)
    el, er, fl, fr = [W.expand(challenge, label, W.N * W.R) for label in range(4)]
    e, f = W.mm(el, er, W.N, W.R, W.N), W.mm(fl, fr, W.N, W.R, W.N)
    return ([(x+y) % W.Q for x, y in zip(a, e)],
            [(x+y) % W.Q for x, y in zip(b, f)])


def make_leaves(challenge: bytes, a: Sequence[int], b: Sequence[int]):
    ap, bp = encoded_operands(challenge, a, b)
    cp = [0] * W.CELLS
    digest = hashlib.sha256(b'TRNM-PON-TRACE1\0' + challenge)
    leaves = []
    for bi in range(W.N // W.R):
        for bj in range(W.N // W.R):
            for bk in range(W.N // W.R):
                raw = []
                for i in range(bi * W.R, (bi+1) * W.R):
                    for j in range(bj * W.R, (bj+1) * W.R):
                        pos = i * W.N + j
                        cp[pos] = (cp[pos] + sum(ap[i*W.N+k] * bp[k*W.N+j]
                                                 for k in range(bk*W.R, (bk+1)*W.R))) % W.Q
                        raw.append(cp[pos])
                tile = W.field_bytes(raw)
                assert len(tile) == LEAF_BYTES
                leaves.append(tile)
                digest.update(tile)
    assert len(leaves) == LEAVES
    return tuple(leaves), digest.digest()


def tree_levels(leaves: Sequence[bytes]):
    if len(leaves) != LEAVES or any(len(leaf) != LEAF_BYTES for leaf in leaves):
        raise ValueError('LEAF_SHAPE')
    levels = [[H('w2a-merkle-leaf', struct.pack('<H', i), leaf)
               for i, leaf in enumerate(leaves)]]
    for depth in range(TREE_DEPTH):
        layer = levels[-1]
        if len(layer) % 2:
            raise ValueError('TREE_SHAPE')
        levels.append([H('w2a-merkle-node', struct.pack('<B', depth), layer[i], layer[i+1])
                       for i in range(0, len(layer), 2)])
    assert len(levels[-1]) == 1
    return levels


def sampled_indices(challenge: bytes, task: bytes, root: bytes, count: int):
    if any(len(v) != 32 for v in (challenge, task, root)) or not 1 <= count <= 32:
        raise ValueError('SAMPLE_PROFILE')
    chosen = []
    cursor = 0
    while len(chosen) < count:
        if cursor >= 1024:
            raise ValueError('SAMPLE_LIMIT')
        value = H('w2a-sample-index', challenge, task, root, struct.pack('<I', cursor))
        i = int.from_bytes(value[:4], 'little') % LEAVES  # 512 divides 2^32 exactly
        if i not in chosen:
            chosen.append(i)
        cursor += 1
    return tuple(chosen)


def make_sidecar(challenge: bytes, a: Sequence[int], b: Sequence[int], count: int):
    leaves, trace = make_leaves(challenge, a, b)
    levels = tree_levels(leaves)
    task = W.task_id(a, b)
    indices = sampled_indices(challenge, task, levels[-1][0], count)
    openings = tuple(Opening(index, leaves[index], tuple(level[index >> depth ^ 1]
                      for depth, level in enumerate(levels[:-1]))) for index in indices)
    return Sidecar(levels[-1][0], openings, trace)


def verify_merkle(opening: Opening, root: bytes) -> bool:
    if (not 0 <= opening.index < LEAVES or len(opening.raw) != LEAF_BYTES
            or len(root) != 32 or len(opening.siblings) != TREE_DEPTH
            or any(len(v) != 32 for v in opening.siblings)):
        return False
    state = H('w2a-merkle-leaf', struct.pack('<H', opening.index), opening.raw)
    for depth, sibling in enumerate(opening.siblings):
        if (opening.index >> depth) & 1:
            state = H('w2a-merkle-node', struct.pack('<B', depth), sibling, state)
        else:
            state = H('w2a-merkle-node', struct.pack('<B', depth), state, sibling)
    return state == root


def tile_expected(ap, bp, index: int) -> bytes:
    bi, rem = divmod(index, (W.N // W.R)**2)
    bj, bk = divmod(rem, W.N // W.R)
    out = []
    for i in range(bi * W.R, (bi+1) * W.R):
        for j in range(bj * W.R, (bj+1) * W.R):
            out.append(sum(ap[i*W.N+k] * bp[k*W.N+j]
                           for k in range((bk+1)*W.R)) % W.Q)
    return W.field_bytes(out)


def verify_sidecar(challenge: bytes, a: Sequence[int], b: Sequence[int], sidecar: Sidecar,
                   count: int) -> bool:
    """True means only sampled claims checked; never export as complete validity."""
    checked_context(challenge, a, b)
    if len(sidecar.openings) != count:
        return False
    expected = sampled_indices(challenge, W.task_id(a, b), sidecar.root, count)
    if tuple(v.index for v in sidecar.openings) != expected:
        return False
    # A/B, nonce and challenge source are authenticated by an independent caller.
    ap, bp = encoded_operands(challenge, a, b)
    return all(verify_merkle(opening, sidecar.root)
               and tile_expected(ap, bp, opening.index) == opening.raw
               for opening in sidecar.openings)


def corrupted_sidecar(challenge, a, b, count):
    """Adversarial soundness counterexample: one bad committed tile escapes sampling."""
    leaves, trace = make_leaves(challenge, a, b)
    leaves = list(leaves)
    task = W.task_id(a, b)
    for bad_index in range(64):
        damaged = leaves.copy()
        changed = bytearray(damaged[bad_index]); changed[0] ^= 1
        damaged[bad_index] = bytes(changed)
        levels = tree_levels(damaged)
        root = levels[-1][0]
        indices = sampled_indices(challenge, task, root, count)
        if bad_index in indices:
            continue
        openings = tuple(Opening(i, damaged[i], tuple(level[(i >> depth) ^ 1]
                         for depth, level in enumerate(levels[:-1]))) for i in indices)
        return bad_index, Sidecar(root, openings, trace)
    raise ValueError('NO_COUNTEREXAMPLE_WITHIN_BUDGET')


def comparison(challenge, a, b, counts=(1, 4, 16)):
    checked_context(challenge, a, b)
    start = time.process_time_ns()
    product, valid_trace = W.evaluate(challenge, a, b)
    full_cpu = time.process_time_ns() - start
    rows=[]
    for count in counts:
        start = time.process_time_ns()
        sidecar = make_sidecar(challenge, a, b, count)
        producer_cpu = time.process_time_ns() - start
        if sidecar.reference_trace != valid_trace:
            raise AssertionError('W1_TRACE_DISAGREEMENT')
        start = time.process_time_ns()
        accepted = verify_sidecar(challenge, a, b, sidecar, count)
        sample_cpu = time.process_time_ns() - start
        if not accepted:
            raise AssertionError('VALID_SAMPLE_DISAGREEMENT')
        bad_index, corrupted = corrupted_sidecar(challenge, a, b, count)
        # This negative example passes the sample but differs in one committed tile.
        if not verify_sidecar(challenge, a, b, corrupted, count):
            raise AssertionError('MISSED_CORRUPTION_COUNTEREXAMPLE_ABSENT')
        rows.append(dict(count=count, original_w1_full_cpu_ns=full_cpu,
                         sidecar_production_cpu_ns=producer_cpu,
                         sampled_rejection_filter_cpu_ns=sample_cpu,
                         unsampled_corrupt_tile=bad_index,
                         unsampled_corruption_accepted_by_filter=True,
                         complete_consensus_validity=False))
    return rows
