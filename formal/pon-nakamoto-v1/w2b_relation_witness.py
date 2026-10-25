"""W2-B research: exact 512-tile W1 relation witness, NOT a succinct proof.

This reference describes what a future independently reviewed STARK/SNARK
circuit must enforce, including trace SHA and public statement binding. It
intentionally recomputes the complete W1 relation and provides no cost
saving, zero-knowledge, cryptographic soundness, chainwork or FinalUse.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from contract_wire import H
import work_oracle as W
import w2a_merkle_sampling as A

WITNESS_BYTES = A.LEAVES * A.LEAF_BYTES
DOMAIN = b'pon-w2b-exact-w1-relation-research-v0'


@dataclass(frozen=True)
class Witness:
    trace_tiles: bytes
    computed_trace: bytes
    computed_product: bytes


def statement_id(challenge: bytes, task: bytes, target: bytes, proof: bytes) -> bytes:
    if any(type(x) is not bytes or len(x) != 32 for x in (challenge, task, target)):
        raise ValueError('STATEMENT')
    if type(proof) is not bytes or len(proof) != W.PROOF_BYTES:
        raise ValueError('PROOF')
    return H('w2b-statement', DOMAIN, challenge, task, target, proof)


def construct(challenge: bytes, a: list[int], b: list[int]) -> Witness:
    A.checked_context(challenge, a, b)
    leaves, trace = A.make_leaves(challenge, a, b)
    product, reference_trace = W.evaluate(challenge, a, b)
    if trace != reference_trace:
        raise AssertionError('W2B_TRACE_REFERENCE_MISMATCH')
    out = b''.join(leaves)
    if len(out) != WITNESS_BYTES:
        raise AssertionError('W2B_WITNESS_LENGTH')
    return Witness(out, trace, W.field_bytes(product))


def check_relation(challenge: bytes, task: bytes, target: bytes, proof: bytes,
                   witness: Witness) -> dict:
    """An explicit full arithmetic replay: NEVER a verified-work capability."""
    statement = statement_id(challenge, task, target, proof)
    a, b, claim_product, ticket = W.precheck(challenge, task, target, proof)
    if (type(witness.trace_tiles) is not bytes
            or len(witness.trace_tiles) != WITNESS_BYTES
            or type(witness.computed_trace) is not bytes
            or len(witness.computed_trace) != 32
            or type(witness.computed_product) is not bytes
            or len(witness.computed_product) != W.CELLS*4):
        raise ValueError('WITNESS_LENGTH')
    # SHA256's exact prefix stream must be constrained INSIDE a future circuit.
    h = hashlib.sha256(b'TRNM-PON-TRACE1\x00'+challenge)
    h.update(witness.trace_tiles)
    if h.digest() != witness.computed_trace or h.digest() != proof[-32:]:
        raise ValueError('TRANSCRIPT')
    # Every tile and every partial intermediate must have a valid arithmetic
    # recurrence. This prototype checks by full replay; it is NOT succinct.
    leaves, independent_trace = A.make_leaves(challenge, a, b)
    if b''.join(leaves) != witness.trace_tiles or independent_trace != witness.computed_trace:
        raise ValueError('WITNESS_ARITHMETIC')
    actual_product, checked_trace = W.evaluate(challenge, a, b)
    if checked_trace != witness.computed_trace:
        raise ValueError('TRANSCRIPT')
    exact_product = W.field_bytes(actual_product)
    if exact_product != witness.computed_product or proof[4 + 2*W.CELLS*4:-32] != exact_product:
        raise ValueError('PRODUCT')
    return dict(statement=statement.hex(), ticket=ticket.hex(),
                tile_count=A.LEAVES, witness_bytes=WITNESS_BYTES,
                result='EXACT_W1_RELATION_RESEARCH_ONLY',
                succinct_proof=False, cryptographic_proof=False,
                verified_work=False, consensus_chainwork=False)
