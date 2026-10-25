"""Research-only exact W1 relation witness for a future cryptographic proof.

This is NOT a STARK, SNARK, succinct proof, verified-work capability, or
consensus implementation. It deliberately recomputes all 512 W1 prefix tiles.
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
    encoded = b''.join(leaves)
    if len(encoded) != WITNESS_BYTES:
        raise AssertionError('W2B_WITNESS_LENGTH')
    return Witness(encoded, trace, W.field_bytes(product))

def check_relation(challenge: bytes, task: bytes, target: bytes, proof: bytes,
                   witness: Witness) -> dict:
    """Exhaustive reference replay. This function NEVER returns VerifiedWork."""
    statement = statement_id(challenge, task, target, proof)
    a, b, claimed, ticket = W.precheck(challenge, task, target, proof)
    if (type(witness.trace_tiles) is not bytes
            or len(witness.trace_tiles) != WITNESS_BYTES
            or type(witness.computed_trace) is not bytes
            or len(witness.computed_trace) != 32
            or type(witness.computed_product) is not bytes
            or len(witness.computed_product) != W.CELLS * 4):
        raise ValueError('WITNESS_LENGTH')
    digest = hashlib.sha256(b'TRNM-PON-TRACE1\x00' + challenge + witness.trace_tiles).digest()
    if digest != witness.computed_trace or digest != proof[-32:]:
        raise ValueError('TRANSCRIPT')
    leaves, oracle_trace = A.make_leaves(challenge, a, b)
    if b''.join(leaves) != witness.trace_tiles or oracle_trace != witness.computed_trace:
        raise ValueError('WITNESS_ARITHMETIC')
    product, verified_trace = W.evaluate(challenge, a, b)
    if verified_trace != witness.computed_trace:
        raise ValueError('TRANSCRIPT')
    exact = W.field_bytes(product)
    if exact != witness.computed_product or proof[4 + 2 * W.CELLS * 4:-32] != exact:
        raise ValueError('PRODUCT')
    return dict(statement=statement.hex(), ticket=ticket.hex(), tile_count=A.LEAVES,
                witness_bytes=WITNESS_BYTES, result='EXACT_W1_RELATION_RESEARCH_ONLY',
                succinct_proof=False, cryptographic_proof=False, verified_work=False,
                consensus_chainwork=False)
