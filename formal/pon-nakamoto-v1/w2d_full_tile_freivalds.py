"""W2-D RESEARCH ONLY: full-tile Fiat-Shamir/Freivalds W1 checks.

All 512 intermediate W1 tiles are transmitted (131072 bytes). Every tile
recurrence and C=AB is checked probabilistically in TWO rounds over F_q;
claimed trace SHA256 is checked exactly. This is not a production profile,
independently reviewed proof, SNARK, STARK or VerifiedWork capability.

Soundness bound is conditional on SHA256 random-oracle independence, challenge
being fixed by the external protocol before sidecar commitment, and bounded
adversarial commitment grinding. For any *fixed* false arithmetic statement,
two independent uniform field vectors catch a nonzero matrix error except
with probability at most 1/q^2. This is not an unconditional cryptocurrency
security theorem or a measured adversarial attack-cost lower bound.
"""
from __future__ import annotations
import hashlib
import struct
import time
from contract_wire import H
import work_oracle as W

DOMAIN = b'pon-w2d-full-tile-freivalds-research-v0'
BLOCKS = W.N // W.R
TILE_VALUES = W.R * W.R
TILE_BYTES = TILE_VALUES * 4
TILES = BLOCKS**3
SIDECAR_BYTES = TILES * TILE_BYTES
ROUNDS = 2


def witness(challenge: bytes, a: list[int], b: list[int]) -> bytes:
    if type(challenge) is not bytes or len(challenge) != 32:
        raise ValueError('CHALLENGE')
    W.check(a); W.check(b)
    el,er,fl,fr = [W.expand(challenge, label, W.N*W.R) for label in range(4)]
    ap = [(x+y) % W.Q for x,y in zip(a,W.mm(el,er,W.N,W.R,W.N))]
    bp = [(x+y) % W.Q for x,y in zip(b,W.mm(fl,fr,W.N,W.R,W.N))]
    cp = [0]*W.CELLS
    output = bytearray()
    for bi in range(BLOCKS):
        for bj in range(BLOCKS):
            for bk in range(BLOCKS):
                for i in range(W.R):
                    for j in range(W.R):
                        row, col = bi*W.R+i, bj*W.R+j
                        pos = row*W.N+col
                        cp[pos] = (cp[pos]+sum(ap[row*W.N+bk*W.R+k]
                              * bp[(bk*W.R+k)*W.N+col] for k in range(W.R))) % W.Q
                        output.extend(struct.pack('<I', cp[pos]))
    assert len(output) == SIDECAR_BYTES
    return bytes(output)


def commitment(challenge: bytes, task: bytes, target: bytes,
               proof: bytes, sidecar: bytes) -> bytes:
    if any(type(v) is not bytes or len(v) != 32 for v in (challenge,task,target)):
        raise ValueError('STATEMENT')
    if type(proof) is not bytes or len(proof) != W.PROOF_BYTES:
        raise ValueError('PROOF_LENGTH')
    if type(sidecar) is not bytes or len(sidecar) != SIDECAR_BYTES:
        raise ValueError('SIDECAR_LENGTH')
    return H('w2d-statement-commit', DOMAIN, challenge, task, target, proof, sidecar)


def field_vector(seed: bytes, label: bytes, indices: bytes, count: int) -> tuple[int,...]:
    if type(seed) is not bytes or len(seed) != 32 or type(indices) is not bytes:
        raise ValueError('VECTOR_SEED')
    if count not in (W.R, W.N):
        raise ValueError('VECTOR_LENGTH')
    values=[]
    for counter in range(32):
        block=H('w2d-freivalds-r', DOMAIN, seed, label, indices,
                struct.pack('<I',counter))
        for (v,) in struct.iter_unpack('<I',block):
            if v < W.Q: # exact uniform rejection sampling; never modulo-reduce
                values.append(v)
                if len(values) == count:
                    return tuple(values)
    raise ValueError('VECTOR_SAMPLING_LIMIT')


def _mul_mv(matrix: list[int], vec: tuple[int,...], rows: int, inner: int) -> list[int]:
    return [sum(matrix[i*inner+k]*vec[k] for k in range(inner)) % W.Q
            for i in range(rows)]


def verify(challenge: bytes, task: bytes, target: bytes,
           proof: bytes, sidecar: bytes) -> dict:
    """Accepts a *research* randomized check, NEVER native VerifiedWork."""
    a,b,claimed,ticket = W.precheck(challenge,task,target,proof)
    seed=commitment(challenge,task,target,proof,sidecar)
    vals=struct.unpack('<'+str(TILES*TILE_VALUES)+'I', sidecar)
    if any(v >= W.Q for v in vals):
        raise ValueError('SIDECAR_FIELD')
    trace=hashlib.sha256(b'TRNM-PON-TRACE1\0'+challenge+sidecar).digest()
    if trace != proof[-32:]:
        raise ValueError('TRANSCRIPT')
    el,er,fl,fr = [W.expand(challenge,label,W.N*W.R) for label in range(4)]
    ap = [(x+y)%W.Q for x,y in zip(a,W.mm(el,er,W.N,W.R,W.N))]
    bp = [(x+y)%W.Q for x,y in zip(b,W.mm(fl,fr,W.N,W.R,W.N))]
    # Group by column/inner tile so all 8 output-row tiles share one
    # unpredictable field vector and one B_tile*r, rather than 8 copies.
    vectors={}
    for bj in range(BLOCKS):
        for bk in range(BLOCKS):
            b_tile=[bp[(bk*W.R+k)*W.N+bj*W.R+j]
                    for k in range(W.R) for j in range(W.R)]
            for round_ in range(ROUNDS):
                idx=struct.pack('<BBB',bj,bk,round_)
                rr=field_vector(seed,b'tile',idx,W.R)
                vectors[bj,bk,round_] = rr, _mul_mv(b_tile,rr,W.R,W.R)
    for bi in range(BLOCKS):
        for bj in range(BLOCKS):
            old=[0]*TILE_VALUES
            for bk in range(BLOCKS):
                index=(bi*BLOCKS+bj)*BLOCKS+bk
                new=vals[index*TILE_VALUES:(index+1)*TILE_VALUES]
                a_tile=[ap[(bi*W.R+i)*W.N+bk*W.R+k]
                        for i in range(W.R) for k in range(W.R)]
                for round_ in range(ROUNDS):
                    rr,br=vectors[bj,bk,round_]
                    lhs=[sum(((new[i*W.R+j]-old[i*W.R+j])%W.Q)*rr[j]
                               for j in range(W.R))%W.Q for i in range(W.R)]
                    if lhs != _mul_mv(a_tile,br,W.R,W.R):
                        raise ValueError('TILE_RELATION')
                old=new
    for round_ in range(ROUNDS):
        rr=field_vector(seed,b'product',bytes([round_]),W.N)
        br=_mul_mv(b,rr,W.N,W.N)
        if _mul_mv(a,br,W.N,W.N) != _mul_mv(claimed,rr,W.N,W.N):
            raise ValueError('PRODUCT_RELATION')
    return dict(schema='w2d-full-tile-research-v0',ticket=ticket.hex(),
                commitment=seed.hex(),tiles=TILES,sidecar_bytes=SIDECAR_BYTES,
                freivalds_rounds=ROUNDS,verified_work=False,
                chainwork=False,production_activation=False,
                result='PROBABILISTIC_RELATION_RESEARCH_ONLY')


def comparative_cost(challenge: bytes, a: list[int], b: list[int]):
    """Actual caller process CPU, not hardware/GPU bounds or a cost theorem."""
    target=bytes([255])*32  # synthetic research-only loose target
    task=W.task_id(a,b)
    before=time.process_time_ns();proof=W.prove(challenge,a,b)
    producer_cpu=time.process_time_ns()-before
    before=time.process_time_ns();raw=witness(challenge,a,b)
    witness_cpu=time.process_time_ns()-before
    before=time.process_time_ns();W.verify(challenge,task,target,proof)
    w1_cpu=time.process_time_ns()-before
    before=time.process_time_ns();verdict=verify(challenge,task,target,proof,raw)
    w2d_cpu=time.process_time_ns()-before
    return dict(schema='w2d-bounded-cpu-study-v0',w1_producer_cpu_ns=producer_cpu,
                w2d_extra_witness_cpu_ns=witness_cpu,
                w1_verifier_cpu_ns=w1_cpu,w2d_verifier_cpu_ns=w2d_cpu,
                witness_bytes=len(raw),ticket=verdict['ticket'],
                w2d_research_only=True,w2d_verifier_cheaper_measured=w2d_cpu<w1_cpu,
                independent_gpu_measured=False,production_activation=False)
