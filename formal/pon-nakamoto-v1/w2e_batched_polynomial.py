"""W2-E research: fully committed batched polynomial tile identity checks.

All 512 cumulative W1 tile states and exact SHA256 transcript are bound to
one commitment. The randomized scalar identity has total degree <= 3 and is
nonzero for ANY fixed incorrect step: it uses independent variables for each
output row, output column and inner-tile position. Five independent field
rounds have fixed-input Schwartz-Zippel error <= (3/q)^5 under uniform
sampling; Fiat-Shamir grinding security is not proven. This never creates
VerifiedWork, Chainwork or production protocol authority.
"""
from __future__ import annotations
import hashlib
import math
import struct
import time
from contract_wire import H
import work_oracle as W
import w2d_full_tile_freivalds as D

DOMAIN=b'pon-w2e-batched-polynomial-research-v0'
ROUNDS=5
SIDECAR_BYTES=D.SIDECAR_BYTES


def vector(seed: bytes, kind: bytes, iteration: int, length: int) -> list[int]:
    if type(seed) is not bytes or len(seed)!=32 or type(kind) is not bytes:
        raise ValueError('VECTOR')
    if type(iteration) is not int or not 0<=iteration<ROUNDS or length not in (8,64):
        raise ValueError('VECTOR_RANGE')
    values=[]
    for ctr in range(32):
        digest=H('w2e-global-poly-r',DOMAIN,seed,kind,
                 struct.pack('<I',iteration),struct.pack('<I',ctr))
        for (x,) in struct.iter_unpack('<I',digest):
            if x<W.Q:
                values.append(x)
                if len(values)==length:return values
    raise ValueError('VECTOR_SAMPLING')


def _dot(a,b):
    return sum(x*y for x,y in zip(a,b))%W.Q


def _ab_scalar(a,b,u,v):
    """Compute u^T A B v in O(n^2), never full matrix multiplication."""
    n=W.N
    left=[sum(u[i]*a[i*n+k] for i in range(n))%W.Q for k in range(n)]
    right=[sum(b[k*n+j]*v[j] for j in range(n))%W.Q for k in range(n)]
    return _dot(left,right)


def _prefix_scalar(states,ap,bp,u,v,w):
    blocks=D.BLOCKS
    lhs=0
    for bi in range(blocks):
        for bj in range(blocks):
            prior=[0]*D.TILE_VALUES
            for bk in range(blocks):
                ix=(bi*blocks+bj)*blocks+bk
                cur=states[ix*D.TILE_VALUES:(ix+1)*D.TILE_VALUES]
                block_sum=0
                for i in range(W.R):
                    row_sum=sum((cur[i*W.R+j]-prior[i*W.R+j])*v[bj*W.R+j]
                                for j in range(W.R))
                    block_sum+=u[bi*W.R+i]*row_sum
                lhs=(lhs+w[bk]*block_sum)%W.Q
                prior=cur
    n=W.N
    alpha=[sum(u[i]*ap[i*n+k] for i in range(n))%W.Q for k in range(n)]
    beta=[sum(bp[k*n+j]*v[j] for j in range(n))%W.Q for k in range(n)]
    rhs=sum(w[k//W.R]*alpha[k]*beta[k] for k in range(n))%W.Q
    return lhs,rhs


def verify(challenge:bytes,task:bytes,target:bytes,proof:bytes,witness:bytes) -> dict:
    a,b,c,ticket=W.precheck(challenge,task,target,proof)
    if type(witness) is not bytes or len(witness)!=SIDECAR_BYTES:
        raise ValueError('WITNESS_LENGTH')
    states=struct.unpack('<'+str(D.TILES*D.TILE_VALUES)+'I',witness)
    if any(v>=W.Q for v in states):
        raise ValueError('WITNESS_FIELD')
    trace=hashlib.sha256(b'TRNM-PON-TRACE1\0'+challenge+witness).digest()
    if trace!=proof[-32:]:
        raise ValueError('TRANSCRIPT')
    seed=H('w2e-full-statement',DOMAIN,challenge,task,target,proof,witness)
    el,er,fl,fr=[W.expand(challenge,i,W.N*W.R)for i in range(4)]
    ap=[(x+y)%W.Q for x,y in zip(a,W.mm(el,er,W.N,W.R,W.N))]
    bp=[(x+y)%W.Q for x,y in zip(b,W.mm(fl,fr,W.N,W.R,W.N))]
    for round_ in range(ROUNDS):
        u=vector(seed,b'left-rows',round_,W.N)
        v=vector(seed,b'right-cols',round_,W.N)
        w=vector(seed,b'inner-blocks',round_,D.BLOCKS)
        lhs,rhs=_prefix_scalar(states,ap,bp,u,v,w)
        if lhs!=rhs:
            raise ValueError('BATCHED_TILE_RELATION')
        lhs_product=sum(u[i]*sum(c[i*W.N+j]*v[j]
                                 for j in range(W.N)) for i in range(W.N))%W.Q
        if lhs_product!=_ab_scalar(a,b,u,v):
            raise ValueError('PRODUCT_RELATION')
    return dict(schema='w2e-batched-polynomial-research-v0',
                full_transcript=True,checked_steps=D.TILES,
                rounds=ROUNDS,fixed_input_schwartz_zippel_bound=(3/W.Q)**ROUNDS,
                witness_bytes=SIDECAR_BYTES,ticket=ticket.hex(),
                verified_work=False,chainwork=False,production_activation=False,
                independent_accepted=False,result='BATCHED_POLYNOMIAL_RESEARCH_ONLY')


def costs(challenge:bytes,a:list[int],b:list[int]):
    target=bytes([255])*32;task=W.task_id(a,b)
    t=time.process_time_ns();proof=W.prove(challenge,a,b)
    producer_ns=time.process_time_ns()-t
    t=time.process_time_ns();witness=D.witness(challenge,a,b)
    witness_ns=time.process_time_ns()-t
    t=time.process_time_ns();W.verify(challenge,task,target,proof)
    w1_ns=time.process_time_ns()-t
    t=time.process_time_ns();verdict=verify(challenge,task,target,proof,witness)
    batch_ns=time.process_time_ns()-t
    return dict(schema='w2e-batched-cpu-study-v0',w1_producer_cpu_ns=producer_ns,
                extra_witness_cpu_ns=witness_ns,w1_verify_cpu_ns=w1_ns,
                w2e_verify_cpu_ns=batch_ns,witness_bytes=len(witness),
                round_count=ROUNDS,fixed_relation_bound=(3/W.Q)**ROUNDS,
                verified_work=False,production_activation=False)
