"""W2-D RESEARCH ONLY: full W1 intermediate tape plus Fiat-Shamir Freivalds.

This is a transparent, *probabilistic* batch relation check, not a succinct
proof, formal soundness proof or activated Chain consensus. It does not produce
VerifiedWork, final-use authority, reward or Chainwork. The random oracle and
finite field assumptions need independent third-party review.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import struct
from contract_wire import H
import work_oracle as W

N,R,Q = W.N,W.R,W.Q
TILE_COUNT = (N // R)**3
WORDS = TILE_COUNT * R * R
TAPE_BYTES = WORDS * 4
SIDECAR_BYTES = 4 + TAPE_BYTES
MAGIC = b'PFD1'  # NEVER PNW1, cannot decode as Chain work
DEFAULT_ROUNDS = 3

@dataclass(frozen=True)
class Candidate:
    proof: bytes
    sidecar: bytes


def expansions(challenge):
    el,er,fl,fr=[W.expand(challenge,x,N*R)for x in range(4)]
    return el,er,fl,fr


def prepared(challenge,a,b):
    W.check(a);W.check(b)
    el,er,fl,fr=expansions(challenge)
    e=W.mm(el,er,N,R,N);f=W.mm(fl,fr,N,R,N)
    ap=[(x+y)%Q for x,y in zip(a,e)]
    bp=[(x+y)%Q for x,y in zip(b,f)]
    return el,er,fl,fr,ap,bp


def produce(challenge,a,b):
    if not isinstance(challenge,bytes) or len(challenge)!=32:raise ValueError('CHALLENGE')
    el,er,fl,fr,ap,bp=prepared(challenge,a,b)
    cp=[0]*W.CELLS
    tape=bytearray()
    for i0 in range(0,N,R):
        for j0 in range(0,N,R):
            for k0 in range(0,N,R):
                for i in range(i0,i0+R):
                    for j in range(j0,j0+R):
                        pos=i*N+j
                        cp[pos]=(cp[pos]+sum(ap[i*N+k]*bp[k*N+j]for k in range(k0,k0+R)))%Q
                        tape.extend(struct.pack('<I',cp[pos]))
    if len(tape)!=TAPE_BYTES:raise AssertionError('TAPE_LENGTH')
    trace=hashlib.sha256(b'TRNM-PON-TRACE1\0'+challenge+tape).digest()
    c1=W.mm(W.mm(a,fl,N,N,R),fr,N,R,N)
    c2=W.mm(el,W.mm(er,bp,R,N,N),N,R,N)
    product=[(x-y-z)%Q for x,y,z in zip(cp,c1,c2)]
    proof=b'PNW1'+W.field_bytes(a)+W.field_bytes(b)+W.field_bytes(product)+trace
    return Candidate(proof,MAGIC+bytes(tape))


def checked_tape(challenge,proof,sidecar):
    if type(sidecar)is not bytes or len(sidecar)!=SIDECAR_BYTES:raise ValueError('TAPE_LENGTH')
    if sidecar[:4]!=MAGIC:raise ValueError('TAPE_VERSION')
    raw=sidecar[4:]
    if any(x>=Q for(x,)in struct.iter_unpack('<I',raw)):
        raise ValueError('TAPE_FIELD')
    actual=hashlib.sha256(b'TRNM-PON-TRACE1\0'+challenge+raw).digest()
    if actual != proof[-32:]:raise ValueError('TRACE_BIND')
    return raw


def field_vector(statement,domain,round_number):
    result=[]
    for i in range(N):
        for retry in range(16):
            value=struct.unpack('<I',H('w2d-field-coeff-v1',statement,
                                      domain,struct.pack('<III',round_number,i,retry))[:4])[0]
            if value < Q:
                result.append(value)
                break
        else:raise ValueError('FS_SAMPLE_EXHAUSTED')
    return result


def reconstruct_prefixes(raw):
    words=[x for(x,)in struct.iter_unpack('<I',raw)]
    prefixes=[[0]*W.CELLS for _ in range(N//R)]
    offset=0
    for bi in range(N//R):
        for bj in range(N//R):
            for bk in range(N//R):
                prefix=prefixes[bk]
                for i in range(bi*R,(bi+1)*R):
                    for j in range(bj*R,(bj+1)*R):
                        prefix[i*N+j]=words[offset]
                        offset+=1
    if offset!=WORDS:raise AssertionError('TAPE_DECODE')
    return prefixes


def right_projection(matrix,vector):
    return [sum(matrix[i*N+j]*vector[j]for j in range(N))%Q for i in range(N)]


def prefix_check(prefixes,ap,bp,vector):
    prior=[0]*N
    for k in range(N//R):
        lhs=right_projection(prefixes[k],vector)
        j0=k*R
        projected_b=[sum(bp[(j0+t)*N+j]*vector[j]for j in range(N))%Q
                     for t in range(R)]
        for i in range(N):
            rhs=sum(ap[i*N+j0+t]*projected_b[t]for t in range(R))%Q
            if (lhs[i]-prior[i])%Q!=rhs:
                return False
        prior=lhs
    return True


def product_check(a,b,c,vector):
    projected_b=right_projection(b,vector)
    return right_projection(a,projected_b)==right_projection(c,vector)


def verify(challenge,expected_task,target,proof,sidecar,rounds=DEFAULT_ROUNDS):
    """Only a research relation verdict. NEVER grant Chain VerifiedWork."""
    if type(rounds)is not int or not 2<=rounds<=5:raise ValueError('ROUNDS')
    if type(challenge)is not bytes or len(challenge)!=32:raise ValueError('CHALLENGE')
    a,b,c,_ticket=W.precheck(challenge,expected_task,target,proof)
    raw=checked_tape(challenge,proof,sidecar)
    digest=H('w2d-fs-statement-v1',challenge,expected_task,target,proof,
             hashlib.sha256(raw).digest())
    prefixes=reconstruct_prefixes(raw)
    _el,_er,_fl,_fr,ap,bp=prepared(challenge,a,b)
    for k in range(rounds):
        if not prefix_check(prefixes,ap,bp,field_vector(digest,b'prefix',k)):
            raise ValueError('PREFIX')
    for k in range(rounds):
        if not product_check(a,b,c,field_vector(digest,b'product',k)):
            raise ValueError('PRODUCT')
    return {'outcome':'RESEARCH_PROBABILISTIC_RELATION_CHECKED',
            'rounds':rounds,'verified_work':False,'chainwork':0,
            'consensus_activated':False,'sidecar_bytes':len(sidecar)}
