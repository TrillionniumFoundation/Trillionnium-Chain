"""Research only: Fiat-Shamir Freivalds product claims, NOT PoN work hardness."""
import hashlib
import struct
import time
from contract_wire import H
import work_oracle as W

N,R,Q=W.N,W.R,W.Q
ROUNDS=6
MAGIC=b'PND0'
PROOF_BYTES=4+4*W.CELLS*4


def masked(challenge,a,b):
    el,er,fl,fr=[W.expand(challenge,x,N*R) for x in range(4)]
    left=W.mm(el,er,N,R,N)
    right=W.mm(fl,fr,N,R,N)
    ap=[(x+y)%Q for x,y in zip(a,left)]
    bp=[(x+y)%Q for x,y in zip(b,right)]
    return ap,bp,(el,er,fl,fr)


def precomputed_base(a,b):
    W.check(a);W.check(b)
    return W.mm(a,b,N,N,N)


def direct(challenge,a,b,base=None):
    W.check(a);W.check(b)
    if base is None:base=precomputed_base(a,b)
    if len(base)!=W.CELLS:raise ValueError('BASE_LENGTH')
    ap,bp,_=masked(challenge,a,b)
    cp=W.mm(ap,bp,N,N,N)
    return MAGIC+W.field_bytes(a)+W.field_bytes(b)+W.field_bytes(base)+W.field_bytes(cp)


def factored(challenge,a,b,base):
    W.check(a);W.check(b);W.check(base)
    ap,bp,(el,er,fl,fr)=masked(challenge,a,b)
    # (A+EL*ER)(B+FL*FR) = AB + (A FL)FR + EL(ER B) + EL(ER FL)FR.
    af=W.mm(W.mm(a,fl,N,N,R),fr,N,R,N)
    eb=W.mm(el,W.mm(er,b,R,N,N),N,R,N)
    ef=W.mm(W.mm(el,W.mm(er,fl,R,N,R),N,R,R),fr,N,R,N)
    cp=[(x+y+z+w)%Q for x,y,z,w in zip(base,af,eb,ef)]
    return MAGIC+W.field_bytes(a)+W.field_bytes(b)+W.field_bytes(base)+W.field_bytes(cp)


def vector(seed,round_number):
    data=[];block=0
    while len(data)<N:
        raw=H('w2d-freivalds-vector-v0',seed,struct.pack('<I',round_number),struct.pack('<I',block))
        data.extend(value for (value,) in struct.iter_unpack('<I',raw) if value<Q)
        block+=1
    return data[:N]


def matvec(matrix,vec):
    return [sum(matrix[i*N+j]*vec[j] for j in range(N))%Q for i in range(N)]


def ticket(challenge,proof):
    return H('w2d-ticket-research-v0',challenge,hashlib.sha256(proof).digest())


def verify(challenge,task,target,proof):
    if any(type(x)is not bytes or len(x)!=32 for x in (challenge,task,target)):
        raise ValueError('CONTEXT')
    if type(proof)is not bytes or len(proof)!=PROOF_BYTES:raise ValueError('LENGTH')
    if proof[:4]!=MAGIC:raise ValueError('VERSION')
    xs=struct.unpack('<'+'I'*(4*W.CELLS),proof[4:])
    if any(x>=Q for x in xs):raise ValueError('FIELD')
    a,b,c,cp=[xs[i*W.CELLS:(i+1)*W.CELLS] for i in range(4)]
    if W.task_id(a,b)!=task:raise ValueError('TASK')
    if target==bytes(32) or ticket(challenge,proof)>target:raise ValueError('TARGET')
    seed=H('w2d-freivalds-input-v0',challenge,task,hashlib.sha256(proof).digest())
    for rd in range(ROUNDS):
        v=vector(seed,rd)
        if matvec(a,matvec(b,v))!=matvec(c,v):
            raise ValueError('BASE_PROJECTION')
    ap,bp,_=masked(challenge,a,b)
    for rd in range(ROUNDS):
        v=vector(seed,rd+ROUNDS)
        if matvec(ap,matvec(bp,v))!=matvec(cp,v):
            raise ValueError('MASKED_PROJECTION')
    return {'status':'PROJECTION_CHECKED_RESEARCH_ONLY',
            'rounds_per_relation':ROUNDS,'verified_work':False,
            'chainwork':0,'consensus_activation':False}


def compare(seed=1):
    cases=[]
    target=bytes([255])*32
    for label in ('zero','dense'):
        if label=='zero':a=b=[0]*W.CELLS
        else:
            a=[(i*11+3)%97 for i in range(W.CELLS)]
            b=[(i*17+7)%101 for i in range(W.CELLS)]
        started=time.process_time_ns()
        base=precomputed_base(a,b)
        prep=time.process_time_ns()-started
        for nonce in (0,1):
            challenge=H('w2d-comparison-challenge-v0',struct.pack('<Q',seed),label.encode(),struct.pack('<Q',nonce))
            start=time.process_time_ns();proof=direct(challenge,a,b,base);direct_cpu=time.process_time_ns()-start
            start=time.process_time_ns();optimized=factored(challenge,a,b,base);factored_cpu=time.process_time_ns()-start
            if proof!=optimized:raise AssertionError('DIFFERENTIAL')
            start=time.process_time_ns();valid=verify(challenge,W.task_id(a,b),target,proof);verify_cpu=time.process_time_ns()-start
            mutated=bytearray(proof);mutated[-1]^=1
            start=time.process_time_ns()
            try:verify(challenge,W.task_id(a,b),target,bytes(mutated))
            except ValueError as exc:bad=str(exc)
            else:raise AssertionError('FORGERY_ACCEPTED')
            reject_cpu=time.process_time_ns()-start
            cases.append({'material':label,'nonce':nonce,'base_precompute_cpu_ns':prep,
                          'direct_cpu_ns':direct_cpu,'factored_cpu_ns':factored_cpu,
                          'verify_cpu_ns':verify_cpu,'corrupted_cpu_ns':reject_cpu,
                          'corrupted_result':bad,'ticket':ticket(challenge,proof).hex(),
                          'proof_sha256':hashlib.sha256(proof).hexdigest(),
                          'accepted_only_as_research':valid['status']})
    return {'schema':'w2d-freivalds-product-research-v0',
            'q':Q,'n':N,'freivalds_rounds_per_relation':ROUNDS,
            'proof_bytes':PROOF_BYTES,'gpu_measurement':None,
            'hash_grinding_soundness_reviewed':False,
            'useful_work_hardness_proved':False,'prod_activation':False,'rows':cases}


if __name__=='__main__':
    import json
    print(json.dumps(compare(),indent=2,sort_keys=True))
