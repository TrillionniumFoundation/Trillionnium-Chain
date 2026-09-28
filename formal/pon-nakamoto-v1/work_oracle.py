"""Independent scalar Python implementation of the fixed research work relation.
This verifies correct transcripts, not conjectured cost hardness or public-network security.
"""
from __future__ import annotations
import hashlib,struct
from contract_wire import H
N,R,Q=64,8,4294967291
CELLS=N*N
PROOF_BYTES=4+12*CELLS+32

def field_bytes(a):return struct.pack('<'+'I'*len(a),*a)
def check(a):
    if len(a)!=CELLS or any(type(v)is not int or not 0<=v<Q for v in a):raise ValueError('FIELD')
def task_id(a,b):check(a);check(b);return H('task',field_bytes(a),field_bytes(b))
def expand(c,label,n):
    out=[];counter=0
    while len(out)<n:
        if counter>=128:raise ValueError("NOISE_BUDGET")
        chunk=H('noise',c,bytes([label]),struct.pack('<I',counter));counter+=1
        out.extend(v for(v,)in struct.iter_unpack('<I',chunk)if v<Q)
    return out[:n]
def mm(a,b,n,k,m):
    return [sum(a[i*k+t]*b[t*m+j]for t in range(k))%Q for i in range(n)for j in range(m)]
def evaluate(c,a,b):
    check(a);check(b)
    el,er,fl,fr=[expand(c,x,N*R)for x in range(4)]
    e,f=mm(el,er,N,R,N),mm(fl,fr,N,R,N)
    aa=[(x+y)%Q for x,y in zip(a,e)];bb=[(x+y)%Q for x,y in zip(b,f)]
    cp=[0]*CELLS;trace=hashlib.sha256(b'TRNM-PON-TRACE1\0'+c)
    for i0 in range(0,N,R):
        for j0 in range(0,N,R):
            for k0 in range(0,N,R):
                tile=[]
                for i in range(i0,i0+R):
                    for j in range(j0,j0+R):
                        pos=i*N+j;cp[pos]=(cp[pos]+sum(aa[i*N+k]*bb[k*N+j]for k in range(k0,k0+R)))%Q;tile.append(cp[pos])
                trace.update(field_bytes(tile))
    c1=mm(mm(a,fl,N,N,R),fr,N,R,N);c2=mm(el,mm(er,bb,R,N,N),N,R,N)
    product=[(x-y-z)%Q for x,y,z in zip(cp,c1,c2)]
    return product,trace.digest()
def prove(c,a,b):
    product,trace=evaluate(c,a,b)
    return b'PNW1'+field_bytes(a)+field_bytes(b)+field_bytes(product)+trace
def verify(c,task,target,proof):
    if len(proof)!=PROOF_BYTES:raise ValueError('LENGTH')
    if proof[:4]!=b'PNW1':raise ValueError('VERSION')
    values=list(struct.unpack('<'+'I'*(3*CELLS),proof[4:-32]));a,b,p=values[:CELLS],values[CELLS:2*CELLS],values[2*CELLS:]
    check(p)
    if task_id(a,b)!=task:raise ValueError('TASK')
    ticket=H('ticket',c,proof[-32:])
    if len(target)!=32 or target==bytes(32)or ticket>target:raise ValueError('TARGET')
    product,trace=evaluate(c,a,b)
    if trace!=proof[-32:]:raise ValueError('TRANSCRIPT')
    if p!=product:raise ValueError('PRODUCT')
    return ticket,product
