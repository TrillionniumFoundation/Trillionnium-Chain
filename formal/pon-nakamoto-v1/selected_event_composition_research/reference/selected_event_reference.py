#!/usr/bin/env python3
"""Experimental selected LOCAL product v1, not W1 and not qualified PoW.

Fixed F_q, N=64, r=8. Fully verifies two authenticated original input blocks,
nonce-dependent rank-8 noise blocks, one noisy local block product, and the
corresponding original useful local block product. No claim about the other
511 local products, cumulative W1 trace, a full matrix, or a model decision.

One coordinate is selected from the context-bound nonce seed, with a separate
hash domain. A prover cannot choose another coordinate for that same seed.
Nonce grinding and cheap selector filtering remain possible; neither this
selection rule nor nonce-dependent noise establishes a minimum work cost.
"""
from dataclasses import dataclass
from hashlib import sha256

Q = 4294967291
N = 64
R = 8
DOMAIN = b'TRNM-PON-SELECTED-EVENT-RESEARCH-R1\x00'
PROFILE = b'local-product8-fq4294967291-n64-r8-selected-v1'

class Refusal(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise Refusal(reason)

def H(tag, *parts):
    need(type(tag) is bytes and len(tag)<256, 'HASH_TAG')
    h=sha256(DOMAIN+bytes([len(tag)])+tag)
    for value in parts:
        need(type(value) is bytes and len(value)<2**32, 'HASH_PART')
        h.update(len(value).to_bytes(4,'little')); h.update(value)
    return h.digest()

def words(a):
    need(type(a) in (tuple,list) and len(a)==64, 'BLOCK_LENGTH')
    need(all(type(x) is int and 0<=x<Q for x in a), 'FIELD')
    return b''.join(x.to_bytes(4,'little') for x in a)

def block_mul(a,b):
    words(a);words(b)
    return tuple(sum(a[i*R+k]*b[k*R+j] for k in range(R))%Q
                 for i in range(R) for j in range(R))

def block_add(a,b):
    return tuple((x+y)%Q for x,y in zip(a,b))

def leaf(label,index,block):
    need(label in (b'A',b'B') and type(index) is int and 0<=index<64,'LEAF_ID')
    return H(b'leaf',PROFILE,label,bytes([index]),words(block))

def tree(label,blocks):
    need(type(blocks) in (tuple,list) and len(blocks)==64,'MATRIX_BLOCKS')
    levels=[[leaf(label,i,b) for i,b in enumerate(blocks)]]
    for level in range(6):
        prev=levels[-1]
        levels.append([H(b'node',PROFILE,label,bytes([level]),prev[i],prev[i+1])
                       for i in range(0,len(prev),2)])
    return levels

def opening(levels,index):
    path=[]
    for level in range(6):
        path.append(levels[level][index^1]);index//=2
    return tuple(path)

def check_opening(root,label,index,block,path):
    need(type(path) in (tuple,list) and len(path)==6,'PATH_LENGTH')
    digest=leaf(label,index,block)
    for level,sibling in enumerate(path):
        need(type(sibling) is bytes and len(sibling)==32,'PATH_HASH')
        left,right=(digest,sibling) if index%2==0 else (sibling,digest)
        digest=H(b'node',PROFILE,label,bytes([level]),left,right)
        index//=2
    need(digest==root,'MERKLE')

def task_id(root_a,root_b):
    return H(b'task',PROFILE,root_a,root_b)

@dataclass(frozen=True)
class Expected:
    # The caller must retain these independently; task eligibility before the
    # parent challenge and live chain authority are outside this reference.
    chain:bytes
    parent:bytes
    header_without_work:bytes
    root_a:bytes
    root_b:bytes
    target:bytes
    def validate(self):
        need(all(type(x) is bytes and len(x)==32 for x in
          (self.chain,self.parent,self.header_without_work,self.root_a,self.root_b,self.target)), 'CONTEXT')
        need(self.target!=bytes(32),'TARGET_ZERO')
    def commitment(self):
        self.validate()
        return H(b'context',PROFILE,self.chain,self.parent,self.header_without_work,
                 task_id(self.root_a,self.root_b),self.target)

@dataclass(frozen=True)
class Witness:
    nonce:int
    bi:int
    bk:int
    bj:int
    a:tuple
    b:tuple
    path_a:tuple
    path_b:tuple
    noisy_product:tuple
    useful_product:tuple

@dataclass(frozen=True)
class VerifiedSelectedEvent:
    # This is NOT VerifiedWork or VerifiedDecision.
    context:bytes
    event_id:bytes
    ticket:bytes
    useful_product:tuple


def seed(ctx,nonce):
    need(type(nonce) is int and 0<=nonce<2**64,'NONCE')
    return H(b'noise-seed',ctx.commitment(),nonce.to_bytes(8,'little'))

def selected_coordinates(s):
    """Exactly one of 8^3 local products for this context-bound nonce seed.

    Three independent byte positions, each masked by 7. Since 8 divides 256,
    each coordinate is unbiased under a uniform hash; no retry rule is needed.
    The selector has a distinct hash tag from the seed and noise draws.
    """
    need(type(s) is bytes and len(s)==32,'SELECTOR_SEED')
    raw=H(b'selected-coordinate',s)
    return tuple(x & 7 for x in raw[:3])

def noise_eight(s,label,index):
    """One aligned 8-value block of a fixed 512-value factor.

    Up to 128 SHA-256 digest calls; candidates are little-endian u32 and rejected >=q.
    Draw block labels and counters are canonical. No modulo bias or fallback.
    """
    need(label in range(4) and type(index) is int and 0<=index<64,'NOISE_COORD')
    out=[]
    for counter in range(128):
        raw=H(b'noise-eight',s,bytes([label,index]),counter.to_bytes(4,'little'))
        for k in range(0,32,4):
            x=int.from_bytes(raw[k:k+4],'little')
            if x<Q:
                out.append(x)
                if len(out)==8:
                    return tuple(out)
    raise Refusal('NOISE_BUDGET')

def noise_blocks(s,bi,bk,bj):
    el=sum((noise_eight(s,0,bi*8+i) for i in range(8)),())
    er=sum((noise_eight(s,1,i*8+bk) for i in range(8)),())
    fl=sum((noise_eight(s,2,bk*8+i) for i in range(8)),())
    fr=sum((noise_eight(s,3,i*8+bj) for i in range(8)),())
    return block_mul(el,er),block_mul(fl,fr)

def statement(ctx,w):
    # Canonical verified-event values only; randomized proof encodings are out.
    return H(b'event',ctx.commitment(),w.nonce.to_bytes(8,'little'),
             bytes([w.bi,w.bk,w.bj]),words(w.noisy_product),words(w.useful_product))

def verify(ctx,w):
    ctx.validate()
    need(type(w) is Witness,'WITNESS')
    need(all(type(i) is int and 0<=i<8 for i in (w.bi,w.bk,w.bj)),'TILE_COORD')
    s=seed(ctx,w.nonce)
    need((w.bi,w.bk,w.bj)==selected_coordinates(s),'SELECTED_COORD')
    words(w.a);words(w.b);words(w.noisy_product);words(w.useful_product)
    check_opening(ctx.root_a,b'A',w.bi*8+w.bk,w.a,w.path_a)
    check_opening(ctx.root_b,b'B',w.bk*8+w.bj,w.b,w.path_b)
    # Cheap claimed-ticket screening does not grant verification authority.
    eid=statement(ctx,w)
    ticket=H(b'ticket',eid)
    need(ticket<=ctx.target,'TARGET')
    e,f=noise_blocks(s,w.bi,w.bk,w.bj)
    need(block_mul(block_add(w.a,e),block_add(w.b,f))==w.noisy_product,'NOISY_PRODUCT')
    need(block_mul(w.a,w.b)==w.useful_product,'USEFUL_PRODUCT')
    return VerifiedSelectedEvent(ctx.commitment(),eid,ticket,w.useful_product)

def produce(ctx,nonce,blocks_a,blocks_b):
    s=seed(ctx,nonce)
    bi,bk,bj=selected_coordinates(s)
    ta=tree(b'A',blocks_a);tb=tree(b'B',blocks_b)
    need(ta[-1][0]==ctx.root_a and tb[-1][0]==ctx.root_b,'TASK_ROOT')
    a=tuple(blocks_a[bi*8+bk]);b=tuple(blocks_b[bk*8+bj])
    e,f=noise_blocks(s,bi,bk,bj)
    return Witness(nonce,bi,bk,bj,a,b,opening(ta,bi*8+bk),opening(tb,bk*8+bj),
                   block_mul(block_add(a,e),block_add(b,f)),block_mul(a,b))
