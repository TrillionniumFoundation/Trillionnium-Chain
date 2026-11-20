"""Deterministic fixture inputs; no fixture algorithm runs in the native owner."""
from __future__ import annotations
from functools import lru_cache
import hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
P=(1<<255)-19
L=(1<<252)+27742317777372353535851937790883648493
D=-121665*pow(121666,-1,P)%P
B=(15112221349535400772501151409588531511454012693041857206046113283949847762202,
   4*pow(5,-1,P)%P,1,0)
B=(B[0],B[1],1,B[0]*B[1]%P)
I=(0,1,1,0)
SEED=bytes([17])*32
def H(tag,*parts):
    return hashlib.sha256(b"TRNM-PON1\0"+struct.pack("<H",len(tag))+tag+
      b"".join(struct.pack("<I",len(part))+part for part in parts)).digest()
def add(p,q):
    x,y,z,t=p;xx,yy,zz,tt=q
    a=(y-x)*(yy-xx)%P;b=(y+x)*(yy+xx)%P;c=2*D*t*tt%P;d=2*z*zz%P
    e,f,g,h=b-a,d-c,d+c,b+a
    return e*f%P,g*h%P,f*g%P,e*h%P
def multiply(k,p):
    answer=I
    while k:
        if k&1:answer=add(answer,p)
        p=add(p,p);k>>=1
    return answer
def encode(p):
    x,y,z,_=p;z=pow(z,-1,P);x=x*z%P;y=y*z%P
    return (y|((x&1)<<255)).to_bytes(32,"little")
@lru_cache(maxsize=1)
def signing_material():
    expanded=hashlib.sha512(SEED).digest()
    scalar=(int.from_bytes(expanded[:32],"little")&((1<<254)-8))|(1<<254)
    return expanded,scalar,encode(multiply(scalar,B))
def sign(message):
    expanded,scalar,public=signing_material()
    r=int.from_bytes(hashlib.sha512(expanded[32:]+message).digest(),"little")%L
    r_bytes=encode(multiply(r,B))
    k=int.from_bytes(hashlib.sha512(r_bytes+public+message).digest(),"little")%L
    return r_bytes+((r+k*scalar)%L).to_bytes(32,"little")
@lru_cache(maxsize=1)
def network():
    params=json.loads((ROOT/"config/pon/devnet-v1.json").read_bytes())
    return H(b"network",params["chain_label"].encode())
@lru_cache(maxsize=2048)
def wire(tag,payload,*,nonce=1,fee=10000000,expiry=(1<<64)-1,net=None):
    if net is None:net=network()
    raw=b"PNX1"+net+signing_material()[2]+struct.pack("<QQQBH",nonce,expiry,fee,tag,len(payload))+payload
    return raw+sign(H(b"tx-sign",raw))
def payloads():
    fixed={1:40,2:80,3:32,4:64,5:64,6:176,7:104,10:112,11:136,12:32,
           13:652,14:96,15:168,17:128,18:344,19:344,20:144,21:684,22:1028}
    for tag,size in fixed.items():yield "fixed-"+str(tag),tag,bytes([tag])*size
    for count in (1,2,16):
        payload=bytearray(145+count*40);payload[144]=count
        for i in range(count):payload[145+i*40:177+i*40]=i.to_bytes(32,"big")
        yield "alloc-"+str(count),8,bytes(payload)
    for count in (0,1,8):yield "task-path-"+str(count),9,bytes(72)+bytes([count])+bytes(32*count)
    for a,b in ((159,159),(159,512),(512,159),(512,512)):
        yield "equivocation-"+str(a)+"-"+str(b),16,bytes(32)+struct.pack("<H",a)+bytes(a)+struct.pack("<H",b)+bytes(b)
    for rank in (1,2):
        p=bytearray(242+520*rank);p[:6]=b"ILF2\x02\0";p[6]=rank;p[8:10]=b"\0\x04"
        yield "factor-"+str(rank),23,bytes(p)
    for ranks in ((),(1,),(2,),(1,2),(1,1,1)):
        p=bytearray(242);p[:6]=b"ILF3\x03\0";p[6]=7;p[7]=len(ranks);p[8:10]=b"\0\x04"
        for target,rank in enumerate(ranks):p.extend(bytes([target,rank])+bytes(520*rank))
        yield "evolution-"+"-".join(map(str,ranks)),24,bytes(p)
    yield "funded-reservation",2,b"TSC1"+b"t"*32+b"".join(bytes([i])*32 for i in range(1,11))+struct.pack("<QQQ",7,11,13)
    for verdict in (1,2):
        yield "funded-decision-"+str(verdict),5,b"TSD1"+b"t"*32+b"c"*32+b"o"*32+b"e"*32+bytes([verdict])
def row(name,raw,height=10):
    return {"name":name,"height":height,"wire_hex":raw.hex()}
def cases():
    # A complete retained grammar table, including profiles rejected only after decode.
    for label,tag,payload in payloads():
        good=wire(tag,payload)
        yield row(label,good)
        yield row(label+"-truncated",good[:-1])
        yield row(label+"-extra",good+b"\0")
        yield row(label+"-payload-short",wire(tag,payload[:-1]))
        yield row(label+"-payload-long",wire(tag,payload+b"\0"))
        yield row(label+"-bad-net-expired-sig",wire(tag,payload,net=bytes(32),expiry=0)[:-64]+bytes(64))
        yield row(label+"-zero-nonce-high-fee",wire(tag,payload,nonce=0,fee=(1<<64)-1))
    good=wire(1,bytes([1])*40)
    for tag in range(256):
        p=bytearray(good);p[92]=tag
        yield row("all-tag-"+str(tag),bytes(p))
    for length in (0,1,3,4,35,36,67,68,75,76,83,84,91,92,93,94,95,158,159,198,199,200,2047,2048,2049,65537):
        yield row("raw-length-"+str(length),(good+bytes(max(0,length-len(good))))[:length])
    for nonce in (0,1,(1<<64)-1):
        for fee in (0,1,10000000,10000001,(1<<64)-1):
            yield row("nonce-fee-"+str(nonce)+"-"+str(fee),wire(1,bytes(40),nonce=nonce,fee=fee))
    for height in (0,1,9,10,11,(1<<64)-2,(1<<64)-1):
        for expiry in (0,10,(1<<64)-1):
            yield row("height-expiry-"+str(height)+"-"+str(expiry),wire(1,bytes(40),expiry=expiry),height)
    # Every sender byte and signature byte crosses the actual strict owner.
    for position in list(range(36,68))+list(range(len(good)-64,len(good))):
        changed=bytearray(good);changed[position]^=1
        yield row("strict-byte-"+str(position),bytes(changed))
    for value in (0,1,P-1,P,(1<<255)-1,1|(1<<255),(P-1)|(1<<255),(1<<256)-1):
        point=value.to_bytes(32,"little")
        changed=bytearray(good);changed[36:68]=point
        yield row("public-point-"+str(value),bytes(changed))
        changed=bytearray(good);changed[-64:-32]=point
        yield row("signature-point-"+str(value),bytes(changed))
    for value in (0,1,L-1,L,L+1,(1<<256)-1):
        yield row("scalar-"+str(value),good[:-32]+value.to_bytes(32,"little"))
    for position in (0,1,2,3,93,94):
        changed=bytearray(good);changed[position]^=1
        yield row("framing-"+str(position),bytes(changed))
    # Valid recovery after several previous successes/rejections in this same owner.
    for i in range(8):
        yield row("reused-owner-"+str(i),wire(1,bytes([i])*40,nonce=i+1,fee=10000000,expiry=99),99)
def corpus_bytes():
    rows=list(cases())
    names=[r["name"] for r in rows]
    if len(names)!=len(set(names)):raise ValueError("Duplicate canonical fixture")
    return b"".join(json.dumps(r,sort_keys=True,separators=(",",":")).encode()+b"\n" for r in rows)
