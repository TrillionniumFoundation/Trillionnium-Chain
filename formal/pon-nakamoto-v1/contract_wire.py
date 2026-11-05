"""Separately coded Python wire oracle. No native-code call is used to derive bytes.
Public schemas in config/pon are loaded strictly; unsigned/decoded records are not authority.
"""
from __future__ import annotations
from pathlib import Path
import hashlib,json,struct,os
ROOT=Path(__file__).resolve().parents[2]

def unique(pairs):
    d={}
    for k,v in pairs:
        if k in d:raise ValueError('duplicate JSON key')
        d[k]=v
    return d

def read_config(path):
    return json.loads((ROOT/path).read_text(),object_pairs_hook=unique)
SCHEMA=read_config('config/pon/ledger-v1.json')
WORK_PROFILE=read_config('config/pon/work-profile-v1.json')
MODEL_FAMILY=read_config('config/pon/model-family-v1.json')
COMMANDS={row['tag']:row for row in SCHEMA['commands']}
NAMES={row['name']:row['tag'] for row in SCHEMA['commands']}

def canonical(value):
    def visit(x):
        if x is None or isinstance(x,(str,bool)):return
        if type(x)is int:
            if not -(1<<63)<=x<(1<<64):raise ValueError('integer range')
            return
        if isinstance(x,list):
            for v in x:visit(v)
            return
        if isinstance(x,dict)and all(isinstance(k,str)for k in x):
            for v in x.values():visit(v)
            return
        raise ValueError('unsupported canonical value')
    visit(value)
    return json.dumps(value,ensure_ascii=True,separators=(',',':'),sort_keys=True).encode()

def H(tag,*parts):
    if isinstance(tag,str):tag=tag.encode()
    h=hashlib.sha256(b'TRNM-PON1\0'+struct.pack('<H',len(tag))+tag)
    for p in parts:h.update(struct.pack('<I',len(p)));h.update(p)
    return h.digest()
def development_parameters(policy="legacy-first-two-v3"):
    params = read_config('config/pon/devnet-v1.json')
    if policy == "legacy-first-two-v3":
        return params
    if policy != "closed-round-all-eligible-min-v1":
        raise ValueError("EVALUATION_POLICY")
    rule = read_config('config/pon/evaluation-round-v1.json')
    if rule['id'] != policy or rule['production_activation'] is not False:
        raise ValueError("EVALUATION_POLICY")
    params.update(rule['genesis_overrides'])
    params['evaluation_policy_hash'] = H('evaluation-policy', canonical(rule)).hex()
    return params

# Explicit process-start experimental selection; never switch a running ledger or
# rewrite an existing namespace. The native CLI requires its own matching option.
PARAMS=development_parameters(os.environ.get('TRNM_PON_EVALUATION_POLICY', 'legacy-first-two-v3'))
NETWORK=H('network',PARAMS['chain_label'].encode())
PARAMETER_HASH=H('parameters',canonical(PARAMS),canonical(SCHEMA),canonical(WORK_PROFILE),canonical(MODEL_FAMILY))

def u64(n):
    if type(n)is not int or not 0<=n<1<<64:raise ValueError('u64 range')
    return struct.pack('<Q',n)

def fixed(h):
    if isinstance(h,str):
        if len(h)!=64 or h!=h.lower():raise ValueError('hash encoding')
        h=bytes.fromhex(h)
    if not isinstance(h,bytes)or len(h)!=32:raise ValueError('hash size')
    return h

def header_encode(h):
    if set(h)!={x['name']for x in SCHEMA['header']}:raise ValueError('header fields')
    return b'PNH1'+struct.pack('<H',1)+b''.join(fixed(h[f['name']]) if f['type']=='hash32' else u64(h[f['name']]) for f in SCHEMA['header'])

def header_decode(b):
    if len(b)!=318:raise ValueError('LENGTH')
    if b[:6]!=b'PNH1\x01\x00':raise ValueError('VERSION')
    out={};pos=6
    for f in SCHEMA['header']:
        n=32 if f['type']=='hash32' else 8
        out[f['name']]=b[pos:pos+n] if n==32 else struct.unpack_from('<Q',b,pos)[0];pos+=n
    return out

def payload_encode(tag,fields):
    if tag not in COMMANDS:raise ValueError('VERSION')
    schema=COMMANDS[tag]['payload']
    if set(fields)!={f['name']for f in schema}:raise ValueError('payload fields')
    out=b''
    for f in schema:
        v=fields[f['name']];kind=f['type']
        if kind=='hash32':out+=fixed(v)
        elif kind=='u64':out+=u64(v)
        elif kind=='sig64':
            if len(v)!=64:raise ValueError('signature length')
            out+=v
        elif kind=='allocation16':
            if not 1<=len(v)<=16 or [x[0]for x in v]!=sorted(set(x[0]for x in v)):raise ValueError('allocation ordering/count')
            out+=bytes([len(v)])+b''.join(fixed(cid)+u64(score)for cid,score in v)
        elif kind=='proof8':
            if len(v)>8:raise ValueError('LIMIT')
            out+=bytes([len(v)])+b''.join(fixed(x)for x in v)
        else:raise ValueError('unknown field type')
    return out

def payload_decode(tag,b):
    if tag not in COMMANDS:raise ValueError('VERSION')
    pos=0;fields={}
    for f in COMMANDS[tag]['payload']:
        kind=f['type']
        if kind=='allocation16':
            if pos==len(b)or not 1<=b[pos]<=16:raise ValueError('LIMIT')
            count=b[pos];pos+=1;end=pos+40*count
            if end>len(b):raise ValueError('LENGTH')
            v=[(b[p:p+32],struct.unpack_from('<Q',b,p+32)[0])for p in range(pos,end,40)];pos=end
            if [x[0]for x in v]!=sorted(set(x[0]for x in v)):raise ValueError('NONCANONICAL')
        elif kind=='proof8':
            if pos==len(b)or b[pos]>8:raise ValueError('LIMIT')
            count=b[pos];pos+=1;end=pos+32*count
            if end>len(b):raise ValueError('LENGTH')
            v=[b[p:p+32]for p in range(pos,end,32)];pos=end
        else:
            n={'hash32':32,'sig64':64,'u64':8}[kind];end=pos+n
            if end>len(b):raise ValueError('LENGTH')
            v=struct.unpack_from('<Q',b,pos)[0]if kind=='u64'else b[pos:end];pos=end
        fields[f['name']]=v
    if pos!=len(b):raise ValueError('LENGTH')
    return fields

def tx_unsigned(network,sender,nonce,expiry,fee_limit,tag,fields):
    if nonce==0 or fee_limit>PARAMS['max_fee_limit']:raise ValueError('NONCANONICAL')
    p=payload_encode(tag,fields)
    return b'PNX1'+fixed(network)+fixed(sender)+u64(nonce)+u64(expiry)+u64(fee_limit)+bytes([tag])+struct.pack('<H',len(p))+p

def tx_decode(b):
    if len(b)>PARAMS['max_transaction_bytes']:raise ValueError('LIMIT')
    if len(b)<159:raise ValueError('LENGTH')
    if b[:4]!=b'PNX1':raise ValueError('VERSION')
    nonce,expiry,fee_limit=struct.unpack_from('<QQQ',b,68);tag=b[92];n=struct.unpack_from('<H',b,93)[0]
    if len(b)!=159+n:raise ValueError('LENGTH')
    if nonce==0 or fee_limit>PARAMS['max_fee_limit']:raise ValueError('NONCANONICAL')
    f=payload_decode(tag,b[95:95+n])
    return dict(network=b[4:36],sender=b[36:68],nonce=nonce,expiry=expiry,fee_limit=fee_limit,tag=tag,fields=f,signature=b[-64:],unsigned=b[:-64])

def state_root(values):
    if len(values)>PARAMS['max_state_keys']:raise ValueError('LIMIT')
    nodes={}
    for key,value in values.items():
        if isinstance(key,str):key=key.encode()
        if not isinstance(value,bytes):value=canonical(value)
        if len(key)>160 or len(value)>4096:raise ValueError('LIMIT')
        index=int.from_bytes(H('state-key',key),'big')
        if index in nodes:raise ValueError('collision')
        nodes[index]=H('state-leaf',key,value)
    empty=H('state-empty')
    # Bottom-up by integer path is independent of Rust's top-down partition implementation.
    for _ in range(256):
        parents={}
        for index in {i>>1 for i in nodes}:
            parents[index]=H('state-node',nodes.get(index*2,empty),nodes.get(index*2+1,empty))
        nodes=parents;empty=H('state-node',empty,empty)
    return nodes.get(0,empty)

def sequence_root(tag,items):
    leaves=[H(tag+'-leaf',u64(i),b)for i,b in enumerate(items)]
    if not leaves:return H(tag+'-empty')
    while len(leaves)>1:
        if len(leaves)%2:leaves.append(leaves[-1])
        leaves=[H(tag+'-node',a,b)for a,b in zip(leaves[::2],leaves[1::2])]
    return leaves[0]

def allocation_leaf(contribution,payee,score):return H('allocation-leaf',fixed(contribution),fixed(payee),u64(score))
def allocation_root_and_proofs(rows):
    if len(rows)>256 or not rows:raise ValueError('allocation count')
    rows=sorted(rows,key=lambda r:r[0]);leaves=[allocation_leaf(*r)for r in rows];proofs=[[]for _ in leaves];groups=[[i]for i in range(len(leaves))]
    while len(leaves)>1:
        if len(leaves)%2:leaves.append(leaves[-1]);groups.append([])
        out=[];newgroups=[]
        for i in range(0,len(leaves),2):
            a,b=leaves[i:i+2]
            for member in groups[i]:proofs[member].append(b)
            for member in groups[i+1]:proofs[member].append(a)
            # Sorted pairs make inclusion proof order-independent, not allocation order-dependent.
            out.append(H('allocation-node',min(a,b),max(a,b)));newgroups.append(groups[i]+groups[i+1])
        leaves=out;groups=newgroups
    return leaves[0],{row[0]:proof for row,proof in zip(rows,proofs)}
def allocation_check(leaf,proof,root):
    if len(proof)>8:return False
    for sibling in proof:leaf=H('allocation-node',min(leaf,sibling),max(leaf,sibling))
    return leaf==root
