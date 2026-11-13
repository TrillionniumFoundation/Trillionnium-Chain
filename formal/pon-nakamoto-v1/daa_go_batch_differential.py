"""Independent Go/Python ASERT research comparison, NOT native PoN qualification.

Runs an exact bounded JSONL Go program; no shell or network. Every sample uses
one of two independently implemented integer/overflow paths and a frozen seed.
The emitted JSON attests observations only on the named local binaries/sources.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
from daa_research_oracle import asert_target, UINT64_MAX

CAP=(1<<255)-1

def sample_inputs(seed:int, count:int)->list[dict]:
    rng=random.Random(seed)
    samples=[]
    half_lives=[1,2,10,100,3600,7200,14400,28800,UINT64_MAX]
    for i in range(count):
        h=2+rng.randrange(200000)
        anchor_height=rng.randrange(1,h)
        anchor_parent=rng.choice([0,1,1000000,UINT64_MAX,*[rng.getrandbits(64) for _ in range(2)]])
        spacing=rng.choice([1,10,60,600,UINT64_MAX])
        ideal=(h-anchor_height)*spacing
        # Include extreme time clocks and many realistic near-cadence cases.
        parent=rng.choice([
            0,UINT64_MAX,anchor_parent,
            min(UINT64_MAX,max(0,anchor_parent+ideal+rng.randint(-50000,50000))),
            rng.getrandbits(64),rng.randrange(1<<32)
        ])
        power=1<<rng.randint(0,253)
        anchor_target=rng.choice([1,2,3,123456789,power,CAP])
        samples.append({
           'anchor_target':str(anchor_target),
           'anchor_parent_time':anchor_parent,
           'evaluation_parent_time':parent,
           'anchor_height':anchor_height,
           'candidate_height':h,
           'spacing':spacing,
           'half_life':half_lives[i%len(half_lives)],
           'pow_limit':str(CAP)
        })
    return samples

def negative_inputs(seed: int, count: int) -> list[dict]:
    rng=random.Random(seed ^ 0xFA17DAA)
    rows=[]
    for i in range(count):
        row=sample_inputs(rng.randrange(1<<30),1)[0]
        kind=i%8
        if kind==0: row['anchor_target']='0'
        if kind==1: row['pow_limit']='0'
        if kind==2: row['anchor_target']=str(CAP+1)
        if kind==3: row['anchor_height']=row['candidate_height']
        if kind==4: row['spacing']=0
        if kind==5: row['half_life']=0
        if kind==6:
            row['candidate_height']=UINT64_MAX
            row['anchor_height']=1
            row['spacing']=UINT64_MAX
        if kind==7:
            row['candidate_height']=UINT64_MAX
            row['anchor_height']=1
            row['spacing']=1<<62
        rows.append(row)
    return rows

def run(go_binary:Path,seed:int,count:int,output:Path|None)->dict:
    if not 1<=count<=100000:raise ValueError('SAMPLE_COUNT')
    vectors=sample_inputs(seed,count)
    payload=b''.join(json.dumps(x,sort_keys=True,separators=(',',':')).encode()+b'\n' for x in vectors)
    exe=go_binary.resolve(strict=True)
    p=subprocess.run([str(exe)],input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,check=True)
    lines=p.stdout.splitlines()
    if len(lines)!=len(vectors):raise AssertionError('GO_RESULT_COUNT')
    result_digest=hashlib.sha256()
    reasons={}
    for i,(data,raw) in enumerate(zip(vectors,lines)):
        obj=json.loads(raw)
        try:
            expected=asert_target(int(data['anchor_target']),data['anchor_parent_time'],data['evaluation_parent_time'],data['anchor_height'],data['candidate_height'],data['spacing'],data['half_life'],int(data['pow_limit']))
        except ValueError:
            if 'error' not in obj:raise AssertionError(f'{i} PYTHON_REJECT_GO_ACCEPT {obj}')
            label='both-rejected'
        else:
            actual=obj.get('target')
            if actual!=f'{expected:064x}':raise AssertionError(f'{i} target mismatch got={actual} expected={expected:064x} input={data}')
            label='both-accepted'
        reasons[label]=reasons.get(label,0)+1
        result_digest.update(i.to_bytes(4,'big'))
        result_digest.update(hashlib.sha256(json.dumps(data,sort_keys=True).encode()).digest())
        result_digest.update(hashlib.sha256(raw).digest())
    negative=negative_inputs(seed,max(128,min(1024,count//8)))
    negative_payload=b''.join(json.dumps(x,sort_keys=True,separators=(',',':')).encode()+b'\n' for x in negative)
    negative_process=subprocess.run([str(exe)],input=negative_payload,stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,timeout=120,check=True)
    negative_output=negative_process.stdout.splitlines()
    if len(negative_output)!=len(negative):raise AssertionError('GO_NEGATIVE_COUNT')
    for i,(data,raw) in enumerate(zip(negative,negative_output)):
        try:
            asert_target(int(data['anchor_target']),data['anchor_parent_time'],data['evaluation_parent_time'],data['anchor_height'],data['candidate_height'],data['spacing'],data['half_life'],int(data['pow_limit']))
        except ValueError:
            pass
        else:
            raise AssertionError(f'negative {i} unexpectedly accepted by Python')
        if 'error' not in json.loads(raw):
            raise AssertionError(f'negative {i} unexpectedly accepted by Go')
    report={'schema':'trnm-daa-independent-go-python-v1','research_only':True,
            'source_identity':'local-run-not-exact-GitHub-Rust-checkout','seed':seed,
            'sample_count':count,'negative_count':len(negative),
            'negative_digest':hashlib.sha256(negative_payload+negative_process.stdout).hexdigest(),'matches':reasons,'vector_digest':hashlib.sha256(payload).hexdigest(),
            'result_digest':result_digest.hexdigest(),
            'limitations':['no native Rust test executed','no W1 PoW','no authenticated chain ancestry','no WAN or operator independence','no consensus activation']}
    if output:
        output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--go-binary',type=Path,required=True)
    parser.add_argument('--seed',type=int,default=20261026)
    parser.add_argument('--count',type=int,default=8192)
    parser.add_argument('--output',type=Path)
    a=parser.parse_args()
    print(json.dumps(run(a.go_binary,a.seed,a.count,a.output),sort_keys=True))
