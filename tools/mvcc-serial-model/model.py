#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass
import argparse, hashlib, json, random

class Reject(ValueError): pass
MAX_U128=(1<<128)-1

@dataclass(frozen=True)
class Object:
    version:int
    value:int

@dataclass(frozen=True)
class Tx:
    index:int
    reads:tuple[str,...]
    target:str
    delta:int
    payer:str
    resource_limit:int
    force_revert:bool=False

@dataclass
class Result:
    index:int
    outcome:str
    read_versions:dict[str,int]
    write_version:int|None
    write_value:int|None
    resources:dict[str,int]
    fee:int
    reexecuted:bool=False

PRICES={"compute":3,"state_read":2,"state_write":5,"tx_da":1}

def checked_add(a:int,b:int)->int:
    value=a+b
    if value<0 or value>MAX_U128: raise Reject("arithmetic-overflow")
    return value

def root(label:str,value:object)->str:
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),default=lambda x:x.__dict__).encode()
    return hashlib.sha256(label.encode()+b"\x00"+raw).hexdigest()

def execute(tx:Tx,state:dict[str,Object])->Result:
    ids=tuple(dict.fromkeys(tx.reads+(tx.target,)))
    if any(i not in state for i in ids): raise Reject("unknown-object")
    versions={i:state[i].version for i in ids}
    resources={"compute":1+len(ids),"state_read":len(ids),"state_write":1,"tx_da":len(json.dumps(tx.__dict__,sort_keys=True,default=list).encode())}
    units=sum(resources.values())
    fee=0
    for key,value in resources.items(): fee=checked_add(fee,value*PRICES[key])
    if units>tx.resource_limit:
        return Result(tx.index,"OutOfResource",versions,None,None,resources,fee)
    if tx.force_revert:
        return Result(tx.index,"Reverted",versions,None,None,resources,fee)
    read_sum=sum(state[i].value for i in tx.reads)
    target=state[tx.target]
    value=checked_add(target.value,checked_add(tx.delta,read_sum))
    return Result(tx.index,"Success",versions,target.version+1,value,resources,fee)

def apply(result:Result,tx:Tx,state:dict[str,Object])->None:
    if result.outcome=="Success":
        prior=state[tx.target]
        if result.write_version!=prior.version+1: raise Reject("write-version")
        state[tx.target]=Object(result.write_version,result.write_value)

def run_block(parent:dict[str,Object],txs:list[Tx],schedule:list[int],workers:int)->dict:
    if workers<=0: raise Reject("workers")
    if sorted(schedule)!=list(range(len(txs))): raise Reject("schedule")
    speculative={idx:execute(txs[idx],parent) for idx in schedule}
    state=dict(parent); receipts=[]; totals={k:0 for k in PRICES}; deltas=[]
    for tx in sorted(txs,key=lambda x:x.index):
        result=speculative[tx.index]
        if any(state[obj].version!=version for obj,version in result.read_versions.items()):
            result=execute(tx,state); result.reexecuted=True
        apply(result,tx,state)
        for key,value in result.resources.items(): totals[key]=checked_add(totals[key],value)
        deltas.append((tx.payer,-result.fee)); deltas.append(("fee-pool",result.fee))
        receipts.append(result)
    reduced={}
    for account,delta in sorted(deltas): reduced[account]=reduced.get(account,0)+delta
    if sum(reduced.values())!=0: raise Reject("fee-conservation")
    state_view={k:{"version":v.version,"value":v.value} for k,v in sorted(state.items())}
    receipt_view=[r.__dict__ for r in receipts]
    return {"state":state_view,"receipts":receipt_view,"resources":totals,"fee_deltas":reduced,
            "state_root":root("state",state_view),"receipt_root":root("receipt",receipt_view),
            "resource_root":root("resource",totals),"fee_root":root("fees",reduced),"workers":workers}

def corpus(seed:int)->tuple[dict[str,Object],list[Tx]]:
    rnd=random.Random(seed)
    parent={name:Object(0,rnd.randint(1,20)) for name in "abcd"}
    txs=[
        Tx(0,("a",),"b",1,"payer-0",200),
        Tx(1,("b",),"c",2,"payer-1",200),
        Tx(2,("a",),"d",3,"payer-2",200),
        Tx(3,("c",),"a",4,"payer-3",200),
        Tx(4,("d",),"b",5,"payer-4",2),
        Tx(5,("a",),"c",6,"payer-5",200,True),
    ]
    return parent,txs

def comparable(result:dict)->dict:
    return {k:v for k,v in result.items() if k!="workers"}

def self_test()->dict:
    runs=0; reexec=0
    for seed in range(32):
        parent,txs=corpus(seed); expected=None
        for workers in (1,2,4,8):
            for variant in range(4):
                schedule=list(range(len(txs))); random.Random(seed*100+workers*10+variant).shuffle(schedule)
                result=run_block(parent,txs,schedule,workers); view=comparable(result)
                if expected is None: expected=view
                elif view!=expected: raise Reject("serial-equivalence-drift")
                reexec+=sum(1 for r in result["receipts"] if r["reexecuted"]); runs+=1
        assert expected["receipts"][4]["outcome"]=="OutOfResource"
        assert expected["receipts"][5]["outcome"]=="Reverted"
        assert sum(expected["fee_deltas"].values())==0
    negatives=[]
    parent,txs=corpus(1)
    def reject(name,fn):
        try: fn()
        except Reject as exc: negatives.append({"case":name,"error":str(exc)})
        else: raise AssertionError(f"accepted:{name}")
    reject("bad-worker-count",lambda:run_block(parent,txs,list(range(6)),0))
    reject("bad-schedule",lambda:run_block(parent,txs,[0,1,2,3,4,4],2))
    huge=[Tx(0,("a",),"b",MAX_U128,"payer",200)]
    reject("arithmetic-overflow",lambda:run_block(parent,huge,[0],1))
    missing=[Tx(0,("missing",),"b",1,"payer",200)]
    reject("undeclared-missing-object",lambda:run_block(parent,missing,[0],1))
    return {"schema":"trnm-mvcc-serial-equivalence-evidence-v1","runs":runs,"reexecutions":reexec,
            "worker_counts":[1,2,4,8],"seeds":32,"negative":negatives,"candidate_only":True,"jmt_authority":False,"settlement_authority":False}

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--self-test",action="store_true"); a=p.parse_args()
    if not a.self_test: raise SystemExit("use --self-test")
    print(json.dumps(self_test(),sort_keys=True,separators=(",",":"))); return 0
if __name__=="__main__": raise SystemExit(main())
