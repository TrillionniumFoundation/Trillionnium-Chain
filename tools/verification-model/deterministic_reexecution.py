#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass, field
import argparse, hashlib, json

class Reject(ValueError): pass


def h(label:str,*parts:object)->str:
    d=hashlib.sha256(); d.update(label.encode()+b"\x00")
    for part in parts:
        raw=str(part).encode(); d.update(len(raw).to_bytes(4,"big")); d.update(raw)
    return d.hexdigest()

@dataclass(frozen=True)
class Profile:
    profile_id:str
    version:int
    profile_hash:str
    profile_class:str
    enabled:bool
    valid_from:int
    expires_after:int
    revoked:bool=False

@dataclass(frozen=True)
class Receipt:
    task_id:str
    lease_id:str
    attempt:int
    runtime_digest:str
    input_commitment:str
    output_commitment:str
    seed:int
    trace_root:str
    profile_id:str
    profile_version:int
    profile_hash:str
    order_height:int
    order_block_id:str

@dataclass
class Challenge:
    challenger:str
    bond:int
    opened_height:int
    evidence:list[str]=field(default_factory=list)
    response:str|None=None
    status:str="open"

@dataclass
class Result:
    receipt:Receipt
    status:str="ResultPending"
    statement_digest:str|None=None
    challenge_deadline:int|None=None
    challenge:Challenge|None=None
    order_height:int=0
    order_block_id:str=""

class Registry:
    def __init__(self,profiles:list[Profile])->None:
        self.profiles={(p.profile_id,p.version):p for p in profiles}
    def resolve(self,pid:str,version:int,phash:str,height:int)->Profile:
        p=self.profiles.get((pid,version))
        if p is None: raise Reject("profile-unknown-no-fallback")
        if p.profile_hash!=phash: raise Reject("profile-hash")
        if not p.enabled: raise Reject("profile-disabled")
        if p.revoked or height<p.valid_from or height>p.expires_after: raise Reject("profile-expired-or-revoked")
        return p

def deterministic_execute(runtime_digest:str,input_commitment:str,seed:int)->tuple[str,str]:
    output=h("trnm.deterministic-reexecution.output.v1",runtime_digest,input_commitment,seed)
    trace=h("trnm.deterministic-reexecution.trace.v1",runtime_digest,input_commitment,seed,output)
    return output,trace

def evaluate(registry:Registry,result:Result,height:int,window:int,backend_available:bool=True)->None:
    r=result.receipt
    if result.status!="ResultPending": raise Reject("result-state")
    p=registry.resolve(r.profile_id,r.profile_version,r.profile_hash,height)
    if p.profile_class!="objective-deterministic": raise Reject("wrong-profile-class-no-fallback")
    required=[r.task_id,r.lease_id,r.runtime_digest,r.input_commitment,r.output_commitment,r.trace_root,r.order_block_id]
    if r.attempt<0 or not all(required): raise Reject("evidence-missing")
    if not backend_available: raise Reject("backend-unavailable")
    output,trace=deterministic_execute(r.runtime_digest,r.input_commitment,r.seed)
    if output!=r.output_commitment or trace!=r.trace_root: raise Reject("deterministic-mismatch")
    if window<=0: raise Reject("challenge-window")
    result.statement_digest=h("trnm.deterministic-reexecution.statement.v1",r)
    result.challenge_deadline=height+window
    result.status="ChallengeWindow"; result.order_height=r.order_height; result.order_block_id=r.order_block_id

def open_challenge(result:Result,challenger:str,bond:int,height:int)->None:
    if result.status!="ChallengeWindow" or result.challenge is not None: raise Reject("challenge-conflict")
    if result.challenge_deadline is None or height>result.challenge_deadline or bond<=0 or not challenger: raise Reject("challenge-invalid-or-late")
    result.challenge=Challenge(challenger,bond,height)

def add_evidence(result:Result,evidence_id:str)->None:
    if result.challenge is None or result.challenge.status!="open" or not evidence_id: raise Reject("challenge-evidence-state")
    if evidence_id in result.challenge.evidence: raise Reject("duplicate-evidence")
    result.challenge.evidence.append(evidence_id)

def respond(result:Result,response_digest:str)->None:
    if result.challenge is None or result.challenge.status!="open" or result.challenge.response is not None or not response_digest: raise Reject("challenge-response-state")
    result.challenge.response=response_digest

def adjudicate(result:Result,uphold:bool,height:int)->None:
    c=result.challenge
    if c is None or c.status!="open" or not c.evidence or c.response is None: raise Reject("challenge-not-ready")
    c.status="upheld" if uphold else "rejected"
    result.status="ResultRejected" if uphold else "ResultFinal"
    if result.order_height!=result.receipt.order_height or result.order_block_id!=result.receipt.order_block_id: raise Reject("order-rewrite")

def finalize_timeout(result:Result,height:int)->None:
    if result.status!="ChallengeWindow" or result.challenge is not None or result.challenge_deadline is None or height<=result.challenge_deadline: raise Reject("not-mature")
    result.status="ResultFinal"

def self_test()->dict:
    pid="deterministic-reexecution-v1"; ph=h("profile",pid,1)
    objective=Profile(pid,1,ph,"objective-deterministic",True,1,100)
    disabled=Profile("zk-v1",1,h("profile","zk-v1",1),"objective-cryptographic",False,1,100)
    subjective=Profile("subjective-v1",1,h("profile","subjective-v1",1),"subjective",True,1,100)
    reg=Registry([objective,disabled,subjective])
    output,trace=deterministic_execute("runtime-A","input-A",7)
    receipt=Receipt("task","lease",0,"runtime-A","input-A",output,7,trace,pid,1,ph,10,"block-10")
    no_challenge=Result(receipt); evaluate(reg,no_challenge,10,5); finalize_timeout(no_challenge,16); assert no_challenge.status=="ResultFinal"
    rejected=Result(receipt); evaluate(reg,rejected,10,5); open_challenge(rejected,"challenger",10,11); add_evidence(rejected,"e1"); respond(rejected,"r1"); adjudicate(rejected,True,12); assert rejected.status=="ResultRejected"
    accepted=Result(receipt); evaluate(reg,accepted,10,5); open_challenge(accepted,"challenger",10,11); add_evidence(accepted,"e1"); respond(accepted,"r1"); adjudicate(accepted,False,12); assert accepted.status=="ResultFinal"
    negatives=[]
    def reject(name,fn):
        try: fn()
        except Reject as exc: negatives.append({"case":name,"error":str(exc)})
        else: raise AssertionError(f"accepted:{name}")
    bad=Receipt(**{**receipt.__dict__,"output_commitment":"wrong"}); reject("output-mismatch",lambda:evaluate(reg,Result(bad),10,5))
    missing=Receipt(**{**receipt.__dict__,"trace_root":""}); reject("missing-evidence",lambda:evaluate(reg,Result(missing),10,5))
    unknown=Receipt(**{**receipt.__dict__,"profile_id":"unknown"}); reject("unknown-no-fallback",lambda:evaluate(reg,Result(unknown),10,5))
    zk=Receipt(**{**receipt.__dict__,"profile_id":"zk-v1","profile_hash":disabled.profile_hash}); reject("disabled-profile",lambda:evaluate(reg,Result(zk),10,5))
    sub=Receipt(**{**receipt.__dict__,"profile_id":"subjective-v1","profile_hash":subjective.profile_hash}); reject("subjective-objective-forbidden",lambda:evaluate(reg,Result(sub),10,5))
    reject("backend-unavailable",lambda:evaluate(reg,Result(receipt),10,5,False))
    late=Result(receipt); evaluate(reg,late,10,5); reject("late-challenge",lambda:open_challenge(late,"c",1,16))
    dup=Result(receipt); evaluate(reg,dup,10,5); open_challenge(dup,"c",1,11); reject("duplicate-challenge",lambda:open_challenge(dup,"d",1,11))
    reject("premature-finalize",lambda:finalize_timeout(Result(receipt,status="ChallengeWindow",challenge_deadline=15),15))
    return {"schema":"trnm-deterministic-reexecution-evidence-v1","positive":[no_challenge.status,rejected.status,accepted.status],"negative":negatives,"candidate_only":True,"global_profile_enabled":False,"settlement_authority":False}

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--self-test",action="store_true"); a=p.parse_args()
    if not a.self_test: raise SystemExit("use --self-test")
    print(json.dumps(self_test(),sort_keys=True,separators=(",",":"))); return 0
if __name__=="__main__": raise SystemExit(main())
