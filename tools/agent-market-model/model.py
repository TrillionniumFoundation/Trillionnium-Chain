#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass, field
import argparse, hashlib, json

class Reject(ValueError): pass

def hid(*parts: object) -> str:
    h=hashlib.sha256(); h.update(b"trnm.agent-market-model.v1\x00")
    for part in parts:
        raw=str(part).encode(); h.update(len(raw).to_bytes(4,"big")); h.update(raw)
    return h.hexdigest()

@dataclass
class Capability:
    capability_id: str
    agent_id: str
    operations: set[str]
    lanes: set[int]
    spend_limit: int
    valid_from: int
    expires_after: int
    generation: int=1
    spent: int=0
    reserved: int=0
    revoked: bool=False

@dataclass
class Session:
    session_id: str
    agent_id: str
    capability_id: str
    lanes: set[int]
    expires_after: int
    generation: int=1
    revoked: bool=False

@dataclass
class Agent:
    agent_id: str
    controller_key: str
    capabilities: dict[str,Capability]=field(default_factory=dict)
    sessions: dict[str,Session]=field(default_factory=dict)
    nonces: dict[tuple[str,int],int]=field(default_factory=dict)

@dataclass
class Escrow:
    funded: int
    reserved: int=0
    refunded: int=0
    closed: bool=False

@dataclass
class Task:
    task_id: str
    requester: str
    status: str
    escrow: Escrow
    revision: int=0
    accepted_bid: str|None=None
    active_lease: str|None=None
    checkpoint: str|None=None
    provider: str|None=None
    refund_applied: bool=False

@dataclass
class Bid:
    bid_id: str
    task_id: str
    provider: str
    price: int
    status: str="open"

@dataclass
class Lease:
    lease_id: str
    task_id: str
    provider: str
    price: int
    revision: int
    status: str="offered"

class Market:
    def __init__(self) -> None:
        self.agents: dict[str,Agent]={}; self.tasks: dict[str,Task]={}; self.bids: dict[str,Bid]={}; self.leases: dict[str,Lease]={}

    def add_agent(self,name:str) -> Agent:
        a=Agent(hid("agent",name),hid("controller",name)); self.agents[a.agent_id]=a; return a

    def grant_capability(self,a:Agent,ops:set[str],lanes:set[int],limit:int,start:int,end:int) -> Capability:
        if not ops or not lanes or limit<=0 or start<0 or end<=start: raise Reject("invalid-capability")
        c=Capability(hid(a.agent_id,sorted(ops),sorted(lanes),limit,start,end),a.agent_id,set(ops),set(lanes),limit,start,end)
        a.capabilities[c.capability_id]=c; return c

    def grant_session(self,a:Agent,c:Capability,lanes:set[int],end:int) -> Session:
        if c.revoked or not lanes or not lanes.issubset(c.lanes) or end>c.expires_after: raise Reject("session-not-attenuated")
        s=Session(hid(a.agent_id,c.capability_id,sorted(lanes),end),a.agent_id,c.capability_id,set(lanes),end)
        a.sessions[s.session_id]=s
        for lane in lanes: a.nonces[(s.session_id,lane)]=0
        return s

    def authorize(self,a:Agent,s:Session,op:str,lane:int,nonce:int,charge:int,height:int):
        c=a.capabilities.get(s.capability_id)
        if c is None or c.revoked or s.revoked or c.generation!=s.generation: raise Reject("revoked-or-generation")
        if height<c.valid_from or height>c.expires_after or height>s.expires_after: raise Reject("expired")
        if op not in c.operations or lane not in c.lanes or lane not in s.lanes: raise Reject("scope")
        if a.nonces.get((s.session_id,lane))!=nonce: raise Reject("nonce")
        if charge<0 or c.spent+c.reserved+charge>c.spend_limit: raise Reject("budget")
        return c

    def consume(self,a:Agent,s:Session,lane:int,c:Capability,charge:int) -> None:
        a.nonces[(s.session_id,lane)]+=1; c.spent+=charge

    def create_task(self,a:Agent,s:Session,lane:int,nonce:int,funding:int,height:int) -> Task:
        c=self.authorize(a,s,"create-task",lane,nonce,funding,height)
        if funding<=0: raise Reject("funding")
        t=Task(hid(a.agent_id,s.session_id,lane,nonce,"task"),a.agent_id,"open",Escrow(funding))
        self.tasks[t.task_id]=t; self.consume(a,s,lane,c,funding); return t

    def submit_bid(self,a:Agent,s:Session,lane:int,nonce:int,task_id:str,price:int,height:int) -> Bid:
        c=self.authorize(a,s,"bid",lane,nonce,0,height); t=self.tasks[task_id]
        if t.status!="open" or price<=0 or price>t.escrow.funded: raise Reject("bid-invalid")
        b=Bid(hid(task_id,a.agent_id,lane,nonce),task_id,a.agent_id,price); self.bids[b.bid_id]=b; self.consume(a,s,lane,c,0); return b

    def accept_bid(self,a:Agent,s:Session,lane:int,nonce:int,bid_id:str,height:int) -> Lease:
        c=self.authorize(a,s,"accept-bid",lane,nonce,0,height); b=self.bids[bid_id]; t=self.tasks[b.task_id]
        if a.agent_id!=t.requester or t.status!="open" or t.active_lease is not None or b.status!="open": raise Reject("duplicate-or-unauthorized-lease")
        if t.escrow.reserved+b.price>t.escrow.funded: raise Reject("escrow")
        t.escrow.reserved+=b.price; t.status="leased"; t.accepted_bid=b.bid_id; b.status="accepted"; t.revision+=1
        l=Lease(hid(t.task_id,b.provider,t.revision),t.task_id,b.provider,b.price,t.revision); self.leases[l.lease_id]=l; t.active_lease=l.lease_id
        self.consume(a,s,lane,c,0); return l

    def start(self,a:Agent,s:Session,lane:int,nonce:int,lease_id:str,height:int) -> None:
        c=self.authorize(a,s,"start",lane,nonce,0,height); l=self.leases[lease_id]; t=self.tasks[l.task_id]
        if a.agent_id!=l.provider or l.status!="offered" or t.status!="leased" or t.active_lease!=lease_id: raise Reject("start-invalid")
        l.status="active"; t.status="active"; t.provider=a.agent_id; t.revision+=1; self.consume(a,s,lane,c,0)

    def checkpoint(self,a:Agent,s:Session,lane:int,nonce:int,task_id:str,value:str,height:int) -> None:
        c=self.authorize(a,s,"checkpoint",lane,nonce,0,height); t=self.tasks[task_id]
        if a.agent_id!=t.provider or t.status!="active" or not value: raise Reject("checkpoint-invalid")
        t.checkpoint=hid(task_id,t.revision,value); t.revision+=1; self.consume(a,s,lane,c,0)

    def pause(self,a:Agent,s:Session,lane:int,nonce:int,task_id:str,height:int) -> None:
        c=self.authorize(a,s,"pause",lane,nonce,0,height); t=self.tasks[task_id]
        if a.agent_id not in {t.requester,t.provider} or t.status!="active": raise Reject("pause-invalid")
        t.status="paused"; t.revision+=1; self.consume(a,s,lane,c,0)

    def resume(self,a:Agent,s:Session,lane:int,nonce:int,task_id:str,height:int) -> None:
        c=self.authorize(a,s,"resume",lane,nonce,0,height); t=self.tasks[task_id]
        if a.agent_id!=t.provider or t.status!="paused": raise Reject("resume-invalid")
        t.status="active"; t.revision+=1; self.consume(a,s,lane,c,0)

    def migrate(self,requester:Agent,s:Session,lane:int,nonce:int,task_id:str,new_provider:str,height:int) -> Lease:
        c=self.authorize(requester,s,"migrate",lane,nonce,0,height); t=self.tasks[task_id]
        if requester.agent_id!=t.requester or t.status not in {"active","paused"} or not t.checkpoint: raise Reject("migration-requires-checkpoint")
        old=self.leases[t.active_lease]; old.status="superseded"; t.status="leased"; t.provider=None; t.revision+=1
        l=Lease(hid(task_id,new_provider,t.revision),task_id,new_provider,old.price,t.revision); self.leases[l.lease_id]=l; t.active_lease=l.lease_id
        self.consume(requester,s,lane,c,0); return l

    def terminate(self,a:Agent,s:Session,lane:int,nonce:int,task_id:str,kind:str,height:int) -> None:
        if kind not in {"cancel","timeout"}: raise Reject("terminal-kind")
        c=self.authorize(a,s,kind,lane,nonce,0,height); t=self.tasks[task_id]
        allowed={"cancel":{"open","leased","paused"},"timeout":{"active","paused","leased"}}[kind]
        if a.agent_id!=t.requester or t.status not in allowed: raise Reject("terminal-invalid")
        t.status="cancelled" if kind=="cancel" else "timed-out"; t.revision+=1; self.consume(a,s,lane,c,0)

    def refund(self,a:Agent,s:Session,lane:int,nonce:int,task_id:str,height:int) -> int:
        c=self.authorize(a,s,"refund",lane,nonce,0,height); t=self.tasks[task_id]
        if a.agent_id!=t.requester or t.status not in {"cancelled","timed-out"} or t.refund_applied: raise Reject("refund-invalid-or-duplicate")
        amount=t.escrow.funded-t.escrow.reserved-t.escrow.refunded
        if amount<0: raise Reject("escrow-invariant")
        t.escrow.refunded+=amount; t.refund_applied=True; t.status="refunded"; t.escrow.closed=True; t.revision+=1
        self.consume(a,s,lane,c,0); return amount

def self_test() -> dict:
    m=Market(); req=m.add_agent("requester"); prov=m.add_agent("provider"); prov2=m.add_agent("provider2")
    req_ops={"create-task","accept-bid","pause","migrate","cancel","timeout","refund"}; prov_ops={"bid","start","checkpoint","pause","resume"}
    rc=m.grant_capability(req,req_ops,{1,2},1000,1,100); rs=m.grant_session(req,rc,{1,2},100)
    pc=m.grant_capability(prov,prov_ops,{3},10,1,100); ps=m.grant_session(prov,pc,{3},100)
    p2c=m.grant_capability(prov2,prov_ops,{4},10,1,100); p2s=m.grant_session(prov2,p2c,{4},100)
    t=m.create_task(req,rs,1,0,600,2); b=m.submit_bid(prov,ps,3,0,t.task_id,400,2); l=m.accept_bid(req,rs,1,1,b.bid_id,2); m.start(prov,ps,3,1,l.lease_id,2)
    m.checkpoint(prov,ps,3,2,t.task_id,"checkpoint-1",3); m.pause(req,rs,2,0,t.task_id,3); l2=m.migrate(req,rs,2,1,t.task_id,prov2.agent_id,4); m.start(prov2,p2s,4,0,l2.lease_id,4)
    m.pause(req,rs,2,2,t.task_id,5); m.terminate(req,rs,2,3,t.task_id,"cancel",5); refunded=m.refund(req,rs,2,4,t.task_id,5)
    negatives=[]
    def reject(name,fn):
        try: fn()
        except Reject as exc: negatives.append({"case":name,"error":str(exc)})
        else: raise AssertionError(f"accepted:{name}")
    reject("cross-lane-replay",lambda: m.authorize(req,rs,"refund",1,4,0,5))
    reject("scope-escalation",lambda: m.authorize(prov,ps,"accept-bid",3,3,0,5))
    rc.revoked=True; reject("revoked-capability",lambda: m.authorize(req,rs,"refund",2,5,0,5)); rc.revoked=False
    reject("duplicate-refund",lambda: m.refund(req,rs,2,5,t.task_id,5))
    t2=m.create_task(req,rs,1,2,300,6); b2=m.submit_bid(prov,ps,3,3,t2.task_id,200,6); m.accept_bid(req,rs,1,3,b2.bid_id,6)
    reject("duplicate-lease",lambda: m.accept_bid(req,rs,1,4,b2.bid_id,6))
    t2.status="active"; t2.provider=prov.agent_id
    reject("migration-without-checkpoint",lambda: m.migrate(req,rs,2,5,t2.task_id,prov2.agent_id,7))
    reject("budget-overflow",lambda: m.create_task(req,rs,1,4,500,7))
    return {"schema":"trnm-agent-market-model-evidence-v1","task":t.task_id,"refunded":refunded,"positive_transitions":11,"negative":negatives,"candidate_only":True,"global_state_authority":False}

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--self-test",action="store_true"); a=p.parse_args()
    if not a.self_test: raise SystemExit("use --self-test")
    print(json.dumps(self_test(),sort_keys=True,separators=(",",":"))); return 0
if __name__=="__main__": raise SystemExit(main())
