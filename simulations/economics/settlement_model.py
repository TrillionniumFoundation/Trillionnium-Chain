#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import asdict, dataclass
import argparse, hashlib, json

class Reject(ValueError): pass
MAX=(1<<128)-1

def add(a:int,b:int)->int:
    v=a+b
    if v<0 or v>MAX: raise Reject("arithmetic-overflow")
    return v

def sub(a:int,b:int)->int:
    if b<0 or b>a: raise Reject("insolvent")
    return a-b

def canon(value:object)->bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),default=lambda x:asdict(x)).encode()

def digest(label:str,value:object)->str:
    return hashlib.sha256(label.encode()+b"\x00"+canon(value)).hexdigest()

@dataclass(frozen=True)
class Policy:
    policy_id:str
    provider_bps:int=8500
    protocol_bps:int=500
    verifier_bps:int=300
    burn_bps:int=200
    challenger_bps_of_slashed_bond:int=5000
    related_party_allowed:bool=False
    def validate(self)->None:
        values=[self.provider_bps,self.protocol_bps,self.verifier_bps,self.burn_bps]
        if any(v<0 or v>10000 for v in values) or sum(values)>10000: raise Reject("policy-bps")
        if not 0<=self.challenger_bps_of_slashed_bond<=10000: raise Reject("challenge-bps")

@dataclass(frozen=True)
class Intent:
    task_id:str
    lease_id:str
    result_id:str
    result_status:str
    profile_hash:str
    payer:str
    provider:str
    verifier_pool:str
    challenger:str|None
    escrow_id:str
    escrow_asset:str
    escrow_amount:int
    bond_id:str
    bond_asset:str
    bond_amount:int
    active_price_root:str
    intent_price_root:str
    policy_id:str
    maturity_height:int
    expiry_height:int
    nonce:str

@dataclass
class Receipt:
    intent_id:str
    status:str
    movements:list[dict]
    replay:bool=False
    poco_weight_eligible:bool=False

class Engine:
    def __init__(self,policy:Policy)->None:
        policy.validate(); self.policy=policy
        self.balances:dict[tuple[str,str],int]={}; self.receipts:dict[str,Receipt]={}; self.nonce_index:dict[str,str]={}
    def set_balance(self,owner:str,asset:str,amount:int)->None:
        if amount<0 or amount>MAX: raise Reject("balance")
        self.balances[(owner,asset)]=amount
    def get(self,owner:str,asset:str)->int: return self.balances.get((owner,asset),0)
    def move(self,source:str,target:str,asset:str,amount:int,movements:list[dict])->None:
        if amount<0: raise Reject("negative-movement")
        self.balances[(source,asset)]=sub(self.get(source,asset),amount)
        self.balances[(target,asset)]=add(self.get(target,asset),amount)
        movements.append({"source":source,"target":target,"asset":asset,"amount":amount})
    def snapshot_totals(self)->dict[str,int]:
        out={}
        for (_,asset),amount in self.balances.items(): out[asset]=out.get(asset,0)+amount
        return out
    def apply(self,intent:Intent,height:int)->Receipt:
        intent_id=digest("trnm.settlement-intent.v1",intent)
        if intent_id in self.receipts:
            prior=self.receipts[intent_id]
            return Receipt(prior.intent_id,prior.status,list(prior.movements),True,False)
        prior_id=self.nonce_index.get(intent.nonce)
        if prior_id is not None and prior_id!=intent_id: raise Reject("nonce-conflict")
        if not all([intent.task_id,intent.lease_id,intent.result_id,intent.profile_hash,intent.payer,intent.provider,intent.escrow_id,intent.escrow_asset,intent.bond_id,intent.bond_asset,intent.nonce]): raise Reject("binding-missing")
        if intent.policy_id!=self.policy.policy_id: raise Reject("policy-root")
        if intent.intent_price_root!=intent.active_price_root: raise Reject("stale-price")
        if height<intent.maturity_height: raise Reject("not-mature")
        if height>intent.expiry_height and intent.result_status not in {"Expired","Cancelled"}: raise Reject("intent-expired")
        if intent.payer==intent.provider and not self.policy.related_party_allowed: raise Reject("related-party")
        if intent.result_status=="ResultRejected" and not intent.challenger: raise Reject("challenger-required")
        if self.get(intent.escrow_id,intent.escrow_asset)!=intent.escrow_amount: raise Reject("wrong-asset-or-escrow")
        if self.get(intent.bond_id,intent.bond_asset)!=intent.bond_amount: raise Reject("wrong-asset-or-bond")
        before=self.snapshot_totals(); movements=[]
        escrow=intent.escrow_id; bond=intent.bond_id
        if intent.result_status=="ResultFinal":
            provider=intent.escrow_amount*self.policy.provider_bps//10000
            protocol=intent.escrow_amount*self.policy.protocol_bps//10000
            verifier=intent.escrow_amount*self.policy.verifier_bps//10000
            burn=intent.escrow_amount*self.policy.burn_bps//10000
            refund=intent.escrow_amount-provider-protocol-verifier-burn
            self.move(escrow,intent.provider,intent.escrow_asset,provider,movements)
            self.move(escrow,"treasury",intent.escrow_asset,protocol,movements)
            self.move(escrow,intent.verifier_pool,intent.escrow_asset,verifier,movements)
            self.move(escrow,"burn",intent.escrow_asset,burn,movements)
            self.move(escrow,intent.payer,intent.escrow_asset,refund,movements)
            self.move(bond,intent.provider,intent.bond_asset,intent.bond_amount,movements)
            status="Settled"
        elif intent.result_status=="ResultRejected":
            self.move(escrow,intent.payer,intent.escrow_asset,intent.escrow_amount,movements)
            reward=intent.bond_amount*self.policy.challenger_bps_of_slashed_bond//10000
            treasury=intent.bond_amount-reward
            self.move(bond,intent.challenger,intent.bond_asset,reward,movements)
            self.move(bond,"treasury",intent.bond_asset,treasury,movements)
            status="SlashedAndRefunded"
        elif intent.result_status in {"Cancelled","Expired"}:
            self.move(escrow,intent.payer,intent.escrow_asset,intent.escrow_amount,movements)
            self.move(bond,intent.provider,intent.bond_asset,intent.bond_amount,movements)
            status="Refunded"
        else:
            raise Reject("result-status")
        after=self.snapshot_totals()
        if before!=after: raise Reject("asset-conservation")
        if self.get(escrow,intent.escrow_asset)!=0 or self.get(bond,intent.bond_asset)!=0: raise Reject("terminal-residue")
        receipt=Receipt(intent_id,status,movements,False,False)
        self.receipts[intent_id]=receipt; self.nonce_index[intent.nonce]=intent_id
        return receipt

# Make all economic transitions failure-atomic: a rejected path restores every
# mutable map, including response-loss indexes. This intentionally wraps the
# model instead of relying on individual branches to remember rollback.
_unchecked_apply=Engine.apply
def _transactional_apply(self:Engine,intent:Intent,height:int)->Receipt:
    before_balances=dict(self.balances); before_receipts=dict(self.receipts); before_nonces=dict(self.nonce_index)
    try:
        return _unchecked_apply(self,intent,height)
    except Exception:
        self.balances=before_balances; self.receipts=before_receipts; self.nonce_index=before_nonces
        raise
Engine.apply=_transactional_apply

def make(status:str,nonce:str="n1",payer:str="consumer",provider:str="provider",price:str="price-v1",asset:str="USD",bond_asset:str="BOND")->Intent:
    return Intent("task","lease","result",status,"profile",payer,provider,"verifier-pool","challenger" if status=="ResultRejected" else None,"escrow",asset,10000,"bond",bond_asset,1000,price,price,"policy-v1",10,100,nonce)

def engine_for(intent:Intent)->Engine:
    e=Engine(Policy("policy-v1")); e.set_balance(intent.escrow_id,intent.escrow_asset,intent.escrow_amount); e.set_balance(intent.bond_id,intent.bond_asset,intent.bond_amount); return e

def self_test()->dict:
    outcomes={}
    for status in ("ResultFinal","ResultRejected","Cancelled","Expired"):
        i=make(status,nonce=status); e=engine_for(i); r=e.apply(i,10); replay=e.apply(i,10)
        assert replay.replay and replay.intent_id==r.intent_id; outcomes[status]=r.status
    negatives=[]
    def reject(name,fn):
        try: fn()
        except Reject as exc: negatives.append({"case":name,"error":str(exc)})
        else: raise AssertionError(f"accepted:{name}")
    i=make("ResultFinal")
    reject("not-mature",lambda:engine_for(i).apply(i,9))
    stale=Intent(**{**asdict(i),"intent_price_root":"old"}); reject("stale-price",lambda:engine_for(stale).apply(stale,10))
    wrong=engine_for(i); wrong.set_balance("escrow","USD",9999); reject("insolvent-escrow",lambda:wrong.apply(i,10))
    related=make("ResultFinal",payer="same",provider="same"); reject("related-party",lambda:engine_for(related).apply(related,10))
    badstatus=make("ResultPending"); reject("unknown-result-status",lambda:engine_for(badstatus).apply(badstatus,10))
    overflow=make("ResultFinal"); oe=engine_for(overflow); oe.set_balance("provider","USD",MAX); frozen=dict(oe.balances); reject("arithmetic-overflow",lambda:oe.apply(overflow,10)); assert oe.balances==frozen
    rejected=make("ResultRejected"); missing=Intent(**{**asdict(rejected),"challenger":None}); me=engine_for(missing); frozen=dict(me.balances); reject("missing-challenger",lambda:me.apply(missing,10)); assert me.balances==frozen
    base=make("Cancelled",nonce="shared"); ce=engine_for(base); ce.apply(base,10)
    conflict=Intent(**{**asdict(base),"task_id":"other"}); reject("nonce-conflict",lambda:ce.apply(conflict,10))
    wrong_asset=make("ResultFinal",asset="EUR"); we=engine_for(wrong_asset); we.balances[("escrow","EUR")]=0; we.balances[("escrow","USD")]=10000; reject("wrong-asset",lambda:we.apply(wrong_asset,10))
    return {"schema":"trnm-settlement-conservation-evidence-v1","outcomes":outcomes,"negative":negatives,"multi_asset":True,"candidate_only":True,"failure_atomic":True,"poco_weight_eligible":False,"jmt_authority":False}

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--self-test",action="store_true"); a=p.parse_args()
    if not a.self_test: raise SystemExit("use --self-test")
    print(json.dumps(self_test(),sort_keys=True,separators=(",",":"))); return 0
if __name__=="__main__": raise SystemExit(main())
