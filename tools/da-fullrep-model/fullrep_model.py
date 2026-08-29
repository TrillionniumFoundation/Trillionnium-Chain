#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass, field
import argparse
import hashlib
import json
from typing import Iterable

TRANSACTION_BATCH = "transaction-batch"
ARTIFACT_EVIDENCE = "artifact-evidence"
NAMESPACES = {TRANSACTION_BATCH, ARTIFACT_EVIDENCE}

class Reject(ValueError):
    pass


def digest(namespace: str, data: bytes) -> str:
    if namespace not in NAMESPACES:
        raise Reject("unknown-namespace")
    h=hashlib.sha256()
    h.update(b"trnm.da-fullrep.object.v1\x00")
    h.update(namespace.encode("ascii"))
    h.update(len(data).to_bytes(8,"big"))
    h.update(data)
    return h.hexdigest()

@dataclass
class Record:
    namespace: str
    data: bytes
    object_id: str
    retention_until: int
    durable: bool = False
    attested_sequence: int | None = None
    holds: set[str] = field(default_factory=set)
    tombstoned: bool = False

@dataclass
class Provider:
    provider_id: str
    journal_sequence: int = 0
    records: dict[tuple[str,str],Record] = field(default_factory=dict)

    def persist(self, namespace: str, data: bytes, retention_until: int) -> Record:
        if namespace not in NAMESPACES or not data or retention_until <= 0:
            raise Reject("invalid-persist")
        object_id=digest(namespace,data)
        key=(namespace,object_id)
        prior=self.records.get(key)
        if prior:
            if prior.data != data or prior.retention_until != retention_until or prior.tombstoned:
                raise Reject("conflicting-replay")
            return prior
        rec=Record(namespace,data,object_id,retention_until,durable=True)
        self.records[key]=rec
        return rec

    def attest(self, namespace: str, object_id: str) -> dict:
        rec=self.records.get((namespace,object_id))
        if rec is None or not rec.durable or rec.tombstoned:
            raise Reject("attest-before-durable")
        if rec.attested_sequence is None:
            self.journal_sequence += 1
            rec.attested_sequence=self.journal_sequence
        return {"provider":self.provider_id,"namespace":namespace,"object_id":object_id,
                "length":len(rec.data),"retention_until":rec.retention_until,
                "sequence":rec.attested_sequence,"mode":"DA-FULLREP-V1"}

    def retrieve(self, namespace: str, object_id: str) -> bytes:
        rec=self.records.get((namespace,object_id))
        if rec is None or rec.tombstoned:
            raise Reject("not-found-or-withheld")
        if digest(namespace,rec.data) != object_id:
            raise Reject("stored-digest-drift")
        return rec.data

    def add_hold(self, namespace: str, object_id: str, hold: str) -> None:
        if not hold:
            raise Reject("empty-hold")
        self.records[(namespace,object_id)].holds.add(hold)

    def release_hold(self, namespace: str, object_id: str, hold: str) -> None:
        self.records[(namespace,object_id)].holds.discard(hold)

    def gc(self, namespace: str, object_id: str, height: int, node_permit: bool) -> None:
        rec=self.records[(namespace,object_id)]
        if not node_permit:
            raise Reject("node-permit-required")
        if height <= rec.retention_until or rec.holds:
            raise Reject("retention-or-hold-active")
        rec.tombstoned=True
        rec.data=b""

def certificate(attestations: Iterable[dict], threshold: int) -> dict:
    rows=sorted(attestations,key=lambda x:x["provider"])
    if threshold <= 0 or len(rows) < threshold:
        raise Reject("insufficient-threshold")
    providers=[r["provider"] for r in rows]
    if len(providers) != len(set(providers)):
        raise Reject("duplicate-provider")
    statement={(r["namespace"],r["object_id"],r["length"],r["retention_until"],r["mode"]) for r in rows}
    if len(statement) != 1:
        raise Reject("statement-mismatch")
    if rows[0]["mode"] != "DA-FULLREP-V1":
        raise Reject("sampling-mode-disabled")
    return {"statement":list(next(iter(statement))),"providers":providers,"threshold":threshold}

def repair(target: Provider, namespace: str, object_id: str, retention_until: int, sources: Iterable[Provider]) -> Record:
    good=[]
    for source in sources:
        try:
            data=source.retrieve(namespace,object_id)
        except Reject:
            continue
        if digest(namespace,data)==object_id:
            good.append(data)
    if not good or any(data != good[0] for data in good):
        raise Reject("no-consistent-complete-source")
    return target.persist(namespace,good[0],retention_until)

def withholding_evidence(provider: Provider, certificate_value: dict, namespace: str, object_id: str, request_nonce: str) -> dict:
    if provider.provider_id not in certificate_value["providers"]:
        raise Reject("provider-not-certified")
    try:
        provider.retrieve(namespace,object_id)
    except Reject:
        return {"provider":provider.provider_id,"namespace":namespace,"object_id":object_id,"request_nonce":request_nonce,"outcome":"withheld"}
    raise Reject("bytes-available")

def self_test() -> dict:
    p1,p2,p3,p4=(Provider(f"p{i}") for i in range(1,5))
    data=b"canonical transaction batch"
    recs=[p.persist(TRANSACTION_BATCH,data,100) for p in (p1,p2,p3)]
    atts=[p.attest(TRANSACTION_BATCH,r.object_id) for p,r in zip((p1,p2,p3),recs)]
    cert=certificate(atts,3)
    assert p1.retrieve(TRANSACTION_BATCH,recs[0].object_id)==data
    repaired=repair(p4,TRANSACTION_BATCH,recs[0].object_id,100,[p1,p2,p3])
    assert repaired.data==data
    p4.add_hold(TRANSACTION_BATCH,repaired.object_id,"challenge:1")
    negatives=[]
    def reject(name,fn):
        try: fn()
        except Reject as exc: negatives.append({"case":name,"error":str(exc)})
        else: raise AssertionError(f"accepted:{name}")
    reject("attest-before-durable",lambda: Provider("x").attest(TRANSACTION_BATCH,recs[0].object_id))
    reject("cross-namespace",lambda: p1.retrieve(ARTIFACT_EVIDENCE,recs[0].object_id))
    reject("duplicate-provider",lambda: certificate([atts[0],atts[0],atts[1]],3))
    bad=dict(atts[0]); bad["mode"]="DA-DAS-V1"
    reject("sampling-disabled",lambda: certificate([bad,atts[1],atts[2]],3))
    reject("gc-with-hold",lambda: p4.gc(TRANSACTION_BATCH,repaired.object_id,101,True))
    reject("gc-without-node-permit",lambda: p4.gc(TRANSACTION_BATCH,repaired.object_id,101,False))
    p4.release_hold(TRANSACTION_BATCH,repaired.object_id,"challenge:1")
    p4.gc(TRANSACTION_BATCH,repaired.object_id,101,True)
    evidence=withholding_evidence(p4,cert,TRANSACTION_BATCH,repaired.object_id,"nonce-1")
    return {"schema":"trnm-da-fullrep-model-evidence-v1","positive":5,"negative":negatives,"withholding":evidence,"candidate_only":True,"network_authority":False}

def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--self-test",action="store_true")
    args=parser.parse_args()
    if not args.self_test: raise SystemExit("use --self-test")
    print(json.dumps(self_test(),sort_keys=True,separators=(",",":")))
    return 0
if __name__=="__main__": raise SystemExit(main())
