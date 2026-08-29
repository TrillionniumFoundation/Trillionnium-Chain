#!/usr/bin/env python3
"""Strict offline generator for the G0 current truth observation."""
from __future__ import annotations
import argparse, copy, datetime as dt, json, re, tempfile
from pathlib import Path
from typing import Any

SHA40=re.compile(r"^[0-9a-f]{40}$")
REF_KEYS=("assessed_plan_authority","candidate_baseline","control_plane_head","default_branch_tip","live_plan_tip")
EDGES={
 ("assessed_plan_authority","live_plan_tip"),
 ("candidate_baseline","control_plane_head"),
 ("default_branch_tip","candidate_baseline"),
}
OUTCOMES={"MODULE_CLOSED_CANDIDATE","BLOCKED_UPSTREAM","BASE_DRIFT","STOP_CONDITION","RESUME_REQUIRED"}

class EvidenceError(ValueError): pass

def canonical(value:Any)->bytes:
    return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()

def strict_object(pairs:list[tuple[str,Any]])->dict[str,Any]:
    out={}
    for key,value in pairs:
        if key in out: raise EvidenceError(f"duplicate-json-key:{key}")
        out[key]=value
    return out

def load(path:Path)->dict[str,Any]:
    try:
        value=json.loads(path.read_text(),object_pairs_hook=strict_object,
            parse_constant=lambda x:(_ for _ in ()).throw(EvidenceError(f"nonfinite:{x}")))
    except json.JSONDecodeError as exc: raise EvidenceError(f"invalid-json:{exc}") from exc
    if not isinstance(value,dict): raise EvidenceError("root-not-object")
    return value

def sha(value:Any,label:str)->str:
    if not isinstance(value,str) or not SHA40.fullmatch(value): raise EvidenceError(f"sha40:{label}")
    return value

def validate(v:dict[str,Any])->None:
    if v.get("schema")!="trnm-plan-evidence-manifest-v1" or v.get("manifest_version")!=1: raise EvidenceError("schema")
    if v.get("repository")!="TrillionniumFoundation/Trillionnium-Chain" or v.get("observation_source")!="github-api-read-only": raise EvidenceError("source")
    observed=v.get("observed_at")
    if not isinstance(observed,str) or not observed.endswith("Z"): raise EvidenceError("observed-at")
    try: dt.datetime.fromisoformat(observed[:-1]+"+00:00")
    except ValueError as exc: raise EvidenceError("observed-at") from exc
    base=v.get("source_baseline",{})
    for key in ("package_base_commit","package_base_tree","candidate_base_commit","candidate_base_tree"): sha(base.get(key),key)
    if not str(base.get("package_base_ref","")).startswith("refs/heads/") or not str(base.get("candidate_base_ref","")).startswith("refs/heads/"): raise EvidenceError("base-ref")

    rows=v.get("refs")
    if not isinstance(rows,list) or [r.get("key") for r in rows]!=list(REF_KEYS): raise EvidenceError("ref-order-or-set")
    refs={}
    for row in rows:
        key=row["key"]
        if key in refs or not str(row.get("ref","")).startswith("refs/heads/"): raise EvidenceError("ref")
        sha(row.get("commit"),key+".commit"); sha(row.get("tree"),key+".tree")
        if not isinstance(row.get("verified_commit"),bool) or not row.get("authority"): raise EvidenceError("ref-authority")
        refs[key]=row
    if refs["assessed_plan_authority"]["commit"]==refs["live_plan_tip"]["commit"]: raise EvidenceError("assessed-live-collapse")
    if refs["default_branch_tip"]["authority"]!="observation-only": raise EvidenceError("default-tip-escalation")

    seen=set()
    for edge in v.get("lineage",[]):
        pair=(edge.get("from"),edge.get("to")); seen.add(pair)
        if pair[0] not in refs or pair[1] not in refs or pair[0]==pair[1] or edge.get("authority")!="observed-only": raise EvidenceError("lineage")
        a,b,s=edge.get("ahead_by"),edge.get("behind_by"),edge.get("status")
        if not isinstance(a,int) or a<0 or not isinstance(b,int) or b<0: raise EvidenceError("lineage-count")
        valid=(s=="identical" and a==b==0) or (s=="ahead" and a>0 and b==0) or (s=="behind" and b>0 and a==0) or (s=="diverged" and a>0 and b>0)
        if not valid: raise EvidenceError("lineage-shape")
    if seen!=EDGES: raise EvidenceError("lineage-set")

    pr_seen=set()
    for pr in v.get("pull_requests",[]):
        n=pr.get("number")
        if not isinstance(n,int) or n<=0 or n in pr_seen or pr.get("head_key") not in refs: raise EvidenceError("pr")
        pr_seen.add(n)
        if pr.get("accepted") is not False or pr.get("merged") is not False: raise EvidenceError("pr-promotion")

    ids=[]; control=refs["control_plane_head"]["commit"]
    for run in v.get("workflow_runs",[]):
        ids.append(run.get("id")); sha(run.get("head_commit"),"workflow-head")
        if run["head_commit"]!=control: raise EvidenceError("stale-workflow-head")
        eligible=run.get("status")=="completed" and run.get("conclusion")=="success"
        if run.get("evidence_eligible") is not eligible: raise EvidenceError("workflow-eligibility")
        if run.get("g0_gate_evidence") is True and (not eligible or run.get("evidence_scope")!="G0_TRUTH_PROVENANCE_V1"): raise EvidenceError("g0-evidence")
        if not isinstance(run.get("g0_gate_evidence"),bool): raise EvidenceError("g0-evidence-type")
    if not ids or ids!=sorted(ids) or len(ids)!=len(set(ids)): raise EvidenceError("workflow-order")

    truth=v.get("machine_truth",{})
    for key in ("production_candidate","production_consensus_activation","release_ready","v1_normative_freeze","v1_node_support"):
        if truth.get(key) is not False: raise EvidenceError("truth-promotion:"+key)
    guards=v.get("guard_rows",[])
    if not guards or len({r.get("name") for r in guards})!=len(guards) or any(r.get("value") is not False or r.get("mutable_by_package") is not False for r in guards): raise EvidenceError("guards")
    package=v.get("package",{})
    if package.get("id")!="G0_TRUTH_PROVENANCE_V1" or package.get("owner")!="A01" or package.get("local_outputs_complete") is not True: raise EvidenceError("package")
    if package.get("terminal_outcome") not in OUTCOMES: raise EvidenceError("outcome")
    if package["terminal_outcome"]=="BLOCKED_UPSTREAM" and not package.get("blockers"): raise EvidenceError("blocker")
    rules=v.get("observation_rules",{})
    if not rules or any(flag is not True for flag in rules.values()): raise EvidenceError("rules")

def snapshot(v:dict[str,Any])->dict[str,Any]:
    validate(v); r={x["key"]:x for x in v["refs"]}; runs=v["workflow_runs"]
    candidate=lambda key,pr:{"ref":r[key]["ref"],"commit":r[key]["commit"],"tree":r[key]["tree"],"pull_request":pr,"status":r[key]["authority"],"accepted":False}
    return {
      "schema":"trnm-current-snapshot-v1","snapshot_version":1,"observed_at":v["observed_at"],"repository":v["repository"],
      "generated_from":"docs/development/plan-evidence-manifest-v1.json",
      "default_branch":{"name":"main","ref":r["default_branch_tip"]["ref"],"commit":r["default_branch_tip"]["commit"],"tree":r["default_branch_tip"]["tree"],"authority":r["default_branch_tip"]["authority"],"verified_commit":r["default_branch_tip"]["verified_commit"]},
      "assessed_plan_source":{"ref":r["assessed_plan_authority"]["ref"],"commit":r["assessed_plan_authority"]["commit"],"tree":r["assessed_plan_authority"]["tree"],"authority_status":r["assessed_plan_authority"]["authority"]},
      "live_plan_tip":{"ref":r["live_plan_tip"]["ref"],"commit":r["live_plan_tip"]["commit"],"tree":r["live_plan_tip"]["tree"],"authority":r["live_plan_tip"]["authority"]},
      "latest_candidate":candidate("candidate_baseline",7),"documentation_control":candidate("control_plane_head",8),
      "lineage":v["lineage"],"pull_requests":v["pull_requests"],
      "workflow_evidence":{"exact_head":r["control_plane_head"]["commit"],"runs_total":len(runs),"completed_success":sum(x["evidence_eligible"] for x in runs),"g0_eligible_success":sum(x["g0_gate_evidence"] for x in runs),"rows":runs,"rule":"only completed/success on the exact bound head is eligible, and scope must match the claimed Gate/package"},
      "machine_truth":v["machine_truth"],"guard_rows":v["guard_rows"],
      "package_status":{key:v["package"][key] for key in ("id","owner","local_outputs_complete","terminal_outcome","blockers","blocked_downstream","invalidation_set","rerun_commands")},
      "current_promotion_critical_stack":["G0 truth/provenance exact-head replay","G1-R2 recovery/Core acknowledgement","G1-R3 ordinary proposal authority","G1-R4 application/Safety/checkpoint/multi-block/anti-rollback","G1-R5 native 4/7-node evidence"],
      "truth_rule":"default tip, live branch tip, assessed source, candidate source, tested head, accepted evidence and release authority are distinct identities and must never be silently substituted",
    }

def self_test(v:dict[str,Any])->None:
    validate(v); expected=canonical(snapshot(v))
    if expected!=canonical(snapshot(json.loads(canonical(v)))): raise EvidenceError("nondeterministic")
    mutations=[]
    m=copy.deepcopy(v); m["workflow_runs"][0]["head_commit"]="0"*40; mutations.append(m)
    m=copy.deepcopy(v); m["workflow_runs"][0]["evidence_eligible"]=True; mutations.append(m)
    m=copy.deepcopy(v); m["refs"][4]["commit"]=m["refs"][0]["commit"]; mutations.append(m)
    m=copy.deepcopy(v); m["guard_rows"][0]["value"]=True; mutations.append(m)
    m=copy.deepcopy(v); m["pull_requests"][0]["accepted"]=True; mutations.append(m)
    for mutant in mutations:
        try: validate(mutant)
        except EvidenceError: continue
        raise EvidenceError("mutant-accepted")
    if snapshot(v)["workflow_evidence"]["g0_eligible_success"]!=0: raise EvidenceError("g0-fabricated")
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/"x.json"; p.write_bytes(expected)
        if canonical(json.loads(p.read_text()))!=expected: raise EvidenceError("roundtrip")

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--evidence",type=Path,required=True); ap.add_argument("--output",type=Path); ap.add_argument("--self-test",action="store_true"); ns=ap.parse_args()
    evidence=load(ns.evidence); validate(evidence)
    if ns.self_test: self_test(evidence)
    raw=canonical(snapshot(evidence))
    if ns.output: ns.output.parent.mkdir(parents=True,exist_ok=True); ns.output.write_bytes(raw)
    else: print(raw.decode(),end="")
    return 0
if __name__=="__main__": raise SystemExit(main())
