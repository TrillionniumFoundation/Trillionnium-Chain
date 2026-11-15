#!/usr/bin/env python3
"""Read a retained metadata snapshot; never queries GitHub or qualifies a lane."""
import argparse,collections,hashlib,json,pathlib,re,runpy
ROOT=pathlib.Path("/home/qian-qi/throughput-final-ci-observation-20261107")
H="819309fd312298e099642e1253b1d4ba07113e98"
RUNS={42402618518:"priority",42402618462:"w1"}
SOURCES=("head","prospective-merge")
def main():
 p=argparse.ArgumentParser();p.add_argument("snapshot",type=pathlib.Path);a=p.parse_args()
 snap=a.snapshot.resolve();assert snap.parent==ROOT
 raw=(snap/"snapshot.json").read_bytes();s=json.loads(raw);assert s["requested_head"]==H
 parse_http=runpy.run_path(str(ROOT/"read_ci_metadata.py"))["parse_http"]
 artifacts=[];jobs=[];allruns=[]
 for q in s["queries"]:
  if q.get("exit_code")!=0 or q.get("http_status")!=200:continue
  _,_,body=parse_http((snap/q["http_file"]).read_bytes())
  if "/artifacts?" in q["endpoint"]:artifacts.extend(body["artifacts"])
  if "/jobs?filter=all" in q["endpoint"]:jobs.extend(body["jobs"])
  if q["endpoint"].startswith("repos/TrillionniumFoundation/Trillionnium-Chain/actions/runs?head_sha="):allruns.extend(body["workflow_runs"])
 expected={}
 for runner in ("ubuntu-24.04","ubuntu-24.04-arm"):
  for source in SOURCES:
   for family in ("service-model","state","history"):
    name=f"native priorities ({runner}, {source}, {family})"
    expected[(42402618518,name)]={"family":family,"arch":"arm64" if runner.endswith("-arm") else "x64","source":source}
 for arch in ("x64","arm64"):
  for source in SOURCES:
   for label,family in (("W1 false trace reuse","false-trace"),("W1 factorial legal strategies v3","factorial"),("W1 paid rank and batch v5","rank-batch")):
    expected[(42402618462,f"{label} ({arch}, {source})")]={"family":family,"arch":arch,"source":source}
   for version in ("v1","v2"):
    expected[(42402618462,f"W1 complete legal strategies ({version}, {arch}, {source})")]={"family":"legal-"+version,"arch":arch,"source":source}
 for source in SOURCES:
  expected[(42402618462,f"W1 fresh challenge service (x64, {source})")]={"family":"fresh","arch":"x64","source":source}
 assert len(expected)==34
 expected_aux={(42402618518,"retained-pressure-failure"),(42402618518,"Freeze actual integration push source"),(42402618462,"Freeze actual integration push source")}
 grouped=collections.defaultdict(list)
 for j in jobs:grouped[j.get("run_attempt")].append(j)
 attempts=[];all_native=[]
 for attempt,rows in sorted(grouped.items(),key=lambda x:str(x[0])):
  names=[(j["run_id"],j["name"]) for j in rows]
  missing=[list(x) for x in sorted(set(expected)|expected_aux-set(names))] if False else [list(x) for x in sorted((set(expected)|expected_aux)-set(names))]
  unexpected=[list(x) for x in sorted(set(names)-(set(expected)|expected_aux))]
  native=[];source_totals=collections.Counter()
  for j in rows:
   key=(j["run_id"],j["name"])
   if key not in expected:continue
   steps=j.get("steps",[])
   roles={"materialize":["Reproduce the frozen integration-push source"],
      "before":["Verify source and original project boundary"] if j["run_id"]==42402618518 else ["Reserve observations and verify ordered source identity","Reserve records and verify ordered source identity"],
      "after":["Reverify exact unchanged source"] if j["run_id"]==42402618518 else ["Verify measured source after execution","Verify observed source after execution"],
      "context":["Preserve this lane's actual push source context"]}
   checks={}
   for role,choices in roles.items():
    matches=[x for x in steps if x["name"] in choices]
    if len(matches)!=1:
     checks[role]={"status":"MISSING_OR_DUPLICATE","matches":len(matches)}
     source_totals[role+":MISSING_OR_DUPLICATE"]+=1
    else:
     x=matches[0];checks[role]={k:x.get(k) for k in ("name","status","conclusion","started_at","completed_at")}
     source_totals[role+":"+str(x.get("status"))+"/"+str(x.get("conclusion"))]+=1
   row={k:j.get(k) for k in ("id","run_id","run_attempt","name","head_sha","status","conclusion","started_at","completed_at","runner_name","labels")}
   row.update(expected[key],source_controls=checks,current_steps=[x["name"] for x in steps if x.get("status")=="in_progress"],
    failed_steps=[{k:x.get(k) for k in ("name","status","conclusion","started_at","completed_at")} for x in steps if x.get("conclusion") in ("failure","timed_out","cancelled")],
    artifact_readback_status="NOT_EVALUATED_BY_METADATA",native_gate_validated=False)
   native.append(row)
  all_native.extend(native)
  def counts(rs):return dict(collections.Counter(str(j.get("status"))+"/"+str(j.get("conclusion")) for j in rs))
  attempts.append({"attempt":attempt,"jobs":len(rows),"expected_jobs":37,"native_lanes":len(native),"expected_native_lanes":34,
   "missing_job_names":missing,"unexpected_job_names":unexpected,"duplicate_job_names":len(names)-len(set(names)),
   "head_mismatches":[j["id"] for j in rows if j.get("head_sha")!=H],"workflow_counts":counts(rows),"native_counts":counts(native),
   "source_steps":dict(source_totals),"native":native,"auxiliary":[{k:j.get(k) for k in ("id","run_id","name","status","conclusion")} for j in rows if (j["run_id"],j["name"]) in expected_aux]})
 result={"schema":"trnm-final819-observer-core-v1","head":H,"snapshot":str(snap),"snapshot_sha256":hashlib.sha256(raw).hexdigest(),"started_utc":s["started_utc"],"finished_utc":s["finished_utc"],
 "metadata_coverage_complete":s["metadata_coverage_complete"],"metadata_issues":s["issues"],
 "all_head_runs":[{k:r.get(k) for k in ("id","workflow_id","name","event","head_sha","run_attempt","status","conclusion","created_at","updated_at")} for r in allruns],
 "target_runs":s["target_runs"],"attempts":attempts,
 "artifacts":[{k:x.get(k) for k in ("id","name","size_in_bytes","digest","expired","created_at","updated_at","workflow_run")} for x in artifacts],
 "native_gate_validated":False}
 out=snap/"observer-core-v1.json";out.write_text(json.dumps(result,indent=2)+"\n")
 print(json.dumps({"path":str(out),"sha256":hashlib.sha256(out.read_bytes()).hexdigest(),"finished_utc":s["finished_utc"],"metadata_coverage_complete":s["metadata_coverage_complete"],
 "all_head_runs":result["all_head_runs"],"attempts":[{k:v for k,v in x.items() if k!="native"} for x in attempts],
 "native_terminal":[x for x in all_native if x["status"]=="completed"],"current_native_step_counts":dict(collections.Counter(n for x in all_native for n in x["current_steps"])),
 "artifacts":result["artifacts"],"native_gate_validated":False}))
if __name__=="__main__":main()
