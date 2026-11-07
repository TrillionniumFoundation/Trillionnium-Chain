from pathlib import Path
from datetime import datetime,timezone
import concurrent.futures,hashlib,json,subprocess,time,traceback
R=Path("/home/qian-qi/throughput-final-ci-observation-20261107");D=R/"w1-components-transport-v2"
IDS=[13586134600,13586253351,13586459476,13586509176,13586791050,13587135201]
SCRIPT=R/"read_w1_pure_records_819_v2.py"
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()
def save(p,v):
 with p.open("x") as f:json.dump(v,f,indent=2);f.write("\n")
def one(ident):
 d=D/str(ident);row={"artifact_id":ident,"status":"UNKNOWN","attempted":False,"errors":[],"business_qualification":False}
 stage=json.loads((d/"readback-stage1.json").read_bytes())
 row.update(family=stage.get("family"),arch=stage.get("arch"),source_kind=stage.get("source_kind"),tested_commit=stage.get("tested_commit"),stage1_status=stage.get("status"),stage1_errors=stage.get("errors"),stage1_sha256=sha(d/"readback-stage1.json"))
 if stage.get("archive_authenticated") and stage.get("source_bound") and stage.get("manifest_hashes_complete") and not stage.get("errors"):
  row.update(attempted=True,command=["/usr/bin/python3",str(SCRIPT),str(d)],observer_timeout_seconds=240,started_utc=datetime.now(timezone.utc).isoformat())
  started=time.monotonic_ns()
  with (d/"pure-v2.stdout").open("xb") as out,(d/"pure-v2.stderr").open("xb") as err:
   try:
    run=subprocess.run(row["command"],stdout=out,stderr=err,timeout=240,check=False)
    row.update(exit_code=run.returncode,timed_out=False)
   except subprocess.TimeoutExpired:
    row.update(exit_code=None,timed_out=True);row["errors"].append("original pure reader observer timeout 240s; no retry")
   except Exception as e:
    row.update(exit_code=None,timed_out=False);row["errors"].append(type(e).__name__+": "+str(e))
  row["elapsed_ns"]=time.monotonic_ns()-started
  for stream in ("stdout","stderr"):
   p=d/("pure-v2."+stream);row[stream]={"path":str(p),"bytes":p.stat().st_size,"sha256":sha(p)}
  result=d/"readback-pure-v2.json"
  if result.exists():
   r=json.loads(result.read_bytes());row["pure_readback"]={"path":str(result),"bytes":result.stat().st_size,"sha256":sha(result)};row["errors"].extend(r["errors"])
   row["native_campaign_commands"]=r["native_invocations"];row["native_manifests"]=len(r["manifests"])
   if row.get("exit_code")==0 and not row["timed_out"] and r["complete_component_readback"] and not row["errors"]:row["status"]="COMPONENT_READBACK_COMPLETE"
  else:row["errors"].append("pure reader did not produce complete readback")
 else:row["errors"].append("archive/source/manifest not authenticated; pure reader not attempted")
 row["finished_utc"]=datetime.now(timezone.utc).isoformat();save(d/"pure-driver-v2.json",row)
 print(json.dumps({k:row.get(k) for k in ("artifact_id","status","attempted","exit_code","native_campaign_commands","errors")}),flush=True)
 return row
started=datetime.now(timezone.utc).isoformat();deadline=time.monotonic()+3600;remaining=set(IDS);results=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
 pending={}
 while remaining or pending:
  for ident in IDS:
   if ident in remaining and (D/str(ident)/"readback-stage1.json").is_file():
    pending[pool.submit(one,ident)]=ident;remaining.remove(ident)
  if pending:
   done,_=concurrent.futures.wait(pending,timeout=1,return_when=concurrent.futures.FIRST_COMPLETED)
   for task in done:
    ident=pending.pop(task)
    try:results.append(task.result())
    except Exception as e:
     results.append({"artifact_id":ident,"status":"UNKNOWN","errors":[type(e).__name__+": "+str(e)],"traceback":traceback.format_exc(),"business_qualification":False})
  elif remaining:time.sleep(1)
  if remaining and time.monotonic()>deadline:
   for ident in sorted(remaining):results.append({"artifact_id":ident,"status":"UNKNOWN","attempted":False,"errors":["stage1 record absent at 3600s transport-v2 observer wait bound"],"business_qualification":False})
   remaining.clear()
summary={"schema":"trnm-final819-w1-transport-v2-pure-reader-coverage","head":"819309fd312298e099642e1253b1d4ba07113e98","github_jobs_success":20,"artifact_denominator":len(IDS),"original_v1_artifact_denominator":20,"v1_failures_retained":True,"rows":sorted(results,key=lambda x:x["artifact_id"]),"started_utc":started,"finished_utc":datetime.now(timezone.utc).isoformat(),"script_sha256":sha(SCRIPT),"observer_timeout_seconds_per_artifact":240,"no_native_executed":True,"no_retry":True,"business_qualification":False}
summary["complete_component_readbacks"]=sum(x["status"]=="COMPONENT_READBACK_COMPLETE" for x in results);summary["unknown"]=len(IDS)-summary["complete_component_readbacks"]
summary["original_native_campaigns_verified"]=sum(x.get("native_campaign_commands",0) for x in results if x["status"]=="COMPONENT_READBACK_COMPLETE")
summary["original_native_manifest_count"]=sum(x.get("native_manifests",0) for x in results if x["status"]=="COMPONENT_READBACK_COMPLETE")
save(D/"summary-pure-v2.json",summary)
print(json.dumps({k:v for k,v in summary.items() if k!="rows"}),flush=True)
