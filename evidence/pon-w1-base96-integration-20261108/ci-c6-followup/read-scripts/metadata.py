from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
import datetime,hashlib,json,shutil,subprocess,time
SPEC=json.loads("{\"jobs\":[{\"job_id\":128662532819,\"run_id\":\"42457886543\",\"name\":\"prospective-merge (rust-baseline)\"},{\"job_id\":128662229998,\"run_id\":\"42457886543\",\"name\":\"prospective-merge (external-evidence-contract)\"},{\"job_id\":128662229957,\"run_id\":\"42457886543\",\"name\":\"prospective-merge (fuzz-smoke)\"},{\"job_id\":128662229947,\"run_id\":\"42457886543\",\"name\":\"prospective-merge (protocol-contract)\"},{\"job_id\":128662229937,\"run_id\":\"42457886543\",\"name\":\"W1 actual reuse V3 (arm64, prospective-merge)\"},{\"job_id\":128662229935,\"run_id\":\"42457886543\",\"name\":\"prospective Rust shard (quality)\"},{\"job_id\":128662229865,\"run_id\":\"42457886543\",\"name\":\"cross-arch-cost (x64)\"},{\"job_id\":128662229854,\"run_id\":\"42457886543\",\"name\":\"prospective-merge (repository-truth)\"},{\"job_id\":128662229829,\"run_id\":\"42457886543\",\"name\":\"W1 actual reuse V3 (x64, prospective-merge)\"},{\"job_id\":128662229758,\"run_id\":\"42457886543\",\"name\":\"cross-arch-cost (arm64)\"},{\"job_id\":128662229746,\"run_id\":\"42457886543\",\"name\":\"prospective Rust shard (runtime)\"},{\"job_id\":128662229491,\"run_id\":\"42457886543\",\"name\":\"protocol-contract\"},{\"job_id\":128660702010,\"run_id\":\"42457886518\",\"name\":\"W1 factorial legal strategies v3 (x64, prospective-merge)\"},{\"job_id\":128660701948,\"run_id\":\"42457886518\",\"name\":\"W1 fresh challenge service (x64, head)\"},{\"job_id\":128660701711,\"run_id\":\"42457886555\",\"name\":\"native priorities (ubuntu-24.04-arm, head, service-model)\"},{\"job_id\":128660701637,\"run_id\":\"42457886555\",\"name\":\"native priorities (ubuntu-24.04, head, history)\"},{\"job_id\":128660701605,\"run_id\":\"42457886555\",\"name\":\"native priorities (ubuntu-24.04, head, service-model)\"},{\"job_id\":128660701377,\"run_id\":\"42457886578\",\"name\":\"original native campaign (x64, head, release)\"}],\"prior_snapshot_sha256\":\"1e65f320701a9f1e948a8b4930f97835ee9c02d926446e081ecd07d9ca028f3e\"}")
OUT=Path("/home/qian-qi/work/chain-w1-c6-later-failures-and-history-20261108-ec265b-01")
OUT.mkdir(exist_ok=False)
gh=shutil.which("gh");assert gh
REPO="TrillionniumFoundation/Trillionnium-Chain"
def sha(b):return hashlib.sha256(b).hexdigest()
def put(relative,raw):
 if isinstance(raw,str):raw=raw.encode()
 p=OUT/relative;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(raw)
 return {"path":relative,"bytes":len(raw),"sha256":sha(raw)}
def jput(relative,d):return put(relative,json.dumps(d,sort_keys=True,indent=2)+"\n")
jput("scope.json",{"schema":"TRNM-W1-C6-LATER-FAILURE-READ-SCOPE1",
 "snapshot_path":"/home/qian-qi/work/chain-w1-c7-remote-observation-20261108-ec265b-01/snapshot.json",
 "snapshot_sha256":SPEC["prior_snapshot_sha256"],"selected_new_failure_jobs":SPEC["jobs"],
 "history_run":42456320219,"history_source":"96a241bf43f6a46d35dfb3d4ced9594ed8ceca75",
 "source_edits":0,"CI_reruns":0,"workflow_dispatches":0})
login=subprocess.run([gh,"api","user","--jq",".login"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
put("operator-login.stdout",login.stdout);put("operator-login.stderr",login.stderr)
jput("operator-login-command.json",{"argv":[gh,"api","user","--jq",".login"],"exit_code":login.returncode})
assert login.returncode==0 and login.stdout.decode().strip()=="ProfHepta"
tasks=[(f"new-jobs/{r['job_id']}/metadata",f"repos/{REPO}/actions/jobs/{r['job_id']}",r) for r in SPEC["jobs"]]
tasks += [
 ("history/run-metadata",f"repos/{REPO}/actions/runs/42456320219",None),
 ("history/job-list",f"repos/{REPO}/actions/runs/42456320219/jobs?per_page=100",None)]
def fetch(task):
 label,endpoint,original=task
 started=time.time_ns()
 p=subprocess.run([gh,"api",endpoint],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 meta={"label":label,"endpoint":endpoint,"started_unix_ns":started,"finished_unix_ns":time.time_ns(),
  "exit_code":p.returncode,"stdout":put(label+".raw.json",p.stdout),"stderr":put(label+".stderr",p.stderr)}
 jput(label+".fetch.json",meta)
 row={"label":label,"fetch_exit":p.returncode}
 if p.returncode==0:
  d=json.loads(p.stdout)
  if original:
   row.update({"original":original,"actual_job_id":d.get("id"),"head_sha":d.get("head_sha"),
    "run_id":d.get("run_id"),"status":d.get("status"),"conclusion":d.get("conclusion"),
    "started_at":d.get("started_at"),"completed_at":d.get("completed_at"),
    "first_failed_step":next((x for x in d.get("steps",[]) if x.get("conclusion")=="failure"),None),
    "failed_steps":[x for x in d.get("steps",[]) if x.get("conclusion")=="failure"],
    "skipped_steps":[x["name"] for x in d.get("steps",[]) if x.get("conclusion")=="skipped"],
    "successful_steps":[x["name"] for x in d.get("steps",[]) if x.get("conclusion")=="success"]})
  elif label=="history/job-list":
   row["total_count"]=d.get("total_count")
   row["jobs"]=[{"id":j["id"],"name":j["name"],"head_sha":j.get("head_sha"),
    "status":j["status"],"conclusion":j["conclusion"],"started_at":j.get("started_at"),
    "completed_at":j.get("completed_at"),
    "first_failed_step":next((x for x in j.get("steps",[]) if x.get("conclusion")=="failure"),None),
    "failed_steps":[x for x in j.get("steps",[]) if x.get("conclusion")=="failure"],
    "skipped_steps":[x["name"] for x in j.get("steps",[]) if x.get("conclusion")=="skipped"],
    "successful_steps":[x["name"] for x in j.get("steps",[]) if x.get("conclusion")=="success"]}
    for j in d.get("jobs",[])]
  else:
   row.update({k:d.get(k) for k in ["id","name","head_sha","head_branch","event","run_attempt","status","conclusion","created_at","updated_at","html_url"]})
 else:row["error"]=p.stderr.decode(errors="replace")[:2000]
 print(json.dumps(row,sort_keys=True),flush=True)
 return meta,row
records=[];rows=[]
with ThreadPoolExecutor(max_workers=4) as pool:
 for future in as_completed([pool.submit(fetch,t) for t in tasks]):
  meta,row=future.result();records.append(meta);rows.append(row)
jput("metadata-fetch-manifest.json",{"requests":records,"operator":"ProfHepta","GET_count_including_identity":21,"read_only":True})
jput("metadata-readback.json",{"schema":"TRNM-W1-C6-LATER-FAILURE-METADATA1","rows":rows,"business_causes_not_inferred_from_old_snapshot":True})
print(json.dumps({"finished":True,"out":str(OUT),"fetch_count":len(records),"fetch_failures":[r["label"] for r in records if r["exit_code"]!=0]}),flush=True)
