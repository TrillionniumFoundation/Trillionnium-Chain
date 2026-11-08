from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
import datetime,hashlib,json,re,shutil,subprocess,time
SPEC=json.loads("{\"snapshot_path\":\"/home/qian-qi/work/chain-w1-base62-validation-20261108-ec265b/pr-ci-observation-01/snapshot.json\",\"snapshot_sha256\":\"ee0709dc5cd1b353e2561e24b45eb4ede9f80a007c209ee9aad5968a864d7307\",\"groups\":{\"42457886518\":[{\"job_id\":128660702000,\"name\":\"W1 false trace reuse (arm64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701997,\"name\":\"W1 complete legal strategies (v2, arm64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701995,\"name\":\"W1 complete legal strategies (v2, x64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701957,\"name\":\"W1 paid rank and batch v5 (x64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701943,\"name\":\"W1 complete legal strategies (v1, x64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701933,\"name\":\"W1 fresh challenge service (x64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701927,\"name\":\"W1 complete legal strategies (v1, arm64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701909,\"name\":\"W1 factorial legal strategies v3 (arm64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701885,\"name\":\"W1 paid rank and batch v5 (arm64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701856,\"name\":\"W1 false trace reuse (x64, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886584\":[{\"job_id\":128660701788,\"name\":\"reference (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701752,\"name\":\"reference (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886555\":[{\"job_id\":128660701632,\"name\":\"native priorities (ubuntu-24.04-arm, prospective-merge, history)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701606,\"name\":\"native priorities (ubuntu-24.04-arm, prospective-merge, service-model)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701603,\"name\":\"native priorities (ubuntu-24.04-arm, prospective-merge, state)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701599,\"name\":\"native priorities (ubuntu-24.04, prospective-merge, state)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701592,\"name\":\"native priorities (ubuntu-24.04, prospective-merge, history)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701543,\"name\":\"native priorities (ubuntu-24.04, prospective-merge, service-model)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701340,\"name\":\"retained-pressure-failure\",\"role\":\"unlabelled\"}],\"42457886583\":[{\"job_id\":128660701601,\"name\":\"original state and exit (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701409,\"name\":\"original state and exit (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886547\":[{\"job_id\":128660701441,\"name\":\"native boundary (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701420,\"name\":\"native boundary (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886520\":[{\"job_id\":128660701347,\"name\":\"original workspace test CPU (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701285,\"name\":\"original workspace test CPU (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886526\":[{\"job_id\":128660701319,\"name\":\"recent batch (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701166,\"name\":\"recent batch (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886533\":[{\"job_id\":128660701306,\"name\":\"parent evidence (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701271,\"name\":\"parent evidence (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886519\":[{\"job_id\":128660701244,\"name\":\"PQ network and witness (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701090,\"name\":\"PQ network and witness (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886523\":[{\"job_id\":128660701243,\"name\":\"cleanup (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701236,\"name\":\"aggregate-owner-controls (prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701207,\"name\":\"cleanup (macos-15, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701190,\"name\":\"cleanup (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886542\":[{\"job_id\":128660701162,\"name\":\"export\",\"role\":\"unlabelled\"}],\"42457886506\":[{\"job_id\":128660701119,\"name\":\"CodeQL local SARIF (rust, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701102,\"name\":\"CodeQL local SARIF (actions, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701001,\"name\":\"CodeQL local SARIF (python, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886532\":[{\"job_id\":128660701100,\"name\":\"W1 transparent candidate (prospective-merge, x64)\",\"role\":\"prospective-merge\"}]},\"representatives\":[128660701001,128660701243,128660701244,128660701162,128660701340]}")
OUT=Path("/home/qian-qi/work/chain-w1-c6-ci-failure-diagnostic-20261108-ec265b-01")
OUT.mkdir(exist_ok=False)
repo="TrillionniumFoundation/Trillionnium-Chain"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def put(relative,raw):
 if isinstance(raw,str):raw=raw.encode()
 p=OUT/relative;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(raw)
 return {"path":relative,"bytes":len(raw),"sha256":sha(raw)}
def write_json(relative,value):return put(relative,json.dumps(value,indent=2,sort_keys=True)+"\n")
snapshot_raw=Path(SPEC["snapshot_path"]).read_bytes()
assert sha(snapshot_raw)==SPEC["snapshot_sha256"]
snapshot=json.loads(snapshot_raw)
assert snapshot["source_head"]=="2bdd252aa6c300b7431b9ee897b254b7953cf562"
put("snapshot.json",snapshot_raw)
write_json("failed-check-groups.json",SPEC["groups"])
gh=shutil.which("gh");assert gh
login=subprocess.run([gh,"api","user","--jq",".login"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
put("operator-login.stdout",login.stdout);put("operator-login.stderr",login.stderr)
write_json("operator-login-command.json",{"argv":[gh,"api","user","--jq",".login"],"exit_code":login.returncode})
assert login.returncode==0 and login.stdout.decode().strip()=="ProfHepta", "required configured operator not confirmed"
jobs={x["id"]:x for x in snapshot["check_runs"]}
tasks=[]
for job in SPEC["representatives"]:
 for kind,endpoint in [
  ("job",f"repos/{repo}/actions/jobs/{job}"),
  ("log",f"repos/{repo}/actions/jobs/{job}/logs"),
  ("annotations",f"repos/{repo}/check-runs/{job}/annotations?per_page=100")]:
  tasks.append((job,kind,endpoint))
def fetch(task):
 job,kind,endpoint=task
 base=f"jobs/{job}/{kind}"
 out=OUT/(base+".raw");err=OUT/(base+".stderr")
 out.parent.mkdir(parents=True,exist_ok=True)
 command=[gh,"api",endpoint]
 start=datetime.datetime.now(datetime.timezone.utc).isoformat()
 failure=None;code=None
 with out.open("xb") as stdout,err.open("xb") as stderr:
  try:
   p=subprocess.run(command,stdout=stdout,stderr=stderr,timeout=60)
   code=p.returncode
  except subprocess.TimeoutExpired as e:
   failure="TimeoutExpired:"+str(e.timeout)
 raw=out.read_bytes();errors=err.read_bytes()
 meta={"job_id":job,"kind":kind,"endpoint":endpoint,"argv":command,"started_utc":start,
       "finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
       "exit_code":code,"failure":failure,"stdout":{"path":base+".raw","bytes":len(raw),"sha256":sha(raw)},
       "stderr":{"path":base+".stderr","bytes":len(errors),"sha256":sha(errors)}}
 write_json(base+".fetch.json",meta)
 result={"job_id":job,"name":jobs[job]["name"],"kind":kind,"fetch_exit":code,
         "fetch_failure":failure,"bytes":len(raw)}
 if code==0 and kind=="job":
  d=json.loads(raw)
  result.update({"run_id":d.get("run_id"),"head_sha":d.get("head_sha"),
     "status":d.get("status"),"conclusion":d.get("conclusion"),
     "check_run_url":d.get("check_run_url"),
     "failed_steps":[s for s in d.get("steps",[]) if s.get("conclusion")=="failure"],
     "skipped_steps":[s.get("name") for s in d.get("steps",[]) if s.get("conclusion")=="skipped"]})
 elif code==0 and kind=="annotations":
  d=json.loads(raw);result["annotations"]=d
 elif code==0 and kind=="log":
  text=raw.decode("utf-8",errors="replace")
  lines=text.splitlines()
  hits=[{"line":i+1,"text":line[:1800]} for i,line in enumerate(lines)
        if re.search(r"##\[error\]|Traceback|(?:Error|ValueError|AssertionError):|fatal:|SOURCE_[A-Z_]+|MERGE_[A-Z_]+|BASE_[A-Z_]+|HEAD_[A-Z_]+|Process completed with exit code",line)]
  result["error_lines"]=hits[:8]+(hits[-8:] if len(hits)>8 else [])
  result["error_line_count"]=len(hits)
  result["last_lines"]=lines[-8:]
  result["secret_pattern_seen"]=bool(re.search(r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})",text))
 else:
  result["fetch_stderr"]=errors.decode("utf-8",errors="replace")[:2000]
 print(json.dumps(result,sort_keys=True),flush=True)
 return meta,result
records=[];results=[]
with ThreadPoolExecutor(max_workers=5) as pool:
 for future in as_completed([pool.submit(fetch,t) for t in tasks]):
  meta,result=future.result();records.append(meta);results.append(result)
write_json("fetch-manifest.json",{"schema":"TRNM-W1-C6-FAILED-CHECK-READBACK-FETCH1",
 "snapshot_sha256":SPEC["snapshot_sha256"],"expected_source":snapshot["source_head"],
 "operator":"ProfHepta","requests":records,"mutations":0,"reruns":0,"selected_job_ids":SPEC["representatives"]})
write_json("representative-readback.json",{"schema":"TRNM-W1-C6-FAILED-CHECK-REPRESENTATIVES1",
 "snapshot_failure_count":40,"prospective_named_failure_count":38,
 "sampled_jobs":SPEC["representatives"],"results":results,"all_failure_causes_inferred_from_samples":False})
print(json.dumps({"finished":True,"out":str(OUT),"request_count":len(records),
 "fetch_failures":[r for r in records if r["exit_code"]!=0],"mutations":0,"reruns":0}),flush=True)
