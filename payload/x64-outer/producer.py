#!/usr/bin/env python3
"""One bounded read-only acquisition of the H5DF x64 cross-cost failure log and artifact metadata."""
import concurrent.futures, datetime, hashlib, json, os, pathlib, stat, subprocess, sys, time
OUT=pathlib.Path("/private/tmp/chain-prci-H5DF-cross-arch-cost-x64-original-log-20261114-v1")
REPO="TrillionniumFoundation/Trillionnium-Chain"
RUN=43621754143
HEAD="5df7ae6f482157c5f7fdcbcd52222117a965053f"
BRANCH="fix/chain-hepta-closure-candidate-20261109-481716"
WORKFLOW=".github/workflows/trnm-required-baseline.yml"
JOBS={132528768933:"cross-arch-cost (x64)"}
GH="/opt/homebrew/bin/gh"
ENV=os.environ.copy()
ENV.pop("GH_DEBUG",None)
ENV["GH_HOST"]="github.com"
ENV["PYTHONDONTWRITEBYTECODE"]="1"
ENV["PYTHONOPTIMIZE"]="0"
START=time.monotonic()
DEADLINE=START+300
def utc():
 return datetime.datetime.now(datetime.timezone.utc).isoformat()
def need(ok,msg):
 if not ok: raise ValueError(msg)
def fp(s):
 return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def pin(p):
 s=p.lstat()
 need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,"non-regular evidence")
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(65536),b""):h.update(b)
 need(fp(s)==fp(p.lstat()),"evidence changed")
 return dict(path=str(p),bytes=s.st_size,sha256=h.hexdigest())
def write(name,value):
 p=OUT/name
 raw=(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=False)+"\n").encode()
 with p.open("xb") as f:f.write(raw)
 return pin(p)
def unique_pairs(pairs):
 d={}
 for k,v in pairs:
  need(k not in d,"duplicate JSON key")
  d[k]=v
 return d
def read_json(p):
 return json.loads(p.read_bytes(),object_pairs_hook=unique_pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError("non-finite JSON")))
def capture(label,endpoint,cap):
 out=OUT/(label+".stdout");err=OUT/(label+".stderr")
 argv=[GH,"api","--hostname","github.com","--method","GET",endpoint]
 record=dict(label=label,argv=argv,cwd="/private/tmp",endpoint=endpoint,method="GET",
             origin="https://api.github.com/"+endpoint,started_at=utc(),timeout_seconds=300,
             overall_deadline_seconds=300,stdout_cap_bytes=cap,stderr_cap_bytes=2*1024*1024,
             exit=None,termination_reason=None,HTTP_status_unparsed=True,
             automatic_retry=False,GH_DEBUG_removed=True,GH_HOST="github.com")
 t=time.monotonic()
 with out.open("xb") as of,err.open("xb") as ef:
  p=subprocess.Popen(argv,cwd="/private/tmp",env=ENV,stdin=subprocess.DEVNULL,stdout=of,stderr=ef)
  while p.poll() is None:
   if time.monotonic()>=DEADLINE:record["termination_reason"]="overall_300_second_deadline"
   elif os.fstat(of.fileno()).st_size>cap or os.fstat(ef.fileno()).st_size>2*1024*1024:
    record["termination_reason"]="bounded_output_cap"
   if record["termination_reason"]:
    p.terminate()
    try:p.wait(timeout=3)
    except subprocess.TimeoutExpired:p.kill();p.wait()
    break
   time.sleep(0.1)
  record["exit"]=p.wait()
 record.update(finished_at=utc(),elapsed_seconds=round(time.monotonic()-t,6),stdout=pin(out),stderr=pin(err))
 record["complete_transport"]=record["exit"]==0 and record["termination_reason"] is None
 record["step_receipt"]=write(label+".step.json",record)
 print(json.dumps(dict(label=label,exit=record["exit"],complete_transport=record["complete_transport"],
                       stdout_bytes=record["stdout"]["bytes"],stdout_sha256=record["stdout"]["sha256"])),flush=True)
 return record
def one(jid,name):
 row=dict(job_id=jid,expected_name=name,identity_valid=False,log_complete=False,steps=[],error=None)
 try:
  m=capture("job-"+str(jid)+"-metadata","repos/"+REPO+"/actions/jobs/"+str(jid),2*1024*1024)
  row["steps"].append(m)
  need(m["complete_transport"],"job metadata transport incomplete")
  j=read_json(pathlib.Path(m["stdout"]["path"]))
  need(j.get("id")==jid and j.get("run_id")==RUN and j.get("run_attempt")==1,"job/run/attempt mismatch")
  need(j.get("head_sha")==HEAD and j.get("name")==name,"job head/name mismatch")
  need(j.get("status")=="completed" and j.get("conclusion")=="failure","job not completed failure")
  need(j.get("html_url")=="https://github.com/"+REPO+"/actions/runs/"+str(RUN)+"/job/"+str(jid),"job details URL mismatch")
  row.update(identity_valid=True,observed_job={k:j.get(k) for k in (
   "id","run_id","run_attempt","name","head_sha","head_branch","workflow_name","status","conclusion",
   "html_url","started_at","completed_at","steps")})
  q=capture("job-"+str(jid)+"-original-log","repos/"+REPO+"/actions/jobs/"+str(jid)+"/logs",20*1024*1024)
  row["steps"].append(q)
  row["log_complete"]=q["complete_transport"]
  if not row["log_complete"]:row["error"]="original log transport incomplete; retained bytes are partial"
 except Exception as e:row["error"]=type(e).__name__+": "+str(e)
 return row
PRIOR=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/H5DF-required-ci-progress-v1-ready-001/H5DF-run-43621754143-metadata.stdout")
PRIOR_PIN={"path":str(PRIOR),"bytes":15868,"sha256":"fc337869d51d0c17253de3970edadd8f7ee9739d993b2c8b385d9bf0020dd9b2"}
ORIGINAL_HELPER_PIN={"path":"/private/tmp/chain-prci-R1-prospective-Rust-runtime-original-log-20261114-v1/producer.py","bytes":7384,"sha256":"e2996e652d160530a854585c3d95a69879f71bcbb57e669b8380149b2469ac44"}
def main():
 need(sys.flags.optimize==0,"optimized execution forbidden")
 result=dict(schema="trnm-H5DF-cross-cost-original-log-acquisition-v1",status="UNKNOWN",
  started_at=utc(),finished_at=None,repository=REPO,run_id=RUN,run_attempt=1,head=HEAD,
  workflow_path=WORKFLOW,allowed_job_ids=list(JOBS),overall_budget_seconds=300,
  read_only=True,network_methods=["GET"],maximum_GETs=3,automatic_retry=False,
  prior_run_metadata=PRIOR_PIN,jobs=[],artifact_list=None,artifact_candidates=[],errors=[],
  check_head_is_not_tested_source_proof=True,actual_tested_source_verified=False,
  native_tests_executed=False,ci_actions=False,qualification=False,
  original_capture_helper=ORIGINAL_HELPER_PIN,source_refs_stage_changes=False,
  complete_artifact_list_claimed=False,artifacts_downloaded=False)
 try:
  need(pin(PRIOR)==PRIOR_PIN,"existing exact run metadata pin differs")
  originalpath=pathlib.Path(ORIGINAL_HELPER_PIN["path"])
  need(pin(originalpath)==ORIGINAL_HELPER_PIN,"approved capture source differs")
  obj=read_json(PRIOR)
  need(obj.get("id")==RUN and obj.get("run_attempt")==1 and obj.get("head_sha")==HEAD,"pinned run identity differs")
  need(obj.get("path")==WORKFLOW and obj.get("event")=="pull_request" and obj.get("head_branch")==BRANCH and obj.get("workflow_id")==345677268,"pinned workflow identity differs")
  need(obj.get("repository",{}).get("full_name")==REPO and any(x.get("number")==847 for x in obj.get("pull_requests",[])),"pinned PR/repository relation differs")
  result["prior_run_identity_valid"]=True
  result["prior_run_observation"]="Existing ready001 raw GET finished 2026-11-14T17:41:55.724718+00:00; not a fresh new GET here"
  result["observed_run"]={k:obj.get(k) for k in ("id","run_attempt","workflow_id","path","event","head_sha","head_branch","status","conclusion","pull_requests","created_at","updated_at")}
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   jobfuture=pool.submit(one,132528768933,JOBS[132528768933])
   artifactfuture=pool.submit(capture,"run-"+str(RUN)+"-artifacts-page-001",
    "repos/"+REPO+"/actions/runs/"+str(RUN)+"/artifacts?per_page=100&page=1",4*1024*1024)
   result["jobs"]=[jobfuture.result()]
   result["artifact_list"]=artifactfuture.result()
  a=result["artifact_list"]
  if a["complete_transport"] and a["stdout"]["bytes"]<=4*1024*1024:
   listed=read_json(pathlib.Path(a["stdout"]["path"]))
   need(type(listed.get("total_count")) is int and type(listed.get("artifacts")) is list,"artifact response shape invalid")
   result["artifact_list_total_count"]=listed["total_count"]
   result["artifact_list_returned_count"]=len(listed["artifacts"])
   result["complete_artifact_list_claimed"]=listed["total_count"]==len(listed["artifacts"])<=100
   name="cost-x64-"+HEAD+"-1"
   for item in listed["artifacts"]:
    if item.get("name")==name:
     result["artifact_candidates"].append({k:item.get(k) for k in ("id","name","size_in_bytes","digest","expired","created_at","updated_at","expires_at","workflow_run","url","archive_download_url")})
  result["status"]="ACQUIRED" if all(r["identity_valid"] and r["log_complete"] for r in result["jobs"]) and a["complete_transport"] else "PARTIAL"
  need(pin(PRIOR)==PRIOR_PIN,"pinned prior changed")
 except Exception as e:result["errors"].append(type(e).__name__+": "+str(e))
 if result["errors"]:result["status"]="UNKNOWN" if not result["jobs"] else "PARTIAL"
 result["finished_at"]=utc();result["elapsed_seconds"]=round(time.monotonic()-START,6)
 result["producer"]=pin(pathlib.Path(__file__))
 sp=write("acquisition-summary.json",result)
 ip=write("EVIDENCE_INDEX.json",{"schema":"trnm-fixed-original-file-index-v1",
  "files":[pin(p) for p in sorted(OUT.iterdir()) if p.is_file()],"self_excluded":True,
  "coverage":"Only one job metadata, one original log and one run artifact page; no artifact contents and no actual tested-source inference"})
 print(json.dumps({"status":result["status"],"summary":sp,"index":ip,
  "artifact_candidates":result["artifact_candidates"],"qualification":False}),flush=True)
 return 0 if result["status"]=="ACQUIRED" else 1
if __name__=="__main__":raise SystemExit(main())
