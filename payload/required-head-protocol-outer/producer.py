#!/usr/bin/env python3
"""One read-only acquisition of the fixed H5DF required head protocol failure; exactly bounded two GETs."""
import concurrent.futures, datetime, hashlib, json, os, pathlib, stat, subprocess, sys, time
OUT=pathlib.Path("/private/tmp/chain-prci-H5DF-required-head-protocol-original-log-20261114-v1")
REPO="TrillionniumFoundation/Trillionnium-Chain"
RUN=43621754143
HEAD="5df7ae6f482157c5f7fdcbcd52222117a965053f"
BRANCH="fix/chain-hepta-closure-candidate-20261109-481716"
WORKFLOW=None # Job API does not independently identify a workflow source path.
JOBS={132528769008:"protocol-contract"}
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
             origin="https://api.github.com/"+endpoint,started_at=utc(),timeout_seconds=120,
             overall_deadline_seconds=300,stdout_cap_bytes=cap,stderr_cap_bytes=2*1024*1024,
             exit=None,termination_reason=None,HTTP_status_unparsed=True,
             automatic_retry=False,GH_DEBUG_removed=True,GH_HOST="github.com")
 t=time.monotonic()
 with out.open("xb") as of,err.open("xb") as ef:
  p=subprocess.Popen(argv,cwd="/private/tmp",env=ENV,stdin=subprocess.DEVNULL,stdout=of,stderr=ef)
  while p.poll() is None:
   if time.monotonic()>=DEADLINE:record["termination_reason"]="overall_300_second_deadline"
   elif time.monotonic()-t>=120:record["termination_reason"]="per_request_120_second_deadline"
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

PRIOR_PIN={"path":"/private/tmp/chain-consolidation-20261114-root/H5DF-required-ci-progress-v1-ready-004/H5DF-run-43621754143-jobs-page-001.stdout","bytes":64264,"sha256":"d23f8c1bacccc84de5b23d1915b521017bb22a033faf97dc835f01fa4ee861fc"}
ORIGINAL_HELPER_PIN={"path":"/private/tmp/chain-prci-H5DF-cross-arch-cost-x64-original-log-20261114-v1/producer.py","bytes":9427,"sha256":"54a584717bb86071cfa2afe7a03ca5ad9aa6de4cd7ac968d636f1b228cd9b0b2"}
def main():
 need(sys.flags.optimize==0,"optimized execution forbidden")
 result=dict(schema="trnm-H5DF-required-head-protocol-original-log-acquisition-v1",status="UNKNOWN",
  started_at=utc(),finished_at=None,repository=REPO,run_id=RUN,run_attempt=1,head=HEAD,
  allowed_job_ids=list(JOBS),overall_budget_seconds=300,per_request_budget_seconds=120,
  read_only=True,network_methods=["GET"],maximum_GETs=2,automatic_retry=False,
  existing_metadata_snapshot=PRIOR_PIN,jobs=[],errors=[],
  check_head_is_not_tested_source_proof=True,actual_tested_source_verified=False,
  prospective_source_from_name_inferred=False,required14_membership=True,
  native_tests_executed=False,ci_actions=False,qualification=False,
  original_capture_helper=ORIGINAL_HELPER_PIN,source_refs_stage_changes=False,
  artifacts_downloaded=False)
 try:
  need(pin(pathlib.Path(PRIOR_PIN["path"]))==PRIOR_PIN,"existing ready004 snapshot pin differs")
  need(pin(pathlib.Path(ORIGINAL_HELPER_PIN["path"]))==ORIGINAL_HELPER_PIN,"approved capture source differs")
  prior=read_json(pathlib.Path(PRIOR_PIN["path"]))
  found={r["id"]:r for r in prior["jobs"] if r.get("id") in JOBS}
  need(set(found)==set(JOBS),"existing fixed jobs absent")
  for jid,name in JOBS.items():
   j=found[jid]
   need(j["name"]==name and j["run_id"]==RUN and j["run_attempt"]==1 and j["head_sha"]==HEAD and j["status"]=="completed" and j["conclusion"]=="failure","prior job identity mismatch")
  result["prior_check_rows"]=[found[jid] for jid in JOBS]
  with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
   futures={jid:pool.submit(one,jid,name) for jid,name in JOBS.items()}
   result["jobs"]=[futures[jid].result() for jid in JOBS]
  result["actual_GETs"]=sum(len(r["steps"]) for r in result["jobs"])
  need(result["actual_GETs"]<=2,"unexpected GET count")
  result["status"]="ACQUIRED" if all(r["identity_valid"] and r["log_complete"] for r in result["jobs"]) else "PARTIAL"
  need(pin(pathlib.Path(PRIOR_PIN["path"]))==PRIOR_PIN,"prior snapshot changed")
 except Exception as e:
  result["errors"].append(type(e).__name__+": "+str(e))
  result["status"]="PARTIAL" if result["jobs"] else "UNKNOWN"
 result["finished_at"]=utc();result["elapsed_seconds"]=round(time.monotonic()-START,6)
 result["producer"]=pin(pathlib.Path(__file__))
 sp=write("acquisition-summary.json",result)
 ip=write("EVIDENCE_INDEX.json",{"schema":"trnm-fixed-original-file-index-v1",
  "files":[pin(p) for p in sorted(OUT.iterdir()) if p.is_file()],"self_excluded":True,
  "coverage":"Only the named required head protocol completed-failure job metadata and original log; no run refresh or artifact contents; actual tested source requires original log evidence"})
 print(json.dumps({"status":result["status"],"summary":sp,"index":ip,"actual_GETs":result.get("actual_GETs"),"qualification":False}),flush=True)
 return 0 if result["status"]=="ACQUIRED" else 1
if __name__=="__main__":raise SystemExit(main())
