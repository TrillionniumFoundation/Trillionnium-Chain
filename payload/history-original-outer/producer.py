#!/usr/bin/env python3
"""One bounded read-only acquisition of one fixed R1 history job log."""
import concurrent.futures, datetime, hashlib, json, os, pathlib, stat, subprocess, sys, time
OUT=pathlib.Path("/private/tmp/chain-R1-native-priorities-history-log-review-20261114-v1")
REPO="TrillionniumFoundation/Trillionnium-Chain"
RUN=43604217565
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64"
BRANCH="fix/chain-hepta-closure-candidate-20261109-481716"
WORKFLOW=".github/workflows/pon-priority-acceptance.yml"
JOBS={132475258347:"native priorities (ubuntu-24.04, head, history)"}
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
def main():
 need(sys.flags.optimize==0,"optimized execution forbidden")
 started=utc()
 result=dict(schema="trnm-r1-native-priorities-history-original-log-acquisition-v1",
  status="UNKNOWN",started_at=started,finished_at=None,run_id=RUN,run_attempt=1,head=HEAD,
  workflow_path=WORKFLOW,repository=REPO,allowed_job_ids=list(JOBS),overall_budget_seconds=300,
  read_only=True,network_methods=["GET"],automatic_retry=False,run_metadata=None,jobs=[],errors=[],
  check_head_is_not_tested_source_proof=True,actual_tested_source_verified=False,
  native_tests_executed=False,ci_actions=False,qualification=False)
 try:
  r=capture("run-"+str(RUN)+"-metadata","repos/"+REPO+"/actions/runs/"+str(RUN),2*1024*1024)
  result["run_metadata"]=r
  need(r["complete_transport"],"run metadata transport incomplete")
  obj=read_json(pathlib.Path(r["stdout"]["path"]))
  need(obj.get("id")==RUN and obj.get("run_attempt")==1 and obj.get("head_sha")==HEAD,"run id/attempt/head mismatch")
  need(obj.get("path")==WORKFLOW and obj.get("event")=="pull_request" and obj.get("head_branch")==BRANCH,"run path/event/branch mismatch")
  need(obj.get("repository",{}).get("full_name")==REPO,"repository mismatch")
  need(any(x.get("number")==847 for x in obj.get("pull_requests",[])),"PR847 relation absent")
  result["run_identity_valid"]=True
  result["observed_run"]={k:obj.get(k) for k in ("id","run_attempt","workflow_id","path","event","head_sha","head_branch","status","conclusion","pull_requests","created_at","updated_at")}
  with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
   fut=[pool.submit(one,j,n) for j,n in JOBS.items()]
   result["jobs"]=[f.result() for f in fut]
  result["status"]="ACQUIRED" if all(r["identity_valid"] and r["log_complete"] for r in result["jobs"]) else "PARTIAL"
 except Exception as e:result["errors"].append(type(e).__name__+": "+str(e))
 result["finished_at"]=utc()
 result["elapsed_seconds"]=round(time.monotonic()-START,6)
 result["producer"]=pin(pathlib.Path(__file__))
 sp=write("acquisition-summary.json",result)
 files=[pin(p) for p in sorted(OUT.iterdir()) if p.is_file()]
 ip=write("EVIDENCE_INDEX.json",{"schema":"trnm-fixed-original-file-index-v1","files":files,
   "self_excluded":True,"coverage":"Only this one bounded GET acquisition; no CI rerun and no tested-source inference"})
 print(json.dumps({"status":result["status"],"summary":sp,"index":ip,"qualification":False}),flush=True)
 return 0 if result["status"]=="ACQUIRED" else 1
if __name__=="__main__":raise SystemExit(main())
