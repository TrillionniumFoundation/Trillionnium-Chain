#!/usr/bin/env python3
"""One authorized two-GET snapshot of the newly observed PR head and its comparison with R1."""
import concurrent.futures, datetime, hashlib, json, os, pathlib, stat, subprocess, sys, time
OUT=pathlib.Path("/private/tmp/chain-prci-remote-head-5df7ae6-commit-review-20261114-v1")
REPO="TrillionniumFoundation/Trillionnium-Chain"
NEW="5df7ae6f482157c5f7fdcbcd52222117a965053f"
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64"
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
def commit_view(c):
 d=c.get("commit",{})
 return {"sha":c.get("sha"),"tree":d.get("tree"),"parents":c.get("parents"),"message":d.get("message"),
 "author":d.get("author"),"committer":d.get("committer"),"author_account":c.get("author"),"committer_account":c.get("committer"),
 "html_url":c.get("html_url"),"verification":d.get("verification")}
def file_view(x):
 return {k:x.get(k)for k in ("sha","filename","status","additions","deletions","changes","previous_filename","patch")}
def main():
 need(sys.flags.optimize==0,"optimized execution forbidden")
 started=utc();OUT.mkdir(exist_ok=False)
 result={"schema":"trnm-new-PR-head-readonly-commit-compare-v1","status":"UNKNOWN","started_at":started,
 "repository":REPO,"base_candidate":HEAD,"new_observed_head":NEW,"maximum_GETs":2,"automatic_retry":False,
 "new_head_accepted_as_R1":False,"source_refs_stage_or_configuration_modified":False,"Git_commands_executed":False,
 "logs_or_artifacts_downloaded":False,"steps":[],"errors":[]}
 endpoints=[("new-commit","repos/"+REPO+"/commits/"+NEW),("R1-compare-new","repos/"+REPO+"/compare/"+HEAD+"..."+NEW)]
 with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:
  results=list(pool.map(lambda x:capture(x[0],x[1],8*1024*1024),endpoints))
 result["steps"]=results
 data={}
 for rec in results:
  if rec["complete_transport"]:
   try:data[rec["label"]]=read_json(pathlib.Path(rec["stdout"]["path"]))
   except Exception as e:result["errors"].append(rec["label"]+": "+type(e).__name__+": "+str(e))
  else:result["errors"].append(rec["label"]+": transport incomplete")
 if "new-commit"in data:
  c=data["new-commit"];need(c.get("sha")==NEW,"new commit identity mismatch")
  result["commit"]=commit_view(c);result["commit_stats"]=c.get("stats")
  result["commit_files_returned"]=[file_view(x)for x in c.get("files",[])]
  result["commit_file_count_returned"]=len(c.get("files",[]))
  result["commit_files_without_patch"]=[x["filename"]for x in c.get("files",[])if"patch"not in x]
  result["commit_patch_scope"]="Raw JSON API file patches, not full source blobs; API omission or truncation cannot be treated as full source review"
 if "R1-compare-new"in data:
  c=data["R1-compare-new"];need(c.get("base_commit",{}).get("sha")==HEAD,"comparison base mismatch")
  result["compare"]={k:c.get(k)for k in ("url","html_url","permalink_url","status","ahead_by","behind_by","total_commits")}
  result["compare"]["base_commit"]=commit_view(c["base_commit"])
  result["compare"]["merge_base_commit"]=commit_view(c.get("merge_base_commit",{}))
  result["compare"]["commits_returned"]=[commit_view(x)for x in c.get("commits",[])]
  result["compare"]["files_returned"]=[file_view(x)for x in c.get("files",[])]
  result["compare"]["all_commit_rows_returned"]=type(c.get("total_commits"))is int and len(c.get("commits",[]))==c["total_commits"]
  result["compare"]["API_reports_R1_ancestor"]=c.get("status")=="ahead"and c.get("behind_by")==0 and c.get("merge_base_commit",{}).get("sha")==HEAD
  result["compare"]["local_git_ancestry_not_tested"]=True
  result["compare"]["file_patch_scope"]="First unpaginated compare response; raw API supplied patches only; no extra source fetch"
 if len(data)==2 and not result["errors"]:result["status"]="OBSERVED_NEW_COMMIT_AND_COMPARE"
 else:result["status"]="PARTIAL"
 result["finished_at"]=utc();result["elapsed_seconds"]=round(time.monotonic()-START,6)
 result["producer"]=pin(pathlib.Path(__file__))
 sp=write("summary.json",result)
 files=[pin(p)for p in sorted(OUT.iterdir())if p.is_file()]
 ip=write("EVIDENCE_INDEX.json",{"schema":"trnm-fixed-original-file-index-v1","files":files,"self_excluded":True,"scope":"Exactly two read-only original API responses; newly observed head remains unaccepted"})
 print(json.dumps({"status":result["status"],"summary":sp,"index":ip,"commit":{k:result.get("commit",{}).get(k)for k in ("sha","tree","parents","message")},"files":[{k:v for k,v in x.items()if k!="patch"}for x in result.get("commit_files_returned",[])],"comparison":{k:result.get("compare",{}).get(k)for k in ("status","ahead_by","behind_by","total_commits","API_reports_R1_ancestor")}}),flush=True)
 return 0 if result["status"]=="OBSERVED_NEW_COMMIT_AND_COMPARE"else 1
if __name__=="__main__":raise SystemExit(main())
