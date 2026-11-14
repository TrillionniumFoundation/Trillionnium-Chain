import os,sys,json,hashlib,stat,datetime,re,collections
from pathlib import Path
assert sys.flags.optimize==0
P=json.loads(sys.argv[1])
BASE=Path("/private/tmp/chain-consolidation-20261114-root/R1-required-ci-progress-v1-ready-019")
OUT=BASE/"closed-snapshot-v1"
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(pin):
 p=Path(pin["path"])
 if p.resolve(strict=True)!=p:raise ValueError("canonical input")
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size>1024*1024:raise ValueError("bounded regular input")
  if fp(p.lstat())!=fp(s):raise ValueError("before identity")
  b=b""
  while True:
   q=os.read(fd,65536)
   if not q:break
   b+=q
  if fp(os.fstat(fd))!=fp(s) or fp(p.lstat())!=fp(s):raise ValueError("changed input")
 finally:os.close(fd)
 if len(b)!=pin["bytes"] or hashlib.sha256(b).hexdigest()!=pin["sha256"]:raise ValueError("input pin")
 return b
def jsondata(pin):return json.loads(read(pin))
summary=jsondata(P["pins"]["summary"]);index=jsondata(P["pins"]["index"])
for pin in index["files"]:read(pin)
def rows(pin,key):
 v=jsondata(pin)
 return v if type(v)is list else v[key]
jobs=rows(P["pins"]["jobs"],"jobs");priorjobs=rows(P["prior_jobs"],"jobs")
checks=rows(P["pins"]["checks"],"check_runs");priorchecks=rows(P["prior_checks"],"check_runs")
pos=0;raw=[]
for page in P["pages"]:
 if page["offset"]!=pos or page["truncated_before_offset"] or page["text_is_lossy"]:raise ValueError("terminal page range")
 part=bytes.fromhex(page["bytes_hex"])
 if hashlib.sha256(part).hexdigest()!=page["chunk_sha256"] or len(part)!=page["next_offset"]-pos:raise ValueError("terminal page bytes")
 raw.append(part);pos=page["next_offset"]
last=P["pages"][-1]
if not(last["output_complete"] is True and last["status"]["state"]=="exited" and last["status"]["exit_code"]==0 and pos==last["available_end"]):raise ValueError("actual terminal incomplete")
if len(P["required_names"])!=14 or len(set(P["required_names"]))!=14:raise ValueError("required roster")
byname={}
for job in jobs:
 if job["name"] in byname:raise ValueError("duplicate job name")
 byname[job["name"]]=job
def compact(job):
 return {k:job.get(k) for k in ("id","name","run_id","run_attempt","head_sha","status","conclusion","html_url","started_at","completed_at")}|{"active_or_failed_steps":[x for x in job.get("steps",[]) if x.get("status")=="in_progress" or x.get("conclusion")=="failure"]}
required=[]
for name in P["required_names"]:
 required.append(compact(byname[name]) if name in byname else {"name":name,"status":"absent","conclusion":None,"id":None,"active_or_failed_steps":[]})
def count(rows):
 c=collections.Counter()
 for v in rows:
  if v["status"]=="absent":c["absent"]+=1
  elif v["status"]=="completed":c[v.get("conclusion") or "unknown"]+=1
  else:c[v["status"]]+=1
 return dict(c)
oldjobs={v["id"]:v for v in priorjobs};oldchecks={v["id"]:v for v in priorchecks}
newjobs=[compact(v) for v in jobs if v.get("conclusion")=="failure" and oldjobs.get(v["id"],{}).get("conclusion")!="failure"]
newchecks=[{k:v.get(k) for k in ("id","name","head_sha","status","conclusion","details_url","started_at","completed_at","app")} for v in checks if v.get("conclusion")=="failure" and oldchecks.get(v["id"],{}).get("conclusion")!="failure"]
report={"schema":"trnm-r1-required-progress-ready019-closure-v1","status":"OBSERVED_METADATA_ONLY","created_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"original_summary":P["pins"]["summary"],"original_index":P["pins"]["index"],"observed_from":summary["started_at"],"observed_to":summary["finished_at"],"pr":summary["pr"],"run_id":43604217412,"run_attempt":1,"required_names_count":14,"required_counts":count(required),"required_jobs":required,"all_required_workflow_job_counts":count([compact(x) for x in jobs]),"latest_check_counts":summary["latest_checks"]["status_counts"],"new_failed_jobs_since_ready018":newjobs,"new_failed_checks_since_ready018":newchecks,"prior_snapshot_pins":{"jobs":P["prior_jobs"],"checks":P["prior_checks"]},"original_jobs_pin":P["pins"]["jobs"],"original_checks_pin":P["pins"]["checks"],"source_identity_scope":"API metadata only; neither name nor PR merge_commit_sha proves actual tested checkout source","new_failure_inner_cause":"UNKNOWN_NOT_DOWNLOADED","head_protocol_cause_reference":{"path":"/private/tmp/chain-R1-required-head-protocol-artifact-review-20261114-v1/final-review-v1/review.json","bytes":42945,"sha256":"9c87e3d8ba331bcc467169ff5fd5f52b27efcf7afd44343a273e03ba0e356f42","basis":"Parent and ci_repairs supplied an independent already-closed diagnosis; this snapshot did not download or revalidate the artifact","cause":"CONFIRMATION_TARGET; first replay accepted through 3.999257347s, second History challenge IO11; not inherited from cross-cost PUBLIC_REQUEST_DEADLINE","not_applied_to_prospective_failure":True},"read_only":True,"new_network_requests_by_closure":0,"CI_actions":False,"extra_logs_or_artifacts_downloaded":False,"hosted_qualification_granted":False,"ready017_unknown_preserved":True,"ready018_failure_preserved":True}
OUT.mkdir(exist_ok=False)
def put(n,b):
 p=OUT/n
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 pin={"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
 read(pin);return pin
def js(v):return(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+"\n").encode()
created=[]
created.append(put("closure-producer.py",sys.argv[2].encode()))
created.append(put("approved-launcher.py",P["launcher"].encode()))
created.append(put("actual-launch.json",js(P["launch"])))
created.append(put("actual-terminal-pages.json",js({"schema":"trnm-actual-pty-pages-v1","session_id":last["session_id"],"archive_path":last["archive_path"],"terminal":last,"pages":P["pages"]})))
created.append(put("actual-terminal.log",b"".join(raw)))
reportpin=put("progress-delta.json",js(report));created.append(reportpin)
for pin in index["files"]:read(pin)
union=index["files"]+[P["pins"]["index"]]+created
if len({x["path"] for x in union})!=len(union):raise ValueError("duplicate closure path")
closureindex=put("EVIDENCE_INDEX.json",js({"schema":"trnm-r1-ready019-full-snapshot-index-v1","files":union,"count":len(union),"bytes":sum(x["bytes"]for x in union),"self_excluded":True,"prior_snapshot_files_referenced_not_changed":True}))
seal=put("seal-summary.json",js({"schema":"trnm-r1-ready019-snapshot-seal-v1","status":"CLOSED","progress":reportpin,"index":closureindex,"indexed_files":len(union),"indexed_bytes":sum(x["bytes"]for x in union),"actual_terminal_exit":0,"actual_terminal_output_complete":True,"snapshot_scope":"metadata only; no qualification","automatic_polling":False}))
print(json.dumps({"status":"CLOSED","report":reportpin,"index":closureindex,"seal":seal,"required_counts":report["required_counts"],"new_failed_jobs":newjobs,"new_failed_checks":newchecks},sort_keys=True),flush=True)
