import os,sys,stat,json,hashlib,collections,datetime
from pathlib import Path
assert sys.flags.optimize==0
I=json.loads(sys.argv[1])
ROOT=Path("/private/tmp/chain-consolidation-20261114-root")
D=ROOT/"H5DF-required-ci-progress-v1-ready-002"
OUT=Path("/private/tmp/chain-prci-H5DF-pr-body-preparation-20261114-v1/ready002-offline-delta-v1")
reads={}
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,n=None,h=None):
 p=Path(p);assert p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<8*1024*1024
  raw=b""
  while True:
   b=os.read(fd,1048576)
   if not b:break
   raw+=b
  assert fp(a)==fp(os.fstat(fd))==fp(p.lstat())
 finally:os.close(fd)
 pin={"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
 if n is not None:assert len(raw)==n and pin["sha256"]==h
 reads[str(p)]=(pin,fp(a));return raw,pin
def jr(p,n=None,h=None):
 r,p=read(p,n,h);return json.loads(r),p
s,sp=jr(D/"summary.json",14262,"222d90ad169c08fc1a73a91f042169fa88bd005197d69587945af03c5c65e005")
ix,ip=jr(D/"EVIDENCE_INDEX.json",4375,"34a3c240d3f8757ec2735e5eec6a9e59e75f32092408ede153dc48299cb9210e")
terminal,tp=jr(ROOT/"H5DF-required-ci-progress-v1-ready-002-actual-terminal.json",4531,"c5da3e410e9a4d526933013274bed142055c688020f4b62e9f327a8fb8a3fe0c")
assert s["status"]=="OBSERVED"and s["errors"]==[]and s["metadata_pages_complete"]is True
assert len(s["steps"])==6 and all(x["exit"]==0 and x["timed_out"]is False and x["spawn_error"]is None for x in s["steps"])
for row in ix["files"]:read(row["path"],row["bytes"],row["sha256"])
run=s["required_runs"]["run_jobs"][0]
assert len(s["required_runs"]["run_jobs"])==1 and run["run_id"]==43621754143 and run["observed_attempt"]==1
jobs,jp=jr(run["jobs"]["path"],run["jobs"]["bytes"],run["jobs"]["sha256"])
current=[x for x in jobs if x["matches_observed_run_attempt"]is True]
assert len(current)==19 and len({j["id"]for j in current})==19 and all(j["run_id"]==43621754143 and j["run_attempt"]==1 and j["head_sha"]=="5df7ae6f482157c5f7fdcbcd52222117a965053f"for j in current)
req=[]
for name in I["required_names"]:
 matches=[x for x in current if x["name"]==name];assert len(matches)<=1
 if not matches: req.append({"name":name,"job_id":None,"state":"absent","source_kind_name_hint":"prospective"if name.startswith("prospective")else"head"});continue
 j=matches[0]
 state="success"if j["status"]=="completed"and j["conclusion"]=="success"else"failure"if j["status"]=="completed"and j["conclusion"]=="failure"else"running"if j["status"]=="in_progress"else j["status"]+"/"+str(j["conclusion"])
 req.append({"name":name,"job_id":j["id"],"state":state,"status":j["status"],"conclusion":j["conclusion"],"source_kind_name_hint":"prospective"if name.startswith("prospective")else"head","started_at":j["started_at"],"completed_at":j["completed_at"],"html_url":j["html_url"],"current_steps":[x for x in j["steps"]if x["status"]=="in_progress"],"failed_steps":[x for x in j["steps"]if x["conclusion"]=="failure"],"actual_tested_source_verified":False})
prior,pp=jr(ROOT/"H5DF-required-ci-progress-v1-ready-001/closed-snapshot-v1/progress-delta.json",20609,"c243aadb84c997b525bab9afe76bb46e4d182cf7c475a2b91a61ffe690f80660")
pm={x["name"]:x for x in prior["required"]}
changes=[{"name":x["name"],"previous":{k:pm[x["name"]].get(k)for k in("job_id","state","status","conclusion")},"now":{k:x.get(k)for k in("job_id","state","status","conclusion")}}for x in req if any(x.get(k)!=pm[x["name"]].get(k)for k in("job_id","state","status","conclusion"))]
raw=bytes.fromhex(terminal["bytes_hex"])
assert terminal["session_id"]=="dpty-32ddf1dda63839aa47791d89b9038252145de47685a2c950511d61a0d9bde062"and terminal["offset"]==0 and terminal["next_offset"]==terminal["available_end"]==len(raw)==1142
assert hashlib.sha256(raw).hexdigest()==terminal["chunk_sha256"]=="15653f0c5dea153e9f4b15e22b3f90043fa8491a29e12c61fcabcdc214aa4666"
assert terminal["status"]["state"]=="exited"and terminal["status"]["exit_code"]==0 and terminal["output_complete"]is True and terminal["status"]["capture_error"]is None
printed=json.loads(raw.decode().splitlines()[-1]);assert printed["summary"]==sp and printed["index"]==ip
archive,ap=jr(ROOT/"postpublication-diagnostics-publish-v1-r1-resume-002/summary.json",440684,"70520e50f0259eb283252919ca4aa9f6da92bf15b8d5fff5d8c57dd2e0332ded")
at,atp=jr(ROOT/"postpublication-diagnostics-resume-002-actual-terminal-v1.json",4322,"c3a04e0495394b1d6eb7b18f1eda3ed2f4a520d21252e0348e9be90bd149b738")
araw=bytes.fromhex(at["bytes_hex"]);assert len(araw)==at["available_end"]==at["next_offset"]==1087 and at["offset"]==0 and hashlib.sha256(araw).hexdigest()==at["chunk_sha256"]
assert at["status"]["state"]=="exited"and at["status"]["exit_code"]==0 and at["output_complete"]is True
al=json.loads(araw.decode().splitlines()[-1])
assert archive["status"]==al["status"]=="confirmed"and archive["push_exit"]==al["push_exit"]==0 and archive["source_after_valid"]is True and archive["exact_hook_verified"]is True
assert archive["archive"]==al["archive"]and archive["archive"]["commit"]=="ffc6e0ca4bfa7794ab6031a6e398dcd08b7a1982"and archive["archive"]["source_commit"]=="2a86462a1ab20c68151719ba4635e3c294391e64"
OUT.mkdir(exist_ok=False);made=[]
def save(name,x):
 raw=x if isinstance(x,bytes)else(json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
 p=OUT/name
 with p.open("xb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
 pin=read(p,len(raw),hashlib.sha256(raw).hexdigest())[1];made.append(pin);return pin
save("closure-producer.py",sys.argv[2].encode())
facts={"schema":"trnm-H5DF-ready002-offline-closure-v1","status":"OBSERVED_METADATA_ONLY","closed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"original_summary":sp,"original_index":ip,"actual_terminal":tp,"actual_terminal_SHA":terminal["chunk_sha256"],"snapshot_start":s["started_at"],"snapshot_end":s["finished_at"],"run_id":43621754143,"attempt":1,"PR":s["pr"],"required_counts":dict(collections.Counter(x["state"]for x in req)),"required":req,"changes_since_ready001":changes,"prior_snapshot":pp,"all_run_job_counts":run["observed_attempt_job_counts"],"failed_jobs":[{"name":j["name"],"job_id":j["id"],"status":j["status"],"conclusion":j["conclusion"],"html_url":j["html_url"],"failed_steps":[x for x in j["steps"]if x["conclusion"]=="failure"]}for j in current if j["conclusion"]=="failure"],"raw_GET_exits":[{"label":x["label"],"exit":x["exit"]}for x in s["steps"]],"full_raw_index_file_hashes_verified":True,"actual_tested_source_verified":False,"source_kind_labels_are_metadata_hints_only":True,"no_network_or_tests_or_mutations_in_this_review":True,"qualification":False}
dp=save("progress-delta.json",facts)
arc=save("confirmed-R1-diagnostic-archive-reference.json",{"schema":"trnm-existing-archive-closed-reference-v1","source_summary":ap,"actual_terminal":atp,"actual_status":archive["status"],"actual_push_exit":archive["push_exit"],"source_after_valid":archive["source_after_valid"],"exact_hook_verified":archive["exact_hook_verified"],"archive":archive["archive"],"R1_scope_not_H5DF":True,"not_newly_executed_or_republished":True})
pins=list(reads.values())
for pin,ident in pins:read(pin["path"],pin["bytes"],pin["sha256"]);assert fp(Path(pin["path"]).lstat())==ident
idx=save("EVIDENCE_INDEX.json",{"schema":"trnm-offline-review-evidence-index-v1","files":[v[0]for k,v in sorted(reads.items())],"self_excluded":True})
print(json.dumps({"status":"CLOSED","delta":dp,"archive_reference":arc,"index":idx,"counts":facts["required_counts"],"required":req,"failures":facts["failed_jobs"]},sort_keys=True))
