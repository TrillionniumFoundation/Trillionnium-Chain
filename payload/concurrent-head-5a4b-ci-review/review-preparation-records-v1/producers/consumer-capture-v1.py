#!/usr/bin/env python3
"""Read only fixed Git consumer references and three historical contracts."""
import hashlib,json,os,stat,subprocess,time
from pathlib import Path
OUT=Path("/private/tmp/chain-ci-new-candidate-5a4b7fe8-review-20261114-v1/consumer-closure-v1")
DB="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git"
WT="/private/tmp/chain-consolidation-20261114-mainline"
REVS={"C0":"dc42ce4df5cff79cc61c5addbaf01074b56b06ca","M6":"2a62061177852dc3ebd200fa8d7c66c661a119a1","N":"5a4b7fe8de1adce803184f262fd9f704ead1930c"}
PATHS=["config/pon/pq128-lifetime-budget-v1.json","config/pon/pq128-source-lock-v1.json","config/pon/pq128-lifetime-composition-v2.json","config/pon/pq-proof-profile-binding-v1.json","scripts/ci/pq_lifetime_budget.py","scripts/ci/pq_proof_profile_binding.py","scripts/ci/pq_root_lifetime_register.py"]
ENV=dict(os.environ)
for k in list(ENV):
 if k.startswith("GIT_TRACE") or k in ("GIT_CURL_VERBOSE","GIT_DIFF_OPTS"): ENV.pop(k,None)
ENV.update({"PATH":"/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin","GIT_OPTIONAL_LOCKS":"0","GIT_NO_LAZY_FETCH":"1","GIT_NO_REPLACE_OBJECTS":"1","GIT_ALLOW_PROTOCOL":"","GIT_TERMINAL_PROMPT":"0","GIT_TRACE2":"0","GIT_TRACE2_EVENT":"0","GIT_TRACE2_PERF":"0","PYTHONDONTWRITEBYTECODE":"1"})
def sha(b):return hashlib.sha256(b).hexdigest()
def put(n,b):
 p=OUT/n;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(b)
 assert p.read_bytes()==b
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
steps=[];files=[]
def run(label,args,work=False,allowed=(0,),cap=2*1024*1024):
 argv=["/usr/bin/git","--no-pager"]+(["-C",WT] if work else ["--git-dir="+DB])+args
 t=time.time_ns()
 try:r=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,timeout=60);rc,out,err=r.returncode,r.stdout,r.stderr
 except subprocess.TimeoutExpired as e:rc,out,err=124,e.stdout or b"",e.stderr or b""
 row={"label":label,"argv":argv,"exit":rc,"started_ns":t,"finished_ns":time.time_ns(),"stdout":put("raw/"+label+".stdout",out),"stderr":put("raw/"+label+".stderr",err)};steps.append(row)
 if rc not in allowed or len(out)>cap or len(err)>262144:raise ValueError("bounded read failed "+label)
 return out
if os.path.lexists(OUT):raise RuntimeError("create-only destination exists")
OUT.mkdir(mode=0o700)
state={"status":"HOLD","revisions":REVS,"tests_run":False,"source_refs_config_network_writes":False}
try:
 before=run("head-before",["rev-parse","HEAD"],True).decode().strip()
 clean=run("status-before",["status","--porcelain=v1","--untracked-files=normal"],True)
 if before!=REVS["M6"] or clean:raise ValueError("source not fixed clean M6")
 pattern=r"pq_lifetime_budget|pq_lifetime_current_v2|pq_lifetime_composition|pq128-lifetime-budget-v1|pq128-source-lock-v1|pq128-lifetime-composition-v2|pq128-lifetime-composition-current-v3|pq128-source-correspondence-current-v2"
 refs={}
 for label in ("N","M6"):
  raw=run(label+"-consumer-references",["grep","-n","-I","-E",pattern,REVS[label],"--","scripts","config",".github","formal"],allowed=(0,1))
  refs[label]=raw.decode()
 versions={}
 for p in PATHS:
  one={}
  for label,rev in REVS.items():
   oid=run(label+"-"+p.replace("/","--")+"-oid",["rev-parse",rev+":"+p],cap=100).decode().strip()
   raw=run(label+"-"+p.replace("/","--"),["cat-file","blob",oid],cap=512*1024)
   if hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()!=oid:raise ValueError("object address")
   one[label]={"oid":oid,"bytes":len(raw),"sha256":sha(raw),"raw_path":steps[-1]["stdout"]["path"]}
  versions[p]=one
 after=run("head-after",["rev-parse","HEAD"],True).decode().strip()
 clean_after=run("status-after",["status","--porcelain=v1","--untracked-files=normal"],True)
 if after!=before or clean_after!=clean:raise ValueError("root source changed during read")
 state.update(status="CAPTURED_READONLY_FOR_REVIEW",versions=versions,consumer_reference_files={k:sorted(set(line.split(":",2)[1] for line in v.splitlines())) for k,v in refs.items()},source_unchanged=True)
finally:
 put("steps.json",(json.dumps(steps,sort_keys=True,indent=2)+"\n").encode())
 put("summary.json",(json.dumps(state,sort_keys=True,indent=2)+"\n").encode())
print(json.dumps({"status":state["status"],"consumer_files":state.get("consumer_reference_files"),"summary_sha256":sha((OUT/"summary.json").read_bytes()),"summary":str(OUT/"summary.json")},sort_keys=True),flush=True)
