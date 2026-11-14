#!/usr/bin/env python3
import ast,hashlib,json,os,subprocess,time
from pathlib import Path
BASE=Path("/private/tmp/chain-ci-new-candidate-5a4b7fe8-review-20261114-v1")
OUT=BASE/"final-consumer-edges-v1";DB="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git";WT="/private/tmp/chain-consolidation-20261114-mainline"
REVS={"C0":"dc42ce4df5cff79cc61c5addbaf01074b56b06ca","M6":"2a62061177852dc3ebd200fa8d7c66c661a119a1","N":"5a4b7fe8de1adce803184f262fd9f704ead1930c"}
ENV=dict(os.environ)
for k in list(ENV):
 if k.startswith("GIT_TRACE") or k in ("GIT_CURL_VERBOSE","GIT_DIFF_OPTS"):ENV.pop(k,None)
ENV.update({"PATH":"/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin","GIT_OPTIONAL_LOCKS":"0","GIT_NO_LAZY_FETCH":"1","GIT_NO_REPLACE_OBJECTS":"1","GIT_ALLOW_PROTOCOL":"","GIT_TERMINAL_PROMPT":"0","GIT_TRACE2":"0","GIT_TRACE2_EVENT":"0","GIT_TRACE2_PERF":"0","PYTHONDONTWRITEBYTECODE":"1"})
def sha(x):return hashlib.sha256(x).hexdigest()
def put(n,b):
 if isinstance(b,str):b=b.encode()
 p=OUT/n;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(b)
 if p.read_bytes()!=b:raise ValueError("readback")
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
steps=[]
def run(label,args,work=False,cap=1024*1024,allowed=(0,)):
 argv=["/usr/bin/git","--no-pager"]+(["-C",WT] if work else ["--git-dir="+DB])+args;t=time.time_ns()
 try:r=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,timeout=60);rc,out,err=r.returncode,r.stdout,r.stderr
 except subprocess.TimeoutExpired as e:rc,out,err=124,e.stdout or b"",e.stderr or b""
 steps.append({"label":label,"argv":argv,"exit":rc,"started_ns":t,"finished_ns":time.time_ns(),"stdout":put("raw/"+label+".stdout",out),"stderr":put("raw/"+label+".stderr",err)})
 if rc not in allowed or len(out)>cap or len(err)>262144:raise ValueError(label)
 return out
if os.path.lexists(OUT):raise RuntimeError("create-only directory exists")
OUT.mkdir(mode=0o700)
state={"status":"HOLD","tests_run":False,"source_refs_config_network_writes":False}
try:
 head=run("head-before",["rev-parse","HEAD"],True).strip();status=run("status-before",["status","--porcelain=v1","--untracked-files=normal"],True)
 if head.decode()!=REVS["M6"] or status:raise ValueError("fixed root changed")
 pattern=r"pq_chain_claim_guard|trnm-whole-chain-pq-claim-guard-v1|trnm-pq128-lifetime-composition-result-v2|trnm-pq128-lifetime-composition-current-result-v3|inspect_lifetime_budget"
 for label in ("N","M6"):run(label+"-downstream-consumers",["grep","-n","-I","-E",pattern,REVS[label],"--","scripts","config",".github","formal"],allowed=(0,1))
 extra={}
 for path in ("docs/security/PQ128_LIFETIME_BUDGET_V1.md","config/pon/pq-root-dependency-register-v3.json","trillionnium/crates/trnm-worker-agent/src/audit/artifact.rs"):
  extra[path]={}
  for label in REVS:
   key=label+"-"+path.replace("/","--")
   oid=run(key+"-oid",["rev-parse",REVS[label]+":"+path],cap=100).decode().strip()
   raw=run(key,["cat-file","blob",oid],cap=262144)
   if hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()!=oid:raise ValueError("object hash")
   extra[path][label]={"oid":oid,"bytes":len(raw),"sha256":sha(raw),"raw_path":steps[-1]["stdout"]["path"]}
 arch=Path("/private/tmp/chain-new-candidate-5a4b7fe8-production-review-20261114-v1")
 ab=(arch/"declared-source-check-v1/declared-source-map-check.json").read_bytes()
 if sha(ab)!="0e071cb3bf825173082f801b836729193c6d1c3ee3a7e16cfb6bf871b7fbb279":raise ValueError("arch fixed pins receipt differs")
 ar=json.loads(ab);state["arch_source_map_keys"]=sorted(ar);state["arch_source_map_receipt"]=put("architecture-source-map-check.original.json",ab)
 diff=(arch/"M6-N-name-status.stdout").read_bytes()
 if sha(diff)!="5d7b6443f24fc9d1571709155bfe93cd05d3dcd348016c99c477d0d497416841":raise ValueError("arch full path diff changed")
 state["arch_M6_N_name_status"]=put("architecture-M6-N-name-status.original.txt",diff)
 if run("head-after",["rev-parse","HEAD"],True).strip()!=head or run("status-after",["status","--porcelain=v1","--untracked-files=normal"],True)!=status:raise ValueError("source changed")
 state.update(status="CAPTURED_READONLY_FOR_REVIEW",extra_sources=extra,source_unchanged=True)
finally:
 put("steps.json",json.dumps(steps,sort_keys=True,indent=2)+"\n")
 info=put("summary.json",json.dumps(state,sort_keys=True,indent=2)+"\n")
print(json.dumps({"summary":info,"status":state["status"],"arch_keys":state.get("arch_source_map_keys")},sort_keys=True),flush=True)
