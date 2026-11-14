#!/usr/bin/env python3
import ast,hashlib,json,os,subprocess,time
from pathlib import Path
BASE=Path("/private/tmp/chain-ci-new-candidate-5a4b7fe8-review-20261114-v1")
OUT=BASE/"consumer-closure-v2"
DB="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git"; WT="/private/tmp/chain-consolidation-20261114-mainline"
REVS={"C0":"dc42ce4df5cff79cc61c5addbaf01074b56b06ca","M6":"2a62061177852dc3ebd200fa8d7c66c661a119a1","N":"5a4b7fe8de1adce803184f262fd9f704ead1930c"}
NEW_PATHS=["scripts/ci/pq_root_dependency_register.py","scripts/ci/pq_root_custody_review_v1.py","scripts/ci/pq_root_custody_review_v2.py","scripts/ci/pq_root_migration_review_v1.py","scripts/ci/w1_upstream_security.py","scripts/ci/test_pq_root_dependency_register.py","scripts/ci/test_pq_proof_profile_binding.py","scripts/ci/test_w1_upstream_security.py",".github/workflows/chain-hepta-closure-candidate.yml"]
ENV=dict(os.environ)
for k in list(ENV):
 if k.startswith("GIT_TRACE") or k in ("GIT_CURL_VERBOSE","GIT_DIFF_OPTS"):ENV.pop(k,None)
ENV.update({"PATH":"/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin","GIT_OPTIONAL_LOCKS":"0","GIT_NO_LAZY_FETCH":"1","GIT_NO_REPLACE_OBJECTS":"1","GIT_ALLOW_PROTOCOL":"","GIT_TERMINAL_PROMPT":"0","GIT_TRACE2":"0","GIT_TRACE2_EVENT":"0","GIT_TRACE2_PERF":"0","PYTHONDONTWRITEBYTECODE":"1"})
def sha(x):return hashlib.sha256(x).hexdigest()
def put(n,b):
 if isinstance(b,str):b=b.encode()
 p=OUT/n;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(b)
 if p.read_bytes()!=b:raise ValueError("evidence readback")
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
steps=[]
def run(label,args,work=False,cap=1024*1024):
 argv=["/usr/bin/git","--no-pager"]+(["-C",WT] if work else ["--git-dir="+DB])+args
 t=time.time_ns()
 try:r=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,timeout=60);rc,out,err=r.returncode,r.stdout,r.stderr
 except subprocess.TimeoutExpired as e:rc,out,err=124,e.stdout or b"",e.stderr or b""
 steps.append({"label":label,"argv":argv,"exit":rc,"start_ns":t,"end_ns":time.time_ns(),"stdout":put("raw/"+label+".stdout",out),"stderr":put("raw/"+label+".stderr",err)})
 if rc or len(out)>cap or len(err)>262144:raise ValueError("read failed "+label)
 return out
if os.path.lexists(OUT):raise RuntimeError("create-only path exists")
OUT.mkdir(mode=0o700)
state={"status":"HOLD","tests_run":False,"prior_capture_status":"HOLD only due nonexistent pq_root_lifetime_register.py; no source operation failed","prior_capture_preserved":str(BASE/"consumer-closure-v1"),"revisions":REVS}
try:
 head=run("head-before",["rev-parse","HEAD"],True).strip();status=run("status-before",["status","--porcelain=v1","--untracked-files=normal"],True)
 if head.decode()!=REVS["M6"] or status:raise ValueError("source checkpoint changed")
 priorsteps=json.loads((BASE/"consumer-closure-v1/steps.json").read_bytes())
 priorraw={}
 for row in priorsteps:
  for stream in ("stdout","stderr"):
   item=row[stream];b=Path(item["path"]).read_bytes()
   if len(b)!=item["bytes"] or sha(b)!=item["sha256"]:raise ValueError("prior receipt differs")
  if row["exit"]==0:priorraw[row["label"]]=Path(row["stdout"]["path"]).read_bytes()
 records=[]
 oldpaths=["config/pon/pq128-lifetime-budget-v1.json","config/pon/pq128-source-lock-v1.json","config/pon/pq128-lifetime-composition-v2.json","config/pon/pq-proof-profile-binding-v1.json","scripts/ci/pq_lifetime_budget.py","scripts/ci/pq_proof_profile_binding.py"]
 for path in oldpaths:
  item={"path":path,"versions":{}}
  for label in REVS:
   key=label+"-"+path.replace("/","--");b=priorraw[key];oid=priorraw[key+"-oid"].decode().strip()
   if hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()!=oid:raise ValueError("prior object address")
   item["versions"][label]={"oid":oid,"bytes":len(b),"sha256":sha(b),"source_path":str(BASE/"consumer-closure-v1/raw"/(key+".stdout"))}
  records.append(item)
 for path in NEW_PATHS:
  item={"path":path,"versions":{}}
  for label in ("N","M6"):
   key=label+"-"+path.replace("/","--")
   oid=run(key+"-oid",["rev-parse",REVS[label]+":"+path],cap=100).decode().strip()
   b=run(key,["cat-file","blob",oid])
   if hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()!=oid:raise ValueError("object address")
   item["versions"][label]={"oid":oid,"bytes":len(b),"sha256":sha(b),"source_path":steps[-1]["stdout"]["path"]}
  records.append(item)
 # Complete named enclosing functions for every actual shared-model reference.
 excerpts=[]
 for record in records:
  path=record["path"]
  if not path.endswith(".py"):continue
  raw=Path(record["versions"]["N"]["source_path"]).read_bytes();text=raw.decode();tree=ast.parse(text)
  uses=[n.lineno for n in ast.walk(tree) if (isinstance(n,(ast.Import,ast.ImportFrom)) and "pq_lifetime" in (ast.get_source_segment(text,n) or "")) or (isinstance(n,ast.Attribute) and isinstance(n.value,ast.Name) and n.value.id in ("lifetime","legacy"))]
  spans=[]
  for node in tree.body:
   if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and any(node.lineno<=x<=node.end_lineno for x in uses):spans.append({"name":node.name,"line":node.lineno,"end":node.end_lineno,"source":ast.get_source_segment(text,node)})
  excerpts.append({"path":path,"whole_source":record["versions"]["N"],"uses":sorted(set(uses)),"enclosing_definitions":spans})
 put("consumer-definitions.json",json.dumps(excerpts,sort_keys=True,indent=2)+"\n")
 refs=priorraw["N-consumer-references"].decode()
 put("consumer-reference-paths.json",json.dumps(sorted(set(x.split(":",2)[1] for x in refs.splitlines())),indent=2)+"\n")
 after=run("head-after",["rev-parse","HEAD"],True).strip();statusafter=run("status-after",["status","--porcelain=v1","--untracked-files=normal"],True)
 if head!=after or status!=statusafter:raise ValueError("source changed")
 state.update(status="CAPTURED_READONLY_FOR_REVIEW",records=records,source_unchanged=True,no_Git_source_refs_config_writes=True,no_network=True)
finally:
 put("steps.json",json.dumps(steps,sort_keys=True,indent=2)+"\n")
 meta=put("summary.json",json.dumps(state,sort_keys=True,indent=2)+"\n")
print(json.dumps({"summary":meta,"status":state["status"]},sort_keys=True),flush=True)
