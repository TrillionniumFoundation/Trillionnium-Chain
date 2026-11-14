import os,sys,json,subprocess,hashlib,stat,time
from pathlib import Path
OUT=Path("/private/tmp/chain-R1-nonhost-performance-review-20261114-v1")
OUT.mkdir(mode=0o700,exist_ok=False)
(OUT/"producer.py").write_text(sys.argv[1])
ROOT=Path("/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git")
REV="2a86462a1ab20c68151719ba4635e3c294391e64"
TREE="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"
env=os.environ.copy()
env.update(GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_NO_REPLACE_OBJECTS="1")
def git(*args):
 p=subprocess.run(["/usr/bin/git","--git-dir="+str(ROOT),*args],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
 if p.returncode: raise RuntimeError("immutable_git_read_failed:"+str(p.returncode)+":"+p.stderr.decode("utf-8","replace")[:1000])
 if len(p.stdout)>2*1024*1024: raise RuntimeError("read_cap")
 return p.stdout
if git("rev-parse",REV+"^{tree}").decode().strip()!=TREE: raise RuntimeError("tree")
paths=["AGENTS.md",
"trillionnium/crates/trnm-pon-node/src/ingress/public_v3/pq_identity.rs",
"trillionnium/crates/trnm-pon-node/src/ingress/public_v3/history_response.rs",
"trillionnium/crates/trnm-pon-node/src/ingress/public_v3/canonical_packet.rs"]
rows=[]
for path in paths:
 raw=git("show",REV+":"+path); oid=git("rev-parse",REV+":"+path).decode().strip()
 name=path.replace("/","--")+".original"
 target=OUT/name
 with target.open("xb") as f:f.write(raw)
 rows.append(dict(source_revision=REV,source_path=path,git_blob=oid,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),file=name))
index={"schema":"trnm-r1-nonhost-performance-readonly-source-v1","source_revision":REV,"source_tree":TREE,"source_or_git_mutation":False,"new_native_or_test_run":False,"files":rows}
raw=(json.dumps(index,indent=2,sort_keys=True)+"\n").encode()
(OUT/"source-index.json").write_bytes(raw)
D=Path("/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1")
j=json.loads((D/"critical-path-summary-v2/client-server-compact.json").read_text())
def shape(x,depth=0):
 if depth>=3:return {"type":type(x).__name__,"length":len(x) if isinstance(x,(dict,list)) else None}
 if isinstance(x,dict):return {k:shape(v,depth+1) for k,v in list(x.items())[:20]}
 if isinstance(x,list):return {"count":len(x),"first":shape(x[0],depth+1) if x else None}
 return x
s=shape(j)
(OUT/"existing-client-stage-shape.json").write_text(json.dumps(s,indent=2,sort_keys=True)+"\n")
print(json.dumps({"out":str(OUT),"source_index_bytes":len(raw),"source_index_sha256":hashlib.sha256(raw).hexdigest(),"files":rows,"existing_stage_shape":s},sort_keys=True))
