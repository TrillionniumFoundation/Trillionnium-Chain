import os,sys,json,hashlib,subprocess,datetime
from pathlib import Path
D=Path("/private/tmp/chain-H5DF-W1-replay-callchain-review-20261114-v1/source-v1");D.mkdir(exist_ok=False)
G="/usr/bin/git";DB="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git"
H="5df7ae6f482157c5f7fdcbcd52222117a965053f";R="2a86462a1ab20c68151719ba4635e3c294391e64"
env=dict(os.environ,GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",GIT_OPTIONAL_LOCKS="0")
def put(n,b):
 p=D/n
 with p.open("xb")as f:f.write(b)
 return{"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
put("producer.py",sys.argv[1].encode())
def tree(rev):
 q=subprocess.run([G,"--git-dir="+DB,"ls-tree","-r","-z",rev,"--","trillionnium/crates"],capture_output=True,timeout=40,env=env);assert q.returncode==0
 result={}
 for line in q.stdout.split(b"\0"):
  if not line:continue
  meta,path=line.split(b"\t",1);mode,typ,oid=meta.decode().split();result[path.decode()]=(mode,typ,oid)
 return result
ht=tree(H);rt=tree(R)
exact=["trillionnium/crates/trnm-pon-node/src/store.rs","trillionnium/crates/trnm-pon-node/src/store/growth/work_checked.rs","trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs","trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs","trillionnium/crates/trnm-pon-node/src/host_parent.rs"]
paths=sorted(set(exact)&ht.keys()|{p for p in ht if "pon_work" in p or p.endswith("/history_import.rs")})
rows=[]
for i,p in enumerate(paths):
 mode,typ,oid=ht[p];assert mode=="100644"and typ=="blob"
 q=subprocess.run([G,"--git-dir="+DB,"cat-file","blob",oid],capture_output=True,timeout=30,env=env);assert q.returncode==0 and len(q.stdout)<=2*1024*1024
 assert hashlib.sha1(b"blob "+str(len(q.stdout)).encode()+b"\0"+q.stdout).hexdigest()==oid
 pin=put(str(i).zfill(2)+"-"+Path(p).name+".raw",q.stdout)
 rows.append({"source":p,"H5DF_oid":oid,"R1_oid":rt.get(p,(None,None,None))[2],"same_R1_H5DF":rt.get(p)==ht[p],"captured":pin,"lines":len(q.stdout.splitlines())})
idx=put("source-index.json",(json.dumps({"head":H,"comparison":R,"source_rows":rows,"read_only_git":True},sort_keys=True,indent=2)+"\n").encode())
print(json.dumps({"index":idx,"sources":rows},sort_keys=True))
