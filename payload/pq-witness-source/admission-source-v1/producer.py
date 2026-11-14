import os,sys,json,hashlib,subprocess
from pathlib import Path
O=Path("/private/tmp/chain-R1-pq-witness-deadline-source-review-20261114-v1/admission-source-v1");O.mkdir(mode=0o700,exist_ok=False)
(O/"producer.py").write_text(sys.argv[1])
G="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git";R="2a86462a1ab20c68151719ba4635e3c294391e64"
env=os.environ.copy();env.update(GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_NO_REPLACE_OBJECTS="1")
def git(*args):
 p=subprocess.run(["/usr/bin/git","--git-dir="+G,*args],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 if p.returncode not in (0,1):raise RuntimeError("git")
 if len(p.stdout)>2*1024*1024:raise RuntimeError("cap")
 return p.stdout
raw=git("grep","-n","-E","fn charge_connection|fn charge_ingress|fn check_pq_network_policy|fn pq_network_ingress",R,"--","trillionnium/crates/trnm-pon-node/src")
(O/"exact-charge-source-search.txt").write_bytes(raw)
paths={"trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness.rs","trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/io.rs"}
for l in raw.decode().splitlines():
 parts=l.split(":",3)
 if len(parts)==4:paths.add(parts[1])
rows=[]
for path in sorted(paths):
 b=git("show",R+":"+path)
 if len(b)>600000:raise RuntimeError("filecap")
 name=path.replace("/","--")+".original";(O/name).write_bytes(b)
 rows.append({"path":path,"git_blob":git("rev-parse",R+":"+path).decode().strip(),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"file":name})
(O/"source-index.json").write_text(json.dumps({"revision":R,"files":rows},indent=2,sort_keys=True)+"\n")
print(json.dumps({"files":rows,"search":raw.decode()},sort_keys=True))
