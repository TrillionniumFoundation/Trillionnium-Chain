import os,sys,json,hashlib,subprocess,re
from pathlib import Path
O=Path("/private/tmp/chain-R1-pq-witness-deadline-source-review-20261114-v1/immutable-source-v1");O.mkdir(mode=0o700,exist_ok=False)
(O/"producer.py").write_text(sys.argv[1])
G="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git";R="2a86462a1ab20c68151719ba4635e3c294391e64"
env=os.environ.copy();env.update(GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_NO_REPLACE_OBJECTS="1")
def git(*args):
 p=subprocess.run(["/usr/bin/git","--git-dir="+G,*args],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 if p.returncode not in (0,1):raise RuntimeError("git_read"+str(p.returncode))
 if len(p.stdout)>2*1024*1024:raise RuntimeError("cap")
 return p.stdout
search=git("grep","-n","-E","PQ_WITNESS_DEADLINE|ingress_admission|witness_selected_binary_dispatches_replays_reopens_and_rejects_old_database",R,"--","trillionnium/crates/trnm-pon-node")
(O/"exact-witness-search.txt").write_bytes(search)
paths={"trillionnium/crates/trnm-pon-node/tests/pq_tls_witness_cli.rs"}
for l in search.decode().splitlines():
 parts=l.split(":",3)
 if len(parts)==4 and parts[1].endswith(".rs"):paths.add(parts[1])
rows=[];total=0
for path in sorted(paths):
 raw=git("show",R+":"+path)
 if len(raw)>600000:continue
 total+=len(raw)
 if total>2*1024*1024:raise RuntimeError("sum_cap")
 name=path.replace("/","--")+".original";(O/name).write_bytes(raw)
 rows.append({"path":path,"git_blob":git("rev-parse",R+":"+path).decode().strip(),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"file":name})
(O/"source-index.json").write_text(json.dumps({"revision":R,"files":rows},indent=2,sort_keys=True)+"\n")
p=Path("/private/tmp/chain-consolidation-20261114-root/R1-other-failed-job-original-logs-v1/132475258045-original-log.stdout")
log=p.read_text()
matches=[]
for i,l in enumerate(log.splitlines(),1):
 if re.search(r'tracked_worktree_verified|tested_tree|source.after|source_before|source.before|verify_ci_source|Verify.*source|source identity|source_identity|source_sha',l,re.I):
  matches.append({"line":i,"length":len(l),"text":l[:1600]})
(O/"source-identity-log-locators.json").write_text(json.dumps(matches,indent=2,sort_keys=True)+"\n")
print(json.dumps({"files":rows,"search":search.decode(),"identity_locators":matches},sort_keys=True))
