import os,sys,subprocess,json,hashlib
from pathlib import Path
O=Path("/private/tmp/chain-R1-pq-witness-deadline-source-review-20261114-v1/crypto-signing-source-v1");O.mkdir(mode=0o700,exist_ok=False)
(O/"producer.py").write_text(sys.argv[1])
G="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git";R="2a86462a1ab20c68151719ba4635e3c294391e64"
e=os.environ.copy();e.update(GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_NO_REPLACE_OBJECTS="1")
def git(*a):
 p=subprocess.run(["/usr/bin/git","--git-dir="+G,*a],env=e,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 if p.returncode not in (0,1):raise RuntimeError("git")
 if len(p.stdout)>600000:raise RuntimeError("cap")
 return p.stdout
s=git("grep","-n","-E","pub fn sign_exact_message|pub fn verify_exact_message|pub struct PqNativeSigningKey",R,"--","trillionnium/crates")
(O/"exact-functions.txt").write_bytes(s)
paths={l.split(":",3)[1] for l in s.decode().splitlines() if len(l.split(":",3))==4}
rows=[]
for path in sorted(paths):
 b=git("show",R+":"+path);name=path.replace("/","--")+".original";(O/name).write_bytes(b)
 rows.append({"path":path,"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"git_blob":git("rev-parse",R+":"+path).decode().strip(),"file":name})
(O/"source-index.json").write_text(json.dumps({"revision":R,"files":rows},indent=2,sort_keys=True)+"\n")
print(json.dumps({"search":s.decode(),"files":rows},sort_keys=True))
