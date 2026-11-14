import os,subprocess,json,hashlib,time,shutil,stat
from pathlib import Path
D=Path("/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git")
H="ed0d35487f2a67239e4d646fd41c2c7acb5cc740"
T="1aa9c21812489080980bdc3c1c2bb43611e88354"
W=Path("/private/tmp/chain-public-policy-prefix-cache-20261114")
E=Path("/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1")
BRANCH="fix/chain-public-policy-prefix-cache-20261114"
env=os.environ.copy();env.update(PATH="/Users/qianqi/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",PYTHONDONTWRITEBYTECODE="1",PYTHONOPTIMIZE="0")
def sha(b):return hashlib.sha256(b).hexdigest()
def put(p,b):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(b)
 if p.read_bytes()!=b:raise ValueError("receipt readback")
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def js(o):return (json.dumps(o,indent=2,sort_keys=True)+"\n").encode()
if os.path.lexists(E) or os.path.lexists(W):raise ValueError("create-only worktree/evidence")
if shutil.disk_usage("/private/tmp").free<7*1024**3:raise ValueError("insufficient isolated checkout capacity")
E.mkdir(mode=0o700);O=E/"isolation-v1";O.mkdir()
state={"schema":"trnm-policy-prefix-isolation-v1","status":"HOLD","base":H,"tree":T,"worktree":str(W),"branch":BRANCH,"steps":[],"errors":[],"tests_executed":False,"root_worktree_access":False,"ROG_or_network_access":False}
def run(label,args,cwd=None,timeout=120):
 started=time.time()
 r=subprocess.run(args,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 rec={"label":label,"argv":args,"cwd":str(cwd) if cwd else None,"exit":r.returncode,"seconds":time.time()-started,"stdout":put(O/(label+".stdout"),r.stdout),"stderr":put(O/(label+".stderr"),r.stderr)}
 state["steps"].append(rec)
 return r
try:
 prefix=["/usr/bin/git","--git-dir="+str(D),"-c","protocol.allow=never"]
 r=run("fixed-base-tree",prefix+["rev-parse",H+"^{tree}"],timeout=30)
 if r.returncode or r.stdout.decode().strip()!=T:raise ValueError("base identity")
 r=run("branch-absence",prefix+["show-ref","--verify","--quiet","refs/heads/"+BRANCH],timeout=30)
 if r.returncode!=1:raise ValueError("branch not absent")
 r=run("worktree-add",prefix+["worktree","add","--quiet","-b",BRANCH,str(W),H],timeout=180)
 if r.returncode:raise ValueError("isolated worktree add failed")
 r=run("preflight",["/bin/bash","scripts/project-preflight.sh"],cwd=W,timeout=120)
 if r.returncode:raise ValueError("preflight failed")
 for label,args,expected in [
  ("head",["rev-parse","HEAD"],H),("tree",["rev-parse","HEAD^{tree}"],T),
  ("status",["status","--porcelain=v1","--untracked-files=all"],""),
 ]:
  r=run(label,["/usr/bin/git","-c","protocol.allow=never",*args],cwd=W,timeout=30)
  if r.returncode or r.stdout.decode().strip()!=expected:raise ValueError(label+" identity")
 for relative in ["AGENTS.md","trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs","trillionnium/crates/trnm-protocol/src/pon_wire.rs","trillionnium/crates/trnm-pon-node/Cargo.toml","scripts/pon_public_v3_policy_read.py","scripts/ci/test_pon_public_v3_policy_read.py"]:
  p=W/relative;b=p.read_bytes()
  put(E/"originals"/(relative.replace("/","--")+".original"),b)
 state["status"]="ISOLATED_PREFLIGHT_PASS_CLEAN"
except BaseException as e:
 state["errors"].append(type(e).__name__+": "+str(e));raise
finally:
 put(O/"summary.json",js(state))
print(js({"status":state["status"],"base":H,"tree":T,"worktree":str(W),"summary":str(O/"summary.json"),"summary_sha256":sha((O/"summary.json").read_bytes())}).decode(),flush=True)
