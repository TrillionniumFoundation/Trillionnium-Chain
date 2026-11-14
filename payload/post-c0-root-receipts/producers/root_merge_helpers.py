"""Local audit merge support. No action occurs until setup and explicit calls."""
import ast,difflib,hashlib,json,os,pathlib,re,subprocess,time
def setup(name):
 global src,ev,env,steps,reviewed
 if re.fullmatch(r"[a-z0-9-]+",name) is None:raise ValueError("fixed evidence name required")
 src=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
 ev=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")/name;ev.mkdir(exist_ok=False)
 env=os.environ.copy();env["PATH"]="/Users/qianqi/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin";env["TMPDIR"]="/private/tmp/chain-consolidation-20261114-root/mac-controls-tmp";env["PYTHONDONTWRITEBYTECODE"]="1"
 steps=[];reviewed=set()
manifest="config/pon/pq-cross-branch-corpus-v1.json"
plan="docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
inventory="trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs"
checker="scripts/ci/check_pq_research_integration.py"
negative="scripts/ci/test_pq_research_integration.py"
metadata={manifest,plan,inventory,checker,negative,"scripts/ci/ci_job.sh","scripts/ci/check_ci_contract.py","scripts/ci/test_ci_contract.py"}
def git(*args):return subprocess.check_output(["git",*args],cwd=src,env=env)
def run(label,args,allowed=(0,),timeout=600):
 started=time.monotonic();q=subprocess.run(args,cwd=src,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
 (ev/(label+".log")).write_bytes(q.stdout)
 row={"label":label,"exit":q.returncode,"seconds":round(time.monotonic()-started,3),"sha256":hashlib.sha256(q.stdout).hexdigest()}
 steps.append(row);(ev/"steps.json").write_text(json.dumps(steps,indent=2)+"\n");print(json.dumps(row),flush=True)
 assert q.returncode in allowed,(label,q.stdout[-5000:]);return q
def show(rev,path):return git("show",rev+":"+path)
def blob(path):
 raw=(src/path).read_bytes();return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def merge_text(base,ours,theirs,path):
 original=base.splitlines(keepends=True);edits=[]
 for side,data in enumerate((ours,theirs)):
  current=data.splitlines(keepends=True)
  for tag,i,j,x,y in difflib.SequenceMatcher(a=original,b=current,autojunk=False).get_opcodes():
   if tag!="equal":
    item=(i,j,current[x:y])
    if item not in [e[:3] for e in edits]:edits.append((*item,side))
 edits.sort(key=lambda e:(e[0],e[1],e[3]));out=[];at=0
 for i,j,lines,side in edits:
  assert i>=at,("overlapping non-identical edit",path,i,j,at)
  out.extend(original[at:i]);out.extend(lines);at=j
 out.extend(original[at:]);result="".join(out)
 if path.endswith(".py"):
  for node in ast.walk(ast.parse(result)):
   if hasattr(node,"body") and isinstance(node.body,list):
    names=[n.name for n in node.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))]
    assert len(names)==len(set(names)),("duplicate definitions",path)
 return result
_missing=object()
def merge_json(base,ours,theirs,trail=()):
 if ours==theirs:return ours
 if ours==base:return theirs
 if theirs==base:return ours
 if trail==("required_paths",):
  assert set(base)<=set(ours) and set(base)<=set(theirs)
  return sorted(set(ours)|set(theirs))
 if len(trail)==2 and trail[0]=="pinned_blobs":
  assert trail[1] in reviewed|metadata,("unreviewed pin conflict",trail)
  return blob(trail[1])
 if all(isinstance(v,dict) for v in (base,ours,theirs)):
  result={}
  for key in sorted(set(base)|set(ours)|set(theirs)):
   value=merge_json(base.get(key,_missing),ours.get(key,_missing),theirs.get(key,_missing),trail+(key,))
   if value is not _missing:result[key]=value
  return result
 raise AssertionError(("unresolved JSON conflict",trail))
def refresh_pins(paths):
 m=json.loads((src/manifest).read_text())
 for path in paths:
  if path in m["pinned_blobs"]:m["pinned_blobs"][path]=blob(path)
 m["pinned_blobs"]=dict(sorted(m["pinned_blobs"].items()));m["required_paths"]=sorted(set(m["required_paths"]))
 (src/manifest).write_text(json.dumps(m,indent=2,ensure_ascii=False)+"\n")
