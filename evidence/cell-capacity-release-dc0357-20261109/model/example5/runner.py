import datetime,fcntl,hashlib,json,os,re,subprocess,sys,time
from pathlib import Path
REPO=Path("/home/qq/work/chain-cell-capacity-dc0357-20261109")
BASE=Path("/home/qq/work/chain-cell-capacity-dc0357-20261109-validation")
DEST=BASE/"example5-6ea3bf3-attempt01"
HEAD="6ea3bf3fe13d66333bba3a8c7b97e14b4319b39f"
TREE="6c4401a94defeecb9696c2da1442dcbd27b56352"
GATE=BASE/"cargo-6ea3bf3-attempt01"
GATE_SHA="a33cc2c239d4e0c86a50edd4d1846b6a3852dbb7e0f672eca6c21db11fc9a0cf"
os.umask(0o077)
def sha(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()
def write(p,v):
 with open(p,"x") as f:json.dump(v,f,sort_keys=True,indent=2);f.write("\n")
def ident():
 d={"commit":subprocess.check_output(["/usr/bin/git","rev-parse","HEAD"],cwd=REPO,text=True).strip(),"tree":subprocess.check_output(["/usr/bin/git","rev-parse","HEAD^{tree}"],cwd=REPO,text=True).strip(),"status":subprocess.check_output(["/usr/bin/git","status","--porcelain","--untracked-files=all"],cwd=REPO,text=True).strip()}
 if d!={"commit":HEAD,"tree":TREE,"status":""}:raise RuntimeError("exact clean source mismatch: "+json.dumps(d))
 return d
def sources():
 out={}
 for raw in subprocess.check_output(["/usr/bin/git","ls-files","-z"],cwd=REPO).split(b"\0"):
  if raw:
   s=os.fsdecode(raw);p=Path(s)
   if p.suffix in (".rs",".py",".toml") or p.name=="Cargo.lock":out[s]=sha(REPO/s)
 return out
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
assert sha(GATE/"observation.json")==GATE_SHA,"final gate observation pin"
gate=json.loads((GATE/"observation.json").read_text())
assert gate["passed"] and gate["sources_unchanged"] and not gate["changed_source_files"],"final gates not passed"
assert gate["identity"]=={"commit":HEAD,"tree":TREE,"status":""}
setup=json.loads((GATE/"start.json").read_text())
env=os.environ.copy();env.update(setup["environment"])
rust=str(Path(env["RUSTC"]).parent)
env.update({"PATH":rust+os.pathsep+env.get("PATH",""),"CARGO_TERM_COLOR":"never","PYTHONDONTWRITEBYTECODE":"1"})
assert sha(env["TRNM_PQ_OPENSSL"])==env["TRNM_PQ_OPENSSL_SHA256"],"provider pin"
target=Path(env["CARGO_TARGET_DIR"])
guard=open(str(target)+".owner.lock","a")
fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
for proc in Path("/proc").iterdir():
 if not proc.name.isdecimal():continue
 try:
  cmd=(proc/"cmdline").read_bytes().split(b"\0")
  if cmd and Path(os.fsdecode(cmd[0])).name in ("cargo","rustc","rustdoc","clippy-driver","cargo-clippy"):
   cwd=os.readlink(proc/"cwd")
   if str(REPO) in cwd or any(str(target).encode() in a for a in cmd):raise RuntimeError("target compiler still active pid="+proc.name)
 except (FileNotFoundError,PermissionError,ProcessLookupError):pass
startid=ident();before=sources()
DEST.mkdir(mode=0o700,exist_ok=False)
write(DEST/"sources-start.json",before)
write(DEST/"start.json",{"started_at_utc":utc(),"identity":startid,"environment":setup["environment"],"final_gate_sha256":GATE_SHA})
print(json.dumps({"stage":"example5-started","output":str(DEST),"head":HEAD}),flush=True)
results=[];error=None;binary=target/"debug/examples/cell_sealed_research_next_use_v2"
try:
 commands=[
  ("preflight",["bash","scripts/project-preflight.sh"],REPO),
  ("exact-source",["/usr/bin/python3","scripts/ci/verify_ci_source.py","--kind","head","--expected-head",HEAD],REPO),
  ("example5",[rust+"/cargo","test","--locked","--offline","--jobs","2","-p","trnm-data-availability","--example","cell_sealed_research_next_use_v2","--","--test-threads=1"],REPO/"trillionnium"),
  ("binary-build",[rust+"/cargo","build","--locked","--offline","--jobs","2","-p","trnm-data-availability","--example","cell_sealed_research_next_use_v2"],REPO/"trillionnium")]
 for name,cmd,cwd in commands:
  ident();t=time.monotonic();started=utc()
  with open(DEST/(name+".log"),"xb") as output:
   p=subprocess.run(cmd,cwd=cwd,env=env,stdout=output,stderr=subprocess.STDOUT,timeout=900)
  r={"name":name,"command":cmd,"cwd":str(cwd),"exit_code":p.returncode,"started_at_utc":started,"completed_at_utc":utc(),"elapsed_seconds":time.monotonic()-t,"log_sha256":sha(DEST/(name+".log"))}
  if name=="example5":
   text=(DEST/(name+".log")).read_text()
   r["five_tests_passed"]=bool(re.search(r"test result: ok\. 5 passed; 0 failed;",text))
  write(DEST/(name+"-observation.json"),r);results.append(r);print(json.dumps(r),flush=True)
  if p.returncode or (name=="example5" and not r["five_tests_passed"]):raise RuntimeError(name+" gate failed")
 if not binary.is_file() or not os.access(binary,os.X_OK):raise RuntimeError("non-test executable absent")
except BaseException as e:error=type(e).__name__+": "+str(e)
endid=None;after={}
try:endid=ident();after=sources()
except BaseException as e:error=(error+"; " if error else "")+type(e).__name__+": "+str(e)
write(DEST/"sources-end.json",after)
changed=[s for s in sorted(set(before)|set(after)) if before.get(s)!=after.get(s)]
obs={"schema":"trnm.cell-sealed-research-example-gates.v1","passed":error is None and not changed,"error":error,"identity":endid,"start_identity":startid,"sources_unchanged":not changed,"changed_source_files":changed,"gates":results,"binary":str(binary),"binary_sha256":sha(binary) if binary.is_file() else None,"binary_bytes":binary.stat().st_size if binary.is_file() else None,"completed_at_utc":utc(),"final_gate_sha256":GATE_SHA,"source_start_manifest_sha256":sha(DEST/"sources-start.json"),"source_end_manifest_sha256":sha(DEST/"sources-end.json")}
write(DEST/"observation.json",obs)
print(json.dumps({"stage":"complete","passed":obs["passed"],"error":error,"observation":str(DEST/"observation.json"),"observation_sha256":sha(DEST/"observation.json"),"binary_sha256":obs["binary_sha256"],"changed_source_files":changed}),flush=True)
sys.exit(0 if obs["passed"] else 1)
