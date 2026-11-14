import pathlib,os,sys,stat,subprocess,time,hashlib,json,datetime
if sys.flags.optimize:raise RuntimeError("optimized fetch observer")
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root");SRC=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline");OUT=ROOT/"head5df-immutable-object-fetch-20261114-v1"
if ROOT.resolve(strict=True)!=ROOT or SRC.resolve(strict=True)!=SRC:raise RuntimeError("canonical roots")
os.umask(0o077);OUT.mkdir(mode=0o700,exist_ok=False)
with (OUT/"producer.py").open("xb")as f:f.write(sys.argv[1].encode())
env=os.environ.copy()
for k in list(env):
 if k.startswith("GIT_TRACE")or k in ("GH_DEBUG","GIT_CURL_VERBOSE"):env.pop(k,None)
for k in ("GIT_DIR","GIT_WORK_TREE","GIT_COMMON_DIR","GIT_INDEX_FILE","GIT_NAMESPACE","GIT_CONFIG_COUNT","GIT_CONFIG_PARAMETERS"):
 if k in env:raise RuntimeError("unexpected git override")
env.update(GH_HOST="github.com",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_NO_LAZY_FETCH="1",PYTHONDONTWRITEBYTECODE="1")
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,cap=4194304):
 a=p.lstat()
 if p.resolve(strict=True)!=p or not stat.S_ISREG(a.st_mode)or a.st_nlink!=1 or a.st_size>cap:raise RuntimeError("file scope")
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),"rb")as f:
  if fp(a)!=fp(os.fstat(f.fileno())):raise RuntimeError("open replaced")
  b=f.read(cap+1)
  if fp(a)!=fp(os.fstat(f.fileno())):raise RuntimeError("read changed")
 if fp(a)!=fp(p.lstat())or len(b)!=a.st_size:raise RuntimeError("path changed")
 return b
def pin(p):
 b=read(p);return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(n,v):
 p=OUT/n
 with p.open("xb")as f:f.write((json.dumps(v,sort_keys=True,indent=2)+"\n").encode());f.flush();os.fsync(f.fileno())
 return pin(p)
state=dict(schema="trnm-head5df-exact-object-fetch-v1",started_at=utc(),candidate="5df7ae6f482157c5f7fdcbcd52222117a965053f",steps=[],errors=[],fetch_started=False,source_HEAD_or_localrefs_changed=False,no_checkout=True,qualification=False)
def run(label,argv,seconds,cap=4194304):
 op=OUT/(label+".stdout");ep=OUT/(label+".stderr");r=dict(label=label,argv=argv,started_at=utc(),timeout_seconds=seconds,automatic_retry=False);t=time.monotonic()
 with op.open("xb")as o,ep.open("xb")as e:
  p=subprocess.Popen(argv,cwd=SRC,env=env,stdin=subprocess.DEVNULL,stdout=o,stderr=e)
  while p.poll()is None:
   reason="timeout"if time.monotonic()-t>=seconds else "output_cap"if os.fstat(o.fileno()).st_size>cap or os.fstat(e.fileno()).st_size>cap else None
   if reason:
    r["termination_reason"]=reason;p.terminate()
    try:p.wait(timeout=3)
    except subprocess.TimeoutExpired:p.kill();p.wait()
    break
   time.sleep(.1)
  r["exit"]=p.wait()
 r.update(finished_at=utc(),stdout=pin(op),stderr=pin(ep));state["steps"].append(r);save(label+".step.json",r);print(json.dumps({"label":label,"exit":r["exit"],"termination_reason":r.get("termination_reason")}),flush=True)
 return read(op)if r["exit"]==0 and not r.get("termination_reason")else None
git="/usr/bin/git"
def need(x,m):
 if not x:raise RuntimeError(m)
before=None;localhead=None
try:
 for path,n,d in [("scripts/project-preflight.sh",242,"08645a9c6c8ab5cd9a92aa24e1c19fb71e7330d28e379b805d8e3f81ce8ede1f"),("scripts/ci/project_boundary.py",4485,"5845b10022c1ce625e864c38a9c69ba1982a1d1efad1dc934cc06f3d8dafda47")]:
  b=read(SRC/path);need(len(b)==n and hashlib.sha256(b).hexdigest()==d,"preflight pin")
 localhead=run("local-head-before",[git,"rev-parse","HEAD","HEAD^{tree}"],30);need(localhead==b"2a86462a1ab20c68151719ba4635e3c294391e64\n5c26776f96f15fd131e85a5c2d7c5e895ad7fab4\n","original HEAD")
 need(run("tracked-status-before",[git,"status","--porcelain=v1","--untracked-files=no"],90)==b"","tracked source clean")
 before=run("local-refs-before",[git,"for-each-ref","--format=%(refname) %(objectname)"],30);need(before is not None,"refs before")
 need(run("default-preflight",["/bin/bash","scripts/project-preflight.sh"],120)is not None,"default preflight")
 state["fetch_started"]=True
 result=run("fetch-exact-5df-objects",[git,"-c","gc.auto=0","fetch","--no-tags","--no-recurse-submodules","--no-write-fetch-head","--no-auto-maintenance","origin","5df7ae6f482157c5f7fdcbcd52222117a965053f"],300)
 state["fetch_transport_complete"]=result is not None
 if result is not None:
  b=run("new-head-tree-parents",[git,"show","-s","--format=%H%n%T%n%P","5df7ae6f482157c5f7fdcbcd52222117a965053f"],30)
  need(b==b"5df7ae6f482157c5f7fdcbcd52222117a965053f\n6be4940d38cc88782657f2684cbefe48866f8b9f\nabfcff23d4e2aab7dfd92dfb34937ec7d6021ead 2a86462a1ab20c68151719ba4635e3c294391e64\n","new immutable commit tree parents")
  state["new_commit_object_verified"]=True
except Exception as e:state["errors"].append(type(e).__name__+": "+str(e))
finally:
 if before is not None:
  after=run("local-refs-after",[git,"for-each-ref","--format=%(refname) %(objectname)"],30);state["local_refs_unchanged"]=after==before
  h=run("local-head-after",[git,"rev-parse","HEAD","HEAD^{tree}"],30);state["source_HEAD_unchanged"]=h==localhead
  st=run("tracked-status-after",[git,"status","--porcelain=v1","--untracked-files=no"],90);state["tracked_source_still_clean"]=st==b""
  state["source_HEAD_or_localrefs_changed"]=not(state["local_refs_unchanged"]and state["source_HEAD_unchanged"])
state["finished_at"]=utc();state["complete"]=bool(state.get("new_commit_object_verified")and state.get("local_refs_unchanged")and state.get("source_HEAD_unchanged")and state.get("tracked_source_still_clean")and not state["errors"])
sp=save("summary.json",state);ip=save("EVIDENCE_INDEX.json",{"files":[pin(p)for p in sorted(OUT.iterdir())if p.is_file()],"self_excluded":True})
print(json.dumps({"complete":state["complete"],"fetch_transport_complete":state.get("fetch_transport_complete"),"summary":sp,"index":ip,"errors":state["errors"]}),flush=True)
raise SystemExit(0 if state["complete"]else 1)
