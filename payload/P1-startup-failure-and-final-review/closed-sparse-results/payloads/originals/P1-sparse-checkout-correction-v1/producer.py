import datetime,hashlib,json,os,pathlib,stat,subprocess,sys,time
assert not sys.flags.optimize
B=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root");W=B/"source";E=B/"P1-sparse-checkout-correction-v1";E.mkdir(mode=0o700);(E/"producer.py").write_text(sys.argv[1])
env=dict(os.environ,GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",PYTHONDONTWRITEBYTECODE="1",PYTHONOPTIMIZE="0")
paths=["evidence/pon-joint-resource-contract-20261109/archives/original-campaign-42553751914.zip","evidence/pq-authority-preflight-20261108-9d315/hosted-ci-native-triage-01/native-campaign-artifact-13610289272/original-artifact-13610289272.zip"]
H="6a8cd55573065ceb50cdb65a7834615f79b521ae";T="cbd6b4552c87af27c72c0189806baeb33ecb8bf5";steps=[]
s={"schema":"trnm-P1-sparse-checkout-correction-v1","head":H,"tree":T,"status":"HOLD","steps":steps,"errors":[],"remote_mutations":False,"source_commit_changed":False,"gate_code_changed":False,"restored_tracked_paths":paths,"started_at":datetime.datetime.now(datetime.timezone.utc).isoformat()}
def save():(E/"summary.json").write_text(json.dumps(s,indent=2,sort_keys=True)+"\n")
def run(label,argv,timeout=120):
 t=time.monotonic();r=subprocess.run(argv,cwd=W,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 for suffix,raw in (("stdout",r.stdout),("stderr",r.stderr)):(E/(label+"."+suffix)).write_bytes(raw)
 steps.append({"label":label,"argv":argv,"exit":r.returncode,"elapsed_seconds":round(time.monotonic()-t,3),"stdout_bytes":len(r.stdout),"stdout_sha256":hashlib.sha256(r.stdout).hexdigest(),"stderr_bytes":len(r.stderr),"stderr_sha256":hashlib.sha256(r.stderr).hexdigest()});save();assert r.returncode==0,label
 return r.stdout
def git(label,*args):return run(label,["git",*args])
try:
 assert git("head-before","rev-parse","HEAD").decode().strip()==H and git("tree-before","rev-parse","HEAD^{tree}").decode().strip()==T
 assert git("status-before","status","--porcelain=v1","--untracked-files=all")==b""
 flags=git("flags-before","ls-files","-v","-z").split(b"\0");assert flags[-1]==b""
 assert [x[2:].decode() for x in flags[:-1] if x[:1]!=b"H"]==paths and all(x[:1] in (b"H",b"S") for x in flags[:-1])
 assert all(not (W/p).exists() and not (W/p).is_symlink() for p in paths)
 for name,digest in (("config.worktree","97997ba84fd1c44263deb6f412fc3bef4b05e0103d00c5a97a97ca928299aa13"),("info/sparse-checkout","07c0bfe8afef62cdd40b8ff208965346a0096ebe8afb5dce077b7cd020827a54")):
  f=W/".git"/name;b=f.read_bytes();assert hashlib.sha256(b).hexdigest()==digest;(E/(name.replace("/","--")+".before")).write_bytes(b)
 for i,p in enumerate(paths):git("object-present-"+str(i),"cat-file","-e",H+":"+p)
 run("preflight-audit",["bash","scripts/project-preflight.sh","--audit"])
 git("disable-sparse-checkout","sparse-checkout","disable")
 flags_after=git("flags-after","ls-files","-v","-z").split(b"\0");assert flags_after[-1]==b"" and len(flags_after)==41678 and all(x[:1]==b"H" for x in flags_after[:-1])
 assert git("status-after","status","--porcelain=v1","--untracked-files=all")==b""
 assert git("sparse-config-after","config","--worktree","--get","core.sparseCheckout").strip()==b"false"
 raw=run("original-verify-source", [str(B/"final-python312-env/bin/python"),"-B","scripts/ci/verify_ci_source.py","--kind","head","--expected-head",H,"--output",str(E/"verified-source.json")],300)
 assert len(raw)==423 and hashlib.sha256(raw).hexdigest()=="cca39d3cb68ec4f56128201fcad953c875c60c6117c5dbf7604e359f7faf1fa5" and raw==(E/"verified-source.json").read_bytes()
 assert git("head-after","rev-parse","HEAD").decode().strip()==H and git("tree-after","rev-parse","HEAD^{tree}").decode().strip()==T
 s.update(status="FULL_CHECKOUT_RESTORED_AND_ORIGINAL_SOURCE_VERIFIED",entry_count=41677,raw_source_sha256=hashlib.sha256(raw).hexdigest(),clean=True,all_skip_flags_cleared=True,original_failed_lane_preserved=True)
except BaseException as ex:s["errors"].append(type(ex).__name__+": "+str(ex))
finally:s["finished_at"]=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
print(json.dumps({k:v for k,v in s.items() if k!="steps"}),flush=True)
raise SystemExit(0 if not s["errors"] else 1)
