import datetime,hashlib,json,os,pathlib,re,subprocess,sys,time
assert not sys.flags.optimize
B=pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root");S=B/"source";E=B/"R1-original-w1-v2-controls-linux-v1";E.mkdir(mode=0o700,exist_ok=False)
(E/"producer.py").write_text(sys.argv[1]);inputs=json.loads(sys.argv[2]);(E/"reviewed-inputs.json").write_text(json.dumps(inputs,indent=2,sort_keys=True)+"\n")
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64";TREE="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4";SOURCE_SHA="1b8638f7d5e3fb28abc25c06208df4e189ba3b86c7d0d3a12fb2a431607b7e03"
PY=B/"final-python312-env/bin/python";steps=[]
env=dict(os.environ,PATH=str(PY.parent)+":/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin:/usr/bin:/bin",PYTHONDONTWRITEBYTECODE="1",PYTHONOPTIMIZE="0",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_TERMINAL_PROMPT="0")
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def pin(p):
 b=p.read_bytes();return {"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
def run(label,argv,timeout=300):
 t=time.monotonic();r=subprocess.run(argv,cwd=S,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 a=E/(label+".stdout");a.write_bytes(r.stdout);b=E/(label+".stderr");b.write_bytes(r.stderr)
 steps.append({"label":label,"argv":argv,"cwd":str(S),"exit":r.returncode,"timeout_seconds":timeout,"elapsed_seconds":round(time.monotonic()-t,3),"stdout":pin(a),"stderr":pin(b)})
 print(json.dumps({"label":label,"exit":r.returncode}),flush=True)
 if r.returncode:raise RuntimeError(label+" exited "+str(r.returncode))
 return r
summary={"schema":"trnm-R1-original-W1-31-Linux-controls-v1","head":HEAD,"tree":TREE,"started_at":now(),"status":"HOLD","steps":steps,"errors":[],"qualification":False,"tests_modified":False,"source_before_after_verified":False}
try:
 f=B/"final-repository-truth-offline-2a8646-v1/summary.json";raw=f.read_bytes()
 assert len(raw)==inputs["full_summary_bytes"] and hashlib.sha256(raw).hexdigest()==inputs["full_summary_sha256"]
 prior=json.loads(raw);assert prior["status"]=="passed" and prior["head"]==HEAD and prior["tree"]==TREE and len(prior["steps"])==18 and all(x["exit"]==0 for x in prior["steps"]) and not prior["errors"]
 assert run("head",["git","rev-parse","HEAD"],60).stdout.decode().strip()==HEAD
 assert run("tree",["git","rev-parse","HEAD^{tree}"],60).stdout.decode().strip()==TREE
 assert run("status-before",["git","status","--porcelain=v1","--untracked-files=all"],60).stdout==b""
 run("preflight",["bash","scripts/project-preflight.sh","--audit"],120)
 for rel,n,digest in [("scripts/ci/test_w1_v2_controls_gate.py",22400,"04bcbc29337ec51d52f3cde04f6e4816faaa779a043bef0634435e06d8159e15"),("scripts/ci/w1_v2_controls_gate.py",13036,"32f4eb1310ea855b8eba2edd610b0ede52b4b438f66b42266080973889bf6209")]:
  raw=(S/rel).read_bytes();assert len(raw)==n and hashlib.sha256(raw).hexdigest()==digest
 run("source-before",[str(PY),"-B","scripts/ci/verify_ci_source.py","--kind","head","--expected-head",HEAD,"--output",str(E/"source-before.json")],180)
 run("original-31-controls",[str(PY),"-B","scripts/ci/test_w1_v2_controls_gate.py"],300)
 logs=(E/"original-31-controls.stdout").read_bytes()+(E/"original-31-controls.stderr").read_bytes()
 assert re.findall(rb"^Ran ([0-9]+) tests in ",logs,re.M)==[b"31"] and re.search(rb"^OK$",logs,re.M) and b"skipped=" not in logs
 summary["original_suite_result"]="31 executed; OK; no skips"
except BaseException as ex:summary["errors"].append(type(ex).__name__+": "+str(ex))
try:
 run("source-after",[str(PY),"-B","scripts/ci/verify_ci_source.py","--kind","head","--expected-head",HEAD,"--output",str(E/"source-after.json")],180)
 rows=[(E/n).read_bytes()for n in ("source-before.json","source-after.json","source-before.stdout","source-after.stdout")]
 assert all(len(x)==423 and hashlib.sha256(x).hexdigest()==SOURCE_SHA for x in rows) and all(x==rows[0]for x in rows)
 assert run("status-after",["git","status","--porcelain=v1","--untracked-files=all"],60).stdout==b""
 summary["source_before_after_verified"]=True
except BaseException as ex:summary["errors"].append(type(ex).__name__+": "+str(ex))
summary["status"]="passed" if not summary["errors"]else "failed";summary["finished_at"]=now()
(E/"summary.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
print(json.dumps({"summary":pin(E/"summary.json"),"status":summary["status"],"head":HEAD,"tree":TREE,"errors":summary["errors"]}),flush=True)
raise SystemExit(0 if summary["status"]=="passed"else 1)
