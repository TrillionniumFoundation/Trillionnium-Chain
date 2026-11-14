import pathlib,subprocess,json,os,sys,time,hashlib
root=pathlib.Path("/home/qian-qi/work/chain-time-credit-20261108-qf01")
evidence=pathlib.Path("/home/qian-qi/work/chain-time-credit-20261108-qf01-evidence")
identity=json.loads((evidence/"freeze-source-01/source.json").read_text())
head=identity["source_head"]
assert subprocess.check_output(["git","rev-parse","HEAD"],cwd=root,text=True).strip()==head
env=os.environ.copy()
env.update({"OPENSSL_DIR":"/home/qian-qi/chain-w1-ingress-r17-20261107/provider-runtime/trnm-pq-provider-3.5.9.lq0uAtbU/install","OPENSSL_STATIC":"1","CARGO_BUILD_JOBS":"8","CARGO_TARGET_DIR":"/home/qian-qi/work/chain-time-credit-20261108-qf01-target","RUST_TEST_THREADS":"1","PYTHONDONTWRITEBYTECODE":"1"})
records=[]
def run(name,args,extra=None,must=True):
 e=env.copy()
 if extra:e.update(extra)
 print(json.dumps({"event":"start","name":name,"command":args,"source":head}),flush=True)
 started=time.time()
 with (out/(name+".stdout")).open("w") as stdout,(out/(name+".stderr")).open("w") as stderr:
  r=subprocess.run(args,cwd=root,env=e,stdout=stdout,stderr=stderr)
 record=dict(name=name,command=args,extra_env=extra or {},exit_code=r.returncode,elapsed_seconds=round(time.time()-started,3),source_head=head,stdout=name+".stdout",stderr=name+".stderr")
 records.append(record)
 (out/"commands.json").write_text(json.dumps(records,indent=2)+"\n")
 text=(out/(name+".stdout")).read_text(errors="replace")
 err=(out/(name+".stderr")).read_text(errors="replace")
 print(json.dumps({"event":"done",**record,"stdout_tail":text[-1600:],"stderr_tail":err[-1600:]}),flush=True)
 if r.returncode and must: raise RuntimeError(f"{name} failed with {r.returncode}")
 return r.returncode
def source(name):
 return run(name,["python3","scripts/ci/verify_ci_source.py","--kind","head","--expected-head",head,"--output",str(out/(name+".json"))])

out=evidence/"validation-static-01";out.mkdir(exist_ok=False)
(out/"environment.json").write_text(json.dumps({"source":identity,"declared_env":{k:env[k] for k in ("OPENSSL_DIR","OPENSSL_STATIC","CARGO_BUILD_JOBS","CARGO_TARGET_DIR","RUST_TEST_THREADS","PYTHONDONTWRITEBYTECODE")}},indent=2)+"\n")
run("preflight",["bash","scripts/project-preflight.sh"])
source("source-before")
try:
 run("format",["/home/qian-qi/.cargo/bin/cargo","+1.95.0","fmt","--manifest-path","trillionnium/Cargo.toml","--all","--","--check"])
 fuzz_manifests=subprocess.check_output(["git","ls-files","*fuzz/Cargo.toml"],cwd=root,text=True).splitlines()
 assert len(fuzz_manifests)==1, fuzz_manifests
 for name,manifest in [("graph-workspace","trillionnium/Cargo.toml"),("graph-fuzz",fuzz_manifests[0])]:
  run(name,["/home/qian-qi/.cargo/bin/cargo","+1.95.0","metadata","--locked","--offline","--format-version","1","--manifest-path",manifest])
  report=json.loads((out/(name+".stdout")).read_text())
  summary={"manifest":manifest,"packages":len(report["packages"]),"workspace_members":len(report["workspace_members"]),"resolve_nodes":len(report["resolve"]["nodes"]),"sha256":hashlib.sha256((out/(name+".stdout")).read_bytes()).hexdigest()}
  (out/(name+"-summary.json")).write_text(json.dumps(summary,indent=2)+"\n")
  print(json.dumps(summary),flush=True)
 run("source-negative-controls",["python3","scripts/ci/test_ci_source_integrity.py"])
 run("repository-truth",["bash","scripts/ci/ci_job.sh","repository-truth"])
 run("quantum-source-report",["python3","formal/pon-nakamoto-v1/quantum_bernoulli_source_audit.py"])
finally:
 source("source-after")
print(json.dumps({"result":"PASS","source_head":head,"commands":len(records)}),flush=True)
