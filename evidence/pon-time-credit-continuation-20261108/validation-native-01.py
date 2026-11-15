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

out=evidence/"validation-native-01";out.mkdir(exist_ok=False)
(out/"environment.json").write_text(json.dumps({"source":identity,"declared_env":{k:env[k] for k in ("OPENSSL_DIR","OPENSSL_STATIC","CARGO_BUILD_JOBS","CARGO_TARGET_DIR","RUST_TEST_THREADS","PYTHONDONTWRITEBYTECODE")}},indent=2)+"\n")
cargo=["/home/qian-qi/.cargo/bin/cargo","+1.95.0"]
base=cargo+["test","--locked","--offline","--manifest-path","trillionnium/Cargo.toml","-p","trnm-pon-node"]
run("preflight",["bash","scripts/project-preflight.sh"])
source("source-before")
try:
 run("strict-clippy",cargo+["clippy","--locked","--offline","--manifest-path","trillionnium/Cargo.toml","--workspace","--all-targets","--all-features","--","-D","warnings"])
 run("green-public-regression",base+["--lib","ingress::public_v3::growth::tests::public_growth_v1_future_ancestor_defers_fresh_and_duplicate_before_work","--","--exact","--nocapture","--test-threads=1"])
 run("growth-branch-clock",base+["--lib","native_growth_v2_observed_clock_","--","--nocapture","--test-threads=1"])
 run("research-terminal-height",base+["--lib","research_work_schedule::incremental_boundary_tests::terminal_arithmetic_fixture_accepts_one_complete_w1_then_refuses_successor","--","--exact","--test-threads=1"])
 run("cli-resampled-clock",base+["--bin","trnm-pon-node","growth_cli::clock_tests::native_growth_v2_cli_resamples_wall_clock_after_work_and_keeps_explicit_time_fixed","--","--exact","--nocapture","--test-threads=1"])
 branch=out/"branch-work-schedule"
 run("research-work-schedule",base+["--test","research_work_schedule","--","--test-threads=1"],{"TRNM_WORK_SCHEDULE_RESEARCH_DIR":str(branch)})
 for backend in ("pnh1-authenticated","pgh2-growth"):
  raw=branch/backend;digest=hashlib.sha256((raw/"report.json").read_bytes()).hexdigest()
  run("research-reader-"+backend,["python3","scripts/pon_branch_work_schedule_reader.py","--raw-dir",str(raw),"--report-sha256",digest])
  run("research-reader-controls-"+backend,["python3","scripts/ci/test_pon_branch_work_schedule_reader.py","--raw-dir",str(raw),"--report-sha256",digest,"-v"])
 for name,target in [("growth-cli","native_growth_cli"),("growth-public-cli","native_growth_public_cli"),("growth-persistence-cancellation","growth_persistence_cancellation")]:
  run(name,base+["--test",target,"--","--test-threads=1"])
 for name,selector in [("growth-owner","store::growth::"),("public-growth","ingress::public_v3::growth::tests"),("consensus","consensus::tests"),("legacy-reorg","store::legacy_reorg_root_tests"),("reorg-readback","store::reorg_readback_tests"),("append-readback","store::append_readback_tests")]:
  run(name,base+["--lib",selector,"--","--test-threads=1"])
 joint=out/"joint-daa"
 run("joint-daa",base+["--test","daa_joint_consensus","--","--test-threads=1"],{"TRNM_JOINT_DAA_EVIDENCE_DIR":str(joint)})
 for backend in ("pnh1-authenticated","pgh2-growth"):
  raw=joint/backend;digest=hashlib.sha256((raw/"joint-daa.json").read_bytes()).hexdigest()
  run("joint-reader-"+backend,["python3","scripts/pon_joint_daa_reader.py","--raw-dir",str(raw),"--expected-report-sha256",digest])
  run("joint-reader-controls-"+backend,["python3","scripts/ci/test_pon_joint_daa_reader.py","--raw-dir",str(raw)])
 daa=out/"daa-bounds"
 run("daa-adversarial",base+["--test","daa_adversarial_schedule","--","--test-threads=1"],{"TRNM_DAA_EVIDENCE_DIR":str(daa)})
 digest=hashlib.sha256((daa/"daa-bounds.json").read_bytes()).hexdigest()
 run("daa-reader",["python3","scripts/pon_daa_schedule_reader.py","--raw-dir",str(daa),"--expected-report-sha256",digest])
 run("daa-reader-controls",["python3","scripts/ci/test_pon_daa_schedule_reader.py","--raw-dir",str(daa)])
finally:
 source("source-after")
print(json.dumps({"result":"PASS","source_head":head,"commands":len(records)}),flush=True)
