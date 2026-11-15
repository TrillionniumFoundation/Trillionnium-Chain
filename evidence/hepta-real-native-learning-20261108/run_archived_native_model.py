import pathlib,subprocess,hashlib,json,os,tarfile,stat,time,traceback,sys,platform,xml.etree.ElementTree as ET
root=pathlib.Path("/home/qq/hepta-learning-native-27849cb-d9fb-20261108")
source=root/"source"; transfer=root/"transfer"; extracted=root/"extracted"; run=root/"native-v8"
run.mkdir(mode=0o700)
source.mkdir(mode=0o700)
extracted.mkdir(mode=0o700)
expected_source="27849cbdcfc0d4afc69764d6c1742af22c41c293"
expected_tree="af50e58bf382891fb41861810cbf5425ca0da5a9"
result={"schema":"hepta-real-model-native-archived-run-v1","source":expected_source,"tree":expected_tree,"operation":"learning-d9fb-native-v8","result":"INCOMPLETE","model_test_started":False,"production_activation":False,"qualification":"HOLD_NO_GO"}
def save(name,value):
 with (run/name).open("x") as f: json.dump(value,f,sort_keys=True,indent=2); f.write("\n")
def digest(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def tracked():
 rows=json.loads((transfer/"source-files.json").read_bytes())
 for row in rows:
  p=source/row["path"]
  b=os.readlink(p).encode() if row["mode"]=="120000" else p.read_bytes()
  assert len(b)==row["bytes"] and hashlib.sha256(b).hexdigest()==row["sha256"],row["path"]
  assert hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()==row["git_blob"],row["path"]
  if row["mode"]!="120000": assert bool(p.stat().st_mode & stat.S_IXUSR)==(row["mode"]=="100755"),row["path"]
 return len(rows)
try:
 meta=json.loads((transfer/"result.json").read_bytes())
 assert meta["source"]==expected_source and meta["tree"]==expected_tree
 for name,m in meta["files"].items():
  p=transfer/name
  assert p.stat().st_size==m["bytes"] and digest(p)==m["sha256"],name
 with tarfile.open(transfer/"source.tar","r:") as tf:
  for m in tf.getmembers():
   p=pathlib.PurePosixPath(m.name)
   assert not p.is_absolute() and ".." not in p.parts,m.name
  tf.extractall(source,filter="data")
 result["tracked_before"]=tracked()
 rust=pathlib.Path("/home/qq/.rustup/toolchains/1.96.0-x86_64-unknown-linux-gnu/bin")
 python=pathlib.Path("/home/qq/hepta-smollm2-weight-research-20261103/ci-env/bin/python")
 assert (rust/"cargo").is_file()
 assert digest(python.resolve())=="23bc148d2b48964b621c5561ff2b81c1d9c7b717967a7491efbf12f4304882b5"
 driver=source/"scripts/research/smollm_learning_process_v1.py"
 assert digest(driver)=="2359169fb5e7b8c424df98301ea6e46054c5a8fabcae3f160dea9a284745809c"
 env=dict(os.environ)
 env.update(PATH=str(transfer)+":"+str(rust)+":"+str(python.parent)+":/usr/bin:/bin",PYTHONDONTWRITEBYTECODE="1",CARGO_NET_OFFLINE="true",HF_HUB_OFFLINE="1",TRANSFORMERS_OFFLINE="1",RUSTUP_TOOLCHAIN="1.96.0-x86_64-unknown-linux-gnu")
 libs=[str(p)for p in [pathlib.Path("/usr/lib/llvm-21/lib"),rust.parent/"lib"] if p.is_dir()]
 if libs: env["LD_LIBRARY_PATH"]=":".join(libs)
 list_cmd=[str(rust/"cargo"),"nextest","list","--archive-file",str(transfer/"agentd-nextest.tar.zst"),"--workspace-remap",str(source/"codex-rs"),"--extract-to",str(extracted),"--list-type","binaries-only","--message-format","json"]
 with (run/"archive-list.stdout.json").open("xb") as out,(run/"archive-list.stderr.log").open("xb") as err:
  listing=subprocess.run(list_cmd,cwd=source/"codex-rs",env=env,stdout=out,stderr=err,timeout=120)
 save("archive-list-command.json",{"command":list_cmd,"returncode":listing.returncode})
 assert listing.returncode==0,"archive list failed before actual model test"
 binaries=[]
 for p in extracted.rglob("codex_hepta_agentd-*"):
  if p.is_file() and os.access(p,os.X_OK):
   with p.open("rb") as f: magic=f.read(4)
   if magic!=b"\x7fELF": continue
   ldenv=dict(env); ldenv["LD_LIBRARY_PATH"]=str(p.parent)+":"+ldenv.get("LD_LIBRARY_PATH","")
   ldd=subprocess.run(["/usr/bin/ldd",str(p)],env=ldenv,text=True,capture_output=True,timeout=30)
   binaries.append({"path":str(p),"bytes":p.stat().st_size,"sha256":digest(p),"ldd_exit":ldd.returncode,"ldd_stdout":ldd.stdout,"ldd_stderr":ldd.stderr})
   assert ldd.returncode==0 and "not found" not in ldd.stdout,"missing actual test dynamic dependency"
 assert len(binaries)==1,binaries
 save("compiled-runtime.json",{"archive":meta,"binaries":binaries,"machine":platform.uname()._asdict(),"os_release":pathlib.Path("/etc/os-release").read_text(),"rustc":subprocess.check_output([str(rust/"rustc"),"-Vv"],env=env,text=True),"cgroup":pathlib.Path("/proc/self/cgroup").read_text()})
 config={"operation":result["operation"],"output":str(run/"model"),"research_root":"/home/qq/hepta-smollm2-weight-research-20261103","previous_run":"/home/qq/chain-learning-d9fb-20261108","worker_helper":"/home/qq/chain-learning-d9fb-20261108-readback-runner.py"}
 save("model-config.json",config); (run/"tmp").mkdir(mode=0o700)
 env.update(HEPTA_REAL_MODEL_CONFIG=str(run/"model-config.json"),HEPTA_REAL_MODEL_CONFIG_SHA256=digest(run/"model-config.json"),HEPTA_REAL_MODEL_DRIVER=str(driver),HEPTA_REAL_MODEL_DRIVER_SHA256=digest(driver),HEPTA_REAL_MODEL_PYTHON=str(python),HEPTA_REAL_MODEL_PYTHON_SHA256=digest(python.resolve()),HEPTA_REAL_MODEL_SOURCE_COMMIT=expected_source,HEPTA_REAL_MODEL_SOURCE_TREE=expected_tree,HEPTA_REAL_MODEL_EVIDENCE=str(run/"evidence"),TMPDIR=str(run/"tmp"))
 selected="actual_smollm_training_no_update_native_next_use_and_cold_readback"
 cmd=[str(transfer/"just"),"test","--archive-file",str(transfer/"agentd-nextest.tar.zst"),"--workspace-remap",str(source/"codex-rs"),"--extract-to",str(extracted),"--extract-overwrite","--run-ignored","only","--retries","0","--no-capture","-E","test("+selected+")"]
 save("test-admission.json",{"command":cmd,"environment":{k:v for k,v in env.items() if k.startswith("HEPTA_REAL_MODEL_") or k in ["PATH","LD_LIBRARY_PATH","TMPDIR","PYTHONDONTWRITEBYTECODE","CARGO_NET_OFFLINE","HF_HUB_OFFLINE","TRANSFORMERS_OFFLINE","RUSTUP_TOOLCHAIN"]},"source":expected_source,"tree":expected_tree,"archive_sha256":meta["files"]["agentd-nextest.tar.zst"]["sha256"],"nextest_config_sha256":digest(source/"codex-rs/.config/nextest.toml"),"original_watchdog_seconds":60,"automatic_retries":0,"created_unix_ns":time.time_ns(),"cpu_quota_percent":400,"memory_max_bytes":8589934592})
 result["model_test_started"]=True; result["start_unix_ns"]=time.time_ns(); before=time.monotonic()
 with (run/"test.log").open("xb") as log:
  p=subprocess.run(cmd,cwd=source,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=180)
 result.update(exit_code=p.returncode,end_unix_ns=time.time_ns(),elapsed_seconds=time.monotonic()-before,tracked_after=tracked(),log_sha256=digest(run/"test.log"))
 junit=[source/"codex-rs/target/nextest/local/junit.xml"]
 assert junit[0].is_file(),"original nextest JUnit missing"
 (run/"original-junit.xml").write_bytes(junit[0].read_bytes())
 result["junit_candidates"]=[str(p)for p in junit]
 assert len(junit)==1,junit
 report=ET.parse(junit[0]); cases=report.findall(".//testcase")
 result["testcases"]=[{"classname":e.get("classname"),"name":e.get("name"),"time":e.get("time"),"failure":e.find("failure") is not None,"error":e.find("error") is not None,"skipped":e.find("skipped") is not None}for e in cases]
 result["junit_sha256"]=digest(junit[0])
 assert p.returncode==0 and len(cases)==1 and selected in cases[0].get("name","") and not any(result["testcases"][0][k]for k in ["failure","error","skipped"]),"original actual test did not pass"
 native=json.loads((run/"evidence/native-result.json").read_bytes())
 assert native["result"]=="PASS" and native["operation"]==result["operation"]
 result["native_result"]=native; result["result"]="PASS_ACTUAL_NATIVE_MODEL_ITERATION"
except Exception as e:
 result["result"]="FAIL"; result["error"]=repr(e); result["traceback"]=traceback.format_exc()
finally:
 result["recorded_unix_ns"]=time.time_ns(); save("execution-result.json",result); print(json.dumps(result,sort_keys=True))
sys.exit(0 if result["result"]=="PASS_ACTUAL_NATIVE_MODEL_ITERATION" else 1)
