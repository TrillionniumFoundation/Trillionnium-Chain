#!/usr/bin/env python3
"""One-shot exact-c2 real V2 replay. Inputs and run outputs are never overwritten."""
import datetime,hashlib,json,os,signal,stat,subprocess,sys,time
from pathlib import Path
REPO=Path("/home/qq/work/chain-cell-capacity-dc0357-20261109")
BASE=Path("/home/qq/work/chain-cell-capacity-dc0357-20261109-validation")
HEAD="6ea3bf3fe13d66333bba3a8c7b97e14b4319b39f"
TREE="6c4401a94defeecb9696c2da1442dcbd27b56352"
IDENT={"commit":HEAD,"tree":TREE,"status":""}
SPEC=BASE/"source-inputs.v2.json"
SPEC_SHA="488b838dfdf05ab9768fff18ee81c0874b7bb471cbceeefdf15ab42c5dde6d48"
AUDIT=BASE/"source-inputs.v2.verification.json"
AUDIT_SHA="da304270715cd5791ef1791fefeb279bee9c023f9003e2f0064c2b92480f9db6"
WORKER_SHA="e93bfc47f8055786f2088fc65f61c1f0d2482a0b8b4e5b8b9e30e8707fbb8c1b"
OPERATION="fad809b14a2ef0814d5cb125ac4c2713ca81d962797e038857416a838c0c5cc2"
OUTPUT=BASE/"real-v2-fad809b14a2e-attempt-01"
DEST=BASE/"real-v2-fad809b14a2e-attempt-01-wrapper"
BINARY=Path("/home/qq/work/chain-cell-capacity-dc0357-20261109-target/debug/examples/cell_sealed_research_next_use_v2")
BINARY_SHA="734d4e5f9fcd8b3c9c742cde9f770771219922bebee4343fcd163a3ef7de6a6a"
FINAL_GATE=BASE/"cargo-6ea3bf3-attempt01"
FINAL_GATE_SHA="a33cc2c239d4e0c86a50edd4d1846b6a3852dbb7e0f672eca6c21db11fc9a0cf"
EXAMPLE_GATE=BASE/"example5-6ea3bf3-attempt01"
EXAMPLE_GATE_SHA="168723e97a9e5725050f7345cf06e3b033cf1cbc846ce9c49facda3f9c735840"
os.umask(0o077)
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def check(v,msg):
 if not v:raise RuntimeError(msg)
def sha(path):
 h=hashlib.sha256()
 with open(path,"rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()
def write(path,value):
 with open(path,"x") as f:
  json.dump(value,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
def ident():
 result={"commit":subprocess.check_output(["/usr/bin/git","rev-parse","HEAD"],cwd=REPO,text=True).strip(),"tree":subprocess.check_output(["/usr/bin/git","rev-parse","HEAD^{tree}"],cwd=REPO,text=True).strip(),"status":subprocess.check_output(["/usr/bin/git","status","--porcelain","--untracked-files=all"],cwd=REPO,text=True).strip()}
 check(result==IDENT,"exact clean c2 source mismatch")
 return result
def cgroup_memory():
 result={}
 try:
  rel=next(line.split(":",2)[2] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::"))
  location=Path("/sys/fs/cgroup")/rel.lstrip("/")
  for name in ("memory.max","memory.peak","memory.events"):
   file=location/name
   if file.is_file():result[name]=file.read_text().strip()
  result["scope"]="Hepta systemd job cgroup, wrapper plus native process and descendants"
 except (OSError,StopIteration) as e:result["observation_error"]=str(e)
 return result
def verify_gate(folder,pin,required):
 check(sha(folder/"observation.json")==pin,"gate observation hash: "+str(folder))
 data=json.loads((folder/"observation.json").read_text())
 check(data["passed"] and data["sources_unchanged"] and not data["changed_source_files"] and data["identity"]==IDENT,"gate source or result")
 gates={g["name"]:g for g in data["gates"]}
 for name in required:
  g=gates[name];check(g["exit_code"]==0,"failed prerequisite "+name)
  check(sha(folder/(name+".log"))==g["log_sha256"],"gate raw log changed: "+name)
 return data
def verify_inputs(spec,audit):
 observed=[]
 entries=[(category,name,value) for category in ("model","environment") for name,value in spec[category].items()]
 entries.append(("python","python",spec["python"]))
 expected={(x["category"],x["logical"]):x for x in audit["inputs"]}
 check(len(entries)==31 and len(expected)==31,"input roster")
 for category,name,value in entries:
  prior=expected[(category,name)];path=Path(value["path"])
  check(str(path)==prior["selected_path"] and value["sha256"]==prior["sha256"],"input independent pin mismatch: "+name)
  before=path.stat()
  check(stat.S_ISREG(before.st_mode),"not regular input: "+name)
  digest=sha(path);after=path.stat()
  check((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),"input changed during hash: "+name)
  check(digest==value["sha256"] and before.st_size==prior["size"],"input bytes changed: "+name)
  observed.append({"category":category,"logical":name,"path":str(path),"bytes":before.st_size,"sha256":digest})
 return observed
def validate_native(native,spec):
 check(native.get("passed") is True,"native replay did not pass: "+str(native.get("error")))
 check(native.get("source_input_sha256")==SPEC_SHA,"native spec pin")
 check(native.get("actual_model_run")=="observed_two_forwards","actual two-forward receipt missing")
 check(native.get("typed_snapshot_admitted") is True and native.get("composition_worker_executed") is True,"typed admission/composition worker execution")
 pins=native["operation_pins"]
 check(pins["operation"]==OPERATION,"operation drift")
 check(pins["tcv1"]==native["input"]["tcv1"]==native["bep52"]["tcv1"],"TCV1 drift")
 check(pins["cts1"]==native["snapshot"]["cts1"],"CTS1 drift")
 check(pins["bep52_plan"]==native["bep52"]["plan"],"transport plan drift")
 check(pins["chb1"]==native["handoff"]["descriptor"],"CHB1 drift")
 check(native["handoff"]["worker_sha256"]==WORKER_SHA,"worker drift")
 for key in ("loopback_only","single_operator","empty_initial_cache","original_absolute_deadline","complete_readback"):
  check(native["bep52"][key] is True,"missing transport evidence: "+key)
 check(native["bep52"]["member_sessions_created"]==0,"member minted new session")
 for key in ("source_cache_absent","bep52_cache_absent","retained_from_bep52_received_cache","anchored_reopen","actual_target_readback"):
  check(native["cold_restore"][key] is True,"missing TCA3 restore evidence: "+key)
 for key in ("publisher_cache_absent","bep52_cache_absent","consumer_cache_absent"):
  check(native["sealed_cache_independence"][key] is True,"cache not removed: "+key)
 actual=native["actual_next_use"]
 check(actual["observations"]==2 and actual["connector_complete"] is True and not actual["failures"],"forward receipts")
 check(actual["supervisor"]["outcome"]=="success" and actual["supervisor"]["waited_child_reaped"] is True,"original supervisor wait4 receipt")
 check(native["process"]["exit_code"]==0 and native["process"]["termination_requested"] is False,"native worker process")
 check(native["process"]["original_seconds"]==300 and native["process"]["elapsed_ms"]<300000,"original deadline")
 check(not native["independent_operators"] and not native["hepta_final_use"] and not native["production_activation"],"authority bounds")
 return pins
if sys.argv[1:]!=["--execute"]:raise SystemExit("explicit --execute required")
check(not OUTPUT.exists(),"original operation output already exists; no rerun")
DEST.mkdir(mode=0o700,exist_ok=False)
write(DEST/"one-shot-claim.json",{"operation":OPERATION,"output":str(OUTPUT),"claimed_at_utc":utc(),"same_operation_retry_permitted":False})
observation={"schema":"trnm.cell-sealed-research-real-v2-observation.v1","operation":OPERATION,"source":str(SPEC),"source_sha256":SPEC_SHA,"binary":str(BINARY),"binary_sha256":BINARY_SHA,"output":str(OUTPUT),"recovery_profile":"TCA3 complete-copy catalog anchored cold restore","native_erasure_shard_recovery":False,"original_seconds":300,"runtime_rss_bytes":8589934592,"max_snapshot_bytes":536870912,"outer_timeout_seconds":450,"started_at_utc":utc(),"actual_native_started":False,"passed":False}
error=None;began=time.monotonic();native=None;process=None
try:
 observation["start_identity"]=ident()
 gate=verify_gate(FINAL_GATE,FINAL_GATE_SHA,("da-crate","strict-clippy","fmt"))
 ex=verify_gate(EXAMPLE_GATE,EXAMPLE_GATE_SHA,("example5","binary-build"))
 check(next(g for g in ex["gates"] if g["name"]=="example5")["five_tests_passed"],"five tests required")
 check(ex["binary_sha256"]==BINARY_SHA and sha(BINARY)==BINARY_SHA,"binary independent pin")
 check(sha(SPEC)==SPEC_SHA and sha(AUDIT)==AUDIT_SHA,"source specification/verification pin")
 spec=json.loads(SPEC.read_text());audit=json.loads(AUDIT.read_text())
 check(spec["schema"]=="trnm.cell-sealed-research-source.v2" and spec["operation"]==OPERATION and spec["output"]==str(OUTPUT),"fixed new operation")
 check((spec["seconds"],spec["runtime_rss_bytes"],spec["max_snapshot_bytes"])==(300,8589934592,536870912),"original limits changed")
 check(spec["snapshot"]["worker_sha256"]==WORKER_SHA==spec["context"]["runtime"]==spec["environment"]["scripts/llm_cell_sealed_worker_v1.py"]["sha256"],"worker pins changed")
 check(spec["snapshot"]["quantization"]=="none","unsupported quantization")
 before_inputs=verify_inputs(spec,audit);write(DEST/"inputs-start.json",before_inputs)
 env=os.environ.copy();env.update(json.loads((FINAL_GATE/"start.json").read_text())["environment"])
 env["PATH"]=str(Path(env["RUSTC"]).parent)+os.pathsep+env.get("PATH","")
 env["PYTHONDONTWRITEBYTECODE"]="1"
 check(sha(env["TRNM_PQ_OPENSSL"])==env["TRNM_PQ_OPENSSL_SHA256"],"provider changed")
 command=[str(BINARY),str(SPEC),SPEC_SHA]
 observation.update({"input_count":len(before_inputs),"worker_sha256":WORKER_SHA,"command":command,"final_gate_sha256":FINAL_GATE_SHA,"example_gate_sha256":EXAMPLE_GATE_SHA,"environment":json.loads((FINAL_GATE/"start.json").read_text())["environment"],"memory_start":cgroup_memory(),"wrapper_sha256":sha(Path(__file__))})
 write(DEST/"start.json",observation)
 with open(DEST/"preflight.log","xb") as f:
  preflight=subprocess.run(["bash","scripts/project-preflight.sh"],cwd=REPO,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=30)
 check(preflight.returncode==0,"preflight failed")
 ident()
 check(not OUTPUT.exists(),"operation output appeared before launch")
 print(json.dumps({"stage":"native-start","operation":OPERATION,"source_sha256":SPEC_SHA,"binary_sha256":BINARY_SHA,"output":str(OUTPUT)}),flush=True)
 with open(DEST/"native.stdout","xb") as out,open(DEST/"native.stderr","xb") as err:
  native_started=time.monotonic()
  process=subprocess.Popen(command,cwd=REPO/"trillionnium",env=env,stdout=out,stderr=err,start_new_session=True)
  observation["actual_native_started"]=True;observation["native_pid"]=process.pid
  write(DEST/"native-started.json",{"pid":process.pid,"at_utc":utc(),"command":command})
  terminated=False;killed=False
  while True:
   waited,status,usage=os.wait4(process.pid,os.WNOHANG)
   if waited:
    process.returncode=os.waitstatus_to_exitcode(status);break
   elapsed=time.monotonic()-native_started
   if elapsed>=420 and not terminated:
    os.killpg(process.pid,signal.SIGTERM);terminated=True
   if elapsed>=435 and not killed:
    os.killpg(process.pid,signal.SIGKILL);killed=True
   time.sleep(0.1)
  observation["native_process"]={"exit_code":process.returncode,"elapsed_seconds":time.monotonic()-native_started,"watchdog_term":terminated,"watchdog_kill":killed,"user_cpu_seconds":usage.ru_utime,"system_cpu_seconds":usage.ru_stime,"ru_maxrss_kib":usage.ru_maxrss,"resource_scope":"Linux wait4 rusage for native Rust child, with OS child accounting; peak RSS is not a simultaneous process-tree RSS sum"}
 check(process.returncode==0 and not terminated and not killed,"native exit or cleanup watchdog failure")
 native=json.loads((OUTPUT/"native-result.json").read_text())
 observation["operation_pins"]=validate_native(native,spec)
 after_inputs=verify_inputs(spec,audit);write(DEST/"inputs-end.json",after_inputs)
 check(before_inputs==after_inputs,"input roster changed")
 observation["inputs_unchanged"]=True
 observation["passed"]=True
except BaseException as e:
 error=type(e).__name__+": "+str(e);observation["passed"]=False
finally:
 observation["error"]=error
 try:
  observation["end_identity"]=ident()
  observation["binary_sha256_end"]=sha(BINARY)
  observation["source_sha256_end"]=sha(SPEC)
  check(observation["binary_sha256_end"]==BINARY_SHA and observation["source_sha256_end"]==SPEC_SHA,"binary/spec changed")
 except BaseException as e:
  observation["passed"]=False;observation["error"]=(observation["error"]+"; " if observation["error"] else "")+type(e).__name__+": "+str(e)
 observation["memory_end"]=cgroup_memory()
 observation["total_wrapper_elapsed_seconds"]=time.monotonic()-began
 observation["completed_at_utc"]=utc()
 inventory=[]
 for root in (DEST,OUTPUT):
  if root.exists():
   for p in sorted(root.rglob("*")):
    if p.is_file() and p.name!="observation.json":
     inventory.append({"path":str(p),"bytes":p.stat().st_size,"sha256":sha(p)})
 observation["artifacts"]=inventory
 if native is None and (OUTPUT/"native-result.json").is_file():
  try:native=json.loads((OUTPUT/"native-result.json").read_text())
  except (OSError,ValueError):pass
 if native is not None:observation["native_summary"]={k:native.get(k) for k in ("passed","error","stage","actual_model_run","typed_snapshot_admitted","composition_worker_executed","process")}
 write(DEST/"observation.json",observation)
 print(json.dumps({"stage":"complete","passed":observation["passed"],"error":observation["error"],"actual_native_started":observation["actual_native_started"],"native_summary":observation.get("native_summary"),"observation":str(DEST/"observation.json"),"observation_sha256":sha(DEST/"observation.json")}),flush=True)
sys.exit(0 if observation["passed"] else 1)
