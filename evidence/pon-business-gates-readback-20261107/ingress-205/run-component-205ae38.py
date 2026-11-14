from pathlib import Path
import hashlib,json,os,re,stat,subprocess,time,sys
ROOT=Path("/home/qian-qi/chain-throughput-local-admin-20261107/work-ingress-canonical-d26")
OUT=Path("/home/qian-qi/chain-throughput-local-admin-20261107/review-ingress-canonical-d26/component-205ae38")
EXPECTED_HEAD="205ae38ff01bbf968f3fc2ef0297bee986224684"
OUT.mkdir(exist_ok=False)
def git(*args):
 return subprocess.check_output(["git",*args],cwd=ROOT)
def snapshot(label):
 head=git("rev-parse","HEAD").decode().strip()
 assert head==EXPECTED_HEAD,(label,head)
 status=git("status","--porcelain=v1","--untracked-files=all").decode()
 assert not status,(label,status)
 entries=[]
 for item in git("ls-files","--stage","-z").split(b"\0"):
  if not item:continue
  info,path=item.split(b"\t",1);mode,oid,stage=info.decode().split()
  assert stage=="0",(label,path,stage)
  name=os.fsdecode(path);p=ROOT/name
  before=p.lstat()
  if stat.S_ISLNK(before.st_mode):
   content=os.fsencode(os.readlink(p));size=len(content)
   sha=hashlib.sha256(content)
   blob=hashlib.sha1(b"blob "+str(size).encode()+b"\0"+content)
  else:
   assert stat.S_ISREG(before.st_mode),(name,mode)
   size=before.st_size;sha=hashlib.sha256()
   blob=hashlib.sha1(b"blob "+str(size).encode()+b"\0")
   with p.open("rb") as f:
    while data:=f.read(1024*1024):
     sha.update(data);blob.update(data)
  after=p.lstat()
  assert (before.st_dev,before.st_ino,before.st_mode,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns),(label,name,"changed while reading")
  assert blob.hexdigest()==oid,(label,name,oid,blob.hexdigest())
  entries.append({"path":name,"mode":mode,"bytes":size,"git_blob":oid,"sha256":sha.hexdigest()})
 source={"head":head,"tree":git("rev-parse","HEAD^{tree}").decode().strip(),"status":status,"tracked_files":entries}
 raw=(json.dumps(source,sort_keys=True,indent=2)+"\n").encode()
 (OUT/f"source-{label}.json").write_bytes(raw)
 receipt={"label":label,"manifest_sha256":hashlib.sha256(raw).hexdigest(),"tracked_file_count":len(entries),"head":head,"tree":source["tree"]}
 print(json.dumps({"source":receipt}),flush=True)
 return source,receipt
def command(name,argv):
 path=OUT/(name+".log")
 started=time.time_ns()
 with path.open("wb") as f:
  p=subprocess.run(argv,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT)
 record={"name":name,"argv":argv,"started_unix_ns":started,"ended_unix_ns":time.time_ns(),"exit_code":p.returncode,"log":str(path),"log_bytes":path.stat().st_size,"log_sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
 (OUT/(name+".json")).write_text(json.dumps(record,indent=2)+"\n")
 print(json.dumps(record),flush=True)
 return record
def names(relative):
 source=(ROOT/relative).read_text()
 return re.findall(r"#\[test\]\s*fn\s+([a-zA-Z0-9_]+)\s*\(",source)

from fractions import Fraction
from collections import defaultdict
PLAN_PATH=OUT.parent/"component-adoption-plan-205ae38.json"
PLAN_SHA="82f087389dd27519cb4e1fe2568ba2e1988f200d187d7fd9e922a18d7e63e820"
records=[]
before=None
failure=None
source_equal=False
binary_equal=False
analysis=None
def file_sha(path):
 digest=hashlib.sha256()
 with Path(path).open("rb") as f:
  while block:=f.read(1024*1024):digest.update(block)
 return digest.hexdigest()
def statistics(values):
 values=sorted(values)
 count=len(values)
 assert count==32,count
 median=Fraction(values[count//2-1]+values[count//2],2)
 p95=values[(95*count+99)//100-1]
 return {"count":count,"median_ns":float(median),"median_fraction":{"numerator":median.numerator,"denominator":median.denominator},"p95_ns":p95,"min_ns":values[0],"max_ns":values[-1],"sum_ns":sum(values)},median,p95
def analyze(log,plan):
 observed=[]
 invalid=[]
 for line_number,line in enumerate(Path(log).read_text().splitlines(),1):
  start=line.find("{")
  if start<0:continue
  try:value=json.loads(line[start:])
  except json.JSONDecodeError:
   if "public-v3-body-packet-component-abba-v1" in line:invalid.append({"line":line_number,"text":line})
   continue
  if isinstance(value,dict) and value.get("schema")=="public-v3-body-packet-component-abba-v1":observed.append(value)
 (OUT/"component-records.jsonl").write_text("".join(json.dumps(v,sort_keys=True)+"\n" for v in observed))
 assert not invalid,("invalid component JSON",invalid)
 plans=[v for v in observed if v.get("kind")=="plan"]
 summaries=[v for v in observed if v.get("kind")=="summary"]
 trials=[v for v in observed if v.get("kind")=="trial"]
 assert len(plans)==len(summaries)==1,(len(plans),len(summaries))
 assert len(trials)==plan["expected_trials"]==768,len(trials)
 assert [r["trial"] for r in trials]==list(range(1,769))
 assert plans[0]["expected_trials"]==summaries[0]["expected_trials"]==summaries[0]["actual_trials"]==768
 assert summaries[0]["decoder_errors_retained"]==384 and summaries[0]["mismatches"]==summaries[0]["missing_cpu"]==0
 assert plans[0]["service_gate"] is False and summaries[0]["service_gate"] is False
 assert plans[0]["hardware_cache_flushed"] is False
 assert plans[0]["slots"]==plan["methods_by_slot"]
 assert plans[0]["blocks_per_fixture_exposure"]==plan["blocks_per_fixture_exposure"]
 assert plans[0]["exposures"]==plan["exposures"] and plans[0]["fixtures"]==len(plan["fixtures"])
 expected_error={"malformed-header":"HEADER_CODEC","malformed-count":"TRANSACTION_LIMIT","truncated-proof":"PACKET_LIMIT"}
 tx_count={"native-empty":0,"native-transfers-1":1,"native-transfers-64":64}
 group=defaultdict(list);identities=set();lengths=defaultdict(set);proofs=set()
 for row in trials:
  fixture=row["fixture"];exposure=row["exposure"];block=row["block"];slot=row["slot"];method=row["method"]
  assert fixture in plan["fixtures"] and exposure in plan["exposures"]
  assert type(block) is int and 0<=block<16 and type(slot) is int and 0<=slot<4
  assert method==plan["methods_by_slot"][slot],row
  identity=(fixture,exposure,block,slot)
  assert identity not in identities,identity
  identities.add(identity)
  assert row["matched_original_oracle"] is True,row
  assert type(row["thread_cpu_ns"]) is int and row["thread_cpu_ns"]>0,row
  assert type(row["wall_ns"]) is int and row["wall_ns"]>0,row
  assert type(row["packet_bytes"]) is int and row["packet_bytes"]>0
  assert row["body_bytes"]==len(b'{"op":"submit","packet":"')+2*row["packet_bytes"]+len(b'"}')
  if fixture in tx_count:
   assert row["accepted"] is True and row["error"] is None,row
   assert row["transactions"]==tx_count[fixture] and type(row["proof_bytes"]) is int and row["proof_bytes"]>0,row
   proofs.add(row["proof_bytes"])
  else:
   assert row["accepted"] is False and row["error"]==expected_error[fixture],row
   assert row["transactions"] is None and row["proof_bytes"] is None
  group[(fixture,exposure,method)].append(row)
  lengths[fixture].add((row["body_bytes"],row["packet_bytes"]))
 assert len(proofs)==1,proofs
 assert all(len(v)==1 for v in lengths.values())
 assert sum(r["accepted"] for r in trials)==384
 groups=[];passed=True
 for fixture in plan["fixtures"]:
  for exposure in plan["exposures"]:
   methods={};exact={}
   for method in ["owned","borrowed"]:
    rows=group[(fixture,exposure,method)]
    assert len(rows)==plan["expected_records_per_fixture_exposure_method"]==32
    methods[method]={}
    exact[method]={}
    for kind,key in [("cpu","thread_cpu_ns"),("wall","wall_ns")]:
     data,median,p95=statistics([r[key] for r in rows])
     methods[method][kind]=data;exact[method][kind]=(median,p95)
   ratios={}
   for kind in ["cpu","wall"]:
    median_ratio=exact["borrowed"][kind][0]/exact["owned"][kind][0]
    p95_ratio=Fraction(exact["borrowed"][kind][1],exact["owned"][kind][1])
    ratios[kind]={"median":float(median_ratio),"median_fraction":{"numerator":median_ratio.numerator,"denominator":median_ratio.denominator},"p95":float(p95_ratio)}
   threshold=Fraction(9,10) if fixture=="native-transfers-64" else Fraction(21,20)
   cpu_ratio=exact["borrowed"]["cpu"][0]/exact["owned"]["cpu"][0]
   criterion=cpu_ratio<=threshold
   passed=passed and criterion
   body_bytes,packet_bytes=next(iter(lengths[fixture]))
   groups.append({"fixture":fixture,"exposure":exposure,"body_bytes":body_bytes,"packet_bytes":packet_bytes,"statistics":methods,"ratios":ratios,"adoption_cpu_median_max":float(threshold),"adoption_criterion_passed":criterion})
 result={"schema":"ingress-canonical-component-analysis-v1","head":EXPECTED_HEAD,"plan_sha256":PLAN_SHA,"records_complete":True,"total_trials":768,"accepted":384,"original_codec_errors_retained":384,"oracle_mismatches":0,"missing_cpu":0,"groups":groups,"component_cpu_adoption_criteria_passed":passed,"whole_node_or_original_service_acceptance":False}
 (OUT/"analysis.json").write_text(json.dumps(result,indent=2)+"\n")
 return result
try:
 raw_plan=PLAN_PATH.read_bytes()
 assert hashlib.sha256(raw_plan).hexdigest()==PLAN_SHA,"plan changed"
 plan=json.loads(raw_plan)
 assert plan["candidate_head"]==EXPECTED_HEAD
 assert plan["measurements_started"] is False
 (OUT/"predeclared-plan.json").write_bytes(raw_plan)
 core_path=OUT.parent/"native-205ae38-v3"/"core.json"
 assert file_sha(core_path)==plan["native_core_sha256"]
 native=json.loads(core_path.read_text())
 assert native["cargo_tests_passed"]==native["exact_denominator_checks_passed"]==22 and native["strict_clippy"]["exit_code"]==0
 records.append(command("preflight",["bash","scripts/project-preflight.sh"]))
 assert records[-1]["exit_code"]==0
 before,before_receipt=snapshot("before")
 binary=Path(plan["same_binary"]["path"])
 binary_before=file_sha(binary)
 assert binary_before==plan["same_binary"]["sha256"],"test binary changed"
 environment={k:os.environ.get(k) for k in ["CARGO_HOME","CARGO_TARGET_DIR","CARGO_BUILD_JOBS","CARGO_INCREMENTAL","CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG","CARGO_PROFILE_TEST_OPT_LEVEL","RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS","RUST_TEST_THREADS","OPENSSL_DIR","OPENSSL_LIB_DIR","OPENSSL_INCLUDE_DIR","OPENSSL_STATIC","OPENSSL_CONF","OPENSSL_MODULES","TRNM_PQ_OPENSSL","TRNM_PQ_OPENSSL_SHA256","TRNM_PQ_OPENSSL_VERSION"]}
 (OUT/"environment.json").write_text(json.dumps(environment,indent=2)+"\n")
 provider=Path(os.environ["TRNM_PQ_OPENSSL"])
 assert file_sha(provider)==os.environ["TRNM_PQ_OPENSSL_SHA256"]=="79bd5e815ce341387d8299e66419fb8a56ba952892df8e3edc967cab60e83437"
 assert os.environ["OPENSSL_DIR"]==str(provider.parent.parent)
 assert os.environ["OPENSSL_INCLUDE_DIR"]==str(provider.parent.parent/"include")
 assert os.environ["OPENSSL_LIB_DIR"]==str(provider.parent.parent/"lib")
 assert os.environ["OPENSSL_STATIC"]=="1"
 records.append(command("process-sample-before",["/usr/bin/ps","-eo","pid,ppid,comm,etimes,pcpu,pmem","--sort=-pcpu"]))
 records.append(command("component-abba",plan["command"]))
 actual=records[-1]
 records.append(command("component-exact-denominator",["python3","scripts/ci/check_required_native_test.py",actual["log"],"--test",plan["test_selector"]]))
 denominator=records[-1]
 analysis=analyze(actual["log"],plan)
 records.append(command("process-sample-after",["/usr/bin/ps","-eo","pid,ppid,comm,etimes,pcpu,pmem","--sort=-pcpu"]))
 assert actual["exit_code"]==denominator["exit_code"]==0,"component command or denominator failure"
 assert analysis["component_cpu_adoption_criteria_passed"],"predeclared component CPU adoption criterion failed"
except BaseException as exc:
 failure=repr(exc)
 print(json.dumps({"failure":failure}),flush=True)
finally:
 if before is not None:
  try:
   after,after_receipt=snapshot("after")
   source_equal=before==after
   binary_after=file_sha(binary)
   binary_equal=binary_after==binary_before==plan["same_binary"]["sha256"]
   (OUT/"binary-identity.json").write_text(json.dumps({"path":str(binary),"before_sha256":binary_before,"after_sha256":binary_after,"planned_sha256":plan["same_binary"]["sha256"],"identical":binary_equal},indent=2)+"\n")
  except BaseException as exc:
   failure=(failure or "")+"; final-identity:"+repr(exc)
 summary={"schema":"ingress-canonical-component-run-v1","head":EXPECTED_HEAD,"plan_sha256":PLAN_SHA,"command_records":records,"source_equal":source_equal,"same_binary_before_after":binary_equal,"failure":failure,"records_complete":analysis is not None and analysis["records_complete"],"component_adoption_criteria_passed":analysis is not None and analysis["component_cpu_adoption_criteria_passed"] and source_equal and binary_equal and failure is None,"whole_node_or_original_service_acceptance":False}
 (OUT/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
 print(json.dumps({k:v for k,v in summary.items() if k!="command_records"}),flush=True)
sys.exit(0 if failure is None and source_equal and binary_equal else 1)
