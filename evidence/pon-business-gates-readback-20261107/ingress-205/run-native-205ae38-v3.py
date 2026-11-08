from pathlib import Path
import hashlib,json,os,re,stat,subprocess,time,sys
ROOT=Path("/home/qian-qi/chain-throughput-local-admin-20261107/work-ingress-canonical-d26")
OUT=Path("/home/qian-qi/chain-throughput-local-admin-20261107/review-ingress-canonical-d26/native-205ae38-v3")
EXPECTED_HEAD="205ae38ff01bbf968f3fc2ef0297bee986224684"
OUT.mkdir(exist_ok=True)
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
tests=[]
for file,module,expected in [
("trillionnium/crates/trnm-pon-node/src/ingress/public_v3/canonical_packet/tests.rs","ingress::public_v3::canonical_packet::tests",3),
("trillionnium/crates/trnm-pon-node/src/ingress/public_v3/input_decode_tests.rs","ingress::public_v3::input_decode_tests",4),
("trillionnium/crates/trnm-pon-node/src/ingress/public_v3/work_rejection/tests.rs","ingress::public_v3::work_rejection::tests",4),
("trillionnium/crates/trnm-pon-node/src/ingress/public_v3/work_arithmetic/tests.rs","ingress::public_v3::work_arithmetic::tests",5),
]:
 ns=names(file)
 assert len(ns)==expected,(file,expected,ns)
 tests.extend((["--lib"],module+"::"+n) for n in ns)
tests.extend((["--lib"],"ingress::public_v3::tests::"+name) for name in [
"paid_wrong_product_is_fully_rejected_and_the_preserved_valid_packet_is_activated",
"paid_envelope_malformed_body_is_accounted_before_signed_refusal"
])
integration=names("trillionnium/crates/trnm-pon-node/tests/public_cache_modes.rs")
assert len(integration)==4,integration
tests.extend((["--test","public_cache_modes"],n) for n in integration)
assert len(tests)==22,len(tests)
(OUT/"requested-tests.json").write_text(json.dumps({"head":EXPECTED_HEAD,"tests":[{"target":t,"name":n} for t,n in tests],"ignored_component_benchmark_executed":False},indent=2)+"\n")
records=[]
before=None
source_equal=False
failure=None
try:
 rec=command("preflight",["bash","scripts/project-preflight.sh"])
 records.append(rec)
 assert rec["exit_code"]==0,"preflight"
 before,before_receipt=snapshot("before")
 versions=command("rustc-version",["/home/qian-qi/.cargo/bin/rustc","+1.95.0","--version","--verbose"])
 records.append(versions)
 provider=Path(os.environ["TRNM_PQ_OPENSSL"])
 provider_sha=hashlib.sha256(provider.read_bytes()).hexdigest()
 assert provider_sha==os.environ["TRNM_PQ_OPENSSL_SHA256"]=="79bd5e815ce341387d8299e66419fb8a56ba952892df8e3edc967cab60e83437",("provider sha",provider_sha)
 assert os.environ["OPENSSL_DIR"]==str(provider.parent.parent)
 assert os.environ["OPENSSL_INCLUDE_DIR"]==str(provider.parent.parent/"include")
 assert os.environ["OPENSSL_LIB_DIR"]==str(provider.parent.parent/"lib")
 assert os.environ["OPENSSL_STATIC"]=="1"
 provider_record=command("provider-version",[str(provider),"version","-a"])
 records.append(provider_record)
 assert provider_record["exit_code"]==0,"provider version"
 (OUT/"build-environment.json").write_text(json.dumps({k:os.environ.get(k) for k in ["CARGO_HOME","CARGO_TARGET_DIR","CARGO_BUILD_JOBS","CARGO_INCREMENTAL","CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG","RUST_TEST_THREADS","OPENSSL_DIR","OPENSSL_LIB_DIR","OPENSSL_INCLUDE_DIR","OPENSSL_STATIC","OPENSSL_CONF","OPENSSL_MODULES","TRNM_PQ_OPENSSL","TRNM_PQ_OPENSSL_SHA256","TRNM_PQ_OPENSSL_VERSION"]},indent=2)+"\n")
 for i,(target,test) in enumerate(tests,1):
  rec=command(f"test-{i:02d}",["/home/qian-qi/.cargo/bin/cargo","+1.95.0","test","--manifest-path","trillionnium/Cargo.toml","--locked","--offline","--all-features","-p","trnm-pon-node",*target,test,"--","--exact","--test-threads=1","--nocapture"])
  records.append(rec)
  check=command(f"test-{i:02d}-denominator",["python3","scripts/ci/check_required_native_test.py",rec["log"],"--test",test])
  records.append(check)
  assert rec["exit_code"]==0 and check["exit_code"]==0,("required test",i,test)
 rec=command("strict-workspace-clippy",["/home/qian-qi/.cargo/bin/cargo","+1.95.0","clippy","--manifest-path","trillionnium/Cargo.toml","--workspace","--all-targets","--all-features","--locked","--offline","--","-D","warnings"])
 records.append(rec)
 assert rec["exit_code"]==0,"strict workspace clippy"
except BaseException as exc:
 failure=repr(exc)
 print(json.dumps({"failure":failure}),flush=True)
finally:
 if before is not None:
  try:
   after,after_receipt=snapshot("after")
   source_equal=before==after
  except BaseException as exc:
   failure=(failure or "")+"; source-after:"+repr(exc)
 summary={"head":EXPECTED_HEAD,"records":records,"requested_tests":len(tests),"completed_tests":sum(r["name"].startswith("test-") and not r["name"].endswith("-denominator") and r["exit_code"]==0 for r in records),"denominators_passed":sum(r["name"].endswith("-denominator") and r["exit_code"]==0 for r in records),"source_equal":source_equal,"failure":failure,"original_service_gate_passed":False,"component_benchmark_executed":False,"all_requested_commands_passed":failure is None and source_equal}
 (OUT/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
 print(json.dumps({k:v for k,v in summary.items() if k!="records"}),flush=True)
sys.exit(0 if failure is None and source_equal else 1)
