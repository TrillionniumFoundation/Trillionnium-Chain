#!/usr/bin/env python3
import hashlib,json,os,re,subprocess,time
from pathlib import Path
W=Path("/private/tmp/chain-public-policy-prefix-cache-20261114")
E=Path("/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1")
O=E/"validation-v1"
TARGET=Path("/private/tmp/chain-public-policy-prefix-cache-target-20261114")
P="trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs"
EXPECTED="0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a"
if O.exists() or TARGET.exists():raise ValueError("create-only validation/target")
O.mkdir();TARGET.mkdir()
env=os.environ.copy()
env.update(PATH="/Users/qianqi/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",PYTHONDONTWRITEBYTECODE="1",PYTHONOPTIMIZE="0",CARGO_TARGET_DIR=str(TARGET),CARGO_BUILD_JOBS="2",CARGO_INCREMENTAL="0",RUST_TEST_THREADS="1")
def sha(b):return hashlib.sha256(b).hexdigest()
def js(x):return (json.dumps(x,indent=2,sort_keys=True)+"\n").encode()
def put(name,b):
 p=O/name
 with p.open("xb") as f:f.write(b)
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
state={"schema":"trnm-public-policy-prefix-validation-v1","status":"RUNNING","source_head":"ed0d35487f2a67239e4d646fd41c2c7acb5cc740","modified_source":P,"modified_source_sha256":EXPECTED,"owned_target":str(TARGET),"environment":{k:env[k]for k in ["PATH","CARGO_TARGET_DIR","CARGO_BUILD_JOBS","CARGO_INCREMENTAL","RUST_TEST_THREADS","PYTHONDONTWRITEBYTECODE"]},"steps":[],"native_hosted_campaign_run":False,"hosted_performance_proved":False,"errors":[]}
def run(label,argv,timeout=120,expected_tests=None):
 out=O/(label+".stdout");err=O/(label+".stderr")
 started=time.time()
 with out.open("xb") as so,err.open("xb") as se:
  child=subprocess.Popen(argv,cwd=W,env=env,stdout=so,stderr=se)
  print(json.dumps({"event":"start","label":label,"pid":child.pid,"argv":argv,"timeout":timeout}),flush=True)
  try:code=child.wait(timeout=timeout);timed_out=False
  except subprocess.TimeoutExpired:
   timed_out=True;child.terminate()
   try:code=child.wait(timeout=20)
   except subprocess.TimeoutExpired:child.kill();code=child.wait()
 stdout=out.read_bytes();stderr=err.read_bytes()
 rec={"label":label,"argv":argv,"cwd":str(W),"pid":child.pid,"exit":code,"timed_out":timed_out,"seconds":time.time()-started,"stdout":{"path":str(out),"bytes":len(stdout),"sha256":sha(stdout)},"stderr":{"path":str(err),"bytes":len(stderr),"sha256":sha(stderr)}}
 if expected_tests is not None:
  summaries=re.findall(rb"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;",stdout)
  rec["expected_tests"]=expected_tests;rec["actual_summaries"]=[list(map(int,x))for x in summaries]
  rec["exact_test_count"]=rec["actual_summaries"]==[[expected_tests,0,0]]
 state["steps"].append(rec)
 put(label+".receipt.json",js(rec))
 print(json.dumps({"event":"terminal","label":label,"exit":code,"timed_out":timed_out,"seconds":rec["seconds"],"exact_test_count":rec.get("exact_test_count")}),flush=True)
 if code or timed_out or (expected_tests is not None and not rec["exact_test_count"]):raise ValueError(label+" failed; original streams retained")
try:
 if sha((W/P).read_bytes())!=EXPECTED:raise ValueError("source drift before tests")
 run("preflight",["/bin/bash","scripts/project-preflight.sh"])
 run("rustc-version",["rustc","-Vv"],30)
 run("cargo-version",["cargo","-V"],30)
 run("locked-offline-graph",["cargo","metadata","--locked","--offline","--format-version","1","--no-deps","--manifest-path","trillionnium/Cargo.toml"],120)
 base=["cargo","test","--locked","--offline","--release","--manifest-path","trillionnium/Cargo.toml","-p","trnm-pon-node","--lib"]
 run("cached-policy-three-controls",base+["ingress::public_v3::tests::cached_policy_id_","--","--nocapture"],900,3)
 for name in [
  "paid_envelope_resource_profile_has_fresh_exact_signed_commitment",
  "resource_revision_r20_rejects_signed_old_cookies_and_preserves_control_output_reserve",
  "cookie_binds_every_authority_and_resource_field_and_restart_epoch",
 ]:
  run(name,base+["ingress::public_v3::tests::"+name,"--","--exact","--nocapture"],120,1)
 run("policy-reader-original-controls",["/opt/homebrew/bin/python3","-B","scripts/ci/test_pon_public_v3_policy_read.py","-v"],120)
 run("strict-lib-tests-clippy",["cargo","clippy","--locked","--offline","--release","--manifest-path","trillionnium/Cargo.toml","-p","trnm-pon-node","--lib","--tests","--","-D","warnings"],900)
 run("workspace-format-check",["cargo","fmt","--manifest-path","trillionnium/Cargo.toml","--all","--","--check"],120)
 if sha((W/P).read_bytes())!=EXPECTED:raise ValueError("source drift after tests")
 state["status"]="SELECTED_CONTROLS_PASS"
except BaseException as e:
 state["status"]="HOLD";state["errors"].append(type(e).__name__+": "+str(e))
 raise
finally:
 state["source_after_sha256"]=sha((W/P).read_bytes())
 state["source_unchanged_during_validation"]=state["source_after_sha256"]==EXPECTED
 state["finished_ns"]=time.time_ns()
 put("summary.json",js(state))
 print(json.dumps({"summary":str(O/"summary.json"),"summary_sha256":sha((O/"summary.json").read_bytes()),"status":state["status"],"source_unchanged":state["source_unchanged_during_validation"]}),flush=True)
