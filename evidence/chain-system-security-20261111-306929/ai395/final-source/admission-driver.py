#!/usr/bin/env python3
"""Admit recorded F source-gate evidence with a narrow corpus delta."""
from pathlib import Path
import argparse,datetime,fcntl,hashlib,json,os,re,shutil,signal,stat,subprocess,sys,traceback
R=Path("/home/qq/chain-system-security-20261112-306929")
S=Path("/home/qq/chain-system-security-final-integration-20261112-306929")
O=S/"admit-source-evidence-E-v3"
P="evidence/chain-system-security-20261111-306929"
DEST=P+"/ai395/final-source"
C="config/pon/pq-cross-branch-corpus-v1.json"
F="2d72fa3293989b01596ec8ce0ba3ff370dc4c584"
NATIVE="bac6b7659bd7e2d633e25c2da0add60f6a10c7fb"
def sha(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def write_new(path,b):
 with path.open("xb") as f:f.write(b)
def jout(path,obj):write_new(path,(json.dumps(obj,indent=2,sort_keys=True)+"\n").encode())
def main():
 p=argparse.ArgumentParser();p.add_argument("--inputs",type=Path,required=True);p.add_argument("--inputs-sha256",required=True);a=p.parse_args()
 raw=a.inputs.read_bytes();assert sha(raw)==a.inputs_sha256
 inputs=json.loads(raw);assert inputs["schema"]=="trnm-final-source-evidence-child-inputs-v1"
 assert inputs["parent"]==F and inputs["native_source"]==NATIVE and inputs["source_owner_released"] is True
 O.mkdir()
 records=[];lockfd=None
 def run(name,args,ok=(0,),timeout=180):
  assert re.fullmatch(r"[a-z0-9-]+",name)
  row={"name":name,"argv":args,"cwd":str(R),"started_utc":now(),"timeout_seconds":timeout}
  jout(O/(name+".attempt.json"),row)
  stdout=O/(name+".stdout");stderr=O/(name+".stderr")
  q=None;failure=None
  with stdout.open("xb") as out,stderr.open("xb") as err:
   try:
    q=subprocess.Popen(args,cwd=R,stdout=out,stderr=err,start_new_session=True)
    row["pid"]=q.pid;jout(O/(name+".owner.json"),{"pid":q.pid,"process_group":q.pid,"utc":now()})
    try:row["exit_code"]=q.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
     row["timed_out"]=True
     try:os.killpg(q.pid,signal.SIGTERM)
     except ProcessLookupError:pass
     try:q.wait(timeout=10)
     except subprocess.TimeoutExpired:
      try:os.killpg(q.pid,signal.SIGKILL)
      except ProcessLookupError:pass
      q.wait(timeout=10)
     row["exit_code"]=q.returncode
     failure=RuntimeError(name+" timed out; reconcile repository before any further mutation")
   except BaseException as e:
    failure=e;row["exception"]=repr(e)
    if q is not None and q.poll() is None:
     try:os.killpg(q.pid,signal.SIGTERM)
     except ProcessLookupError:pass
     try:q.wait(timeout=10)
     except subprocess.TimeoutExpired:
      try:os.killpg(q.pid,signal.SIGKILL)
      except ProcessLookupError:pass
      q.wait(timeout=10)
     row["exit_code"]=q.returncode
   finally:
    out.flush();err.flush();os.fsync(out.fileno());os.fsync(err.fileno())
  a=stdout.read_bytes();b=stderr.read_bytes()
  row.update(finished_utc=now(),stdout_bytes=len(a),stderr_bytes=len(b),stdout_sha256=sha(a),stderr_sha256=sha(b))
  records.append(row);jout(O/(name+".receipt.json"),row)
  if failure is not None:raise failure
  if row.get("exit_code") not in ok:raise RuntimeError(name+" exit "+str(row.get("exit_code")))
  return a
 def g(name,args,**kw):return run(name,["git",*args],**kw)

 try:
  assert g("head-before",["rev-parse","HEAD"]).decode().strip()==F
  assert g("clean-before",["status","--porcelain=v1"]).strip()==b""
  run("preflight-before",["bash","scripts/project-preflight.sh"])
  lockfd=os.open(S/"evidence-child-integration-v3.lock",os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  sys.path.insert(0,str(R/"scripts/ci"))
  from verify_ci_source import verify
  before=verify("head",F,root=R);jout(O/"source-parent-before.json",before)
  rb=Path(inputs["full_receipt_path"]).read_bytes()
  assert sha(rb)==inputs["full_receipt_sha256"]
  receipt=json.loads(rb)
  assert receipt["schema"]=="trnm-final-source-gates-v1" and receipt["mode"]=="full"
  assert receipt["source"]==F and receipt["native_qualification_source"]==NATIVE
  assert receipt["all_gates_passed"] is False and receipt["source_before_after_equal"] is True
  assert receipt["protected_native_bytes_equal"] is True and receipt["python_controls_observed"]==65
  assert receipt["controls"]["authority-and-root-controls"]=={"expected":65,"observed_counts":[65],"count_matches":True,"plain_ok_without_skips":True}
  assert receipt["controls"]["source-rejection-controls"]=={"expected":43,"observed_counts":[43],"count_matches":True,"plain_ok_without_skips":False}
  qualified_raw=Path(inputs["full_qualification_path"]).read_bytes()
  assert sha(qualified_raw)==inputs["full_qualification_sha256"]
  qualification=json.loads(qualified_raw)
  assert qualification["schema"]=="trnm-final-source-gates-derived-qualification-v1"
  assert qualification["source"]==F and qualification["original_summary_sha256"]==sha(rb)
  assert qualification["original_driver_exit_code"]==1 and qualification["original_all_gates_passed"] is False
  assert qualification["all_actual_commands_passed"] is True and qualification["python_controls_verified"]==108
  assert qualification["source_before_after_equal"] is True and qualification["protected_native_bytes_equal"] is True
  assert qualification["native_tests_executed"] is False and qualification["clippy_executed"] is False
  assert receipt["native_tests_executed"] is False and receipt["clippy_executed"] is False
  assert len(receipt["commands"])==10
  assert all(x["recorder_exit_code"]==0 and x["actual_exit_code"]==0 and x["actual_status"]=="command_succeeded" for x in receipt["commands"])
  stage=Path(inputs["stage_directory"]);assert stage.is_dir() and not stage.is_symlink()
  expected=inputs["files"];assert expected and all(isinstance(x,str) for x in expected)
  actual={}
  for q in stage.rglob("*"):
   assert not q.is_symlink()
   if q.is_dir():continue
   assert stat.S_ISREG(q.lstat().st_mode)
   rel=q.relative_to(stage).as_posix();b=q.read_bytes()
   assert len(b)<=4194304 and ".." not in Path(rel).parts
   actual[rel]={"bytes":len(b),"sha256":sha(b)}
  assert actual==expected
  dest=R/DEST;assert not dest.exists();dest.mkdir(parents=True)
  newfiles=set()
  for rel,v in sorted(expected.items()):
   out=dest/rel;out.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(stage/rel,out)
   b=out.read_bytes();assert len(b)==v["bytes"] and sha(b)==v["sha256"]
   newfiles.add(DEST+"/"+rel)
  write_new(dest/"admission-driver.py",Path(__file__).read_bytes())
  write_new(dest/"admission-inputs.json",raw)
  newfiles|={DEST+"/admission-driver.py",DEST+"/admission-inputs.json"}
  readme=P+"/README.md";tick=chr(96)
  addition="\n## Final committed source-gate observation\n\nThe full source-only run executed at "+tick+F+tick+"\n(tree "+tick+"ebc11e05eb0015ae5be58ca85ed764e06f4386be"+tick+"). All ten recorded\ncommands returned zero: positive authority/Root/corpus checks, 65 authority,\nRoot and V5-runner controls, 43 source-integrity controls, repository links,\nCargo formatting, and default/all-features locked dependency graphs, including\npreflight. Each command recorded the complete physical source before and after.\nThe 108 controls belong to this exact F commit; they are not new native tests.\n\nThe original outer driver returned 1 and retained all_gates_passed=false:\nits parser incorrectly required the entire unittest log to end at OK. The 43\nsource-integrity methods each passed and their single OK summary was followed\nby six expected fixture receipt JSON lines. A separate derived qualification\nhash-binds and rereads those original bytes, the 65/43 exact test inventories\nand all ten command/source receipts. It verifies 108 controls without rerunning\nthem or changing the original failed aggregate receipt. Both observations and\nthe corrected reader are retained in the final source evidence.\n\nThe [final source evidence](ai395/final-source/README.md) preserves the raw\ncommands and the initially failed evidence integration plus its successful\ncontinuation. This evidence-only successor keeps trillionnium, formal and\nscripts/ci bytes identical to the actual native source "+tick+NATIVE+tick+".\nIts separate final identity, restricted corpus delta and source/link checks are\nrecorded by the publication process; those checks do not relabel the F control\nrun or the 129 native Rust methods. Status remains **HOLD**.\n\nThe first evidence-child admission stopped before any repository mutation because\nan optional transient Cargo lock file was absent. Its clean F snapshot, actual\nexit 1, inputs, driver and complete output are preserved in the\n[admission failure record](ai395/final-source/failed-admission-v2-README.md).\nAfter all native/source owners released the checkout, the continuation used a\ndedicated outside integration lock; no build or test was rerun.\n"
  with (R/readme).open("a") as f:f.write(addition)
  old=json.loads((R/C).read_bytes());m=json.loads((R/C).read_bytes())
  assert len(old["pinned_blobs"])==1593 and len(old["required_paths"])==1499
  changes=[]
  for rel in sorted(newfiles|{readme}):
   b=(R/rel).read_bytes();prior=m["pinned_blobs"].get(rel)
   if rel in newfiles:assert prior is None
   else:assert prior==g("prior-readme-blob",["rev-parse",F+":"+rel]).decode().strip()
   m["pinned_blobs"][rel]=blob(b)
   if rel not in m["required_paths"]:m["required_paths"].append(rel)
   changes.append({"path":rel,"previous_pin":prior,"new_pin":blob(b),"bytes":len(b),"sha256":sha(b)})
  assert {k:v for k,v in old.items() if k not in {"pinned_blobs","required_paths"}}=={k:v for k,v in m.items() if k not in {"pinned_blobs","required_paths"}}
  assert all(m["pinned_blobs"][k]==v for k,v in old["pinned_blobs"].items() if k!=readme)
  assert m["required_paths"][:len(old["required_paths"])]==old["required_paths"]
  assert len(m["pinned_blobs"])==1593+len(newfiles) and len(m["required_paths"])==1499+len(newfiles)
  (R/C).write_text(json.dumps(m,indent=2,sort_keys=True)+"\n")
  jout(O/"reviewed-corpus-delta.json",{"parent":F,"actual_new_files":len(newfiles),"reviewed_changes":changes,"unrelated_pins_and_policy_unchanged":True,"old_required_prefix_preserved":True})
  allowed=newfiles|{readme,C}
  g("runtime-before",["diff","--exit-code",NATIVE,"--","trillionnium","formal","scripts/ci"])
  for n,d in enumerate(["ai395/root-native","ai395/sqlite","ai395/incentives","ai395/final-integration","liveness"]):
   g("preserved-evidence-"+str(n),["diff","--exit-code",F,"--",P+"/"+d])
  run("preflight-before-add",["bash","scripts/project-preflight.sh"])
  g("add-exact-files",["add","--force","--",*sorted(allowed)])
  assert set(g("staged-paths",["diff","--cached","--name-only"]).decode().splitlines())==allowed
  g("unstaged-before-commit",["diff","--exit-code"])
  authored={readme,C,DEST+"/admission-driver.py",DEST+"/admission-inputs.json"}
  authored|={x for x in newfiles if x.endswith(".md")}
  g("authored-whitespace",["diff","--cached","--check","--",*sorted(authored)])
  index=g("index-payloads",["ls-files","--stage","-z","--",*sorted(allowed)])
  for row in index.rstrip(b"\0").split(b"\0"):
   meta,path=row.split(b"\t",1);mode,oid,stage_no=meta.split()
   assert mode in (b"100644",b"100755") and stage_no==b"0" and blob((R/path.decode()).read_bytes())==oid.decode()
  for rel,v in expected.items():
   b=(dest/rel).read_bytes();assert len(b)==v["bytes"] and sha(b)==v["sha256"]
  run("preflight-before-commit",["bash","scripts/project-preflight.sh"])
  g("commit",["-c","user.name=Codex","-c","user.email=codex@openai.com","commit","-s","-m","test(security): archive exact committed source gates and integration provenance"])
  head=g("head-after",["rev-parse","HEAD"]).decode().strip()
  tree=g("tree-after",["rev-parse","HEAD^{tree}"]).decode().strip()
  assert g("clean-after",["status","--porcelain=v1"]).strip()==b""
  assert g("parent-after",["rev-parse","HEAD^"]).decode().strip()==F
  g("runtime-after",["diff","--exit-code",NATIVE,head,"--","trillionnium","formal","scripts/ci"])
  after=verify("head",head,root=R);jout(O/"source-child-after.json",after)
  report={"schema":"trnm-final-source-evidence-admission-v1","head":head,"tree":tree,"parent":F,"native_source":NATIVE,"full_source_gate_receipt_sha256":sha(rb),"physical_source":after,"changed_paths":len(allowed),"stage_payload_files":len(expected),"corpus_pins":len(m["pinned_blobs"]),"required_paths":len(m["required_paths"]),"F_actual_commands_qualified":True,"original_F_wrapper_exit_code":1,"original_F_wrapper_all_gates_passed":False,"derived_qualification_sha256":sha(qualified_raw),"F_raw_controls_verified":108,"F_controls_not_relabelled_as_E_execution":True,"native_reexecuted":False,"runtime_formal_ci_identical":True,"child_source_gates_pending":True,"github_written":False,"status":"HOLD","commands":records,"utc":now()}
  jout(O/"result.json",report)
  print(json.dumps({k:v for k,v in report.items() if k!="commands"}),flush=True)
 except BaseException as e:
  snap={}
  for name,args in [("head",["rev-parse","HEAD"]),("status",["status","--porcelain=v1"]),("staged",["diff","--cached","--name-only"])]:
   try:snap[name]=g("failure-"+name,args).decode()
   except BaseException as se:snap[name]={"error":repr(se)}
  failure={"schema":"trnm-evidence-child-admission-failure-v1","error":repr(e),"traceback":traceback.format_exc(),"commands":records,"readonly_snapshot":snap,"automatic_mutation_retry":False,"status":"HOLD"}
  jout(O/"failure.json",failure);print(json.dumps({k:v for k,v in failure.items() if k!="commands"}),flush=True);raise
 finally:
  if lockfd is not None:fcntl.flock(lockfd,fcntl.LOCK_UN);os.close(lockfd)
if __name__=="__main__":main()
