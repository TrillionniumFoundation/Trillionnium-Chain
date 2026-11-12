#!/usr/bin/env python3
"""Reconcile a completed raw-log whitespace failure without rewriting evidence."""
from pathlib import Path
import datetime,fcntl,hashlib,json,os,re,signal,stat,subprocess,sys,time,traceback
R=Path("/home/qq/chain-system-security-20261112-306929")
S=Path("/home/qq/chain-system-security-final-integration-20261112-306929")
P="evidence/chain-system-security-20261111-306929"
C="config/pon/pq-cross-branch-corpus-v1.json"
PLAN="docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
NATIVE="bac6b7659bd7e2d633e25c2da0add60f6a10c7fb"
PREVIOUS="98cb32df65d11cf6124e47b5246ab4854f137bb1"
OLD=S/"integrate-native-F-v1"
O=S/"integrate-native-F-continuation-v1"
def sha(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def write_new(path,b):
 with path.open("xb") as f:f.write(b)
def jout(path,obj):write_new(path,(json.dumps(obj,indent=2,sort_keys=True)+"\n").encode())
def main():
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
 def fresh_payloads(files):
  for rel,v in files.items():
   q=R/rel;st=q.lstat();assert stat.S_ISREG(st.st_mode),rel
   b=q.read_bytes();assert len(b)==v["bytes"] and sha(b)==v["sha256"],rel
 try:
  assert g("head-before",["rev-parse","HEAD"]).decode().strip()==PREVIOUS
  run("preflight-before",["bash","scripts/project-preflight.sh"])
  g("unstaged-before",["diff","--exit-code"])
  lockfd=os.open(R/"trillionnium/target/debug/.cargo-lock",os.O_RDWR|os.O_NOFOLLOW)
  fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  raw=(S/"integration-inputs-v1.json").read_bytes()
  assert len(raw)==26303 and sha(raw)=="ddd5583a0da71f3fee51d1bd7a023a13f92a4530dbca7a1093e34ee721ab49e7"
  inputs=json.loads(raw)
  assert inputs["native_source"]==NATIVE and inputs["previous_candidate"]==PREVIOUS
  assert inputs["native_owners_released"] is True
  assert inputs["actual_native_passed"]=={"root_unique":66,"root_executions":80,"sqlite":32,"incentives":31}
  assert inputs["workspace_strict_clippy_passed"] is True and inputs["sqlite_strict_clippy_passed"] is True
  initial_driver=(S/"integrate-native-F-v2.py").read_bytes()
  assert sha(initial_driver)=="7c17ee42a33e1c3c90d0a3a85a7c938f0bd386b5ce6f983164cd0647d377b056"
  draft_bytes=Path(inputs["authoring_drafts_path"]).read_bytes()
  assert sha(draft_bytes)==inputs["authoring_drafts_sha256"]=="d6ebf1435d87073786ea03d1d48812a9a15d56b1c18afd6387d6a2f0e8d51fc5"
  drafts=json.loads(draft_bytes)
  expected_raw={}
  for kind,item in inputs["stages"].items():
   for rel,v in item["files"].items():expected_raw[P+"/ai395/"+kind+"/"+rel]=v
  assert len(expected_raw)==182
  fresh_payloads(expected_raw)
  own=P+"/ai395/final-integration"
  ownfiles={own+"/"+n for n in ["integration-inputs.json","integration-driver.py","native-summary.json"]}
  docs={P+"/README.md",PLAN}
  allowed=set(expected_raw)|ownfiles|docs|{C}
  assert len(allowed)==188
  staged=set(g("staged-before",["diff","--cached","--name-only"]).decode().splitlines())
  assert staged==allowed
  assert staged==set((OLD/"staged-paths.stdout").read_text().splitlines())
  index=g("index-before",["ls-files","--stage","-z","--",*sorted(allowed)])
  idx={}
  for line in index.rstrip(b"\0").split(b"\0"):
   meta,path=line.split(b"\t",1);mode,oid,stage=meta.split()
   assert mode==b"100644" and stage==b"0"
   idx[path.decode()]=oid.decode()
  assert set(idx)==allowed
  assert all(blob((R/rel).read_bytes())==oid for rel,oid in idx.items())
  assert (R/own/"integration-inputs.json").read_bytes()==raw
  assert (R/own/"integration-driver.py").read_bytes()==initial_driver
  summary=json.loads((R/own/"native-summary.json").read_bytes())
  assert summary["native_source"]==NATIVE and summary["distinct_native_methods"]==129
  assert {v["path"]:{"bytes":v["bytes"],"sha256":v["sha256"]} for v in summary["published_artifact_digests"]}==expected_raw
  assert (R/P/"README.md").read_text()==drafts["readme"]
  oldplan=g("old-plan",["show",PREVIOUS+":"+PLAN]).decode()
  marker="**V5 witnessed provider readback continuation,"
  assert oldplan.count(marker)==1
  assert (R/PLAN).read_text()==drafts["plan_prefix"]+oldplan[oldplan.index(marker):]
  base=json.loads(g("base-corpus",["show",PREVIOUS+":"+C]))
  current=json.loads((R/C).read_bytes())
  assert len(base["pinned_blobs"])==1406 and len(base["required_paths"])==1312
  assert len(current["pinned_blobs"])==1591 and len(current["required_paths"])==1497
  assert {k:v for k,v in current.items() if k not in {"pinned_blobs","required_paths"}}=={k:v for k,v in base.items() if k not in {"pinned_blobs","required_paths"}}
  assert set(current["pinned_blobs"])==set(base["pinned_blobs"])|set(expected_raw)|ownfiles
  assert current["required_paths"][:len(base["required_paths"])]==base["required_paths"]
  assert set(current["required_paths"])==set(base["required_paths"])|set(expected_raw)|ownfiles
  assert len(current["required_paths"])==len(set(current["required_paths"]))
  for rel,v in base["pinned_blobs"].items():
   if rel not in docs:assert current["pinned_blobs"][rel]==v,rel
  for rel in allowed-{C}:assert current["pinned_blobs"][rel]==idx[rel],rel
  initial_commands=json.loads((OLD/"commands.json").read_bytes())
  assert initial_commands[-1]["name"]=="staged-whitespace" and initial_commands[-1]["exit_code"]==2
  assert not (OLD/"result.json").exists() and (OLD/"failure.json").is_file()
  diagnostic=(OLD/"staged-whitespace.stdout").read_bytes()
  assert len(diagnostic)==32217 and sha(diagnostic)=="6dbddb8dad837703e61f818b8b24fb423c94d7f652a0e639ed1eb64d3a363d25"
  observed=g("reconcile-original-whitespace",["diff","--cached","--check"],ok=(2,))
  assert observed==diagnostic
  rows={}
  pattern=rb"^(evidence/[^:\n]+):([0-9]+): (trailing whitespace\.|new blank line at EOF\.)$"
  for match in re.finditer(pattern,diagnostic,re.M):
   path=match[1].decode();ln=int(match[2]);kind=match[3].decode()
   assert path in expected_raw and path.endswith(".log"),path
   rawlog=(R/path).read_bytes();lines=rawlog.split(b"\n")
   assert 1<=ln<=len(lines)
   if kind=="trailing whitespace.":
    assert lines[ln-1].endswith(b"\r") and not lines[ln-1][:-1].endswith((b" ",b"\t",b"\r")),path
    assert rawlog.count(b"\r")==rawlog.count(b"\r\n"),path
   else:
    assert path.startswith(P+"/ai395/sqlite/records/") and rawlog.endswith(b"\n\n"),path
    assert all(x==b"" for x in lines[ln-1:]),path
   rows.setdefault(path,{"path":path,**expected_raw[path],"diagnostics":[]})["diagnostics"].append({"line":ln,"kind":kind})
  assert len(rows)==23 and sum(len(v["diagnostics"]) for v in rows.values())==71
  assert sum(d["kind"]=="trailing whitespace." for v in rows.values() for d in v["diagnostics"])==52
  assert sum(d["kind"]=="new blank line at EOF." for v in rows.values() for d in v["diagnostics"])==19
  assert len([v for v in rows.values() if v["diagnostics"][0]["kind"]=="trailing whitespace."])==4
  g("authored-whitespace-before",["diff","--cached","--check","--",*sorted(allowed-set(rows))])
  review={"schema":"trnm-raw-evidence-whitespace-review-v1","native_source":NATIVE,"precommit_head":PREVIOUS,"initial_operation":str(OLD),"initial_driver_sha256":sha(initial_driver),"initial_staged_whitespace_exit":2,"initial_diagnostic_bytes":len(diagnostic),"initial_diagnostic_sha256":sha(diagnostic),"classified_diagnostics":71,"pty_crlf_diagnostics":52,"pty_crlf_files":4,"native_eof_blank_diagnostics":19,"native_eof_blank_files":19,"raw_files":list(sorted(rows.values(),key=lambda x:x["path"])),"raw_bytes_preserved":True,"entire_staged_set_reconciled_with_completed_failed_operation":True,"index_equals_physical_bytes":True,"unclassified_paths":0,"authored_file_whitespace_check":"git diff --cached --check -- <all staged paths except these exact 23 hash-bound raw logs>","repository_git_configuration_unchanged":True,"repository_precommit_prepush_hooks_preserved":True,"native_tests_repeated":False,"reason":"The parent-added generic whitespace check flags CRLF emitted by PTYs and original Rust output final blank lines. These are immutable observations, not authored source. Keep raw bytes and the initial failure, hash-check each payload, and apply the unmodified whitespace checker to every other staged path.","utc":now()}
  new_driver=own+"/integration-continuation.py"
  new_review=own+"/raw-log-whitespace-review.json"
  write_new(R/new_driver,Path(__file__).read_bytes())
  jout(R/new_review,review)
  appendix="\n## Raw log formatting preservation\n\nThe first evidence integration stopped at a parent-added generic whitespace\ncheck before committing. Its 71 diagnostics concern exactly four original PTY\nCRLF logs and nineteen original Rust logs with a final blank line. All raw bytes\nand their manifest hashes remain unchanged. The continuation reconciled the\nstaged set and all 182 published payloads, classified the exact diagnostic\nbytes, and applied the original whitespace check to every other staged file.\nThe repository hooks and Git whitespace settings were not changed. See the\n[raw log review](ai395/final-integration/raw-log-whitespace-review.json) and\n[continuation driver](ai395/final-integration/integration-continuation.py).\nThe failed operation and its command receipts are retained with the final\nsource-gate provenance; this formatting observation is not a native test failure.\n"
  with (R/P/"README.md").open("a") as f:f.write(appendix)
  changed_now={new_driver,new_review,P+"/README.md"}
  for rel in sorted(changed_now):
   current["pinned_blobs"][rel]=blob((R/rel).read_bytes())
   if rel not in current["required_paths"]:current["required_paths"].append(rel)
  (R/C).write_text(json.dumps(current,indent=2,sort_keys=True)+"\n")
  allowed|={new_driver,new_review}
  assert len(allowed)==190 and len(current["pinned_blobs"])==1593 and len(current["required_paths"])==1499
  fresh_payloads(expected_raw)
  g("runtime-before-add",["diff","--exit-code",NATIVE,"--","trillionnium","formal","scripts/ci"])
  for i,olddir in enumerate(["evidence/pq-root-witness-provider-readback-20261112","evidence/sqlite-open-boundary-20261112","evidence/chain-incentive-counterexamples-20261112"]):
   g("original-evidence-"+str(i),["diff","--exit-code",PREVIOUS,"--",olddir])
  run("preflight-before-add",["bash","scripts/project-preflight.sh"])
  g("add-continuation",["add","--force","--",*sorted(changed_now|{C})])
  assert set(g("staged-final",["diff","--cached","--name-only"]).decode().splitlines())==allowed
  g("authored-whitespace-final",["diff","--cached","--check","--",*sorted(allowed-set(rows))])
  g("unstaged-final",["diff","--exit-code"])
  run("preflight-before-commit",["bash","scripts/project-preflight.sh"])
  g("commit",["-c","user.name=Codex","-c","user.email=codex@openai.com","commit","-s","-m","test(security): retain frozen-source native and incentive verification"])
  head=g("head-after",["rev-parse","HEAD"]).decode().strip()
  tree=g("tree-after",["rev-parse","HEAD^{tree}"]).decode().strip()
  assert g("clean-after",["status","--porcelain=v1"]).strip()==b""
  g("runtime-after",["diff","--exit-code",NATIVE,head,"--","trillionnium","formal","scripts/ci"])
  fresh_payloads(expected_raw)
  sys.path.insert(0,str(R/"scripts/ci"))
  from verify_ci_source import verify
  source=verify("head",head,root=R)
  jout(O/"source-after-integration.json",source)
  result={"schema":"trnm-native-evidence-integration-continuation-result-v1","head":head,"tree":tree,"previous_head":PREVIOUS,"native_source":NATIVE,"source_verified":source,"runtime_formal_ci_identical":True,"staged_paths":len(allowed),"corpus_pins":len(current["pinned_blobs"]),"required_paths":len(current["required_paths"]),"raw_payloads_unchanged":182,"classified_raw_format_paths":23,"original_failed_operation_retained":str(OLD),"native_tests_repeated":False,"source_gates_pending":True,"github_written":False,"status":"HOLD","commands":records,"utc":now()}
  jout(O/"result.json",result)
  print(json.dumps({k:v for k,v in result.items() if k not in {"commands"}}),flush=True)
 except BaseException as e:
  snapshot={}
  for label,args in [("head",["rev-parse","HEAD"]),("status",["status","--porcelain=v1"]),("staged",["diff","--cached","--name-only"])]:
   try:snapshot[label]=g("failure-state-"+label,args).decode()
   except BaseException as se:snapshot[label]={"error":repr(se)}
  failure={"schema":"trnm-native-evidence-integration-continuation-failure-v1","error":repr(e),"traceback":traceback.format_exc(),"commands":records,"readonly_repository_snapshot":snapshot,"automatic_mutation_retry":False,"github_written":False,"status":"HOLD","utc":now()}
  jout(O/"failure.json",failure)
  print(json.dumps({k:v for k,v in failure.items() if k not in {"commands"}}),flush=True)
  raise
 finally:
  if lockfd is not None:fcntl.flock(lockfd,fcntl.LOCK_UN);os.close(lockfd)
if __name__=="__main__":main()
