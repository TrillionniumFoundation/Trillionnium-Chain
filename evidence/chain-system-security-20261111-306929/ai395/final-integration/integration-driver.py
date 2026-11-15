#!/usr/bin/env python3
"""Integrate verified evidence after exclusive native owners have released the checkout."""
from pathlib import Path
import argparse,datetime,fcntl,hashlib,json,os,shutil,stat,subprocess,sys,traceback
R=Path("/home/qq/chain-system-security-20261112-306929")
S=Path("/home/qq/chain-system-security-final-integration-20261112-306929")
B=S/"candidate-objects.git"
NATIVE="bac6b7659bd7e2d633e25c2da0add60f6a10c7fb"
PREVIOUS="98cb32df65d11cf6124e47b5246ab4854f137bb1"
PREFIX="evidence/chain-system-security-20261111-306929"
PLAN="docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
CORPUS="config/pon/pq-cross-branch-corpus-v1.json"
def sha(data):return hashlib.sha256(data).hexdigest()
def blob(data):return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument("--inputs",type=Path,required=True);p.add_argument("--inputs-sha256",required=True);a=p.parse_args()
 raw=a.inputs.read_bytes();assert sha(raw)==a.inputs_sha256
 inputs=json.loads(raw);assert inputs["schema"]=="trnm-final-native-integration-inputs-v1"
 assert inputs["native_source"]==NATIVE and inputs["previous_candidate"]==PREVIOUS
 assert inputs["native_owners_released"] is True
 assert inputs["actual_native_passed"]=={"root_unique":66,"root_executions":80,"sqlite":32,"incentives":31}
 assert inputs["workspace_strict_clippy_passed"] is True and inputs["sqlite_strict_clippy_passed"] is True
 O=S/"integrate-native-F-v1";O.mkdir()
 records=[];lockfd=None
 def out(name,value):
  with (O/name).open("x") as f:json.dump(value,f,indent=2);f.write("\n")
 def run(name,args):
  start=datetime.datetime.now(datetime.timezone.utc).isoformat()
  q=subprocess.run(args,cwd=R,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
  (O/(name+".stdout")).write_bytes(q.stdout);(O/(name+".stderr")).write_bytes(q.stderr)
  row={"name":name,"argv":args,"exit_code":q.returncode,"started_utc":start,"stdout_sha256":sha(q.stdout),"stderr_sha256":sha(q.stderr)}
  records.append(row);(O/"commands.json").write_text(json.dumps(records,indent=2)+"\n")
  if q.returncode:raise RuntimeError(name+" exit "+str(q.returncode))
  return q.stdout.decode().strip()
 try:
  assert run("head-before",["git","rev-parse","HEAD"])==NATIVE
  assert run("clean-before",["git","status","--porcelain=v1"])==""
  run("preflight-before",["bash","scripts/project-preflight.sh"])
  lockfd=os.open(R/"trillionnium/target/debug/.cargo-lock",os.O_RDWR|os.O_NOFOLLOW)
  fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  sys.path.insert(0,str(R/"scripts/ci"))
  from verify_ci_source import verify
  out("native-checkout-before.json",verify("head",NATIVE,root=R))
  run("import-retained-source",["git","-c","protocol.file.allow=always","fetch","--no-tags","--no-recurse-submodules","--no-write-fetch-head",str(B),"refs/source/final"])
  run("imported-native-byte-equality",["git","diff","--exit-code",NATIVE,PREVIOUS,"--","trillionnium","formal","scripts/ci"])
  run("fast-forward-retained-evidence",["git","merge","--ff-only",PREVIOUS])
  assert run("clean-after-import",["git","status","--porcelain=v1"])==""
  run("preflight-after-import",["bash","scripts/project-preflight.sh"])
  old_corpus=(R/CORPUS).read_bytes();m=json.loads(old_corpus);old=json.loads(old_corpus)
  assert len(m["pinned_blobs"])==1406 and len(m["required_paths"])==1312
  expected_paths=set();copied=[]
  assert set(inputs["stages"])=={"root-native","sqlite","incentives"}
  for kind,item in sorted(inputs["stages"].items()):
   src=Path(item["directory"]);assert src.is_dir() and not src.is_symlink()
   dst=R/PREFIX/"ai395"/kind;assert not dst.exists();dst.mkdir(parents=True)
   actual={}
   for q in src.rglob("*"):
    if q.is_dir():assert not q.is_symlink();continue
    st=q.lstat();assert stat.S_ISREG(st.st_mode)
    rel=q.relative_to(src).as_posix();assert not rel.startswith("/") and ".." not in Path(rel).parts
    b=q.read_bytes();assert len(b)<=4194304
    actual[rel]={"bytes":len(b),"sha256":sha(b)}
   assert actual==item["files"],kind
   for rel,v in sorted(actual.items()):
    source=src/rel;dest=dst/rel;dest.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(source,dest)
    b=dest.read_bytes();assert len(b)==v["bytes"] and sha(b)==v["sha256"]
    rp=dest.relative_to(R).as_posix();expected_paths.add(rp);copied.append({"path":rp,**v})
  drafts=Path(inputs["authoring_drafts_path"])
  assert drafts.parent.resolve()==S.resolve() and drafts.is_file() and not drafts.is_symlink()
  db=drafts.read_bytes();assert sha(db)==inputs["authoring_drafts_sha256"]
  d=json.loads(db);assert d["native_source"]==NATIVE
  readme=R/PREFIX/"README.md";readme.write_text(d["readme"])
  plan=R/PLAN;old_plan=plan.read_text();marker="**V5 witnessed provider readback continuation,"
  assert old_plan.startswith("**System security combined source, 2026-11-12 UTC") and old_plan.count(marker)==1
  plan.write_text(d["plan_prefix"]+old_plan[old_plan.index(marker):])
  own=R/PREFIX/"ai395/final-integration";own.mkdir()
  (own/"integration-inputs.json").write_bytes(raw)
  driver=Path(__file__).read_bytes();(own/"integration-driver.py").write_bytes(driver)
  summary={"schema":"trnm-system-security-native-summary-20261112-v1","native_source":NATIVE,"native_tree":"371c3f55de7940e276496efe2008b537ba4d8268","runtime_composition":"813620f387199bef3eae2493e2af07c70444db58","distinct_native_methods":129,"root_distinct":66,"root_method_executions":80,"root_duplicate_provider_methods":14,"sqlite_distinct":32,"incentive_distinct":31,"python_pinned_oracle":8,"python_pinned_native_differentials":5,"receipt_mutations_rejected":6,"workspace_all_targets_all_features_strict_clippy_passed":True,"sqlite_four_package_strict_clippy_passed":True,"source_tracked_entries":28327,"source_tracked_bytes":2578801275,"later_evidence_commit_is_not_native_execution_source":True,"service_campaign_rerun":False,"v4_source_grouping_repair_implemented":False,"status":"HOLD","production_activation":False,"whole_chain_security_qualified":False,"independent_custody_verified":False,"actual_external_effects_verified":False,"native_m15_production_integration_complete":False,"model_generalization_qualified":False,"permissionless_economic_security_qualified":False,"published_artifact_digests":copied}
  (own/"native-summary.json").write_text(json.dumps(summary,indent=2)+"\n")
  for q in own.iterdir():expected_paths.add(q.relative_to(R).as_posix())
  changed_docs={PREFIX+"/README.md",PLAN}
  review=[]
  for rel in sorted(expected_paths|changed_docs):
   q=R/rel;b=q.read_bytes();assert len(b)<=4194304
   oldpin=m["pinned_blobs"].get(rel)
   if rel in expected_paths:assert oldpin is None,rel
   else:
    previous=run("old-document-blob-"+str(len(review)),["git","rev-parse",PREVIOUS+":"+rel])
    assert oldpin==previous
   m["pinned_blobs"][rel]=blob(b)
   if rel not in m["required_paths"]:m["required_paths"].append(rel)
   review.append({"path":rel,"previous_pin":oldpin,"new_blob":blob(b),"bytes":len(b),"sha256":sha(b)})
  assert all(m[k]==old[k] for k in old if k not in {"pinned_blobs","required_paths"})
  assert all(v==old["pinned_blobs"][k] for k,v in m["pinned_blobs"].items() if k in old["pinned_blobs"] and k not in changed_docs)
  assert m["required_paths"][:len(old["required_paths"])]==old["required_paths"]
  (R/CORPUS).write_text(json.dumps(m,indent=2,sort_keys=True)+"\n")
  out("reviewed-corpus-pin-update.json",{"changed":review,"preserved_previous_pin_count":1406-len(changed_docs),"previous_required_paths_preserved":1312,"new_pins":len(m["pinned_blobs"]),"new_required_paths":len(m["required_paths"]),"all_other_fields_unchanged":True})
  allowed=expected_paths|changed_docs|{CORPUS}
  run("runtime-byte-equality",["git","diff","--exit-code",NATIVE,"--","trillionnium","formal","scripts/ci"])
  for olddir in ["evidence/pq-root-witness-provider-readback-20261112","evidence/sqlite-open-boundary-20261112","evidence/chain-incentive-counterexamples-20261112"]:
   run("preserved-"+olddir.split("/")[-1],["git","diff","--exit-code",PREVIOUS,"--",olddir])
  run("preflight-before-add",["bash","scripts/project-preflight.sh"])
  run("add-exact-owned-files",["git","add","--force","--",*sorted(allowed)])
  actual=set(run("staged-paths",["git","diff","--cached","--name-only"]).splitlines());assert actual==allowed,(actual^allowed)
  run("staged-whitespace",["git","diff","--cached","--check"])
  run("preflight-before-commit",["bash","scripts/project-preflight.sh"])
  run("commit",["git","-c","user.name=Codex","-c","user.email=codex@openai.com","commit","-s","-m","test(security): retain frozen-source native and incentive verification"])
  head=run("head-after",["git","rev-parse","HEAD"]);tree=run("tree-after",["git","rev-parse","HEAD^{tree}"])
  assert run("clean-after",["git","status","--porcelain=v1"])==""
  run("committed-runtime-byte-equality",["git","diff","--exit-code",NATIVE,head,"--","trillionnium","formal","scripts/ci"])
  source=verify("head",head,root=R);out("source-after-integration.json",source)
  result={"schema":"trnm-final-native-evidence-integration-result-v1","head":head,"tree":tree,"previous_head":PREVIOUS,"native_source":NATIVE,"runtime_formal_ci_identical":True,"source_verified":source,"changed_files":len(allowed),"corpus_pins":len(m["pinned_blobs"]),"required_paths":len(m["required_paths"]),"native_tests_repeated":False,"source_gates_pending":True,"github_written":False,"status":"HOLD","commands":records,"utc":datetime.datetime.now(datetime.timezone.utc).isoformat()}
  out("result.json",result);print(json.dumps(result),flush=True)
 except BaseException as e:
  failure={"schema":"trnm-final-native-evidence-integration-failure-v1","error":repr(e),"traceback":traceback.format_exc(),"commands":records,"github_written":False,"status":"HOLD"}
  out("failure.json",failure);print(json.dumps(failure),flush=True);raise
 finally:
  if lockfd is not None:fcntl.flock(lockfd,fcntl.LOCK_UN);os.close(lockfd)
if __name__=="__main__":main()
