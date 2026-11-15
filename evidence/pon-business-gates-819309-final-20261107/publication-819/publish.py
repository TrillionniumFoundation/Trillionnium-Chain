#!/usr/bin/env python3
import pathlib,subprocess,json,hashlib,time,sys,traceback
BASE=pathlib.Path("/home/qian-qi/chain-throughput-local-admin-20261107")
ROOT=BASE/"work-final-business-20261107"
OUT=BASE/"publication-819309f-20261107"
H="819309fd312298e099642e1253b1d4ba07113e98"
TREE="f9d63abb9e2931fd78e26ccb87e3a7955068f267"
BRANCH="fix/chain-six-axis-performance-20261103"
EXPECTED_REMOTE="04bbc81e4aad9b29fef29385d3262297e2cb17df"
GH="/usr/bin/gh"
REPO="TrillionniumFoundation/Trillionnium-Chain"
record={"schema":"trnm-profhepta-final-candidate-publication-v1","head":H,"tree":TREE,"branch":BRANCH,"commands":[],"push_attempted":False,"push_exit_zero":False,"publication_verified":False,"full_native_body_pass_claimed":False,"business_gate_pass_claimed":False}
def digest(p):
 with pathlib.Path(p).open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def file_record(p):
 p=pathlib.Path(p);return {"path":str(p),"bytes":p.stat().st_size,"sha256":digest(p)}
def save():
 tmp=OUT/"receipt.json.tmp";tmp.write_text(json.dumps(record,indent=2)+"\n");tmp.replace(OUT/"receipt.json")
def run(label,argv,timeout=600,check=True):
 p=subprocess.run(argv,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
 path=OUT/(label+".log")
 with path.open("xb") as f:f.write(p.stdout)
 row={"label":label,"argv":argv,"exit_code":p.returncode,"log":file_record(path)}
 record["commands"].append(row);save()
 print(json.dumps({"label":label,"exit_code":p.returncode,"log_bytes":len(p.stdout)}),flush=True)
 if check and p.returncode:raise RuntimeError(label+" exit "+str(p.returncode))
 return p.returncode,p.stdout.decode(errors="replace").rstrip("\n")
def output(label,args,timeout=600):return run(label,args,timeout)[1]
def gh(label,endpoint,jq=None):
 args=[GH,"api",endpoint]
 if jq:args+=["--jq",jq]
 return json.loads(output(label,args,180))
def authority(label):
 who=gh(label+"-identity","user","{login,id}")
 repository=gh(label+"-repository","repos/"+REPO,"{id,full_name,default_branch,permissions}")
 assert who=={"login":"ProfHepta","id":102159240},who
 assert repository["id"]==1323087357 and repository["full_name"]==REPO
 assert repository["permissions"]["admin"] and repository["permissions"]["push"]
 record[label]={"identity":who,"repository":repository};save()
 return who
def ref(label,name):return gh(label,"repos/"+REPO+"/git/ref/heads/"+name)["object"]["sha"]
def main():
 if (OUT/"receipt.json").exists():raise RuntimeError("A publication receipt already exists; reconcile its durable job, do not run a new attempt.")
 record["started_utc"]=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime());record["driver"]=file_record(__file__);save()
 try:
  output("preflight",["/usr/bin/bash","scripts/project-preflight.sh"])
  assert output("local-head-before",["git","rev-parse","HEAD"])==H
  assert output("local-tree-before",["git","rev-parse","HEAD^{tree}"])==TREE
  assert output("local-status-before",["git","status","--porcelain=v1"])==""
  assert output("origin",["git","remote","get-url","origin"])=="https://github.com/"+REPO+".git"
  identity=output("local-commit-identity",["git","show","--no-patch","--format=%an%n%ae%n%cn%n%ce",H])
  assert identity.splitlines()==["ProfHepta","102159240+ProfHepta@users.noreply.github.com"]*2
  sp=BASE/"final-source-validation-20261107"/H/"summary.json"
  source=json.loads(sp.read_text())
  assert source["expected_head"]==H and source["completed"] and source["all_controls_passed"]
  assert source["observed_test_methods"]==source["passed_test_methods"]==source["expected_test_methods"]==666
  assert source["source_before_verified"] and source["source_after_verified"] and source["source_before_after_equal"]
  assert not source["failures"]
  np=BASE/"final-native-validation-20261107/runs"/H/"prepush/manifest.json"
  native=json.loads(np.read_text())
  assert native["commit"]==H and native["tree"]==TREE and native["result"]=="PREPUSH_NATIVE_CHECKS_PASS"
  assert native["source_receipts"]["byte_identical"] and native["failed_step"] is None
  steps={x["label"]:x for x in native["steps"]}
  for label in ("workspace-strict-clippy","node-no-run"):
   s=steps[label]
   assert s["effective_exit_code"]==0 and not s["timed_out"] and s["source_unchanged"]
   assert s["native_status"]=="command_succeeded" and s["native_exit_code"]==0
  assert native["expected_counts"]["integration_targets"]==65 and native["expected_counts"]["cell_tests"]==12
  record["prepush_validation"]={"source_controls":file_record(sp),"source_control_methods_passed":666,"native_prepush":file_record(np),"native_body_tests_executed_by_prepush":False,"strict_workspace_clippy_passed":True,"actual_inventory":native["expected_counts"]};save()
  output("full-source-before-push",["/usr/bin/python3","scripts/ci/verify_ci_source.py","--kind","head","--expected-head",H,"--output",str(OUT/"source-before-push.json")])
  authority("before")
  old=ref("remote-candidate-before",BRANCH);main_before=ref("remote-main-before","main")
  record["remote_before"]=old;record["main_before"]=main_before;save()
  assert old==EXPECTED_REMOTE,"Remote advanced since reviewed merge; stop before push and preserve the new work."
  output("remote-is-ancestor",["git","merge-base","--is-ancestor",old,H])
  output("preflight-before-push",["/usr/bin/bash","scripts/project-preflight.sh"])
  record["push_attempted"]=True;save()
  code,_=run("push",["git","-c","credential.helper=","-c","credential.helper=!/usr/bin/gh auth git-credential","push","--porcelain","origin",H+":refs/heads/"+BRANCH],timeout=1200,check=False)
  record["push_exit_zero"]=code==0;save()
  after=ref("remote-candidate-after",BRANCH);main_after=ref("remote-main-after","main")
  commit=gh("remote-commit-tree","repos/"+REPO+"/git/commits/"+H,"{sha,tree:.tree.sha,parents:[.parents[].sha]}")
  authority("after")
  record["remote_after"]=after;record["main_after"]=main_after;record["remote_commit"]=commit
  record["main_unchanged_observed"]=main_before==main_after
  record["publication_verified"]=after==H and commit["sha"]==H and commit["tree"]==TREE
  output("full-source-after-push",["/usr/bin/python3","scripts/ci/verify_ci_source.py","--kind","head","--expected-head",H,"--output",str(OUT/"source-after-push.json")])
  record["source_before_after_push_equal"]=(OUT/"source-before-push.json").read_bytes()==(OUT/"source-after-push.json").read_bytes()
  assert output("local-head-after",["git","rev-parse","HEAD"])==H
  assert output("local-status-after",["git","status","--porcelain=v1"])==""
  assert record["source_before_after_push_equal"]
  assert code==0 and record["publication_verified"],"Push or remote verification did not complete successfully"
  record["result"]="PUBLISHED_EXISTING_CANDIDATE_BUSINESS_GATES_HOLD"
  return 0
 except BaseException as error:
  record["result"]="PUBLICATION_INCOMPLETE_RETAINED";record["error"]=repr(error)
  record["traceback"]=traceback.format_exc()
  print(record["traceback"],file=sys.stderr,flush=True)
  return 1
 finally:
  record["finished_utc"]=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime());save()
  print(json.dumps({k:record.get(k) for k in ("result","head","tree","remote_before","remote_after","main_before","main_after","publication_verified","business_gate_pass_claimed")},indent=2),flush=True)
if __name__=="__main__":sys.exit(main())
