from pathlib import Path
import json,hashlib,sys
ROOT=Path("/home/qian-qi/throughput-ci-observation-20261107");SNAP=ROOT/"20261107T155220Z-d26e047dedfc-bb63e773";D=SNAP/"history-artifact-read-v1"
sys.path.insert(0,str(ROOT/"pinned-readers-d26-v1/scripts/ci"))
from run_history_native import validate_summary,SELECTOR
from check_required_native_test import validate as validate_named
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
resolver=json.loads((ROOT/"20261107T145028Z-d26e047dedfc-a2c5a3df/source-artifact-read-v1/13578352816/context.json").read_bytes())
joblogs=json.loads((SNAP/"history-job-log-read-v1/summary.json").read_bytes())
sql=json.loads((D/"retained-sql-core-v1.json").read_bytes())
results=[]
for d in sorted(x for x in D.iterdir() if x.is_dir()):
 rb=json.loads((d/"readback.json").read_bytes());a=rb["metadata"]
 source=json.loads((d/"source.json").read_bytes());mat=json.loads((d/"push-source-context.json").read_bytes())
 m=json.loads((d/"history-native/manifest.json").read_bytes());prepared=json.loads((d/"history-native/preparation.json").read_bytes())
 assert not rb["errors"] and a["digest"]=="sha256:"+rb["zip_sha256"] and rb["zip_bytes"]==a["size_in_bytes"]
 assert mat["context"]==resolver and mat["source"]==source and mat["github_event_name"]=="push" and mat["github_sha"]==resolver["head"] and mat["is_github_pr_merge"] is False
 assert mat["context_sha256"]==hashlib.sha256(json.dumps(resolver,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
 assert source["candidate"]==resolver["head"] and source["tested_tree"]==resolver["merge_tree"] and source["tracked_worktree_verified"] is True
 expected=resolver["head"] if source["kind"]=="head" else resolver["merge"]
 assert source["tested_commit"]==expected
 if source["kind"]=="prospective-merge":assert source["base"]==resolver["base"] and source["prospective_merge"]==resolver["merge"]
 runner="ubuntu-24.04-arm" if "-arm-" in a["name"] else "ubuntu-24.04"
 matching=[r for r in joblogs["results"] if r["name"]=="native priorities ("+runner+", "+source["kind"]+", history)"]
 assert len(matching)==1 and not matching[0]["errors"]
 logsource=matching[0]["source_readback"];assert logsource["observed_count"]==2 and logsource["identities"][0]==logsource["identities"][-1]==source
 assert prepared["completed"] is True and prepared["failures"]==[] and prepared["process"]["exit_code"]==0
 assert prepared["source_before"]==prepared["source_after"]==m["source_before"]==m["source_after"]
 assert m["source_before"]["tracked_source_identity"]==source and m["source_before"]["commit"]==expected
 assert m["binary_before"]==m["binary_after"]==prepared["binary"]
 assert m["preparation_sha256"]==sha(d/"history-native/preparation.json")
 bound=[]
 for rel,observed in [("history-native/build.jsonl",prepared["build_log"]),("history-native/history.log",m["log"]),("history-native/history-resources.txt",m["resources"]),("history-native/long-history/summary.json",m["summary_file"])]:
  p=d/rel;assert observed is not None and observed["sha256"]==sha(p) and observed["size_bytes"]==p.stat().st_size
  bound.append({"path":rel,"bytes":p.stat().st_size,"sha256":sha(p)})
 summary=json.loads((d/"history-native/long-history/summary.json").read_bytes());assert summary==m["summary"]
 errors={}
 for name,fn in [("summary",lambda:validate_summary(summary)),("named_test",lambda:validate_named((d/"history-native/history.log").read_text().splitlines(),SELECTOR))]:
  try:fn();errors[name]=None
  except Exception as e:errors[name]=type(e).__name__+": "+str(e)
 assert errors["summary"]=="ValueError: HISTORY_NATIVE_COMPLETION_REQUIRED" and errors["named_test"] is not None
 assert m["process"]["exit_code"]==101 and m["process"]["failure"] is None and m["process"]["cleanup_errors"]==[] and m["passed"] is False
 hosts=[]
 for p in sorted(d.glob("*-host/*.json")):
  o=json.loads(p.read_bytes())
  if p.name in ("child-result.json","controller-result.json"):
   hosts.append({"path":str(p.relative_to(d)),"sha256":sha(p),"result":{k:o.get(k) for k in ("command_exit_code","exit_code","host_errors","final_host_errors","failure","child_result")}})
 row={"artifact_id":int(d.name),"job_id":matching[0]["job_id"],"run_id":a["workflow_run"]["id"],"name":a["name"],"source_binding":{"kind":source["kind"],"candidate":resolver["head"],"base":resolver["base"],"merge":resolver["merge"],"tested_commit":expected,"tree":source["tested_tree"],"materialization_matches_resolver":True,"before_after_equal":True,"actual_source_after_step_succeeded":True},"zip_sha256":rb["zip_sha256"],"preparation_completed":True,"binary_identity_equal":True,"retained_file_bindings":bound,"native_process":m["process"],"native_failures":m["failures"],"independent_pinned_reader_errors":errors,"host_records":hosts,"summary":summary,"sql_readback":next(r for r in sql["results"] if r["artifact_id"]==int(d.name)),"original_gate_validated":False}
 results.append(row)
out={"schema":"trnm-d26-original-history-independent-readback-v1","expected_lanes":4,"observed_lanes":len(results),"scope":"Original authenticated CI execution and exact retained artifact byte observations; pure validators only, no live rebinding or native retry.","results":results,"native_gate_validated":False}
p=D/"independent-readback-v1.json";p.write_text(json.dumps(out,indent=2)+chr(10));print(json.dumps({"path":str(p),"bytes":p.stat().st_size,"sha256":sha(p),"lanes":len(results),"source_and_artifact_bindings_passed":len(results),"native_exits":[r["native_process"]["exit_code"] for r in results],"reader_errors":[r["independent_pinned_reader_errors"] for r in results]}))
