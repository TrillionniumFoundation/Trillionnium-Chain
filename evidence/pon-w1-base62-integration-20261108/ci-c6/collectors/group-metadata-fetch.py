from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
import datetime,hashlib,json,re,shutil,subprocess
SPEC=json.loads("{\"groups\":{\"42457886518\":[{\"job_id\":128660702000,\"name\":\"W1 false trace reuse (arm64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701997,\"name\":\"W1 complete legal strategies (v2, arm64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701995,\"name\":\"W1 complete legal strategies (v2, x64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701957,\"name\":\"W1 paid rank and batch v5 (x64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701943,\"name\":\"W1 complete legal strategies (v1, x64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701933,\"name\":\"W1 fresh challenge service (x64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701927,\"name\":\"W1 complete legal strategies (v1, arm64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701909,\"name\":\"W1 factorial legal strategies v3 (arm64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701885,\"name\":\"W1 paid rank and batch v5 (arm64, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701856,\"name\":\"W1 false trace reuse (x64, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886584\":[{\"job_id\":128660701788,\"name\":\"reference (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701752,\"name\":\"reference (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886555\":[{\"job_id\":128660701632,\"name\":\"native priorities (ubuntu-24.04-arm, prospective-merge, history)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701606,\"name\":\"native priorities (ubuntu-24.04-arm, prospective-merge, service-model)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701603,\"name\":\"native priorities (ubuntu-24.04-arm, prospective-merge, state)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701599,\"name\":\"native priorities (ubuntu-24.04, prospective-merge, state)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701592,\"name\":\"native priorities (ubuntu-24.04, prospective-merge, history)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701543,\"name\":\"native priorities (ubuntu-24.04, prospective-merge, service-model)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701340,\"name\":\"retained-pressure-failure\",\"role\":\"unlabelled\"}],\"42457886583\":[{\"job_id\":128660701601,\"name\":\"original state and exit (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701409,\"name\":\"original state and exit (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886547\":[{\"job_id\":128660701441,\"name\":\"native boundary (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701420,\"name\":\"native boundary (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886520\":[{\"job_id\":128660701347,\"name\":\"original workspace test CPU (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701285,\"name\":\"original workspace test CPU (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886526\":[{\"job_id\":128660701319,\"name\":\"recent batch (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701166,\"name\":\"recent batch (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886533\":[{\"job_id\":128660701306,\"name\":\"parent evidence (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701271,\"name\":\"parent evidence (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886519\":[{\"job_id\":128660701244,\"name\":\"PQ network and witness (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701090,\"name\":\"PQ network and witness (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886523\":[{\"job_id\":128660701243,\"name\":\"cleanup (ubuntu-24.04, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701236,\"name\":\"aggregate-owner-controls (prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701207,\"name\":\"cleanup (macos-15, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701190,\"name\":\"cleanup (ubuntu-24.04-arm, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886542\":[{\"job_id\":128660701162,\"name\":\"export\",\"role\":\"unlabelled\"}],\"42457886506\":[{\"job_id\":128660701119,\"name\":\"CodeQL local SARIF (rust, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701102,\"name\":\"CodeQL local SARIF (actions, prospective-merge)\",\"role\":\"prospective-merge\"},{\"job_id\":128660701001,\"name\":\"CodeQL local SARIF (python, prospective-merge)\",\"role\":\"prospective-merge\"}],\"42457886532\":[{\"job_id\":128660701100,\"name\":\"W1 transparent candidate (prospective-merge, x64)\",\"role\":\"prospective-merge\"}]},\"head\":\"2bdd252aa6c300b7431b9ee897b254b7953cf562\"}")
OUT=Path("/home/qian-qi/work/chain-w1-c6-ci-failure-diagnostic-20261108-ec265b-01")
REPO=Path("/home/qian-qi/work/chain-w1-base62-integration-20261108-ec265b")
gh=shutil.which("gh");assert gh
def sha(b):return hashlib.sha256(b).hexdigest()
def write(relative,raw):
 if isinstance(raw,str):raw=raw.encode()
 p=OUT/relative;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(raw)
 return {"path":relative,"bytes":len(raw),"sha256":sha(raw)}
def jwrite(relative,d):return write(relative,json.dumps(d,sort_keys=True,indent=2)+"\n")
git_args=[
 ["grep","-n","-E","pull_request\\.base\\.sha|expected-base|EXPECTED_BASE_SHA",SPEC["head"],"--",".github/workflows","scripts/ci"],
 ["grep","-n","-E","ci.context|source.context|event.context|source_context|EXPECTED_BASE",SPEC["head"],"--",".github/workflows/codeql.yml",".github/workflows/codeql-local-sarif.yml",".github/workflows/pon-native-priorities.yml",".github/workflows/pon-w1-work-security.yml"]]
for i,args in enumerate(git_args):
 p=subprocess.run(["git","--no-optional-locks"]+args,cwd=REPO,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
 write(f"source-context/git-search-{i}.stdout",p.stdout);write(f"source-context/git-search-{i}.stderr",p.stderr)
 jwrite(f"source-context/git-search-{i}.command.json",{"argv":["git","--no-optional-locks"]+args,"exit":p.returncode})
 print(json.dumps({"source_search":i,"exit":p.returncode,"text":p.stdout.decode()[:45000],"full_bytes":len(p.stdout)}),flush=True)
export=(OUT/"jobs/128660701162/log.raw").read_text()
lines=export.splitlines()
indexes=[i for i,l in enumerate(lines) if "##[error]" in l]
selected=[]
for i in indexes:
 selected.append({"first_line":max(0,i-65)+1,"lines":lines[max(0,i-65):i+4]})
jwrite("source-context/export-failure-context.json",selected)
print(json.dumps({"export_failure_context":selected}),flush=True)
def run_fetch(item):
 run,wanted=item
 endpoint=f"repos/TrillionniumFoundation/Trillionnium-Chain/actions/runs/{run}/jobs?per_page=100"
 command=[gh,"api",endpoint]
 start=datetime.datetime.now(datetime.timezone.utc).isoformat()
 p=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 a=write(f"run-jobs/{run}.raw.json",p.stdout);b=write(f"run-jobs/{run}.stderr",p.stderr)
 meta={"argv":command,"started_utc":start,"finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
       "exit_code":p.returncode,"stdout":a,"stderr":b}
 jwrite(f"run-jobs/{run}.fetch.json",meta)
 results=[]
 if p.returncode==0:
  d=json.loads(p.stdout);alljobs={x["id"]:x for x in d.get("jobs",[])}
  for original in wanted:
   actual=alljobs.get(original["job_id"])
   row=dict(original,run_id=run,found=actual is not None)
   if actual:
    row.update(head_sha=actual.get("head_sha"),conclusion=actual.get("conclusion"),
       status=actual.get("status"),failed_steps=[s for s in actual["steps"] if s.get("conclusion")=="failure"],
       skipped_steps=[s["name"] for s in actual["steps"] if s.get("conclusion")=="skipped"],
       successful_steps=[s["name"] for s in actual["steps"] if s.get("conclusion")=="success"])
   results.append(row)
  meta["api_total_count"]=d.get("total_count");meta["returned_job_count"]=len(d.get("jobs",[]))
 else: meta["fetch_error"]=p.stderr.decode(errors="replace")[:2000]
 print(json.dumps({"run_id":run,"fetch_exit":p.returncode,"jobs":results}),flush=True)
 return meta,results
metas=[];rows=[]
with ThreadPoolExecutor(max_workers=4) as pool:
 for future in as_completed([pool.submit(run_fetch,item) for item in SPEC["groups"].items()]):
  meta,results=future.result();metas.append(meta);rows.extend(results)
result={"schema":"TRNM-W1-C6-SNAPSHOT-FAILED-JOB-STEPS1",
 "snapshot_failures":40,"jobs":rows,"fetches":metas,
 "all_original_failed_jobs_found":len(rows)==40 and all(r["found"] for r in rows),
 "all_found_heads_match_C6":all(r.get("head_sha")==SPEC["head"] for r in rows if r["found"]),
 "no_workflow_reruns_or_changes":True,
 "role_labels_come_from_snapshot_check_names":True}
pin=jwrite("all-failed-job-steps.json",result)
print(json.dumps({"finished":True,"pin":pin,"all_original_failed_jobs_found":result["all_original_failed_jobs_found"],
 "all_found_heads_match_C6":result["all_found_heads_match_C6"]}),flush=True)
