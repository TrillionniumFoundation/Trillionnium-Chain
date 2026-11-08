from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import collections,datetime,hashlib,json,re,resource,shutil,subprocess,time
OUT=Path("/home/qian-qi/work/chain-w1-c8-postpush-ci-observation-20261108-ec265b-01")
OUT.mkdir(exist_ok=False)
REPO=Path("/home/qian-qi/work/chain-w1-base9417-integration-20261108-ec265b")
NAME="TrillionniumFoundation/Trillionnium-Chain"
C8="4e007a87ceecbec8d265f6a70cfd71d512a514b5"
gh=shutil.which("gh");git=shutil.which("git");assert gh and git
started=time.time_ns();records=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def put(name,b):
 p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(b)
 return {"path":name,"bytes":len(b),"sha256":sha(b)}
def jput(name,d):return put(name,(json.dumps(d,sort_keys=True,indent=2)+"\n").encode())
resource.setrlimit(resource.RLIMIT_FSIZE,(24*1024*1024,24*1024*1024))
jput("declaration.json",json.loads("{\"schema\":\"TRNM-W1-C8-CI-OBSERVER-DECLARATION1\",\"source_commit\":\"4e007a87ceecbec8d265f6a70cfd71d512a514b5\",\"fixed_integrated_base\":\"9417e495165865ef6c1288b39084856e31020634\",\"repository\":\"TrillionniumFoundation/Trillionnium-Chain\",\"pull_request\":782,\"root_push_job\":\"1a1baa13bb5-12894-1c09\",\"heavy_terminal_job\":\"1a1baa770fd-12894-1c3b\",\"cold_terminal_job\":\"1a1baac4fa2-12894-1c66\",\"root_execution_authorization\":\"现在正式允许启动C8有界CI observer：m12 heavy1c3b+independent cold1c66都actual success0 complete/durable，quiet已结束。\",\"maximum_pr_reads\":2,\"maximum_check_pages\":10,\"maximum_workflow_run_pages\":10,\"page_size\":100,\"maximum_completed_job_samples\":6,\"transport_command_timeout_seconds\":60,\"outer_timeout_seconds\":600,\"CI_reruns\":0,\"dispatches\":0,\"source_changes\":0,\"new_base_integration_or_qualification\":0,\"full_history_wait\":false}"))
def command(label,argv,cwd=None,timeout=60):
 s=time.time_ns();op=OUT/(label+".stdout");ep=OUT/(label+".stderr");op.parent.mkdir(parents=True,exist_ok=True)
 error=None;timed=False
 with op.open("xb") as of,ep.open("xb") as ef:
  try:r=subprocess.run(argv,cwd=cwd,stdin=subprocess.DEVNULL,stdout=of,stderr=ef,timeout=timeout);rc=r.returncode
  except subprocess.TimeoutExpired:rc=None;timed=True
  except Exception as e:rc=None;error=repr(e)
 raw=op.read_bytes();err=ep.read_bytes()
 rec={"label":label,"argv":argv,"cwd":str(cwd) if cwd else None,"started_unix_ns":s,"finished_unix_ns":time.time_ns(),
 "exit_code":rc,"timed_out":timed,"error":error,"stdout":{"path":op.name if op.parent==OUT else str(op.relative_to(OUT)),"bytes":len(raw),"sha256":sha(raw)},
 "stderr":{"path":str(ep.relative_to(OUT)),"bytes":len(err),"sha256":sha(err)}}
 jput(label+".command.json",rec)
 return rec,raw
def api(label,endpoint,projection=None):
 argv=[gh,"api",endpoint]
 if projection:argv+=["--jq",projection]
 return command(label,argv)
login,raw=api("00-operator-login","user",".login");records.append(login)
assert login["exit_code"]==0 and raw.decode().strip()=="ProfHepta"
pr1,raw=api("01-pr-api",f"repos/{NAME}/pulls/782");records.append(pr1)
pr_first=json.loads(raw) if pr1["exit_code"]==0 else None
pr_final=pr_first;pr_reads=1
refargv=[git,"--no-optional-locks","ls-remote","origin","refs/heads/fix/chain-six-axis-performance-20261103","refs/heads/fix/chain-w1-runtime-integrated-20261107","refs/pull/782/head","refs/pull/782/merge"]
with ThreadPoolExecutor(max_workers=2) as pool:
 fr=pool.submit(command,"02-actual-git-refs",refargv,REPO)
 fc=pool.submit(api,"03-c8-checks-page-1",f"repos/{NAME}/commits/{C8}/check-runs?filter=all&per_page=100&page=1")
 ref_rec,ref_raw=fr.result();check_rec,check_raw=fc.result()
records += [ref_rec,check_rec]
refs={}
if ref_rec["exit_code"]==0:
 for line in ref_raw.decode().splitlines():
  s,r=line.split();assert re.fullmatch("[0-9a-f]{40}",s);refs[r]=s
checks=[];page_counts=[];pagination_errors=[];declared_total=None
if check_rec["exit_code"]==0:
 d=json.loads(check_raw);checks+=d.get("check_runs",[]);declared_total=d.get("total_count")
 page_counts.append({"page":1,"declared_total":declared_total,"returned":len(d.get("check_runs",[]))})
 if type(declared_total) is int and declared_total>100:
  for page in range(2,min(11,(declared_total+99)//100+1)):
   rec,raw=api(f"03-c8-checks-page-{page}",f"repos/{NAME}/commits/{C8}/check-runs?filter=all&per_page=100&page={page}");records.append(rec)
   if rec["exit_code"]!=0:pagination_errors.append(f"page-{page}-fetch-failed");continue
   d=json.loads(raw);checks+=d.get("check_runs",[])
   page_counts.append({"page":page,"declared_total":d.get("total_count"),"returned":len(d.get("check_runs",[]))})
else:pagination_errors.append("page-1-fetch-failed")
if type(declared_total) is int and declared_total>1000:pagination_errors.append("bounded-page-limit")
run_rows=[];run_page_counts=[];run_pagination_errors=[];runs_declared_total=None
for page in range(1,11):
 rec,raw=api(f"03-c8-workflow-runs-page-{page}",f"repos/{NAME}/actions/runs?head_sha={C8}&per_page=100&page={page}");records.append(rec)
 if rec["exit_code"]!=0:
  run_pagination_errors.append(f"page-{page}-fetch-failed");break
 d=json.loads(raw)
 if page==1:runs_declared_total=d.get("total_count")
 page_rows=d.get("workflow_runs",[]);run_rows+=page_rows
 run_page_counts.append({"page":page,"declared_total":d.get("total_count"),"returned":len(page_rows)})
 if type(runs_declared_total) is not int:
  run_pagination_errors.append("invalid-total-count");break
 if page*100>=runs_declared_total:break
if type(runs_declared_total) is int and runs_declared_total>1000:run_pagination_errors.append("bounded-page-limit")
jput("C8-all-workflow-runs.json",run_rows)
if True:
 pr2,raw=api("04-pr-api-second-bounded-read",f"repos/{NAME}/pulls/782");records.append(pr2);pr_reads+=1
 pr_final=json.loads(raw) if pr2["exit_code"]==0 else None
actual_base=refs.get("refs/heads/fix/chain-six-axis-performance-20261103")
actual_head=refs.get("refs/heads/fix/chain-w1-runtime-integrated-20261107")
actual_merge=refs.get("refs/pull/782/merge")
merge_objects={}
for i,s in enumerate(dict.fromkeys(x for x in [actual_merge,None if pr_final is None else pr_final.get("merge_commit_sha")] if x)):
 rec,raw=api(f"05-merge-object-{i+1}",f"repos/{NAME}/git/commits/{s}");records.append(rec)
 if rec["exit_code"]==0:
  d=json.loads(raw);merge_objects[s]={"sha":d["sha"],"tree":d.get("tree",{}).get("sha"),"parents":[x["sha"] for x in d.get("parents",[])],"message":d.get("message")}
compare=None
if actual_base:
 projection="{base_commit:.base_commit.sha,merge_base_commit:.merge_base_commit.sha,status:.status,ahead_by:.ahead_by,behind_by:.behind_by,total_commits:.total_commits}"
 rec,raw=api("06-base-vs-c8-compare-projection",f"repos/{NAME}/compare/{actual_base}...{C8}",projection);records.append(rec)
 if rec["exit_code"]==0:compare=json.loads(raw)
jput("C8-all-checks.json",checks)
unique=len({x["id"] for x in checks})==len(checks)
preferred=["W1 fresh challenge service (x64, prospective-merge)","CodeQL local SARIF (python, prospective-merge)","prospective-merge (repository-truth)"]
selected=[]
for name in preferred:
 rows=[x for x in checks if x.get("name")==name and x.get("status")=="completed"]
 if rows:selected.append(rows[0])
 if len(selected)==2:break
if not selected:
 selected=[x for x in checks if "prospective-merge" in x.get("name","") and x.get("status")=="completed"][:2]
# Bounded representative completed failures: do not extrapolate their causes to every check.
business_words=re.compile(r"fresh|native.*campaign|service.model|history|protocol.contract|cross.arch",re.I)
for row in sorted(checks,key=lambda x:("prospective-merge" in x.get("name",""),not bool(business_words.search(x.get("name",""))),x.get("name",""))):
 if row.get("status")=="completed" and row.get("conclusion")=="failure" and row.get("head_sha")==C8 and all(x["id"]!=row["id"] for x in selected):
  selected.append(row)
 if len(selected)>=6:break
sample_results=[];seen_runs=set()
for i,c in enumerate(selected,1):
 url=c.get("details_url","");m=re.search(r"/actions/runs/(\d+)/job/(\d+)",url)
 if not m:
  sample_results.append({"check_id":c["id"],"name":c.get("name"),"error":"no-job-url"});continue
 run,jid=map(int,m.groups());prefix=f"job-samples/{jid}"
 meta_rec,raw=api(prefix+"/metadata",f"repos/{NAME}/actions/jobs/{jid}");records.append(meta_rec)
 meta=json.loads(raw) if meta_rec["exit_code"]==0 else None
 log_rec,raw=api(prefix+"/log",f"repos/{NAME}/actions/jobs/{jid}/logs");records.append(log_rec)
 lines=raw.decode("utf-8",errors="replace").splitlines() if log_rec["exit_code"]==0 else []
 hits=[{"line":n+1,"text":line} for n,line in enumerate(lines) if re.search(r"(EXPECTED_(BASE|HEAD|MERGE|KIND)(?:_SHA)?:|merge parents differ|ordered.*parent|ValueError:|##\[error\]|CONFIRMATION_TARGET|PUBLIC_REQUEST_DEADLINE|ORIGINAL_THREE_RUN_CAMPAIGN_FAILED|FRESH_NATIVE_PROCESS_REQUIRED|finite_target_met|test result:|Connection refused)",line)]
 declarations=[];values={k:[] for k in ["EXPECTED_KIND","EXPECTED_BASE","EXPECTED_HEAD","EXPECTED_MERGE"]}
 for n,line in enumerate(lines):
  clean=re.sub(r"\x1b\[[0-9;]*m","",line)
  clean=re.sub(r"^\d{4}-\d{2}-\d{2}T[0-9:.]+Z\s*","",clean).strip()
  found=re.fullmatch(r"(EXPECTED_(?:BASE|HEAD|MERGE|KIND))(?:_SHA)?:\s*(.*?)\s*",clean)
  if not found:continue
  key,value=found.groups();declarations.append({"line":n+1,"field":key,"raw_value":value})
  if value not in values[key]:values[key].append(value)
 expected={k:(v[0] if len(v)==1 and (k=="EXPECTED_KIND" or re.fullmatch("[0-9a-f]{40}",v[0])) else None) for k,v in values.items()}
 kept_hits=hits if len(hits)<=160 else hits[:80]+hits[-80:]
 sample={"job_id":jid,"run_id":run,"name":c["name"],"head_sha":None if meta is None else meta.get("head_sha"),
  "conclusion":None if meta is None else meta.get("conclusion"),"metadata_fetch_exit":meta_rec["exit_code"],
  "log_fetch_exit":log_rec["exit_code"],"first_failed_step":None if meta is None else next((x for x in meta.get("steps",[]) if x.get("conclusion")=="failure"),None),
  "tuple_and_error_log_lines":kept_hits,"matching_log_line_count":len(hits),
  "event_declarations":declarations,"event_expected_values":expected,"event_expected_raw_values":values,
  "event_expected_values_inferred_from_API_or_merge":False,
  "job_metadata":prefix+"/metadata.stdout","job_log":prefix+"/log.stdout"}
 jput(prefix+"/readback.json",sample);sample_results.append(sample)
 if run not in seen_runs:
  rec,raw=api(f"run-samples/{run}",f"repos/{NAME}/actions/runs/{run}");records.append(rec);seen_runs.add(run)
status=collections.Counter(f"{x.get('status')}:{x.get('conclusion')}" for x in checks)
result={"schema":"TRNM-W1-C8-POSTPUSH-CI-OBSERVATION1","window_started_unix_ns":started,"window_finished_unix_ns":time.time_ns(),
 "snapshot_atomic":False,"expected_C8":C8,"PR_API_reads":pr_reads,
 "PR_API_first":None if pr_first is None else {k:pr_first.get(k) for k in ["head","base","merge_commit_sha","state","draft","mergeable","mergeable_state","updated_at"]},
 "PR_API_final":None if pr_final is None else {"head_sha":pr_final.get("head",{}).get("sha"),"base_sha":pr_final.get("base",{}).get("sha"),
  "merge_commit_sha":pr_final.get("merge_commit_sha"),"draft":pr_final.get("draft"),"state":pr_final.get("state"),"mergeable":pr_final.get("mergeable"),
  "mergeable_state":pr_final.get("mergeable_state"),"updated_at":pr_final.get("updated_at")},
 "actual_Git_refs":refs,"actual_base":actual_base,"actual_head":actual_head,"actual_merge":actual_merge,"merge_objects":merge_objects,
 "base_C8_compare_projection":compare,"C8_checks":{"count":len(checks),"declared_total":declared_total,"unique_ids":unique,
 "enumeration_complete":len(checks)==declared_total and unique and not pagination_errors and all(x["declared_total"]==declared_total for x in page_counts),"status_counts":dict(status),"page_counts":page_counts,
 "pagination_errors":pagination_errors,"foreign_source_check_ids":[x["id"] for x in checks if x.get("head_sha")!=C8]},
 "C8_workflow_runs":{"count":len(run_rows),"declared_total":runs_declared_total,
 "unique_ids":len({x["id"] for x in run_rows})==len(run_rows),
 "enumeration_complete":len(run_rows)==runs_declared_total and len({x["id"] for x in run_rows})==len(run_rows) and not run_pagination_errors and all(x["declared_total"]==runs_declared_total for x in run_page_counts),
 "page_counts":run_page_counts,"pagination_errors":run_pagination_errors,
 "status_counts":dict(collections.Counter(f"{x.get('status')}:{x.get('conclusion')}" for x in run_rows)),
 "foreign_source_run_ids":[x["id"] for x in run_rows if x.get("head_sha")!=C8]},
 "fixed_integrated_base":"9417e495165865ef6c1288b39084856e31020634",
 "base_changed_since_fixed_integration":None if actual_base is None else actual_base!="9417e495165865ef6c1288b39084856e31020634",
 "new_base_integration_or_qualification_started":False,
 "job_samples":sample_results,"job_sample_limit":6,
 "failure_causes_not_extrapolated_beyond_sampled_jobs":True,
 "all_event_expected_values_unobserved":not any(any(s.get("event_expected_values",{}).get(k) for k in ["EXPECTED_BASE","EXPECTED_HEAD","EXPECTED_MERGE"]) for s in sample_results),
 "read_failures":[r for r in records if r["exit_code"]!=0],
 "source_changes":0,"CI_reruns":0,"dispatches":0,"source_guard_changes":0,"new_operations":0,
 "event_expected_values_not_inferred_from_merge":True}
jput("snapshot.json",result);jput("read-commands.json",records)
print(json.dumps({"out":str(OUT),"window_started_unix_ns":started,"window_finished_unix_ns":result["window_finished_unix_ns"],
 "PR_API_reads":pr_reads,"PR_API_final":result["PR_API_final"],"actual_Git_refs":refs,"merge_objects":merge_objects,
 "base_C8_compare_projection":compare,"C8_checks":result["C8_checks"],"C8_workflow_runs":result["C8_workflow_runs"],"job_samples":sample_results,
 "read_failures":result["read_failures"],"snapshot_sha256":sha((OUT/"snapshot.json").read_bytes())}),flush=True)

