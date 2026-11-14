import pathlib,os,subprocess,signal,json,hashlib,time,datetime,concurrent.futures,math,re,stat,sys
D=pathlib.Path("/private/tmp/chain-prci-remote-5a4b-required-jobs-observation-20261114-v3")
WT=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
FROZEN=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/remote-readonly-refresh-0170-v1/branches.json")
FROZEN_SHA="e52bb1c8c0963b2ddd303761ffe7ba949c080b3a0f72983f508978f8971e7734"
REPO="TrillionniumFoundation/Trillionnium-Chain"
N="5a4b7fe8de1adce803184f262fd9f704ead1930c"
CAND="refs/heads/fix/chain-hepta-closure-candidate-20261109-481716"
MAIN="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
GH="/opt/homebrew/bin/gh";GIT="/usr/bin/git"
def need(c,m):
 if not c:raise ValueError(m)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(v):return(json.dumps(v,indent=2,sort_keys=True)+"\n").encode()
def save(name,value):
 raw=value if isinstance(value,bytes)else encode(value);p=D/name
 with p.open("xb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
 return {"path":str(p),"bytes":len(raw),"sha256":sha(raw)}
def info(p):
 b=p.read_bytes();return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def read_frozen():
 s=FROZEN.lstat()
 def fp(x):return(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
 need(FROZEN.resolve(strict=True)==FROZEN and stat.S_ISREG(s.st_mode)and s.st_nlink==1,"frozen regular single-link")
 with os.fdopen(os.open(FROZEN,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb")as f:
  need(fp(os.fstat(f.fileno()))==fp(s),"frozen open")
  raw=f.read(s.st_size+1);need(fp(os.fstat(f.fileno()))==fp(s),"frozen stable")
 need(fp(FROZEN.lstat())==fp(s)and len(raw)==s.st_size and sha(raw)==FROZEN_SHA,"frozen SHA/identity")
 rows=json.loads(raw);need(isinstance(rows,list)and len(rows)==908,"frozen908")
 heads={}
 for r in rows:
  need(isinstance(r,dict)and type(r["name"])is str and type(r["sha"])is str
       and re.fullmatch("[0-9a-f]{40}",r["sha"])and r["name"]not in heads,"frozen row")
  heads["refs/heads/"+r["name"]]=r["sha"]
 need(len(heads)==908 and len(set(heads.values()))==892 and heads["refs/heads/main"]==MAIN,"frozen map")
 heads[CAND]=N
 need(len(set(heads.values()))==892,"expectedN tips")
 return heads,raw
os.umask(0o077);D.mkdir(mode=0o700,exist_ok=False)
save("observer.py",sys.argv[1].encode())
expected,frozen_raw=read_frozen();save("frozen-0170-branches.json",frozen_raw)
save("expected-heads-with-reviewed-N.json",expected)
env=os.environ.copy()
for key in tuple(env):
 if key.startswith("GIT_TRACE")or key=="GIT_CURL_VERBOSE":del env[key]
env.update(GIT_TERMINAL_PROMPT="0",GIT_OPTIONAL_LOCKS="0",GIT_NO_REPLACE_OBJECTS="1",
 GIT_NO_LAZY_FETCH="1",GH_PROMPT_DISABLED="1",PYTHONDONTWRITEBYTECODE="1")
for key in("GIT_DIR","GIT_WORK_TREE","GIT_COMMON_DIR","GIT_INDEX_FILE","GIT_NAMESPACE","GIT_CONFIG_COUNT","GIT_CONFIG_PARAMETERS"):
 need(key not in env,"unexpected Git override")
START=now();DEADLINE=time.monotonic()+240
def api(endpoint):return[GH,"api","--method","GET",endpoint]
def run(label,argv,timeout=120):
 out=D/(label+".stdout");err=D/(label+".stderr");began=now();tick=time.monotonic()
 budget=min(timeout,max(1,int(DEADLINE-tick)));timed=False;exit_code=None;spawn_error=None
 with out.open("xb")as so,err.open("xb")as se:
  try:
   proc=subprocess.Popen(argv,cwd=WT,env=env,stdin=subprocess.DEVNULL,stdout=so,stderr=se,start_new_session=True)
   try:exit_code=proc.wait(timeout=budget)
   except subprocess.TimeoutExpired:
    timed=True
    try:os.killpg(proc.pid,signal.SIGTERM)
    except ProcessLookupError:pass
    try:exit_code=proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
     try:os.killpg(proc.pid,signal.SIGKILL)
     except ProcessLookupError:pass
     exit_code=proc.wait(timeout=5)
  except Exception as e:spawn_error=type(e).__name__+": "+str(e)
 row={"label":label,"argv":argv,"cwd":str(WT),"started_at":began,"finished_at":now(),
 "timeout_seconds":budget,"exit":exit_code,"timed_out":timed,"spawn_error":spawn_error,
 "elapsed_seconds":round(time.monotonic()-tick,3),"stdout":info(out),"stderr":info(err)}
 value=None;parse_error=None
 if exit_code==0 and not timed and not spawn_error:
  try:
   need(row["stdout"]["bytes"]<=16*1024*1024,"bounded response exceeded")
   raw=out.read_bytes()
   if label=="refs-heads":
    value={}
    for line in raw.decode("ascii").splitlines():
     oid,ref=line.split("\t");need(re.fullmatch("[0-9a-f]{40}",oid)and ref.startswith("refs/heads/")and ref not in value,"head record")
     value[ref]=oid
   else:value=json.loads(raw)
  except Exception as e:parse_error=type(e).__name__+": "+str(e)
 return {"receipt":row,"value":value,"parse_error":parse_error}
commands=[
("refs-heads",[GIT,"ls-remote","--heads","origin"]),
("pr847",api("repos/"+REPO+"/pulls/847")),
("N-check-runs-page-001",api("repos/"+REPO+"/commits/"+N+"/check-runs?filter=all&per_page=100&page=1")),
("N-required-runs-page-001",api("repos/"+REPO+"/actions/workflows/trnm-required-baseline.yml/runs?head_sha="+N+"&per_page=100&page=1")),
("N-required-run43582713392",api("repos/"+REPO+"/actions/runs/43582713392")),
("N-required-jobs-page-001",api("repos/"+REPO+"/actions/runs/43582713392/jobs?filter=all&per_page=100&page=1")),
]
results={}
def brief(label,result):
 q=result["receipt"];print(json.dumps({"phase":"read_finished","label":label,"exit":q["exit"],
 "timed_out":q["timed_out"],"parse_error":result["parse_error"],"stdout_bytes":q["stdout"]["bytes"]}),flush=True)
def heads_report(r):
 if r["value"]is None:
  v={"status":"UNKNOWN","raw":r["receipt"]["stdout"],"error":r["parse_error"]}
 else:
  heads=r["value"];diff=[{"ref":k,"expected":expected.get(k),"observed":heads.get(k)}
   for k in sorted(set(expected)|set(heads))if expected.get(k)!=heads.get(k)]
  v={"status":"MATCH"if not diff else"CHANGED","head_count":len(heads),"distinct_tips":len(set(heads.values())),
   "candidate":heads.get(CAND),"main":heads.get("refs/heads/main"),"differences":diff,
   "raw":r["receipt"]["stdout"],"started_at":r["receipt"]["started_at"],"finished_at":r["receipt"]["finished_at"]}
 pin=save("heads-summary.json",v);print(json.dumps({"phase":"complete_heads_ready","summary":pin,**v}),flush=True)
 return v
heads_summary=None
with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:
 futures={pool.submit(run,label,argv):label for label,argv in commands}
 for future in concurrent.futures.as_completed(futures):
  label=futures[future]
  try:r=future.result()
  except Exception as e:r={"receipt":{"label":label,"exit":None,"stdout":{},"timed_out":False},"value":None,"parse_error":type(e).__name__+": "+str(e)}
  results[label]=r
  if label=="refs-heads":heads_summary=heads_report(r)
  else:brief(label,r)
# Continue the same fixed query only where its recorded first page requires pagination.
more=[];limits={}
for family,key,array_name,maximum in(
 ("N-check-runs","N-check-runs-page-001","check_runs",5),
 ("N-required-runs","N-required-runs-page-001","workflow_runs",3),
 ("N-required-jobs","N-required-jobs-page-001","jobs",3)):
 first=results[key]["value"]
 if first is None:limits[family]={"complete":False,"reason":"first page UNKNOWN"};continue
 total=first.get("total_count")
 need(type(total)is int and total>=0 and isinstance(first.get(array_name),list),"API pagination schema")
 pages=max(1,math.ceil(total/100))
 limits[family]={"reported_total":total,"required_pages":pages,"maximum_pages":maximum,"array_name":array_name}
 for page in range(2,min(pages,maximum)+1):
  endpoint=("repos/"+REPO+"/commits/"+N+"/check-runs?filter=all&per_page=100&page="+str(page)
   if family=="N-check-runs"else"repos/"+REPO+"/actions/runs/43582713392/jobs?filter=all&per_page=100&page="+str(page)
   if family=="N-required-jobs"else"repos/"+REPO+"/actions/workflows/trnm-required-baseline.yml/runs?head_sha="+N+"&per_page=100&page="+str(page))
  more.append((family+"-page-"+f"{page:03d}",api(endpoint)))
if more:
 with concurrent.futures.ThreadPoolExecutor(max_workers=min(4,len(more)))as pool:
  fs={pool.submit(run,label,argv):label for label,argv in more}
  for future in concurrent.futures.as_completed(fs):
   label=fs[future];r=future.result();results[label]=r;brief(label,r)
lists={}
for family,lim in limits.items():
 rows=[];totals=[];failed=[]
 for label in sorted(k for k in results if k.startswith(family+"-page-")):
  val=results[label]["value"]
  if val is None:failed.append(label);continue
  totals.append(val.get("total_count"));rows.extend(val[lim["array_name"]])
 ids=[x["id"]for x in rows]
 complete=not failed and bool(totals)and len(set(totals))==1 and len(ids)==len(set(ids))==totals[0]and lim.get("required_pages",1)<=lim.get("maximum_pages",0)
 lim.update({"complete":complete,"actual_rows":len(rows),"unique_ids":len(set(ids)),"page_total_counts":totals,"failed_pages":failed})
 lists[family]=rows
def counts(rows):
 out={}
 for r in rows:
  k=r.get("status","UNKNOWN")+"/"+str(r.get("conclusion"))
  out[k]=out.get(k,0)+1
 return out
pr=results["pr847"]["value"];pr_view=None
if pr is not None:
 pr_view={k:pr.get(k)for k in("number","state","draft","auto_merge","created_at","updated_at","mergeable","mergeable_state","merge_commit_sha","html_url")}
 pr_view["head"]={k:pr["head"].get(k)for k in("sha","ref","label")}
 pr_view["base"]={k:pr["base"].get(k)for k in("sha","ref","label")}
 pr_view["matches_reviewed_N_and_main"]=pr["head"]["sha"]==N and pr["base"]["sha"]==MAIN
 if not pr_view["matches_reviewed_N_and_main"]:
  print(json.dumps({"phase":"PR_IDENTITY_CHANGED","pr":pr_view}),flush=True)
checks=lists.get("N-check-runs",[]);runs=lists.get("N-required-runs",[])
normalized_checks=[{k:r.get(k)for k in("id","name","head_sha","status","conclusion","started_at","completed_at","details_url","html_url","check_suite")}for r in checks]
normalized_runs=[{k:r.get(k)for k in("id","name","path","head_sha","head_branch","event","status","conclusion","run_attempt","created_at","updated_at","run_started_at","html_url","check_suite_id","pull_requests")}for r in runs]
check_pin=save("N-check-runs-normalized.json",normalized_checks)
run_pin=save("N-required-runs-normalized.json",normalized_runs)
raw_run=results["N-required-run43582713392"]["value"]
observed_run=None
if raw_run is not None:
 observed_run={k:raw_run.get(k)for k in("id","name","path","head_sha","head_branch","event","status","conclusion","run_attempt","created_at","updated_at","run_started_at","html_url","check_suite_id","pull_requests","head_commit")}
 observed_run["matches_expected_N"]=raw_run.get("id")==43582713392 and raw_run.get("head_sha")==N and raw_run.get("path")==".github/workflows/trnm-required-baseline.yml"
jobs=lists.get("N-required-jobs",[])
normalized_jobs=[]
for job in jobs:
 row={k:job.get(k)for k in("id","run_id","run_attempt","name","head_sha","head_branch","status","conclusion","created_at","started_at","completed_at","html_url","check_run_url","labels","runner_id","runner_name","runner_group_id","runner_group_name")}
 name=str(job.get("name","")).lower()
 row["source_kind_hint_from_name"]="prospective"if"prospective"in name else"head"if re.search(r"(^|[^a-z])head([^a-z]|$)",name)else"not_explicit_in_name"
 row["steps"]=[{k:step.get(k)for k in("number","name","status","conclusion","started_at","completed_at")}for step in job.get("steps",[])]
 row["actual_tested_tree_verified_from_originals"]=False
 normalized_jobs.append(row)
jobs_pin=save("N-required-jobs-normalized.json",normalized_jobs)
summary={
"schema":"trnm-fresh-reviewed-N-refs-PR-required-jobs-overview-v3","started_at":START,"finished_at":now(),
"expected_remote_candidate":N,"expected_main":MAIN,
"frozen_inventory":{"source_path":str(FROZEN),"sha256":FROZEN_SHA,"original_branch_names":908,"original_distinct_tips":892},
"heads":heads_summary,"pr":pr_view,"required_workflow":".github/workflows/trnm-required-baseline.yml",
"check_runs":{"raw_scope":"all check-runs returned for exact immutable N","pagination":limits.get("N-check-runs"),
"status_counts":counts(checks),"all_returned_head_sha_equal_N":all(r.get("head_sha")==N for r in checks),"normalized":check_pin},
"required_runs":{"pagination":limits.get("N-required-runs"),"status_counts":counts(runs),
"all_returned_head_sha_equal_N":all(r.get("head_sha")==N for r in runs),"normalized":run_pin,"runs":normalized_runs},
"fixed_required_run":observed_run,"fixed_required_jobs":{"run_id":43582713392,"pagination":limits.get("N-required-jobs"),"status_counts":counts(jobs),"all_returned_run_id_matches":all(r.get("run_id")==43582713392 for r in jobs),"all_returned_head_sha_equal_N":all(r.get("head_sha")==N for r in jobs),"normalized":jobs_pin,"jobs":normalized_jobs},"actual_job_assertion_or_source_tree_cause_not_observed":True,"current_PR_prospective_SHA_not_assumed_actual_job_tested_tree":True,
"unknown_reads":[k for k,v in results.items()if v["value"]is None],
"steps":[results[k]["receipt"]for k in sorted(results)],
"observations_non_atomic":True,"no_remote_ref_lock_claimed":True,
"earlier_0957_and_1020_observations_not_overwritten":True,
"network_readonly":True,"source_stage_git_refs_or_objects_written":False,
"dispatch_rerun_cancel_PR_writes":False,"artifacts_or_job_logs_downloaded":False,
"hosted_qualification_granted":False}
summary_pin=save("summary.json",summary)
entries=[]
for f in sorted(D.iterdir()):
 if f.is_file():entries.append(info(f))
index_pin=save("EVIDENCE_INDEX.json",{"schema":"trnm-readonly-remote-observation-index-v1","files":entries,"self_excluded":"EVIDENCE_INDEX.json"})
print(json.dumps({"phase":"completed","summary":summary_pin,"index":index_pin,"heads":heads_summary,
"pr":pr_view,"check_counts":counts(checks),"check_complete":limits.get("N-check-runs"),
"required_runs":normalized_runs,"runs_complete":limits.get("N-required-runs"),"required_run":observed_run,"job_counts":counts(jobs),"jobs_complete":limits.get("N-required-jobs"),"jobs":[{k:r[k]for k in("id","name","status","conclusion","started_at","completed_at","source_kind_hint_from_name")}for r in normalized_jobs],
"unknown_reads":summary["unknown_reads"]}),flush=True)
