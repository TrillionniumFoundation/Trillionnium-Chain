from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import collections,datetime,hashlib,json,re,resource,shutil,subprocess,time
OUT=Path("/home/qian-qi/work/chain-w1-c7-postpush-ci-observation-20261108-ec265b-01")
OUT.mkdir(exist_ok=False)
REPO=Path("/home/qian-qi/work/chain-w1-base96-integration-20261108-ec265b")
NAME="TrillionniumFoundation/Trillionnium-Chain"
C7="40a3a45d6b8afc5c4706c5235fec47634f4aabbe"
gh=shutil.which("gh");git=shutil.which("git");assert gh and git
started=time.time_ns();records=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def put(name,b):
 p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(b)
 return {"path":name,"bytes":len(b),"sha256":sha(b)}
def jput(name,d):return put(name,(json.dumps(d,sort_keys=True,indent=2)+"\n").encode())
def cap():resource.setrlimit(resource.RLIMIT_FSIZE,(24*1024*1024,24*1024*1024))
def command(label,argv,cwd=None,timeout=60):
 s=time.time_ns();op=OUT/(label+".stdout");ep=OUT/(label+".stderr");op.parent.mkdir(parents=True,exist_ok=True)
 error=None;timed=False
 with op.open("xb") as of,ep.open("xb") as ef:
  try:r=subprocess.run(argv,cwd=cwd,stdin=subprocess.DEVNULL,stdout=of,stderr=ef,timeout=timeout,preexec_fn=cap);rc=r.returncode
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
 fc=pool.submit(api,"03-c7-checks-page-1",f"repos/{NAME}/commits/{C7}/check-runs?filter=all&per_page=100&page=1")
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
  for page in range(2,min(4,(declared_total+99)//100+1)):
   rec,raw=api(f"03-c7-checks-page-{page}",f"repos/{NAME}/commits/{C7}/check-runs?filter=all&per_page=100&page={page}");records.append(rec)
   if rec["exit_code"]!=0:pagination_errors.append(f"page-{page}-fetch-failed");continue
   d=json.loads(raw);checks+=d.get("check_runs",[])
   page_counts.append({"page":page,"declared_total":d.get("total_count"),"returned":len(d.get("check_runs",[]))})
else:pagination_errors.append("page-1-fetch-failed")
if pr_first is None or pr_first.get("merge_commit_sha") is None:
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
 projection="{base_commit:.base_commit.sha,merge_base_commit:.merge_base_commit.sha,status:.status,ahead_by:.ahead_by,behind_by:.behind_by,total_commits:.total_commits,commits:[.commits[]|{sha:.sha,parents:[.parents[].sha]}]}"
 rec,raw=api("06-base-vs-c7-compare-projection",f"repos/{NAME}/compare/{actual_base}...{C7}",projection);records.append(rec)
 if rec["exit_code"]==0:compare=json.loads(raw)
jput("C7-all-checks.json",checks)
unique=len({x["id"] for x in checks})==len(checks)
preferred=["W1 fresh challenge service (x64, prospective-merge)","CodeQL local SARIF (python, prospective-merge)","prospective-merge (repository-truth)"]
selected=[]
for name in preferred:
 rows=[x for x in checks if x.get("name")==name and x.get("status")=="completed"]
 if rows:selected.append(rows[0])
 if len(selected)==2:break
if not selected:
 selected=[x for x in checks if "prospective-merge" in x.get("name","") and x.get("status")=="completed"][:2]
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
 hits=[{"line":n+1,"text":line} for n,line in enumerate(lines) if re.search(r"(EXPECTED_(BASE|HEAD|MERGE|SOURCE).*SHA|BASE_SHA:|HEAD_SHA:|MERGE_SHA:|SOURCE_SHA:|merge parents differ|ordered.*parent|ValueError:|##\[error\])",line)]
 sample={"job_id":jid,"run_id":run,"name":c["name"],"head_sha":None if meta is None else meta.get("head_sha"),
  "conclusion":None if meta is None else meta.get("conclusion"),"metadata_fetch_exit":meta_rec["exit_code"],
  "log_fetch_exit":log_rec["exit_code"],"first_failed_step":None if meta is None else next((x for x in meta.get("steps",[]) if x.get("conclusion")=="failure"),None),
  "tuple_and_error_log_lines":hits[:120],"job_metadata":prefix+"/metadata.stdout","job_log":prefix+"/log.stdout"}
 jput(prefix+"/readback.json",sample);sample_results.append(sample)
 if run not in seen_runs:
  rec,raw=api(f"run-samples/{run}",f"repos/{NAME}/actions/runs/{run}");records.append(rec);seen_runs.add(run)
status=collections.Counter(f"{x.get('status')}:{x.get('conclusion')}" for x in checks)
result={"schema":"TRNM-W1-C7-POSTPUSH-CI-OBSERVATION1","window_started_unix_ns":started,"window_finished_unix_ns":time.time_ns(),
 "snapshot_atomic":False,"expected_C7":C7,"PR_API_reads":pr_reads,
 "PR_API_first":None if pr_first is None else {k:pr_first.get(k) for k in ["head","base","merge_commit_sha","state","draft","mergeable","mergeable_state","updated_at"]},
 "PR_API_final":None if pr_final is None else {"head_sha":pr_final.get("head",{}).get("sha"),"base_sha":pr_final.get("base",{}).get("sha"),
  "merge_commit_sha":pr_final.get("merge_commit_sha"),"draft":pr_final.get("draft"),"state":pr_final.get("state"),"mergeable":pr_final.get("mergeable"),
  "mergeable_state":pr_final.get("mergeable_state"),"updated_at":pr_final.get("updated_at")},
 "actual_Git_refs":refs,"actual_base":actual_base,"actual_head":actual_head,"actual_merge":actual_merge,"merge_objects":merge_objects,
 "base_C7_compare_projection":compare,"C7_checks":{"count":len(checks),"declared_total":declared_total,"unique_ids":unique,
 "enumeration_complete":len(checks)==declared_total and unique and not pagination_errors,"status_counts":dict(status),"page_counts":page_counts,
 "pagination_errors":pagination_errors,"foreign_source_check_ids":[x["id"] for x in checks if x.get("head_sha")!=C7]},
 "job_samples":sample_results,"read_failures":[r for r in records if r["exit_code"]!=0],
 "source_changes":0,"CI_reruns":0,"dispatches":0,"source_guard_changes":0,"new_operations":0,
 "event_expected_values_not_inferred_from_merge":True}
jput("snapshot.json",result);jput("read-commands.json",records)
print(json.dumps({"out":str(OUT),"window_started_unix_ns":started,"window_finished_unix_ns":result["window_finished_unix_ns"],
 "PR_API_reads":pr_reads,"PR_API_final":result["PR_API_final"],"actual_Git_refs":refs,"merge_objects":merge_objects,
 "base_C7_compare_projection":compare,"C7_checks":result["C7_checks"],"job_samples":sample_results,
 "read_failures":result["read_failures"],"snapshot_sha256":sha((OUT/"snapshot.json").read_bytes())}),flush=True)
