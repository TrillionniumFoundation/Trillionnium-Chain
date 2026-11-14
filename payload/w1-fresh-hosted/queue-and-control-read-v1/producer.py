import concurrent.futures,datetime,hashlib,json,os,pathlib,re,subprocess,sys,time
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/queue-and-control-read-v1")
SOURCE=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64"
API="repos/TrillionniumFoundation/Trillionnium-Chain"
os.umask(0o077);E.mkdir(mode=0o700,exist_ok=False)
env={k:v for k,v in os.environ.items() if not k.startswith("GIT_") and k not in ("GH_DEBUG",)}
env.update(PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",GIT_TRACE="0",GIT_TRACE2="0",GIT_TRACE2_EVENT="0",GIT_TRACE2_PERF="0",GH_PROMPT_DISABLED="1",PYTHONDONTWRITEBYTECODE="1")
def sha(b):return hashlib.sha256(b).hexdigest()
def put(p,b):
 with p.open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def run(item):
 label,args,timeout=item;start=datetime.datetime.now(datetime.timezone.utc).isoformat();clock=time.monotonic()
 try:
  p=subprocess.run(args,cwd=SOURCE,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
  rc=p.returncode;out=p.stdout;err=p.stderr;timed=False
 except subprocess.TimeoutExpired as x:
  rc=None;out=x.stdout or b"";err=x.stderr or b"";timed=True
 row={"label":label,"argv":args,"cwd":str(SOURCE),"started_at":start,"finished_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"elapsed_seconds":round(time.monotonic()-clock,3),"timeout_seconds":timeout,"exit":rc,"timed_out":timed,"stdout":put(E/(label+".stdout"),out),"stderr":put(E/(label+".stderr"),err)}
 put(E/(label+".step.json"),(json.dumps(row,indent=2,sort_keys=True)+"\n").encode())
 assert len(out)+len(err)<=8*1024*1024,"read bounded"
 return row,out
endpoint=API+"/actions/workflows/trnm-required-baseline.yml/runs?branch=fix%2Fchain-hepta-closure-candidate-20261109-481716&event=pull_request&status=in_progress&per_page=100&page=1"
items=[
 ("required-same-branch-in-progress-page-001",["/opt/homebrew/bin/gh","api","--hostname","github.com","--include","--method","GET","-H","Accept: application/vnd.github+json","-H","X-GitHub-Api-Version: 2026-03-10",endpoint],120),
 ("R1-control-workflow-matches",["/usr/bin/git","grep","-n","-E","retained-pressure-failure|Original budget controls",HEAD,"--",".github/workflows"],30)]
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(run,items))
rows=[x[0] for x in results]; apirow,raw=results[0]
summary={"schema":"trnm-R1-required-concurrency-read-v1","head":HEAD,"steps":rows,"errors":[],"api_reads":1,"network_mutations":False,"source_or_Git_refs_or_stage_changed":False,"observations_non_atomic":True}
if apirow["exit"]==0 and not apirow["timed_out"]:
 pieces=re.split(br"\r?\n\r?\n",raw,maxsplit=1)
 assert len(pieces)==2 and re.fullmatch(br"HTTP/\S+ 200(?: .*)?",pieces[0].splitlines()[0]),"HTTP200"
 data=json.loads(pieces[1]);runs=data["workflow_runs"]
 assert type(runs)is list and len(runs)<=100,"run page"
 summary["pagination"]={"total_count":data["total_count"],"actual_count":len(runs),"complete":data["total_count"]==len(runs),"page":1,"per_page":100}
 summary["in_progress_runs"]=[{k:r.get(k) for k in ("id","name","path","workflow_id","event","head_branch","head_sha","status","conclusion","run_attempt","created_at","run_started_at","updated_at","html_url","pull_requests")} for r in runs]
else:summary["errors"].append("same-branch in-progress query failed or timed out")
if rows[1]["exit"]!=0:summary["errors"].append("control workflow lookup did not return exact matches")
pin=put(E/"summary.json",(json.dumps(summary,indent=2,sort_keys=True)+"\n").encode())
put(E/"producer.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
print(json.dumps({"summary":pin,"in_progress_runs":summary.get("in_progress_runs"),"pagination":summary.get("pagination"),"control_matches":results[1][1].decode(),"errors":summary["errors"]},sort_keys=True),flush=True)
