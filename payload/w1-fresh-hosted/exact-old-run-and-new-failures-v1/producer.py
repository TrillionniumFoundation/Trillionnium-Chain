import concurrent.futures,datetime,hashlib,json,os,pathlib,re,stat,subprocess,sys,time
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/exact-old-run-and-new-failures-v1")
SOURCE=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64";N2="096c6b5f9b952c49389fd975515744074ba61317"
API="repos/TrillionniumFoundation/Trillionnium-Chain"
os.umask(0o077);E.mkdir(mode=0o700,exist_ok=False)
env={k:v for k,v in os.environ.items() if not k.startswith("GIT_") and k!="GH_DEBUG"}
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
 except subprocess.TimeoutExpired as x:rc=None;out=x.stdout or b"";err=x.stderr or b"";timed=True
 row={"label":label,"argv":args,"cwd":str(SOURCE),"started_at":start,"finished_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"elapsed_seconds":round(time.monotonic()-clock,3),"timeout_seconds":timeout,"exit":rc,"timed_out":timed,"stdout":put(E/(label+".stdout"),out),"stderr":put(E/(label+".stderr"),err)}
 put(E/(label+".step.json"),(json.dumps(row,indent=2,sort_keys=True)+"\n").encode())
 assert len(out)+len(err)<=8*1024*1024,"response bound"
 return row,out
def query(label,endpoint):return(label,["/opt/homebrew/bin/gh","api","--hostname","github.com","--include","--method","GET","-H","Accept: application/vnd.github+json","-H","X-GitHub-Api-Version: 2026-03-10",API+endpoint],120)
def body(result):
 row,raw=result;assert row["exit"]==0 and not row["timed_out"],row["label"]
 pieces=re.split(br"\r?\n\r?\n",raw,maxsplit=1)
 assert len(pieces)==2 and re.fullmatch(br"HTTP/\S+ 200(?: .*)?",pieces[0].splitlines()[0]),"HTTP200"
 return json.loads(pieces[1])
items=[query("N2-run-43588788281-metadata","/actions/runs/43588788281"),
query("R1-W1-head-job-132475259337","/actions/jobs/132475259337"),
query("R1-W1-merge-job-132475258996","/actions/jobs/132475258996"),
("N2-required-workflow",["/usr/bin/git","cat-file","blob",N2+":.github/workflows/trnm-required-baseline.yml"],30),
("R1-W1-fresh-workflow-match",["/usr/bin/git","grep","-n","-F","W1 fresh challenge service",HEAD,"--",".github/workflows"],30)]
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(run,items))
rows=[x[0] for x in results]
old=body(results[0]);headjob=body(results[1]);mergejob=body(results[2])
assert old["id"]==43588788281 and old["head_sha"]==N2 and old["workflow_id"]==345677268 and old["event"]=="pull_request"
assert any(x.get("number")==847 for x in old["pull_requests"])
assert sha(results[3][1])=="a93a36bf4a93f078b162403825ea45d92dc4a34989f678125bdbc928662da844","N2 required differs from R1"
assert rows[4]["exit"]==0,"W1 workflow match"
paths=sorted(set(line.split(":")[1] for line in results[4][1].decode().splitlines()))
assert len(paths)==1 and re.fullmatch(r"\.github/workflows/[A-Za-z0-9_-]+\.ya?ml",paths[0]),"one exact W1 workflow"
w1=run(("R1-W1-fresh-workflow",["/usr/bin/git","cat-file","blob",HEAD+":"+paths[0]],30))
rows.append(w1[0]);assert w1[0]["exit"]==0,"W1 workflow read"
dep_path=E.parent/"dependent-and-controls-v1/summary.json";dep_raw=dep_path.read_bytes();dep=json.loads(dep_raw)
running=[j for j in dep["old_N2_jobs"] if j["status"]!="completed"]
for j in running:
 j["active_steps"]=[x for x in j.pop("steps") if x["status"]=="in_progress"]
 j["original_job_timeout_minutes"]=180
 j["nominal_job_deadline"]=(datetime.datetime.fromisoformat(j["started_at"].replace("Z","+00:00"))+datetime.timedelta(minutes=180)).isoformat()
view={k:old.get(k) for k in ("id","name","path","workflow_id","event","head_branch","head_sha","status","conclusion","run_attempt","created_at","run_started_at","updated_at","html_url","actor","triggering_actor","pull_requests")}
jobs=[{k:j.get(k) for k in ("id","run_id","run_attempt","head_sha","name","status","conclusion","started_at","completed_at","steps")} for j in (headjob,mergejob)]
summary={"schema":"trnm-R1-required-queue-exact-old-and-failure-observation-v1","steps":rows,"old_run":view,"old_N2_jobs_source":{"path":str(dep_path),"bytes":len(dep_raw),"sha256":sha(dep_raw)},"old_nonterminal_jobs":running,"N2_R1_required_workflow_identical":True,"new_failure_jobs":jobs,"W1_workflow_path":paths[0],"errors":[],"network_GETs":3,"mutations":False,"diagnosis":"Same workflow/ref group is occupied by old N2; R1 pending has no jobs. Timing is inferred from original job timeout, not a guaranteed future workflow completion."}
pin=put(E/"summary.json",(json.dumps(summary,indent=2,sort_keys=True)+"\n").encode())
put(E/"producer.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
print(json.dumps({"summary":pin,"old_run":{k:view[k] for k in ("id","head_sha","status","workflow_id","run_attempt","created_at","run_started_at")},"actor":old["actor"]["login"],"triggering_actor":old["triggering_actor"]["login"],"remaining":[{k:j[k] for k in ("id","name","started_at","active_steps","nominal_job_deadline")} for j in running],"new_failed_steps":[{"id":j["id"],"name":j["name"],"steps":[s for s in j["steps"] if s["conclusion"]=="failure"]} for j in jobs],"W1_workflow":paths[0]},sort_keys=True),flush=True)
