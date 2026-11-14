import concurrent.futures,datetime,hashlib,json,os,pathlib,re,stat,subprocess,sys,time
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/dependent-and-controls-v1")
SOURCE=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
READY=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/R1-required-ci-progress-v1-ready-003")
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64"
os.umask(0o077);E.mkdir(mode=0o700,exist_ok=False)
env={k:v for k,v in os.environ.items() if not k.startswith("GIT_") and k!="GH_DEBUG"}
env.update(PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",GIT_TRACE="0",GIT_TRACE2="0",GIT_TRACE2_EVENT="0",GIT_TRACE2_PERF="0",GH_PROMPT_DISABLED="1",PYTHONDONTWRITEBYTECODE="1")
def sha(b):return hashlib.sha256(b).hexdigest()
def put(p,b):
 with p.open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def read(p):
 a=p.lstat();assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=2*1024*1024 and p.resolve()==p
 with p.open("rb") as f:
  before=os.fstat(f.fileno());b=f.read(2*1024*1024+1);after=os.fstat(f.fileno())
 assert before==after==p.lstat() and len(b)==a.st_size
 return b
raw=read(READY/"R1-latest-checks-normalized.json")
assert len(raw)==118519 and sha(raw)=="23c960035321326b79afb463bf388b03af73d2cf6ca7874c79ae7f121df2832a"
data=json.loads(raw)
assert type(data)is list,"normalized checks list"
failures=[x for x in data if x.get("conclusion")=="failure"]
ready_pin=put(E/"ready003-latest-checks-normalized.original.json",raw)
put(E/"ready003-failures.json",(json.dumps({"source":ready_pin,"failures":failures},indent=2,sort_keys=True)+"\n").encode())
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
items=[
("N2-required-43588788281-jobs-page-001",["/opt/homebrew/bin/gh","api","--hostname","github.com","--include","--method","GET","-H","Accept: application/vnd.github+json","-H","X-GitHub-Api-Version: 2026-03-10","repos/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43588788281/jobs?filter=all&per_page=100&page=1"],120),
("R1-pon-budget-controls-workflow",["/usr/bin/git","cat-file","blob",HEAD+":.github/workflows/pon-budget-controls.yml"],30),
("R1-pon-priority-acceptance-workflow",["/usr/bin/git","cat-file","blob",HEAD+":.github/workflows/pon-priority-acceptance.yml"],30)]
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(run,items))
summary={"schema":"trnm-R1-required-dependency-and-control-read-v1","head":HEAD,"steps":[x[0] for x in results],"ready003_source":ready_pin,"ready003_failures":failures,"errors":[],"network_GETs":1,"mutations":False}
row,body=results[0]
if row["exit"]==0 and not row["timed_out"]:
 parts=re.split(br"\r?\n\r?\n",body,maxsplit=1)
 assert len(parts)==2 and re.fullmatch(br"HTTP/\S+ 200(?: .*)?",parts[0].splitlines()[0]),"HTTP200"
 api=json.loads(parts[1]);jobs=api["jobs"]
 summary["jobs_pagination"]={"reported_total":api["total_count"],"actual":len(jobs),"complete":api["total_count"]==len(jobs)}
 summary["old_N2_jobs"]=[{k:j.get(k) for k in ("id","name","run_id","run_attempt","head_sha","status","conclusion","started_at","completed_at","runner_name","labels","steps")} for j in jobs]
else:summary["errors"].append("old N2 jobs query failed")
pin=put(E/"summary.json",(json.dumps(summary,indent=2,sort_keys=True)+"\n").encode())
put(E/"producer.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
running=[j for j in summary.get("old_N2_jobs",[]) if j["status"]!="completed"]
print(json.dumps({"summary":pin,"ready003_failures":failures,"N2_nonterminal_jobs":running,"pagination":summary.get("jobs_pagination"),"errors":summary["errors"]},sort_keys=True),flush=True)
