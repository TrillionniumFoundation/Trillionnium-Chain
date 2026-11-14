import concurrent.futures,datetime,hashlib,json,os,pathlib,re,signal,subprocess,sys,time
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/R1-W1-failure-raw-logs-v2")
SOURCE=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
os.umask(0o077);E.mkdir(mode=0o700,exist_ok=False)
env={k:v for k,v in os.environ.items() if not k.startswith("GIT_") and k!="GH_DEBUG"}
env.update(PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",GH_PROMPT_DISABLED="1",PYTHONDONTWRITEBYTECODE="1")
MAX=16*1024*1024
def sha(b):return hashlib.sha256(b).hexdigest()
def put(p,b):
 with p.open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def get(job):
 label="job-"+str(job)+"-original-log"
 args=["/opt/homebrew/bin/gh","api","--hostname","github.com","--method","GET","-H","Accept: application/vnd.github+json","-H","X-GitHub-Api-Version: 2026-03-10","repos/TrillionniumFoundation/Trillionnium-Chain/actions/jobs/"+str(job)+"/logs"]
 paths=[E/(label+"."+s) for s in ("stdout","stderr")]
 start=datetime.datetime.now(datetime.timezone.utc).isoformat();clock=time.monotonic()
 row={"job_id":job,"argv":args,"cwd":str(SOURCE),"started_at":start,"timeout_seconds":120,"max_stream_bytes":MAX,"timed_out":False,"limit_exceeded":False,"capture_error":None,"exit":None}
 p=None
 with paths[0].open("xb") as out,paths[1].open("xb") as err:
  try:
   p=subprocess.Popen(args,cwd=SOURCE,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
   row["owned_pid"]=p.pid
   while p.poll()is None:
    row["limit_exceeded"]=any(x.stat().st_size>MAX for x in paths)
    row["timed_out"]=time.monotonic()-clock>=120
    if row["limit_exceeded"] or row["timed_out"]:
     os.killpg(p.pid,signal.SIGTERM)
     try:p.wait(timeout=5)
     except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)
     break
    time.sleep(.1)
   row["exit"]=p.returncode
  except Exception as x:
   row["capture_error"]=type(x).__name__+": "+str(x)
   if p is not None and p.poll()is None:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)
  finally:
   out.flush();err.flush();os.fsync(out.fileno());os.fsync(err.fileno())
 row["finished_at"]=datetime.datetime.now(datetime.timezone.utc).isoformat()
 row["elapsed_seconds"]=round(time.monotonic()-clock,3)
 bodies=[]
 for channel,path in zip(("stdout","stderr"),paths):
  raw=path.read_bytes();bodies.append(raw);row[channel]={"path":str(path),"bytes":len(raw),"sha256":sha(raw)}
 row["limit_exceeded"]|=any(len(b)>MAX for b in bodies)
 row["complete_read"]=row["exit"]==0 and not row["timed_out"] and not row["limit_exceeded"] and row["capture_error"]is None
 step=put(E/(label+".step.json"),(json.dumps(row,indent=2,sort_keys=True)+"\n").encode())
 extraction={"job_id":job,"raw":row["stdout"],"complete_read":row["complete_read"],"source_objects":[],"signal_contexts":[]}
 if row["complete_read"]:
  text=bodies[0].decode("utf-8")
  lines=text.splitlines()
  clean=[re.sub(r"^\d{4}-\d{2}-\d{2}T\S+Z\s?","",x) for x in lines]
  for i,line in enumerate(clean):
   if "trnm-ci-source-v1" in line and "{" in line:
    try:
     val=json.JSONDecoder().raw_decode(line[line.index("{"):])[0]
     if type(val)is dict and val.get("schema")=="trnm-ci-source-v1":extraction["source_objects"].append({"raw_line":i+1,"value":val})
    except (ValueError,json.JSONDecodeError): pass
  targets=[i for i,line in enumerate(clean) if re.search(r"Traceback|AssertionError|CONFIRMATION_TARGET|PUBLIC_REQUEST_DEADLINE|FAILED|^error:|^Error:|##\[error\]|SystemExit",line)]
  groups=[]
  for idx in targets:
   lo=max(0,idx-4);hi=min(len(lines),idx+12)
   if groups and lo<=groups[-1][1]:groups[-1][1]=max(hi,groups[-1][1])
   else:groups.append([lo,hi])
  extraction["signal_contexts"]=[{"first_line":lo+1,"last_line":hi,"text":"\n".join(lines[lo:hi])} for lo,hi in groups]
  extraction["line_count"]=len(lines);extraction["tail"]="\n".join(lines[-35:])
  extraction["pattern_hits"]=len(targets)
 pin=put(E/(label+".extraction.json"),(json.dumps(extraction,indent=2,sort_keys=True)+"\n").encode())
 return row,extraction,pin
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:values=list(pool.map(get,(132475259337,132475258996)))
summary={"schema":"trnm-R1-W1-failed-job-raw-log-read-v1","steps":[v[0] for v in values],"extractions":[v[2] for v in values],"all_complete":all(v[0]["complete_read"] for v in values),"network_mutations":False,"native_executed":False,"source_or_refs_or_stage_changed":False}
pin=put(E/"summary.json",(json.dumps(summary,indent=2,sort_keys=True)+"\n").encode())
put(E/"producer.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
print(json.dumps({"summary":pin,"logs":[{"job":v[0]["job_id"],"complete":v[0]["complete_read"],"stdout":v[0]["stdout"],"source_objects":v[1]["source_objects"],"signals":v[1]["signal_contexts"][:12],"extraction":v[2]} for v in values]},sort_keys=True),flush=True)
