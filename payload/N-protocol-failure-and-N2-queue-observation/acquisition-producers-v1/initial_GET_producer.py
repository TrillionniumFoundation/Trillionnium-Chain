import concurrent.futures,hashlib,json,os,pathlib,selectors,signal,subprocess,time,datetime
ROOT=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1")
ROOT.mkdir(mode=0o700)
D=ROOT/"initial-GET-v1";D.mkdir(mode=0o700)
GH="/opt/homebrew/bin/gh"
assert pathlib.Path(GH).is_file()
env=os.environ.copy()
for k in list(env):
 if k.startswith("GIT_TRACE") or k in ("GH_DEBUG","GIT_CURL_VERBOSE","CURL_VERBOSE"):env.pop(k,None)
env.update({"GH_PROMPT_DISABLED":"1","GH_NO_UPDATE_NOTIFIER":"1","GH_PAGER":"cat","PAGER":"cat"})
repo="repos/TrillionniumFoundation/Trillionnium-Chain"
calls=[
 ("pr847",repo+"/pulls/847",90,8*1024*1024),
 ("N-run43582713392",repo+"/actions/runs/43582713392",90,8*1024*1024),
 ("job132415017391",repo+"/actions/jobs/132415017391",90,8*1024*1024),
 ("job132415017476",repo+"/actions/jobs/132415017476",90,8*1024*1024),
 ("main-required-status-checks",repo+"/branches/main/protection/required_status_checks",90,8*1024*1024),
 ("job132415017391-original-log",repo+"/actions/jobs/132415017391/logs",120,32*1024*1024),
 ("job132415017476-original-log",repo+"/actions/jobs/132415017476/logs",120,32*1024*1024)
]
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def capture(spec):
 name,endpoint,budget,cap=spec
 argv=[GH,"api","--hostname","github.com","--method","GET","-H","Accept: application/vnd.github+json","-H","X-GitHub-Api-Version: 2022-11-28",endpoint]
 out=D/(name+".stdout");err=D/(name+".stderr")
 begin=utc();clock=time.monotonic();limits={"stdout":cap,"stderr":1048576};counts={"stdout":0,"stderr":0};flags=[];killed=False
 with out.open("xb") as fo,err.open("xb") as fe:
  p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd="/private/tmp",env=env,start_new_session=True)
  selector=selectors.DefaultSelector()
  for pipe,label,f in [(p.stdout,"stdout",fo),(p.stderr,"stderr",fe)]:
   os.set_blocking(pipe.fileno(),False);selector.register(pipe,selectors.EVENT_READ,(label,f))
  while selector.get_map():
   if time.monotonic()-clock>budget and not killed:
    flags.append("DOWNLOAD_TIMEOUT");os.killpg(p.pid,signal.SIGKILL);killed=True
   for key,_ in selector.select(0.2):
    block=os.read(key.fileobj.fileno(),65536)
    if not block:
     selector.unregister(key.fileobj);key.fileobj.close();continue
    label,f=key.data;remaining=limits[label]-counts[label]
    if len(block)>remaining:
     if remaining>0:f.write(block[:remaining]);counts[label]+=remaining
     if not killed:os.killpg(p.pid,signal.SIGKILL);killed=True
     if "OUTPUT_CAP_EXCEEDED" not in flags:flags.append("OUTPUT_CAP_EXCEEDED")
    else:f.write(block);counts[label]+=len(block)
  selector.close();code=p.wait(timeout=10)
  fo.flush();fe.flush();os.fsync(fo.fileno());os.fsync(fe.fileno())
 row={"name":name,"argv":argv,"method":"GET","started_at":begin,"finished_at":utc(),"budget_seconds":budget,"elapsed_seconds":time.monotonic()-clock,"exit_code":code,"bounded_capture_errors":flags,"complete_capture":not flags,"stdout":{},"stderr":{}}
 for label,path in [("stdout",out),("stderr",err)]:
  b=path.read_bytes();row[label]={"path":str(path),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
 with (D/(name+".receipt.json")).open("xb") as f:f.write((json.dumps(row,indent=2,sort_keys=True)+"\n").encode())
 return row
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:rows=list(pool.map(capture,calls))
summary={"schema":"trnm-N-protocol-readonly-GET-acquisition-v1","scope":"PR847 current metadata, original N workflow/two jobs, main required status-check config, and only two completed original logs.","remote_mutations":False,"source_git_stage_tests_mutated":False,"jobs":rows,"requests_complete":all(x["complete_capture"] for x in rows)}
with (D/"summary.json").open("xb") as f:f.write((json.dumps(summary,indent=2,sort_keys=True)+"\n").encode())
print(json.dumps({"directory":str(D),"requests":[{"name":x["name"],"exit_code":x["exit_code"],"complete_capture":x["complete_capture"],"stdout":x["stdout"],"stderr":x["stderr"],"elapsed_seconds":x["elapsed_seconds"]} for x in rows]},sort_keys=True))
