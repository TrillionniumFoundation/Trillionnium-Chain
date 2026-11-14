import concurrent.futures,hashlib,json,os,pathlib,selectors,signal,subprocess,time,datetime
ROOT=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1")
D=ROOT/"required-pagination-GET-v1";D.mkdir(mode=0o700)
GH="/opt/homebrew/bin/gh";repo="repos/TrillionniumFoundation/Trillionnium-Chain"
env=os.environ.copy()
for k in list(env):
 if k.startswith("GIT_TRACE") or k in ("GH_DEBUG","GIT_CURL_VERBOSE","CURL_VERBOSE"):env.pop(k,None)
env.update({"GH_PROMPT_DISABLED":"1","GH_NO_UPDATE_NOTIFIER":"1","GH_PAGER":"cat","PAGER":"cat"})
calls=[
 ("N2-check-runs-page2",repo+"/commits/096c6b5f9b952c49389fd975515744074ba61317/check-runs?filter=latest&per_page=100&page=2",90,8*1024*1024),
 ("N2-required-workflow-run",repo+"/actions/runs/43588788281",90,8*1024*1024),
 ("N2-required-workflow-jobs",repo+"/actions/runs/43588788281/jobs?filter=latest&per_page=100&page=1",90,8*1024*1024),
 ("N-required-workflow-jobs",repo+"/actions/runs/43582713392/jobs?filter=latest&per_page=100&page=1",90,8*1024*1024)
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
with (D/"summary.json").open("xb") as f:f.write((json.dumps({"schema":"trnm-N2-required-complete-pagination-GET-v1","rows":rows,"only_GET":True},sort_keys=True,indent=2)+"\n").encode())
print(json.dumps({"directory":str(D),"requests":[{"name":x["name"],"exit_code":x["exit_code"],"complete_capture":x["complete_capture"],"stdout":x["stdout"]} for x in rows]},sort_keys=True))
