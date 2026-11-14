import concurrent.futures,datetime,hashlib,json,os,pathlib,re,stat,subprocess
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
OUT=ROOT/"postpublication-remote-refs-snapshot-v1"
PIN=json.loads("{\"path\":\"/private/tmp/chain-consolidation-20261114-root/resume-followup-candidate-execution-2a8646-parallel-hook-v1/summary.json\",\"bytes\":231108,\"sha256\":\"b50fe85416de9efdacf58624236c01a6bd638185ccaae4da7ce9bd198311a04b\"}")
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def need(b,m):
 if not b:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def write(n,b):
 p=OUT/n
 with p.open("xb")as f:f.write(b);f.flush();os.fsync(f.fileno())
 return dict(path=str(p),bytes=len(b),sha256=sha(b))
p=pathlib.Path(PIN["path"]);a=p.lstat();raw=p.read_bytes();b=p.lstat()
need(p.resolve(strict=True)==p and stat.S_ISREG(a.st_mode)and a.st_nlink==1 and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)and len(raw)==PIN["bytes"]and sha(raw)==PIN["sha256"],"original publication pin")
old=json.loads(raw)["remote_after"]
os.umask(0o077);OUT.mkdir(mode=0o700,exist_ok=False)
write("reader.py",__import__("sys").argv[1].encode())
env=dict(os.environ);env.pop("GH_DEBUG",None);env.update(GIT_TERMINAL_PROMPT="0",GIT_OPTIONAL_LOCKS="0",GH_HOST="github.com")
url="https://github.com/TrillionniumFoundation/Trillionnium-Chain.git"
tasks=[("heads",["/usr/bin/git","ls-remote","--heads",url]),("tags",["/usr/bin/git","ls-remote",url,*old["tags"].keys()])]
def run(item):
 label,argv=item;v=dict(label=label,argv=argv,started_at=now(),automatic_retry=False,timeout_seconds=120)
 try:
  p=subprocess.run(argv,cwd="/private/tmp",env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
  out,err=p.stdout,p.stderr;v.update(exit=p.returncode,complete_transport=True)
 except subprocess.TimeoutExpired as e:
  out,err=e.stdout or b"",e.stderr or b"";v.update(exit=None,complete_transport=False,error="TimeoutExpired")
 need(len(out)<=4194304 and len(err)<=1048576,"remote read bound")
 v.update(finished_at=now(),stdout=write(label+".stdout",out),stderr=write(label+".stderr",err))
 refs={}
 if v["complete_transport"]and v["exit"]==0:
  for line in out.decode("utf-8").splitlines():
   oid,ref=line.split("\t")
   need(re.fullmatch("[0-9a-f]{40}",oid)is not None and ref not in refs,"unique exact ref record")
   if label=="heads":need(ref.startswith("refs/heads/"),"head namespace");ref=ref[len("refs/heads/"):]
   refs[ref]=oid
 return v,refs
started=now()
with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:rows=list(pool.map(run,tasks))
readok=all(v["complete_transport"]and v["exit"]==0 for v,_ in rows)
observed={v["label"]:m for v,m in rows}
same=readok and observed=={"heads":old["heads"],"tags":old["tags"]}
result=dict(schema="trnm-postpublication-remote-refs-readonly-v1",status="OBSERVED_UNCHANGED"if same else"OBSERVED_CHANGED"if readok else"UNKNOWN",started_at=started,finished_at=now(),steps=[v for v,_ in rows],original_publication=PIN,observations_non_atomic=True,head_count=len(observed["heads"])if readok else None,main=observed["heads"].get("main")if readok else None,candidate=observed["heads"].get("fix/chain-hepta-closure-candidate-20261109-481716")if readok else None,heads_and_two_archives_match_publication=same,observed=observed,network_readonly=True,source_refs_rules_or_CI_modified=False,merge_or_cleanup_executed=False)
pin=write("summary.json",(json.dumps(result,sort_keys=True,indent=2)+"\n").encode())
print(json.dumps(dict(status=result["status"],head_count=result["head_count"],main=result["main"],candidate=result["candidate"],summary=pin),sort_keys=True))
