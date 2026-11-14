import datetime,hashlib,json,os,pathlib,subprocess,sys,time
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1")
SOURCE=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
HEAD="2a86462a1ab20c68151719ba4635e3c294391e64"
TREE="5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"
os.umask(0o077); E.mkdir(mode=0o700,exist_ok=False)
env={k:v for k,v in os.environ.items() if not k.startswith(("GIT_","GH_"))}
env.update(PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",GIT_TRACE="0",GIT_TRACE2="0",GIT_TRACE2_EVENT="0",GIT_TRACE2_PERF="0",PYTHONDONTWRITEBYTECODE="1")
rows=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def put(p,b):
 with p.open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def run(label,args):
 before=datetime.datetime.now(datetime.timezone.utc).isoformat()
 try:
  p=subprocess.run(args,cwd=SOURCE,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
  rc=p.returncode;out=p.stdout;err=p.stderr;timeout=False
 except subprocess.TimeoutExpired as x:
  rc=None;out=x.stdout or b"";err=x.stderr or b"";timeout=True
 assert len(out)+len(err)<=4*1024*1024,"bounded response"
 row={"label":label,"argv":args,"cwd":str(SOURCE),"started_at":before,"finished_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"exit":rc,"timeout":timeout,"stdout":put(E/(label+".stdout"),out),"stderr":put(E/(label+".stderr"),err)}
 rows.append(row)
 put(E/(label+".step.json"),(json.dumps(row,indent=2,sort_keys=True)+"\n").encode())
 assert rc==0 and not timeout,label+" failed"
 return out
commit=run("R1-commit",["/usr/bin/git","cat-file","commit",HEAD])
assert commit.splitlines()[0]==("tree "+TREE).encode(),"R1 tree"
workflow=run("R1-required-workflow",["/usr/bin/git","cat-file","blob",HEAD+":.github/workflows/trnm-required-baseline.yml"])
assert sha(workflow)=="a93a36bf4a93f078b162403825ea45d92dc4a34989f678125bdbc928662da844","fixed workflow"
meta={"schema":"trnm-R1-required-queue-source-read-v1","head":HEAD,"tree":TREE,"steps":rows,"source_or_refs_changed":False,"network_reads":False,"stage_written":False}
put(E/"source-read.json",(json.dumps(meta,indent=2,sort_keys=True)+"\n").encode())
put(E/"capture-source-read.py",sys.orig_argv[sys.orig_argv.index("-c")+1].encode())
print(json.dumps({"directory":str(E),"head":HEAD,"workflow":rows[-1]["stdout"],"status":"READ_ONLY_CAPTURED"}),flush=True)
