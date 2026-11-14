import datetime,hashlib,json,os,pathlib,stat,sys,time,traceback
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
LAUNCH=ROOT/"H5DF-required-ci-progress-ready003-launch-v1"
OUT=ROOT/"H5DF-required-ci-progress-v1-ready-003"
P=pathlib.Path("/private/tmp/chain-prci-head-5df7ae6-ci-progress-preparation-20261114-v1/read_head5df_required_ci_progress_v1.py")
SIZE=19479;SHA="3f50aa71fa06f37e64c1ed1e669ad1b1b45ebe27acfddb5004957ef3a43c68fb"
def need(v,m):
    if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,indent=2,sort_keys=True)+"\n").encode()
def fp(s):return s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
need(not sys.flags.optimize and sys.dont_write_bytecode,"no optimize/pyc")
need(ROOT.resolve(strict=True)==ROOT and not LAUNCH.exists() and not LAUNCH.is_symlink()
     and not OUT.exists() and not OUT.is_symlink(),"unique create-only directories")
need(P.resolve(strict=True)==P,"canonical collector")
s=P.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==SIZE,"pinned ordinary collector")
fd=os.open(P,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
    need(fp(os.fstat(fd))==fp(s),"collector open identity")
    with os.fdopen(fd,"rb",closefd=False) as f:raw=f.read(SIZE+1)
    need(fp(os.fstat(fd))==fp(s),"collector stable FD")
finally:os.close(fd)
need(fp(P.lstat())==fp(s) and len(raw)==SIZE and sha(raw)==SHA,"collector bytes/version")
os.umask(0o077);LAUNCH.mkdir(mode=0o700,exist_ok=False)
def save(name,b):
    p=LAUNCH/name
    with p.open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
    return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
save("launcher.py",sys.argv[1].encode())
save("pinned-collector.py.original",raw)
removed_GH_DEBUG="GH_DEBUG" in os.environ
os.environ.pop("GH_DEBUG",None);os.environ["GH_HOST"]="github.com"
os.environ["PYTHONDONTWRITEBYTECODE"]="1";os.environ["PYTHONOPTIMIZE"]="0"
args=[str(P),"--evidence-dir",str(OUT)]
meta={"schema":"trnm-H5DF-required-reader-pinned-launch-v1","started_at":now(),"producer":{"path":str(P),"bytes":SIZE,"sha256":SHA},
 "argv":args,"executable":sys.executable,"cwd":os.getcwd(),"output":str(OUT),
 "source_version":fp(s),"GH_DEBUG_removed":removed_GH_DEBUG,"GH_HOST":"github.com",
 "GET_only_source_reviewed":True,"automatic_retry":False,"original_overall_budget_seconds":240,"original_max_GET_workers":4,
 "source_Git_index_refs_not_modified":True,"CI_mutations_authorized":False}
save("launch.json",enc(meta));save("pin-check.json",enc({"source":meta["producer"],"version":fp(s),"validated":True}))
tick=time.monotonic();exit_code=None;error=None
try:
    sys.argv=args
    exec(compile(raw,str(P),"exec",optimize=0),{"__name__":"__main__","__file__":str(P)})
    exit_code=0
except SystemExit as exc:
    exit_code=exc.code if type(exc.code) is int else (0 if exc.code is None else 1)
except BaseException as exc:
    exit_code=1;error={"type":type(exc).__name__,"message":str(exc)}
    save("exception.txt",traceback.format_exc().encode())
finally:
    unchanged=fp(P.lstat())==fp(s) and P.read_bytes()==raw
    result={"schema":"trnm-H5DF-required-reader-pinned-launch-result-v1","finished_at":now(),
      "collector_exit":exit_code,"collector_error":error,"collector_source_unchanged":unchanged,
      "elapsed_seconds":round(time.monotonic()-tick,3),"output":str(OUT),"automatic_retry":False}
    pin=save("result.json",enc(result))
    print(json.dumps({"launcher_result":pin,"collector_exit":exit_code,"source_unchanged":unchanged}),flush=True)
sys.exit(exit_code if unchanged else 1)
