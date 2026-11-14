import hashlib,json,os,pathlib,stat,sys
p=pathlib.Path("/private/tmp/chain-prci-R1-ci-progress-reader-preparation-20261114-v1/read_R1_required_ci_progress_v1.py")
n=19408;digest="8d3a5cba653cd53caa4144d71193e4b7ff3faf49f4a10a1ebce45940eb072503"
def need(c,m):
 if not c:raise ValueError(m)
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
need(sys.flags.optimize==0,"optimized launcher forbidden")
need(p.resolve(strict=True)==p,"canonical approved reader")
s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==n,"approved regular single-link reader")
with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb")as f:
 need(fp(os.fstat(f.fileno()))==fp(s),"reader before")
 b=f.read(n+1);need(fp(os.fstat(f.fileno()))==fp(s),"reader during")
need(fp(p.lstat())==fp(s) and len(b)==n and hashlib.sha256(b).hexdigest()==digest,"approved reader SHA/version")
ev="/private/tmp/chain-consolidation-20261114-root/R1-required-ci-progress-v1-ready-017"
need(not pathlib.Path(ev).exists(),"create-only snapshot already exists")
env=os.environ.copy();env.pop("GH_DEBUG",None);env["GH_HOST"]="github.com";env["PYTHONDONTWRITEBYTECODE"]="1";env["PYTHONOPTIMIZE"]="0"
argv=[sys.executable,"-B",str(p),"--evidence-dir",ev]
print(json.dumps({"phase":"approved_reader_hash_verified","reader":{"path":str(p),"bytes":n,"sha256":digest},"argv":argv,"GH_DEBUG_removed":True,"GH_HOST":"github.com","snapshot":ev,"automatic_polling":False}),flush=True)
need(fp(p.lstat())==fp(s),"reader changed before exec")
os.execve(sys.executable,argv,env)
