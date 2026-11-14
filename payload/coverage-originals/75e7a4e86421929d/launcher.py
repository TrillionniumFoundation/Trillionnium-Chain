import hashlib,os,pathlib,stat,sys
if sys.flags.optimize:raise RuntimeError("optimized pinned launcher")
p=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/probe_history_artifact_explicit_tail_v2.py")
a=p.lstat()
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
if p.resolve(strict=True)!=p or not stat.S_ISREG(a.st_mode)or a.st_nlink!=1 or a.st_size!=17756:raise RuntimeError("reviewed producer scope")
with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),"rb")as f:
 if fp(os.fstat(f.fileno()))!=fp(a):raise RuntimeError("producer open changed")
 raw=f.read(17757)
 if fp(os.fstat(f.fileno()))!=fp(a):raise RuntimeError("producer read changed")
if fp(p.lstat())!=fp(a)or len(raw)!=17756 or hashlib.sha256(raw).hexdigest()!="d5855261347c49727c2879defd5470eb6356b1f0a40679ee89d1c258adb25513":raise RuntimeError("reviewed producer bytes differ")
os.environ.pop("GH_DEBUG",None)
os.environ["GH_HOST"]="github.com"
os.umask(0o077)
D=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/history-explicit-tail-range-probe-v2-launch-001");D.mkdir(mode=0o700,exist_ok=False)
with (D/"launcher.py").open("xb")as f:f.write(sys.argv[1].encode());f.flush();os.fsync(f.fileno())
sys.argv=["/private/tmp/chain-consolidation-20261114-root/probe_history_artifact_explicit_tail_v2.py"]
exec(compile(raw,str(p),"exec",optimize=0),{"__name__":"__main__","__file__":str(p)})
