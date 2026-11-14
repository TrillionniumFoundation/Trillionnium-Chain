import hashlib,os,pathlib,stat,sys
if sys.flags.optimize:raise RuntimeError("optimized pinned launcher")
p=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/R1-diagnostic-tag-dispatch-only-preparation-v1/dispatch_published_r1_stage1_v1.py")
a=p.lstat()
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
if p.resolve(strict=True)!=p or not stat.S_ISREG(a.st_mode)or a.st_nlink!=1 or a.st_size!=30284:raise RuntimeError("reviewed producer scope")
with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),"rb")as f:
 if fp(os.fstat(f.fileno()))!=fp(a):raise RuntimeError("producer open changed")
 raw=f.read(30285)
 if fp(os.fstat(f.fileno()))!=fp(a):raise RuntimeError("producer read changed")
if fp(p.lstat())!=fp(a)or len(raw)!=30284 or hashlib.sha256(raw).hexdigest()!="bf25839cb805e1005192125a1de5b916bf3017825465fff866ec6533fdb09dac":raise RuntimeError("reviewed producer bytes differ")
os.environ.pop("GH_DEBUG",None)
os.environ["GH_HOST"]="github.com"
os.umask(0o077)
D=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/R1-diagnostic-dispatch-only-actual-launch-v1");D.mkdir(mode=0o700,exist_ok=False)
with (D/"launcher.py").open("xb")as f:f.write(sys.argv[1].encode());f.flush();os.fsync(f.fileno())
sys.argv=["/private/tmp/chain-consolidation-20261114-root/R1-diagnostic-tag-dispatch-only-preparation-v1/dispatch_published_r1_stage1_v1.py","--spec","/private/tmp/chain-consolidation-20261114-root/R1-diagnostic-tag-dispatch-only-preparation-v1/spec.for-review.json","--spec-bytes","2356","--spec-sha256","46f67594e5ebea6efc26eb67fa24b52ff642efd755c7476cfb0e8ffdd8b8794b"]
exec(compile(raw,str(p),"exec",optimize=0),{"__name__":"__main__","__file__":str(p)})
