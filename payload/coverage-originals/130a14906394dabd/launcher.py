import hashlib,os,pathlib,stat,sys
if sys.flags.optimize:raise RuntimeError("optimized pinned launcher")
p=pathlib.Path("/private/tmp/chain-prci-R1-history-selected-member-reader-preparation-20261114-v1/read_history_artifact_selected_members_v1.py")
a=p.lstat()
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
if p.resolve(strict=True)!=p or not stat.S_ISREG(a.st_mode)or a.st_nlink!=1 or a.st_size!=23040:raise RuntimeError("reviewed producer scope")
with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),"rb")as f:
 if fp(os.fstat(f.fileno()))!=fp(a):raise RuntimeError("producer open changed")
 raw=f.read(23041)
 if fp(os.fstat(f.fileno()))!=fp(a):raise RuntimeError("producer read changed")
if fp(p.lstat())!=fp(a)or len(raw)!=23040 or hashlib.sha256(raw).hexdigest()!="1cee9d0f0e321e4e367d65fe5ba48880a0efef423f034b176e649c17481adef6":raise RuntimeError("reviewed producer bytes differ")
os.environ.pop("GH_DEBUG",None)
os.environ["GH_HOST"]="github.com"
os.umask(0o077)
D=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/R1-history-selected-members-launch-001");D.mkdir(mode=0o700,exist_ok=False)
with (D/"launcher.py").open("xb")as f:f.write(sys.argv[1].encode());f.flush();os.fsync(f.fileno())
sys.argv=["/private/tmp/chain-prci-R1-history-selected-member-reader-preparation-20261114-v1/read_history_artifact_selected_members_v1.py"]
exec(compile(raw,str(p),"exec",optimize=0),{"__name__":"__main__","__file__":str(p)})
