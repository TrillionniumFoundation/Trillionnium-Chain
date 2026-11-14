import hashlib,os,stat,sys
from pathlib import Path
p=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1/selected-resume-001-producer.py')
a=p.lstat()
if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or p.resolve(strict=True)!=p:raise SystemExit('PRODUCER_TYPE')
flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
with os.fdopen(os.open(p,flags),'rb')as f:
 b=f.read(29179);z=os.fstat(f.fileno())
fp=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
if fp(a)!=fp(z) or fp(a)!=fp(p.lstat()) or len(b)!=29178 or hashlib.sha256(b).hexdigest()!='aedf670225c743f11eb55588b441faa1000f882a18eaa2e4b8e3e903e406e578':raise SystemExit('PRODUCER_PIN')
if sys.flags.optimize:raise SystemExit('OPTIMIZATION_FORBIDDEN')
sys.argv=[str(p)]
exec(compile(b,str(p),'exec',dont_inherit=True,optimize=0),{'__name__':'__main__','__file__':str(p)})
