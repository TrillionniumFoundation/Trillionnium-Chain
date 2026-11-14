import hashlib,os,stat,sys
from pathlib import Path
p=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1/selected-producer.py')
a=p.lstat()
if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or p.resolve(strict=True)!=p:raise SystemExit('PRODUCER_TYPE')
flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
with os.fdopen(os.open(p,flags),'rb')as f:
 b=f.read(26266);z=os.fstat(f.fileno())
fp=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
if fp(a)!=fp(z) or fp(a)!=fp(p.lstat()) or len(b)!=26265 or hashlib.sha256(b).hexdigest()!='016e306f086be343fb59d2b6f47c1fb39053c0ea90b53ec87ebb96b46354a717':raise SystemExit('PRODUCER_PIN')
if sys.flags.optimize:raise SystemExit('OPTIMIZATION_FORBIDDEN')
sys.argv=[str(p)]
exec(compile(b,str(p),'exec',dont_inherit=True,optimize=0),{'__name__':'__main__','__file__':str(p)})
