import os,sys,stat,hashlib
from pathlib import Path
p=Path('/private/tmp/chain-H5DF-arm64-cross-cost-original-evidence-20261114-v1/producer.py')
a=p.lstat()
if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size!=10764 or p.resolve()!=p:raise ValueError('producer shape')
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
with os.fdopen(fd,'rb') as f:
 b=f.read(10765);z=os.fstat(f.fileno())
if (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns) or p.lstat()!=z:raise ValueError('producer changed')
if len(b)!=10764 or hashlib.sha256(b).hexdigest()!='cb327032b629d3a4b7231892cb88720273e257b469a759893f8f0d7c10134e83':raise ValueError('producer pin')
sys.argv=[str(p)]
exec(compile(b,str(p),'exec'),{'__name__':'__main__','__file__':str(p)})
