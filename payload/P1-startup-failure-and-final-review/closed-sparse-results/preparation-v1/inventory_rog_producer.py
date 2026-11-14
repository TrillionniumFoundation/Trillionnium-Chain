import os,stat,json
from pathlib import Path
B=Path('/home/qian-qi/chain-final-consolidation-20261114-root')
names=['final-repository-truth-offline-6a8cd5-v1','P1-index-flag-diagnostic-v1','P1-sparse-checkout-precorrection-v1','P1-sparse-checkout-correction-v1']
rows=[];tot=0
for name in names:
 root=B/name;assert root.resolve()==root and stat.S_ISDIR(os.lstat(root).st_mode) and not root.is_symlink()
 files=[];dirs=[]
 for at,ds,fs in os.walk(root,followlinks=False):
  p=Path(at);s=os.lstat(p);assert stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode)
  dirs.append(str(p.relative_to(root)))
  for n in ds:
   assert n!='.git';z=os.lstat(p/n);assert stat.S_ISDIR(z.st_mode) and not stat.S_ISLNK(z.st_mode)
  for n in fs:
   q=p/n;z=os.lstat(q);assert stat.S_ISREG(z.st_mode) and z.st_nlink==1 and z.st_size<=16*1024*1024
   files.append({'path':str(q.relative_to(root)),'bytes':z.st_size});tot+=z.st_size
 rows.append({'directory':str(root),'file_count':len(files),'bytes':sum(r['bytes'] for r in files),'directories':dirs,'files':files})
assert tot<=64*1024*1024
print(json.dumps({'scope':names,'file_count':sum(r['file_count'] for r in rows),'total_bytes':tot,'roots':rows,'active_full_v2_read':False},indent=2))
