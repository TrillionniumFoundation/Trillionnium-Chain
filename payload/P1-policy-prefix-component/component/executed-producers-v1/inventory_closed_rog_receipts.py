import pathlib,stat,json,hashlib,os
B=pathlib.Path('/home/qian-qi/chain-final-consolidation-20261114-root')
roots=[B/'policy-prefix-linux-validation-v1',B/'policy-prefix-linux-default-harness-v1'];rows=[]
for root in roots:
 assert root.resolve()==root
 for parent,dirs,files in os.walk(root,followlinks=False):
  for name in dirs:
   p=pathlib.Path(parent)/name;s=p.lstat();assert stat.S_ISDIR(s.st_mode) and not p.is_symlink()
  for name in files:
   p=pathlib.Path(parent)/name;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and not p.is_symlink()
   b=p.read_bytes();t=p.stat();assert(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(t.st_dev,t.st_ino,t.st_size,t.st_mtime_ns,t.st_ctime_ns)
   rows.append({'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
print(json.dumps({'schema':'trnm-policy-prefix-closed-ROG-file-inventory-v1','files':sorted(rows,key=lambda x:x['path']),'count':len(rows),'bytes':sum(x['bytes']for x in rows),'only_closed_validation_directories':True,'source_worktrees_targets_excluded':True},indent=2))
