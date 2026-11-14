import os,stat,json
from pathlib import Path
p=Path('/private/tmp/chain-consolidation-20261114-root/P1-root-source-tool-records-v1')
assert p.resolve()==p and stat.S_ISDIR(os.lstat(p).st_mode)
rows=[]
for e in os.scandir(p):
 s=e.stat(follow_symlinks=False)
 rows.append({'name':e.name,'bytes':s.st_size,'regular':stat.S_ISREG(s.st_mode),'directory':stat.S_ISDIR(s.st_mode),'symlink':stat.S_ISLNK(s.st_mode),'links':s.st_nlink})
print(json.dumps({'directory':str(p),'entries':rows},indent=2))
