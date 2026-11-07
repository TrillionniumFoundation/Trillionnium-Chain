/usr/bin/python3 - <<'PY'
import os,json,pathlib,subprocess
r=pathlib.Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2')
for sub in ('publication-materialization-v4','chain-publication'):
 p=r/sub
 print(json.dumps({'kind':'directory','path':str(p),'items':[{'name':x.name,'directory':x.is_dir(),'bytes':None if x.is_dir() else x.stat().st_size} for x in sorted(p.iterdir())][:100] if p.exists() else None}))
p=r/'publication-materialization-v4'
for f in sorted(p.iterdir()):
 if f.is_file() and (f.suffix in ('.json','.py') or f.name=='fetch-001.log'):
  b=f.read_bytes()
  print(json.dumps({'kind':'file','path':str(f),'bytes':len(b),'text':b.decode(errors='replace') if len(b)<18000 else b[-18000:].decode(errors='replace'),'tail_only':len(b)>=18000}))
env=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0')
def git(*args):
 q=subprocess.run(['/usr/bin/git','--no-replace-objects','--git-dir='+str(r/'chain.git'),*args],capture_output=True,env=env)
 return q
for args in [('rev-parse','690f710c1b6808787996e86aa4c36bd53e1f3939^{tree}'),('worktree','list','--porcelain')]:
 q=git(*args);print(json.dumps({'kind':'git','args':args,'exit':q.returncode,'stdout':q.stdout.decode(),'stderr':q.stderr.decode()}))
q=git('ls-tree','-r','-z','--full-tree','690f710c1b6808787996e86aa4c36bd53e1f3939')
if q.returncode: raise SystemExit(q.stderr.decode())
rows=[]
for entry in q.stdout.split(b'\0'):
 if not entry: continue
 a,path=entry.split(b'\t',1);mode,kind,oid=a.decode().split();rows.append({'mode':mode,'type':kind,'oid':oid,'path':path.decode()})
oids=sorted({x['oid'] for x in rows if x['type']=='blob'})
c=subprocess.run(['/usr/bin/git','--no-replace-objects','--git-dir='+str(r/'chain.git'),'cat-file','--batch-check=%(objectname) %(objecttype) %(objectsize)'],input=('\n'.join(oids)+'\n').encode(),capture_output=True,env=env)
if c.returncode: raise SystemExit(c.stderr.decode())
missing={line.split()[0] for line in c.stdout.decode().splitlines() if line.endswith(' missing')}
print(json.dumps({'kind':'inventory','tracked_entries':len(rows),'unique_blobs':len(oids),'missing_unique_blobs':len(missing),'missing_paths':[x for x in rows if x['oid'] in missing],'non_blob_entries':[x for x in rows if x['type']!='blob']}))
q=git('show','690f710c1b6808787996e86aa4c36bd53e1f3939:AGENTS.md')
print(json.dumps({'kind':'agents','exit':q.returncode,'text':q.stdout.decode(),'stderr':q.stderr.decode()}))
PY