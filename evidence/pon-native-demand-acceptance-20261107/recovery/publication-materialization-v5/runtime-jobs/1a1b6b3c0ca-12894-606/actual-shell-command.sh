/usr/bin/python3 - <<'PY'
import os,json,pathlib,subprocess,hashlib,time,collections
r=pathlib.Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2'); out=r/'publication-materialization-v5';out.mkdir(exist_ok=False)
env=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0');base=['/usr/bin/git','--no-replace-objects','--git-dir='+str(r/'chain.git')]
def run(args,timeout=90): return subprocess.run(args,capture_output=True,env=env,timeout=timeout)
def git(*args):
 q=run(base+list(args))
 if q.returncode: raise RuntimeError({'command':args,'exit':q.returncode,'stderr':q.stderr.decode(errors='replace')})
 return q.stdout
def save(name,v):
 with (out/name).open('x') as f: json.dump(v,f,sort_keys=True,indent=2);f.write('\n')
head='690f710c1b6808787996e86aa4c36bd53e1f3939';tree=git('rev-parse',head+'^{tree}').decode().strip();assert tree=='b9ff2e5c4ca6e465b86cb4b2bd466ad831147899'
refs=git('for-each-ref','--format=%(refname) %(objectname)').decode();save('refs-before.json',{'refs':refs,'sha256':hashlib.sha256(refs.encode()).hexdigest()})
rows=[]
for x in git('ls-tree','-r','-z','--full-tree',head).split(b'\0'):
 if not x: continue
 a,path=x.split(b'\t',1);mode,kind,oid=a.decode().split();rows.append({'mode':mode,'type':kind,'oid':oid,'path':path.decode()})
available={}
for x in git('cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype) %(objectsize)').decode().splitlines():
 oid,kind,size=x.split();available[oid]={'type':kind,'size':int(size)}
missing=sorted({x['oid'] for x in rows if x['type']=='blob'}-set(available));missing_rows=[x for x in rows if x['oid'] in set(missing)]
for tag,rev in [('frozen',head),('known-base','29464319e6fc6ddeaffad481e2500883202be7e2')]:
 local_tree=git('rev-parse',rev+'^{tree}').decode().strip();args=['/usr/bin/gh','api','repos/TrillionniumFoundation/Trillionnium-Chain/git/trees/'+local_tree+'?recursive=1'];q=run(args,120)
 (out/(tag+'-github-tree.stdout')).write_bytes(q.stdout);(out/(tag+'-github-tree.stderr')).write_bytes(q.stderr)
 save(tag+'-github-tree-receipt.json',{'command':args,'exit_code':q.returncode,'tree':local_tree,'stdout_bytes':len(q.stdout),'stdout_sha256':hashlib.sha256(q.stdout).hexdigest(),'stderr_bytes':len(q.stderr)})
 if q.returncode==0:
  data=json.loads(q.stdout);assert data['sha']==local_tree and data.get('truncated') is False
  sizes={x['sha']:x['size'] for x in data['tree'] if x['type']=='blob'}
  for x in missing_rows: x['github_size']=sizes.get(x['oid'])
  if all(x['github_size'] is not None for x in missing_rows): break
  print(json.dumps({'kind':'metadata-coverage','tag':tag,'covered':sum(x['github_size'] is not None for x in missing_rows),'missing_paths':len(missing_rows)}),flush=True)
 else: print(json.dumps({'kind':'metadata-refused','tag':tag,'exit':q.returncode,'stderr':q.stderr.decode()}),flush=True)
inv={'source_commit':head,'source_tree':tree,'tracked_entries':len(rows),'tracked_blob_paths':sum(x['type']=='blob' for x in rows),'unique_blobs':len({x['oid'] for x in rows if x['type']=='blob'}),'available_objects':len(available),'missing_unique_blobs':len(missing),'missing':missing_rows,'non_blobs':[x for x in rows if x['type']!='blob']};save('missing-before.json',inv)
byoid={x['oid']:x for x in missing_rows};largest=sorted(byoid.values(),key=lambda x:x.get('github_size') or -1,reverse=True)[:30]
failed=json.loads((r/'publication-materialization-v4/fetch-001.json').read_text());failed_oids=failed['command'][failed['command'].index('origin')+1:]
print(json.dumps({'kind':'inventory','tracked_entries':len(rows),'unique_blobs':inv['unique_blobs'],'missing_unique_blobs':len(missing),'missing_paths':len(missing_rows),'unknown_sizes':sum(x.get('github_size') is None for x in byoid.values()),'missing_bytes_known':sum(x.get('github_size') or 0 for x in byoid.values()),'largest':largest,'failed_batch_missing':[byoid[x] for x in failed_oids if x in byoid]}),flush=True)
for path in ('AGENTS.md','PROJECT_BOUNDARY.md','OPERATIONS.md'):
 q=git('show',head+':'+path);print(json.dumps({'kind':'instructions','path':path,'text':q.decode()}),flush=True)
print(json.dumps({'kind':'done','output_dir':str(out)}),flush=True)
PY