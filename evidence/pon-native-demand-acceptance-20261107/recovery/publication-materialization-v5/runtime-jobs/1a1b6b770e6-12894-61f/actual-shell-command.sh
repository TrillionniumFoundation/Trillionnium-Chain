/usr/bin/python3 - <<'PY'
import os,json,pathlib,subprocess,hashlib,time,sys
r=pathlib.Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2');out=r/'publication-materialization-v5';inv=json.loads((out/'missing-before.json').read_text())
env=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0')
base=['/usr/bin/git','--no-replace-objects','--git-dir='+str(r/'chain.git')]
deadline=time.monotonic()+780
def save(name,v):
 with (out/name).open('x') as f: json.dump(v,f,sort_keys=True,indent=2);f.write('\n')
def available():
 q=subprocess.run(base+['cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype) %(objectsize)'],capture_output=True,env=env,timeout=90)
 if q.returncode: raise RuntimeError(q.stderr.decode())
 return {s.split()[0] for s in q.stdout.decode().splitlines()}
before=available();unique={x['oid']:x for x in inv['missing']};todo=[x for k,x in unique.items() if k not in before]
large=sorted([x for x in todo if x['github_size']>=1048576],key=lambda x:x['oid'])
small=sorted([x for x in todo if x['github_size']<1048576],key=lambda x:x['oid'])
batches=[];batch=[];size=0
for row in small:
 if batch and (len(batch)>=96 or size+row['github_size']>2097152):
  batches.append(batch);batch=[];size=0
 batch.append(row);size+=row['github_size']
if batch:batches.append(batch)
save('remaining-plan.json',{'source_commit':inv['source_commit'],'source_tree':inv['source_tree'],'missing_before':len(todo),'raw_threshold_bytes':1048576,'raw_objects':large,'git_batches':batches,'max_git_batch_objects':96,'max_git_batch_bytes':2097152,'prior_raw_job':'1a1b6b58336-12894-611'})
print(json.dumps({'kind':'plan','missing_before':len(todo),'large':len(large),'large_bytes':sum(x['github_size'] for x in large),'git_batches':len(batches),'small':len(small),'small_bytes':sum(x['github_size'] for x in small)}),flush=True)
failure=None
for row in large:
 if time.monotonic()>=deadline:failure={'stage':'raw','code':'GLOBAL_DEADLINE'};break
 oid=row['oid'];p=out/'raw-blobs';raw=p/(oid+'.raw');err=p/(oid+'.stderr');args=['/usr/bin/gh','api','-H','Accept: application/vnd.github.raw+json','repos/TrillionniumFoundation/Trillionnium-Chain/git/blobs/'+oid]
 start=time.time();timed_out=False
 with raw.open('xb') as f,err.open('xb') as e:
  try: code=subprocess.run(args,stdout=f,stderr=e,timeout=min(150,max(1,deadline-time.monotonic()))).returncode
  except subprocess.TimeoutExpired:code=124;timed_out=True
 b=raw.read_bytes();actual=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
 rec={'command':args,'expected_blob':oid,'expected_bytes':row['github_size'],'actual_bytes':len(b),'actual_git_blob_sha1':actual,'raw_sha256':hashlib.sha256(b).hexdigest(),'exit_code':code,'timed_out':timed_out,'elapsed_seconds':time.time()-start,'path':row['path'],'imported':False}
 if code==0 and len(b)==row['github_size'] and actual==oid:
  q=subprocess.run(base+['hash-object','-w','--stdin'],input=b,capture_output=True,env=env,timeout=60);rec.update(import_exit_code=q.returncode,import_stdout=q.stdout.decode(),import_stderr=q.stderr.decode());rec['imported']=q.returncode==0 and q.stdout.decode().strip()==oid
 save('raw-blobs/'+oid+'.receipt.json',rec);print(json.dumps({'kind':'raw','oid':oid,'bytes':len(b),'exit':code,'identity_verified':actual==oid and len(b)==row['github_size'],'imported':rec['imported'],'elapsed_seconds':rec['elapsed_seconds']}),flush=True)
 if not rec['imported']:failure={'stage':'raw','oid':oid,'receipt':'raw-blobs/'+oid+'.receipt.json'};break
 del b
if failure is None:
 for i,batch in enumerate(batches):
  if time.monotonic()>=deadline:failure={'stage':'git','code':'GLOBAL_DEADLINE','batch':i};break
  args=['/usr/bin/git','-c','credential.helper=','-c','credential.helper=!/usr/bin/gh auth git-credential','-c','fetch.negotiationAlgorithm=noop','--git-dir='+str(r/'chain.git'),'fetch','--no-filter','--no-tags','--no-write-fetch-head','--recurse-submodules=no','origin']+[x['oid'] for x in batch]
  log=out/('sized-fetch-'+str(i).zfill(3)+'.log');start=time.time();timed_out=False
  with log.open('xb') as f:
   try:code=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,env=env,timeout=min(120,max(1,deadline-time.monotonic()))).returncode
   except subprocess.TimeoutExpired:code=124;timed_out=True
  raw=log.read_bytes();rec={'batch':i,'command':args,'objects':len(batch),'expected_blob_bytes':sum(x['github_size'] for x in batch),'exit_code':code,'timed_out':timed_out,'elapsed_seconds':time.time()-start,'log_bytes':len(raw),'log_sha256':hashlib.sha256(raw).hexdigest()}
  save('sized-fetch-'+str(i).zfill(3)+'.json',rec);print(json.dumps({'kind':'fetch',**{k:rec[k] for k in ('batch','objects','expected_blob_bytes','exit_code','elapsed_seconds','log_bytes')}}),flush=True)
  if code!=0:failure={'stage':'git','batch':i,'receipt':'sized-fetch-'+str(i).zfill(3)+'.json'};break
after=available();remaining=sorted(set(unique)-after);refs=subprocess.run(base+['for-each-ref','--format=%(refname) %(objectname)'],capture_output=True,env=env,timeout=30)
reftext=refs.stdout.decode();expected=json.loads((out/'refs-before.json').read_text());same=refs.returncode==0 and reftext==expected['refs']
rec={'source_commit':inv['source_commit'],'source_tree':inv['source_tree'],'missing_unique_blobs':len(remaining),'missing':remaining,'refs_unchanged':same,'refs_sha256':hashlib.sha256(refs.stdout).hexdigest(),'failure':failure}
save('remaining-result.json',rec);print(json.dumps({'kind':'result',**{k:v for k,v in rec.items() if k!='missing'}}),flush=True)
sys.exit(0 if not remaining and same and failure is None else 1)
PY