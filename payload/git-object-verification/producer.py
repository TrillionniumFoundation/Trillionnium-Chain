import datetime, hashlib, json, os, pathlib, re, stat, subprocess, sys, time
S=pathlib.Path('/private/tmp/chain-consolidation-20261114-mainline')
E=pathlib.Path('/private/tmp/chain-new-head-5df7-git-object-verification-20261114-v1')
OLD='2a86462a1ab20c68151719ba4635e3c294391e64';NEW='5df7ae6f482157c5f7fdcbcd52222117a965053f';TREE='6be4940d38cc88782657f2684cbefe48866f8b9f'
PARENTS=['abfcff23d4e2aab7dfd92dfb34937ec7d6021ead',OLD]
sha=lambda b:hashlib.sha256(b).hexdigest()
oid=lambda kind,b:hashlib.sha1(kind.encode()+b' '+str(len(b)).encode()+b'\0'+b).hexdigest()
def stable(path,cap=8*1024*1024):
 p=pathlib.Path(path);a=p.lstat();v=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 if p.resolve(strict=True)!=p or not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size>cap:raise ValueError('unsafe or oversized input')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  f=os.fstat(fd);out=[]
  if v(a)!=v(f):raise ValueError('input identity race')
  while True:
   q=os.read(fd,65536)
   if not q:break
   out.append(q)
  b=os.fstat(fd)
 finally:os.close(fd)
 raw=b''.join(out)
 if v(a)!=v(b) or v(b)!=v(p.lstat()) or len(raw)!=a.st_size:raise ValueError('input changed')
 return raw
E.mkdir(mode=0o700)
def put(rel,raw):
 p=E/rel;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(raw)
 return {'path':str(p),'bytes':len(raw),'sha256':sha(raw)}
def js(rel,x):return put(rel,(json.dumps(x,sort_keys=True,indent=2)+'\n').encode())
put('producer.py',sys.argv[1].encode())
env=os.environ.copy()
for k in list(env):
 if k.startswith('GIT_TRACE') or k in ('GIT_CURL_VERBOSE','GH_DEBUG'):env.pop(k,None)
env.update(GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_TERMINAL_PROMPT='0',GIT_ALLOW_PROTOCOL='',PYTHONDONTWRITEBYTECODE='1',PYTHONOPTIMIZE='0')
steps=[]
def git(label,args,stdout_rel=None,cap=8*1024*1024):
 argv=['/usr/bin/git','--no-replace-objects','-C',str(S)]+args
 out=E/(stdout_rel or 'commands/'+label+'.stdout');out.parent.mkdir(parents=True,exist_ok=True)
 err=E/('commands/'+label+'.stderr');err.parent.mkdir(parents=True,exist_ok=True)
 started=datetime.datetime.now(datetime.timezone.utc).isoformat();t=time.monotonic();timed=False
 with out.open('xb') as so,err.open('xb') as se:
  p=subprocess.Popen(argv,env=env,stdout=so,stderr=se)
  try:
   while p.poll() is None:
    if out.stat().st_size>cap or err.stat().st_size>65536:raise ValueError('read output bound')
    if time.monotonic()-t>60:timed=True;raise TimeoutError('read command timeout')
    time.sleep(.02)
  finally:
   if p.poll() is None:p.kill()
   actual=p.wait()
 raw=stable(out,cap);errorraw=stable(err,65536)
 row={'label':label,'argv':argv,'cwd':str(pathlib.Path.cwd()),'pid':p.pid,'started_at':started,'finished_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'timeout_seconds':60,'timeout':timed,'exit_code':actual,'stdout':{'path':str(out),'bytes':len(raw),'sha256':sha(raw)},'stderr':{'path':str(err),'bytes':len(errorraw),'sha256':sha(errorraw)}}
 steps.append(row)
 if actual!=0:raise ValueError('read command nonzero '+label)
 return raw
state={'schema':'trnm-5df-all-new-git-objects-verification-v1','status':'HOLD','old':OLD,'new':NEW,'tree':TREE,'parents':PARENTS,'steps':steps,'network_calls':0,'source_index_refs_stage_mutated':False,'worktree_tests_build_native':False,'history_39file_checks_repeated':False}
try:
 sources=[
 ('fetch-summary.json','/private/tmp/chain-consolidation-20261114-root/head5df-immutable-object-fetch-20261114-v1/summary.json','7051816f15f23d2e9ce182062e1c2b1d3c84b17c4e597388f56f777154828e65'),
 ('api-scope-summary.json','/private/tmp/chain-prci-remote-head-5df7ae6-commit-review-20261114-v1/scope-and-patches-v1/scope-summary.json','ee27851678dc860bccd3630eab4ce69a3640199365aa78c7ec96ed4caa754e1e'),
 ('previous-derived-input-summary.json','/private/tmp/chain-new-head-5df7-deadline-controller-review-20261114-v1/input-summary.json','593207e1148e34a1a11ba2e6bee82b288e1b2c385143a7e609e25201cd1669c3'),
 ('corpus-api.patch','/private/tmp/chain-prci-remote-head-5df7ae6-commit-review-20261114-v1/scope-and-patches-v1/patches/01-part-01.patch','24254644e9732664e315ed076eb80608f40a8f59044369448b34abfd194a610e')]
 inputs={}
 for name,path,h in sources:
  raw=stable(path)
  if sha(raw)!=h:raise ValueError('pinned input mismatch '+name)
  pin=put('inputs/'+name,raw);inputs[name]={'origin':path,**pin}
 state['inputs']=inputs
 scope=json.loads(stable(E/'inputs/api-scope-summary.json'))
 before=git('head-before',['rev-parse','HEAD','HEAD^{tree}'],cap=1024)
 if before!= (OLD+'\n5c26776f96f15fd131e85a5c2d7c5e895ad7fab4\n').encode():raise ValueError('SOURCE head drift')
 commit=git('exact-commit',['cat-file','commit',NEW],stdout_rel='new-commit.raw',cap=65536)
 if oid('commit',commit)!=NEW:raise ValueError('commit content-address')
 header=commit.split(b'\n\n',1)[0].splitlines()
 trees=[l[5:].decode() for l in header if l.startswith(b'tree ')]
 parents=[l[7:].decode() for l in header if l.startswith(b'parent ')]
 if trees!=[TREE] or parents!=PARENTS:raise ValueError('commit header identity')
 state['commit_content_verified']={'git_oid':NEW,'bytes':len(commit),'sha256':sha(commit),'tree':trees[0],'parents':parents}
 rawdiff=git('full-raw-no-renames-diff',['diff-tree','--no-commit-id','--raw','-z','--no-renames','--no-abbrev','--no-ext-diff','-r',OLD,NEW],stdout_rel='R1-to-5df.raw-diff-tree',cap=65536)
 fields=rawdiff.split(b'\0')
 if fields[-1]!=b'':raise ValueError('diff trailing delimiter')
 fields.pop()
 if len(fields)!=24:raise ValueError('diff field count')
 expected={x['filename']:x for x in scope['files']}
 if len(expected)!=12:raise ValueError('API set count')
 changes=[]
 for i in range(0,len(fields),2):
  meta=fields[i].decode();path=fields[i+1].decode()
  m=re.fullmatch(r':([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([AM])',meta)
  if not m or path not in expected:raise ValueError('diff form/path')
  oldmode,newmode,oldoido,newoid,status=m.groups();api=expected[path]
  if newmode!='100644' or newoid!=api['sha'] or {'A':'added','M':'modified'}[status]!=api['status']:raise ValueError('new diff mismatch')
  if status=='A':
   if oldmode!='000000' or oldoido!='0'*40:raise ValueError('added preimage')
  elif oldmode!='100644' or oldoido=='0'*40:raise ValueError('modified preimage')
  changes.append({'path':path,'old_mode':oldmode,'new_mode':newmode,'old_oid':oldoido,'new_oid':newoid,'status':status})
 if len({x['path'] for x in changes})!=12 or {x['path'] for x in changes}!=set(expected):raise ValueError('complete changed set')
 state['diff_tree']=changes;state['complete_12_path_set_matches_API']=True
 actual={};newfiles=[];total=0
 for n,row in enumerate(changes,1):
  raw=git('new-blob-'+str(n).zfill(2),['cat-file','blob',row['new_oid']],stdout_rel='new-files/'+row['path'])
  if oid('blob',raw)!=row['new_oid']:raise ValueError('blob content-address')
  total+=len(raw)
  if total>64*1024*1024:raise ValueError('total object bytes cap')
  actual[row['path']]=raw
  newfiles.append({**row,'source_path':str(E/'new-files'/row['path']),'bytes':len(raw),'sha256':sha(raw)})
 state['new_blob_count']=len(newfiles);state['new_blob_total_bytes']=total;state['new_files']=newfiles
 oldsummary=json.loads(stable(E/'inputs/previous-derived-input-summary.json'))
 checks=[]
 for row in oldsummary['derived']:
  raw=stable(row['path'])
  if len(raw)!=row['bytes'] or sha(raw)!=row['sha256'] or raw!=actual[row['repo_path']]:raise ValueError('derived full bytes differ')
  checks.append({'repo_path':row['repo_path'],'previous_derived':row,'actual_new_blob':next(x for x in newfiles if x['path']==row['repo_path']),'byte_equal':True})
 state['previous_derived_full_bytes_equal']=checks
 cp='config/pon/pq-cross-branch-corpus-v1.json';crow=next(x for x in changes if x['path']==cp)
 oldraw=git('old-corpus-blob',['cat-file','blob',crow['old_oid']],stdout_rel='old-corpus.json')
 if oid('blob',oldraw)!=crow['old_oid']:raise ValueError('old corpus identity')
 def no_duplicates(pairs):
  out={}
  for k,v in pairs:
   if k in out:raise ValueError('duplicate JSON key')
   out[k]=v
  return out
 a=json.loads(oldraw,object_pairs_hook=no_duplicates);b=json.loads(actual[cp],object_pairs_hook=no_duplicates)
 typed=[]
 def walk(x,y,p=()):
  if type(x)!=type(y):typed.append((p,x,y));return
  if isinstance(x,dict):
   if x.keys()!=y.keys():raise ValueError('corpus keys changed')
   for k in x:walk(x[k],y[k],p+(k,))
  elif isinstance(x,list):
   if len(x)!=len(y):raise ValueError('corpus length changed')
   for i,(xx,yy) in enumerate(zip(x,y)):walk(xx,yy,p+(i,))
  elif x!=y:typed.append((p,x,y))
 walk(a,b)
 selected={'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md','docs/security/PQ_AUTHORITY_EFFECT_REGISTER_V1.md','docs/security/W1_LIFETIME_CURRENT_SOURCE_OBSERVATION_V2.md','scripts/ci/test_pq_authority_effect_register.py','scripts/test_w1_owned_process_collector_v1.py','trillionnium/crates/trnm-pon-node/src/ingress/public_v2.rs'}
 if len(typed)!=6 or {p[-1] for p,_,_ in typed}!=selected:raise ValueError('corpus exact six diff')
 bindings=[]
 for pointer,oldval,newval in typed:
  path=pointer[-1];row=next(x for x in newfiles if x['path']==path)
  if type(oldval)is not str or type(newval)is not str or (oldval,newval)!=(row['old_oid'],row['new_oid']):raise ValueError('corpus literal binding differs')
  bindings.append({'json_pointer':'/'+('/'.join(str(x).replace('~','~0').replace('/','~1') for x in pointer)),'repo_path':path,'old_blob':oldval,'new_blob':newval,'actual_new_source_bytes':row['bytes'],'actual_new_source_sha256':row['sha256']})
 state['corpus']={'typed_changed_leaves':6,'unchanged_key_and_array_shapes':True,'only_selected_six_git_oid_updates':True,'bindings':bindings,'all_active_consumers_or_historical_evidence_revalidated':False}
 after=git('head-after',['rev-parse','HEAD','HEAD^{tree}'],cap=1024)
 if before!=after:raise ValueError('SOURCE head changed')
 state['source_head_tree_unchanged']=True
 state['status']='VERIFIED_ALL_12_NEW_GIT_BLOBS'
except BaseException as exc:
 state['error']=type(exc).__name__+': '+str(exc)
finally:
 state['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 pin=js('summary.json',state)
 files=[]
 for p in sorted(E.rglob('*')):
  if p.is_file():
   raw=stable(p);files.append({'path':str(p.relative_to(E)),'bytes':len(raw),'sha256':sha(raw)})
 index=js('EVIDENCE_INDEX.json',{'schema':'trnm-exact-git-object-review-files-v1','root':str(E),'file_count':len(files),'total_bytes':sum(x['bytes'] for x in files),'files':files,'index_excludes_itself':True})
 print(json.dumps({'status':state['status'],'summary':pin,'index':index,'objects':state.get('new_blob_count'),'object_bytes':state.get('new_blob_total_bytes'),'commands':len(steps),'error':state.get('error'),'corpus_changed_leaves':state.get('corpus',{}).get('typed_changed_leaves')},sort_keys=True))
if state['status']!='VERIFIED_ALL_12_NEW_GIT_BLOBS':raise SystemExit(1)
