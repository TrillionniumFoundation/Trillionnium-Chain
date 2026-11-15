/usr/bin/python3 - <<'PY'
import os,json,pathlib,subprocess,hashlib,time,stat,traceback
root=pathlib.Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2')
out=root/'publication-materialization-v5';pub=root/'chain-publication';bare=root/'chain.git'
head='690f710c1b6808787996e86aa4c36bd53e1f3939';tree='b9ff2e5c4ca6e465b86cb4b2bd466ad831147899'
env=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0')
base=['/usr/bin/git','--no-replace-objects','--git-dir='+str(bare)]
def save(name,value):
 with (out/name).open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n')
def command(args,cwd=None,timeout=180):
 p=subprocess.run(args,cwd=cwd,capture_output=True,env=env,timeout=timeout)
 if p.returncode:raise RuntimeError({'command':args,'exit_code':p.returncode,'stderr':p.stderr.decode(errors='replace')})
 return p.stdout
def git(*args):return command(base+list(args))
def wg(*args):return command(['/usr/bin/git','--no-replace-objects','-C',str(pub),*args])
receipt={'source_commit':head,'source_tree':tree,'worktree':str(pub),'result':'INCOMPLETE','started_unix_seconds':time.time()}
try:
 expected_refs=json.loads((out/'refs-before.json').read_text())['refs']
 assert git('for-each-ref','--format=%(refname) %(objectname)').decode()==expected_refs
 assert wg('rev-parse','HEAD').decode().strip()==head
 assert wg('rev-parse','HEAD^{tree}').decode().strip()==tree
 assert wg('symbolic-ref','HEAD').decode().strip()=='refs/heads/fix/chain-native-demand-acceptance-20261107'
 assert command(['/usr/bin/git','-C',str(root/'chain-source-bounded'),'rev-parse','HEAD']).decode().strip()==head
 rows=[]
 for entry in git('ls-tree','-r','-z','--full-tree',head).split(b'\0'):
  if not entry:continue
  a,p=entry.split(b'\t',1);mode,kind,oid=a.decode().split();rows.append({'path':p.decode(),'mode':mode,'type':kind,'oid':oid})
 assert all(x['type']=='blob' for x in rows)
 available={}
 for line in git('cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype) %(objectsize)').decode().splitlines():
  oid,kind,n=line.split();available[oid]={'type':kind,'bytes':int(n)}
 missing=sorted({x['oid'] for x in rows}-set(available));assert not missing
 assert all(available[x['oid']]['type']=='blob' for x in rows)
 receipt.update(tracked_paths=len(rows),unique_blobs=len({x['oid'] for x in rows}),missing_unique_blobs=0,expected_checkout_bytes=sum(available[x['oid']]['bytes'] for x in rows))
 tracked={x['path'] for x in rows};unexpected=[]
 for directory,dirs,files in os.walk(pub,followlinks=False):
  for name in files:
   p=pathlib.Path(directory)/name;rel=p.relative_to(pub).as_posix()
   if rel!='.git' and rel not in tracked:unexpected.append(rel)
  for name in dirs:
   p=pathlib.Path(directory)/name
   if p.is_symlink() and p.relative_to(pub).as_posix() not in tracked:unexpected.append(p.relative_to(pub).as_posix())
 save('checkout-before.json',{'head':head,'tree':tree,'unexpected_existing_files':unexpected,'tracked_paths':len(rows),'missing_blobs':missing})
 assert not unexpected,unexpected
 index_lock=pathlib.Path(wg('rev-parse','--git-path','index.lock').decode().strip())
 if not index_lock.is_absolute():index_lock=pub/index_lock
 assert index_lock.resolve().parent==bare/'worktrees/chain-publication'
 if index_lock.exists():
  data=index_lock.read_bytes();st=index_lock.stat()
  save('initial-checkout-stale-lock.json',{'path':str(index_lock),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mtime_ns':st.st_mtime_ns,'initial_checkout_job':'1a1b6873dbb-12894-4d6','initial_job_terminal_as_confirmed_by_root':True,'action':'move exact owned stale lock to retained evidence'})
  destination=out/'initial-checkout-stale-index.lock';assert not destination.exists();index_lock.rename(destination)
 args=['/usr/bin/git','--no-replace-objects','-C',str(pub),'read-tree','--reset','-u',head]
 start=time.time()
 with (out/'checkout.log').open('xb') as f:
  code=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,env=env,timeout=240).returncode
 log=(out/'checkout.log').read_bytes()
 receipt.update(checkout_command=args,checkout_exit_code=code,checkout_seconds=time.time()-start,checkout_log_bytes=len(log),checkout_log_sha256=hashlib.sha256(log).hexdigest())
 assert code==0
 print(json.dumps({'kind':'checkout','exit_code':code,'tracked_paths':len(rows),'expected_bytes':receipt['expected_checkout_bytes']}),flush=True)
 manifest=[];total=0
 for row in rows:
  p=pub/row['path'];st=p.lstat();expected_size=available[row['oid']]['bytes']
  if row['mode']=='120000':
   assert stat.S_ISLNK(st.st_mode);body=os.fsencode(os.readlink(p));assert len(body)==expected_size
   git_hash=hashlib.sha1(b'blob '+str(expected_size).encode()+b'\0'+body).hexdigest();sha=hashlib.sha256(body).hexdigest();actual_size=len(body)
  else:
   assert stat.S_ISREG(st.st_mode)
   mode='100755' if st.st_mode&0o111 else '100644';assert mode==row['mode'],(row['path'],mode,row['mode'])
   assert st.st_size==expected_size,(row['path'],st.st_size,expected_size)
   h=hashlib.sha1(b'blob '+str(expected_size).encode()+b'\0');s=hashlib.sha256();actual_size=0
   with p.open('rb') as f:
    while True:
     chunk=f.read(1048576)
     if not chunk:break
     h.update(chunk);s.update(chunk);actual_size+=len(chunk)
   git_hash=h.hexdigest();sha=s.hexdigest()
  assert git_hash==row['oid'] and actual_size==expected_size,(row['path'],git_hash,row['oid'])
  manifest.append({**row,'bytes':actual_size,'sha256':sha,'actual_git_blob_sha1':git_hash});total+=actual_size
 save('checkout-file-manifest.json',{'head':head,'tree':tree,'tracked_paths':len(manifest),'total_bytes':total,'files':manifest})
 identity={'head':wg('rev-parse','HEAD').decode().strip(),'tree':wg('rev-parse','HEAD^{tree}').decode().strip(),'status':wg('status','--porcelain=v1','--untracked-files=all').decode()}
 assert identity=={'head':head,'tree':tree,'status':''},identity
 assert git('for-each-ref','--format=%(refname) %(objectname)').decode()==expected_refs
 args=['bash','scripts/project-preflight.sh'];start=time.time()
 with (out/'preflight.stdout.log').open('xb') as f,(out/'preflight.stderr.log').open('xb') as e:
  code=subprocess.run(args,cwd=pub,stdout=f,stderr=e,env=env,timeout=90).returncode
 receipt.update(checkout_bytes=total,all_tracked_blob_hashes_match=True,all_tracked_modes_match=True,identity_before_preflight=identity,preflight_command=args,preflight_exit_code=code,preflight_seconds=time.time()-start)
 for name in ('preflight.stdout.log','preflight.stderr.log','checkout-file-manifest.json'):
  b=(out/name).read_bytes();receipt[name]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
 assert code==0
 final={'head':wg('rev-parse','HEAD').decode().strip(),'tree':wg('rev-parse','HEAD^{tree}').decode().strip(),'status':wg('status','--porcelain=v1','--untracked-files=all').decode()}
 assert final==identity
 assert git('for-each-ref','--format=%(refname) %(objectname)').decode()==expected_refs
 assert command(['/usr/bin/git','-C',str(root/'chain-source-bounded'),'rev-parse','HEAD']).decode().strip()==head
 receipt.update(result='COMPLETE_VERIFIED_CHECKOUT',identity_after_preflight=final,refs_unchanged=True,refs_sha256=hashlib.sha256(expected_refs.encode()).hexdigest(),frozen_running_source_head_unchanged=True)
except BaseException as e:
 receipt.update(result='FAILED',failure_type=type(e).__name__,failure=str(e),traceback=traceback.format_exc())
finally:
 receipt['finished_unix_seconds']=time.time();save('checkout-result.json',receipt);print(json.dumps(receipt),flush=True)
raise SystemExit(0 if receipt['result']=='COMPLETE_VERIFIED_CHECKOUT' else 1)
PY