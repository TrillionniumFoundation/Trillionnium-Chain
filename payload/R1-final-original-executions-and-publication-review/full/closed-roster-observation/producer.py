import datetime,hashlib,json,os,pathlib,re,stat,sys
BASE=pathlib.Path('/home/qian-qi/chain-final-consolidation-20261114-root')
R=BASE/'final-repository-truth-offline-2a8646-v1'
O=BASE/'R1-full-closed-roster-observation-prci-v1'
HEAD='2a86462a1ab20c68151719ba4635e3c294391e64';TREE='5c26776f96f15fd131e85a5c2d7c5e895ad7fab4'
SS='70e5dd235cf16b1ec3a0ba37da2a5c523cce3e97000a13de9fdd92e5e440ffef'
SOURCE='1b8638f7d5e3fb28abc25c06208df4e189ba3b86c7d0d3a12fb2a431607b7e03'
LABELS=['initial-head','initial-status','pre-update-preflight','local-bundle-verify','local-bundle-list-heads','fetch-exact-local-bundle','fetched-commit','fetched-tree','fast-forward-ancestry','fast-forward','preflight-audit','rust-version','cargo-version','conformance-environment','runtime-environment','verify-source-before','repository-truth','verify-source-after']
def stamp(s):return[s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def rd(p):
 q=pathlib.PurePosixPath(str(p));assert q.is_absolute() and '..' not in q.parts
 d=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for x in q.parts[1:-1]:
   n=os.open(x,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=d);os.close(d);d=n
  fd=os.open(q.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=d)
 finally:os.close(d)
 try:
  s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=16*1024*1024
  with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(s.st_size+1)
  assert len(b)==s.st_size and stamp(os.fstat(fd))==stamp(s)
  assert stamp(p.lstat())==stamp(s)
  return b,{'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'source_version':stamp(s)}
 finally:os.close(fd)
def inv():
 assert R.resolve(strict=True)==R
 out={};ds={}
 for b,ns,fs in os.walk(R,followlinks=False):
  for n in ns:
   p=pathlib.Path(b)/n;s=p.lstat();assert stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode)
   ds[str(p.relative_to(R))]=stamp(s)
  for n in fs:
   p=pathlib.Path(b)/n;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
   out[str(p.relative_to(R))]=stamp(s)
 return {'files':out,'directories':ds}
def save(n,b):
 p=O/n
 with p.open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 b2,info=rd(p);assert b==b2;return info
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
before=inv();raw,si=rd(R/'summary.json');assert si['bytes']==21354 and si['sha256']==SS
s=json.loads(raw);assert s['status']=='passed' and s['head']==HEAD and s['tree']==TREE and s['expected_start_head']=='6a8cd55573065ceb50cdb65a7834615f79b521ae'
assert s['lane_exit']==0 and s['source_before_after_verified'] is True and s['errors']==[]
assert s['finished_at'] and [x['label'] for x in s['steps']]==LABELS and all(x['exit']==0 for x in s['steps'])
expected={'summary.json':(21354,SS),'source-before.json':(423,SOURCE),'source-after.json':(423,SOURCE)}
for x in s['steps']:
 assert x['timeout_seconds']==(2700 if x['label']=='repository-truth' else 300)
 for ch in ['stdout','stderr']:
  n=x['label']+'.'+ch;assert x[ch+'_path']==str(R/n) and n not in expected
  expected[n]=(x[ch+'_bytes'],x[ch+'_sha256'])
assert len(expected)==39
extras=sorted(set(before['files'])-set(expected));assert set(expected).issubset(before['files'])
assert len(extras)<=256
for n in extras:
 q=pathlib.PurePosixPath(n)
 assert n.startswith('ci-observations/') and re.fullmatch(r'[A-Za-z0-9._/-]+',n) and str(q)==n and '..' not in q.parts
pins=[];rows=[];sumbytes=0
for n in sorted(before['files']):
 b,i=rd(R/n);assert i['source_version']==before['files'][n];sumbytes+=len(b);assert sumbytes<=32*1024*1024
 if n in expected:assert (len(b),i['sha256'])==expected[n]
 else:pins.append({'path':n,'bytes':len(b),'sha256':i['sha256']})
 rows.append({**i,'relative_path':n,'origin':{'host':'rog','path':str(R/n)}})
for n in ['source-before.json','source-after.json','verify-source-before.stdout','verify-source-after.stdout']:
 b,i=rd(R/n);assert len(b)==423 and i['sha256']==SOURCE
 identity=json.loads(b);assert identity=={'base':None,'candidate':HEAD,'kind':'head','prospective_merge':None,'schema':'trnm-ci-source-v1','tested_commit':HEAD,'tested_tree':TREE,'tests_executed_by_identity_check':False,'tracked_bytes':3994964901,'tracked_entries':41677,'tracked_worktree_verified':True}
assert inv()==before
manifest={'schema':'trnm-closed-original-sublogs-manifest-v1','head':HEAD,'tree':TREE,'receipt_directory':str(R),'terminal_summary_sha256':SS,'files':pins}
O.mkdir(exist_ok=False)
prod=save('producer.py',sys.argv[1].encode())
m=save('closed-original-logs.json',(json.dumps(manifest,indent=2)+'\n').encode())
result={'schema':'trnm-R1-full-closed-roster-observation-v1','started_at':started,'finished_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'original_status':s['status'],'original_lane_exit':s['lane_exit'],'original_lane_elapsed_seconds':next(x['elapsed_seconds'] for x in s['steps'] if x['label']=='repository-truth'),'original_summary':si,'head':HEAD,'tree':TREE,'expected_start_head':'6a8cd55573065ceb50cdb65a7834615f79b521ae','files':rows,'original_file_count':len(rows),'original_bytes':sumbytes,'required_flat_originals':39,'nested_originals':len(pins),'nested_bytes':sum(x['bytes'] for x in pins),'manifest':m,'producer':prod,'full_directory_members_verified':True,'unknown_files_excluded':[],'source_directory_changed':False,'source_or_git_or_lane_commands_executed':False,'hosted_qualification':False,'stage_written':False}
result_info=save('closed-roster-observation.json',(json.dumps(result,indent=2)+'\n').encode())
print(json.dumps({'directory':str(O),'manifest':m,'observation':result_info,'original_files':len(rows),'original_bytes':sumbytes,'nested_count':len(pins),'nested_bytes':sum(x['bytes'] for x in pins),'nested':pins,'original_status':s['status']}))
