import ast, datetime, hashlib, json, os, pathlib, re, stat, subprocess, sys, time
E=pathlib.Path('/private/tmp/chain-new-head-5df7-deadline-controller-review-20261114-v1')
S=pathlib.Path('/private/tmp/chain-consolidation-20261114-mainline')
D=pathlib.Path('/private/tmp/chain-prci-remote-head-5df7ae6-commit-review-20261114-v1/scope-and-patches-v1')
R1='2a86462a1ab20c68151719ba4635e3c294391e64'
N='5df7ae6f482157c5f7fdcbcd52222117a965053f'
paths=['scripts/test_w1_owned_process_collector_v1.py','scripts/w1_owned_process_collector_v1.py','scripts/ci/ci_job.sh','trillionnium/crates/trnm-pon-node/src/ingress/public_v2.rs']
sha=lambda b:hashlib.sha256(b).hexdigest()
oid=lambda b:hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def stable(p):
 p=pathlib.Path(p);a=p.lstat()
 if p.resolve(strict=True)!=p or not stat.S_ISREG(a.st_mode) or a.st_nlink!=1: raise ValueError('unsafe input '+str(p))
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  b=os.fstat(fd);data=b''
  if (a.st_dev,a.st_ino,a.st_mode,a.st_nlink,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(b.st_dev,b.st_ino,b.st_mode,b.st_nlink,b.st_size,b.st_mtime_ns,b.st_ctime_ns): raise ValueError('race')
  if b.st_size>2*1024*1024:raise ValueError('input cap')
  while True:
   v=os.read(fd,65536)
   if not v:break
   data+=v
  c=os.fstat(fd)
 finally:os.close(fd)
 if (b.st_dev,b.st_ino,b.st_mode,b.st_nlink,b.st_size,b.st_mtime_ns,b.st_ctime_ns)!=(c.st_dev,c.st_ino,c.st_mode,c.st_nlink,c.st_size,c.st_mtime_ns,c.st_ctime_ns) or p.lstat()!=c or len(data)!=b.st_size:raise ValueError('changed input')
 return data
def put(rel,data):
 p=E/rel;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(data)
 return {'path':str(p),'bytes':len(data),'sha256':sha(data)}
def js(rel,value):return put(rel,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())
def apply_exact(old,patch):
 lines=old.splitlines(keepends=True);ps=patch.splitlines(keepends=True);out=[];cursor=0;i=0;hunks=[]
 while i<len(ps):
  h=ps[i].rstrip(b'\r\n');m=re.fullmatch(rb'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)',h)
  if not m:raise ValueError('unexpected patch line '+repr(ps[i]))
  a,ac,b,bc=(int(m.group(1)),int(m.group(2) or 1),int(m.group(3)),int(m.group(4) or 1))
  start=a-1 if ac else a
  if start<cursor:raise ValueError('overlap')
  out.extend(lines[cursor:start]);cursor=start
  if len(out)!=(b-1 if bc else b):raise ValueError('new coordinate')
  i+=1;co=cn=0
  while i<len(ps) and not ps[i].startswith(b'@@ '):
   q=ps[i]
   if not q or q[:1] not in (b' ',b'-',b'+'):raise ValueError('patch token')
   body=q[1:]
   # GitHub text patch's final context line can lack newline while source has one.
   if not body.endswith(b'\n') and i==len(ps)-1:
    body+=b'\n'
   if q[:1] in (b' ',b'-'):
    if cursor>=len(lines) or lines[cursor]!=body:raise ValueError('old context mismatch at '+str(cursor+1))
    cursor+=1;co+=1
   if q[:1] in (b' ',b'+'):out.append(body);cn+=1
   i+=1
  if (co,cn)!=(ac,bc):raise ValueError('hunk counts')
  hunks.append({'old_start':a,'old_count':ac,'new_start':b,'new_count':bc})
 out.extend(lines[cursor:]);return b''.join(out),hunks
E.mkdir(mode=0o700)
put('producer.py',sys.argv[1].encode())
env=os.environ.copy()
for k in list(env):
 if k.startswith('GIT_TRACE') or k in ('GIT_CURL_VERBOSE','GH_DEBUG'):env.pop(k,None)
env.update(GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_TERMINAL_PROMPT='0',GIT_ALLOW_PROTOCOL='',PYTHONDONTWRITEBYTECODE='1',PYTHONOPTIMIZE='0')
steps=[]
def git(label,args):
 cmd=['/usr/bin/git','--no-replace-objects','-C',str(S)]+args
 started=datetime.datetime.now(datetime.timezone.utc).isoformat()
 p=subprocess.run(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 if len(p.stdout)>2*1024*1024 or len(p.stderr)>65536:raise ValueError('output bound')
 so=put('commands/'+label+'.stdout',p.stdout);se=put('commands/'+label+'.stderr',p.stderr)
 steps.append({'label':label,'argv':cmd,'cwd':str(pathlib.Path.cwd()),'started_at':started,'finished_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':p.returncode,'stdout':so,'stderr':se})
 if p.returncode:raise ValueError('Git read failed '+label)
 return p.stdout
result={'schema':'trnm-new-head-deadline-controller-inputs-v1','old':R1,'new':N,'new_blob_source':'strict reconstruction of pinned complete API patch and immutable R1 blob; no new network/blob request','steps':steps,'source_refs_stage_changes':False,'tests_or_target_helpers_executed':False}
try:
 inputs=[('scope-summary.json','ee27851678dc860bccd3630eab4ce69a3640199365aa78c7ec96ed4caa754e1e'),('patches/11-part-01.patch','fd920f2318abc62d4daf3c451366904f3273ad6b5047fda2d794193cf841a660'),('patches/12-part-01.patch','e81cccfa2244091530ff3e99fce5f326e90bdc8d8a428114953e7d406be54a8d')]
 captured={}
 for path,digest in inputs:
  raw=stable(D/path)
  if sha(raw)!=digest:raise ValueError('input SHA '+path)
  captured[path]=raw;put('inputs/'+path,raw)
 raw=git('R1-exact-source-tree',['ls-tree','-z',R1,'--',*paths])
 tree={}
 for line in raw.split(b'\0'):
  if not line:continue
  meta,path=line.split(b'\t');mode,kind,obj=meta.decode().split()
  if kind!='blob' or mode not in ('100644','100755'):raise ValueError('tree kind')
  tree[path.decode()]={'mode':mode,'oid':obj}
 if set(tree)!=set(paths):raise ValueError('source set mismatch '+repr(tree))
 sources={};roster=[]
 for n,path in enumerate(paths):
  b=git('R1-blob-'+str(n+1),['cat-file','blob',tree[path]['oid']])
  if oid(b)!=tree[path]['oid']:raise ValueError('Git content-address mismatch')
  sources[path]=b
  row=put('R1/'+path,b);row.update(repo_path=path,git_oid=tree[path]['oid'],mode=tree[path]['mode']);roster.append(row)
 derived=[]
 for path,patch,expected in [(paths[0],'patches/11-part-01.patch','530169ab9de7079958ada8f2f4d66702ea54cca0'),(paths[3],'patches/12-part-01.patch','3a9fbe26283920a77ae4883a46153440abbe7e12')]:
  b,hunks=apply_exact(sources[path],captured[patch])
  if oid(b)!=expected:raise ValueError('derived Git identity mismatch '+path+': '+oid(b))
  row=put('5df-derived/'+path,b);row.update(repo_path=path,git_oid=expected,mode=tree[path]['mode'],hunks=hunks,source_kind='derived exact Git blob');derived.append(row)
 result.update(status='INPUTS_CLOSED',sources=roster,derived=derived)
except BaseException as exc:
 result.update(status='HOLD',error=type(exc).__name__+': '+str(exc))
finally:
 pin=js('input-summary.json',result);print(json.dumps({'status':result.get('status'),'summary':pin,'source_count':len(result.get('sources',[])),'derived_count':len(result.get('derived',[]))},sort_keys=True))
if result.get('status')!='INPUTS_CLOSED':raise SystemExit(1)
