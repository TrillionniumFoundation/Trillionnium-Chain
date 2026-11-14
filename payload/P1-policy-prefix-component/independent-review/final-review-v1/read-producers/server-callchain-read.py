import os,stat,hashlib,json,re,subprocess
from pathlib import Path
D=Path('/private/tmp/chain-public-policy-prefix-independent-review-20261114-v1')
db='/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git'
head='ed0d35487f2a67239e4d646fd41c2c7acb5cc740'
def stable(p,sha):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1
  parts=[]
  while True:
   z=os.read(fd,1048576)
   if not z:break
   parts.append(z)
  b=b''.join(parts)
  k=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  assert k(a)==k(os.fstat(fd))==k(os.lstat(p))
  assert hashlib.sha256(b).hexdigest()==sha
  return b
 finally:os.close(fd)
old=stable(D/'M8--trillionnium--crates--trnm-pon-node--src--ingress--public_v3.rs.original','1a90c3eebf8a8642264f8a65ef906f5bdb9c1e656fab8650dc028328f104fb70').decode()
env=os.environ.copy()
for k in list(env):
 if k.startswith('GIT_TRACE') or k in ('GIT_CURL_VERBOSE',):env.pop(k)
env.update(GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0',GIT_TRACE2='0',GIT_TRACE2_EVENT='0',GIT_TRACE2_PERF='0')
rel='trillionnium/crates/trnm-pon-node/src/ingress/public_v3/pq_identity.rs'
cmd=['/usr/bin/git','--git-dir',db,'show',head+':'+rel]
p=subprocess.run(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
assert p.returncode==0 and not p.stderr
b=p.stdout;target=D/'M8--trillionnium--crates--trnm-pon-node--src--ingress--public_v3--pq_identity.rs.original'
with open(target,'xb') as f:f.write(b)
ql=b.decode().splitlines();ol=old.splitlines()
def context(lines,pattern,before,after,cap):
 out=[]
 for i,line in enumerate(lines[:cap]):
  if pattern in line:
   start=max(0,i-before);end=min(len(lines),i+after+1)
   out.append({'line':i+1,'start':start+1,'end':end,'text':'\n'.join(f'{j+1}: {lines[j]}' for j in range(start,end))})
 return out
x={'schema':'trnm-policy-prefix-readonly-reachable-server-callsite-v1','scope':'Textual selected contexts of already identified ordinary server stages; not a global callgraph or direct runtime counter','head':head,'capture':{'path':str(target),'source_path':rel,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'argv':cmd,'exit_code':0},'public_v3_resource_profile':context(ol,'resource_profile(',5,8,4245),'pq_identity_resource_profile':context(ql,'fn resource_profile',3,35,len(ql)),'pq_identity_policy_id':context(ql,'policy.id()',8,8,len(ql)),'tests_or_source_helpers_run':False}
raw=(json.dumps(x,indent=2,sort_keys=True)+'\n').encode();path=D/'production-server-policy-callchain.json'
with open(path,'xb') as f:f.write(raw)
print(json.dumps({'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'capture':x['capture'],'public_v3_resource_profile':x['public_v3_resource_profile'],'pq_identity_resource_profile':x['pq_identity_resource_profile'],'pq_identity_policy_id':x['pq_identity_policy_id']},indent=2))
