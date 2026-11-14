import os,hashlib,json,subprocess,stat
from pathlib import Path
D=Path('/private/tmp/chain-public-policy-prefix-independent-review-20261114-v1');head='ed0d35487f2a67239e4d646fd41c2c7acb5cc740';db='/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git'
env=os.environ.copy()
for k in list(env):
 if k.startswith('GIT_TRACE') or k=='GIT_CURL_VERBOSE':env.pop(k)
env.update(GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0',GIT_TRACE2='0',GIT_TRACE2_EVENT='0',GIT_TRACE2_PERF='0')
rel='trillionnium/crates/trnm-pon-node/src/ingress/public_v3/work_arithmetic.rs'
cmd=['/usr/bin/git','--git-dir',db,'show',head+':'+rel]
r=subprocess.run(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30);assert r.returncode==0 and not r.stderr
b=r.stdout;assert len(b)<1048576
path=D/'M8--trillionnium--crates--trnm-pon-node--src--ingress--public_v3--work_arithmetic.rs.original'
with open(path,'xb') as f:f.write(b)
lines=b.decode().splitlines()
g=D/'M8--trillionnium--crates--trnm-pon-node--src--ingress--public_v3--growth.rs.original'
fd=os.open(g,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
 a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1
 chunks=[]
 while True:
  z=os.read(fd,1048576)
  if not z:break
  chunks.append(z)
 gb=b''.join(chunks);k=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 assert k(a)==k(os.fstat(fd))==k(os.lstat(g))
finally:os.close(fd)
x={'schema':'trnm-policy-prefix-selected-production-profile-dispatch-v1','head':head,'work_arithmetic_capture':{'path':str(path),'source_path':rel,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'argv':cmd,'exit_code':0},'work_arithmetic_lines_1_to_100':'\n'.join(f'{n+1}: {s}' for n,s in enumerate(lines[:100])),'growth_capture':{'path':str(g),'bytes':len(gb),'sha256':hashlib.sha256(gb).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(gb)).encode()+b'\0'+gb).hexdigest()},'growth_lines_1_to_60':'\n'.join(f'{n+1}: {s}' for n,s in enumerate(gb.decode().splitlines()[:60])),'scope':'The three ordinary server call sites reach PublicPolicy::id through resource_profile. Other profile domains remain separate; unchanged bodies are not a claim of complete callgraph coverage.','tests_or_source_helpers_run':False}
raw=(json.dumps(x,indent=2,sort_keys=True)+'\n').encode();target=D/'production-profile-dispatch-closure.json'
with open(target,'xb') as f:f.write(raw)
print(json.dumps({'path':str(target),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'body':x},indent=2))
