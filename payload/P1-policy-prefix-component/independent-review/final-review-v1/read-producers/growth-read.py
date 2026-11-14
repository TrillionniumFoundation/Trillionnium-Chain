import os,stat,hashlib,json,re,subprocess
from pathlib import Path
D=Path('/private/tmp/chain-public-policy-prefix-independent-review-20261114-v1')
db='/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git';head='ed0d35487f2a67239e4d646fd41c2c7acb5cc740'
env=os.environ.copy()
for k in list(env):
 if k.startswith('GIT_TRACE') or k=='GIT_CURL_VERBOSE':env.pop(k)
env.update(GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0',GIT_TRACE2='0',GIT_TRACE2_EVENT='0',GIT_TRACE2_PERF='0')
rel='trillionnium/crates/trnm-pon-node/src/ingress/public_v3/growth.rs'
cmd=['/usr/bin/git','--git-dir',db,'show',head+':'+rel]
p=subprocess.run(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
assert p.returncode==0 and not p.stderr
b=p.stdout;assert len(b)<1048576
target=D/'M8--trillionnium--crates--trnm-pon-node--src--ingress--public_v3--growth.rs.original'
with open(target,'xb') as f:f.write(b)
lines=b.decode().splitlines();contexts=[]
for i,s in enumerate(lines):
 if 'fn resource_profile' in s or 'policy.id()' in s:
  start=max(0,i-5);end=min(len(lines),i+22)
  contexts.append({'matched_line':i+1,'start':start+1,'end':end,'text':'\n'.join(f'{n+1}: {lines[n]}' for n in range(start,end))})
assert any('fn resource_profile' in x['text'] for x in contexts)
x={'schema':'trnm-policy-prefix-growth-profile-callchain-v1','head':head,'capture':{'path':str(target),'source_path':rel,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'argv':cmd,'exit_code':0},'contexts':contexts,'tests_or_source_helpers_run':False}
raw=(json.dumps(x,indent=2,sort_keys=True)+'\n').encode();path=D/'production-growth-policy-callchain.json'
with open(path,'xb') as f:f.write(raw)
print(json.dumps({'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'capture':x['capture'],'contexts':contexts},indent=2))
