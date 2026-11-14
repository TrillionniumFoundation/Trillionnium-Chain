import os,subprocess,json,hashlib
from pathlib import Path
D=Path('/private/tmp/chain-public-policy-prefix-independent-review-20261114-v1')
env=os.environ.copy()
for k in list(env):
 if k.startswith('GIT_TRACE') or k=='GIT_CURL_VERBOSE':env.pop(k)
env.update(GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0',GIT_TRACE2='0',GIT_TRACE2_EVENT='0',GIT_TRACE2_PERF='0')
cmd=['/usr/bin/git','--git-dir','/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git','grep','-n','-e','fn resource_profile','-e','policy.id()','ed0d35487f2a67239e4d646fd41c2c7acb5cc740','--','trillionnium/crates/trnm-pon-node/src/ingress/public_v3']
p=subprocess.run(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
assert p.returncode in (0,1) and len(p.stdout)<32768
r={'argv':cmd,'exit_code':p.returncode,'stdout':p.stdout.decode(),'stderr':p.stderr.decode(),'read_only_no_lazy_fetch':True,'scope':'Only the immutable PublicV3 module subtree; this is symbol location, not full callgraph coverage'}
raw=(json.dumps(r,indent=2,sort_keys=True)+'\n').encode()
path=D/'resource-profile-definition-location.json'
with open(path,'xb') as f:f.write(raw)
print(json.dumps({'file':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'result':r},indent=2))
