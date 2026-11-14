import os,sys,json,hashlib,subprocess,re
from pathlib import Path
B=Path('/private/tmp/chain-H5DF-W1-replay-callchain-review-20261114-v1')
D=B/'domain-source-v1';D.mkdir(mode=0o700)
def put(n,b):
 p=D/n
 with p.open('xb')as f:f.write(b)
 return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
put('producer.py',sys.argv[1].encode())
src='trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs'
env=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_TERMINAL_PROMPT='0',GIT_OPTIONAL_LOCKS='0')
oids=[]
for rev in ['5df7ae6f482157c5f7fdcbcd52222117a965053f','2a86462a1ab20c68151719ba4635e3c294391e64']:
 q=subprocess.run(['/usr/bin/git','--git-dir=/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git','ls-tree','-z',rev,'--',src],capture_output=True,timeout=30,env=env);assert q.returncode==0
 meta,path=q.stdout.rstrip(b'\0').split(b'\t');mode,typ,oid=meta.decode().split();assert path.decode()==src and mode=='100644'and typ=='blob';oids.append(oid)
q=subprocess.run(['/usr/bin/git','--git-dir=/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git','cat-file','blob',oids[0]],capture_output=True,timeout=30,env=env);assert q.returncode==0 and len(q.stdout)<1024*1024
assert hashlib.sha1(b'blob '+str(len(q.stdout)).encode()+b'\0'+q.stdout).hexdigest()==oids[0]
pin=put('operator_continuous_owner.rs.raw',q.stdout);ls=q.stdout.decode().splitlines()
ep=put('remote-history-domain.txt',''.join(f'{i+1}: {ls[i]}\n'for i in range(529,min(len(ls),599))).encode())
index=json.loads((B/'source-v1/source-index.json').read_text());hits=[]
for row in index['source_rows']:
 if 'pon_work'not in row['source']:continue
 raw=Path(row['captured']['path']).read_bytes();assert hashlib.sha256(raw).hexdigest()==row['captured']['sha256']
 for i,s in enumerate(raw.decode().splitlines()):
  if re.search(r'verify_checked_with_kernel|evaluate_transcript_kernel_with_progress|CheckedProofInputs\s*\{',s):
   hits.append({'source':row['source'],'line':i+1,'text':s})
hp=put('private-kernel-callers.json',(json.dumps(hits,indent=2)+'\n').encode())
summary={'source':src,'H5DF_oid':oids[0],'R1_oid':oids[1],'same_R1_H5DF':oids[0]==oids[1],'raw':pin,'excerpt':ep,'private_callers':hp}
put('summary.json',(json.dumps(summary,indent=2)+'\n').encode())
print(json.dumps({'summary':summary,'domain_excerpt':(D/'remote-history-domain.txt').read_text(),'callers':hits},sort_keys=True))
