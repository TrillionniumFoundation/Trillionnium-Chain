import os,sys,json,hashlib,subprocess,re,stat
from pathlib import Path
D=Path("/private/tmp/chain-H5DF-W1-replay-callchain-review-20261114-v1")/'measurement-source-v1';D.mkdir(mode=0o700)
def put(n,b):
 p=D/n
 with p.open('xb') as f:f.write(b)
 return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
put('producer.py',sys.argv[1].encode())
G='/usr/bin/git';DB='/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git'
H='5df7ae6f482157c5f7fdcbcd52222117a965053f';R='2a86462a1ab20c68151719ba4635e3c294391e64'
env=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_TERMINAL_PROMPT='0',GIT_OPTIONAL_LOCKS='0')
paths=['trillionnium/crates/trnm-pon-node/src/ingress.rs','trillionnium/crates/trnm-pon-node/src/ingress/history_import/observation.rs','trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs']
rows=[];hits={}
for i,p in enumerate(paths):
 vals=[]
 for rev in [H,R]:
  q=subprocess.run([G,'--git-dir='+DB,'ls-tree','-z',rev,'--',p],capture_output=True,timeout=30,env=env);assert q.returncode==0
  meta,name=q.stdout.rstrip(b'\0').split(b'\t');mode,typ,oid=meta.decode().split();assert name.decode()==p and mode=='100644' and typ=='blob'
  vals.append(oid)
 q=subprocess.run([G,'--git-dir='+DB,'cat-file','blob',vals[0]],capture_output=True,timeout=30,env=env);assert q.returncode==0 and len(q.stdout)<3*1024*1024
 assert hashlib.sha1(b'blob '+str(len(q.stdout)).encode()+b'\0'+q.stdout).hexdigest()==vals[0]
 pin=put(str(i)+'-'+Path(p).name+'.raw',q.stdout);row={'source':p,'H5DF_oid':vals[0],'R1_oid':vals[1],'same_R1_H5DF':vals[0]==vals[1],'captured':pin};rows.append(row)
 lines=q.stdout.decode().splitlines()
 pattern=r'observe_submit_phase|fn signed_confirmation_phase_with_builder|fn .*history|struct HistoryImportObserver|fn new\(|fn .*phase|receive_public_page_from_before_observed|client_replays|work_cpu_ns|HistoryImportObserver::new|thread::spawn|let mut verifier|remote_history|ThreadCpuStamp'
 hits[p]=[{'line':j+1,'text':s}for j,s in enumerate(lines)if re.search(pattern,s)]
 if i==1:
  put('history-observation-numbered.txt',''.join(f'{j+1}: {s}\n'for j,s in enumerate(lines)).encode())
sp=Path("/private/tmp/chain-H5DF-W1-replay-callchain-review-20261114-v1")/'source-v1'
for filename,source,ranges in [
 ('request-phase-boundaries.txt','31-request_observation.rs.raw',[(1230,1518)]),
 ('scalar-domain-and-promotion.txt','32-scalar_cpu.rs.raw',[(468,635),(1000,1107),(1380,1430)]),
]:
 raw=(sp/source).read_bytes();expected=next(x for x in json.loads((sp/'source-index.json').read_text())['source_rows']if x['captured']['path'].endswith(source))['captured']
 assert len(raw)==expected['bytes'] and hashlib.sha256(raw).hexdigest()==expected['sha256']
 lines=raw.decode().splitlines()
 put(filename,''.join('\n'+source+' lines '+str(a)+'-'+str(b)+'\n'+''.join(f'{j+1}: {lines[j]}\n'for j in range(a-1,b))for a,b in ranges).encode())
idx=put('source-index.json',(json.dumps({'sources':rows,'sites':hits},sort_keys=True,indent=2)+'\n').encode())
print(json.dumps({'index':idx,'sources':rows,'sites':hits},sort_keys=True))
