import os,sys,json,hashlib,stat,re
from pathlib import Path
B=Path('/private/tmp/chain-H5DF-W1-replay-callchain-review-20261114-v1')
M=B/'measurement-source-v1'
D=B/'measurement-excerpts-v1';D.mkdir(mode=0o700)
def put(n,b):
 p=D/n
 with p.open('xb')as f:f.write(b)
 return{'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
put('producer.py',sys.argv[1].encode())
index=json.loads((M/'source-index.json').read_text())['sources'];rows=[]
plans=[
 ('call-and-fixture.txt','0-ingress.rs.raw',[(1320,1345),(2670,2750)]),
 ('fixture-thread-and-replay.txt','2-public_v3_from_zero.rs.raw',[(1277,1510)]),
]
for name,src,ranges in plans:
 p=M/src;raw=p.read_bytes();pin=next(r['captured']for r in index if r['captured']['path']==str(p))
 assert len(raw)==pin['bytes']and hashlib.sha256(raw).hexdigest()==pin['sha256']
 ls=raw.decode().splitlines()
 rows.append(put(name,''.join('\n'+src+' lines '+str(a)+'-'+str(b)+'\n'+''.join(f'{i+1}: {ls[i]}\n'for i in range(a-1,b))for a,b in ranges).encode()))
p=B/'source-v1/33-store.rs.raw';raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()=='5918270368c61b420d26910dc5934714e1423f71c686b2d01f8d2e3ccceb990c'
ls=raw.decode().splitlines()
hs=[i for i,s in enumerate(ls)if re.search(r'fn remote_history_cpu_domain|fn begin_remote_history_cpu_epoch|remote_history_cpu:|cold_remote_history_epoch',s)]
rows.append(put('store-history-domain.txt',''.join(f'{i+1}: {ls[i]}\n'for i in sorted(set(j for h in hs for j in range(max(0,h-6),min(len(ls),h+48))))).encode()))
p=Path('/private/tmp/chain-prci-H5DF-cross-cost-selected-artifact-20261114-v1/selected-v1/members/from-zero-native/confirmation/report.json')
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
try:
 a=os.fstat(fd);raw=b''
 while True:
  b=os.read(fd,1048576)
  if not b:break
  raw+=b
 z=os.fstat(fd);assert(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)
 assert stat.S_ISREG(a.st_mode)and a.st_nlink==1 and len(raw)==13555781 and hashlib.sha256(raw).hexdigest()=='8b222dc0c57d1995dc2b33332d42cd7686078e5defa7e847abdd62816b40aaee'
finally:os.close(fd)
r=json.loads(raw);facts=[]
for i,p in enumerate(r['phases']):
 phase=[]
 for j,replay in enumerate(p['independent_history_page_replay']):
  o=replay['native_import_observation']
  phase.append({'replay_index':j,'replay_fields':{k:v for k,v in replay.items()if k!='native_import_observation'},'observation_keys':list(o),'packets':[{'packet_index':q['packet_index'],'packet_id':q['packet_id'],'work':next(x for x in q['phases']if x['phase']=='work')}for q in o['packets']],'host_checkpoint_attribution':o.get('host_checkpoint_attribution'),'native_attribution':o.get('native_attribution'),'measurement_failures':o['measurement_failures']})
 facts.append({'phase_index':i,'mode':p.get('mode'),'worker_count':p.get('attacker_workers'),'replays':phase})
pin=put('exact-work-host-attribution.json',(json.dumps({'original_report':{'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},'phases':facts},sort_keys=True,indent=2)+'\n').encode());rows.append(pin)
put('index.json',(json.dumps(rows,indent=2)+'\n').encode())
print(json.dumps({'files':rows},sort_keys=True))
