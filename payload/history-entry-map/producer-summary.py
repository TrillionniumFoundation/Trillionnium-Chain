import os,sys,json,pathlib,hashlib,stat
D=pathlib.Path('/private/tmp/chain-R1-history-4105-entry-map-20261114-v1')
def enc(v):return(json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
def put(n,b):
 if isinstance(b,str):b=b.encode()
 if len(b)>65536:raise RuntimeError('small-output cap')
 with(D/n).open('xb')as f:f.write(b);f.flush();os.fsync(f.fileno())
def read(p,sha=None,n=None):
 p=pathlib.Path(p);a=os.lstat(p)
 if p.resolve(strict=True)!=p or not stat.S_ISREG(a.st_mode)or a.st_nlink!=1:raise RuntimeError('regular canonical')
 fp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK),'rb')as f:
  if fp(os.fstat(f.fileno()))!=fp(a):raise RuntimeError('open identity')
  b=f.read(1024*1024+1)
  if len(b)!=a.st_size or fp(os.fstat(f.fileno()))!=fp(a)or fp(os.lstat(p))!=fp(a):raise RuntimeError('changed')
 if sha is not None and hashlib.sha256(b).hexdigest()!=sha:raise RuntimeError('sha')
 if n is not None and len(b)!=n:raise RuntimeError('size')
 return b
put('producer-summary.py',sys.argv[1])
report=json.loads(sys.argv[2])
refs=[]
for n in('workflow-source.json','runner-source.json','native-source.json'):
 q=json.loads(read(D/n));b=read(q['capture'],q['sha256'],q['bytes'])
 if hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()!=q['git_blob']:raise RuntimeError('source blob')
 q['url']='https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/'+report['source']['commit']+'/'+q['path'];refs.append(q)
host='/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/scripts--ci--run_from_zero_host.py'
b=read(host,'2840de7cc19626c32d165bcfd032479db27180f03516ba3cefb0dafdaf61f4eb',28366)
refs.append({'source':report['source']['commit'],'path':'scripts/ci/run_from_zero_host.py','git_blob':'df0643a36ab7110d0b5af9d13cd9e291bbf022f0','capture':host,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'url':'https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/'+report['source']['commit']+'/scripts/ci/run_from_zero_host.py'})
report['source_references']=refs
put('entry-map.json',enc(report))
put('README.md','''# R1 4105-block history entry map

This is only a fixed-source entry/budget/artifact map for job 132475258347. The job metadata was supplied by root; this map has not read the original failed job log and does not assert its cause.

Workflow: original 180-minute native-priorities job, separate prepare, then run_from_zero_host.py -> run_history_native.py -> the exact prepared ancestry_long_sync release ELF and one original ignored selector. The history adapter introduces no execution timeout or from-zero 900-second bound. The Host systemd TimeoutStopSec=20s is cleanup, not a runtime deadline.

The original test creates/adopts all 4105 real work blocks, renews the V3 task four times, checks corruption refusal, and serves paid PublicV2 loopback RPC for a separate strict public History verifier. The server has an original finite lifetime of1800s and original2s policy; this is not the four-second/16-worker confirmation experiment.

Inspect the actual server exit evidence, independent sync error/stage/cursor, native history.log, summary.json and runner manifest before attributing failure. The recorded completed-import count is not a durable-block count. No native test/helper or captured source was executed; no network, source/ref/config or stage mutation occurred.
''')
rows=[]
for p in sorted(D.iterdir()):
 if not p.is_file():raise RuntimeError('unexpected directory')
 b=read(p)
 rows.append({'path':p.name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'origin':{'host':'mac','path':str(p)}})
ib=enc({'schema':'trnm-r1-history-4105-entry-map-index-v1','files':rows,'file_count':len(rows),'total_bytes':sum(x['bytes']for x in rows),'readonly_source_only':True})
put('EVIDENCE_INDEX.json',ib)
for n in('entry-map.json','README.md','EVIDENCE_INDEX.json'):
 b=read(D/n);print(json.dumps({'path':str(D/n),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}))
print(json.dumps({'files_before_index':len(rows),'bytes_before_index':sum(x['bytes']for x in rows),'status':'CLOSED_STATIC_ENTRY_MAP_NOT_CAUSE'}))
