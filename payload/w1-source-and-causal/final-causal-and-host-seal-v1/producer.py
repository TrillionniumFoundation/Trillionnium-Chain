import os,sys,json,pathlib,hashlib,stat
BASE=pathlib.Path('/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1')
D=BASE/'final-causal-and-host-seal-v1'
if D.exists():raise RuntimeError('create-only seal')
D.mkdir(mode=0o700)
def enc(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
def ident(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def raw_read(p,sha=None,n=None):
 p=pathlib.Path(p)
 if p.resolve(strict=True)!=p:raise RuntimeError('canonical')
 a=os.lstat(p)
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK),'rb')as f:
  q=os.fstat(f.fileno())
  if ident(q)!=ident(a)or not stat.S_ISREG(q.st_mode)or q.st_nlink!=1 or q.st_size>65536:raise RuntimeError('source shape')
  b=f.read(65537)
  if len(b)!=q.st_size or ident(q)!=ident(os.fstat(f.fileno()))or ident(q)!=ident(os.lstat(p)):raise RuntimeError('source changed')
 if sha is not None and hashlib.sha256(b).hexdigest()!=sha:raise RuntimeError('sha')
 if n is not None and len(b)!=n:raise RuntimeError('size')
 return b
def put(name,b):
 if isinstance(b,str):b=b.encode()
 if len(b)>65536:raise RuntimeError('cap')
 fd=os.open(D/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as f:f.write(b);f.flush();os.fsync(f.fileno())
 raw_read(D/name,hashlib.sha256(b).hexdigest(),len(b))
 return D/name
put('producer.py',sys.argv[1])
a=json.loads(sys.argv[2])
for name,v in a.items():put(name+'.json',enc(v))
def dec(v):
 return v.get('structuredContent')or json.loads(v['content'][0]['text'])
v1=dec(a['v1_terminal']);v2=dec(a['v2_terminal'])
if v1['status']['exit_code']!=1 or not v1['output_complete'] or 'small-output cap: attacker-cpu.json'not in v1['text']:raise RuntimeError('wrong failed run')
if v2['status']['exit_code']!=0 or not v2['output_complete']or v2['next_offset']!=2965:raise RuntimeError('wrong closed run')
b=raw_read(BASE/'final-causal-and-host-review-v2/OUTPUT_INDEX.json','307f9a94a26f5babf8accd712cef6ee1a818034326008d59545a97e593d83e45',2990);idx=json.loads(b)
files=[]
for entry in idx['files']:
 raw_read(entry['path'],entry['sha256'],entry['bytes']);files.append(pathlib.Path(entry['path']))
files.append(BASE/'final-causal-and-host-review-v2/OUTPUT_INDEX.json')
for name in ('producer.py','analysis-input.json','cpu-phases.json'):
 files.append(BASE/'final-causal-and-host-review-v1'/name)
put('README.md','''# R1 diagnosis closure records

The final small report is ../final-causal-and-host-review-v2/review.md and summary.json. Its OUTPUT_INDEX pins all eleven outputs. The two original ZIPs and large reports remain references; no duplicate copy, tests, native/profiling execution, network requests, source/Git/ref/config or stage writes were performed by this closure.

The first code-mode orchestration failed before target launch because TextEncoder was unavailable. The first actual packaging run exited 1 when attacker-cpu.json exceeded the explicit 64 KiB output cap; its three already-written ordinary files and authoritative terminal are retained unchanged. The second run reduces only the displayed per-worker fields, retaining original full derived evidence and all claims. It exited 0 with complete 2965-byte output.

The final per-phase JSON is 61163 bytes; each other direct-read output and each record in this seal directory is also at most 64 KiB. None of these read-only packaging statuses is a test or four-second qualification pass.

The EVIDENCE_INDEX references existing original files by exact absolute Mac path and digest, without moving or modifying them. This directory's own index and seal are intentionally outside the index's noncircular member list.
''')
files.extend(p for p in D.iterdir()if p.is_file())
rows=[]
for p in sorted(set(files),key=str):
 b=raw_read(p)
 rows.append({'path':str(p.relative_to(BASE)),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'origin':{'host':'mac','path':str(p)}})
index={'schema':'trnm-r1-causal-and-host-review-closure-index-v1','root':str(BASE),'files':rows,'file_count':len(rows),'total_bytes':sum(r['bytes']for r in rows),'runtime_result_unchanged':'CONFIRMATION_TARGET failed; no adequate safe optimization demonstrated','all_files_at_most_65536_bytes':True}
ib=enc(index);put('EVIDENCE_INDEX.json',ib)
seal={'schema':'trnm-r1-causal-and-host-review-seal-v1','index':{'path':str(D/'EVIDENCE_INDEX.json'),'bytes':len(ib),'sha256':hashlib.sha256(ib).hexdigest()},'indexed_file_count':len(rows),'indexed_total_bytes':index['total_bytes'],'first_packaging_exit':1,'final_packaging_exit':0,'target_terminal_output_complete':True,'stage_writer':False,'source_or_network_or_test_actions':False}
sb=enc(seal);put('SEAL.json',sb)
print(json.dumps({'status':'SEALED_READONLY_DIAGNOSIS','directory':str(D),'index':seal['index'],'seal':{'path':str(D/'SEAL.json'),'bytes':len(sb),'sha256':hashlib.sha256(sb).hexdigest()},'indexed_file_count':len(rows),'indexed_total_bytes':index['total_bytes']},ensure_ascii=False))
