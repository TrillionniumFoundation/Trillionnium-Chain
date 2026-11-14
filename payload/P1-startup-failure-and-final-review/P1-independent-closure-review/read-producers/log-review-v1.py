import os,sys,stat,re,json,hashlib,datetime
from pathlib import Path
x=json.loads(sys.argv[1]);D=Path('/private/tmp/chain-public-policy-P1-independent-closure-review-20261114-v1');out=[]
def sig(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(row):
 fd=os.open(row['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<1024*1024
  chunks=[]
  while True:
   z=os.read(fd,65536)
   if not z:break
   chunks.append(z)
  b=b''.join(chunks);assert sig(a)==sig(os.fstat(fd))==sig(os.lstat(row['path']))
  assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
  return b
 finally:os.close(fd)
def selected_flags(j):
 names={'status','production_activation','whole_chain_pq_qualified','pq_128_qualified','actual_lifetime_failure_bound','composition_coverage_proved','theorem_applicability_verified','cryptographic_acceptance','node_activated','runtime_implemented','activation','complete_callgraph_coverage_proved'}
 result=[]
 def visit(v,p=''):
  if type(v) is dict:
   for k,z in v.items():
    if k in names and type(z) in (str,bool,int,type(None)):result.append({'pointer':p+'/'+k,'type':type(z).__name__,'value':z})
    if type(z) in (dict,list):visit(z,p+'/'+k)
  elif type(v) is list:
   for i,z in enumerate(v):
    if type(z) in (dict,list):visit(z,p+'/'+str(i))
 visit(j)
 return result
for row in x:
 b=read(row);text=b.decode();r=dict(row,raw_verified=True)
 kind=row['kind']
 if kind=='python_pass':
  m=re.search(r'Ran (\d+) tests? in ',text);assert m and int(m.group(1))==row['expected_count']
  assert text.rstrip().endswith('OK') and not re.search(r'^FAILED|^ERROR:|^FAIL:',text,re.M)
  ok=re.findall(r'^test_\S+ .* \.\.\. ok$',text,re.M);assert len(ok)==row['expected_count']
  r['parsed']={'passed':len(ok),'failed':0,'errors':0,'skipped':0,'tail':text[-150:]}
 elif kind in ('rust_serial','rust_default'):
  m=re.search(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',text);assert m and tuple(map(int,m.groups()))==(row['expected_count'],0,0)
  names=re.findall(r'^test (\S+) \.\.\. ok$',text,re.M);assert len(names)==row['expected_count']
  r['parsed']={'passed':len(names),'failed':0,'ignored':0,'methods':names,'summary':m.group(0)}
 elif kind=='mac_compile_hold':
  errors=re.findall(r'^error\[[^\]]+\]:.*$',text,re.M)
  assert len(errors)==11 and 'due to 11 previous errors' in text and 'test result:' not in text
  r['parsed']={'compile_error_count':len(errors),'errors':errors,'tests_executed':False,'tail':text[-500:]}
 elif kind=='prior_tmpdir_hold':
  assert 'Ran 58 tests' in text and 'FAILED (failures=1, errors=4)' in text and 'symlink source refused' in text
  ok=re.findall(r'^test_\S+ .* \.\.\. ok$',text,re.M);assert len(ok)==53
  r['parsed']={'passed':53,'failures':1,'errors':4,'symlink_source_refusal_present':True,'tail':text[-350:]}
 elif kind in ('inspector_hold','contract_output','hash_use_scope'):
  j=json.loads(text);r['parsed']={'selected_flags':selected_flags(j)}
  if kind=='inspector_hold':assert j['status']=='HOLD' and j.get('production_activation') is False
  if kind=='hash_use_scope':r['parsed']['top_keys']=list(j)
 elif kind in ('rust_warning','clippy'):
  r['parsed']={'sqlite_unqualified_warning_retained':'SQLite I/O boundary UNQUALIFIED: RUSTC must be absolute' in text,'last_lines':text.splitlines()[-5:],'producer_returncode':row['producer_exit']}
  assert row['producer_exit']==0
 out.append(r)
report={'schema':'trnm-P1-independent-closed-log-documentation-review-v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'READ_ONLY_RECEIPT_CHECKS_PASS','count':len(out),'bytes_read':sum(z['bytes'] for z in out),'files':out,'tests_or_helpers_executed':False,'no_originals_modified':True,'scope':'Pinned closed raw streams supporting documented separate failures/serial/default passes and inspector scope; not a new run or hosted acceptance'}
raw=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode();p=D/'closed-log-documentation-review.json'
with open(p,'xb') as f:f.write(raw)
print(json.dumps({'status':report['status'],'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'items':[{'kind':r['kind'],'label':r['label'],'parsed':r['parsed']} for r in out]},indent=2))
