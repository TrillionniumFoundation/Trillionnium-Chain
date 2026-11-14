import os,sys,stat,json,hashlib,subprocess,ast,copy,re,datetime
from pathlib import Path
x=json.loads(sys.argv[1]);D=Path(x['directory']);D.mkdir(mode=0o700)
base=x['base'];head=x['head'];db='/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git'
env=os.environ.copy()
for k in list(env):
 if k.startswith('GIT_TRACE') or k=='GIT_CURL_VERBOSE':env.pop(k)
env.update(GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0',GIT_TRACE2='0',GIT_TRACE2_EVENT='0',GIT_TRACE2_PERF='0')
commands=[];cache={};fences={}
def digest(b):return hashlib.sha256(b).hexdigest()
def oid(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def put(n,b):
 with open(D/n,'xb') as f:f.write(b)
def jput(n,v):put(n,(json.dumps(v,indent=2,sort_keys=True)+'\n').encode())
def git(*a):
 cmd=['/usr/bin/git','--git-dir',db,*a]
 p=subprocess.run(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
 assert p.returncode==0 and not p.stderr,(cmd,p.returncode,p.stderr[-300:])
 assert len(p.stdout)<4*1024*1024
 commands.append({'argv':cmd,'exit_code':0,'bytes':len(p.stdout),'sha256':digest(p.stdout)})
 return p.stdout
def source(ref,path):
 if (ref,path) not in cache:cache[(ref,path)]=git('show',ref+':'+path)
 return cache[(ref,path)]
def sig(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,n=None,h=None):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<4*1024*1024
  chunks=[]
  while True:
   z=os.read(fd,262144)
   if not z:break
   chunks.append(z)
  b=b''.join(chunks);assert sig(a)==sig(os.fstat(fd))==sig(os.lstat(p))
  assert n is None or len(b)==n
  assert h is None or digest(b)==h
  fences[str(p)]=sig(a)
  return b
 finally:os.close(fd)
def pairs(items):
 out={}
 for k,v in items:
  assert k not in out,'duplicate JSON key'
  out[k]=v
 return out
def parse(b):return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError(x)))
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def td(a,b,path=()):
 if type(a) is not type(b):return [{'path_parts':list(path),'old_type':type(a).__name__,'new_type':type(b).__name__,'old':a,'new':b}]
 if type(a) is dict:
  assert set(a)==set(b),('mapping key set changed',path)
  return [d for k in a for d in td(a[k],b[k],path+(k,))]
 if type(a) is list:
  assert len(a)==len(b),('list length changed',path)
  return [d for i,(av,bv) in enumerate(zip(a,b)) for d in td(av,bv,path+(i,))]
 return [] if a==b else [{'path_parts':list(path),'type':type(a).__name__,'old':a,'new':b}]
try:
 raw=git('cat-file','commit',head);put('commit.original',raw)
 assert hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==head
 header=raw.split(b'\n\n',1)[0].splitlines()
 tree=[s.split(b' ',1)[1].decode() for s in header if s.startswith(b'tree ')];parents=[s.split(b' ',1)[1].decode() for s in header if s.startswith(b'parent ')]
 assert tree==[x['tree']] and parents==[base]
 paths=git('diff','--no-ext-diff','--no-textconv','--name-only','-z',base,head).decode().strip('\0').split('\0')
 assert paths==x['expected_paths'] and len(paths)==10
 rawdiff=git('diff','--no-ext-diff','--no-textconv','--raw','--no-abbrev','-z',base,head);put('immutable-raw-diff.original',rawdiff)
 records=rawdiff.split(b'\0');assert records[-1]==b'';records=records[:-1]
 assert len(records)==20
 for header,path in zip(records[::2],records[1::2]):
  cols=header.decode().split();assert cols[0]==':100644' and cols[1]=='100644' and cols[-1]=='M'
 patch=read(Path(x['patch']['path']),x['patch']['bytes'],x['patch']['sha256']);put('author-final-patch.original',patch)
 actual=git('diff','--no-ext-diff','--no-textconv','--no-color','--binary','--full-index',base,head)
 norm=lambda b:re.sub(rb'(?m)^index [0-9a-f]+\.\.[0-9a-f]+( .*)?$',rb'index OID..OID\1',b)
 assert norm(patch)==norm(actual),'author patch differs from actual P1 diff'
 put('immutable-full-index-diff.original',actual)
 inventory=[]
 for path in paths:
  a=source(base,path);b=source(head,path)
  inventory.append({'path':path,'old':{'bytes':len(a),'sha256':digest(a),'git_blob':oid(a)},'new':{'bytes':len(b),'sha256':digest(b),'git_blob':oid(b)}})
 frozen=[]
 for path,h in x['metadata']['frozen_files_unchanged'].items():
  a=source(base,path);b=source(head,path);assert a==b and digest(b)==h
  frozen.append({'path':path,'bytes':len(b),'sha256':h,'git_blob':oid(b),'same_as_M8':True})
 mp='config/pon/pq128-source-correspondence-current-v2.json';cp='config/pon/pq128-lifetime-composition-current-v3.json'
 om,nm=parse(source(base,mp)),parse(source(head,mp));oc,nc=parse(source(base,cp)),parse(source(head,cp))
 md=td(om,nm);cd=td(oc,nc)
 expected_public='trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs'
 assert {tuple(t['path_parts']) for t in md}=={('current_source_files_sha256',expected_public),('current_source_snapshot_sha256',)}
 assert {tuple(t['path_parts']) for t in cd}=={('current_lifetime_correspondence','sha256'),('current_lifetime_correspondence','source_snapshot_sha256')}
 assert len(md)==len(cd)==2
 assert len(nm['current_source_files_sha256'])==21 and set(nm['current_source_files_sha256'])==set(om['current_source_files_sha256'])
 oldmap=digest(source(base,mp));newmap=digest(source(head,mp));oldcanon=digest(canonical(om['current_source_files_sha256']));newcanon=digest(canonical(nm['current_source_files_sha256']))
 assert oldcanon==om['current_source_snapshot_sha256'] and newcanon==nm['current_source_snapshot_sha256']
 assert newmap==x['metadata']['new_map_sha256'] and newcanon==x['metadata']['new_snapshot_sha256']
 assert nc['current_lifetime_correspondence']=={'path':mp,'sha256':newmap,'source_snapshot_sha256':newcanon}
 twentyone=[]
 for path in sorted(nm['current_source_files_sha256']):
  a=source(base,path);b=source(head,path)
  assert digest(a)==om['current_source_files_sha256'][path] and digest(b)==nm['current_source_files_sha256'][path]
  twentyone.append({'path':path,'old':{'bytes':len(a),'sha256':digest(a),'git_blob':oid(a)},'new':{'bytes':len(b),'sha256':digest(b),'git_blob':oid(b)},'changed':a!=b})
 assert [z['path'] for z in twentyone if z['changed']]==[expected_public]
 astproof=[]
 for path in ('scripts/ci/pq_lifetime_current_v2.py','scripts/ci/pq_lifetime_composition.py'):
  a=source(base,path);b=source(head,path)
  assert a.count(oldmap.encode())==1 and a.count(oldcanon.encode())==1
  assert a.replace(oldmap.encode(),newmap.encode()).replace(oldcanon.encode(),newcanon.encode())==b
  aa=ast.parse(a);bb=ast.parse(b);updates=[]
  for node in ast.walk(aa):
   if isinstance(node,ast.Constant) and type(node.value) is str and node.value in (oldmap,oldcanon):
    before=node.value;node.value={oldmap:newmap,oldcanon:newcanon}[node.value];updates.append({'line':node.lineno,'old':before,'new':node.value})
  assert len(updates)==2 and ast.dump(aa,include_attributes=False)==ast.dump(bb,include_attributes=False)
  astproof.append({'path':path,'changed_string_constants':updates,'AST_otherwise_identical':True,'exact_text_otherwise_identical':True})
 docs=[]
 for path in ('docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md','docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'):
  a=source(base,path);b=source(head,path);assert b.startswith(a)
  docs.append({'path':path,'change':'append-only','old_bytes':len(a),'new_bytes':len(b),'append_bytes':len(b)-len(a),'append_sha256':digest(b[len(a):])})
 for path in ('docs/security/PQ128_LIFETIME_BUDGET_V1.md','docs/security/PQ128_LIFETIME_COMPOSITION_V2.md'):
  a=source(base,path);b=source(head,path);assert a.count(oldmap.encode())==1 and a.count(oldcanon.encode())==1
  assert a.replace(oldmap.encode(),newmap.encode()).replace(oldcanon.encode(),newcanon.encode())==b
  docs.append({'path':path,'change':'only two current digest strings replaced','historical_prose_and_qualifications_unchanged':True})
 corpuspath='config/pon/pq-cross-branch-corpus-v1.json';a=parse(source(base,corpuspath));b=parse(source(head,corpuspath));corpusdiff=td(a,b)
 assert len(corpusdiff)==8 and all(len(z['path_parts'])==2 and z['path_parts'][0]=='pinned_blobs' for z in corpusdiff)
 for z in corpusdiff:
  path=z['path_parts'][1];assert z['new']==oid(source(head,path)) and z['old']==oid(source(base,path))
 tests=[]
 testpins={z['path']:z['sha256'] for z in x['consumer']['suites']}
 testpins.update({'scripts/ci/test_pon_public_v3_policy_read.py':'f423a03fa0757b21927dbcb5e5ed977d729aecefee131d725a5f7be56a2c706f','scripts/ci/test_hash_use_contract.py':'6f70a7335ae33f0f5adcaf14fcc6fb783da16c59e945eab2fd637ed25cee881f'})
 for path,h in testpins.items():
  a=source(base,path);b=source(head,path);assert a==b and digest(b)==h
  tests.append({'path':path,'bytes':len(b),'sha256':h,'git_blob':oid(b),'M8_P1_exact_equal':True})
 consumer_bind=[]
 for label,s in [('current-consumer-validation-v2',x['consumer']),('final-contract-validation-v1',x['contract'])]:
  assert s['source_before']==s['source_after']
  items=[]
  for path,v in s['source_before'].items():
   b=source(head,path);items.append({'path':path,'receipt':v,'P1':{'bytes':len(b),'sha256':digest(b)},'matches':v=={'bytes':len(b),'sha256':digest(b)}})
  consumer_bind.append({'label':label,'source_before_after_equal':True,'all_selected_source_receipt_bytes_equal_P1':all(i['matches'] for i in items),'rows':items})
 refs=[]
 for r in x['summary_refs']:
  b=read(Path(r['path']),r['bytes'],r['sha256']);refs.append(r)
 result={'schema':'trnm-P1-independent-static-metadata-closure-v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'STATIC_CHECKS_PASS','head':head,'tree':tree[0],'sole_parent':parents[0],'author_patch_exact_to_commit_except_index_abbreviation':True,'inventory':inventory,'frozen3':frozen,'typed_current_map_changes':md,'typed_composition_changes':cd,'source21':twentyone,'changed_current_source_count':1,'map_raw_sha256':newmap,'canonical_source_map_sha256':newcanon,'reader_AST_changes':astproof,'documentation_changes':docs,'corpus_pin_changes':corpusdiff,'tests_unchanged':tests,'validation_source_correspondence':consumer_bind,'pinned_existing_receipts':refs,'qualification_or_mathematics_changed':False,'tests_or_source_helpers_run':False,'source_git_stage_network_mutations':False,'commands':commands}
 jput('static-metadata-closure.json',result)
 print(json.dumps({'status':result['status'],'head':head,'tree':tree[0],'sole_parent':parents[0],'changed_paths':len(paths),'frozen3':frozen,'map_raw_sha256':newmap,'canonical_source_map_sha256':newcanon,'changed_current_source_count':1,'reader_AST_changes':astproof,'corpus_updated_pins':len(corpusdiff),'validation_binding':[{k:z[k] for k in ('label','source_before_after_equal','all_selected_source_receipt_bytes_equal_P1')} for z in consumer_bind],'receipt':{'path':str(D/'static-metadata-closure.json'),'bytes':(D/'static-metadata-closure.json').stat().st_size,'sha256':digest((D/'static-metadata-closure.json').read_bytes())}},indent=2))
except BaseException as e:
 jput('failure.json',{'status':'STATIC_INSPECTION_FAILED','error':type(e).__name__+': '+str(e),'commands':commands,'tests_run':False,'source_git_stage_mutated':False})
 raise
