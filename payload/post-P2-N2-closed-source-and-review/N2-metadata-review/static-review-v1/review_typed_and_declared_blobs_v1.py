#!/usr/bin/env python3
"""Static typed/AST and content-address review; do not import repository modules."""
import ast,copy,difflib,hashlib,json,os,re,subprocess,sys,time,traceback
from pathlib import Path
B=Path('/private/tmp/chain-N2-metadata-integration-review-20261114-v1');O=B/'static-review-v1'
D=Path('/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git')
heads={'N':'5a4b7fe8de1adce803184f262fd9f704ead1930c','N2':'096c6b5f9b952c49389fd975515744074ba61317','P2':'1e54c4ff66a92827c83bea8715f59f6b299e98cf'}
HP='config/pon/hash-use-contract-v1.json';RP='scripts/ci/hash_use_contract.py';CP='config/pon/pq-cross-branch-corpus-v1.json';IP='trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs'
if os.path.lexists(O):raise ValueError('create-only static review')
O.mkdir(mode=0o700)
env=os.environ.copy();env.update(GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0',GIT_ALLOW_PROTOCOL='',GIT_PAGER='cat',PYTHONDONTWRITEBYTECODE='1',PYTHONOPTIMIZE='0')
for k in list(env):
 if k.startswith('GIT_TRACE')or k=='GIT_CURL_VERBOSE':env.pop(k,None)
env.update(GIT_TRACE2='0',GIT_TRACE2_EVENT='0',GIT_TRACE2_PERF='0')
def sha(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def js(x):return (json.dumps(x,indent=2,sort_keys=True)+'\n').encode()
def put(p,b):
 with p.open('xb')as f:f.write(b)
 if p.read_bytes()!=b:raise ValueError('readback')
 return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
put(O/'review_typed_and_declared_blobs_v1.py',sys.argv[1].encode())
def source(label,path):return (B/'sources'/(label+'--'+path.replace('/','--')+'.original')).read_bytes()
def consts(raw):
 out={}
 for n in ast.parse(raw).body:
  if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
   try:out[n.targets[0].id]=ast.literal_eval(n.value)
   except (ValueError,TypeError):pass
 return out
def norm(raw):
 t=ast.parse(raw)
 for n in t.body:
  if isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id=='REVIEWED_SOURCE_MAP_SHA256'for x in n.targets):n.value=ast.Constant(value='ONLY_REVIEWED_SOURCE_MAP_DIGEST')
 return ast.dump(t,include_attributes=False)
def typed(a,b,path=()):
 if type(a)is not type(b):return [{'path':list(path),'before':a,'after':b,'kind':'type'}]
 if isinstance(a,dict):
  out=[]
  for k in sorted(set(a)|set(b)):
   if k not in a:out.append({'path':list(path+(k,)),'after':b[k],'kind':'added'})
   elif k not in b:out.append({'path':list(path+(k,)),'before':a[k],'kind':'removed'})
   else:out.extend(typed(a[k],b[k],path+(k,)))
  return out
 if isinstance(a,list):
  if a==b:return []
  return [{'path':list(path),'before':a,'after':b,'kind':'list'}]
 return []if a==b else[{'path':list(path),'before':a,'after':b,'kind':'value'}]
state={'schema':'trnm-N2-metadata-static-review-v1','status':'HOLD','steps':[],'tests_or_repository_helpers_executed':False,'worktree_refs_stage_network_mutated':False,'errors':[]}
def run(label,args,input=None):
 argv=['/usr/bin/git','--git-dir='+str(D),'-c','protocol.allow=never',*args]
 r=subprocess.run(argv,input=input,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 if len(r.stdout)>16*1024*1024:raise ValueError('bounded source input')
 state['steps'].append({'label':label,'argv':argv,'exit':r.returncode,'stdout':put(O/(label+'.stdout'),r.stdout),'stderr':put(O/(label+'.stderr'),r.stderr)})
 if r.returncode:raise ValueError('read failed '+label)
 return r.stdout
try:
 manifests={n:json.loads(source(n,HP))for n in heads}
 readers={n:source(n,RP)for n in heads};constants={n:consts(r)for n,r in readers.items()}
 for n in heads:
  m=manifests[n];c=constants[n]
  if sha(canon(m['source_files']))!=c['REVIEWED_SOURCE_MAP_SHA256']:raise ValueError('map literal '+n)
  if sha(canon({k:v for k,v in m.items()if k!='source_files'}))!=c['REVIEWED_SEMANTICS_SHA256']:raise ValueError('semantics literal '+n)
  if len(m['source_files'])!=31 or len(m['uses'])!=19 or set(m['uses'])!=set(c['USES']):raise ValueError('closed roster')
  used=set(p for u in m['uses'].values()for p in u['source_paths'])
  if used!=set(m['source_files']):raise ValueError('source/use coverage')
 if len({norm(x)for x in readers.values()})!=1:raise ValueError('reader semantic AST changed')
 semantics={n:{k:v for k,v in m.items()if k!='source_files'}for n,m in manifests.items()}
 if not(semantics['N']==semantics['N2']==semantics['P2']):raise ValueError('typed semantics changed')
 hashreview={'N_to_N2_typed_changes':typed(manifests['N'],manifests['N2']),'P2_to_N2_typed_changes':typed(manifests['P2'],manifests['N2']),'same_19_use_semantics_and_31_paths':True,'reader_AST_equal_except_one_map_literal':True,'review_base':constants['P2']['REVIEW_BASE'],'max_bytes':1024*1024,'max_source_bytes':2*1024*1024,'max_depth':64,'qualification':manifests['P2']['qualification'],'map_commitments':{n:constants[n]['REVIEWED_SOURCE_MAP_SHA256']for n in heads},'semantics_commitment':constants['P2']['REVIEWED_SEMANTICS_SHA256'],'selected_P2_hash_manifest_oid':blob(source('P2',HP)),'selected_P2_hash_reader_oid':blob(readers['P2'])}
 corpus={n:json.loads(source(n,CP))for n in heads}
 def corpusdelta(a,b):
  x,y=corpus[a],corpus[b]
  return {'pinned_count_before':len(x['pinned_blobs']),'pinned_count_after':len(y['pinned_blobs']),'required_count_before':len(x['required_paths']),'required_count_after':len(y['required_paths']),'pins_added':{k:v for k,v in y['pinned_blobs'].items()if k not in x['pinned_blobs']},'pins_removed':{k:v for k,v in x['pinned_blobs'].items()if k not in y['pinned_blobs']},'pins_changed':{k:{'before':x['pinned_blobs'][k],'after':y['pinned_blobs'][k]}for k in x['pinned_blobs'].keys()&y['pinned_blobs'].keys()if x['pinned_blobs'][k]!=y['pinned_blobs'][k]},'required_added':sorted(set(y['required_paths'])-set(x['required_paths'])),'required_removed':sorted(set(x['required_paths'])-set(y['required_paths'])),'required_order_equal':x['required_paths']==y['required_paths'],'other_typed_changes':typed({k:v for k,v in x.items()if k not in ['pinned_blobs','required_paths']},{k:v for k,v in y.items()if k not in ['pinned_blobs','required_paths']})}
 corpusreview={'N_to_N2':corpusdelta('N','N2'),'P2_to_N2':corpusdelta('P2','N2')}
 if corpusreview['N_to_N2']['pins_added']or corpusreview['N_to_N2']['pins_removed']or not corpusreview['N_to_N2']['required_order_equal']or corpusreview['N_to_N2']['other_typed_changes']:raise ValueError('unexpected N2 corpus semantics')
 inv={n:source(n,IP)for n in heads}
 if inv['N2']!=inv['P2']:raise ValueError('inventory expected absorbed')
 invpaths={n:re.findall(r'^        "([^"]+)",$',b.decode(),re.M)for n,b in inv.items()}
 invreview={'N_entries':len(invpaths['N']),'N2_entries':len(invpaths['N2']),'P2_entries':len(invpaths['P2']),'N_to_N2_added':sorted(set(invpaths['N2'])-set(invpaths['N'])),'N_to_N2_removed':sorted(set(invpaths['N'])-set(invpaths['N2'])),'N2_equals_P2_entire_bytes':True,'oid':blob(inv['P2']),'sha256':sha(inv['P2'])}
 # Actual immutable Git bytes for the selected 31 sources, deduplicated by object.
 roster=sorted(manifests['P2']['source_files']);all_entries={};oid_expect={}
 for n in ['N','N2','P2']:
  raw=run(n+'-31-source-ls-tree',['ls-tree','-z',heads[n],'--',*roster]);entries={}
  for row in raw.split(b'\0'):
   if not row:continue
   left,path=row.split(b'\t',1);mode,kind,oid=left.decode().split();path=path.decode()
   if kind!='blob'or mode!='100644':raise ValueError('selected source mode/type')
   entries[path]={'oid':oid,'mode':mode};oid_expect[oid]=None
  if set(entries)!=set(roster):raise ValueError('actual 31 path set')
  all_entries[n]=entries
 oids=sorted(oid_expect)
 sizes=run('unique-source-object-sizes',['cat-file','--batch-check=%(objectname) %(objecttype) %(objectsize)'],('\n'.join(oids)+'\n').encode()).decode().splitlines()
 totals=0
 for expected,line in zip(oids,sizes,strict=True):
  oid,typ,n=line.split();n=int(n)
  if oid!=expected or typ!='blob'or not 0<n<=2*1024*1024:raise ValueError('actual source type/size')
  oid_expect[oid]=n;totals+=n
 if totals>8*1024*1024:raise ValueError('closed 31-source raw cap')
 batch=run('unique-source-objects',['cat-file','--batch'],('\n'.join(oids)+'\n').encode());pos=0;object_meta={}
 for oid in oids:
  end=batch.index(b'\n',pos);header=batch[pos:end].decode();got,typ,n=header.split();n=int(n);pos=end+1
  raw=batch[pos:pos+n];pos+=n
  if got!=oid or typ!='blob'or n!=oid_expect[oid]or len(raw)!=n or batch[pos:pos+1]!=b'\n'or blob(raw)!=oid:raise ValueError('object address/encoding')
  pos+=1;object_meta[oid]={'bytes':n,'sha256':sha(raw)}
 if pos!=len(batch):raise ValueError('extra batch bytes')
 actual={}
 for n in heads:
  rows=[]
  for path in roster:
   ent=all_entries[n][path];meta=object_meta[ent['oid']];pin=manifests[n]['source_files'][path]
   rows.append({'path':path,**ent,**meta,'declared':pin,'matches_declared':meta==pin})
  actual[n]={'count':len(rows),'matching':sum(x['matches_declared']for x in rows),'rows':rows}
 if actual['N2']['matching']!=31 or actual['P2']['matching']!=31:raise ValueError('current map mismatch')
 actualmeta=put(O/'all31-actual-source-objects.json',js({'heads':heads,'unique_object_count':len(oids),'total_raw_bytes':totals,'actual':actual}))
 # These are protected current metadata paths, not newly selected sources.
 protected=[
 'config/pon/pq128-lifetime-composition-current-v3.json','config/pon/pq128-source-correspondence-current-v2.json',
 'scripts/ci/pq_lifetime_current_v2.py','scripts/ci/pq_lifetime_composition.py',
 'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs',
 'formal/pon-nakamoto-v1/fixtures/native-collector-e4abb172.py.raw',
 'scripts/ci/owned_process_collector.py','scripts/ci/test_owned_process_collector.py',
 ]
 protected_rows=[]
 raw=run('P2-protected-current-paths',['ls-tree','-z',heads['P2'],'--',*protected])
 for record in raw.split(b'\0'):
  if not record:continue
  left,path=record.split(b'\t',1);mode,kind,oid=left.decode().split();path=path.decode()
  protected_rows.append({'path':path,'mode':mode,'oid':oid,'P2_corpus_pin':corpus['P2']['pinned_blobs'].get(path),'in_P2_required_paths':path in corpus['P2']['required_paths'],'in_N2_changed_paths':False})
 changed=(B/'commands/N-N2-all-name-status.stdout').read_text().splitlines();changed_paths={x.split('\t')[1]for x in changed}
 if any(p in changed_paths for p in protected):raise ValueError('protected source changed by N2')
 for x in protected_rows:
  if x['P2_corpus_pin']!=x['oid']:raise ValueError('P2 protected corpus pin mismatch '+x['path'])
 pending_three=['.github/workflows/pon-w1-work-security.yml','scripts/ci/test_w1_v2_controls_gate.py','scripts/ci/w1_v2_controls_gate.py']
 proposal=[]
 for path in pending_three:
  proposal.append({'path':path,'old_P2_corpus_oid':corpus['P2']['pinned_blobs'][path],'incoming_N2_corpus_oid':corpus['N2']['pinned_blobs'][path],'condition':'only after pr_ci semantic review selects exact N2 blob'})
 report={'schema':'trnm-N2-metadata-compatible-disposition-v1','heads':heads,'hash_use':hashreview,'corpus':corpusreview,'distributed_inventory':invreview,'actual_31_source_proof':actualmeta,'protected_P2_current_bindings':protected_rows,'recommendation':{'hash_manifest':'keep P2 entire file; N2 has the rejected N store identity, all other30 pins equal','hash_reader':'keep P2 entire file and H1 map commitment/comment; all runtime AST otherwise equal','inventory':'P2 and N2 already byte-identical; no edit','corpus':'start from P2 entire file and preserve every existing pin/required path; apply only the separately selected3 W1 blob updates','conditional_3_pin_updates':proposal},'runtime_or_test_threshold_changes_in_four_reviewed_paths':False,'tests_run':False,'stage_source_Git_refs_or_network_mutated':False,'qualification_granted':False}
 rm=put(O/'review.json',js(report))
 state.update(status='STATIC_COMPATIBILITY_REVIEW_COMPLETE',review=rm,actual_source_counts={n:actual[n]['matching']for n in heads},actual_unique_objects=len(oids),actual_raw_bytes=totals,corpus_N_to_N2_pin_changes=len(corpusreview['N_to_N2']['pins_changed']),corpus_P2_required_removed_by_N2=corpusreview['P2_to_N2']['required_removed'])
except BaseException as exc:state['errors'].append({'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()})
finally:
 sm=put(O/'summary.json',js(state))
 print(json.dumps({'status':state['status'],'summary':sm,'review':state.get('review'),'actual_source_counts':state.get('actual_source_counts'),'unique_objects':state.get('actual_unique_objects'),'raw_bytes':state.get('actual_raw_bytes'),'errors':state['errors']}),flush=True)
sys.exit(0 if state['status']=='STATIC_COMPATIBILITY_REVIEW_COMPLETE'else 1)
