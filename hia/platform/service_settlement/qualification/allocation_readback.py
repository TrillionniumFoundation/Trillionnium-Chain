"""Read actual allocator journals, every refusal/retry, and immutable parallel views."""
from .observations import Recorded,Blobs,ident,exact_int,document
from .common import CODES
from .process_readback import owned_process
class Allocated(Recorded):
 def owned(self,name,owner=None,body=None,height=None,*,expected_status=0):
  if expected_status==0:return super().owned(name,owner,body,height)
  assert expected_status==103
  r=self.take(name,True);assert type(r['status']) is int and r['status']==103 and r['result_pointer_nonnull'] is False
  assert 'result' not in r and 'result_owner' not in r
  owners=[] if owner is None else [owner];assert r['owners']==owners and len(r['before'])==len(r['after'])==len(owners)
  for o,b,a in zip(owners,r['before'],r['after'],strict=True):assert self.blobs.read(b)==self.blobs.read(a)==self.snapshot(o)
  if body is None:assert 'request' not in r
  else:assert self.blobs.read(r['request'])==body
  if name in ['engine_apply','engine_replay']:
   assert r['scalar_inputs']=={'height':height} and type(r['scalar_inputs']['height']) is int
  else:assert 'scalar_inputs' not in r
  return None
def actions(fixture):
 import struct
 data=bytes.fromhex(fixture['input']);p=16;result=[]
 for _ in range(struct.unpack_from('<Q',data,8)[0]):
  op,slot,height,n=struct.unpack_from('<4Q',data,p);p+=32;result.append((op,slot,height,data[p:p+n]));p+=n
 assert p==len(data);return result
def counters(row):
 assert set(row)=={'calls','frees','live','bytes','failures','bad_frees'}
 for v in row.values():exact_int(v)
 assert row['calls']==row['frees']+row['failures']+row['live'] and row['bad_frees']==0
 return row
def verify(store,fixtures):
 r=store.doc('allocator/report.json');assert r['status']=='PASS' and r['tested_shapes']==25 and r['actual_allocation_failures']==136
 assert r['production_image_changed'] is False and r['test_only_interposer'] is True and r['complete_lifetime_balance'] is True
 assert r['public_allocator_failure_paths_qualified'] is True and r['observer_build']==store.identity('allocator-build/build.json')
 build=store.doc('allocator-build/build.json');public=store.doc('build/public/build.json')
 assert build['status']=='TEST_OBSERVER_LINKED_NOT_EXECUTED' and build['production_build']==store.identity('build/public/build.json') and build['production_image']==public['artifact']
 assert build['production_image_changed'] is False and build['test_only_allocator_interposer'] is True and build['exact_production_objects_relinked'] is True
 assert r['observed_image']==build['image']==store.identity('allocator-build/engine-observed.so')
 for role in ['engine-owned','control','trust','receipt','rollup','settle','values']:
  wanted=public['emitter_execution']['object'] if role=='engine-owned' else public['modules'][role]['renamed']
  assert build['unchanged_production_objects'][role]==wanted==store.identity('allocator-build/'+role+'.o')==store.identity('build/public/'+role+'.o')
 assert store.read('allocator-build/observer.c')==store.read('source/hia/platform/service_settlement/qualification/allocator_observer.c')
 assert build['observer']==store.identity('allocator-build/observer.c')
 assert store.read('allocator-build/production-build.json')==store.read('build/public/build.json')
 origin=store.origin;root=store.source_root
 object_paths=[origin+'/allocator-build/'+name+'.o' for name in ['engine-owned','control','trust','receipt','rollup','settle','values']]
 exports=sorted(public['exports']+['trnm_settlement_test_alloc_'+name for name in ['calls','frees','live','bytes','failures','bad_frees','fail_after']])
 mapping='{\n global:\n'+''.join('  '+name+';\n' for name in exports)+' local: *;\n};\n'
 assert store.read('allocator-build/observer.map')==mapping.encode() and build['symbols']==exports
 specs={
 'preflight':['bash',root+'/scripts/project-preflight.sh','--audit'],
 'compile-observer':['/usr/bin/gcc','-std=c11','-O2','-fPIC','-Wall','-Wextra','-Werror','-c',origin+'/allocator-build/observer.c','-o',origin+'/allocator-build/observer.o'],
 'link-observed':['/usr/bin/gcc','-shared','-Wl,-z,defs,-z,noexecstack,-z,relro,-z,now,--build-id=none,--wrap=calloc,--wrap=free',*object_paths,origin+'/allocator-build/observer.o','-Wl,--version-script='+origin+'/allocator-build/observer.map','-pthread','-o',origin+'/allocator-build/engine-observed.so'],
 'defined-symbols':['/usr/bin/nm','-D','--defined-only',origin+'/allocator-build/engine-observed.so'],
 'undefined-symbols':['/usr/bin/nm','-D','--undefined-only',origin+'/allocator-build/engine-observed.so']}
 assert [r['name'] for r in build['stages']]==list(specs)
 for name,argv in specs.items():
  actual,_=owned_process(store,'allocator-build/'+name,30,argv,root,store.session['runtime_environment'])
  assert {'name':name,**actual}==next(x for x in build['stages'] if x['name']==name)
 assert sorted(line.split()[-1] for line in store.read('allocator-build/defined-symbols/stdout.raw').decode().splitlines())==exports
 undefined={line.split()[-1].split('@')[0] for line in store.read('allocator-build/undefined-symbols/stdout.raw').decode().splitlines()}
 assert sorted(undefined)==build['undefined_symbols'] and undefined<={'calloc','free','memcpy','abort','pthread_mutex_lock','pthread_mutex_unlock','__cxa_finalize','_ITM_registerTMCloneTable','_ITM_deregisterTMCloneTable','__gmon_start__'}

 assert store.read('allocator/public-harness.py')==store.read('source/hia/platform/service_settlement/qualification/native.py')
 assert store.read('allocator/executed-qualifier.py')==store.read('source/hia/platform/service_settlement/qualification/allocator.py')
 records=[document(x) for x in store.read('allocator/calls.jsonl').splitlines()]
 for field,name in [('stream','actual-bytes.chunked-zlib.bin'),('chunk_journal','chunks.jsonl'),('index','calls.jsonl'),('chunks_index','chunk-index.json')]:assert r['capture'][field]==store.identity('allocator/'+name)
 blobs=Blobs(store,'allocator',None);assert r['capture']['chunks']==len(blobs.index) and r['capture']['uncompressed_unique_bytes']==blobs.unique_bytes
 api=Allocated(records,blobs,CODES);api.require_heights=True
 lifecycle=actions(fixtures[1]);trust=lifecycle[0][3];engines=[api.owned('engine_new',body=trust)]
 for index in [1,2,5,8]:
  _,_,height,command=lifecycle[index];engines.append(api.owned('engine_apply',engines[-1],command,height))
 error=api.owned('engine_apply',engines[3],lifecycle[6][3],lifecycle[6][2]);assert api.kind(error)==255
 baseline=dict(api.live)
 cases=[
 ('new-valid','engine_new',None,trust,None),
 ('new-domain-error','engine_new',None,actions(fixtures[2])[0][3],None),
 ('new-malformed','engine_new',None,b'',None),
 ('receipt-success','engine_apply',engines[0],lifecycle[1][3],lifecycle[1][2]),
 ('rollup-success','engine_apply',engines[2],lifecycle[5][3],lifecycle[5][2]),
 ('settle-not-mature','engine_apply',engines[3],lifecycle[6][3],lifecycle[6][2]),
 ('settle-success','engine_apply',engines[3],lifecycle[8][3],lifecycle[8][2]),
 ('settle-already-consumed','engine_apply',engines[4],lifecycle[9][3],lifecycle[9][2]),
 ('replay-exact','engine_replay',engines[4],lifecycle[10][3],lifecycle[10][2]),
 ('replay-conflict','engine_replay',engines[4],lifecycle[11][3],lifecycle[11][2]),
 ('engine-clone','engine_clone',engines[4],None,None),
 ('owned-engine-clone','owned_clone',engines[4],None,None),
 ('state-copy','engine_state_copy',engines[4],None,None),
 ('error-display','error_display',error,None,None),
 ('owned-error-clone','owned_clone',error,None,None)]
 for op,name in [(6,'consumption_receipt_id'),(7,'consumption_rollup_id'),(8,'settlement_policy_hash'),(11,'operation_id')]:
  body=next(data for f in fixtures for code,slot,height,data in actions(f) if code==op)
  cases.extend([(name+'-valid',name,None,body,None),(name+'-malformed',name,None,b'',None)])
 execution=next(data for f in fixtures for op,slot,height,data in actions(f) if op==10)
 cases.extend([('execution-context','engine_validate_execution',engines[0],execution,None),('execution-malformed','engine_validate_execution',engines[0],b'',None)])
 assert len(cases)==25 and len(r['controls'])==162
 pos=0;failures=0;last=None
 for label,name,owner,body,height in cases:
  row=r['controls'][pos];pos+=1;assert row['name']==label+'-normal'
  before=counters(row['before']);after=counters(row['after']);allocations=exact_int(row['allocations'],1)
  if last is not None:assert before==last
  assert after['calls']-before['calls']==after['frees']-before['frees']==allocations and after['failures']==before['failures']
  assert after['live']==before['live']==6 and after['bytes']==before['bytes']
  result=api.owned(name,owner,body,height);expected=api.snapshot(result)
  assert expected==blobs.read(row['expected_owner']);api.drop(result);last=after
  for ordinal in range(1,allocations+1):
   row=r['controls'][pos];pos+=1
   assert row['name']==label+'-allocation-failure' and row['ordinal']==ordinal and row['status']==103
   assert row['no_output'] is True and row['existing_owners_unchanged'] is True and row['retry_equal'] is True
   before=counters(row['before']);failed=counters(row['after_failure']);after=counters(row['after_retry'])
   assert before==last and failed['calls']-before['calls']==ordinal and failed['failures']==before['failures']+1
   assert failed['live']==after['live']==before['live']==6 and failed['bytes']==after['bytes']==before['bytes']
   assert after['calls']-failed['calls']==after['frees']-failed['frees']==allocations and after['failures']==failed['failures']
   assert api.owned(name,owner,body,height,expected_status=103) is None and api.live==baseline
   result=api.owned(name,owner,body,height);assert api.snapshot(result)==expected;api.drop(result)
   assert api.live==baseline;last=after;failures+=1
 state=api.view('engine_state',engines[4]);root=api.view('engine_state_root',engines[4])
 row=r['controls'][pos];pos+=1;assert row['name']=='eight-readers-clone-view-drop' and row['threads']==8 and row['owners']==256 and row['existing_owners_unchanged'] is True
 assert row['before']==last;before=counters(row['before']);after=counters(row['after'])
 assert after['calls']-before['calls']==after['frees']-before['frees']==256 and after['failures']==before['failures'] and after['live']==before['live'] and after['bytes']==before['bytes']
 threads=store.doc('allocator/concurrent-observations.json');assert len(threads)==8
 for i,row in enumerate(threads):
  assert row['worker']==i and len(row['operations'])==32
  for ordinal,x in enumerate(row['operations']):assert x=={'ordinal':ordinal,'status':0,'views':[ident(state),ident(root)]}
 for owner in list(api.live):api.drop(owner)
 assert pos==162 and failures==136 and api.pos==len(records) and api.native==r['capture']['native_calls'] and len(records)==r['capture']['records']
 final=counters(r['final_counters']);assert final=={'calls':2058,'frees':1922,'failures':136,'live':0,'bytes':0,'bad_frees':0}
 assert final['frees']-after['frees']==6 and final['calls']==after['calls'] and final['failures']==after['failures'] and not api.live
 blobs.stream.close()
 return {'controls':162,'failures':136,'final_counters':final,'threads':8,'concurrent_owners':256,'journal_records':len(records),'native_calls':api.native}
