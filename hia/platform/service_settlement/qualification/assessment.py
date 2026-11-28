"""All semantic readback predicates shared by the writer's final check and read-only CLI."""
import lzma,re,math
from pathlib import Path,PurePosixPath
from ..contract import ROOT,HERE,COUNTS,LIMITS,FALSE_SCOPES,SCHEMA,source_inputs,repository,document,digest,identity,file_identity
from .observations import Blobs,Recorded,validate_summary,replay,exact_int
from .common import CODES
from .process_readback import owned_process
from .original_readback import readback as original_readback
from .build_readback import verify as build_readback
from .allocation_readback import verify as allocation_readback
def sources(store):
 session=store.session
 assert session['schema']=='trnm.hia.service-settlement-engine.execution.v1' and session['limits']==LIMITS
 assert type(session['start_monotonic_ns']) is int and session['deadline_monotonic_ns']==session['start_monotonic_ns']+1200*10**9
 before=store.doc('source-before.json');after=store.doc('source-after.json')
 assert before==after==session['source_inputs']==source_inputs()
 for name,value in before.items():assert store.source(name)==value
 state=repository()
 assert state==session['repository']==store.doc('repository-after.json')
 return before,state
def native(store,public,fixtures):
 report=store.doc('native/report.json');records=[document(x) for x in store.read('native/calls.jsonl').splitlines()]
 validate_summary(report,records,fixtures)
 assert report['image']==public['artifact']==store.identity('build/public/settlement-engine.so')
 assert report['source_inputs']==public['source_inputs'] and report['build']==store.identity('build/public/build.json')
 assert report['fee_build']==store.identity('build/units/arithmetic/build.json') and report['fee_image']==store.identity('build/units/arithmetic/module.so') and report['fee_private_calls']==169
 for field,name in [('stream','actual-bytes.chunked-zlib.bin'),('chunk_journal','chunks.jsonl'),('index','calls.jsonl'),('chunks_index','chunk-index.json')]:assert report['capture'][field]==store.identity('native/'+name)
 for row in records:
  if row['function'] in ['engine_apply','engine_replay']:
   assert set(row['scalar_inputs'])=={'height'} and type(row['scalar_inputs']['height']) is int and 0<=row['scalar_inputs']['height']<1<<64
  else:assert 'scalar_inputs' not in row
 blobs=Blobs(store,'native');assert blobs.unique_bytes==report['capture']['uncompressed_unique_bytes'] and len(blobs.index)==report['capture']['chunks']
 errors=store.doc('source/hia/platform/service_settlement/qualification/errors.json')
 error_ids={(CODES.index(c)+1,m.encode()):i for i,(_,c,m) in enumerate(errors,1)}
 api=Recorded(records,blobs,CODES);api.require_heights=True
 result=replay(api,fixtures,store.doc('native/fixture-results.json'),error_ids)
 assert api.explicit_height_calls==1754 and api.implicit_height_calls==0 and api.errors==report['public_error_observations']
 result['actual_height_calls']=api.explicit_height_calls
 blobs.stream.close();return result
def tools(store):
 result=dict(store.doc('build/build.json')['tools'])
 for label,row in store.doc('original/qualification/actual-toolchains.json').items():result[label.replace('-','_')]=row
 for label,row in store.doc('allocator-build/build.json')['tools'].items():
  if label in result:assert result[label]==row
  result[label]=row
 for label,row in store.doc('runtime-tools.json').items():
  if label in result:assert result[label]==row
  result[label]=row
 for row in result.values():
  assert set(row)=={'path','bytes','sha256'} and store.actual(row['path'])=={k:row[k] for k in ['bytes','sha256']}
 required={'native_compiler','rustc','cargo','rustdoc','cargo_clippy','clippy_driver','cargo_fmt','rustfmt','python','ld','objcopy','allocator_cc'}
 assert required<=set(result);return result
def assessment(store):
 source,state=sources(store);build=build_readback(store);original,_=original_readback(store)
 raw=store.read('generator/original-output/original.stdout.raw')
 assert lzma.decompress(store.read('source/hia/platform/service_settlement/qualification/fixtures.json.xz'))==raw
 fixtures=document(raw)['fixtures'];public=store.doc('build/public/build.json');observed=native(store,public,fixtures)
 allocation=allocation_readback(store,fixtures)
 session=store.session;origin=store.origin;root=store.source_root;python=session['python']['path'];environment=session['runtime_environment']
 assert environment=={'PATH':'/usr/bin:/bin','HOME':session['home'],'PYTHONDONTWRITEBYTECODE':'1'}
 specs={
 'build':(240,[python,'-B','-m','hia.platform.service_settlement.build','--output',origin+'/build'],session['build_environment']),
 'native':(240,[python,'-B','-m','hia.platform.service_settlement.qualification.native','--build',origin+'/build/public','--fee-build',origin+'/build/units/arithmetic','--output',origin+'/native'],environment),
 'allocator-build':(240,[python,'-B','-m','hia.platform.service_settlement.qualification.build_allocator','--build',origin+'/build/public','--output',origin+'/allocator-build'],environment),
 'allocator':(240,[python,'-B','-m','hia.platform.service_settlement.qualification.allocator','--build',origin+'/build/public','--observer',origin+'/allocator-build','--output',origin+'/allocator'],environment)}
 processes={}
 owned_process(store,'stages/preflight',30,['/usr/bin/bash','scripts/project-preflight.sh']+(['--audit'] if session['repository']['branch']=='HEAD' else []),root,environment)
 for name,(seconds,argv,env) in specs.items():processes[name]=owned_process(store,'stages/'+name,seconds,argv,root,env)[0]
 assert observed['native_elapsed_ns_sum']<=processes['native']['elapsed_ns']
 assert store.doc('source-after.json')==source
 counts={'original_registered':original['original_outer_tests']+original['nested_fixture_types'],'original_outer':original['original_outer_tests'],'original_nested_fixture_types':original['nested_fixture_types'],'original_nested_phases':original['nested_actual_phases'],'doctests':original['compile_fail_doctests'],'fixtures':observed['fixtures'],'operations':observed['operations'],'native_calls':observed['native_calls'],'actual_height_calls':observed['actual_height_calls'],'allocator_controls':allocation['controls'],'allocator_failures':allocation['failures'],'allocator_calls':allocation['final_counters']['calls'],'allocator_frees':allocation['final_counters']['frees'],'concurrent_threads':allocation['threads'],'concurrent_owners':allocation['concurrent_owners'],'live_owners':observed['live_owners'],'allocator_live':allocation['final_counters']['live'],'allocator_live_bytes':allocation['final_counters']['bytes'],'allocator_bad_frees':allocation['final_counters']['bad_frees']}
 assert counts==COUNTS
 return {'source_inputs':source,'source_digest':digest(source),'head':state['head'],'tree':state['tree'],'repository_clean':state['repository_clean'],'counts':counts,'limits':LIMITS,'tools':tools(store),'details':{'build':build,'original':original,'native':observed,'allocator':allocation}}
def control_reference(store,value):
 assert set(value)=={'path','bytes','sha256'}
 path=Path(value['path'])
 assert path.is_absolute() and path.is_relative_to(Path(store.origin))
 relative=path.relative_to(Path(store.origin)).as_posix()
 assert relative in {'integrity/report.json','stages/integrity/receipt.json'}
 assert store.identity(relative)=={k:value[k] for k in ['bytes','sha256']}
 return relative
def verify_controls(store):
 from .integrity_roster import ROSTER
 value=store.doc('integrity/report.json')
 assert value['schema']=='trnm.hia.service-settlement-engine.integrity.v1' and value['status']=='PASS' and value['roster']==ROSTER
 assert all(type(value[k]) is int for k in ['passed','failed','not_run'])
 assert value['passed']==len(ROSTER) and value['failed']==value['not_run']==0
 assert [r['name'] for r in value['cases']]==ROSTER and all(r['result'] in ['PASS','REJECTED'] for r in value['cases'])
 metadata=next(r for r in value['cases'] if r['name']=='changed_compiler_input_refused')
 assert metadata['build_metadata_controls']==[{'name':name,'result':'REJECTED','exception':'AssertionError'} for name in ['public_stage_receipts_changed','emitter_check_roster_empty']]
 assert value['actual_engine_calls_here']==0 and value['actual_ctypes_u64_calls']==10
 assert value['source_inputs']==store.session['source_inputs'] and value['source_digest']==digest(value['source_inputs'])
 assert value['fresh_execution'] is True and value['prior_controls_reused'] is False
 session=store.session
 process=owned_process(store,'stages/integrity',240,[session['python']['path'],'-B','-m','hia.platform.service_settlement.qualification.integrity','--input',store.origin,'--output',store.origin+'/integrity'],store.source_root,session['runtime_environment'])[0]
 assert value['elapsed_ns']<=process['elapsed_ns']
 result={'status':'PASS','roster':ROSTER,'passed':len(ROSTER),'failed':0,'not_run':0,'report':{'path':store.origin+'/integrity/report.json',**store.identity('integrity/report.json')},'process_receipt':{'path':store.origin+'/stages/integrity/receipt.json',**store.identity('stages/integrity/receipt.json')}}
 for key in ['report','process_receipt']:control_reference(store,result[key])
 return result
def summary(report,actual,controls):
 assert report['schema']==SCHEMA and report['status']=='PASS' and report['finalized'] is True
 for key in ['source_inputs','source_digest','head','tree','repository_clean','counts','limits','tools']:assert report[key]==actual[key],key
 assert all(type(v) is int for v in report['counts'].values())
 assert report['source_inputs_stable'] is True and report['prior_execution_reused'] is False
 for key in FALSE_SCOPES:assert report[key] is False
 assert report['integrity_controls']==controls
 assert type(report['elapsed_ns']) is int and 0<report['elapsed_ns']<=1200*10**9
 return True
