from pathlib import Path
import copy,ctypes as C,hashlib,importlib.util,json,struct,sys,time,traceback
import argparse
from ..contract import ROOT as SOURCE_ROOT,HERE,SCHEMA,FALSE_SCOPES,canonical,digest
from . import original_readback as original
from . import observations as readback
from . import native as m
from . import assessment as assess
from . import allocation_readback,build_readback
from .evidence import Evidence
from .integrity_roster import ROSTER
parser=argparse.ArgumentParser();parser.add_argument('--input',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
ROOT=args.input.resolve(strict=True);OUT=args.output.absolute();assert OUT==ROOT/'integrity';OUT.mkdir(mode=0o700)
producer=HERE/'qualification/native.py'
rows=[];started=time.monotonic()
def reject(name,fn):
 try:fn()
 except (AssertionError,KeyError,ValueError,TypeError) as error:rows.append({'name':name,'result':'REJECTED','exception':type(error).__name__});return
 raise AssertionError(('negative accepted',name))
def passed(name):rows.append({'name':name,'result':'PASS'})
class Proxy:
 def __init__(self,base):self.base=base;self.docs={};self.ids={};self.data={};self.actuals={}
 def __getattr__(self,name):return getattr(self.base,name)
 def doc(self,name):
  value=copy.deepcopy(self.base.doc(name))
  if name in self.docs:value=self.docs[name](value)
  return value
 def identity(self,name):return self.ids.get(name,self.base.identity(name))
 def actual(self,name):return self.actuals.get(name,self.base.actual(name))
 def read(self,name):return self.data.get(name,self.base.read(name))
def mutate_doc(path,update):
 p=Proxy(store)
 def f(v):update(v);return v
 p.docs[path]=f;return p
def full(s):return original.readback(s)
report={'status':'INCOMPLETE','scope':'Reader semantic mutation controls and actual ctypes u64 observer ABI controls; not a new Engine native execution.'}
try:
 store=Evidence(ROOT,pending=True)
 positive,_=full(store);assert positive['status']=='INDEPENDENT_FULL_FRESH_ORIGINAL_PROVENANCE_PASS';passed('actual_complete_fresh_original_positive')
 # Two actual owned commands have the same 240 second deadline and valid success receipts.
 good=store.doc('original/qualification/original-all/receipt.json')
 foreign=store.doc('original/qualification/adapter-locked-build/receipt.json')
 readback.basic_process(good,240);readback.basic_process(foreign,240)
 reject('actual_foreign_success_240_receipt_cannot_replace_original_all',
  lambda:original.owned_process(store,'original/qualification/adapter-locked-build',240,good['argv'],good['cwd'],good['environment']))
 gp='generator/qualification/fresh-original-generate/receipt.json'
 mutations=[
 ('generator_wrong_argv',gp,lambda v:v['argv'].__setitem__(2,'/foreign/capture_exec.py')),
 ('generator_wrong_cwd',gp,lambda v:v.__setitem__('cwd','/foreign')),
 ('generator_wrong_env',gp,lambda v:v['environment'].__setitem__('LD_PRELOAD','/foreign.so')),
 ('generator_incomplete_status',gp,lambda v:v.__setitem__('status','INCOMPLETE')),
 ('generator_missing_actual_start',gp,lambda v:v.__setitem__('started',False)),
 ('generator_boolean_exit_code',gp,lambda v:v.__setitem__('exit_code',False)),
 ('generator_late_success',gp,lambda v:v['collector_readback']['result'].__setitem__('completed_monotonic_ns',v['original_deadline_monotonic_ns']+1)),
 ('generator_unreaped_domain',gp,lambda v:v['collector_readback']['result'].__setitem__('collector_wait_domain_reaped',False)),
 ('generator_cleanup_error',gp,lambda v:v.__setitem__('cleanup_errors',['injected'])),
 ('generator_changed_deadline',gp,lambda v:v.__setitem__('execution_deadline_seconds',121)),
 ('generator_changed_cleanup',gp,lambda v:v.__setitem__('cleanup_deadline_seconds',4)),
 ('generator_changed_command_hash',gp,lambda v:v['command'].__setitem__('sha256','0'*64)),
 ('generator_changed_original_executable','generator/qualification/report.json',lambda v:v['original_executable'].__setitem__('sha256','0'*64)),
 ('generator_changed_source_report','generator/qualification/report.json',lambda v:v['source_report'].__setitem__('sha256','0'*64)),
 ('generator_failed_source_fence','generator/qualification/report.json',lambda v:v.__setitem__('final_fence','FAIL')),
 ('generator_incomplete_roster','generator/qualification/report.json',lambda v:v.__setitem__('operations',2635)),
 ('original_optimized_adapter','original/qualification/report.json',lambda v:v['original_adapter_binary']['cargo_event']['profile'].__setitem__('opt_level','3')),
 ('original_reused_adapter','original/qualification/report.json',lambda v:v['original_adapter_binary']['cargo_event'].__setitem__('fresh',True)),
 ('original_outer_roster_miscount','original/qualification/report.json',lambda v:v.__setitem__('original_outer_tests_passed',137)),
 ('original_config_present','original/qualification/cargo-config-inventory.json',lambda v:v.__setitem__('present',['/foreign/config.toml'])),
 ('generator_exec_request_wrong_executable','generator/exec-request.json',lambda v:v['argv'].__setitem__(0,'/foreign/reference')),
 ('generator_exec_intent_wrong_height_independent_argv','generator/original-output/actual-exec-intent.json',lambda v:v['argv'].__setitem__(1,'other')),
 ]
 for name,path,change in mutations:
  p=mutate_doc(path,change);reject(name,lambda p=p:full(p))
 for name,path in [('missing_full_stdout','generator/original-output/original.stdout.raw'),('changed_capture_wrapper','generator/capture_exec.py'),('changed_raw_process_stdout','generator/qualification/fresh-original-generate/stdout.raw')]:
  p=Proxy(store);p.ids[path]={'bytes':0,'sha256':'0'*64};reject(name,lambda p=p:full(p))
 p=Proxy(store);p.data['generator/original-output/original.stderr.raw']=b'error';reject('nonempty_actual_original_stderr',lambda:full(p))
 p=Proxy(store);p.actuals[store.view['roots']['original']+'/cargo-target/debug/settlement-reference']={'bytes':1,'sha256':'0'*64};reject('actual_original_binary_bytes_changed',lambda:full(p))
 for text in ['{"x":1e999}','{"x":NaN}','{"x":Infinity}','{"x":1,"x":2}']:reject('strict_json_'+text,lambda text=text:readback.document(text))
 class Cap:
  def __init__(self):self.records=[]
  def blob(self,b):return bytes(b)
  def record(self,r):self.records.append(copy.deepcopy(r))
 def height_case(name,h):
  api=m.PublicEngine.__new__(m.PublicEngine);api.capture=Cap()
  old=C.create_string_buffer(b'SSOWN001'+struct.pack('<3Q',1,0,0),32)
  new=C.create_string_buffer(b'SSOWN001'+struct.pack('<3Q',4,0,0),32)
  oldp=C.addressof(old);newp=C.addressof(new);observed=[]
  proto=C.CFUNCTYPE(C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.POINTER(C.c_void_p))
  def callback(owner,height,data,n,out):
   observed.append(height);assert owner==oldp and C.string_at(data,n)==b'abc';out[0]=newp;return 0
  cb=proto(callback);api.functions={name:cb};api.live={oldp:1};api.next_id=2
  result=api.owned(name,oldp,b'abc',h)
  assert result==newp and observed==[h] and api.capture.records[0]['scalar_inputs']=={'height':h}
  assert api.capture.records[0]['before']==api.capture.records[0]['after']
 for name in ['engine_apply','engine_replay']:
  for h in [0,1,(1<<32)-1,1<<63,(1<<64)-1]:height_case(name,h);passed(name+'_actual_ctypes_u64_'+str(h))
 for h in [-1,True,1<<64,1.5,None]:reject('observer_invalid_height_'+repr(h),lambda h=h:height_case('engine_apply',h))
 def reader_height(row,expected):
  api=readback.Recorded([row],None,[]);api.require_heights=True;api.call=lambda *a,**k:7
  result=api.owned('engine_apply',owner=1,body=b'abc',height=expected)
  assert result==7 and api.explicit_height_calls==1 and api.implicit_height_calls==0
 for h in [0,(1<<64)-1]:reader_height({'scalar_inputs':{'height':h}},h);passed('reader_actual_height_'+str(h))
 for name,row,h in [('missing',{},0),('wrong',{'scalar_inputs':{'height':1}},0),('bool',{'scalar_inputs':{'height':False}},0),('extra',{'scalar_inputs':{'height':0,'other':1}},0)]:
  reject('reader_height_'+name,lambda row=row,h=h:reader_height(row,h))

 actual=assess.assessment(store);controls={'status':'INTERNAL_CONTROL_FIXTURE_ONLY'}
 positive_report={'schema':SCHEMA,'status':'PASS','finalized':True,**actual,**FALSE_SCOPES,'source_inputs_stable':True,'prior_execution_reused':False,'integrity_controls':controls,'elapsed_ns':1}
 def summary_negative(name,change):
  altered=copy.deepcopy(positive_report);change(altered);reject(name,lambda:assess.summary(altered,actual,controls))
 summary_negative('pending_qualification_cannot_be_upgraded',lambda r:r.__setitem__('status','INCOMPLETE'))
 summary_negative('reused_execution_cannot_be_upgraded',lambda r:r.__setitem__('prior_execution_reused',True))
 summary_negative('unstable_source_cannot_be_upgraded',lambda r:r.__setitem__('source_inputs_stable',False))
 summary_negative('missing_actual_tool_cannot_be_upgraded',lambda r:r['tools'].pop('rustc'))
 summary_negative('changed_actual_tool_cannot_be_upgraded',lambda r:r['tools']['rustc'].__setitem__('sha256','0'*64))
 summary_negative('wrong_source_digest_cannot_be_upgraded',lambda r:r.__setitem__('source_digest','0'*64))
 summary_negative('whole_store_claim_cannot_be_upgraded',lambda r:r.__setitem__('store_qualified',True))
 for name,path in [('foreign_control_report_refused','/foreign/report.json'),('traversal_control_report_refused',store.origin+'/../report.json')]:
  reject(name,lambda path=path:assess.control_reference(store,{'path':path,'bytes':0,'sha256':'0'*64}))
 p=mutate_doc('source-before.json',lambda d:d.pop('hia/platform/service_settlement/readback.py'))
 reject('missing_canonical_reader_source_refused',lambda:assess.sources(p))
 raw=store.read('generator/original-output/original.stdout.raw');fixtures=readback.document(raw)['fixtures']
 p=mutate_doc('allocator/report.json',lambda d:d['controls'].pop())
 reject('missing_allocator_control_refused',lambda:allocation_readback.verify(p,fixtures))
 p=Proxy(store);name='build/units/control/native-compile/stdin.raw';p.data[name]=store.read(name)+b'\nchanged'
 reject('changed_compiler_input_refused',lambda:build_readback.verify(p))
 metadata_controls=[]
 for label,path,field in [('public_stage_receipts_changed','build/public/build.json','stages'),('emitter_check_roster_empty','build/public/emitter-execution/report.json','checks')]:
  p=mutate_doc(path,lambda value,field=field:value.__setitem__(field,[] if field=='stages' else {}))
  try:build_readback.verify(p)
  except AssertionError:metadata_controls.append({'name':label,'result':'REJECTED','exception':'AssertionError'})
  else:raise AssertionError(('build metadata inconsistency accepted',label))
 rows[-1]['build_metadata_controls']=metadata_controls
 p=Proxy(store);p.ids['build/public/settlement-engine.so']={'bytes':0,'sha256':'0'*64}
 reject('changed_native_image_refused',lambda:assess.native(p,store.doc('build/public/build.json'),fixtures))
 p=mutate_doc('allocator/report.json',lambda d:d['final_counters'].__setitem__('live',1))
 reject('allocator_leak_refused',lambda:allocation_readback.verify(p,fixtures))
 assert [r['name'] for r in rows]==ROSTER

 report.update(status='PASS',schema='trnm.hia.service-settlement-engine.integrity.v1',roster=ROSTER,passed=len(rows),failed=0,not_run=0,fresh_execution=True,prior_controls_reused=False,source_inputs=store.session['source_inputs'],source_digest=digest(store.session['source_inputs']),elapsed_ns=int((time.monotonic()-started)*1e9),controls=len(rows),cases=rows,elapsed_seconds=time.monotonic()-started,actual_engine_calls_here=0,actual_ctypes_u64_calls=10,legacy_archive_rewritten=False,source={'reader':readback.file_id(Path(readback.__file__)),'original_reader':readback.file_id(Path(original.__file__)),'observer':readback.file_id(producer)})
except BaseException:report.update(status='FAIL',cases=rows,exception=traceback.format_exc())
(OUT/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:report.get(k) for k in ['status','controls','actual_ctypes_u64_calls','elapsed_seconds','exception']}))
raise SystemExit(0 if report['status']=='PASS' else 1)
