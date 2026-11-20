"""Actual original negative domain/RAII comparison, with a private no-vDSO platform fixture."""
from pathlib import Path
import os,sys,json,struct,hashlib,traceback,importlib.util,argparse
from .build import ROOT, HERE, source_manifest
SOURCE=HERE
BUNDLE=None
MARKER='HIA_PAID_CPU_ORACLE:'
PREFIX='ingress::public_v3::scalar_cpu::hia_paid_cpu_account_oracle::'
def need(ok,msg):
 if not ok:raise ValueError(msg)
def ident(p):
 p=Path(p);h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return {'bytes':p.stat().st_size,'sha256':h.hexdigest()}
def read(p):return json.loads(Path(p).read_bytes())
def write(p,obj):Path(p).write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n')
def sources():
 return source_manifest()
def native_case(name):
 need(BUNDLE is not None,"A current admitted native bundle is required")
 report=read(BUNDLE/"native-comparison.json");captured=next(r for r in report["faults"] if r["name"]==name)
 row=captured["physical"];folder=BUNDLE/"raw/faults"/name;raw=(folder/"stdout.raw").read_bytes()
 need(hashlib.sha256(raw).hexdigest()==row["output_sha256"],"Native physical receipt changed")
 need(ident(folder/"syscalls.raw")==captured["raw_inputs"]["syscalls.raw"],"Native physical trace changed")
 if raw:
  need(len(raw)==1536,'Native complete receipt missing');w=struct.unpack('<192Q',raw);o=w[64:128]
  return {'exit_code':row['exit_code'],'constructor_panicked':False,'global_poisoned':bool(w[1]),
   'global_unavailable':bool(w[9]),'in_flight':w[14],'booked_reservation_ns':w[22],'owner_panicked':bool(o[22]),
   'owner_spawn_failed':bool(w[6]),'scope_error':o[3],
   'worker_counts':{'spawned':o[14],'started':o[15],'finished':o[16],'known':o[17]},
   'some':{'owner_cpu_ns':bool(o[4]),'scoped_worker_cpu_ns':bool(o[6]),'total_cpu_ns':bool(o[8]),
    'live_paid_cpu_ns':bool(o[10]),'residual_cpu_ns':bool(o[12])},
   'live_refused':bool(o[18]),'accounting_unavailable':bool(o[19]),
   'source_evidence':{str(folder/n):ident(folder/n) for n in ('stdin.raw','stdout.raw','stderr.raw','syscalls.raw','physical.json')}}
 need(row['exit_code']==101,'Empty native outcome was not actual constructor panic')
 return {'constructor_panicked':True,'exit_code':101,'source_evidence':{str(folder/n):ident(folder/n) for n in ('stdin.raw','stdout.raw','stderr.raw','syscalls.raw','physical.json')}}
def observation(folder):
 rows=[json.loads(line.split(MARKER,1)[1]) for line in (folder/'stdout.raw').read_text().splitlines() if MARKER in line]
 need(len(rows)==1 and rows[0]['kind']=='actual-fault','No unique actual original observation')
 need(rows[0]['original_domain_and_raii_executed'] is True and rows[0]['complete_original_executor'] is False,'Original execution boundary was relabeled')
 return rows[0]
def role_validation(report,folder):
 events=[json.loads(line) for line in (folder/'events.jsonl').read_text().splitlines()]
 actual=[e for e in events if e['kind']=='actual-role'];roster=report['roster']
 def person(tid):return roster.get(tid,roster.get(str(tid)))
 constructor=[e for e in actual if e['role']==1];owners=[e for e in actual if e['role']==2];workers=[e for e in actual if e['role']==3]
 need(len(constructor)==1 and len(owners)<=1,'Actual private owner identity count differs')
 if owners:
  need(person(owners[0]['tid'])['parent']==constructor[0]['tid'] and owners[0]['index']==0,'Owner role did not belong to actual created child')
  need(sorted(w['index'] for w in workers)==list(range(len(workers))),'Missing/reordered actual worker role')
  need(all(person(w['tid'])['parent']==owners[0]['tid'] for w in workers),'Worker role not original owner descendant')
 else:need(not workers,'Workers exist without an actual owner')
 need(all('terminal' in person(e['tid']) for e in actual),'A reported role was not actually retired')
 for e in actual:
  birth=person(e['tid'])['birth'];terminal=person(e['tid'])['terminal']['sequence']
  need(birth<e['sequence']<terminal,'Actual role lies outside its real birth/exit')
 return {'actual_constructor_tid':constructor[0]['tid'],'actual_owner_tids':[e['tid'] for e in owners],
   'actual_worker_tids':[e['tid'] for e in workers],'every_actual_role_retired':True}
def compare(name,actual,native,report,folder):
 need(actual['label']==name,'Original case label differs')
 need(actual['constructor_panicked']==native['constructor_panicked'],'Constructor panic outcome differs')
 result={'name':name,'status':'PASS','actual_original':actual,'native':native,'trace':ident(folder/'events.jsonl'),
   'actual_roles':role_validation(report,folder),'injections':report['injections'],
   'clock1_environment':'private child initial auxv removes vDSO advertisement; unchanged libc raw fallback',
   'normal_vdso_error_or_timing_behavior_claimed':False,'exact_ns_equal_between_independent_runs':False}
 if actual['constructor_panicked']:
  need(actual['operation_returned'] is False and len(report['injections'])==1
       and report['injections'][0]['clock_id']==1,'Constructor failure published an operation')
  result['operation_returned']=False;return result
 g=actual['global'];o=actual['owner']
 need(o['owner_spawn_failed']==native['owner_spawn_failed'],'Actual owner spawn outcome differs')
 need(g['poisoned']==native['global_poisoned'] and g['in_flight']==native['in_flight'],'Original mutex poison/reservation state differs')
 if o['owner_spawn_failed']:
  need(o['operation_returned'] is False and actual['live'] is None and not result['actual_roles']['actual_owner_tids'],'Refused owner fabricated operation')
  result['operation_returned']=False;return result
 need(o['owner_panicked']==native['owner_panicked'],'Original owner panic differs')
 if o['worker_counts_before_finish'] is not None:
  need(all(o['worker_counts_before_finish'][k]==v for k,v in native['worker_counts'].items()),'Original actual worker interval count differs')
  need(o['scope_error']==native['scope_error'],'Original scoped join error priority differs')
 else:
  need(not result['actual_roles']['actual_worker_tids'] and o['owner_panicked'],'Missing actual pre-finish state')
 if o['owner_panicked']:
  need(o['operation_returned'] is False and o['receipt'] is None,'Original panic fabricated a returned settlement')
  result['operation_returned']=False;return result
 need(o['operation_returned'] is True and o['receipt'] is not None,'Original operation did not return settlement')
 receipt=o['receipt']
 need({k:receipt[k] is not None for k in native['some']}==native['some'],'Original returned known/Unknown fields differ')
 need(receipt['live_refused']==native['live_refused'] and receipt['accounting_unavailable']==native['accounting_unavailable'],'Original returned failure latch differs')
 for key,short in [('spawned_workers','spawned'),('started_workers','started'),('finished_workers','finished'),('known_workers','known')]:
  need(receipt[key]==native['worker_counts'][short],'Original returned worker count differs')
 if not native['global_poisoned']:need(g['unavailable']==native['global_unavailable'],'Original unknown fence differs')
 if receipt['total_cpu_ns'] is not None:
  need(receipt['owner_cpu_ns']+receipt['scoped_worker_cpu_ns']==receipt['total_cpu_ns'],'Original full CPU union differs')
 if receipt['residual_cpu_ns'] is not None:
  need(receipt['total_cpu_ns']-receipt['live_paid_cpu_ns']==receipt['residual_cpu_ns'],'Original unique residual differs')
 if name in ('live-clock3-einval','live-clock3-invalid-timespec','outer-clock3-einval'):
  need(g['flow']['booked_reservation_ns']==native['booked_reservation_ns']==100_000_000 and g['flow']['settled_full_cpu_ns']==0
       and g['flow']['live_debited_cpu_ns']>0,'Unknown settlement refunded or erased later known debit')
 if name=='live-clock3-eio-fallback':
  injected=report['injections'];need(len(injected)==1 and injected[0]['clock_id']==3,'Wrong actual original fallback injection')
  chain=[c for c in report['actual_clock_calls'] if c['tid']==injected[0]['tid']]
  at=next(i for i,c in enumerate(chain) if c['entry']==injected[0]['entry'])
  need(chain[at]['result']==-5 and chain[at+1]['clock_id']==3 and chain[at+1]['result']==0,'Original rustix one-call actual fallback missing')
 result['operation_returned']=True
 return result
def compare_original_faults(binary,out,bundle,original_root):
 global BUNDLE
 from .qualify import validate_bundle
 BUNDLE=Path(bundle).resolve(strict=True)
 validate_bundle(BUNDLE,Path(original_root).resolve(strict=True))
 out=Path(out);out.mkdir(mode=0o700)
 binary=Path(binary);before=sources();binary_before=ident(binary)
 from . import owned_ptrace as trace
 report={'schema':'trnm.hia.paid-cpu-actual-original-fault-differential.v1','status':'FAIL','cases':[],
  'whole_paid_account_closed':False,'request_node_service_closed':False,'complete_original_block_executor':False,
  'source_before':before,'executable_before':binary_before}
 try:
  argv=[str(binary),'--exact',PREFIX+'original_actual_fault_profile','--nocapture','--test-threads=1']
  env={'TRNM_HIA_PAID_FAULT_LABEL':'private-baseline','TRNM_HIA_PAID_FAULT_WORKERS':'1','TRNM_HIA_PAID_FAULT_TXS':'1'}
  baselines=[]
  for disabled,label in [(False,'normal-vdso-baseline'),(True,'raw-fallback-baseline')]:
   folder=out/label;r=trace.run(argv,folder,disable_vdso=disabled,env=env)
   observed=observation(folder)
   need(observed['constructor_panicked'] is False and observed['owner']['operation_returned'] is True
        and not observed['global']['poisoned'] and not observed['owner']['receipt']['accounting_unavailable'],'Actual original fault observer baseline failed')
   baselines.append({'label':label,'trace_report':ident(folder/'report.json'),'observation':observed,'actual_roles':role_validation(r,folder),
      'clock1_syscalls':sum(c['clock_id']==1 for c in r['actual_clock_calls']),'clock3_syscalls':sum(c['clock_id']==3 for c in r['actual_clock_calls'])})
   if disabled:constructor_clocks=[c for c in r['actual_clock_calls'] if c['role']==1 and c['clock_id']==1]
  need(constructor_clocks and all(c['result']==0 for c in constructor_clocks),'Original constructor wall-clock path not observed')
  constructor_final=constructor_clocks[-1]['role_clock_ordinal']
  report.update(baselines=baselines,constructor_final_clock_ordinal=constructor_final,
   constructor_scope='complete original standalone constructor; failure targets its final observed CLOCK1 for budget.updated after original ListenerIntake construction')
  from .cases import original_fault_cases
  cases=original_fault_cases();need(len(cases)==13 and len({c['name'] for c in cases})==13,'Incomplete original fault corpus')
  for case in cases:
   name=case['name'];fault={k:v for k,v in case.items() if k not in ('name','workers','txs')}
   if fault.get('clock_when')=='constructor-final':fault['clock_when']=constructor_final
   folder=out/name;runtime={**env,'TRNM_HIA_PAID_FAULT_LABEL':name,'TRNM_HIA_PAID_FAULT_WORKERS':str(case['workers']),'TRNM_HIA_PAID_FAULT_TXS':str(case['txs'])}
   r=trace.run(argv,folder,disable_vdso=True,env=runtime,fault=fault)
   actual=observation(folder);native=native_case(name)
   comparison=compare(name,actual,native,r,folder);write(folder/'comparison.json',comparison);report['cases'].append(comparison)
  report['status']='PASS'
 except BaseException as error:report.update(failure=repr(error),traceback=traceback.format_exc())
 finally:
  after=sources();report['source_after']='MATCH' if after==before else 'FAIL';report['executable_after']='MATCH' if ident(binary)==binary_before else 'FAIL'
  if report['source_after']!='MATCH' or report['executable_after']!='MATCH':report['status']='FAIL'
  write(out/'report.json',report)
  print(json.dumps({'status':report['status'],'cases':[{'name':c['name'],'status':c['status']} for c in report['cases']],
     'failure':report.get('failure'),'traceback':report.get('traceback'),'source_after':report['source_after'],'binary_after':report['executable_after']},sort_keys=True))
 return report
if __name__=="__main__":
 raise SystemExit("Use the source-bound paid_cpu.rust_oracle entry; a bare executable is not original-source evidence")
