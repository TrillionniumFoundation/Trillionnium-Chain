import os,sys,json,hashlib,zipfile,stat,pathlib
D=pathlib.Path('/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/cpu-distribution-v1')
assert D.is_dir()
with (D/'cpu-distribution-producer.py').open('x') as f:f.write(sys.argv[1])
E=pathlib.Path('/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/R1-W1-complete-artifacts-v1')
specs=[('head','14117751904.zip','b77dd9120901f5e4d3ccdd21be7f307fecabedabaca28a9d3c3d184d867d6ef8'),('prospective','14117403147.zip','2f13596450302835bcaf325d3b2364b95d1eeb6abe9f25dbc353a1efc4f2802a')]
out=[]
def ident(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def sum_known(xs):
 return {'count':len(xs),'known_count':sum(type(x)is int for x in xs),'unknown_count':sum(type(x)is not int for x in xs),'known_sum_ns':sum(x for x in xs if type(x)is int)}
def calls(xs):
 return {'count':len(xs),'client_cpu':sum_known([x.get('client_thread_cpu_ns') for x in xs]),'first_started_ns':min((x['started_ns'] for x in xs if type(x.get('started_ns'))is int),default=None),'last_ended_ns':max((x['ended_ns'] for x in xs if type(x.get('ended_ns'))is int),default=None),'returned_after_window_count':sum(x.get('returned_after_window')is True for x in xs),'returned_after_deadline_count':sum(x.get('returned_after_deadline')is True for x in xs),'solution_search_cpu':sum_known([x.get('metrics',{}).get('solution_search_thread_cpu_ns') for x in xs]),'solution_trials':sum(x.get('metrics',{}).get('solution_trials',0) for x in xs)}
for mode,name,h in specs:
 p=E/name
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK),'rb') as f:
  a=os.fstat(f.fileno());assert stat.S_ISREG(a.st_mode) and a.st_nlink==1
  raw=f.read();assert hashlib.sha256(raw).hexdigest()==h;f.seek(0)
  with zipfile.ZipFile(f) as z:
   for variant in ('original','fresh'):
    member='fresh-service/'+variant+'/report.json';b=z.read(member);j=json.loads(b)
    for ix,ph in enumerate(j['phases']):
     workers=[{'worker':w['worker'],'calling_thread_cpu_ns':w['calling_thread_cpu_ns'],'attempt_cap_reached':w['attempt_cap_reached'],'calls':calls(w['calls']),'pointer':f'/phases/{ix}/attacks/{i}'} for i,w in enumerate(ph['attacks'])]
     assert all(type(w['calling_thread_cpu_ns'])is int for w in workers)
     assert sum(w['calling_thread_cpu_ns'] for w in workers)==ph['attacker_workers_cpu_ns']
     records=ph['observations']['records']; groups={}
     for record in records:
      op=str(record.get('operation'))
      groups.setdefault(op,[]).append(record)
     ops={}
     for op,rows in groups.items():
      settlements=[r['cpu_settlement'] for r in rows if isinstance(r.get('cpu_settlement'),dict)]
      ops[op]={'record_count':len(rows),'dispatch_thread_cpu':sum_known([r.get('dispatch_thread_cpu_ns') for r in rows]),'settlement_count':len(settlements),'settlement_fields':{key:sum_known([s.get(key) for s in settlements]) for key in ('owner_cpu_ns','scoped_worker_cpu_ns','total_cpu_ns','live_paid_cpu_ns','residual_cpu_ns')}}
     m=ph['service']['metrics']
     row={'mode':mode,'variant':variant,'phase':ph['mode'],'phase_index':ix,'original_zip':str(p),'zip_sha256':h,'member':member,'report_bytes':len(b),'report_sha256':hashlib.sha256(b).hexdigest(),'pointer':f'/phases/{ix}','requested_window_ns':ph['requested_window_ns'],'business_started_ns':ph['business_started_ns'],'confirmation_ended_ns':ph['confirmation_ended_ns'],'finite_business_target_met':ph['finite_business_target_met'],'workers':workers,'attacker_workers_cpu_ns':ph['attacker_workers_cpu_ns'],'attacker_workers_cpu_scope':ph['attacker_workers_cpu_scope'],'reader_cpu_ns':ph['reader_cpu_ns'],'honest_head_calls':calls(ph['honest_heads']),'honest_submit_calls':calls(ph['honest_submissions']),'honest_history_calls':calls(ph['honest_history']),'independent_replay_and_confirmation_cpu_ns':ph['independent_replay_and_confirmation_cpu_ns'],'independent_replay_and_confirmation_wall_ns':ph['independent_replay_and_confirmation_wall_ns'],'independent_page_cpu':sum_known([r.get('replay_thread_cpu_ns')for r in ph['independent_history_page_replay']]),'independent_pages':[{'pointer':f'/phases/{ix}/independent_history_page_replay/{i}',**{k:v for k,v in r.items()if k not in ('native_import_observation','next_after','prior_after')}}for i,r in enumerate(ph['independent_history_page_replay'])],'independent_final_confirmation_stage':ph['independent_final_confirmation_stage'],'initial_meter':ph['initial_meter'],'final_meter':ph['final_meter'],'service_error':ph['service']['error'],'service_cpu_fields':{k:v for k,v in m.items()if 'cpu' in k},'service_selected_counts':{k:m[k]for k in ('accepted_connections','issued_challenges','completed_submit','completed_read','work_started','work_finished','work_failed','tasks_enqueued','tasks_dequeued','tasks_skipped_before_dispatch','ticket_refusals','signature_refusals','replay_refusals')},'observation_scope':{k:v for k,v in ph['observations'].items()if k!='records'},'observed_operation_cpu':ops,'accounting_closed':ph['accounting_closed']}
     assert m['mutation_cpu_charged_ns']==m['mutation_full_work_cpu_ns']+m['mutation_dispatch_excluding_work_cpu_ns']
     out.append(row)
  assert ident(a)==ident(os.fstat(f.fileno()))==ident(os.lstat(p))
obj={'schema':'trnm-r1-original-cpu-distribution-readonly-v1','source':'2a86462a1ab20c68151719ba4635e3c294391e64','no_new_execution':True,'no_four_second_cpu_fraction_claim':True,'rows':out}
p=D/'cpu-distribution.json';b=(json.dumps(obj,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
with p.open('xb') as f:f.write(b)
print(json.dumps({'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}))
for r in out:
 print(json.dumps({'mode':r['mode'],'variant':r['variant'],'phase':r['phase'],'attacker_workers_cpu_ns':r['attacker_workers_cpu_ns'],'per_worker_ns':[w['calling_thread_cpu_ns']for w in r['workers']],'reader_cpu_ns':r['reader_cpu_ns'],'honest_submit':r['honest_submit_calls'],'honest_history':r['honest_history_calls'],'independent_total_ns':r['independent_replay_and_confirmation_cpu_ns'],'independent_pages_ns':r['independent_page_cpu'],'service':r['service_cpu_fields'],'initial_meter':r['initial_meter'],'final_meter':r['final_meter'],'observation_ops':r['observed_operation_cpu']},sort_keys=True))
