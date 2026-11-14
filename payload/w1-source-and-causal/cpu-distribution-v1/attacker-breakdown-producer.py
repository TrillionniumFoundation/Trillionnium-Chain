import os,sys,json,hashlib,zipfile,stat,pathlib,collections
D=pathlib.Path('/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/cpu-distribution-v1')
with (D/'attacker-breakdown-producer.py').open('x') as f:f.write(sys.argv[1])
E=pathlib.Path('/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1/R1-W1-complete-artifacts-v1')
specs=[('head','14117751904.zip','b77dd9120901f5e4d3ccdd21be7f307fecabedabaca28a9d3c3d184d867d6ef8'),('prospective','14117403147.zip','2f13596450302835bcaf325d3b2364b95d1eeb6abe9f25dbc353a1efc4f2802a')]
def ident(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def accum(v):
 return {'values_count':len(v),'known_count':sum(type(x)is int for x in v),'null_or_missing_count':sum(type(x)is not int for x in v),'known_sum':sum(x for x in v if type(x)is int)}
rows=[]
for mode,name,h in specs:
 p=E/name
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK),'rb') as f:
  a=os.fstat(f.fileno());assert stat.S_ISREG(a.st_mode)and a.st_nlink==1
  data=f.read();assert hashlib.sha256(data).hexdigest()==h;f.seek(0)
  with zipfile.ZipFile(f)as z:
   for var in ('original','fresh'):
    m='fresh-service/'+var+'/report.json';b=z.read(m);j=json.loads(b);ph=j['phases'][1]
    workers=[];all_calls=[]
    for i,w in enumerate(ph['attacks']):
     calls=w['calls'];all_calls.extend(calls)
     constructions=[c.get('from_zero_construction')for c in calls if isinstance(c.get('from_zero_construction'),dict)]
     cp=accum([c.get('client_thread_cpu_ns')for c in calls]);co=accum([c.get('attacker_cpu_ns')for c in constructions])
     whole=w['calling_thread_cpu_ns'];assert type(whole)is int
     complete_client=cp['null_or_missing_count']==0
     complete_construct=(var=='original' and not constructions)or(var=='fresh' and len(constructions)==len(calls)and co['null_or_missing_count']==0)
     remainder=whole-cp['known_sum']-co['known_sum']if complete_client and complete_construct else None
     assert remainder is None or remainder>=0
     workers.append({'worker':w['worker'],'pointer':f'/phases/1/attacks/{i}','calling_thread_cpu_ns':whole,'calls_count':len(calls),'attempt_cap_reached':w['attempt_cap_reached'],'statuses':dict(collections.Counter(c.get('status')for c in calls)),'call.client_thread_cpu_ns':cp,'metrics.solution_search_thread_cpu_ns':accum([c.get('metrics',{}).get('solution_search_thread_cpu_ns')for c in calls]),'metrics.solution_trials':accum([c.get('metrics',{}).get('solution_trials')for c in calls]),'from_zero_construction.attacker_cpu_ns':co,'residual_after_client_and_construction_cpu_ns':remainder,'first_call_started_ns':min((c['started_ns']for c in calls if type(c.get('started_ns'))is int),default=None),'last_call_ended_ns':max((c['ended_ns']for c in calls if type(c.get('ended_ns'))is int),default=None)})
    cons=[c['from_zero_construction']for c in all_calls if isinstance(c.get('from_zero_construction'),dict)]
    whole=ph['attacker_workers_cpu_ns'];assert sum(w['calling_thread_cpu_ns']for w in workers)==whole
    residual=sum(w['residual_after_client_and_construction_cpu_ns']for w in workers)if all(type(w['residual_after_client_and_construction_cpu_ns'])is int for w in workers)else None
    row={'mode':mode,'variant':var,'zip_path':str(p),'zip_sha256':h,'member':m,'report_sha256':hashlib.sha256(b).hexdigest(),'original_scope':ph['attacker_workers_cpu_scope'],'worker_count':len(workers),'attacker_workers_cpu_ns':whole,'calls_total':len(all_calls),'calls_per_worker_min':min(w['calls_count']for w in workers),'calls_per_worker_max':max(w['calls_count']for w in workers),'call.client_thread_cpu_ns':accum([c.get('client_thread_cpu_ns')for c in all_calls]),'metrics.solution_search_thread_cpu_ns':accum([c.get('metrics',{}).get('solution_search_thread_cpu_ns')for c in all_calls]),'metrics.solution_trials':accum([c.get('metrics',{}).get('solution_trials')for c in all_calls]),'from_zero_construction':{key:accum([c.get(key)for c in cons])for key in ('attacker_cpu_ns','setup_cpu_ns','search_cpu_ns','packet_encoding_cpu_ns')},'construction_coverage_original':j.get('construction_coverage'),'root_cpu_scope_fields':{k:v for k,v in j.items()if 'cpu' in k or k=='shared_material_setup_wall_ns'},'residual_after_client_and_construction_cpu_ns':residual,'residual_scope':'Unmeasured separately: original prepare/clone or fresh packet digest, post-call response conversion/diagnostic JSON, compact_pressure_call serde+hash, row/loop/clock/bookkeeping. Never exclusively JSON.','latest_recorded_call_end_ns':max((w['last_call_ended_ns']for w in workers if type(w['last_call_ended_ns'])is int),default=None),'workers':workers}
    rows.append(row)
  assert ident(a)==ident(os.fstat(f.fileno()))==ident(os.lstat(p))
p=D/'attacker-breakdown.json';b=(json.dumps({'schema':'trnm-r1-pressure-attacker-cpu-breakdown-readonly-v1','rows':rows},ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
with p.open('xb')as f:f.write(b)
print(json.dumps({'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}))
for r in rows:print(json.dumps({k:v for k,v in r.items()if k not in ('workers','zip_path','zip_sha256','member','report_sha256','original_scope','residual_scope','root_cpu_scope_fields')},ensure_ascii=False,sort_keys=True))
