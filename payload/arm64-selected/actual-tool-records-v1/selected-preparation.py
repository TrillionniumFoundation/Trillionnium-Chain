import ast,difflib,hashlib,json,os,stat,sys,time
from pathlib import Path
old,new=json.loads(sys.argv[1])
base=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1')
out=base/'selected-plan-v1';out.mkdir(mode=0o700)
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,n,h):
 p=Path(p);a=p.lstat()
 if p.resolve(strict=True)!=p or not stat.S_ISREG(a.st_mode)or a.st_nlink!=1:raise ValueError('SOURCE_TYPE')
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb')as f:
  if fp(a)!=fp(os.fstat(f.fileno())):raise ValueError('OPEN_IDENTITY')
  b=f.read(n+1)
  if fp(a)!=fp(os.fstat(f.fileno())):raise ValueError('FD_CHANGED')
 if fp(a)!=fp(p.lstat())or len(b)!=n or hashlib.sha256(b).hexdigest()!=h:raise ValueError('SOURCE_PIN')
 return b
def put(p,b):
 with p.open('xb')as f:f.write(b)
 if p.read_bytes()!=b:raise ValueError('READBACK')
 return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def putj(p,v):return put(p,(json.dumps(v,sort_keys=True,indent=2)+'\n').encode())
ref='/private/tmp/chain-prci-H5DF-cross-cost-selected-artifact-20261114-v1/selected-producer.py'
if read(ref,26244,'144a9f3e7af6d3ccf5c1e46c80db9c28e796aeaf22b135d67874a8f3888b3184')!=old.encode():raise ValueError('REFERENCE_BYTES')
compile(new,str(base/'selected-producer.py'),'exec',dont_inherit=True,optimize=0)
a=ast.parse(old);b=ast.parse(new)
functions=lambda t:{n.name:ast.dump(n,include_attributes=False)for n in t.body if isinstance(n,ast.FunctionDef)}
af,bf=functions(a),functions(b)
if set(af)!=set(bf)or any(af[k]!=bf[k]for k in af if k!='main'):raise ValueError('HELPER_AST_DRIFT')
dpath=base/'directory-v1/summary.json'
d=json.loads(read(dpath,6078,'71d2ba7895fd2c00303255fbddcd665de79a861aa96b5e4e5646ad6a478587c3'))
c=d['central_directory'];cd=json.loads(read(c['path'],c['bytes'],c['sha256']))
if d['status']!='DIRECTORY_VERIFIED_SELECTED_RECORDS_PENDING'or cd['artifact_id']!=14124468052 or cd['entries']!=161:raise ValueError('CD_IDENTITY')
selectors=['caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct','from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection','four_from_zero_w1_traces_keep_native_state_and_chainwork_unchanged','from_zero_service_shares_cpu_with_honest_work_and_reopened_owner','from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline']
selected=['from-zero-native/manifest.json','from-zero-native/confirmation/report.json','source.json','from-zero-native-host/controller-result.json']+['from-zero-native/'+n+'/'+suffix for n in selectors for suffix in('process.json','stdout','stderr')]+['from-zero-native-host/'+x for x in('child-result.json','inside-before.json','inside-after.json','outside-after.json','prepare-build.json','systemd-run.log')]
members=sorted(cd['members'],key=lambda x:x['local_header_offset'])
byname={r['path']:r for r in members}
if len(set(selected))!=25 or len(byname)!=161 or len({r['local_header_offset']for r in members})!=161:raise ValueError('ROSTER')
spans=[]
for name in selected:
 row=byname[name];i=members.index(row);start=row['local_header_offset'];end=(members[i+1]['local_header_offset']if i+1<len(members)else cd['central_directory_offset'])-1
 if row['directory']or not row['small_member_candidate_only']or not(0<=start<=end<cd['central_directory_offset']):raise ValueError('SPAN_TYPE')
 if not row['compressed_bytes']+30<=end-start+1<=row['compressed_bytes']+30+1024+65535+16:raise ValueError('RECORD_BOUND')
 spans.append({'path':name,'start':start,'end':end,'bytes':end-start+1,'row':row,'already_in_tail':start>=9844301 and end<=9909857})
groups=[]
for span in sorted([x for x in spans if not x['already_in_tail']],key=lambda x:x['start']):
 if groups and groups[-1]['end']+1==span['start']:
  groups[-1]['end']=span['end'];groups[-1]['members'].append(span['path'])
 else:groups.append({'start':span['start'],'end':span['end'],'members':[span['path']]})
total=sum(x['bytes']for x in spans);expanded=sum(x['row']['uncompressed_bytes']for x in spans)
if total>4*1024*1024 or expanded>64*1024*1024 or 2+len(groups)>21:raise ValueError('PLAN_BOUND')
source=put(base/'selected-producer.py',new.encode())
patch=put(out/'x64-to-arm64-selected.patch',''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='reviewed-x64/selected-producer.py',tofile='arm64/selected-producer.py')).encode())
plan={'schema':'trnm-H5DF-arm64-selected-ranges-approval-plan-v1','status':'PREPARED_NOT_EXECUTED','artifact_id':14124468052,'run_id':43621754143,'run_attempt':1,'job_id':132528769087,'head':d['workflow_head'],'tree':d['expected_tree'],'directory_pin':{'path':str(dpath),'bytes':6078,'sha256':'71d2ba7895fd2c00303255fbddcd665de79a861aa96b5e4e5646ad6a478587c3'},'central_directory_pin':c,'actual_directory_members':161,'selected_paths':selected,'records':spans,'new_range_groups':groups,'directory_original_GETs':2,'planned_new_GETs':len(groups),'planned_combined_GETs':2+len(groups),'maximum_combined_GETs':21,'selected_record_bytes':total,'selected_expanded_bytes':expanded,'reused_tail_paths':[x['path']for x in spans if x['already_in_tail']],'whole_zip_requested':False,'ELF_SQLite_requested':False,'merge_rule':'only exactly adjacent selected records; never intervening unselected data','combined_budget_seconds':900,'combined_monotonic_started':d['monotonic_started'],'combined_monotonic_deadline':d['monotonic_deadline'],'seconds_remaining_at_preparation':d['monotonic_deadline']-time.monotonic(),'per_GET_seconds':180,'no_automatic_retry':True,'refuse_HTTP_200':True,'root_confirmation_required_before_execution':True,'source':source,'diff':patch,'unchanged_helper_names':[k for k in af if k!='main'],'one_summary_projection_correction':'manifest binary_sha256_before/after names match real manifest; no admission or acquisition guard changed'}
pp=putj(out/'selected-range-plan.json',plan)
print(json.dumps({'status':'PREPARED_NOT_EXECUTED','producer':source,'diff':patch,'plan':pp,'planned_new_GETs':len(groups),'selected_members':25,'selected_record_bytes':total,'selected_expanded_bytes':expanded,'ranges':[{'start':g['start'],'end':g['end'],'bytes':g['end']-g['start']+1,'members':len(g['members'])}for g in groups],'remaining_seconds':plan['seconds_remaining_at_preparation']},sort_keys=True))
