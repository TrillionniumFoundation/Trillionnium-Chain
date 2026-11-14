import collections,datetime,hashlib,json,os,re,stat,sys,zlib
from pathlib import Path,PurePosixPath
BASE=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1')
SRC=BASE/'selected-resume-001'
OUT=BASE/'final-review-v3'
HEAD='5df7ae6f482157c5f7fdcbcd52222117a965053f'
TREE='6be4940d38cc88782657f2684cbefe48866f8b9f'
SELECTORS=['caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct','from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection','four_from_zero_w1_traces_keep_native_state_and_chainwork_unchanged','from_zero_service_shares_cpu_with_honest_work_and_reopened_owner','from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline']
def need(v,m):
 if not v:raise ValueError(m)
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,size=None,sha=None):
 p=Path(path);a=p.lstat()
 need(p.resolve(strict=True)==p and stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<=32*1024*1024,'INPUT_TYPE')
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb')as f:
  need(fp(a)==fp(os.fstat(f.fileno())),'INPUT_OPEN')
  b=f.read(a.st_size+1)
  need(fp(a)==fp(os.fstat(f.fileno())),'INPUT_FD_STABLE')
 need(fp(a)==fp(p.lstat())and len(b)==a.st_size,'INPUT_PATH_STABLE')
 need(size is None or len(b)==size,'INPUT_SIZE');need(sha is None or hashlib.sha256(b).hexdigest()==sha,'INPUT_SHA')
 return b
def pairs(items):
 d={}
 for k,v in items:need(k not in d,'DUPLICATE_KEY');d[k]=v
 return d
def parse(b):return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in()).throw(ValueError('NONFINITE')))
def pin(path):
 b=read(path);return{'path':str(path),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def getpin(p):return read(p['path'],p['bytes'],p['sha256'])
def put(name,value):
 b=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode();p=OUT/name
 need(len(b)<=65536,'COMPACT_OUTPUT_64K_CAP')
 with p.open('xb')as f:f.write(b)
 need(read(p)==b,'OUTPUT_READBACK')
 return{'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def typed_equal(a,b):
 if type(a)is not type(b):return False
 if isinstance(a,dict):return set(a)==set(b)and all(typed_equal(a[k],b[k])for k in a)
 if isinstance(a,list):return len(a)==len(b)and all(typed_equal(x,y)for x,y in zip(a,b))
 return a==b
OUT.mkdir(mode=0o700)
with(OUT/'producer.py').open('xb')as f:f.write(sys.argv[1].encode())
acqpin={'path':str(SRC/'summary.json'),'bytes':22217,'sha256':'721e28940cd1735b304104886fc2b553ba7df62e72b80d810ba350e99fb6daa6'}
acq=parse(getpin(acqpin));need(acq['status']=='SELECTED_ORIGINAL_MEMBERS_VERIFIED'and acq['actual_new_GETs']==8 and acq['actual_combined_GETs']==11,'ACQUISITION')
need(len(acq['steps'])==8 and all(x['complete_transport']is True and type(x['exit'])is int and x['exit']==0 and x['http_status']==206 for x in acq['steps']),'EIGHT_ACTUAL_206')
directory=parse(getpin(acq['directory_stage']))
need(acq['combined_monotonic_deadline']==directory['monotonic_deadline']and acq['combined_elapsed_seconds']<900,'ORIGINAL_DEADLINE')
cd=parse(getpin(directory['central_directory']));bycd={r['path']:r for r in cd['members']}
index=parse(getpin(acq['selected_members']))
need(index['count']==25 and len(index['files'])==25 and len(bycd)==161,'SELECTED_COUNT')
raws={};proofs=[]
for row in index['files']:
 name=row['path'];need(name not in raws,'DUPLICATE_SELECTED')
 raw=getpin(row['original']);need(len(raw)==row['bytes']and hashlib.sha256(raw).hexdigest()==row['sha256'],'SELECTED_INDEX')
 need(zlib.crc32(raw)&0xffffffff==int(bycd[name]['crc32_declared_hex'],16),'SELECTED_CRC')
 raws[name]=raw;proofs.append({'member':name,'bytes':len(raw),'sha256':row['sha256'],'crc32':row['crc32'],'crc32_verified':True,'original':row['original'],'origin':row['origin']})
j=lambda name:parse(raws[name])
manifest=j('from-zero-native/manifest.json');report=j('from-zero-native/confirmation/report.json');source=j('source.json')
expected={'base':None,'candidate':HEAD,'kind':'head','prospective_merge':None,'schema':'trnm-ci-source-v1','tested_commit':HEAD,'tested_tree':TREE,'tests_executed_by_identity_check':False,'tracked_bytes':3995072357,'tracked_entries':41681,'tracked_worktree_verified':True}
need(typed_equal(source,expected),'EXACT_TYPED_SOURCE')
need(typed_equal(manifest['source_before'],manifest['source_after']),'MANIFEST_SOURCE_PAIR')
for label in('source_before','source_after'):
 q=manifest[label];need(q['commit']==HEAD and q['tree']==TREE and q['test_sha256']=='c20a1d34bcb4ad9d0f37a9b65815aac3c9e50b267edb9a65e856b3acd954064f'and typed_equal(q['tracked_source_identity'],source),'MANIFEST_SOURCE_BINDING')
fmap=manifest['files'];need(type(fmap)is dict and len(fmap)==54,'NATIVE_FILEMAP_SIZE')
for k,v in fmap.items():
 pp=PurePosixPath(k);need(not pp.is_absolute()and pp.as_posix()==k and all(x not in('', '.', '..')for x in pp.parts)and re.fullmatch('[0-9a-f]{64}',v)is not None,'FILEMAP_FORMAT')
native_matches=[]
for row in proofs:
 name=row['member']
 if name.startswith('from-zero-native/')and name!='from-zero-native/manifest.json':
  rel=name[len('from-zero-native/'):];need(fmap.get(rel)==row['sha256'],'SELECTED_NATIVE_FILEMAP')
  native_matches.append({'manifest_files_key':rel,'sha256':row['sha256'],'member':name})
need(len(native_matches)==16,'SELECTED_NATIVE_FILEMAP_COUNT')
need([r['name']for r in manifest['runs']]==SELECTORS,'EXACT_FIVE_NATIVE_ROSTER')
native=[]
for row,name in zip(manifest['runs'],SELECTORS):
 prefix='from-zero-native/'+name+'/'
 process=j(prefix+'process.json');stdout=raws[prefix+'stdout'];stderr=raws[prefix+'stderr']
 need(typed_equal(process,row['process']),'PROCESS_INLINE_ORIGINAL_EXACT')
 need(type(process['exit_code'])is int and process['exit_code']==0 and process['timed_out']is False and row['passed']is True,'NATIVE_EXIT')
 need(process['command']==['/home/runner/work/_temp/target-cross-arch-cost/release/deps/public_v3_from_zero-bcd934e577e47a17',name,'--exact','--nocapture','--test-threads=1'],'ORIGINAL_NATIVE_ARGV')
 need(process['stdout_sha256']==row['stdout_sha256']==hashlib.sha256(stdout).hexdigest()and process['stderr_sha256']==row['stderr_sha256']==hashlib.sha256(stderr).hexdigest(),'NATIVE_STREAMS')
 text=stdout.decode('utf-8')
 labels=re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. ',text,re.M)
 need(labels==[name]and 'running 1 test' in text and re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out; finished in [0-9.]+s$',text,re.M)is not None,'EXACT_HARNESS_PASS')
 ne=row['named_execution'];need(ne['test']==name and type(ne['executed_tests'])is int and ne['executed_tests']==1,'NAMED_EXECUTION')
 native.append({'name':name,'manifest_pointer':'/runs/'+str(len(native)),'named_execution':ne,'command':process['command'],'exit_code':0,'timed_out':False,'actual_passed':1,'actual_failed':0,'actual_ignored':0,'unrelated_filtered':11,'process_pin':pin(SRC/'members'/prefix/'process.json'),'stdout_pin':pin(SRC/'members'/prefix/'stdout'),'stderr_pin':pin(SRC/'members'/prefix/'stderr'),'wall_ns':process['wall_ns'],'cpu_ns':process['cpu_ns'],'cpu_scope':process['cpu_scope']})
need(manifest['failures']==['CONFIRMATION_TARGET']and manifest['passed']is False and manifest['all_named_tests_passed']is True,'MANIFEST_FAILURE')
need(manifest['confirmation_observation']['original_gate_validated']is False and manifest['confirmation_observation']['original_gate_validation_error']=='CONFIRMATION_TARGET','ORIGINAL_VALIDATOR_ERROR')
need(manifest['binary_sha256_before']==manifest['binary_sha256_after']=='2ebad185ecc1204d50c8d31b903722c99490929a5c7249366c99f32304d76ae5','RECORDED_BINARY_PAIR')
verification=put('selected-source-and-native-verification.json',{'schema':'trnm-H5DF-arm-selected-source-verification-v1','source':source,'manifest_source_before_after':manifest['source_before'],'recorded_binary_sha256_before':manifest['binary_sha256_before'],'recorded_binary_sha256_after':manifest['binary_sha256_after'],'ELF_bytes_not_acquired_or_independently_hashed':True,'selected_members':proofs,'manifest_native_filemap_declared_count':54,'selected_native_filemap_verified_count':len(native_matches),'selected_native_filemap_matches':native_matches,'unselected_manifest_declared_files_not_byte_verified':sorted(set(fmap)-{x['manifest_files_key']for x in native_matches}),'five_actual_native_controls':native,'manifest_outcome':{k:manifest[k]for k in('schema','passed','failures','all_named_tests_passed','format_passed','source_recompiled','execution_finished','production_activation','independent_wan_accepted','work_hardness_accepted')},'original_confirmation_validator':{'pointer':'/confirmation_observation','original_gate_validated':False,'original_gate_validation_error':'CONFIRMATION_TARGET'},'whole_artifact_sha256_verified':False,'all_artifact_members_crc_verified':False})
controller=j('from-zero-native-host/controller-result.json');child=j('from-zero-native-host/child-result.json')
inside0=j('from-zero-native-host/inside-before.json');inside1=j('from-zero-native-host/inside-after.json');outside=j('from-zero-native-host/outside-after.json')
limits={'cpu.max':'25000 100000','cpu.max.burst':'0','memory.max':'2147483648','memory.swap.max':'0','pids.max':'256'}
for x in(inside0,inside1,outside):need(typed_equal(x['limits'],limits)and x['read_errors']=={},'HOST_LIMITS')
for key in('boot_id','parent','installed_unit_sha256','service','parent_path'):need(typed_equal(inside0[key],inside1[key])and typed_equal(inside1[key],outside[key]),'HOST_IDENTITY')
need(controller['failure']is None and controller['final_host_errors']==[]and controller['systemd_run_exit']==1 and child['host_errors']==[]and child['native_child_exit']==1,'HOST_OUTCOME')
need(typed_equal(controller['parent_lease'],controller['final_parent_lease']),'LEASE_PAIR')
need(controller['preparation']['completed']is True and controller['preparation']['process']['exit_code']==0 and controller['preparation']['binary_sha256']==manifest['binary_sha256_before'],'BUILD_IDENTITY')
def cpu_stat(x):
 d={}
 for line in x['counters']['cpu.stat'].splitlines():
  k,v=line.split();need(k not in d,'CPU_STAT_DUPLICATE');d[k]=int(v)
 return d
c0,c1=cpu_stat(inside0),cpu_stat(inside1);need(set(c0)==set(c1),'CPU_STAT_KEYS')
host=put('host-original-controls.json',{'schema':'trnm-H5DF-arm-host-original-controls-v1','controller':{'schema':controller['schema'],'systemd_run_exit':controller['systemd_run_exit'],'failure':controller['failure'],'final_host_errors':controller['final_host_errors'],'parent_reused':controller['parent_reused'],'preparation_completed':True,'preparation_build_exit':0,'preparation_binary_sha256':controller['preparation']['binary_sha256'],'preparation_source_before':controller['preparation']['source_before'],'preparation_source_after':controller['preparation']['source_after']},'child':child,'limits_before_after_outside_exact':limits,'parent_identity':inside0['parent'],'boot_id':inside0['boot_id'],'installed_unit_sha256':inside0['installed_unit_sha256'],'service':inside0['service'],'thread_cgroup_before_after':inside0['thread_cgroup'],'thread_privileges_before':inside0['thread_privileges'],'thread_privileges_after':inside1['thread_privileges'],'inside_before_utc':inside0['observed_utc'],'inside_after_utc':inside1['observed_utc'],'cpu_stat_before':c0,'cpu_stat_after':c1,'cpu_stat_delta':{k:c1[k]-c0[k]for k in c0},'cpu_stat_scope':'Entire original native child command between inside snapshots; contains builds/setup and multiple controls; not the four-second pressure phase or one replay; cannot allocate throttled time to an individual phase','original_pins':{n:pin(SRC/'members/from-zero-native-host'/n)for n in('controller-result.json','child-result.json','inside-before.json','inside-after.json','outside-after.json','prepare-build.json','systemd-run.log')}})
def phase_rows(snapshot):
 return [v for v in snapshot['phases']if(v.get('started')or v.get('completed')or v.get('error_code'))and v['phase']in('work','admission','commit','cpu_wait','history_epoch_open','history_epoch_close','history_import')]
def calltop(c):
 return{k:c[k]for k in('status','started_ns','ended_ns','elapsed_wall_ns','client_thread_cpu_ns','deadline_ms','returned_after_deadline','returned_after_window','error')if k in c}
def phase_info(i,p):
 out={'report_pointer':'/phases/'+str(i),'reported':{k:p[k]for k in('mode','workers','requested_window_ns','business_started_ns','confirmation_ended_ns','client_confirmation_latency_ns','client_confirmed_before_original_window_end','client_confirmed_transactions','finite_business_target_met','invariant_target_met','no_attack_accepted','receiver_matches_valid_honest_prefix','full_native_state_equal','verification_errors','reader_cpu_ns','attacker_workers_cpu_ns','attacker_workers_cpu_scope','independent_replay_and_confirmation_cpu_ns','independent_replay_and_confirmation_wall_ns','initial_meter','final_meter')},'submit_calls':[calltop(c)for c in p['honest_submissions']],'history_calls':[calltop(c)for c in p['honest_history']],'head_calls_count':len(p['honest_heads']),'head_successes_in_window':p['honest_head_successes_in_window'],'replays':[]}
 need(p['requested_window_ns']==4000000000 and p['workers']==(0 if i==0 else 16),'ORIGINAL_WINDOW_WORKERS')
 for k,q in enumerate(p['independent_history_page_replay']):
  n=q['native_import_observation'];baseptr='/phases/'+str(i)+'/independent_history_page_replay/'+str(k)
  buckets=[x for x in n['host_checkpoint_attribution']['buckets']if x['calls']['calls_started']]
  checkpoint=next(x for x in n['host_checks']if x['phase']=='checkpoint')
  need(sum(x['calls']['calls_started']for x in buckets)==checkpoint['calls_started']and n['host_checkpoint_attribution']['all_checkpoint_calls_attributed']is True,'HOST_BUCKET_COUNT')
  row={'report_pointer':baseptr,'reported':{a:b for a,b in q.items()if a!='native_import_observation'},'page_active_phases':phase_rows(n),'packet_active_phases':[{'packet_index':x['packet_index'],'phases':phase_rows(x)}for x in n['packets']],'host_checks':n['host_checks'],'host_work_bucket':next((x['calls']for x in buckets if x['owner_phase']=='work'),None),'host_commit_bucket':next((x['calls']for x in buckets if x['owner_phase']=='commit'),None),'native_wait_attribution':n['native_attribution'],'measurement_failures':n['measurement_failures'],'cpu_intervals_are_nested_not_additive':n['cpu_intervals_are_nested_not_additive']}
  out['replays'].append(row)
 out['attack_workers']=[{'worker':x['worker'],'calling_thread_cpu_ns':x['calling_thread_cpu_ns'],'recorded_calls':len(x['calls']),'call_status_counts':dict(collections.Counter(c.get('status','MISSING')for c in x['calls'])),'attempt_cap_reached':x['attempt_cap_reached']}for x in p['attacks']]
 need(sum(x['calling_thread_cpu_ns']for x in out['attack_workers'])==p['attacker_workers_cpu_ns'],'WORKER_CPU_SUM')
 records=p['observations']['records']
 out['receiver_observations']={'retained_records':len(records),'measurement_failures':p['observations']['measurement_failures'],'records_not_retained':p['observations']['records_not_retained'],'dispatch_thread_cpu_known_sum_ns':sum(x['dispatch_thread_cpu_ns']for x in records if type(x.get('dispatch_thread_cpu_ns'))is int),'full_work_thread_cpu_known_sum_ns':sum(x['full_work_thread_cpu_ns']for x in records if type(x.get('full_work_thread_cpu_ns'))is int),'cpu_intervals_are_nested_not_additive':p['observations']['cpu_intervals_are_nested_not_additive'],'cpu_includes_reactor_authentication':p['observations']['cpu_includes_reactor_authentication'],'cpu_includes_reactor_authentication_or_response_signing':p['observations']['cpu_includes_reactor_authentication_or_response_signing'],'scope':'Retained receiver records only; full-work nested in dispatch; not total process or full service CPU'}
 out['service_metrics_selected']={k:v for k,v in p['service']['metrics'].items()if 'cpu' in k or k in('work_started','work_finished','work_failed','work_ns','queue_wait_ns','tasks_enqueued','tasks_dequeued','completed_submit','completed_read')}
 out['native_clock_scope']=p['independent_history_page_replay'][0]['native_import_observation']['clock_scope']
 out['host_bucket_scope']=p['independent_history_page_replay'][0]['native_import_observation']['host_checkpoint_attribution']['scope']
 out['clock_limit']='Replay started/ended are original traffic phase clock. Native phase and Host timestamps have their own observer-local epoch; no invented exact cross-epoch absolute conversion. CPU/wall intervals overlap/nest and must not be added.'
 return out
phase_details=[phase_info(i,p)for i,p in enumerate(report['phases'])]
need(len(phase_details)==2,'TWO_ORIGINAL_PHASES')
phasepins=[]
for i,detail in enumerate(phase_details):
 # Preserve compact independent scopes instead of repeating wait records in every replay.
 for row in detail['replays']:
  waits=row.pop('native_wait_attribution')
  wc=lambda x:{k:x[k]for k in('reserve_attempts','reserve_returns','reserve_granted','reserve_budget_refusals','reserve_other_refusals','sleep_calls_started','sleep_calls_completed','requested_sleep_ns','actual_sleep_wall_ns')}
  row['native_wait_attribution_compact']={'page_owner_mode':waits['page']['owner_mode'],'page_epoch_substeps':[{'substep':x['substep'],'wall_ns':x['span']['wall_ns'],'thread_cpu_ns':x['span']['thread_cpu_ns'],'accepted':x['span']['accepted'],'error_code':x['span']['error_code']}for x in waits['page']['epoch_substeps']],'page_cpu_waits':[wc(x)for x in waits['page']['cpu_waits']],'packet_cpu_waits':[{'packet_index':x['packet_index'],'cpu_waits':[wc(c)for c in x['attribution']['cpu_waits']]}for x in waits['packets']]}
 replay_details=detail.pop('replays')
 detail['replay_detail_files']=[put(('baseline'if i==0 else'pressure')+'-replay-'+str(k)+'-stage.json',row)for k,row in enumerate(replay_details)]
 phasepins.append(put(('baseline'if i==0 else'pressure')+'-stage-facts.json',detail))
last=report['phases'][1]['independent_history_page_replay'][-1]
lastn=last['native_import_observation'];lastpacket=lastn['packets'][0]
lp={x['phase']:x for x in lastpacket['phases']}
need(lp['work']['accepted']is True and lp['work']['completed']is True and lp['commit']['error_code']=='PUBLIC_REQUEST_DEADLINE'and last['replay_error']=='PUBLIC_REQUEST_DEADLINE','LAST_REPLAY_PHASE')
need(lastn['native_attribution']['page']['owner_mode']=='exclusive','EXCLUSIVE_OWNER')
table=[]
for i,p in enumerate(report['phases']):
 table.append({'pointer':'/phases/'+str(i),'mode':p['mode'],'workers':p['workers'],'requested_window_ns':p['requested_window_ns'],'Submit_records':len(p['honest_submissions']),'Submit_ok_before_window':sum(c['status']=='ok'and c['ended_ns']<=p['requested_window_ns']and c['returned_after_deadline']is False and c['returned_after_window']is False for c in p['honest_submissions']),'History_records':len(p['honest_history']),'History_ok_before_window':sum(c['status']=='ok'and c['ended_ns']<=p['requested_window_ns']and c['returned_after_deadline']is False and c['returned_after_window']is False for c in p['honest_history']),'replay_records':len(p['independent_history_page_replay']),'accepted_in_window':sum(x['replay_accepted']is True and x['replay_ended_ns']<=p['requested_window_ns']for x in p['independent_history_page_replay']),'confirmation_latency_ns':p['client_confirmation_latency_ns'],'confirmation_ended_ns':p['confirmation_ended_ns'],'confirmed_transactions':p['client_confirmed_transactions'],'finite_business_target_met':p['finite_business_target_met'],'verification_errors':p['verification_errors'],'replays':[{k:v for k,v in x.items()if k!='native_import_observation'}for x in p['independent_history_page_replay']]})
facts={'schema':'trnm-H5DF-arm64-original-confirmation-facts-v1','status':'ORIGINAL_FAILURE_CAUSE_BOUNDED','observed_run':{'repository':'TrillionniumFoundation/Trillionnium-Chain','run_id':43621754143,'run_attempt':1,'job_id':132528769087,'head':HEAD,'tree':TREE,'artifact_id':14124468052,'artifact_declared_bytes':9909858,'artifact_declared_sha256':'3b093c989b92fb7d657195826ae6faed9e641840dbe8f48c7721aebcf7804d7d','job_url':'https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43621754143/job/132528769087'},'acquisition':{'initial_selected_attempt':'HOLD / GH_GET_NONZERO / no body; original retained','explicit_once_resume_status':acq['status'],'selected_members':25,'actual_CD_members':161,'actual_directory_and_both_selected_attempt_GETs':11,'automatic_retry':False,'original_900s_deadline_preserved':True,'combined_elapsed_seconds':acq['combined_elapsed_seconds'],'whole_zip_sha256_verified':False,'all_member_crc_verified':False,'selected_member_CRC_and_SHA_verified':True,'ELF_SQLite_not_acquired':True},'native_original_results':{'names':SELECTORS,'each_exited_zero':True,'each_named_harness_one_pass_zero_failed_zero_ignored':True,'unrelated_filtered_per_invocation':11,'manifest_passed':False,'manifest_failures':['CONFIRMATION_TARGET'],'original_validator_error':'CONFIRMATION_TARGET','all_named_tests_passed':True},'report_identity':{k:report[k]for k in('schema','finite_target_met','invariant_target_met','same_packet_sequence_in_both_runs','signed_honest_packets','production_activation','public_network_ready','work_profile_qualified')},'baseline_pressure':table,'last_pressure_replay':{'report_pointer':'/phases/1/independent_history_page_replay/3','native_snapshot':pin(BASE/'offline-analysis-v1/pressure-replay-3-native-observation.json'),'packet_work_phase':lp['work'],'packet_admission_phase':lp['admission'],'packet_commit_phase':lp['commit'],'host_work_bucket':next(x for x in lastn['host_checkpoint_attribution']['buckets']if x['owner_phase']=='work'),'host_commit_bucket':next(x for x in lastn['host_checkpoint_attribution']['buckets']if x['owner_phase']=='commit'),'host_checkpoint_aggregate':next(x for x in lastn['host_checks']if x['phase']=='checkpoint'),'owner':'exclusive','page_cpu_waits':lastn['native_attribution']['page']['cpu_waits'],'packet_cpu_waits':lastn['native_attribution']['packets'][0]['attribution']['cpu_waits'],'epoch_substeps':lastn['native_attribution']['page']['epoch_substeps']},'scope_and_causal_limits':['This ARM original proves a commit-phase PUBLIC_REQUEST_DEADLINE after completed accepted W1 work; not the x64 work-phase rejection.','All 1170 last-page checkpoint calls and all 1099 work calls were accepted. These are observations, not permission to reduce fresh Host checks.','Host-span CPU and summed wall are nested; CPU includes each invoking thread while phase CPU is caller-local. Neither sums prove CFS/quota contention, synchronous I/O, or a safe optimization.','Actual parent limits are 25000/100000 = 0.25 CPU, burst0, 2GiB, zero swap, pids256; whole-child cpu.stat is not a phase-specific clock.','Binary before/after hashes are original manifest/controller records; ELF bytes were not fetched.','No source/ref/config/stage changes; no native/build/test/probe/dispatch/rerun executed; no new performance fix or qualification claimed.'],'source_and_control_verification':verification,'host_original_controls':host,'phase_details':phasepins,'original_report_pin':pin(SRC/'members/from-zero-native/confirmation/report.json'),'original_manifest_pin':pin(SRC/'members/from-zero-native/manifest.json'),'acquisition_summary':acqpin,'completed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
facts_pin=put('exact-confirmation-facts.json',facts)
for row in proofs:getpin(row['original'])
getpin(acqpin);getpin(acq['directory_stage']);getpin(directory['central_directory'])
print(json.dumps({'status':facts['status'],'facts':facts_pin,'source_and_controls':verification,'host':host,'phases':phasepins,'selected_member_count':25,'matched_native_manifest_entries':len(native_matches),'baseline_confirmation_latency_ns':table[0]['confirmation_latency_ns'],'pressure_replays':table[1]['replay_records'],'pressure_accepted':table[1]['accepted_in_window'],'last_replay_error':last['replay_error'],'last_replay_failed_phase':'commit','phase_observation_not_new_execution':True},sort_keys=True))
