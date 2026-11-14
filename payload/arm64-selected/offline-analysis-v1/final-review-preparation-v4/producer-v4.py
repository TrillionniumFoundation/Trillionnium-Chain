import datetime,hashlib,json,os,stat,sys,zlib
from pathlib import Path
BASE=Path('/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1')
SRC=BASE/'selected-resume-001';OUT=BASE/'final-review-v4'
def need(v,m):
 if not v:raise ValueError(m)
def fp(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(p,n=None,h=None):
 p=Path(p);a=p.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and p.resolve(strict=True)==p and a.st_size<=32*1024*1024,'SOURCE_TYPE')
 with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb')as f:
  need(fp(a)==fp(os.fstat(f.fileno())),'SOURCE_OPEN');b=f.read(a.st_size+1);need(fp(a)==fp(os.fstat(f.fileno())),'SOURCE_FD')
 need(fp(a)==fp(p.lstat())and len(b)==a.st_size,'SOURCE_PATH')
 need(n is None or len(b)==n,'SOURCE_SIZE');need(h is None or hashlib.sha256(b).hexdigest()==h,'SOURCE_SHA')
 return b
def pin(p):
 b=read(p);return{'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def getpin(p):return read(p['path'],p['bytes'],p['sha256'])
def pj(b):
 def pairs(items):
  d={}
  for k,v in items:need(k not in d,'DUPLICATE_KEY');d[k]=v
  return d
 return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in()).throw(ValueError('NONFINITE')))
def put(name,v):
 b=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode();need(len(b)<=65536,'OUTPUT_64K');p=OUT/name
 with p.open('xb')as f:f.write(b)
 need(read(p)==b,'READBACK');return pin(p)
OUT.mkdir(mode=0o700)
with(OUT/'producer.py').open('xb')as f:f.write(sys.argv[1].encode())
acqpin={'path':str(SRC/'summary.json'),'bytes':22217,'sha256':'721e28940cd1735b304104886fc2b553ba7df62e72b80d810ba350e99fb6daa6'}
a=pj(getpin(acqpin));need(a['status']=='SELECTED_ORIGINAL_MEMBERS_VERIFIED'and a['actual_combined_GETs']==11,'ACQUISITION')
idx=pj(getpin(a['selected_members']));need(idx['count']==25,'COUNT')
raws={}
for row in idx['files']:
 b=getpin(row['original']);need(len(b)==row['bytes']and hashlib.sha256(b).hexdigest()==row['sha256']and zlib.crc32(b)&0xffffffff==int(row['crc32'],16),'CRC_SHA')
 raws[row['path']]=b
j=lambda name:pj(raws[name])
m=j('from-zero-native/manifest.json');r=j('from-zero-native/confirmation/report.json')
sourceproof=pin(BASE/'final-review-v3/selected-source-and-native-verification.json')
hostproof=pin(BASE/'final-review-v3/host-original-controls.json')
sp=pj(getpin(sourceproof));hp=pj(getpin(hostproof))
need(sp['selected_native_filemap_verified_count']==16 and sp['manifest_native_filemap_declared_count']==54,'SOURCE_PROOF')
need(len(sp['five_actual_native_controls'])==5 and all(x['exit_code']==0 and x['actual_passed']==1 and x['actual_failed']==0 and x['actual_ignored']==0 for x in sp['five_actual_native_controls']),'ORIGINAL_FIVE')
need(m['failures']==['CONFIRMATION_TARGET']and m['passed']is False and m['all_named_tests_passed']is True,'MANIFEST_FAILURE')
phasepins=[pin(BASE/'final-review-v3'/n)for n in('baseline-stage-facts.json','pressure-stage-facts.json')]
for p in phasepins:
 ph=pj(getpin(p))
 for q in ph['replay_detail_files']:getpin(q)
last=r['phases'][1]['independent_history_page_replay'][3]
n=last['native_import_observation'];q={x['phase']:x for x in n['packets'][0]['phases']}
need(q['work']['accepted']is True and q['work']['completed']is True and q['commit']['error_code']=='PUBLIC_REQUEST_DEADLINE','LAST_PHASE')
work=next(x for x in n['host_checkpoint_attribution']['buckets']if x['owner_phase']=='work')
commit=next(x for x in n['host_checkpoint_attribution']['buckets']if x['owner_phase']=='commit')
checkpoint=next(x for x in n['host_checks']if x['phase']=='checkpoint')
need(work['calls']['calls_started']==1099 and work['calls']['calls_accepted']==1099 and checkpoint['calls_started']==1170 and checkpoint['calls_accepted']==1170,'LAST_HOST_OBSERVATIONS')
table=[]
for i,p in enumerate(r['phases']):
 need(p['workers']==(0 if i==0 else 16)and p['requested_window_ns']==4000000000,'WINDOW_WORKERS')
 table.append({'pointer':'/phases/'+str(i),'mode':p['mode'],'workers':p['workers'],'requested_window_ns':p['requested_window_ns'],'Submit_records':len(p['honest_submissions']),'Submit_ok_before_window':sum(c['status']=='ok'and c['ended_ns']<=p['requested_window_ns']and c['returned_after_deadline']is False and c['returned_after_window']is False for c in p['honest_submissions']),'History_records':len(p['honest_history']),'History_ok_before_window':sum(c['status']=='ok'and c['ended_ns']<=p['requested_window_ns']and c['returned_after_deadline']is False and c['returned_after_window']is False for c in p['honest_history']),'replay_records':len(p['independent_history_page_replay']),'accepted_in_window':sum(x['replay_accepted']is True and x['replay_ended_ns']<=p['requested_window_ns']for x in p['independent_history_page_replay']),'confirmation_latency_ns':p['client_confirmation_latency_ns'],'confirmation_ended_ns':p['confirmation_ended_ns'],'confirmed_transactions':p['client_confirmed_transactions'],'finite_business_target_met':p['finite_business_target_met'],'verification_errors':p['verification_errors'],'replays':[{k:v for k,v in x.items()if k!='native_import_observation'}for x in p['independent_history_page_replay']],'attacker_workers_cpu_ns':p['attacker_workers_cpu_ns'],'reader_cpu_ns':p['reader_cpu_ns'],'independent_replay_and_confirmation_cpu_ns':p['independent_replay_and_confirmation_cpu_ns'],'independent_replay_and_confirmation_wall_ns':p['independent_replay_and_confirmation_wall_ns']})
packets=r['signed_honest_packets']
need(type(packets)is list and len(packets)==7,'ORIGINAL_SEVEN_PACKETS')
fact={'schema':'trnm-H5DF-arm64-original-confirmation-facts-v1','status':'ORIGINAL_FAILURE_CAUSE_BOUNDED','repository':'TrillionniumFoundation/Trillionnium-Chain','run_id':43621754143,'run_attempt':1,'job_id':132528769087,'head':'5df7ae6f482157c5f7fdcbcd52222117a965053f','tree':'6be4940d38cc88782657f2684cbefe48866f8b9f','artifact_id':14124468052,'job_url':'https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43621754143/job/132528769087','acquisition':{'selected_members':25,'directory_entries':161,'directory_and_both_selected_attempt_GETs':11,'initial_selected_attempt':'HOLD/GH_GET_NONZERO/0 body; original retained','explicit_once_resume':True,'all_eight_resume_ranges_actual_206':True,'original_900_second_deadline_preserved':True,'combined_elapsed_seconds':a['combined_elapsed_seconds'],'selected_member_CRC_SHA_verified':True,'whole_ZIP_SHA_verified':False,'all_artifact_CRC_verified':False,'no_ELF_SQLite_acquired':True},'native_original_results':{'names':[x['name']for x in sp['five_actual_native_controls']],'five_process_exit_codes':[x['exit_code']for x in sp['five_actual_native_controls']],'each_harness_one_pass_zero_failed_zero_ignored':True,'unrelated_filtered_per_invocation':11,'manifest_passed':False,'manifest_failures':['CONFIRMATION_TARGET'],'original_confirmation_validator_error':m['confirmation_observation']['original_gate_validation_error']},'report_identity':{**{k:r[k]for k in('schema','finite_target_met','invariant_target_met','same_packet_sequence_in_both_runs','production_activation','public_network_ready','work_profile_qualified')},'signed_honest_packets_pointer':'/signed_honest_packets','signed_honest_packet_count':7,'packet_wire_bytes_not_duplicated_in_this_compact_report':True},'baseline_pressure':table,'last_pressure_replay':{'pointer':'/phases/1/independent_history_page_replay/3','raw_native_snapshot':pin(BASE/'offline-analysis-v1/pressure-replay-3-native-observation.json'),'packet_work_phase':q['work'],'packet_admission_phase':q['admission'],'packet_commit_phase':q['commit'],'host_work_bucket':work,'host_commit_bucket':commit,'host_checkpoint_aggregate':checkpoint,'owner':n['native_attribution']['page']['owner_mode'],'page_cpu_waits':n['native_attribution']['page']['cpu_waits'],'packet_cpu_waits':n['native_attribution']['packets'][0]['attribution']['cpu_waits'],'epoch_substeps':n['native_attribution']['page']['epoch_substeps']},'limits':hp['limits_before_after_outside_exact'],'source_and_native_controls':sourceproof,'host_original_controls':hostproof,'phase_details':phasepins,'original_manifest_pin':pin(SRC/'members/from-zero-native/manifest.json'),'original_report_pin':pin(SRC/'members/from-zero-native/confirmation/report.json'),'acquisition_summary':acqpin,'evidence_limits':['ARM fourth replay completed accepted W1 work; the error arose in commit. Do not inherit x64 work-phase error location.','All accepted Host checks do not imply deadline credit or permission to reduce their frequency.','Host CPU and summed Host wall are nested in native phase/replay metrics; do not add these or infer CFS/quota/I/O as a unique cause.','Replay timestamps and native observation timestamps use different local epochs; no invented absolute cross-epoch conversion.','Whole-child cpu.stat and whole-test wait4 counters are not four-second per-phase measurements.','The binary SHA pair is recorded in original manifest/controller; ELF bytes were not independently acquired.','Only 16 selected entries of the 54-entry native filemap are byte-verified; other declarations are retained, not claimed read.','This is original failure evidence, with no code fix/native/build/test/probe/dispatch/rerun or qualification upgrade.'],'offline_packaging_history':['First derived summary producer syntax error retained.','Two derived summary attempts hit the unchanged 64KiB output cap; original packet wire bytes and per-replay details now referenced instead of duplicated.','These are local read-only packaging errors, distinct from the original hosted failure and the first network acquisition HOLD.'],'completed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
p=put('exact-confirmation-facts.json',fact)
md='''# H5DF ARM64 原始 cross-arch-cost 失败

固定对象：commit 5df7ae6f482157c5f7fdcbcd52222117a965053f，tree 6be4940d38cc88782657f2684cbefe48866f8b9f；run 43621754143 / attempt 1 / job 132528769087 / artifact 14124468052。

原五个 native selectors 均实际 exit 0，各自具名 harness 显示 1 passed、0 failed、0 ignored。原业务校验器独立拒绝 CONFIRMATION_TARGET。源码、test SHA 与记录的 binary SHA 前后相同；Host 的五项限额及身份前后核对通过。binary 记录为 2ebad185…，未获取或执行 ELF。

Baseline 在 1.805452089 秒业务延迟内确认，7 次 History 回放全部接受。Pressure 保留 4 秒、16 workers、7 packets/depth 6：7 个 Submit ACK，4 次 History 响应，前三次回放接受；第四次在 3.302799444–4.001658537 秒返回 PUBLIC_REQUEST_DEADLINE，未完成确认。

第四次的 W1 work 已接受：600.582643 ms wall、32.751792 ms caller CPU；其中 Work 桶 1,099 次 fresh Host 全部通过。失败发生在后续 commit：93.329799 ms wall、1.905472 ms caller CPU，21 次归入 commit 的 Host 检查全部通过。全页 1,170 次 checkpoint 通过。该页是 exclusive owner，page/packet 各一次 CPU reserve 均 granted、没有 sleep，durable_begin 0.540461 ms。此位置与 x64 的 Work 阶段拒绝不同。

这些时钟嵌套且范围不同。Host 的累计 wall、调用线程 CPU、整 child cpu.stat 不能相加或用于断定唯一的调度、配额、I/O 原因。本次不提出已经验证的性能修复，也不放宽任何原控制。

取证保留第一次 selected GET 的 HOLD。root 明确批准的单次续读使用原 900 秒截止时间，8 个精确范围均返回 206；25 个成员的 local header、descriptor、CRC 与 SHA 核验通过。整 ZIP SHA 和其余成员 CRC 未验证。原始大报告保留在 selected-resume-001/members/，这里仅提供其 pin 与有界字段引用，未重复 packet wire bytes。

本地摘要脚本的首个语法错误和两次 64 KiB 输出上限拒绝也原样保留；它们不是新的 CI/native 结果。没有源码、Git/ref、配置、stage、原失败证据修改，没有新 native、build、test、probe 或远端写入。
'''
raw=md.encode();rp=OUT/'README.md'
with rp.open('xb')as f:f.write(raw)
need(read(rp)==raw,'README_READBACK')
for row in idx['files']:getpin(row['original'])
getpin(acqpin)
print(json.dumps({'status':fact['status'],'facts':p,'README':pin(rp),'source_proof':sourceproof,'host_proof':hostproof,'phase_details':phasepins,'baseline_confirmation_latency_ns':table[0]['confirmation_latency_ns'],'pressure_records':table[1]['replay_records'],'pressure_accepted':table[1]['accepted_in_window'],'original_failed_phase':'commit'},sort_keys=True))
