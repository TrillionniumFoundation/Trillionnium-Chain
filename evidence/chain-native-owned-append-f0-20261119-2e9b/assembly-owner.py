from pathlib import Path
from datetime import datetime,timezone
from collections import Counter
import json,hashlib,tarfile,io,stat,time,resource,sys,traceback
root=Path('/home/qian-qi/work/chain-native-owned-append-f0-20261119-2e9b');out=root/'artifact-build-1';out.mkdir(exist_ok=False);(out/'owner.py').write_text(sys.argv[1]);pub=root/'publication-1';pub.mkdir(exist_ok=False);t=time.monotonic();cpu=resource.getrusage(resource.RUSAGE_SELF);res={'schema':'chain-owned-append-original-f0-complete-evidence-build-v1','head':'e8b0ec93ab6a6a1ff5e36cfcf9d1179e030a5975','run_id':44465153982,'complete':False}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def write(p,obj):
 with p.open('x') as f:json.dump(obj,f,indent=2,sort_keys=True,allow_nan=False);f.write('\n')
def copy(p,dest):
 raw=p.read_bytes()
 with dest.open('xb') as f:f.write(raw)
def save():(out/'RESULT.json').write_text(json.dumps(res,indent=2)+'\n')
try:
 rb=json.loads((root/'f0-independent-readback.json').read_text());assert rb['head']==res['head'] and rb['run_id']==res['run_id'] and rb['business_pass'] is False
 snap_raw=(root/'automatic-ci-at-f0-1/SNAPSHOT.json').read_bytes();snap=json.loads(snap_raw);assert snap['head']==res['head'] and snap['complete_job_denominators'] is True and len(snap['runs'])==28
 recovery=json.loads((root/'automatic-ci-timepoint-recovery-2/RESULT.json').read_text());assert recovery['complete'] is True and recovery['exit_code']==0 and recovery['retry_count']==1
 failed=[]
 for run in snap['runs']:
  for log in run['failed_job_log_requests']:
   p=root/'automatic-ci-at-f0-1'/log['file'];raw=p.read_bytes();assert len(raw)==log['bytes'] and sha(raw)==log['sha256']
   if log['exit_code']!=0:
    assert log['job_id']==recovery['job_id'];p=Path(recovery['stdout']['file']);raw=p.read_bytes();assert len(raw)==recovery['stdout']['bytes'] and sha(raw)==recovery['stdout']['sha256']
    selected={'file':str(p.relative_to(root)),'bytes':len(raw),'sha256':sha(raw),'read_only_recovery_used':True}
   else:selected={'file':str(p.relative_to(root)),'bytes':len(raw),'sha256':sha(raw),'read_only_recovery_used':False}
   failed.append({'run_id':run['run']['id'],'run_name':run['run']['name'],'job_id':log['job_id'],'name':log['name'],'conclusion':log['conclusion'],'original_request':log,'complete_log':selected})
 assert len(failed)==43
 jobs=[j for r in snap['runs'] for j in r['jobs']['items']]
 ci={'head':res['head'],'timepoint_not_terminal':True,'run_count':len(snap['runs']),'automatic_run_count':sum(r['run']['event']!='workflow_dispatch' for r in snap['runs']),'job_count':len(jobs),'job_states':dict(Counter(j['conclusion'] or j['status'] for j in jobs)),'run_states':dict(Counter(r['run']['conclusion'] or r['run']['status'] for r in snap['runs'])),'snapshot_pending_run_ids':snap['snapshot_pending_run_ids'],'all_final':snap['all_final'],'original_api_failure_count':len(snap['api_failures']),'original_snapshot_bytes':len(snap_raw),'original_snapshot_sha256':sha(snap_raw),'failed_job_count':len(failed),'every_failure_log_verified_after_one_read_only_recovery':True,'failure_logs':failed,'recovery':recovery,'snapshot_requests_are_sequential_intervals_not_one_atomic_state':True,'business_rerun':False}
 write(pub/'automatic-ci-timepoint-readback.json',ci)
 cp=json.loads((root/'current-cost-profile.json').read_text())['run'];timing=json.loads((root/'collection/timing.stdout').read_text());cost={'schema':'chain-owned-append-original-f0-complete-cost-scope-v1','head':res['head'],'run_id':res['run_id'],'original_credits_windows_and_cpu_assertions_changed':False,'nested_intervals_overlap_and_are_not_additive':True,'full_physical_cost_closed':False,'unknown_cost_dimensions':rb['unknown_cost_dimensions'],'provider_timing':timing,'provider_zero_billable_fields_do_not_prove_zero_cost':True,'money':None,'phases':[]}
 for p in cp['phases']:
  cost['phases'].append({k:v for k,v in p.items() if k not in ('history_attempts','actual_graph_frequency')})
 cost['readback_execution']=json.loads((root/'readback-execution-1/RESULT.json').read_text());cost['ci_timepoint_collection']={k:snap[k] for k in ('ended_utc','total_wall_seconds','aggregate_child_user_cpu_seconds','aggregate_child_system_cpu_seconds')};cost['failed_read_recovery']=recovery
 write(pub/'cost-summary.json',cost)
 for origin,dest in [('f0-independent-readback.json','f0-independent-readback.json'),('current-cost-profile.json','current-cost-profile.json'),('analysis-1/current-bottleneck.json','measured-bottleneck-comparison.json'),('automatic-ci-at-f0-1/SNAPSHOT.json','automatic-ci-original-timepoint.json'),('f0-readback.py','f0-readback.py'),('prior-f0-readback.py','prior-f0-readback.py'),('prior-cost-profile.py','prior-cost-profile.py'),('READERS_CONFIGS.json','READERS_CONFIGS.json'),('collection/COLLECTION.json','COLLECTION.json'),('dispatch-1/RESULT.json','single-dispatch.json'),('readers-preparation-1/RESULT.json','readers-preparation.json'),('readback-execution-1/RESULT.json','readback-execution.json'),('zip-parts-1/MANIFEST.json','zip-parts-manifest.json')]:copy(root/origin,pub/dest)
 previous=root.parent/'chain-native-operation-readback-f0-20261119-2e9b/automatic-ci-final-publication-3';prev=json.loads((previous/'RESULT.json').read_text());assert prev['complete'] is True and prev['head']=='3db79eb2682ba3bcbbf33557c5eee3b67731028f'
 for name in ('predecessor-complete-ci-originals.tar.xz','predecessor-complete-ci-summary.json','predecessor-complete-ci-index.json'):copy(previous/name,pub/name)
 copy(previous/'RESULT.json',pub/'predecessor-complete-ci-archive-cost.json')
 assert sha((pub/'predecessor-complete-ci-originals.tar.xz').read_bytes())=='e48a44484cffe9ed01b5b9a055ecc9a0b98819cde976397d2ab51daa505f2c6e'
 paths=[]
 for folder in ('dispatch-1','collection','readers-preparation-1','readers-source','readback-execution-1','analysis-1','collection-observation-2','automatic-ci-at-f0-1','automatic-ci-timepoint-recovery-2','zip-parts-1'):
  for p in (root/folder).rglob('*'):
   if not p.is_file():continue
   name=str(p.relative_to(root))
   if name.startswith('collection/artifact-') or name.startswith('zip-parts-1/f0-original.zip.part-'):continue
   paths.append(p)
 for name in ('f0-readback.py','prior-f0-readback.py','prior-cost-profile.py','READERS_CONFIGS.json','f0-independent-readback.json','current-cost-profile.json'):paths.append(root/name)
 paths=sorted(paths);assert len(paths)==len(set(paths));rows=[];archive=pub/'complete-f0-readback-originals.tar.xz'
 with tarfile.open(archive,'x:xz',format=tarfile.PAX_FORMAT) as tar:
  for p in paths:
   st=p.lstat();assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and not p.is_symlink();raw=p.read_bytes();name=str(p.relative_to(root));row={'path':name,'bytes':len(raw),'sha256':sha(raw)};rows.append(row);member=tarfile.TarInfo(name);member.size=len(raw);member.mode=0o644;member.mtime=0;tar.addfile(member,io.BytesIO(raw))
 with tarfile.open(archive,'r:xz') as tar:
  members=tar.getmembers();assert len(members)==len(rows)
  for member,row in zip(members,rows):
   raw=tar.extractfile(member).read();assert member.name==row['path'] and len(raw)==row['bytes'] and sha(raw)==row['sha256']
 zip_manifest=json.loads((root/'zip-parts-1/MANIFEST.json').read_text())
 write(pub/'archive-index.json',{'schema':'chain-owned-append-lossless-originals-index-v1','head':res['head'],'files':rows,'archive':{'path':archive.name,'bytes':archive.stat().st_size,'sha256':sha(archive.read_bytes())},'all_archive_bytes_verified':True,'original_f0_zip_losslessly_separate_parts':zip_manifest,'prior_source_ci_originals':{'head':prev['head'],'archive':{'path':'predecessor-complete-ci-originals.tar.xz','bytes':prev['archive_bytes'],'sha256':prev['archive_sha256']},'members':prev['members'],'all_final':True},'current_live_final_ci_not_archived_as_terminal':str(root/'automatic-ci-1')})
 readme=(
 '# Original F0 readback: owned native append candidate\n\n'
 '## Actual failed business result\n\n'
 'The sole original F0 run is 44465153982, attempt 1, against Draft #970 source e8b0ec93ab6a6a1ff5e36cfcf9d1179e030a5975 and tree c896826d4f376d6643b05c15486f573e9aff6546. This evidence publication is not a replacement tested source.\n\n'
 'The original 30-second phases confirmed **1/6** rounds; the original scheduled four-second target passed **0/6**. Timely network ACK exposure was **21/42**, and ACK is not confirmation. Actual native exit was **101**. The original readers refused **BASELINE_MUST_PASS**, **F0_ALL_SIX_SCHEDULED_FOUR_SECOND_TARGETS_REQUIRED**, and **NUMERIC_DEPLETION_REQUIRED**. Seven preparation controls passed and final owned services were known empty. Those facts do not qualify business success.\n\n'
 'All six rounds and 42 packet exposures remain in the denominator, including 21 unattempted exposures and three unattempted rounds. First baseline confirmation elapsed 17.899795997 seconds from its scheduled offset. The windows, burst/refill/reserve, worker and queue limits, snapshot 64, and fixed-512 CPU assertion were not changed. No business or CI rerun was used.\n\n'
 '## Exact original evidence\n\n'
 'The provider ZIP is 18,781,500 bytes, SHA-256 6f0550eff271a1f6b2328595cf75b2099b5b34963460df16bd7220412f84d46b. Provider digest matched; all 444 members and every one of the 443 declared original files passed length/SHA checks. Three parts concatenate byte-for-byte to this ZIP. Their original offsets, lengths, SHA-256 and Git blob identities are in zip-parts-manifest.json.\n\n'
 'The independent wrapper changed only source HEAD/TREE/RUN identities; all 12 original imported reader files and five configs matched their frozen hashes. The collector interface only supplies exact provider-body filename aliases and an expected_head field verified against both the native collection receipt and provider run. The original collector receipt and precise alias proof remain in the archive. Readback exit 0 verifies the failed evidence; it is not workload success.\n\n'
 '## Actual bottleneck and observer result\n\n'
 'Baseline observed 14 actual imports, 97,451 Host checkpoints, 5.654544360 seconds client thread CPU, and 4.678058554 seconds nested Host CPU. Client account_graph recorded 79 calls, 4.212871962 seconds CPU and 18.414139705 seconds wall time. The prior source had 10 imports and 80,709 checks. Different runner allocations and completed work prevent a paired causal speed claim; nested timings overlap and must not be summed.\n\n'
 'ROOT observed five actual client imports and 24,058 Host checks but no confirmed round. The original credit identity reconciles initial 2,000,000,000 + credited refill 5,011,216,826 - paid debit 5,011,486,185 = remaining 1,999,730,641 ns. This is not numeric depletion.\n\n'
 'The new observer snapshot change is reflected in this run: baseline 28 and ROOT 395 receiver records are complete, measurement failures are zero, and no records were omitted. This does not repair the prior run record-392 gap or establish physical network bytes, full system cost, or monetary charges. Physical network bytes remain unknown for all observed records.\n\n'
 '## Every actual CI denominator\n\n'
 'The current retained timepoint contains **28 runs (27 automatic plus this sole F0), 204 job records, and 43 failed jobs**. At the roster there were 11 in-progress runs, 11 successful runs and six failed runs. During sequential job reads: 100 success, 43 failure, 53 in-progress and eight skipped job states were observed. This is not an atomic or terminal snapshot. One failed-log read timed out after 312.574029 seconds with 15,383 partial bytes; the partial body and error are retained. Exactly one read-only recovery returned its full 42,066-byte log. All 43 failed-job full logs were subsequently byte/SHA verified. The original snapshot still records its failure; the supplementary readback binds the recovery without rewriting it. The separate terminal collector continues and no pending job is called successful.\n\n'
 'The prior source 3db79eb2682ba3bcbbf33557c5eee3b67731028f is now independently terminal: **26 runs, 205 jobs = 156 success / 41 failure / 7 skipped / 1 cancelled**, with all 42 failed or cancelled logs retained and verified. The complete 618-file archive is included, including all intermediate read-only polling observations and native cost. Its provider run-duration sum is 29,408,000 ms; this is neither CPU nor a monetary amount. The required baseline 44451670905 actually failed. These prior-source results cannot qualify the new source.\n\n'
 'The source #970 full public suite still has its real 294-pass/1-fail/2-ignored result. The original fixed-512 test paid 298,399,949 ns from 400,000,000 ns and retained 101,600,051 ns, so its required exhaustion assertion failed. It was not rerun to obtain a different CPU outcome. All frozen local repository-truth failures remain in source evidence; later source-map repairs or exact Git input restores do not retroactively change this F0 or that frozen gate status.\n\n'
 '## Complete files and costs\n\n'
 f'complete-f0-readback-originals.tar.xz retains {len(rows)} complete original collector, readback, source, configuration, failure-recovery, analysis and CI timepoint files; archive-index.json binds every byte length and SHA. The raw ZIP is separately stored as three exact parts to avoid duplicating it and its extracted members. The predecessor CI archive is separately bound to its original source. Restoring the ZIP under its recorded collection path and extracting its exact safe members recreates the original readback inputs.\n\n'
 'cost-summary.json and current-cost-profile.json preserve actual CPU/wall intervals, original controller resources, full paid-credit balances, provider timing and all unknown dimensions. The provider reports 536,000 ms run duration with zero billable fields; zero fields do not prove zero cost. Compiler/dependency CPU, concurrent whole-system RSS, storage I/O and byte-seconds, physical network traffic, GPU, energy and provider charges remain unknown. No merge, deployment, production activation, independent WAN, F1 or complete-cost qualification is claimed.\n')
 (pub/'README.md').write_text(readme)
 files=[]
 for p in sorted(pub.iterdir()):
  raw=p.read_bytes();files.append({'path':p.name,'absolute_path':str(p),'bytes':len(raw),'sha256':sha(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()})
 files+=zip_manifest['parts'];c=resource.getrusage(resource.RUSAGE_SELF);res.update(complete=True,files=files,archive_members=len(rows),archive_sha256=sha(archive.read_bytes()),wall_seconds=time.monotonic()-t,self_user_cpu_seconds=c.ru_utime-cpu.ru_utime,self_system_cpu_seconds=c.ru_stime-cpu.ru_stime,current_run_count=28,current_job_count=len(jobs),failed_job_count=len(failed),current_ci_all_final=False);save();print(json.dumps(res),flush=True)
except BaseException as e:res['error']=repr(e);save();(out/'error.log').write_text(traceback.format_exc());raise
