#!/usr/bin/env python3
"""Read existing c5dd campaign data and immutable source; no native execution."""
from pathlib import Path
import datetime
import hashlib
import json
import subprocess
import zipfile

OUT = Path(__file__).resolve().parent
ROOT = Path('/workspace/scratch/b5a148b09b11/chain-six-axis')
ARCHIVE = Path('/workspace/scratch/b5a148b09b11/next-hosted/c5dd7c-review/c5dd7c-original-campaign-13276003536.zip')
COMMIT = 'c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1'
TREE = '30f59a8ec2abdc269bf91e228c58206b23add43d'
EXPECTED_ARCHIVE = '78e1b41ced06d6b77568a132d60623a1a7b5059ef9791dd43cc8ed4110efaacb'
sha = lambda raw: hashlib.sha256(raw).hexdigest()
archive_raw = ARCHIVE.read_bytes()
assert sha(archive_raw) == EXPECTED_ARCHIVE
sources = []
for relative in [
    'trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/history_import/observation.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs',
    'trillionnium/crates/trnm-pon-node/Cargo.toml',
    'docs/protocol/pon-nakamoto-v1/details/PERFORMANCE_ACCEPTANCE.md',
]:
    raw = subprocess.check_output(['git','--no-replace-objects','show',COMMIT+':'+relative],cwd=ROOT)
    sources.append({'path':relative,'source_commit':COMMIT,'bytes':len(raw),'sha256':sha(raw),
                    'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
                    'current_worktree_bytes_equal':(ROOT/relative).read_bytes()==raw,
                    'url':'https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/'+COMMIT+'/'+relative})
runs=[]
with zipfile.ZipFile(ARCHIVE) as z:
    source_raw=z.read('source-before.json');source=json.loads(source_raw)
    assert source['tested_commit']==COMMIT and source['tested_tree']==TREE
    for run in (1,2,3):
        member=f'run-{run}-raw/baseline.json';raw=z.read(member);data=json.loads(raw)
        rows=[]
        for index,history in enumerate(data['history']):
            client=history.get('client_import')
            if client is None:
                rows.append({'history_index':index,'client_import_observed':False})
                continue
            observation=client['native_import_observation']
            checkpoints=[h for h in observation['host_checks'] if h['phase']=='checkpoint']
            assert len(checkpoints)==1
            host=checkpoints[0]
            phases=[{'packet_index':p['packet_index'],'packet_id':p['packet_id'],**phase}
                    for p in observation['packets'] for phase in p['phases']
                    if phase['phase']=='submit_result' and phase['started']]
            rows.append({'history_index':index,'client_import_observed':True,
                         'network_started_ns':history['started_ns'],'network_ended_ns':history['ended_ns'],
                         'network_status':history['status'],
                         'client_import':{k:v for k,v in client.items() if k!='native_import_observation'},
                         'host_checkpoint':host,'submit_result_phases':phases,
                         'observer_scope':{k:observation[k] for k in (
                             'measurement_failures','host_checks_are_nested_not_additive',
                             'cpu_intervals_are_nested_not_additive','phase_cpu_excludes_scoped_workers',
                             'host_cpu_includes_each_calling_thread','host_cpu_is_full_worker_cpu',
                             'observation_has_consensus_authority','clock_scope')},
                         'mean_host_invocation_cpu_ns':host['thread_cpu_ns']/host['calls_completed']
                             if host['calls_completed'] and host['thread_cpu_ns'] is not None else None,
                         'mean_nested_host_invocation_wall_ns':host['wall_ns']/host['calls_completed']
                             if host['calls_completed'] and host['wall_ns'] is not None else None})
        complete=rows[6]
        assert complete['host_checkpoint']['calls_completed']==29928
        assert complete['host_checkpoint']['calls_rejected']==0
        assert complete['host_checkpoint']['calls_unfinished']==0
        assert len(complete['submit_result_phases'])==1
        runs.append({'run':run,'member':member,'raw_bytes':len(raw),'raw_sha256':sha(raw),
                     'state_backend':data['state_backend'],'original_duration_seconds':data['duration_seconds'],
                     'confirmations':data['confirmations'],'service_outcome':data['service_outcome'],
                     'phase_process_context':data['phase_process_context'],'history':rows})

paths=['/proc/sys/kernel/random/boot_id','/proc/thread-self/cgroup']+[
    '/sys/fs/cgroup/trnmponpublic.slice/'+name for name in
    ('cpu.max','cpu.max.burst','memory.max','memory.swap.max','pids.max')]
result={'schema':'trnm-c5dd-host-checkpoint-cost-readback-v1',
        'readback_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source':source,'source_raw_sha256':sha(source_raw),'source_bindings':sources,
        'artifact':{'id':13276003536,'path':str(ARCHIVE),'bytes':len(archive_raw),'sha256':sha(archive_raw),
                    'downloaded_by_this_reader':False},'runs':runs,
        'static_accepted_checkpoint_work':{
            'fresh_file_open_operations':7,'file_drops_closing_descriptors':7,
            'complete_Read_read_calls_minimum_when_all_seven_texts_nonempty':14,
            'parent_symlink_metadata_API_calls':1,
            'normal_case_source_buffer_bytes':5*129+2*257,
            'contents_or_authorization_verdict_cached':False,
            'paths_precomputed_or_literal':paths,
            'path_utf8_byte_lengths':[len(p.encode()) for p in paths],
            'std_C_string_stack_threshold_bytes':384,
            'per_page6_29928_checkpoints_source_level_fresh_opens':29928*7,
            'per_page6_29928_checkpoints_minimum_nonempty_Read_calls':29928*14,
            'per_page6_29928_checkpoints_parent_metadata_API_calls':29928,
            'counts_are_static_source_arithmetic_not_observed_syscall_trace':True},
        'limits':[
            '29928 is the checkpoint aggregate of the entire index6 page import, not an exact activation-only call count.',
            'Host CPU sums actual Host-call intervals on each invoking thread; caller CPU excludes scoped workers. Their ratio is not an exact cost fraction.',
            'Host intervals nest inside page import and include no full worker CPU or independent transport duration; do not add nested totals.',
            'No per-file open/read/close/parser CPU attribution exists in this retained aggregate.',
            'Resource_sample cpu.stat/BTreeMap parsing is not called by KernelBudget.verify; it is not repeated at every checkpoint.',
            'Static source inspection and arithmetic provide no measured optimization benefit or service acceptance.'
        ],'native_tests_executed':0,'benchmarks_executed':0,
        'source_target_ref_or_PR_mutated':False}
with (OUT/'host-checkpoint-readback.json').open('x') as f:f.write(json.dumps(result,indent=2)+'\n')
print(json.dumps({'source':COMMIT,'artifact_sha256':sha(archive_raw),'runs':[
    {'run':r['run'],'complete_page_import_wall_ns':r['history'][6]['client_import']['wall_ns'],
     'checkpoint_calls':r['history'][6]['host_checkpoint']['calls_completed'],
     'host_cpu_ns':r['history'][6]['host_checkpoint']['thread_cpu_ns'],
     'host_nested_wall_ns':r['history'][6]['host_checkpoint']['wall_ns'],
     'submit_result_wall_ns':r['history'][6]['submit_result_phases'][0]['wall_ns'],
     'mean_host_cpu_ns':r['history'][6]['mean_host_invocation_cpu_ns']} for r in runs]}))
