#!/usr/bin/env python3
"""Audit immutable C8 core and real-receiver results; execute no tests or guards."""
import collections,hashlib,importlib.util,json,sys
from pathlib import Path

HELPER=Path('/home/qian-qi/work/chain-w1-c8-audit-backend-native-v2-20261108-ec265b.py')
HELPER_SHA='3aece36c2ea23e0e74f85197d224cb6ff5bc43c2ced5fe775bac59b8b5292047'
assert hashlib.sha256(HELPER.read_bytes()).hexdigest()==HELPER_SHA
hs=importlib.util.spec_from_file_location('c8_audit_helpers',HELPER)
h=importlib.util.module_from_spec(hs);hs.loader.exec_module(h)
REPO=Path('/home/qian-qi/work/chain-w1-base9417-integration-20261108-ec265b')
ROOT=Path('/home/qian-qi/work/chain-w1-c8-root-validation-20261108-ec265b')
TOOLS=Path('/home/qian-qi/work/chain-w1-c8-root-tools-20261108-ec265b')
DEST=Path('/home/qian-qi/work/chain-w1-c8-adversarial-core-receiver-20261108-ec265b-01')
SOURCE={'commit':'4e007a87ceecbec8d265f6a70cfd71d512a514b5','tree':'19a4f1a6e1cec5c27e595fa555b97cddc4717a3c'}
SOURCE_SHA='ae4700561bdd1dd273af73d36ca712162d430097daa9d1c3147704c9fe07083c'
DRIVER_SHA='d3c6953430a8efce70396eac88c891aa91501633013c09d5018f0b00e9fb7d1f'

def audit(spec,inputs):
    name=spec['component'];assert name in ('core','receiver')
    directory=Path(spec['path']).parent;dest=DEST/name;dest.mkdir()
    raw={};index=[]
    def add(path,rel=None,pin=None):
        path=Path(path);b=h.stable(path)
        if pin:
            assert h.sha(b)==pin['sha256'],str(path)
            if 'bytes' in pin:assert len(b)==pin['bytes']
        rel=rel or path.name;assert rel not in raw
        raw[rel]=b;index.append({'archive_member':rel,'original_path':str(path),'bytes':len(b),'sha256':h.sha(b)})
        return b
    m=h.load(add(directory/'manifest.json',pin=spec))
    assert m['qualification_complete'] is True and m['repo']==str(REPO)
    assert {'commit':m['source_commit'],'tree':m['source_tree']}==SOURCE
    assert m['fresh_proof_generations']==0
    assert all(m[x] is False for x in ('production_qualified','security_qualified','original_business_budget_qualified','resource_billing_complete','payment_qualified'))
    before=add(directory/'source-before.json',pin={'sha256':SOURCE_SHA})
    assert add(directory/'source-after.json',pin={'sha256':SOURCE_SHA})==before
    guard=h.load(before)
    assert guard['kind']=='head' and guard['candidate']==guard['tested_commit']==SOURCE['commit']
    assert guard['tested_tree']==SOURCE['tree'] and guard['base'] is None and guard['prospective_merge'] is None
    assert guard['tracked_worktree_verified'] is True and guard['tests_executed_by_identity_check'] is False
    p=h.load(add(TOOLS/(name+'-plan.json'),'provenance/plan.json',{'sha256':m['plan_sha256']}))
    assert p['source_commit']==SOURCE['commit'] and p['source_tree']==SOURCE['tree']
    assert m['driver_sha256']==DRIVER_SHA
    add(TOOLS/'qualify_source.py','provenance/qualify_source.py',{'sha256':DRIVER_SHA})
    commands=m['commands'];n={'core':20,'receiver':4}[name]
    assert len(commands)==m['actual_command_count']==p['declared_command_count']==n
    assert len(p['commands'])+3==n
    assert commands[0]['label']=='00-preflight' and commands[0]['argv']==['bash','scripts/project-preflight.sh','--dev']
    expected_guard=['python3','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',SOURCE['commit'],'--output']
    assert commands[1]['label']=='01-source-before' and commands[1]['argv']==expected_guard+[str(directory/'source-before.json')]
    assert commands[-1]['label']=='99-source-after' and commands[-1]['argv']==expected_guard+[str(directory/'source-after.json')]
    for i,(pc,c) in enumerate(zip(p['commands'],commands[2:-1]),2):
        expanded=[s.replace('@REPO@',str(REPO)).replace('@OUT@',str(directory)).replace('@HEAD@',SOURCE['commit']) for s in pc['argv']]
        assert c['label']==f'{i:02d}-'+pc['label'] and c['argv']==expanded and c['cwd']==str(REPO/pc.get('cwd',''))
    py=collections.Counter();rust=collections.Counter();rows=[];labels=set()
    for c in commands:
        label=c['label'];assert label not in labels;labels.add(label)
        assert type(c['exit']) is int and c['exit']==0 and c.get('timeout',False) is False
        assert c['cwd']==str(REPO)
        assert type(c['started_monotonic_ns']) is int and type(c['finished_monotonic_ns']) is int
        assert c['finished_monotonic_ns']>=c['started_monotonic_ns']
        streams=[]
        for stream in ('stdout','stderr'):
            pin=c[stream];path=Path(pin['path']);assert path==directory/(label+'.'+stream)
            streams.append(add(path,pin=pin))
        outcomes=h.outcomes(b'\n'.join(streams).decode('utf-8'))
        assert c['python_test_counts']==[x['methods'] for x in outcomes['python']]
        assert c['rust_test_outcomes']==[] and outcomes['rust']==[]
        for r in outcomes['python']:
            assert r['terminal']=='OK' and r['failed']==r['errors']==r['skipped']==0
            for k in ('methods','passed','failed','errors','skipped'):py[k]+=r[k]
        rows.append({'label':label,'argv':c['argv'],'cwd':c['cwd'],'exit':c['exit'],'outcomes':outcomes})
    expected_py={'core':571,'receiver':11}[name]
    assert py['methods']==py['passed']==m['python_test_methods_reported']==expected_py
    assert m['rust_test_outcomes']=={'passed':0,'failed':0,'ignored':0}
    extra={}
    if name=='core':
        block=add(directory/'w1-current-command-block.sh',pin={'sha256':m['ci_command_block_sha256']})
        source_lines=h.stable(REPO/'scripts/ci/ci_job.sh').decode().splitlines()
        starts=[i for i,line in enumerate(source_lines) if 'w1_contract_out=' in line]
        assert len(starts)==1 and source_lines[starts[0]-1].strip()=='('
        end=next(i for i in range(starts[0],len(source_lines)) if source_lines[i]=='    )')
        expected=('#!/usr/bin/env bash\nset -euo pipefail\n'+'\n'.join(source_lines[starts[0]-1:end+1])+'\n').encode()
        assert expected==block
        suites=[('cancellation-handoff',22),('coordinator-contract',20),('provider-contract',11),('generation-target',13),
            ('owner-cancellation',8),('source-builder',8),('owned-runtime-reader',7),('kaggle-worker-contract',12),
            ('winner-identity',4),('deployment-evidence-binding',12),('deployment-comparison-audit',20),('owned-process-collector',14)]
        for leaf,count in suites:
            b=add(directory/'ci-receipts/w1-postwin-contracts'/(leaf+'.log'),'retained-logs/'+leaf+'.log')
            records=h.outcomes(b.decode())['python'];assert len(records)==1
            assert records[0]['methods']==records[0]['passed']==count and records[0]['terminal']=='OK'
        extra={'current_retained_CI_block_exactly_matches_source':True,'retained_suites_methods':[n for _,n in suites],
            'retained_log_counts_are_crosschecks_not_additional_executions':True,'staged32_included':False,'full_History_workload_executed':False}
    else:
        binding=h.load(add(ROOT/'receiver-launch-binding.json','provenance/receiver-launch-binding.json',{'sha256':'4c8cd536ff93021db9cd64ce5750903dd33173cc642f02ce6bb41dd618e00e61'}))
        add(TOOLS/'launch_receiver.py','provenance/launch_receiver.py',{'sha256':'d05c7dd4e5a04be9fc74b7ace62c64083762c8647e83170be1c9312af5cd74ea'})
        native_pin=p['native_build_manifest']
        assert native_pin['sha256']=='0fcf604c56d415907fc721f9262d7b6a843b1db49cd62246d706ccf8d319f310'
        native=h.load(add(Path(native_pin['path']),'provenance/native-manifest.json',native_pin))
        assert native['source']==SOURCE and native['qualification_complete'] is True and len(native['commands'])==10
        assert binding['source_commit']==SOURCE['commit'] and binding['source_tree']==SOURCE['tree']
        assert binding['native_manifest_sha256']==native_pin['sha256'] and binding['plan_sha256']==m['plan_sha256']
        actual_native_map={}
        for c in native['commands']:
            for stream in ('stdout','stderr'):
                pin=c[stream];b=h.stable(pin['path']);assert len(b)==pin['bytes'] and h.sha(b)==pin['sha256']
                actual_native_map[pin['path']]=h.sha(b)
        assert len(actual_native_map)==20 and binding['actual_native_logs_checked']==actual_native_map
        verifier=native['binaries']['verifier']['file'];argv=commands[2]['argv']
        assert argv[argv.index('--verifier')+1]==verifier['path']
        assert argv[argv.index('--verifier-sha256')+1]==verifier['sha256']==binding['verifier_sha256']
        prior=Path('/home/qian-qi/work/chain-w1-c8-adversarial-backend-native-20261108-ec265b-02/native')
        pm=h.load(add(prior/'manifest.json','provenance/independent-native-review-manifest.json',{'sha256':'33df73464a74152d159cd590bac63e4e1a5470dd6891b1147918e1611ae9c675'}))
        ps=h.load(add(prior/'summary.json','provenance/independent-native-review-summary.json',{'sha256':'180dcfcfb57e3c8f2decd381a9d75b3697b8eab1065e330ac7855a31c2db041b'}))
        v=ps['provenance']['binary_bindings']['verifier']
        assert ps['source']==SOURCE and ps['original_manifest_sha256']==native_pin['sha256'] and v['independently_rehashed'] is True
        assert {k:v[k] for k in ('path','bytes','sha256')}==verifier
        control=h.load(add(directory/'real-receiver-controls/summary.json','real-receiver-controls/summary.json',{'sha256':'ce59188533940f3fea8deb856652e277a7e5121919c403beca0c7e3ced137ecd'}))
        assert control['tests_run']==11 and control['failures']==control['errors']==control['skipped']==0
        assert control['result']=='PASS' and control['fresh_proof_generations']==0 and control['actual_complete_receipt_used'] is True
        assert control['verifier_sha256']==verifier['sha256']
        extra={'native_launch_binding_and_20_original_logs_rechecked':True,'verifier_hash_bound_to_completed_independent_native_review':True,
            'verifier_elf_reread_by_this_component_audit':False,'actual_original_Nov5_receipt_used':True,
            'receipt_sha256':control['receipt_sha256'],'new_receipts_generated':0,'winning_W1_Node_admission_established':False}
    terminal=inputs['terminals'][name]
    assert terminal['state']=='succeeded' and type(terminal['exit_code']) is int and terminal['exit_code']==0
    assert terminal['output_complete'] is True and terminal['output_durable'] is True and terminal['timed_out'] is False
    assert not terminal['automatic_retry'] and not terminal['cancelled'] and not any(terminal['log_truncated'].values())
    b=h.dump(terminal);raw['durable-job-terminal.json']=b;index.append({'archive_member':'durable-job-terminal.json',
        'original_path':'authoritative h_process_status readback','bytes':len(b),'sha256':h.sha(b)})
    summary={'schema':'TRNM-W1-C8-INDEPENDENT-COMPONENT-REVIEW1','component':name,'source':SOURCE,
        'original_manifest_sha256':spec['sha256'],'durable_job_id':terminal['job_id'],'actual_command_count':len(commands),
        'python':dict(py),'rust':dict(rust),'command_reviews':rows,'provenance':extra,
        'all_bound_outputs_match':True,'source_guards_before_after_exact_equal':True,
        'scope':'Exact C8 head source only, not a current prospective-merge event qualification.',
        'audit_reran_tests':False,'audit_reran_source_guard':False,'audit_started_operation':False,
        'new_complete_proofs':0,'full_source_qualification_aggregate_claimed':False}
    result=h.finish_package(dest,raw,index,summary)
    print(json.dumps({**result,'commands':len(commands),'python_passed':py['passed']}),flush=True)
    return summary,result

inputs_bytes=h.stable(Path(sys.argv[1]));inputs=h.load(inputs_bytes);assert inputs['source']==SOURCE
DEST.mkdir();results=[];receipts=[]
for spec in inputs['manifests']:
    result,receipt=audit(spec,inputs);results.append(result);receipts.append(receipt)
assert {r['component'] for r in results}=={'core','receiver'}
total={'commands':sum(r['actual_command_count'] for r in results),'python_passed':sum(r['python']['passed'] for r in results),
    'rust_passed':0,'rust_ignored':0}
assert total=={'commands':24,'python_passed':582,'rust_passed':0,'rust_ignored':0}
h.write(DEST/'audit-inputs.json',inputs_bytes);h.write(DEST/'audit-driver.py',h.stable(Path(__file__)))
h.write(DEST/'audit-helper.py',h.stable(HELPER))
h.write(DEST/'completed-components.json',h.dump({'schema':'TRNM-W1-C8-COMPLETED-COMPONENTS1','source':SOURCE,
    'components':receipts,'counts':total,'ordinary_passes':582,'full_source_qualification_aggregate_claimed':False,
    'pending_components':['owner','historical-regressions','history-local-compile-list','staged32'],
    'separately_audited_components':['backend','native'],'new_complete_proofs':0}))
print(json.dumps({'complete':True,'out':str(DEST),'counts':total}),flush=True)
