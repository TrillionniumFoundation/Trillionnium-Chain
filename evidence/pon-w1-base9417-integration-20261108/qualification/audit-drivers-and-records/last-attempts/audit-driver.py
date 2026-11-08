#!/usr/bin/env python3
"""Read-only audit of C8 History compile/list and both declared staged attempts."""
import collections,hashlib,importlib.util,json,re,sys
from pathlib import Path

HELPER=Path('/home/qian-qi/work/chain-w1-c8-audit-backend-native-v2-20261108-ec265b.py')
assert hashlib.sha256(HELPER.read_bytes()).hexdigest()=='3aece36c2ea23e0e74f85197d224cb6ff5bc43c2ced5fe775bac59b8b5292047'
hs=importlib.util.spec_from_file_location('c8_audit_helpers',HELPER)
h=importlib.util.module_from_spec(hs);hs.loader.exec_module(h)
REPO=h.REPO;ROOT=h.ROOT;TOOLS=h.TOOLS;SOURCE=h.SOURCE
DEST=Path('/home/qian-qi/work/chain-w1-c8-adversarial-last-attempts-20261108-ec265b-01')
SOURCE_SHA='ae4700561bdd1dd273af73d36ca712162d430097daa9d1c3147704c9fe07083c'
DRIVER_SHA='d3c6953430a8efce70396eac88c891aa91501633013c09d5018f0b00e9fb7d1f'
STAGED_PLAN_SHA='af2a4739fed7e449f80cffb44b237b3a36015b674174a990c40f017e7b812512'
HISTORY_NAME='actual_v3_long_chain_public_full_sync_reopen_and_corrupt_index_refusal'
HISTORY_ELF='/home/qian-qi/work/chain-w1-base9417-owner-target-20261108-ec265b/release/deps/history_stage_diagnostic-9b826b863c9887cc'
KNOWN_MANIFESTS={
    'core':'ed8cd6e6d6e2772ec0bbfc97181581df53e2d116d0c76823f3a68e90defe3daf',
    'owner':'6d9013a9ee10badb278215ac1ac81243ada13cd5c279cbc3833250cc50c63bef',
    'receiver':'6cefe7af75dc4f075b26bb1f8ac77693769f16ce4a31173708399f334ebda29b',
    'backend':'a3d530e67e3fd916f3c5e906ba0b851c00c3393cef0173db443d644109e1a47d',
    'native':'0fcf604c56d415907fc721f9262d7b6a843b1db49cd62246d706ccf8d319f310',
    'historical-regressions':'eef45c33e9aae4650c70fcaefc174841e6f75cd8c018139705d459e1fc71c1e6',
    'history-local':'b39888daf3d2223c6600a693f663ca213698dffd6d9854ee887afd36af741738'}

def terminal(b,job,success):
    t=h.load(b)
    assert t['job_id']==job and t['state']==('succeeded' if success else 'failed')
    assert type(t['exit_code']) is int and t['exit_code']==(0 if success else 1)
    assert t['output_complete'] is True and t['output_durable'] is True and t['timed_out'] is False
    assert t['automatic_retry'] is False and t['cancelled'] is False and not any(t['log_truncated'].values())
    return t

def audit(spec,inputs):
    name=spec['component'];assert name in ('history-local','staged-original','staged-repeat')
    directory=Path(spec['path']).parent;dest=DEST/name;dest.mkdir()
    raw={};index=[]
    def raw_add(rel,b,origin):
        assert rel not in raw
        raw[rel]=b;index.append({'archive_member':rel,'original_path':str(origin),'bytes':len(b),'sha256':h.sha(b)})
        return b
    def add(path,rel=None,pin=None):
        path=Path(path);b=h.stable(path)
        if pin:
            assert h.sha(b)==pin['sha256'],str(path)
            if 'bytes' in pin:assert len(b)==pin['bytes']
        return raw_add(rel or path.name,b,path)
    m=h.load(add(directory/'manifest.json',pin=spec))
    success=spec['expected_qualification_complete'];assert type(success) is bool and m['qualification_complete'] is success
    assert m['repo']==str(REPO) and {'commit':m['source_commit'],'tree':m['source_tree']}==SOURCE
    assert m['fresh_proof_generations']==0
    assert all(m[x] is False for x in ('production_qualified','security_qualified','original_business_budget_qualified','resource_billing_complete','payment_qualified'))
    before=add(directory/'source-before.json',pin={'sha256':SOURCE_SHA})
    assert add(directory/'source-after.json',pin={'sha256':SOURCE_SHA})==before
    guard=h.load(before)
    assert guard['kind']=='head' and guard['candidate']==guard['tested_commit']==SOURCE['commit']
    assert guard['tested_tree']==SOURCE['tree'] and guard['base'] is None and guard['prospective_merge'] is None
    assert guard['tracked_worktree_verified'] is True and guard['tests_executed_by_identity_check'] is False
    plan_name='history-local' if name=='history-local' else 'staged'
    p=h.load(add(TOOLS/(plan_name+'-plan.json'),'provenance/plan.json',{'sha256':m['plan_sha256']}))
    assert p['source_commit']==SOURCE['commit'] and p['source_tree']==SOURCE['tree']
    assert m['driver_sha256']==DRIVER_SHA and p['fresh_cargo_target'] is False
    add(TOOLS/'qualify_source.py','provenance/qualify_source.py',{'sha256':DRIVER_SHA})
    commands=m['commands'];count=5 if name=='history-local' else 4
    assert len(commands)==m['actual_command_count']==p['declared_command_count']==count
    assert len(p['commands'])+3==count
    assert commands[0]['label']=='00-preflight' and commands[0]['argv']==['bash','scripts/project-preflight.sh','--dev']
    expected_guard=['python3','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',SOURCE['commit'],'--output']
    assert commands[1]['label']=='01-source-before' and commands[1]['argv']==expected_guard+[str(directory/'source-before.json')]
    assert commands[-1]['label']=='99-source-after' and commands[-1]['argv']==expected_guard+[str(directory/'source-after.json')]
    for i,(pc,c) in enumerate(zip(p['commands'],commands[2:-1]),2):
        expanded=[s.replace('@REPO@',str(REPO)).replace('@OUT@',str(directory)).replace('@HEAD@',SOURCE['commit']) for s in pc['argv']]
        assert c['label']==f'{i:02d}-'+pc['label'] and c['argv']==expanded and c['cwd']==str(REPO/pc.get('cwd',''))
    py=collections.Counter();rows=[];labels=set();last_finished=-1
    for c in commands:
        label=c['label'];assert label not in labels;labels.add(label)
        expected_exit=1 if not success and label=='02-w1-retained-staged-tests' else 0
        assert type(c['exit']) is int and c['exit']==expected_exit and c.get('timeout',False) is False
        assert c['cwd']==str(REPO)
        assert type(c['started_monotonic_ns']) is int and type(c['finished_monotonic_ns']) is int
        assert c['finished_monotonic_ns']>=c['started_monotonic_ns']>=last_finished
        last_finished=c['finished_monotonic_ns'];streams=[]
        for stream in ('stdout','stderr'):
            pin=c[stream];path=Path(pin['path']);assert path==directory/(label+'.'+stream)
            streams.append(add(path,pin=pin))
        text=b'\n'.join(streams).decode('utf-8');result=h.outcomes(text)
        assert c['python_test_counts']==[r['methods'] for r in result['python']]
        assert c['rust_test_outcomes']==[] and result['rust']==[]
        for r in result['python']:
            assert r['errors']==r['skipped']==0
            assert (r['terminal']=='OK') is success
            for k in ('methods','passed','failed','errors','skipped'):py[k]+=r[k]
        if name!='history-local' and label=='02-w1-retained-staged-tests':
            named=re.findall(r'^test_[^\n]+\.\.\. (ok|FAIL|ERROR|skipped[^\n]*)$',text,re.M)
            assert len(named)==32 and named.count('ok')==py['passed'] and named.count('FAIL')==py['failed']
        rows.append({'label':label,'argv':c['argv'],'cwd':c['cwd'],'exit':c['exit'],'outcomes':result})
    expected=spec['expected_python']
    assert {k:py[k] for k in ('methods','passed','failed','errors','skipped')}==expected
    assert py['methods']==m['python_test_methods_reported']==(0 if name=='history-local' else 32)
    assert m['rust_test_outcomes']=={'passed':0,'failed':0,'ignored':0}
    extra={}
    if name=='history-local':
        assert spec['sha256']==KNOWN_MANIFESTS[name] and success
        assert p['full_history_executed'] is False and p['declared_test_passes']==0
        assert m['fresh_cargo_target'] is False and m['cargo_target']=='/home/qian-qi/work/chain-w1-base9417-owner-target-20261108-ec265b'
        add(TOOLS/'history_compile_list.py','provenance/history_compile_list.py',{'sha256':'434fddeea24ccb11a5975755eef092458c54b526673ef829756e1c727376a563'})
        artifact=h.load(add(directory/'history-artifact-and-list.json',pin={'sha256':'918a5de9baf6514ea5a87c3bbb812467bbb465f48d9e6fceb53ab3f89a808e40'}))
        assert artifact['schema']=='TRNM-W1-C8-HISTORY-COMPILE-AND-LIST1' and artifact['source_commit']==SOURCE['commit']
        assert artifact['cargo_log_sha256']==h.sha(raw['02-history-release-compile.stdout'])=='7fc8a474de30683169e56063fe9f5c0af00f7f3b952130daac308602fbd1ff9f'
        assert artifact['full_history_executed'] is False and artifact['test_passes_claimed']==0 and artifact['listed_test_count']==1
        assert artifact['production_qualified'] is False and artifact['resource_qualified'] is False
        assert artifact['list_argv']==[HISTORY_ELF,HISTORY_NAME,'--exact','--ignored','--list']
        assert type(artifact['list_exit']) is int and artifact['list_exit']==0
        assert artifact['elf']==HISTORY_ELF and artifact['elf_bytes']==9910608 and artifact['elf_sha256']=='cc252a4f811e981a90fa3f8adb8f59b2df20249c32246e8a365928e04e3ca9fd'
        astdout=add(directory/'history-artifact-and-list.list.stdout',pin={'sha256':artifact['list_stdout_sha256']})
        astderr=add(directory/'history-artifact-and-list.list.stderr',pin={'sha256':artifact['list_stderr_sha256']})
        assert astdout.decode().strip()==HISTORY_NAME+': test\n\n1 test, 0 benchmarks' and astderr==b''
        cargo=[h.load(x) for x in raw['02-history-release-compile.stdout'].splitlines() if x]
        assert any(x.get('reason')=='build-finished' and x.get('success') is True for x in cargo)
        arts=[x for x in cargo if x.get('reason')=='compiler-artifact' and x.get('target',{}).get('name')=='history_stage_diagnostic' and x.get('executable')]
        assert len(arts)==1 and arts[0]==artifact['compiler_artifact'] and arts[0]['executable']==HISTORY_ELF
        art=arts[0]
        assert art['target']['src_path']==str(REPO/'trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs')
        assert art['manifest_path']==str(REPO/'trillionnium/crates/trnm-pon-node/Cargo.toml')
        assert art['target']['kind']==['test'] and art['profile']['test'] is True and str(art['profile']['opt_level'])=='3'
        extra={'release_compile_and_exact_ignored_entry_listing_only':True,'listed_ignored_entries':1,
            'listed_entry_counted_as_executed_or_ignored_method':False,'full_History_workload_executed':False,
            'full_4105_block_History_budget_qualified':False,'fresh_target':False,'unique_actual_C8_Cargo_artifact_reparsed':True,
            'history_elf':{'path':HISTORY_ELF,'bytes':artifact['elf_bytes'],'sha256':artifact['elf_sha256']},
            'elf_hash_recomputed_by_original_compile_list_helper':True,'elf_rehashed_by_this_audit':False,'elf_published':False}
    else:
        assert m['plan_sha256']==STAGED_PLAN_SHA and commands[2]['argv']==['python3','-m','unittest','discover','-s','scripts/ci','-p','test_w1_staged_observer.py','-v']
        for record in spec['provenance_files']:
            add(record['path'],'provenance/'+record['leaf'],record)
        if name=='staged-original':
            assert not success and py['passed']==31 and py['failed']==1
            assert spec['sha256']=='a6e8363bfa6a157fc1b414b64e4af59bb11211166fe06f1b0962460253e89e25'
            assert h.sha(raw['02-w1-retained-staged-tests.stderr'])=='6523776cafbcfcb998f508af0a9a890ef1714adfc5a06aadd59a952baf4bca4c'
            binding=h.load(raw['provenance/staged-launch-binding.json'])
            inp=h.load(raw['provenance/staged-launch-input.json'])
            assert binding['schema']=='TRNM-W1-C8-STAGED-LAUNCH-BINDING2'
            assert binding['source_commit']==SOURCE['commit'] and binding['source_tree']==SOURCE['tree']
            assert binding['input_sha256']==h.sha(raw['provenance/staged-launch-input.json'])
            assert binding['unchanged_original_test_parameters'] is True and binding['declared_test_methods']==32
            assert binding['new_operation_not_created'] is True and binding['new_operation_deadline_not_selected'] is True
            assert binding['observed_monotonic_ns']<=commands[0]['started_monotonic_ns']
            known=binding['known_current_components'];assert len(known)==7 and {x['component'] for x in known}==set(KNOWN_MANIFESTS)
            for x in known:
                assert x['manifest_sha256']==KNOWN_MANIFESTS[x['component']]
                entry=inp['components'][x['component']]
                assert x['job_id']==entry['job_id'] and x['authoritative_terminal']==entry['authoritative_terminal']
                t=x['authoritative_terminal'];assert t['state']=='succeeded' and t['exit_code']==0 and t['output_complete'] is True and t['output_durable'] is True
                assert x['current_unit']['ActiveState']=='inactive' and x['current_unit']['MainPID']=='0'
                assert x['current_unit']['LoadState']=='not-found' and x['current_unit']['ControlGroup']=='' and x['current_cgroup'] is None
            extra={'failure_branch':'DEADLINE_EXHAUSTED_BEFORE_SPAWN','failed_method':'ProcessLifecycleTests.test_ignored_sigterm_escalates_and_output_overflow_remains_failure',
                'SIGKILL_cleanup_subcase_covered_by_this_attempt':False,'subsequent_OUTPUT_LIMIT_subcase_executed':False,
                'first_attempt_qualification_complete':False,'temporary_per_control_artifact_in_retained_manifest':False,
                'specific_IO_CPU_or_host_cause_established':False,'known_prior_units_observed_inactive':7,
                'whole_host_idle_established':False,'effective_omitted_termination_grace_default_seconds':5,
                'patched_global_point15_does_not_change_definition_time_default':True}
        else:
            binding=h.load(raw['provenance/staged-repeat-launch-binding.json'])
            declaration=h.load(raw['provenance/staged-one-repeat-declaration.json'])
            inp=h.load(raw['provenance/staged-launch-input.json'])
            assert binding['schema']=='TRNM-W1-C8-STAGED-DECLARED-REPEAT-LAUNCH1'
            assert binding['source_commit']==declaration['source_commit']==SOURCE['commit']
            assert binding['source_tree']==declaration['source_tree']==SOURCE['tree']
            assert binding['input_sha256']==h.sha(raw['provenance/staged-launch-input.json'])=='10d7e0f459ed7ec6b400e8e141c4d59f8b4889c9fcd127bbebaf60c9b6c9ec9f'
            assert binding['repeat_declaration_sha256']==h.sha(raw['provenance/staged-one-repeat-declaration.json'])=='7b51a7dee784b9375eb1c1dcc9b8f54869538810c763ee1514208ba42912ce95'
            assert declaration['maximum_additional_attempts']==1 and declaration['stop_after_second_failure'] is True
            assert declaration['test_parameters_changed'] is False and declaration['test_argv_changed'] is False
            assert declaration['source_changed'] is False and declaration['short_timeout_seconds']==0.2
            assert declaration['test_plan_sha256']==STAGED_PLAN_SHA and declaration['driver_sha256']==DRIVER_SHA
            assert declaration['repeat_out']==str(directory) and declaration['old_failure_retained'] is True
            assert declaration['aggregate_must_include_both_attempts'] is True
            assert declaration['environment_overrides']=={} and declaration['priority_changed'] is False and declaration['added_cpu_or_memory_limits'] is False
            assert binding['original_failed_attempt']==declaration['original']
            original=declaration['original']
            assert original['manifest_sha256']=='a6e8363bfa6a157fc1b414b64e4af59bb11211166fe06f1b0962460253e89e25'
            assert original['job_id']=='1a1ba8f182e-12894-1b97' and original['qualification_complete'] is False
            assert (original['ran'],original['passed'],original['failed'])==(32,31,1)
            assert original['terminal']==h.load(inputs['terminals']['staged-original'].encode())
            assert binding['all_first_attempts_passed'] is False and binding['repeat_is_causal_explanation'] is False
            assert binding['new_operation_not_created'] is True and binding['new_operation_deadline_not_selected'] is True
            assert binding['unchanged_original_test_parameters'] is True and binding['declared_test_methods']==32
            assert binding['observed_monotonic_ns']<=commands[0]['started_monotonic_ns']
            argv=binding['argv']
            assert argv[1:]==[str(TOOLS/'qualify_source.py'),'--repo',str(REPO),'--head',SOURCE['commit'],'--out',str(directory),'--plan',str(TOOLS/'staged-plan.json')]
            first_review=h.load(h.stable(DEST/'staged-original/summary.json'))
            assert first_review['command_reviews'][2]['argv']==commands[2]['argv'] and first_review['command_reviews'][2]['cwd']==commands[2]['cwd']
            known=binding['known_current_components'];assert len(known)==7 and {x['component'] for x in known}==set(KNOWN_MANIFESTS)
            for x in known:
                assert x['manifest_sha256']==KNOWN_MANIFESTS[x['component']]
                entry=inp['components'][x['component']]
                assert x['job_id']==entry['job_id'] and x['authoritative_terminal']==entry['authoritative_terminal']
                assert x['current_unit']['LoadState']=='not-found' and x['current_unit']['ActiveState']=='inactive'
                assert x['current_unit']['MainPID']=='0' and x['current_unit']['ControlGroup']=='' and x['current_cgroup'] is None
            failed_unit=binding['original_failed_unit']
            assert failed_unit['fields']=={'MainPID':'0','ControlGroup':'','LoadState':'not-found','ActiveState':'inactive','SubState':'dead'}
            assert failed_unit['cgroup'] is None
            extra={'one_predeclared_repeat':True,'original_parameters_and_source_preserved':True,
                'original_failed_attempt_relabelled':False,'repeat_is_additional_execution':True,
                'first_failure_cause_established_by_repeat':False,'stable_timing_or_whole_host_idle_established':False,
                'effective_omitted_termination_grace_default_seconds':5,'new_operation_created':False}
    tb=inputs['terminals'][name].encode();t=terminal(tb,spec['job_id'],success)
    raw_add('durable-job-terminal.json',tb,'authoritative h_process_status raw text')
    summary={'schema':'TRNM-W1-C8-INDEPENDENT-COMPONENT-REVIEW1','component':name,'source':SOURCE,
        'original_manifest_sha256':spec['sha256'],'durable_job_id':t['job_id'],'actual_command_count':len(commands),
        'qualification_complete':success,'python':dict(py),'rust':{},'command_reviews':rows,'provenance':extra,
        'all_bound_outputs_match':True,'source_guards_before_after_exact_equal':True,
        'scope':'Exact C8 head source and explicit attempt only; no current prospective-merge event qualification.',
        'audit_reran_tests':False,'audit_reran_source_guard':False,'audit_started_operation':False,
        'new_complete_proofs':0,'full_source_qualification_aggregate_claimed':False}
    receipt=h.finish_package(dest,raw,index,summary)
    print(json.dumps({**receipt,'commands':len(commands),'qualification_complete':success,'python':dict(py)}),flush=True)
    return summary,receipt

inputs_bytes=h.stable(Path(sys.argv[1]));inputs=h.load(inputs_bytes);assert inputs['source']==SOURCE
assert [x['component'] for x in inputs['manifests']]==['history-local','staged-original','staged-repeat']
DEST.mkdir();results=[];receipts=[]
for spec in inputs['manifests']:
    result,receipt=audit(spec,inputs);results.append(result);receipts.append(receipt)
total={'commands':sum(r['actual_command_count'] for r in results),'python_methods':sum(r['python'].get('methods',0) for r in results),
    'python_passed':sum(r['python'].get('passed',0) for r in results),'python_failed':sum(r['python'].get('failed',0) for r in results),'rust_passed':0,'rust_ignored':0}
assert total==inputs['expected_totals']
h.write(DEST/'audit-inputs.json',inputs_bytes);h.write(DEST/'audit-driver.py',h.stable(Path(__file__)))
h.write(DEST/'audit-helper.py',h.stable(HELPER))
h.write(DEST/'completed-components.json',h.dump({'schema':'TRNM-W1-C8-COMPLETED-ATTEMPT-REVIEWS1','source':SOURCE,
    'components':receipts,'counts':total,'original_failure_preserved':True,'full_source_qualification_aggregate_claimed':False,
    'separately_audited_components':['backend','native','core','receiver','owner','historical-regressions'],'new_complete_proofs':0}))
print(json.dumps({'complete':True,'out':str(DEST),'counts':total}),flush=True)
