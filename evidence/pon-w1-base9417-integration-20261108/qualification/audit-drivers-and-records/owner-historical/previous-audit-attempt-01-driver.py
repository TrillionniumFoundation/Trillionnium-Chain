#!/usr/bin/env python3
"""Audit C8 owner02 and historical module raw records; execute no tests or guards."""
import collections,hashlib,importlib.util,json,sys
from pathlib import Path

HELPER=Path('/home/qian-qi/work/chain-w1-c8-audit-backend-native-v2-20261108-ec265b.py')
assert hashlib.sha256(HELPER.read_bytes()).hexdigest()=='3aece36c2ea23e0e74f85197d224cb6ff5bc43c2ced5fe775bac59b8b5292047'
hs=importlib.util.spec_from_file_location('c8_audit_helpers',HELPER)
h=importlib.util.module_from_spec(hs);hs.loader.exec_module(h)
REPO=h.REPO;ROOT=h.ROOT;TOOLS=h.TOOLS;MTOOLS=h.MTOOLS;SOURCE=h.SOURCE
TARGET=Path('/home/qian-qi/work/chain-w1-base9417-owner-target-20261108-ec265b')
DEST=Path('/home/qian-qi/work/chain-w1-c8-adversarial-owner-historical-20261108-ec265b-01')
SOURCE_SHA='ae4700561bdd1dd273af73d36ca712162d430097daa9d1c3147704c9fe07083c'
DRIVER_SHA='d3c6953430a8efce70396eac88c891aa91501633013c09d5018f0b00e9fb7d1f'
CACHE_BASIS='Independent copy of completed C7 owner+History target; original empty creation is historical only; registry/toolchain reused; no cleanroom claim'
OWNER_MANIFEST_SHA='6d9013a9ee10badb278215ac1ac81243ada13cd5c279cbc3833250cc50c63bef'
IMPORT_SHA='d7ce0440c68a30cd6a00c5c1e964a1a360f27767848bdca63667991e3f7d2619'
OWNER_ELF={'path':str(TARGET/'debug/deps/trnm_pon_node-2c98293081e75af8'),'bytes':467190280,'sha256':'1cc1db569c0d21f27aabc3ddbef4730ce11a6481c026b35ed69460c09028d456'}

def terminal_checked(b,job):
    t=h.load(b)
    assert t['job_id']==job and t['state']=='succeeded'
    assert type(t['exit_code']) is int and t['exit_code']==0
    assert t['output_complete'] is True and t['output_durable'] is True
    assert t['timed_out'] is False and t['cancelled'] is False and t['automatic_retry'] is False
    assert not any(t['log_truncated'].values()) and all(t['log_synced'].values())
    assert all(v is None for v in t['log_errors'].values())
    return t

def audit(spec,inputs,prior_owner=None):
    name=spec['component'];assert name in ('owner','historical-regressions')
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
    assert m['qualification_complete'] is True and m['repo']==str(REPO)
    assert {'commit':m['source_commit'],'tree':m['source_tree']}==SOURCE
    assert m['fresh_proof_generations']==0 and m['cargo_target']==str(TARGET)
    assert m['fresh_cargo_target'] is False and m['independent_reproducible_build_established'] is False
    assert all(m[x] is False for x in ('production_qualified','security_qualified','original_business_budget_qualified','resource_billing_complete','payment_qualified'))
    before=add(directory/'source-before.json',pin={'sha256':SOURCE_SHA})
    assert add(directory/'source-after.json',pin={'sha256':SOURCE_SHA})==before
    guard=h.load(before)
    assert guard['kind']=='head' and guard['candidate']==guard['tested_commit']==SOURCE['commit']
    assert guard['tested_tree']==SOURCE['tree'] and guard['base'] is None and guard['prospective_merge'] is None
    assert guard['tracked_worktree_verified'] is True and guard['tests_executed_by_identity_check'] is False
    p=h.load(add(TOOLS/(name+'-plan.json'),'provenance/plan.json',{'sha256':m['plan_sha256']}))
    assert p['source_commit']==SOURCE['commit'] and p['source_tree']==SOURCE['tree']
    assert m['driver_sha256']==DRIVER_SHA and p['fresh_cargo_target'] is False
    add(TOOLS/'qualify_source.py','provenance/qualify_source.py',{'sha256':DRIVER_SHA})
    commands=m['commands'];n={'owner':19,'historical-regressions':4}[name]
    assert len(commands)==m['actual_command_count']==p['declared_command_count']==n
    assert len(p['commands'])+3==n
    assert commands[0]['label']=='00-preflight' and commands[0]['argv']==['bash','scripts/project-preflight.sh','--dev']
    expected_guard=['python3','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',SOURCE['commit'],'--output']
    assert commands[1]['label']=='01-source-before' and commands[1]['argv']==expected_guard+[str(directory/'source-before.json')]
    assert commands[-1]['label']=='99-source-after' and commands[-1]['argv']==expected_guard+[str(directory/'source-after.json')]
    for i,(pc,c) in enumerate(zip(p['commands'],commands[2:-1]),2):
        expanded=[s.replace('@REPO@',str(REPO)).replace('@OUT@',str(directory)).replace('@HEAD@',SOURCE['commit']) for s in pc['argv']]
        assert c['label']==f'{i:02d}-'+pc['label'] and c['argv']==expanded and c['cwd']==str(REPO/pc.get('cwd',''))
    py=collections.Counter();rust=collections.Counter();rows=[];labels=set();last_finished=-1
    for c in commands:
        label=c['label'];assert label not in labels;labels.add(label)
        assert type(c['exit']) is int and c['exit']==0 and c.get('timeout',False) is False
        assert c['cwd'] in (str(REPO),str(REPO/'trillionnium'))
        assert type(c['started_monotonic_ns']) is int and type(c['finished_monotonic_ns']) is int
        assert c['finished_monotonic_ns']>=c['started_monotonic_ns']>=last_finished
        last_finished=c['finished_monotonic_ns'];streams=[]
        for stream in ('stdout','stderr'):
            pin=c[stream];path=Path(pin['path']);assert path==directory/(label+'.'+stream)
            streams.append(add(path,pin=pin))
        result=h.outcomes(b'\n'.join(streams).decode('utf-8'))
        assert c['python_test_counts']==[] and result['python']==[]
        assert c['rust_test_outcomes']==[{k:r[k] for k in ('passed','failed','ignored')} for r in result['rust']]
        for r in result['rust']:
            assert r['terminal']=='ok' and r['failed']==r['measured']==0
            for k in ('passed','failed','ignored'):rust[k]+=r[k]
        rows.append({'label':label,'argv':c['argv'],'cwd':c['cwd'],'exit':c['exit'],'outcomes':result})
    expected_rust={'owner':{'passed':37,'failed':0,'ignored':4},'historical-regressions':{'passed':10,'failed':0,'ignored':0}}[name]
    assert dict(rust)==m['rust_test_outcomes']==expected_rust and m['python_test_methods_reported']==0
    extra={}
    if name=='owner':
        assert spec['sha256']==OWNER_MANIFEST_SHA and m['cache_basis']==p['cache_basis']==CACHE_BASIS
        imp=h.load(add(MTOOLS/'owner-import-c8-01/manifest.json','strict-import/manifest.json',{'sha256':IMPORT_SHA}))
        assert imp['source']==SOURCE and imp['qualification_complete'] is True
        assert imp['actual_command_count']==19 and imp['rust_test_outcomes']==expected_rust
        assert imp['commands']==commands and imp['owner_binary']==OWNER_ELF
        assert imp['raw_log_files_verified']==imp['raw_log_files_copied']==38
        assert imp['fresh_cargo_target'] is False and imp['independent_cleanroom_build'] is False
        assert all(imp[k] is False for k in ('new_tests_or_cargo_executed_by_import','node_executed_by_import','operation_created','deadline_selected'))
        assert imp['original_qualification_manifest']=={k:spec[k] for k in ('path','bytes','sha256')}
        binding=h.load(add(ROOT/'owner-launch-binding-02.json','provenance/owner-launch-binding-02.json',imp['owner_launch_binding']))
        assert binding['source_commit']==SOURCE['commit'] and binding['source_tree']==SOURCE['tree']
        assert binding['target']==str(TARGET) and binding['out']==str(directory) and binding['fresh_cargo_target'] is False
        assert binding['initial_regular_files_checked']==3065 and binding['source_inode_sharing']==binding['destination_hardlinks']==binding['destination_duplicate_inodes']==0
        assert binding['new_operation_created'] is False and binding['deadline_selected'] is False
        copy=h.load(add(binding['copy_record']['path'],'provenance/cache-copy.json',binding['copy_record']))
        provenance=h.load(add(binding['copy_provenance']['path'],'provenance/cache-provenance.json',binding['copy_provenance']))
        assert copy['fresh_cargo_target'] is False and copy['independent_cleanroom_build'] is False and copy['copy_complete'] is True
        assert type(copy['copy_exit_code']) is int and copy['copy_exit_code']==0
        assert copy['source_target']!=copy['destination']==str(TARGET)
        assert copy['source_target_written'] is False and copy['source_regular_metadata_unchanged'] is True
        assert copy['shared_source_inode_count']==copy['destination_hardlink_count']==copy['destination_duplicate_inode_count']==0
        assert copy['source_stat_inventory_before_sha256']==copy['source_stat_inventory_after_sha256']
        assert copy['source_binaries_before']==copy['source_binaries_after']
        add(binding['launcher']['path'],'provenance/launcher-v2.py',binding['launcher'])
        add(imp['adapter']['path'],'strict-import/import-owner-c8-v1.py',imp['adapter'])
        extracted=h.load(add(imp['extracted_binding']['path'],'strict-import/extracted-owner-artifact.json',imp['extracted_binding']))
        assert extracted['owner_executable']==OWNER_ELF and extracted['cargo_artifact']==imp['cargo_artifact']
        assert extracted['source_commit']==SOURCE['commit'] and extracted['source_tree']==SOURCE['tree']
        assert extracted['derived_extraction'] is True and extracted['original_root_owner_artifact_file_claimed'] is False
        artifact_lines=[h.load(line) for line in raw['13-owner-no-run-json.stdout'].splitlines() if line]
        artifacts=[r for r in artifact_lines if r.get('reason')=='compiler-artifact' and r.get('profile',{}).get('test') is True and r.get('target',{}).get('name')=='trnm_pon_node' and r.get('executable')]
        assert len(artifacts)==1 and artifacts[0]==imp['cargo_artifact']
        assert any(r.get('reason')=='build-finished' and r.get('success') is True for r in artifact_lines)
        artifact=artifacts[0]
        assert artifact['manifest_path']==str(REPO/'trillionnium/crates/trnm-pon-node/Cargo.toml')
        assert artifact['target']['src_path']==str(REPO/'trillionnium/crates/trnm-pon-node/src/lib.rs')
        assert artifact['package_id'].startswith('path+file://'+str(REPO/'trillionnium/crates/trnm-pon-node')+'#')
        assert artifact['executable']==OWNER_ELF['path'] and artifact['filenames']==[OWNER_ELF['path']]
        assert artifact['profile']['test'] is True and artifact['profile']['opt_level']=='3'
        for rec in imp['original_files_copied']:
            original=rec['original'];copied=rec['copy']
            assert original['bytes']==copied['bytes'] and original['sha256']==copied['sha256']
            if original['path'] in {x['original_path'] for x in index}:
                b=h.stable(copied['path']);assert len(b)==copied['bytes'] and h.sha(b)==copied['sha256']
        exit_rec=imp['qualification_job_exit'];exit_j=h.load(add(exit_rec['path'],'durable-job/owner-attempt-02-exit.json',exit_rec))
        assert exit_j['job_id']==spec['job_id'] and type(exit_j['exit_code']) is int and exit_j['exit_code']==0
        assert exit_j['timed_out'] is False and exit_j['cancelled'] is False and exit_j['output_complete'] is True and exit_j['output_durable'] is True
        failure=h.load(add(MTOOLS/'owner-launch-validation-failure-01.json','attempt-history/owner-launch-validation-failure-01.json',imp['previous_attempt']['record']))
        assert failure['qualification_commands_executed']==failure['test_methods_executed']==0 and failure['Cargo_or_Node_started'] is False
        assert failure['job_id']=='1a1ba70f3e9-12894-1ab5'
        originals={}
        for f in failure['original_files']:
            b=f['utf8'].encode();assert len(b)==f['bytes'] and h.sha(b)==f['sha256']
            originals[Path(f['path']).name]=b
        assert len(originals)==8 and h.load(originals['exit.json'])['exit_code']==1
        assert b'assert "copied" in plan["cache_basis"].lower()' in originals['stderr.log']
        old=originals['launch-owner-c8.py'].decode().splitlines();new=raw['provenance/launcher-v2.py'].decode().splitlines()
        assert len(old)==len(new) and [i+1 for i,(a,b) in enumerate(zip(old,new)) if a!=b]==[13,14,103]
        assert originals['owner-plan.json']==raw['provenance/plan.json']
        add(MTOOLS/'owner-attempt-02-declaration.json','attempt-history/owner-attempt-02-declaration.json',{'sha256':'a1716926a1348cee61781c2c23e2484fd37945053f05a20b8a4ea86b729110ae'})
        import_terminal_bytes=inputs['terminals']['owner-import'].encode()
        terminal_checked(import_terminal_bytes,'1a1ba85c4c0-12894-1b51')
        raw_add('strict-import/durable-job-terminal.json',import_terminal_bytes,'authoritative h_process_status raw text')
        extra={'copied_C7_cache_provenance_checked':True,'fresh_target':False,'independent_cleanroom_build':False,
            'copy_metadata_regular_files_checked_at_launch':3065,'all_copied_file_content_hashes_claimed':False,
            'exact_original_38_log_hashes_recomputed':True,'owner_executable':OWNER_ELF,
            'owner_elf_hash_recomputed_by_original_strict_import':True,'owner_elf_rehashed_by_this_audit':False,
            'unique_actual_C8_Cargo_artifact_reparsed':True,'import_record_is_derived_not_original_root_artifact':True,
            'import_commands_added_to_qualification_count':0,'previous_predispatch_failure_preserved':True,
            'previous_predispatch_failure_qualification_commands':0,'launcher_v2_changed_line_numbers':[13,14,103],
            'new_historical_module10_included':False,'new_operation_created':False}
    else:
        assert prior_owner and prior_owner['original_manifest_sha256']==OWNER_MANIFEST_SHA
        assert m['cache_basis']=='Reuse completed C8 owner target; committed-source historical arithmetic/cache regression methods only'
        assert commands[2]['argv']==['/home/qian-qi/.cargo/bin/cargo','+1.95.0','test','--locked','--offline','--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node','--lib','store::historical_commitment_tests::','--','--show-output','--test-threads=1']
        names={r['name'] for row in rows for r in row['outcomes']['named_rust']}
        owner_names={r['name'] for row in prior_owner['command_reviews'] for r in row['outcomes']['named_rust']}
        assert len(names)==10 and all(x.startswith('store::historical_commitment_tests::') for x in names)
        assert not names.intersection(owner_names)
        add(DEST/'owner/summary.json','provenance/independent-owner-review.json')
        extra={'original_owner19_contract_preserved':True,'module_methods_distinct_from_owner_legacy_admission_and_reorg_filters':True,
            'counts_are_executions_not_global_unique_methods':True,'reused_C8_owner_target':True,'fresh_target':False,
            'full_History_workload_executed':False,'performance_or_RSS_budget_qualified':False,'new_operation_created':False}
    terminal_bytes=inputs['terminals'][name].encode();terminal=terminal_checked(terminal_bytes,spec['job_id'])
    raw_add('durable-job-terminal.json',terminal_bytes,'authoritative h_process_status raw text')
    summary={'schema':'TRNM-W1-C8-INDEPENDENT-COMPONENT-REVIEW1','component':name,'source':SOURCE,
        'original_manifest_sha256':spec['sha256'],'durable_job_id':terminal['job_id'],'actual_command_count':len(commands),
        'python':dict(py),'rust':dict(rust),'command_reviews':rows,'provenance':extra,
        'all_bound_outputs_match':True,'source_guards_before_after_exact_equal':True,
        'scope':'Exact C8 head source only, not current prospective-merge event qualification.',
        'audit_reran_tests':False,'audit_reran_source_guard':False,'audit_started_operation':False,
        'new_complete_proofs':0,'full_source_qualification_aggregate_claimed':False}
    result=h.finish_package(dest,raw,index,summary)
    print(json.dumps({**result,'commands':len(commands),'rust':dict(rust)}),flush=True)
    return summary,result

inputs_bytes=h.stable(Path(sys.argv[1]));inputs=h.load(inputs_bytes);assert inputs['source']==SOURCE
assert [x['component'] for x in inputs['manifests']]==['owner','historical-regressions']
DEST.mkdir();results=[];receipts=[]
for spec in inputs['manifests']:
    result,receipt=audit(spec,inputs,results[0] if results else None);results.append(result);receipts.append(receipt)
total={'commands':sum(r['actual_command_count'] for r in results),'python_passed':0,
    'rust_passed':sum(r['rust']['passed'] for r in results),'rust_ignored':sum(r['rust']['ignored'] for r in results)}
assert total=={'commands':23,'python_passed':0,'rust_passed':47,'rust_ignored':4}
h.write(DEST/'audit-inputs.json',inputs_bytes);h.write(DEST/'audit-driver.py',h.stable(Path(__file__)))
h.write(DEST/'audit-helper.py',h.stable(HELPER))
h.write(DEST/'completed-components.json',h.dump({'schema':'TRNM-W1-C8-COMPLETED-COMPONENTS1','source':SOURCE,
    'components':receipts,'counts':total,'ordinary_passes':47,'full_source_qualification_aggregate_claimed':False,
    'pending_components':['history-local-compile-list','staged32'],
    'separately_audited_components':['backend','native','core','receiver'],'new_complete_proofs':0}))
print(json.dumps({'complete':True,'out':str(DEST),'counts':total}),flush=True)
