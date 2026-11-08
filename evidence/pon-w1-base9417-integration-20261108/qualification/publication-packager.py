#!/usr/bin/env python3
"""Freeze independently checked C8 qualification history, then copy the owned D6 directory."""
import collections,hashlib,importlib.util,io,json,os,shutil,subprocess,sys,tarfile
from pathlib import Path

HELPER=Path('/home/qian-qi/work/chain-w1-c8-audit-backend-native-v2-20261108-ec265b.py')
assert hashlib.sha256(HELPER.read_bytes()).hexdigest()=='3aece36c2ea23e0e74f85197d224cb6ff5bc43c2ced5fe775bac59b8b5292047'
hs=importlib.util.spec_from_file_location('c8_audit_helpers',HELPER)
h=importlib.util.module_from_spec(hs);hs.loader.exec_module(h)
SOURCE=h.SOURCE
D6=Path('/home/qian-qi/work/chain-w1-c8-attestation-20261108-ec265b')
DEST=D6/'evidence/pon-w1-base9417-integration-20261108/qualification'
OUT=Path('/home/qian-qi/work/chain-w1-c8-qualification-publication-20261108-ec265b-01')
BASE=Path('/home/qian-qi/work')
AUDITS={
 'backend-native':BASE/'chain-w1-c8-adversarial-backend-native-20261108-ec265b-02',
 'core-receiver':BASE/'chain-w1-c8-adversarial-core-receiver-20261108-ec265b-01',
 'owner-historical':BASE/'chain-w1-c8-adversarial-owner-historical-20261108-ec265b-02',
 'last-attempts':BASE/'chain-w1-c8-adversarial-last-attempts-20261108-ec265b-01'}
SPECS=[
 ('backend','backend-native','76ddf549ca569cdc146a5f454d2384783696712cfe7a3b0f51c834abc1c587c6'),
 ('native','backend-native','33df73464a74152d159cd590bac63e4e1a5470dd6891b1147918e1611ae9c675'),
 ('core','core-receiver','83977ffddc3fdcd8875cd10e548dd11f62ce7b2dd5917ba8e2ea00ccd602c9bf'),
 ('owner','owner-historical','1c2dc86659813e9bbb5290b59792facc824c3e548f2d6e7ad2457498227ecd54'),
 ('receiver','core-receiver','3ba6ff7b8966ad64fb1495c36141ffc7a9a7e89cedad2b76c0605eda8e4b88e7'),
 ('historical-regressions','owner-historical','1bc9f12e7c190056ee0850b338c565665c55668ae491dbcf684dcda2f3028ace'),
 ('history-local','last-attempts','766cda79f1867976c570005243bd89a670c2c3e3e0b31644ad44048c1cd2975a'),
 ('staged-original','last-attempts','68e2bb2b215abcaf52c41b11d56f52e2519db4fc383c83fb54f912a85c333898'),
 ('staged-repeat','last-attempts','e43e62ada39c298d2675ea992de0d8cbdd484954c0413537f91d875c26689ae1')]
EXPECTED_COUNTS={
 'backend':(7,0,0,0),'native':(10,4,0,0),'core':(20,571,0,0),'owner':(19,37,0,4),
 'receiver':(4,11,0,0),'historical-regressions':(4,10,0,0),'history-local':(5,0,0,0),
 'staged-original':(4,31,1,0),'staged-repeat':(4,32,0,0)}

def safe(name,b):
    assert not name.startswith('/') and '..' not in Path(name).parts
    assert len(b)<25*1024*1024 and not b.startswith((b'\x7fELF',b'SQLite format 3\0')),name
    assert not any(x in Path(name).parts for x in ('environ','.ssh','.gnupg'))
    if name.endswith('.json'):h.load(b)

def copy_file(src,dst,pin=None):
    src=Path(src);assert not src.is_symlink()
    b=h.stable(src);safe(dst.relative_to(OUT).as_posix(),b)
    if pin:
        assert h.sha(b)==pin['sha256'],str(src)
        if 'bytes' in pin:assert len(b)==pin['bytes']
    h.write(dst,b);assert h.stable(dst)==b
    return b

def read_component(name,group,pin):
    source=AUDITS[group]/name;dest=OUT/'components'/name
    mb=h.stable(source/'manifest.json');assert h.sha(mb)==pin
    m=h.load(mb);assert m['source']==SOURCE and m['component']==name and m['raw_tar_readback_verified'] is True
    expected={f['path'] for f in m['files']}|{'manifest.json'}
    assert expected=={p.name for p in source.iterdir() if p.is_file()} and len(expected)==5
    for f in m['files']:copy_file(source/f['path'],dest/f['path'],f)
    copy_file(source/'manifest.json',dest/'manifest.json',{'sha256':pin})
    derived=h.load(h.stable(dest/'summary.json'));idx=h.load(h.stable(dest/'raw-output-index.json'))
    assert derived['source']==SOURCE and derived['component']==name
    archive_bytes=h.stable(dest/'raw-logs.tar.gz');contents={}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes),mode='r:gz') as tf:
        entries=tf.getmembers();assert len(entries)==m['raw_tar_members']==len(idx)
        assert len({x.name for x in entries})==len(entries)
        byname={x['archive_member']:x for x in idx};assert len(byname)==len(idx)
        for member in entries:
            assert member.isfile() and member.name in byname
            b=tf.extractfile(member).read();safe(member.name,b)
            r=byname[member.name];assert len(b)==r['bytes'] and h.sha(b)==r['sha256']
            contents[member.name]=b
    orig=h.load(contents['manifest.json'])
    assert h.sha(contents['manifest.json'])==derived['original_manifest_sha256']
    assert orig.get('source',{'commit':orig.get('source_commit'),'tree':orig.get('source_tree')})==SOURCE
    assert orig['qualification_complete'] is (name!='staged-original')
    assert orig['repo']==str(h.REPO)
    py=collections.Counter();rust=collections.Counter();expected_negative=0;unexpected_nonzero=0
    command_rows=[]
    for row in orig['commands']:
        streams=[]
        for stream in ('stdout','stderr'):
            member=row['label']+'.'+stream;b=contents[member];record=row[stream]
            assert len(b)==record['bytes'] and h.sha(b)==record['sha256']
            streams.append(b)
            command_stream_index.append({'component_attempt':name,'label':row['label'],'stream':stream,
                'original_path':record['path'],'bytes':len(b),'sha256':h.sha(b),
                'archive':'components/'+name+'/raw-logs.tar.gz','member':member})
        result=h.outcomes(b'\n'.join(streams).decode('utf-8'))
        for r in result['python']:
            for k in ('methods','passed','failed','errors','skipped'):py[k]+=r[k]
        for r in result['rust']:
            for k in ('passed','failed','ignored'):rust[k]+=r[k]
        assert type(row['exit']) is int
        expected_exit=1 if name=='backend' and row['label']=='source-probe' else 0
        if row['exit']!=0:
            if expected_exit==row['exit']:expected_negative+=1
            else:unexpected_nonzero+=1
        command_rows.append({'label':row['label'],'argv':row['argv'],'cwd':row['cwd'],'exit':row['exit'],
            'expected_exit':expected_exit,'python':result['python'],'rust':result['rust']})
    ordinary=py['methods']+rust['passed']+rust['failed']
    passed=py['passed']+rust['passed'];failed=py['failed']+py['errors']+rust['failed']
    assert (len(orig['commands']),passed,failed,rust['ignored'])==EXPECTED_COUNTS[name]
    assert ordinary==passed+failed and py['skipped']==0
    assert derived['actual_command_count']==len(orig['commands'])
    return {'component_attempt':name,'commands':len(orig['commands']),'ordinary_method_executions':ordinary,
        'passed':passed,'failed':failed,'ignored':rust['ignored'],'expected_negative_commands':expected_negative,
        'unexpected_nonzero_commands':unexpected_nonzero,'qualification_complete':orig['qualification_complete'],
        'original_manifest_sha256':derived['original_manifest_sha256'],'durable_job_id':derived['durable_job_id'],
        'independent_review_manifest_sha256':pin,'raw_archive_sha256':h.sha(archive_bytes),'raw_archive_members':len(idx),
        'path':'components/'+name,'python':dict(py),'rust':dict(rust),'command_reviews':command_rows}

def totals(rows):
    return {key:sum(r[key] for r in rows) for key in ('commands','ordinary_method_executions','passed','failed','ignored','expected_negative_commands','unexpected_nonzero_commands')}

assert not OUT.exists() and not DEST.exists()
assert h.sha(h.stable(D6/'AGENTS.md'))=='082d3f5d3d134efe1273f3bd1cc28a9d41db41be6f8996de8cc9545386094631'
for parent in (D6,D6/'evidence',DEST.parent,DEST):
    for leaf in ('AGENTS.override.md','AGENTS.md'):
        p=parent/leaf
        if p.exists():assert p==D6/'AGENTS.md','Unreviewed applicable instruction file: '+str(p)
preflight=subprocess.run(['bash','scripts/project-preflight.sh','--dev'],cwd=D6,capture_output=True)
assert preflight.returncode==0,(preflight.stdout,preflight.stderr)
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=D6).decode().strip()=='41d717cc9608153dec0daa26ad68ebf8129ed215'
assert subprocess.check_output(['git','rev-parse','MERGE_HEAD'],cwd=D6).decode().strip()==SOURCE['commit']
OUT.mkdir();h.write(OUT/'publication-preflight.stdout',preflight.stdout);h.write(OUT/'publication-preflight.stderr',preflight.stderr)
command_stream_index=[];components=[read_component(*spec) for spec in SPECS]
assert len(command_stream_index)==154 and len({x['original_path'] for x in command_stream_index})==154
original=totals([r for r in components if r['component_attempt']!='staged-repeat'])
all_attempts=totals(components)
selected=totals([r for r in components if r['component_attempt']!='staged-original'])
assert original=={'commands':73,'ordinary_method_executions':665,'passed':664,'failed':1,'ignored':4,'expected_negative_commands':1,'unexpected_nonzero_commands':1}
assert all_attempts=={'commands':77,'ordinary_method_executions':697,'passed':696,'failed':1,'ignored':4,'expected_negative_commands':1,'unexpected_nonzero_commands':1}
assert selected=={'commands':73,'ordinary_method_executions':665,'passed':665,'failed':0,'ignored':4,'expected_negative_commands':1,'unexpected_nonzero_commands':0}
for group,source in AUDITS.items():
    for p in sorted(source.iterdir()):
        if p.is_file():
            assert p.suffix in ('.py','.json') and not p.is_symlink()
            copy_file(p,OUT/'audit-drivers-and-records'/group/p.name)
post=BASE/'chain-w1-c8-postowner-evidence-20261108-ec265b-01'
pm=h.stable(post/'manifest.json');assert h.sha(pm)=='0ba4ecdacb4b84691774e2fbf3bcc842e5517c5188090c29166c4aa7c5676df2'
pmeta=h.load(pm);assert pmeta['member_count']==len(pmeta['members'])==75
assert pmeta['source_commit']==SOURCE['commit'] and pmeta['source_tree']==SOURCE['tree']
assert pmeta['target_read_or_write_by_this_packager'] is False and pmeta['tests_reexecuted']==0
assert {p.relative_to(post).as_posix() for p in post.rglob('*') if p.is_file()}=={x['path'] for x in pmeta['members']}|{'manifest.json'}
for member in pmeta['members']:copy_file(post/member['path'],OUT/'postowner-launch-provenance'/member['path'],member)
copy_file(post/'manifest.json',OUT/'postowner-launch-provenance/manifest.json',{'sha256':h.sha(pm)})
copy_file(BASE/'chain-w1-c8-staged-attempt-01-source-review-20261108-ec265b.json',OUT/'staged-attempt-01-source-review.json',{'sha256':'167846874873a896697294b8a429235895f8460cae6ee913b62863497e913307'})
copy_file(Path(__file__),OUT/'publication-packager.py')
h.write(OUT/'command-output-index.json',h.dump(command_stream_index))
summary={'schema':'TRNM-W1-C8-INDEPENDENT-QUALIFICATION-HISTORY1','source':SOURCE,
    'source_parents':['40a3a45d6b8afc5c4706c5235fec47634f4aabbe','9417e495165865ef6c1288b39084856e31020634'],
    'source_identity_kind':'head','current_prospective_merge_event_qualified':False,
    'all_first_attempts_passed':False,'original_campaign':original,'all_declared_attempts':all_attempts,
    'selected_successful_coverage_set':selected,
    'selected_set_scope':'Successful coverage uses the one predeclared staged repeat. It is not an all-green first campaign and does not erase or explain the original failure.',
    'total_component_attempts':9,'distinct_component_roles':8,'raw_command_streams_independently_rehashed':154,
    'counts_derived_from_actual_raw_summaries_and_actual_command_arrays':True,'components':components,
    'staged_attempt_limit':{'original_attempts':1,'maximum_additional_attempts':1,'additional_attempts_executed':1,
        'same_source_plan_driver_argv_and_parameters':True,'control_wall_seconds':0.2,'effective_omitted_cleanup_default_seconds':5,
        'original_failure_retained':True,'first_failure_specific_IO_CPU_or_host_cause_established':False,
        'repeat_establishes_stable_timing_or_whole_host_idle':False},
    'excluded_from_test_counts':{'source_checks_and_build_commands':True,'precommit_Python_methods':160,
        'History_ignored_entry_listed_only':1,'independent_audit_and_import_tests':0,
        'owner_predispatch_failure_qualification_commands':0,'owner_predispatch_failure_methods':0,
        'audit_helper_failures_tests':0},
    'retained_nonqualification_failures':[
        {'job_id':'1a1ba70f3e9-12894-1ab5','kind':'owner launcher cache_basis wording check before qualifier exec','qualification_commands':0,'methods':0,'preserved_in':'components/owner/raw-logs.tar.gz'},
        {'job_id':'1a1ba7809b7-12894-1ae5','kind':'independent audit stale source-hash constant','qualification_commands':0,'methods':0,'preserved_in':'audit-drivers-and-records/backend-native'},
        {'job_id':'1a1ba8dab13-12894-1b8d','kind':'independent audit incorrect traceback substring','qualification_commands':0,'methods':0,'preserved_in':'audit-drivers-and-records/owner-historical'}],
    'build_provenance':{'owner_backend_native_fresh_targets':False,'independent_C7_cache_copies':True,
        'registry_and_toolchain_reused':True,'independent_cleanroom_or_reproducible_build_established':False,
        'owner_ELF_rehashed_by_original_strict_import_not_this_aggregate':True,
        'native_and_backend_ELF_rehashed_by_component_audit':True,
        'History_ELF_hash_bound_to_original_compile_list_helper':True},
    'scope_limits':{'new_complete_proofs':0,'receiver_uses_original_Nov5_complete_receipt':True,
        'full_4105_block_History_executed':False,'winning_W1_Node_admission_established':False,
        'prior_ABBA80_bound_to_C8_full_generation':False,'positive_provider_payment_established':False,
        'complete_historical_process_reaping_and_resource_billing':False,'original_business_budget_qualified':False,
        'production_or_deployment_qualified':False,'full_cryptographic_or_protocol_security_qualified':False,
        'new_lifecycle_operation_started_by_this_review':False,'lifecycle_evidence_included':False},
    'four_gate_status':['HOLD']*4,'source_modified_by_audit':False,'tests_rerun_by_audit':0,
    'git_index_or_commit_completeness_claimed_by_this_package':False}
h.write(OUT/'summary.json',h.dump(summary))
table='\n'.join('| '+r['component_attempt']+' | '+str(r['commands'])+' | '+str(r['ordinary_method_executions'])+' | '+str(r['passed'])+' | '+str(r['failed'])+' | '+str(r['ignored'])+' |' for r in components)
readme=f'''# C8 qualification history and independent audit

Frozen executed source: `{SOURCE['commit']}`, tree `{SOURCE['tree']}`. Source parents are C7 and the fixed base9417 commit. These records qualify the frozen head source within the stated tests; they do not qualify a later prospective-merge event or the post-hoc evidence commit.

**The first campaign was not all green.** Its 73 commands produced 665 ordinary method executions: 664 passed and 1 failed, with 4 Rust methods ignored. One additional complete staged suite was declared in advance and run with the same source, plan, driver, argv and original parameters. It passed all 32 methods. Across every declared qualification attempt, the retained total is **77 commands, 697 ordinary method executions, 696 passed, 1 failed and 4 ignored**. The backend also has one deliberately expected source-probe exit 1, which is not a test method.

The selected successful coverage set contains 73 commands and 665 passed ordinary methods, plus 4 ignored. It uses the one repeat for staged coverage. That selected set must never replace the all-attempt totals or turn the original `qualification_complete=false` into true.

| Component or attempt | Commands | Ordinary executions | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: | ---: | ---: |
{table}

## Original staged failure and bounded repeat

The original staged job `1a1ba8f182e-12894-1b97` has 31 passed methods and one failure in `test_ignored_sigterm_escalates_and_output_overflow_remains_failure`. Its original 0.2-second allowance expired before Popen, producing `DEADLINE_EXHAUSTED_BEFORE_SPAWN`; the SIGKILL cleanup assertion was not satisfied and the later OUTPUT_LIMIT subcase was not entered. The production observer starts this allowance before declaration persistence and output-file setup. No per-phase measurement establishes which activity caused the exhaustion, and no I/O, CPU or whole-host-idle explanation is claimed.

The test patches a module constant to 0.15, but `measure` already captured the default argument when it was defined. Because the test passes no explicit cleanup-grace keyword, the actual omitted default remains 5 seconds. Neither this fixture nor production deadline logic was changed. The successful job `1a1ba97e353-12894-1bcf` is the single predeclared complete-suite repeat, not an extension of the first trial's deadline. It adds actual SIGKILL/OUTPUT_LIMIT branch coverage; it does not explain the first failure or establish stable short-budget timing. The launcher observations concern the seven known qualification units and the original failed unit at bounded times, not all host workloads, zombie reaping or historical resource ownership.

## Evidence and counting

Each component directory contains its original manifest and every original stdout/stderr byte in a read-back-verified `raw-logs.tar.gz`, a per-member hash index, an independent review and a file manifest. `command-output-index.json` maps all 154 command streams to those archives. Raw Python and Rust outcomes, including the failure and ignored counts, were parsed independently; the aggregate also rechecked every archived stream and recomputed the totals. Source-before and source-after are the original strict head-identity records, not newly run checks.

The History group compiled its release test binary with `--no-run` and listed one exact ignored entry using `--ignored --list`. It executed zero test methods and no 4105-block workload. The 10 historical/cache regression methods are separate from the owner's legacy-admission and reorganization filters. Counts describe executions, not global unique tests across previous sources or repeated attempts. Precommit 160 Python methods, prerequisite imports, audits, copy/preparation receipts and listed-only entries are not added to the qualification totals.

The owner, backend and native targets were independent copies of qualified C7 caches, with `fresh=false`; registry and toolchain caches were reused. Original C7 empty-target creation is historical provenance, not an empty C8 target or clean-room claim. Actual Cargo/source and ELF pins are retained. Backend/native ELFs were rehashed by the independent component audit; owner ELF hashing is bound to the original strict import, and History ELF hashing to its original compile/list helper. This aggregate does not reread or publish those executables.

## Preserved preparation and audit failures

The initial owner launcher failed its wording assertion before invoking any qualifier, Cargo or Node, and executed zero qualification commands or methods. Its original failure and the exact three-line external launcher correction are retained. Two independent audit-only failures are also retained: an incorrect inherited source-hash constant and an incorrect traceback substring. They executed no tests or source guards and did not change original qualification outcomes; corrected audits used new output directories. Audit-driver inputs preserve raw terminal text where available and do not use a rounded request-fingerprint number as an identity authority.

## Limits and publication

This package generates zero complete proofs. The 11 receiver controls use the original November 5 complete receipt with the C8 verifier. It establishes no winning W1 Node admission, C8-bound full-generation ABBA benefit, positive provider payment, complete historical process accounting, original business-budget pass, deployment qualification or full cryptographic/protocol security. All four engineering gates remain **HOLD**. Lifecycle observations belong to a separate package and are not counted here.

Only allowlisted logs, JSON, source helpers and review documents are copied. ELF binaries, SQLite databases, private process environments and credentials are excluded. The package manifest proves filesystem bytes, including every component archive and provenance member. The publishing owner must still verify all listed files in the Git index and the published commit; this package makes no circular claim about its own eventual publication.
'''
h.write(OUT/'README.md',readme.encode())
files=[]
for p in sorted(OUT.rglob('*')):
    if p.is_dir():continue
    assert p.is_file() and not p.is_symlink()
    b=h.stable(p);safe(p.relative_to(OUT).as_posix(),b)
    files.append({'path':p.relative_to(OUT).as_posix(),'bytes':len(b),'sha256':h.sha(b)})
manifest={'schema':'TRNM-W1-C8-QUALIFICATION-PUBLICATION1','source':SOURCE,'files':files,
    'file_count_excluding_manifest':len(files),'total_bytes_excluding_manifest':sum(x['bytes'] for x in files),
    'actual_component_attempts':9,'actual_commands':77,'raw_command_streams':154,
    'ordinary_method_executions':697,'passed':696,'failed':1,'ignored':4,
    'selected_coverage_commands':73,'selected_coverage_passed_methods':665,'all_first_attempts_passed':False,
    'raw_archives_member_readback_verified':True,'filesystem_members_verified':True,
    'git_index_or_commit_verified_by_this_packager':False,'source_written':False,'tests_executed':0}
h.write(OUT/'manifest.json',h.dump(manifest))
shutil.copytree(OUT,DEST)
for f in files+[{'path':'manifest.json','bytes':len(h.stable(OUT/'manifest.json')),'sha256':h.sha(h.stable(OUT/'manifest.json'))}]:
    b=h.stable(DEST/f['path']);assert len(b)==f['bytes'] and h.sha(b)==f['sha256']
assert {p.relative_to(DEST).as_posix() for p in DEST.rglob('*') if p.is_file()}=={f['path'] for f in files}|{'manifest.json'}
print(json.dumps({'complete':True,'external':str(OUT),'published_worktree_directory':str(DEST),
    'manifest_sha256':h.sha(h.stable(DEST/'manifest.json')),'summary_sha256':h.sha(h.stable(DEST/'summary.json')),
    'README_sha256':h.sha(h.stable(DEST/'README.md')),'files_including_manifest':len(files)+1,
    'bytes_excluding_manifest':sum(x['bytes'] for x in files),'all_attempts':all_attempts,'selected_coverage':selected,
    'raw_streams':len(command_stream_index),'old_evidence_or_source_changed':False}),flush=True)
