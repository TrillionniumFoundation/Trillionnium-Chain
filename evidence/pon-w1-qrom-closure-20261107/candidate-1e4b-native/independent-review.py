#!/usr/bin/env python3
"""Independent evidence review. Does not rerun tests or edit frozen A."""
from pathlib import Path
from collections import Counter
import difflib,gzip,hashlib,io,json,os,re,stat,subprocess,sys,tarfile
P=Path('/home/qian-qi/work/chain-qrom-closure-20261107-evidence')
ROOT=Path('/home/qian-qi/work/chain-qrom-local-20261107-7150')
RAW=P/'native-1e4bffc371bc'
DIAG=P/'native-1e4bffc371bc-failure-diagnostic'
OUT=P/'native-1e4bffc371bc-review'
HEAD='1e4bffc371bcdc53aabc621b6b6cb2485ab36f53'
TREE='23c95cb4acfcfd2b1355d9d6e33c4c18b3f332a0'
OLD='7150d96a2112875b4afcf3023361a5cef4a0e4b1'
PREFIX='trillionnium/crates/trnm-pon-node/src/release_owner/'
FULL={'full-source-before','full-source-after'}
ARCHIVE_SHA='787ecdea6f3dfb11f03b61dd20f2484b763453f390b3d9802ca37e0cc5ec89c0'
DIAG_SHA='413a6c7bf5a589b876cf05dd72855379b1643b9da2cbe19d64bacc3a5d5a9d09'
SOURCES={
    'root_separation_tests':('7d0f8b33e7d9f6b316053508c6f1df9f5510c985f5e757470d85d0818888fb39',7),
    'sealed_tests':('64767fdd1a3c8cf95413e7afe550472ea97890d5c5cb0b2965e81c0d4e4d7697',8)}
MUST_INCLUDE={
'canonical_root_roles_round_trip_through_publication_and_record',
'tagged_root_roles_reject_noncanonical_duplicate_and_out_of_range_keys',
'decoded_root_role_keys_do_not_bypass_complete_root_validation',
'sealed_kernel_rejects_payload_extent_and_exec_mutations',
'sealed_mtime_and_nonexec_mode_changes_refuse_all_held_uses',
'sealed_ctime_only_change_refuses_all_held_uses',
'expired_old_root_keeps_dual_quorum_recovery_and_cold_proof_replay',
'sealed_copy_survives_in_place_source_rewrite_and_path_replacement'}
def digest(b): return hashlib.sha256(b).hexdigest()
def sha(p): return digest(Path(p).read_bytes())
def read(n): return json.loads((RAW/n).read_text())
def write(n,x):
    with (OUT/n).open('x') as f: json.dump(x,f,sort_keys=True,indent=2);f.write('\n')
def git(*a): return subprocess.check_output(['git','--no-replace-objects',*a],cwd=ROOT)
def check_archive(path,expected,field):
    assert sha(path)==expected
    payload={}
    with tarfile.open(path,'r:gz') as archive:
        for member in archive:
            assert member.isfile() and '/' not in member.name and member.name not in payload
            payload[member.name]=archive.extractfile(member).read()
    manifest=json.loads(payload.pop('manifest.json'))
    entries=manifest[field]
    assert len(entries)==len(payload)
    assert len({r['path'] for r in entries})==len(entries)
    assert {r['path'] for r in entries}==set(payload)
    for row in entries:
        b=payload[row['path']]
        assert len(b)==row['bytes'] and digest(b)==row['sha256']
        assert (path.parent/row['path']).read_bytes()==b
    return {'archive':str(path),'bytes':path.stat().st_size,'sha256':expected,
        'payload_files':len(payload),'all_members_match_manifest_and_retained_originals':True}
def parse_list(n):
    s=(RAW/(n+'.stdout.log')).read_text()
    names=re.findall(r'^(\S+): test$',s,re.M)
    count=re.findall(r'^(\d+) tests?, (\d+) benchmarks?$',s,re.M)
    assert len(count)==1 and int(count[0][0])==len(names) and int(count[0][1])==0
    assert len(set(names))==len(names)
    return names
def parse_run(n):
    s=(RAW/(n+'.stdout.log')).read_text()
    rows=[{'name':m.group(1),'status':m.group(2),'ignored_reason':m.group(3)} for m in
        re.finditer(r'^test (\S+) \.\.\. (ok|FAILED|ignored)(?:, ([^\n]*))?$',s,re.M)]
    blocks=[{'result':m.group(1),'passed':int(m.group(2)),'failed':int(m.group(3)),
        'ignored':int(m.group(4)),'measured':int(m.group(5)),'filtered':int(m.group(6))}
        for m in re.finditer(r'^test result: ([^.]+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;',s,re.M)]
    assert len(blocks)==1 and len(set(r['name']for r in rows))==len(rows)
    assert Counter(r['status']for r in rows)==Counter({k:v for k,v in
        [('ok',blocks[0]['passed']),('FAILED',blocks[0]['failed']),('ignored',blocks[0]['ignored'])] if v})
    return rows,blocks[0]
assert git('rev-parse','HEAD').decode().strip()==HEAD
assert git('rev-parse','HEAD^{tree}').decode().strip()==TREE
OUT.mkdir(exist_ok=False)
(OUT/'review.py').write_bytes(Path(__file__).read_bytes())
archives=[check_archive(RAW/'observations.tar.gz',ARCHIVE_SHA,'payload_files'),
          check_archive(DIAG/'observations.tar.gz',DIAG_SHA,'files')]
write('archive-integrity.json',archives)
summary=read('native-summary.json')
assert summary['head']==HEAD and summary['tree']==TREE
controller=P/'native-candidate-1e4b-controller-terminal.json'
assert sha(controller)=='1f65b42512567bddf6fe95b1abbc7ea64b1513248156cfc2d70ae8e2d81e0430'
terminal=json.loads(controller.read_text())
assert terminal['job_id']=='1a1b67a06fa-12894-47d' and terminal['output_complete'] is True and terminal['exit_code']==2
(OUT/'controller-terminal.json').write_bytes(controller.read_bytes())
stages=summary['commands']
names=[r['name']for r in stages]
assert len(set(names))==len(names)
expected={'bootstrap-preflight','base-bundle-verify','base-bundle-fetch','candidate-bundle-verify',
'candidate-bundle-fetch','candidate-ancestry','candidate-fast-forward','preflight-audit',
'full-source-before','cargo-metadata-chain','cargo-metadata-v2','dependencies-before','cargo-fmt',
'rustc-version','cargo-version','release-owner-list','release-owner-ignored-list','release-owner-tests',
'ingress-exact-test','v2-native-tests','v2-release-build','v2-fixed-receipt','v2-complete-native',
'v2-mutated-receipt','v2-mutated-artifacts','v2-native-mutated-artifacts',
'v2-environment-risc0_dev_mode','v2-environment-risc0_prover',
'v2-environment-bonsai_api_url','v2-environment-bonsai_api_key',
'chain-strict-clippy','dependencies-after','full-source-after'}
assert set(names)==expected
for row in stages:
    assert read(row['name']+'.json')==row
    for stream in ('stdout','stderr'):
        p=RAW/(row['name']+'.'+stream+'.log')
        assert p.stat().st_size==row[stream+'_bytes'] and sha(p)==row[stream+'_sha256']
    calculated=(row['timed_out'] is False and row['launch_error'] is None and row['exit_code']==row['expected_exit'])
    assert row['expectation_met'] is calculated
bad=[r['name']for r in stages if not r['expectation_met']]
assert bad==summary['failed_observations']
assert summary['all_observed_command_expectations_met'] is (not bad)
assert all(type(v)is bool for v in summary['semantic_and_identity_checks'].values())
nonfull_bad=[n for n in bad if n not in FULL]
required=summary['required_narrow_stages']
assert len(required)==len(set(required)) and set(required)<=expected
semantic_ok=all(summary['semantic_and_identity_checks'].values())
narrow=not nonfull_bad and semantic_ok and all(next(r for r in stages if r['name']==n)['expectation_met']for n in required)
assert summary['narrow_candidate_gate_pass'] is narrow
for name in FULL:
    row=next(r for r in stages if r['name']==name)
    assert row['exit_code']==1 and row['expectation_met'] is False
    assert 'source is not clean' in (RAW/(name+'.stderr.log')).read_text()
source_before,source_after=read('selected-source-before.json'),read('selected-source-after.json')
assert source_before==source_after and source_before['selected_bytes_and_modes_match_head'] is True
entries={}
for item in git('ls-tree','-r','-z',HEAD).split(b'\0'):
    if item:
        h,p=item.split(b'\t',1);mode,kind,blob=h.decode().split()
        assert kind=='blob';entries[p.decode()]={'mode':mode,'git_blob':blob}
all_rows=source_after['files']
assert len(all_rows)==2805 and len({r['path']for r in all_rows})==2805
assert {p for p in entries if not p.startswith('evidence/')}<={r['path']for r in all_rows}
for row in all_rows:
    path=ROOT/row['path'];st=path.lstat()
    assert stat.S_ISREG(st.st_mode) and row['expected']==entries[row['path']]
    b=path.read_bytes()
    blob=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
    mode='100755'if st.st_mode&0o111 else '100644'
    assert blob==entries[row['path']]['git_blob'] and mode==entries[row['path']]['mode'] and digest(b)==row['sha256']
work_before,work_after=read('source-worktree-before.json'),read('source-worktree-after.json')
assert work_before==work_after and work_after['full_tracked_clean'] is False
source_check={'head':HEAD,'tree':TREE,'selected_count':len(all_rows),
'selected_before_after_same':True,'selected_current_bytes_modes_rechecked':True,
'snapshot_sha256':sha(RAW/'selected-source-after.json'),
'full_tracked_identity_verified':False,'worktree_record_count':work_after['record_count'],
'all_remaining_status_entries_deleted_evidence':work_after['all_reported_changes_are_deleted_evidence']}
write('selected-source-third-check.json',source_check)
all_names,ignored_names=parse_list('release-owner-list'),parse_list('release-owner-ignored-list')
rows,counts=parse_run('release-owner-tests')
assert Counter(r['name']for r in rows)==Counter(all_names)
assert Counter(r['name']for r in rows if r['status']=='ignored')==Counter(ignored_names)
outcomes={r['name']:r['status']for r in rows}
key_rows=[]
for module,(expected_sha,number) in SOURCES.items():
    p=ROOT/PREFIX/(module+'.rs');data=p.read_bytes();assert digest(data)==expected_sha
    found=re.findall(r'#\[test\]\s*(?:#\[[^]]+\]\s*)*fn\s+(\w+)\s*\(',data.decode())
    assert len(found)==number and len(set(found))==number
    for name in found:
        full='release_owner::'+module+'::'+name
        key_rows.append({'name':full,'source':PREFIX+module+'.rs','source_sha256':expected_sha,
            'registered_once':all_names.count(full)==1,'actual_outcome':outcomes.get(full),
            'ignored':full in ignored_names})
assert MUST_INCLUDE<={r['name'].split('::')[-1]for r in key_rows}
key_pass=all(r['registered_once']and r['actual_outcome']=='ok'and not r['ignored']for r in key_rows)
key_result={'key_count':len(key_rows),'root_count':7,'sealed_count':8,'all_fifteen_actual_pass':key_pass,
    'rows':key_rows,'entire_release_owner_module_pass':counts['failed']==0,'module_counts':counts,
    'module_failed_names':[r['name']for r in rows if r['status']=='FAILED'],
    'module_ignored':[r for r in rows if r['status']=='ignored']}
write('key-fifteen-completion.json',key_result)
old=git('show',OLD+':'+PREFIX+'sealed.rs').decode().splitlines(keepends=True)
new=(ROOT/PREFIX/'sealed.rs').read_text().splitlines(keepends=True)
ops=[x for x in difflib.SequenceMatcher(a=old,b=new,autojunk=False).get_opcodes()if x[0]!='equal']
comment_only=bool(ops)and all(kind=='insert'and all(line.strip().startswith('//')for line in new[j:k])for kind,_,_,j,k in ops)
assert comment_only
write('sealed-production-comment-only.json',{'baseline':OLD,'head':HEAD,
'production_sealed_source_sha256':sha(ROOT/PREFIX/'sealed.rs'),
'only_inserted_comment_lines':True,'guard_code_bytes_changed':False})
feature=read('v2-feature-check.json')
assert feature['features']==['disable-dev-mode','std']
assert feature['default_prover_client_features_absent'] is True and feature['disable_dev_mode_active'] is True
assert feature['proof_environment_variable_names_present']==[]
for value in feature['direct_dependency_declarations'].values():
    assert value['default-features'] is False and value['version']=='=3.0.6'and set(value['features'])=={'std','disable-dev-mode'}
v2rows,v2counts=parse_run('v2-native-tests')
assert v2counts['passed']==3 and v2counts['failed']==0 and v2counts['ignored']==0
fixture=ROOT/'evidence/pon-w1-full-v2-20261105'
vr=json.loads((RAW/'v2-fixed-receipt.stdout.log').read_text())
vn=json.loads((RAW/'v2-complete-native.stdout.log').read_text())
assert vr['schema']=='TRNM-W1-V2-FULL-VERIFY1' and vn['schema']=='TRNM-W1-V2-NATIVE1'
for key in ['work_id','header_sha256','journal_sha256','expected_artifacts_sha256']:assert vr[key]==vn[key]
for key,name in [('header_sha256','header.bin'),('expected_artifacts_sha256','expected-artifacts.bin'),('receipt_sha256','succinct.bin')]:assert vr[key]==sha(fixture/name)
assert vn['input_sha256']==sha(fixture/'input.bin') and vn['full_replay_calls']==1001 and vn['iterations']==1000
assert vr['independent_proof_trials']==1 and vr['iterations']==1
b=bytearray((fixture/'succinct.bin').read_bytes());b[76]^=1
assert bytes(b)==(RAW/'mutated-receipt.bin').read_bytes()
b=bytearray((fixture/'expected-artifacts.bin').read_bytes());b[0]^=1
assert bytes(b)==(RAW/'mutated-artifacts.bin').read_bytes()
for name,marker in [('v2-mutated-receipt','W1_V2_CRYPTO_REJECT'),('v2-mutated-artifacts','W1_V2_PUBLIC_REJECT'),('v2-native-mutated-artifacts','PublicStatement')]:
    assert marker in (RAW/(name+'.stderr.log')).read_text()
for key in ['RISC0_DEV_MODE','RISC0_PROVER','BONSAI_API_URL','BONSAI_API_KEY']:
    assert 'unexpected proof environment: '+key in (RAW/('v2-environment-'+key.lower()+'.stderr.log')).read_text()
deps=read('resolved-dependencies-after.json')
assert deps['all_supported_source_checks_pass'] is True
assert read('resolved-dependencies-comparison.json')['packages_and_source_files_unchanged'] is True
diag=json.loads((DIAG/'diagnostic-summary.json').read_text())
assert diag['head']==HEAD and diag['test_window_or_source_modified'] is False and diag['run_count']==1
assert diag['selected_source_before_after_match_head']is True and diag['binary_unchanged']is True
all_semantic=summary['semantic_and_identity_checks']
result={'schema':'TRNM-W1-A-INDEPENDENT-NATIVE-REVIEW1','head':HEAD,'tree':TREE,
'overall_controller_exit':terminal['exit_code'],'overall_controller_state':terminal['state'],
'controller_exit_is_not_used_as_narrow_gate_verdict':True,
'all_observed_command_expectations_met':summary['all_observed_command_expectations_met'],
'narrow_candidate_gate_pass':narrow,'native_gate_conclusion':'FAIL'if not narrow else 'PASS_FOR_SELECTED_SCOPE_ONLY',
'full_source_refusals':sorted(FULL),'all_failed_command_observations':bad,
'non_full_source_failed_command_observations':nonfull_bad,
'required_commands':[{'name':r['name'],'exit_code':r['exit_code'],'expected_exit':r['expected_exit'],
'timed_out':r['timed_out'],'expectation_met':r['expectation_met'],'elapsed_seconds':r['elapsed_seconds'],
'stdout_sha256':r['stdout_sha256'],'stderr_sha256':r['stderr_sha256']}for r in stages],
'semantic_and_identity_checks':all_semantic,
'feature_check':feature,'key_fifteen':key_result,'source_after':source_check,
'dependency_package_count':deps['package_count'],
'dependency_archived_source_file_count':sum(p.get('source_files_verified',0)for p in deps['packages'].values()),
'archives':archives,'evidence_integrity_checks_completed':True,
'separate_single_exact_diagnostic':{'pass':diag['isolated_diagnostic_pass'],'runs':1,
'original_module_failure_overridden':False,'archive_sha256':DIAG_SHA,
'elapsed_seconds':next(r['elapsed_seconds']for r in diag['records']if r['name']=='service-exact-test'),
'cause_established':False},
'clippy_pass':next(r['expectation_met']for r in stages if r['name']=='chain-strict-clippy'),
'v2_fixed_receipt_native_and_negative_controls_pass':True,
'v2_independent_proof_trials':1,'v2_one_input_native_replay_calls':1001,
'full_workspace_tests_rerun':False,'original_7150_failure_and_timeout_preserved':True,
'full_tracked_identity_verified':False,'post_quantum_soundness_qualified':False,
'unconditional_project_security_bits':None,'production_or_consensus_admission_authorized':False,
'cloud_copy_completed':False}
write('summary.json',result)
write('review-process-semantics.json',{'exit_rule':'0 iff independently recomputed narrow gate true; otherwise 2, even when archive review is complete.',
'observed_narrow_gate':narrow,'no_test_rerun_performed_by_this_review':True,
'main_runner_exit_rule':'all_observed_command_expectations_met; must read native-summary semantic verdict separately.'})
files=[p for p in sorted(OUT.iterdir())if p.is_file()]
write('manifest.json',{'head':HEAD,'files':[{'path':p.name,'bytes':p.stat().st_size,'sha256':sha(p)}for p in files]})
with (OUT/'observations.tar.gz').open('xb')as raw:
    with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0)as zipped:
        with tarfile.open(mode='w',fileobj=zipped)as archive:
            for p in files+[OUT/'manifest.json']:
                data=p.read_bytes();info=tarfile.TarInfo(p.name);info.size=len(data);info.mode=0o600;info.mtime=0
                archive.addfile(info,io.BytesIO(data))
package={'path':str(OUT/'observations.tar.gz'),'bytes':(OUT/'observations.tar.gz').stat().st_size,
'sha256':sha(OUT/'observations.tar.gz'),'summary_sha256':sha(OUT/'summary.json'),
'manifest_sha256':sha(OUT/'manifest.json'),'narrow_candidate_gate_pass':narrow,'key_fifteen_pass':key_pass,
'evidence_review_complete':True,'cloud_copy_completed':False}
write('package-result.json',package)
print(json.dumps(package,sort_keys=True),flush=True)
raise SystemExit(0 if narrow else 2)
