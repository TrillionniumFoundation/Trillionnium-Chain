#!/usr/bin/env python3
"""Publish verified filesystem packages to two explicitly owned D5 directories.

Does not stage, commit, push, test, build, mutate C7 or operate the Node.
"""
import hashlib
import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

D5=Path('/home/qian-qi/work/chain-w1-c7-attestation-20261108-ec265b')
EVIDENCE=D5/'evidence/pon-w1-base96-integration-20261108'
DEST=EVIDENCE/'qualification'
BASEDEST=EVIDENCE/'base91-observation'
BASESRC=Path('/home/qian-qi/work/chain-w1-base91-publication-20261108-ec265b-01')
ROOT=Path('/home/qian-qi/work')
SOURCE={'commit':'40a3a45d6b8afc5c4706c5235fec47634f4aabbe','tree':'4b25e3194a0682adff40bb476f2e7c0a395639fe'}
COMPONENTS=[
    ('core',1,'95b6f4758f7f181c1994e80707fffbe87d61ff06ebb45410f3b3c537db152fd9'),
    ('owner',1,'9dfc3ca6815faaca75cefaefe7093ec00c5d1a267edae4a50a2c7bcb5e55255f'),
    ('receiver',1,'3ec6bfaaac0107c483374d8e74c71259d5b048ea884c83cc386909de8c65f8e4'),
    ('backend',2,'416d477156ccc76a7e7370fef0652d9518b36bbdaf3fcb468c10b533bde450be'),
    ('native',2,'30abdf8425a57aa483fd9c3b5410bd8aa7a9a3f515073f81c55c415a94bea352'),
    ('history-local',3,'0eea6a914ba780d3a5e90a3195ac157549d483da1239ab734f320ca511596de5'),
    ('staged',3,'894c07d94057a4e4b6b9d5463a07516b83156e6f18cf8fd3842ec6e863f9b184'),
]

def sha(b):
    return hashlib.sha256(b).hexdigest()

def read(path):
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK)
    try:
        a=os.fstat(fd)
        assert stat.S_ISREG(a.st_mode) and a.st_size<25*1024*1024
        chunks=[]
        remaining=a.st_size+1
        while remaining:
            b=os.read(fd,min(1048576,remaining))
            if not b:
                break
            chunks.append(b)
            remaining-=len(b)
        b=b''.join(chunks)
        z=os.fstat(fd)
        fields=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        assert fields(a)==fields(z) and len(b)==z.st_size
        assert not b.startswith((b'\x7fELF',b'SQLite format 3'))
        return b
    finally:
        os.close(fd)

def write(path,b):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f:
        f.write(b)

def dump(v):
    return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()

def safe_relative(s):
    p=Path(s)
    assert not p.is_absolute() and '..' not in p.parts
    return p

def copy_manifest_package(src,dest,manifest_pin=None):
    mb=read(src/'manifest.json')
    if manifest_pin:
        assert sha(mb)==manifest_pin
    m=json.loads(mb)
    listed=m.get('files',m.get('members'))
    assert isinstance(listed,list) and listed
    allowed={safe_relative(x['path']).as_posix() for x in listed}|{'manifest.json'}
    actual={p.relative_to(src).as_posix() for p in src.rglob('*') if p.is_file()}
    assert actual==allowed, (str(src),actual-allowed,allowed-actual)
    dest.mkdir()
    for row in listed:
        rel=safe_relative(row['path'])
        b=read(src/rel)
        assert len(b)==row['bytes'] and sha(b)==row['sha256']
        write(dest/rel,b)
    write(dest/'manifest.json',mb)
    for row in listed:
        b=read(dest/row['path'])
        assert len(b)==row['bytes'] and sha(b)==row['sha256']
    return m

def check_tar(component):
    index=json.loads(read(component/'raw-output-index.json'))
    if isinstance(index,dict):
        index=index['members']
    mapped={row.get('archive_member',row.get('member')):row for row in index}
    assert len(mapped)==len(index)
    with tarfile.open(component/'raw-logs.tar.gz',mode='r:gz') as tf:
        assert sorted(tf.getnames())==sorted(mapped)
        for item in tf:
            assert item.isfile()
            safe_relative(item.name)
            b=tf.extractfile(item).read()
            row=mapped[item.name]
            assert len(b)==row['bytes'] and sha(b)==row['sha256']
            assert not b.startswith((b'\x7fELF',b'SQLite format 3'))
    return len(index)

def final_manifest(path,source):
    files=[]
    for p in sorted(path.rglob('*')):
        if p.is_file():
            b=read(p)
            files.append({'path':p.relative_to(path).as_posix(),'bytes':len(b),'sha256':sha(b)})
    manifest={'schema':'TRNM-W1-C7-QUALIFICATION-PUBLICATION-MANIFEST1','source':source,
        'members':files,'members_excluding_self':len(files),'files_including_manifest':len(files)+1,
        'all_filesystem_members_reverified':True,'git_index_or_committed_publication_verified_by_this_audit':False}
    write(path/'manifest.json',dump(manifest))
    expected={x['path'] for x in files}|{'manifest.json'}
    assert expected=={p.relative_to(path).as_posix() for p in path.rglob('*') if p.is_file()}
    for row in files:
        b=read(path/row['path'])
        assert len(b)==row['bytes'] and sha(b)==row['sha256']
    return manifest,sha(read(path/'manifest.json'))

assert not DEST.exists() and not BASEDEST.exists()
tools=Path(__file__).parent
pre=subprocess.run(['bash','scripts/project-preflight.sh','--dev'],cwd=D5,capture_output=True)
pre_record={'argv':['bash','scripts/project-preflight.sh','--dev'],'cwd':str(D5),'exit':pre.returncode,
            'stdout_sha256':sha(pre.stdout),'stderr_sha256':sha(pre.stderr)}
write(tools/'publication-preflight.stdout',pre.stdout)
write(tools/'publication-preflight.stderr',pre.stderr)
write(tools/'publication-preflight.json',dump(pre_record))
assert pre.returncode==0,pre.stderr.decode(errors='replace')
DEST.mkdir()
summaries=[]
component_index=[]
total_raw=0
for name,attempt,pin in COMPONENTS:
    src=ROOT/f'chain-w1-c7-adversarial-components-20261108-ec265b-0{attempt}'/name
    target=DEST/name
    original=copy_manifest_package(src,target,pin)
    s=json.loads(read(target/'summary.json'))
    assert s['source']==SOURCE and s['all_bound_outputs_match'] is True
    assert s['source_guards_before_after_exact_equal'] is True and s['durable_exit']==0
    raw_count=check_tar(target)
    assert raw_count==original['raw_tar_members']
    total_raw+=raw_count
    summaries.append(s)
    component_index.append({'component':name,'actual_commands':s['actual_command_count'],
        'original_manifest_sha256':s['original_manifest_sha256'],'component_publication_manifest_sha256':pin,
        'python':s['python'],'rust':s['rust'],'durable_job_id':s['durable_job_id'],'raw_members':raw_count})
py={k:sum(s['python'].get(k,0) for s in summaries) for k in ('methods','passed','failed','errors','skipped')}
rust={k:sum(s['rust'].get(k,0) for s in summaries) for k in ('passed','failed','ignored')}
count=sum(s['actual_command_count'] for s in summaries)
assert count==69 and py=={'methods':614,'passed':614,'failed':0,'errors':0,'skipped':0}
assert rust=={'passed':41,'failed':0,'ignored':4} and total_raw==214
assert sum(len(s['actual_nonzero_commands']) for s in summaries)==1
assert next(s for s in summaries if s['component']=='backend')['actual_nonzero_commands']==['source-probe']
history=json.loads(read(tools/'audit-history-final-input.json'))
audit_rows=[]
for i,row in enumerate(history['audit_attempts'],1):
    prefix=DEST/'audit-history'/f'attempt-{i:02d}'
    terminal=json.loads(row['terminal_raw'])
    assert terminal['output_complete'] is True and terminal['output_durable'] is True
    assert terminal['exit_code']==(1 if i==1 else 0) and terminal['timed_out'] is False
    write(prefix/'terminal.json',row['terminal_raw'].encode())
    response=json.loads(row['output_response_raw'])
    for stream in ('stdout','stderr'):
        b=bytes.fromhex(response[stream]['bytes_hex'])
        assert response[stream]['offset']==0 and response[stream]['eof'] is True
        assert len(b)==response[stream]['size']==response[stream]['next_offset']
        write(prefix/(stream+'.raw'),b)
    db=read(Path(row['driver']['path']))
    assert sha(db)==row['driver']['sha256']
    write(prefix/'executed-audit-driver.py',db)
    audit_rows.append({'job_id':terminal['job_id'],'exit':terminal['exit_code'],'driver_sha256':sha(db),
                       'interpretation':row['interpretation']})
for name,original,pin in [
    ('original-inputs.json',ROOT/'chain-w1-c7-adversarial-audit-inputs-20261108-ec265b.json','5bd8c2b291a3f5f7ece1bf5d06b2fec74cbdb5e038212fb8452d09a0880cd2df'),
    ('last-inputs.json',ROOT/'chain-w1-c7-adversarial-last-inputs-20261108-ec265b.json','7ddd6dea92c89ff30dc70d790e24d19ebf015ed3e3455f10c730ec6767107173')]:
    # Pins are verified against the recorded upload; no qualification execution occurs here.
    b=read(original)
    assert sha(b)==pin
    write(DEST/'audit-history'/name,b)
write(DEST/'audit-history/summary.json',dump({'schema':'TRNM-W1-C7-AUDIT-HISTORY1','attempts':audit_rows,
    'first_audit_assertion_is_not_a_qualification_failure':True,'tests_rerun_by_audits':0,
    'qualification_results_rewritten':False}))
for name in ('publication-preflight.stdout','publication-preflight.stderr','publication-preflight.json'):
    write(DEST/'publication'/name,read(tools/name))
write(DEST/'publication/assembly-driver.py',read(Path(__file__)))
write(DEST/'README.md',read(tools/'qualification-README.prepared.md'))
summary={'schema':'TRNM-W1-C7-QUALIFICATION-INDEPENDENT-SUMMARY1','source':SOURCE,
    'source_parents':['2bdd252aa6c300b7431b9ee897b254b7953cf562','96a241bf43f6a46d35dfb3d4ced9594ed8ceca75'],
    'documentation_is_posthoc':True,'qualification_components':component_index,'actual_command_count':count,
    'python':py,'rust':rust,'ordinary_passes':py['passed']+rust['passed'],'ignored_methods':rust['ignored'],
    'history_listed_ignored_entry_count':1,'history_full_workload_executions':0,
    'history_list_adds_ordinary_or_ignored_method_executions':False,'raw_archive_members_total':total_raw,
    'all_component_jobs_succeeded_complete_durable':True,
    'all_actual_command_outputs_rehashed':True,'all_tar_members_readback_verified':True,
    'expected_nonzero_command':{'component':'backend','label':'source-probe','actual_exit':1,
        'meaning':'Actual committed source identity emitted, then unknown stage rejected without starting a proof'},
    'new_full_proof_generations_in_qualification':0,'operations_started_by_qualification_or_audit':0,
    'c7_lifecycle_separate_status':'launch-Unknown; no heavy/cold execution qualification claimed',
    'c5_c6_lifecycle_relabelled_as_c7':False,
    'all_four_engineering_gates_closed':False,'hosted_ci_or_new_event_tuple_qualified_by_this_package':False,
    'historical_abba_rebound_to_c7_generation':False,
    'audit_attempt_history':audit_rows,
    'publication_scope':'Only explicit logs, source identities, Cargo metadata, plans, drivers, readbacks and posthoc reviews; no ELF, databases, state trees, process environments or credentials.',
    'git_index_or_committed_publication_verified_by_this_audit':False}
write(DEST/'summary.json',dump(summary))
manifest,manifest_sha=final_manifest(DEST,SOURCE)
copy_manifest_package(BASESRC,BASEDEST)
base_raw=check_tar(BASEDEST)
base_manifest=json.loads(read(BASEDEST/'manifest.json'))
result={'schema':'TRNM-W1-C7-TWO-PACKAGES-FILESYSTEM-PUBLISHED1','qualification':{
    'directory':str(DEST),'manifest_sha256':manifest_sha,'files':manifest['files_including_manifest'],
    'summary_sha256':sha(read(DEST/'summary.json')),'commands':count,'ordinary_passes':655,'ignored':4,
    'raw_members':total_raw},'base91_observation':{'directory':str(BASEDEST),
    'manifest_sha256':sha(read(BASEDEST/'manifest.json')),'files':base_manifest['files_including_manifest'],
    'raw_members':base_raw,'summary_sha256':sha(read(BASEDEST/'summary.json'))},
    'source_worktrees_modified':False,'git_add_commit_or_push_performed':False,
    'requires_publisher_explicit_index_and_commit_member_verification':True}
write(tools/'publication-result.json',dump(result))
print(json.dumps(result),flush=True)
