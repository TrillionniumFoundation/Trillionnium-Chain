#!/usr/bin/env python3
"""Separate bounded exact-test diagnostics; preserves the failed workspace archive."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import signal
import subprocess
import time

ROOT=Path('/home/qian-qi/work/chain-qrom-local-20261107-7150')
OLD=Path('/home/qian-qi/work/chain-qrom-closure-20261107-evidence/native-7150')
OUT=Path('/home/qian-qi/work/chain-qrom-closure-20261107-evidence/native-7150-failure-diagnostics')
HEAD='7150d96a2112875b4afcf3023361a5cef4a0e4b1'
BINARY=OLD/'cargo-target/debug/deps/trnm_pon_node-d0b5619ab979ee7c'
TESTS=[('ingress','ingress::public_v3::tests::write_half_closed_or_disconnected_signed_submits_waiting_or_queued_do_not_start_work'),
 ('root-separation','release_owner::root_separation_tests::expired_old_root_keeps_dual_quorum_recovery_and_cold_proof_replay'),
 ('sealed-copy','release_owner::sealed_tests::sealed_copy_survives_in_place_source_rewrite_and_path_replacement')]
ENV=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(OLD/'cargo-target'),CARGO_TERM_COLOR='never')

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def write(name,value):
    with (OUT/name).open('x') as stream:
        json.dump(value,stream,sort_keys=True,indent=2); stream.write('\n')

def frozen():
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==HEAD

def source_check(phase):
    frozen()
    prior=json.loads((OLD/'selected-source-before.json').read_text())
    failures=[]
    for row in prior['files']:
        p=ROOT/row['path']
        try:
            actual=sha(p)
            if actual!=row['sha256']: failures.append({'path':row['path'],'expected':row['sha256'],'actual':actual})
        except OSError as error: failures.append({'path':row['path'],'error':str(error)})
    result={'head':HEAD,'selected_count':len(prior['files']),'reference_sha256':sha(OLD/'selected-source-before.json'),
        'selected_bytes_match_reference_and_HEAD':not failures,'mismatches':failures,'full_tracked_identity_claimed':False}
    write('source-'+phase+'.json',result)
    if failures: raise RuntimeError('selected source identity changed')
    return result

def observe(short,name,expected_binary):
    frozen()
    if sha(BINARY)!=expected_binary: raise RuntimeError('test binary changed before diagnostic')
    argv=[str(BINARY),name,'--exact','--nocapture','--test-threads=1']
    stdout,stderr=OUT/(short+'.stdout.log'),OUT/(short+'.stderr.log')
    began=datetime.now(timezone.utc).isoformat(); start=time.monotonic()
    timed_out=False
    print(json.dumps({'started':short,'command':argv}),flush=True)
    with stdout.open('xb') as out,stderr.open('xb') as err:
        process=subprocess.Popen(argv,cwd=ROOT,env=ENV,stdout=out,stderr=err,start_new_session=True)
        try: process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            timed_out=True; os.killpg(process.pid,signal.SIGKILL); process.wait()
    text=stdout.read_text(errors='replace')
    match=re.search(r'^test result: ([^.]+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;',text,re.M)
    result=None
    if match:
        result={'result':match.group(1),'passed':int(match.group(2)),'failed':int(match.group(3)),
            'ignored':int(match.group(4)),'measured':int(match.group(5)),'filtered_out':int(match.group(6))}
    one_test=(text.count('running 1 test\n')==1 and name in text and result is not None and
        result['passed']+result['failed']+result['ignored']==1 and result['ignored']==0)
    row={'name':short,'test':name,'command':argv,'cwd':str(ROOT),'source_commit':HEAD,
        'binary_sha256':expected_binary,'started_utc':began,'elapsed_seconds':time.monotonic()-start,
        'timeout_seconds':90,'timed_out':timed_out,'exit_code':process.returncode,'result':result,
        'exactly_one_requested_nonignored_test_reported':one_test,
        'diagnostic_passed':not timed_out and process.returncode==0 and one_test,
        'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr),
        'stdout_bytes':stdout.stat().st_size,'stderr_bytes':stderr.stat().st_size,
        'original_workspace_result_replaced':False,'full_workspace_passed':False,'post_quantum_soundness_qualified':False}
    write(short+'.json',row); print(json.dumps(row),flush=True)
    return row

def main():
    frozen(); before=source_check('before')
    binary={'path':str(BINARY),'sha256':sha(BINARY),'bytes':BINARY.stat().st_size,
        'script_sha256':sha(Path(__file__)),'source_commit':HEAD,
        'environment_overrides':{'PYTHONDONTWRITEBYTECODE':'1','CARGO_BUILD_JOBS':'2','CARGO_TARGET_DIR':str(OLD/'cargo-target'),'CARGO_TERM_COLOR':'never'},
        'other_host_environment':'Inherited without dumping secret values; same host/account and source directory as the original run.',
        'RUST_BACKTRACE_added':False,'test_thread_count_change_explicitly_authorized':{'original':2,'diagnostic':1}}
    write('binary-before.json',binary)
    rows=[]
    try:
        for short,name in TESTS: rows.append(observe(short,name,binary['sha256']))
    finally:
        after=source_check('after')
        same=sha(BINARY)==binary['sha256']
        write('binary-after.json',{'path':str(BINARY),'sha256':sha(BINARY),'matches_before':same})
        write('diagnostics-summary.json',{'schema':'TRNM-W1-NATIVE-7150-EXACT-FAILURE-DIAGNOSTICS1',
            'head':HEAD,'source_before':before,'source_after':after,'binary':binary,'binary_unchanged':same,
            'records':rows,'original_failed_archive_sha256':sha(OLD/'native-7150-observations.tar.gz'),
            'original_workspace_trial_unchanged':True,'full_workspace_passed':False,
            'post_quantum_soundness_qualified':False,'unconditional_project_security_bits':None})
    print(json.dumps({'diagnostics_complete':True,'out':str(OUT),'cases':len(rows)}),flush=True)

if __name__=='__main__': main()
