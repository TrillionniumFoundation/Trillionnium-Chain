#!/usr/bin/env python3
"""Bind an actual native build and selected execution to an unchanged source snapshot."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path('/workspace/scratch/301262829a43/pon-pq-impl/history-followup')
EVIDENCE = Path('/workspace/scratch/301262829a43/pon-pq-impl/history-evidence')
TARGET = Path('/tmp/pon-history-final-20261027')
PREFIX = 'store::operator_continuous_owner::history_import::tests::'

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):h.update(block)
    return h.hexdigest()

def snapshot():
    names=subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=ROOT).split(b'\0')
    return {name.decode():sha(ROOT/name.decode()) for name in sorted(set(names)) if name
        and not name.startswith(b'evidence/') and (ROOT/name.decode()).is_file()}

def main():
    label=sys.argv[1]
    out=EVIDENCE/label
    out.mkdir(exist_ok=False)
    original=TARGET/'debug/deps/trnm_pon_node-aa155a388a5d67f4'
    saved=EVIDENCE/'original-v4-ce6e82f3.bin'
    if not saved.exists():
        assert sha(original)=='ce6e82f30af1a9cc7bf05ddd8ae0b7a686e73ad9c85c90290bf89956b5ebaf99'
        shutil.copy2(original,saved)
    assert sha(saved)=='ce6e82f30af1a9cc7bf05ddd8ae0b7a686e73ad9c85c90290bf89956b5ebaf99'
    env=os.environ.copy()
    env.update(PATH='/workspace/scratch/301262829a43/pon-build-inputs/unpacked/toolchain/bin:'+env['PATH'],
        CARGO_HOME='/workspace/scratch/301262829a43/pon-build-inputs/original-cargo-home',
        CARGO_TARGET_DIR=str(TARGET),CARGO_BUILD_JOBS='1',CARGO_PROFILE_TEST_DEBUG='0')
    assert not env.get('RUSTFLAGS') and not env.get('CARGO_ENCODED_RUSTFLAGS')
    before=snapshot(); (out/'source-before.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
    cmd=['cargo','test','--offline','--locked','--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node',
         '--lib',PREFIX,'--no-run','--message-format=json-render-diagnostics']
    record={'schema':'history-followup-native-attempt-v1','label':label,'parent':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'command':cmd,'environment':{k:env[k] for k in ['PATH','CARGO_HOME','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','CARGO_PROFILE_TEST_DEBUG']},
        'cargo_lock_sha256':sha(ROOT/'trillionnium/Cargo.lock'),'started_unix':time.time(),'production_qualified':False}
    (out/'attempt.json').write_text(json.dumps(record,indent=2)+'\n')
    with (out/'build.stdout.jsonl').open('w') as stdout,(out/'build.stderr.log').open('w') as stderr:
        built=subprocess.run(cmd,cwd=ROOT,env=env,stdout=stdout,stderr=stderr)
    record['build_returncode']=built.returncode
    after=snapshot();(out/'source-after-build.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n')
    record['source_stable_during_build']=before==after
    if built.returncode==0 and before==after:
        artifacts=[json.loads(line) for line in (out/'build.stdout.jsonl').read_text().splitlines() if line.startswith('{')]
        executables=[x['executable'] for x in artifacts if x.get('reason')=='compiler-artifact'
            and x.get('executable') and x.get('target',{}).get('name')=='trnm_pon_node']
        assert len(executables)==1,executables
        binary=out/'native-test-snapshot.bin'; shutil.copy2(executables[0],binary)
        record['binary']=str(binary); record['binary_sha256']=sha(binary)
        listing=subprocess.run([str(binary),'--list'],text=True,capture_output=True,check=True)
        (out/'test-list.log').write_text(listing.stdout)
        selected=[line for line in listing.stdout.splitlines() if line.startswith(PREFIX)]
        record['selected_tests']=selected
        assert len(selected)==6,selected
        run_cmd=[str(binary),PREFIX,'--test-threads=1','--nocapture']
        record['run_command']=run_cmd
        with (out/'native-tests.log').open('w') as log:
            executed=subprocess.run(run_cmd,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
        record['test_returncode']=executed.returncode
        log=(out/'native-tests.log').read_text()
        record['summary_lines']=[line for line in log.splitlines() if line.startswith('test result:')]
        record['exact_six_passed']=bool(re.search(r'test result: ok\. 6 passed; 0 failed;',log))
        record['binary_stable_after_execution']=record['binary_sha256']==sha(binary)
    final=snapshot();(out/'source-after.json').write_text(json.dumps(final,sort_keys=True,indent=2)+'\n')
    record['source_stable']=before==final
    record['finished_unix']=time.time()
    record['passed']=all(record.get(key,False) for key in ['source_stable','binary_stable_after_execution','exact_six_passed'])
    (out/'attempt.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:record[k] for k in ['label','build_returncode','source_stable','passed']}),flush=True)
    sys.exit(0 if record['passed'] else 1)

if __name__=='__main__':main()
