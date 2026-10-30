#!/usr/bin/env python3
"""Exact source/build/execution binding for the original 25-package V6 slice."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time

ROOT=Path('/workspace/scratch/301262829a43/pon-pq-impl/history-v6')
HERE=Path(__file__).resolve().parent
PREFIX='store::history_effect_v6::tests::'
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1<<20),b''):h.update(chunk)
    return h.hexdigest()
def snapshot():
    names=subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=ROOT).split(b'\0')
    return {n.decode():sha(ROOT/n.decode()) for n in sorted(set(names)) if n and not n.startswith(b'evidence/') and (ROOT/n.decode()).is_file()}
def main():
    out=HERE/sys.argv[1];out.mkdir(exist_ok=False)
    unique=HERE.parent/'history-evidence/native-attempt-07-nonce-and-pidfd/native-test-snapshot.bin'
    assert sha(unique)=='76aeb191a35b1d13702346cab6b077b392266ba3e83c477e692944ddae8d86d7'
    env=os.environ.copy();env.update(PATH='/workspace/scratch/301262829a43/pon-build-inputs/unpacked/toolchain/bin:'+env['PATH'],
        CARGO_HOME='/workspace/scratch/301262829a43/pon-build-inputs/original-cargo-home',CARGO_TARGET_DIR='/tmp/pon-history-final-20261027',
        CARGO_BUILD_JOBS='1',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0')
    assert not env.get('RUSTFLAGS') and not env.get('CARGO_ENCODED_RUSTFLAGS')
    before=snapshot();(out/'source-before.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
    (out/'source.patch').write_bytes(subprocess.check_output(['git','diff','--binary','HEAD'],cwd=ROOT))
    added=subprocess.check_output(['git','ls-files','--others','--exclude-standard','-z'],cwd=ROOT).split(b'\0')
    with tarfile.open(out/'untracked-source.tar.gz','w:gz') as tar:
        for name in added:
            if name and not name.startswith(b'evidence/') and (ROOT/name.decode()).is_file():tar.add(ROOT/name.decode(),arcname=name.decode())
    command=['cargo','test','--offline','--locked','--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node','--lib','--no-run','--message-format=json-render-diagnostics']
    record={'schema':'history-effect-v6-native-attempt-v1','base':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'started_unix':time.time(),'command':command,'cargo_lock_sha256':sha(ROOT/'trillionnium/Cargo.lock'),
        'environment':{k:env[k] for k in ('PATH','CARGO_HOME','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','CARGO_PROFILE_TEST_DEBUG','CARGO_INCREMENTAL')},'production_qualified':False}
    (out/'attempt.json').write_text(json.dumps(record,indent=2)+'\n')
    with (out/'build.stdout.jsonl').open('w') as stdout,(out/'build.stderr.log').open('w') as stderr:
        built=subprocess.run(command,cwd=ROOT,env=env,stdout=stdout,stderr=stderr)
    record['build_returncode']=built.returncode
    after=snapshot();(out/'source-after-build.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n')
    record['source_stable_during_build']=before==after
    if built.returncode==0 and before==after:
        rows=[json.loads(s) for s in (out/'build.stdout.jsonl').read_text().splitlines() if s.startswith('{')]
        executables=[r['executable'] for r in rows if r.get('reason')=='compiler-artifact' and r.get('executable') and r.get('target',{}).get('name')=='trnm_pon_node']
        assert len(executables)==1,executables
        binary=out/'native-test-snapshot.bin';shutil.copy2(executables[0],binary)
        record['binary']=str(binary);record['binary_sha256']=sha(binary)
        listing=subprocess.check_output([str(binary),'--list'],text=True);(out/'test-list.log').write_text(listing)
        selected=[s for s in listing.splitlines() if s.startswith(PREFIX)]
        record['selected_tests']=selected;assert len(selected)==5,selected
        env['TRNM_HISTORY_V6_ARTIFACT_DIR']=str(out/'native-artifacts')
        command=[str(binary),PREFIX,'--test-threads=1','--nocapture'];record['test_command']=command
        with (out/'native-tests.log').open('w') as log:executed=subprocess.run(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
        record['test_returncode']=executed.returncode
        raw=(out/'native-tests.log').read_text();record['summaries']=[s for s in raw.splitlines() if s.startswith('test result:')]
        record['required_summary']=bool(re.search(r'test result: ok\. 4 passed; 0 failed; 1 ignored;',raw))
        record['binary_stable']=sha(binary)==record['binary_sha256']
    after=snapshot();(out/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n')
    record['source_stable']=before==after;record['finished_unix']=time.time()
    record['passed']=all(record.get(k,False) for k in ('source_stable','binary_stable','required_summary'))
    (out/'attempt.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:record[k] for k in ('build_returncode','source_stable','passed')}),flush=True)
    return 0 if record['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
