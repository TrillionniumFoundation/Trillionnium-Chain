import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path('/workspace/scratch/3069292387f3/chain-sqlite')
OUT = pathlib.Path('/workspace/scratch/3069292387f3/sqlite-evidence')
BIN = pathlib.Path('/workspace/scratch/747d27b1ca86/build-setup/rust195/bin')
PHASE = sys.argv[1]
PACKAGES = sys.argv[2:]
ENV = os.environ.copy()
ENV.update(PATH=str(BIN)+':'+ENV['PATH'], RUSTC=str(BIN/'rustc'),
           CARGO_HOME='/workspace/scratch/3069292387f3/sqlite-cargo-home',
           CARGO_TARGET_DIR='/workspace/scratch/3069292387f3/sqlite-target',
           CARGO_BUILD_JOBS='2', CARGO_TERM_COLOR='never')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def snapshot():
    files = [ROOT/'rust-toolchain.toml', ROOT/'trillionnium/Cargo.toml',
             ROOT/'trillionnium/Cargo.lock']
    for package in ['trnm-data-availability', 'trnm-mvcc-fee',
                    'trnm-service-settlement', 'trnm-task-kernel',
                    'trnm-crypto-primitives', 'trnm-protocol']:
        directory = ROOT/'trillionnium/crates'/package
        files.append(directory/'Cargo.toml')
        files.extend(sorted(directory.glob('src/**/*.rs')))
    return {
        'head': subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'scope': 'selected actual crate sources, manifests and workspace lock; partial checkout, not complete repository source qualification',
        'files_sha256': {str(p.relative_to(ROOT)):sha(p) for p in files},
        'rustc_path':str(BIN/'rustc'), 'rustc_sha256':sha(BIN/'rustc'),
    }

receipts=[]
for package in PACKAGES:
    subprocess.run(['bash','scripts/project-preflight.sh'],cwd=ROOT,check=True)
    before=snapshot()
    argv=['cargo','test','--locked','--offline','-p',package,'--lib','sqlite_',
          '--','--nocapture','--test-threads=1']
    prefix=OUT/f'{PHASE}-{package}'
    started=time.time()
    print(json.dumps({'event':'start','phase':PHASE,'package':package,'head':before['head'],'argv':argv}),flush=True)
    with prefix.with_suffix('.stdout').open('w') as stdout, prefix.with_suffix('.stderr').open('w') as stderr:
        try:
            result=subprocess.run(argv,cwd=ROOT/'trillionnium',env=ENV,stdout=stdout,stderr=stderr,timeout=1800)
            exit_code=result.returncode
        except subprocess.TimeoutExpired:
            exit_code=124
    after=snapshot()
    output=prefix.with_suffix('.stdout').read_text()
    diagnostics=prefix.with_suffix('.stderr').read_text()
    native_summaries=re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;',output)
    binaries=[]
    for name in re.findall(r'Running unittests .*? \((.*?)\)',diagnostics):
        path=pathlib.Path(name)
        if not path.is_absolute(): path=ROOT/'trillionnium'/path
        if path.is_file(): binaries.append({'path':str(path),'bytes':path.stat().st_size,'sha256':sha(path)})
    receipt={'phase':PHASE,'package':package,'argv':argv,'started_unix':started,
             'elapsed_seconds':time.time()-started,'exit_code':exit_code,
             'status':'command_succeeded' if exit_code==0 else 'command_failed',
             'native_summaries':native_summaries,'source_before':before,
             'source_after':after,'selected_sources_unchanged':before==after,
             'binaries_after':binaries,
             'environment':{k:ENV.get(k) for k in ['RUSTC','RUSTFLAGS','RUSTC_WRAPPER','CARGO_HOME','CARGO_TARGET_DIR','CARGO_BUILD_JOBS']}}
    for stream in ['stdout','stderr']:
        path=prefix.with_suffix('.'+stream)
        receipt[stream]={'bytes':path.stat().st_size,'sha256':sha(path)}
    prefix.with_suffix('.json').write_text(json.dumps(receipt,indent=2)+'\n')
    receipts.append(receipt)
    print(json.dumps({k:receipt[k] for k in ['phase','package','exit_code','elapsed_seconds','native_summaries','selected_sources_unchanged']}),flush=True)
(OUT/f'{PHASE}-summary.json').write_text(json.dumps(receipts,indent=2)+'\n')
