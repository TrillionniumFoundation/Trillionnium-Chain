#!/usr/bin/env python3
"""Resolve the two explicit native-runner skips without changing original tests."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/workspace/scratch/68dd104c2e6a/chain-lifecycle')
OUT = Path(sys.argv[1]).resolve()
OUT.mkdir(parents=True, exist_ok=False)
HEAD = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
if HEAD != '2d71bd943e88fb25d19c2d86feb09b86657a87d3':
    raise SystemExit('Unexpected source head')
ENV = os.environ.copy()
ENV.update({
    'PATH': '/workspace/scratch/d95a703b8dd6/toolchain/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin:' + ENV['PATH'],
    'CARGO_HOME': '/workspace/scratch/d95a703b8dd6/toolchain/cargo',
    'CARGO_TARGET_DIR': '/workspace/scratch/68dd104c2e6a/cargo-target',
    'CARGO_INCREMENTAL': '0', 'CARGO_PROFILE_DEV_DEBUG': '0',
    'CARGO_PROFILE_TEST_DEBUG': '0', 'CARGO_BUILD_JOBS': '2',
    'RUST_TEST_THREADS': '1', 'PYTHONDONTWRITEBYTECODE': '1',
})
rows = []

def run(name, argv, cwd=ROOT):
    start = time.time()
    with (OUT / (name + '.log')).open('xb') as stream:
        result = subprocess.run(argv, cwd=cwd, env=ENV, stdout=stream,
                                stderr=subprocess.STDOUT, check=False)
    row = dict(name=name, command=argv, source_commit=HEAD,
               cwd_relative_to_source=str(Path(cwd).relative_to(ROOT)),
               started_unix_seconds=start, duration_seconds=time.time()-start,
               exit_code=result.returncode, log=name+'.log')
    rows.append(row)
    print(json.dumps({k:row[k] for k in ('name','exit_code','duration_seconds')}), flush=True)
    return result.returncode

def source(label):
    return run(label,[sys.executable,'scripts/ci/verify_ci_source.py','--kind','head',
                      '--expected-head',HEAD,'--output',str(OUT/(label+'.json'))])

if source('source-before'):
    raise SystemExit(1)
run('preflight',['bash','scripts/project-preflight.sh'])
built = run('grouped-native-build',['cargo','build','--locked','--offline','-p',
             'trnm-crypto-primitives','--example','pon_routed_int257_grouped'],ROOT/'trillionnium')
identity = None
if built == 0:
    binary=Path(ENV['CARGO_TARGET_DIR'])/'debug/examples/pon_routed_int257_grouped'
    before=hashlib.sha256(binary.read_bytes()).hexdigest()
    ENV['TRNM_GROUPED_NATIVE']=str(binary)
    run('grouped-native-complete-suite',[sys.executable,
          'formal/pon-nakamoto-v1/test_grouped_cell_operator_v0.py','-v'])
    after=hashlib.sha256(binary.read_bytes()).hexdigest()
    identity={'path':str(binary),'sha256_before':before,'sha256_after':after,
              'unchanged':before==after,'bytes':binary.stat().st_size}
source('source-after')
artifacts=[]
for path in sorted(OUT.iterdir()):
    raw=path.read_bytes()
    artifacts.append({'path':path.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
report={'schema':'pon-grouped-native-supplement-v1','source_commit':HEAD,
        'status':'PASS' if all(r['exit_code']==0 for r in rows) and identity and identity['unchanged'] else 'FAIL',
        'commands':rows,'artifacts':artifacts,'native_binary':identity,
        'initial_two_skips_preserved':True,'qualification':'HOLD_NO_GO',
        'performance_comparison_qualified':False,'work_profile_qualified':False}
(OUT/'manifest.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':report['status'],'commands':len(rows)}),flush=True)
raise SystemExit(0 if report['status']=='PASS' else 1)
