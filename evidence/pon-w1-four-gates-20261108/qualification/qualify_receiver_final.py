#!/usr/bin/env python3
"""Retain real command exits and exact committed source guards, outside checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

ap=argparse.ArgumentParser()
ap.add_argument('--repo',required=True,type=Path)
ap.add_argument('--head',required=True)
ap.add_argument('--out',required=True,type=Path)
ap.add_argument('--plan',required=True,type=Path)
ap.add_argument('--target',type=Path)
args=ap.parse_args()
args.out.mkdir(parents=True,exist_ok=False)
plan=json.loads(args.plan.read_text())
env=os.environ.copy()
env.update(PYTHONDONTWRITEBYTECODE='1',RUSTUP_TOOLCHAIN='1.95.0',
           CARGO_BUILD_JOBS='8',CARGO_INCREMENTAL='0',
           RUSTC='/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc',
           RUSTDOC='/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustdoc',
           TRNM_CI_RECEIPT_DIR=str(args.out/'ci-receipts'))
for key in ('RUSTC','RUSTDOC'):
    env[key]=str(Path(env[key]).resolve(strict=True))
if args.target:env['CARGO_TARGET_DIR']=str(args.target)
env['PATH']='/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin:/home/qian-qi/.cargo/bin:'+env.get('PATH','')
manifest={'schema':'TRNM-W1-EXACT-SOURCE-QUALIFICATION4','source_commit':args.head,
          'repo':str(args.repo),'plan_sha256':hashlib.sha256(args.plan.read_bytes()).hexdigest(),
          'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'commands':[],'fresh_proof_generations':0,'production_qualified':False,
          'security_qualified':False,'original_business_budget_qualified':False,
          'resource_billing_complete':False,'payment_qualified':False,
          'cargo_target':str(args.target) if args.target else None,
          'build_env':{k:env[k] for k in ('RUSTUP_TOOLCHAIN','CARGO_BUILD_JOBS','CARGO_INCREMENTAL','RUSTC','RUSTDOC')},
          'verifier_source_commit':'034aa74358e0a5fa33f33e83cb63669e9738da4b',
          'fresh_cargo_target':False,'independent_reproducible_build_established':False,
          'cache_basis':'separate copied development cache, when Cargo runs',
          'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}

def save():
    (args.out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')

def run(label,argv,cwd=None,timeout=900):
    record={'label':label,'argv':argv,'cwd':str(cwd or args.repo),
            'started_monotonic_ns':time.monotonic_ns()}
    so=args.out/(label+'.stdout');se=args.out/(label+'.stderr')
    with so.open('xb') as stdout,se.open('xb') as stderr:
        try:
            p=subprocess.run(argv,cwd=cwd or args.repo,env=env,stdin=subprocess.DEVNULL,
                             stdout=stdout,stderr=stderr,timeout=timeout)
            record['exit']=p.returncode
        except subprocess.TimeoutExpired:
            record['exit']=None;record['timeout']=True
    record['finished_monotonic_ns']=time.monotonic_ns()
    combined=so.read_text(errors='replace')+'\n'+se.read_text(errors='replace')
    record['python_test_counts']=[int(n) for n in re.findall(r'^Ran ([0-9]+) tests? in ',combined,re.M)]
    record['rust_test_outcomes']=[{'passed':int(p),'failed':int(f),'ignored':int(i)} for p,f,i in re.findall(r'test result: [^.]+\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;',combined)]
    for k,p in [('stdout',so),('stderr',se)]:
        b=p.read_bytes();record[k]={'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
    manifest['commands'].append(record);save()
    print(json.dumps({k:record[k] for k in ('label','exit','python_test_counts','rust_test_outcomes')}),flush=True)
    return record['exit']==0

if not run('00-preflight',['bash','scripts/project-preflight.sh','--dev']):raise SystemExit(1)
guard=['python3','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',args.head,'--output']
if not run('01-source-before',guard+[str(args.out/'source-before.json')]):raise SystemExit(1)
manifest['source_tree']=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=args.repo,text=True).strip()
if plan.get('extract_w1_block'):
    lines=(args.repo/'scripts/ci/ci_job.sh').read_text().splitlines()
    start=[i for i,l in enumerate(lines) if 'w1_contract_out=' in l]
    if len(start)!=1 or lines[start[0]-1].strip()!='(':raise RuntimeError('exact W1 command block start changed')
    end=next(i for i in range(start[0],len(lines)) if lines[i]=='    )')
    block='#!/usr/bin/env bash\nset -euo pipefail\n'+'\n'.join(lines[start[0]-1:end+1])+'\n'
    p=args.out/'w1-current-command-block.sh';p.write_text(block)
    manifest['ci_command_block_sha256']=hashlib.sha256(block.encode()).hexdigest()
all_ok=True
for idx,item in enumerate(plan['commands'],start=2):
    argv=[v.replace('@REPO@',str(args.repo)).replace('@OUT@',str(args.out)).replace('@HEAD@',args.head) for v in item['argv']]
    cwd=args.repo/item.get('cwd','')
    all_ok=run(f"{idx:02d}-"+item['label'],argv,cwd,item.get('timeout',900)) and all_ok
all_ok=run('99-source-after',guard+[str(args.out/'source-after.json')]) and all_ok
manifest['qualification_complete']=all_ok
manifest['actual_command_count']=len(manifest['commands'])
manifest['python_test_methods_reported']=sum(sum(c['python_test_counts']) for c in manifest['commands'])
manifest['rust_test_outcomes']={k:sum(r[k] for c in manifest['commands'] for r in c['rust_test_outcomes']) for k in ('passed','failed','ignored')}
save()
print(json.dumps({k:manifest[k] for k in ('qualification_complete','actual_command_count','python_test_methods_reported','rust_test_outcomes')}),flush=True)
raise SystemExit(0 if all_ok else 1)
