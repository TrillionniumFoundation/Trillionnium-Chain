#!/usr/bin/env python3
"""Run and preserve one source-bound native local V3 campaign, including failed outcomes."""
from __future__ import annotations
import argparse
import json
import os
import platform
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/ci'))
from check_public_readiness_evidence import git, sha, source_inventory
from check_public_v3_service_campaign import TEST, FLAGS, validate_bundle

def run(out):
    out=Path(out).resolve()
    if out.is_relative_to(ROOT): raise ValueError('observation directory must be outside source checkout')
    if git(ROOT,'status','--porcelain'): raise ValueError('CLEAN_COMMITTED_SOURCE_REQUIRED')
    commit,tree=git(ROOT,'rev-parse','HEAD'),git(ROOT,'rev-parse','HEAD^{tree}')
    out.mkdir(parents=True,exist_ok=False)
    manifest=dict(schema='public-v3-local-service-bundle-v2',source_commit=commit,source_tree=tree,
        source_files_sha256=source_inventory(ROOT,commit),source_clean_before=True,source_clean_after=False,
        source_changed=False,timed_out=False,build_returncode=None,run_returncode=None,negative_returncode=None,
        binary_sha256_before=None,binary_sha256_after=None,commands=[],**{k:False for k in FLAGS})
    manifest['environment']=dict(platform=platform.platform(),python=sys.version,
        rustc=subprocess.check_output(['rustc','--version'],text=True).strip(),
        cargo=subprocess.check_output(['cargo','--version'],text=True).strip(),
        profile='test (not release)',build_jobs=1,test_threads=1,
        selected_build_env={k:os.environ.get(k) for k in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_PROFILE_DEV_DEBUG','CARGO_BUILD_TARGET')})
    env={k:v for k,v in os.environ.items() if not k.startswith('TRNM_')}
    env.update(CARGO_BUILD_JOBS='1',CARGO_NET_OFFLINE='true',RUST_TEST_THREADS='1',
               PYTHONDONTWRITEBYTECODE='1',TRNM_PUBLIC_V3_CAMPAIGN_DIR=str(out/'native'))
    def execute(name,command,timeout):
        start=time.monotonic_ns()
        with (out/(name+'.log')).open('wb') as log:
            process=subprocess.Popen(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try: result=process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                manifest['timed_out']=True;os.killpg(process.pid,signal.SIGKILL);result=process.wait()
        manifest['commands'].append(dict(name=name,command=command,returncode=result,elapsed_ns=time.monotonic_ns()-start))
        return result
    try:
        command=['cargo','test','--offline','--locked','--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node',
                 '--test','public_v3_service_campaign','--no-run','--message-format=json']
        manifest['build_returncode']=execute('build',command,600)
        if manifest['build_returncode']: raise ValueError('NATIVE_BUILD_FAILED')
        executables=[]
        for line in (out/'build.log').read_text().splitlines():
            if line.startswith('{'):
                row=json.loads(line)
                if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='public_v3_service_campaign' and row.get('executable'):
                    executables.append(Path(row['executable']).resolve())
        if len(executables)!=1: raise ValueError('EXACT_NATIVE_TEST_BINARY_REQUIRED')
        binary=executables[0]
        manifest['binary_sha256_before']=sha(binary.read_bytes())
        manifest['run_returncode']=execute('run',[str(binary),TEST,'--exact','--nocapture','--test-threads=1'],90)
        manifest['binary_sha256_after']=sha(binary.read_bytes())
        if manifest['run_returncode']: raise ValueError('NATIVE_CAMPAIGN_FAILED')
        manifest['negative_returncode']=execute('negative',[sys.executable,'scripts/ci/test_public_v3_service_campaign.py','--report',str(out/'native/report.json')],60)
        if manifest['negative_returncode']: raise ValueError('NEGATIVE_VALIDATION_TESTS_FAILED')
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        manifest['failure']=str(error)
    finally:
        manifest['source_clean_after']=git(ROOT,'rev-parse','HEAD')==commit and not git(ROOT,'status','--porcelain')
        manifest['source_changed']=not manifest['source_clean_after']
        manifest['files']={p.relative_to(out).as_posix():sha(p.read_bytes()) for p in sorted(out.rglob('*')) if p.is_file()}
        (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    result=validate_bundle(out)
    print(json.dumps(dict(result,observation=str(out)),sort_keys=True))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',required=True)
    run(parser.parse_args().out)
