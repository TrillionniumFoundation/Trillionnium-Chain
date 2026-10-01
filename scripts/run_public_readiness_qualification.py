#!/usr/bin/env python3
"""Source-bound local engineering qualification; never authorizes a public launch.

Preserves every failed command and delegates the full existing native/reference
regression to its actual owner. Long live-clock TCP campaigns are additional evidence.
"""
from __future__ import annotations
import argparse, hashlib, json, os, platform, signal, subprocess, sys, time
from importlib.metadata import version
from cryptography.hazmat.backends.openssl.backend import backend as openssl_backend
from pathlib import Path
from qualification_runtime import bind_python_runtime, read_gnu_time_peak_rss

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ('public_network_ready', 'production_activation', 'independent_accepted',
         'future_window_accepted', 'work_profile_qualified', 'physical_power_loss')
TESTS = ('test_model_attribution', 'test_work_utility', 'test_public_evaluation_lifecycle', 'test_llm_adapter_contract')

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def relevant(path):
    return (path.startswith(('trillionnium/', 'formal/pon-nakamoto-v1/', 'scripts/'))
            and not path.endswith('.md')) or path.startswith('config/pon/') or path.startswith('.github/workflows/')

def run(args):
    if git('status', '--porcelain'):
        raise ValueError('CLEAN_COMMITTED_SOURCE_REQUIRED')
    commit, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
    out = Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=False)
    (out/'logs').mkdir()
    env = dict(os.environ)
    for key in list(env):
        if key.startswith('TRNM_'): env.pop(key)
    env.update(CARGO_HOME=str(Path(args.cargo_home).resolve()), CARGO_TARGET_DIR=str(Path(args.target).resolve()),
               CARGO_BUILD_JOBS='2', CARGO_NET_OFFLINE='true', RUST_TEST_THREADS='1',
               PYTHONDONTWRITEBYTECODE='1', OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1')
    env, child_python3 = bind_python_runtime(env)
    records = []
    report = dict(schema='trnm-public-readiness-engineering-v1', source_commit=commit, source_tree=tree,
        source_clean=True, all_commands_passed=False, source_files_sha256={p:sha(ROOT/p) for p in git('ls-files').splitlines() if relevant(p)},
        environment=dict(platform=platform.platform(), python=platform.python_version(),
            child_python3=child_python3,
            numpy=__import__('numpy').__version__, cryptography=__import__('cryptography').__version__,
            cryptography_openssl=openssl_backend.openssl_version_text(), cffi=version('cffi'),
            rust=subprocess.check_output(['rustc','--version'],text=True).strip(),
            hardware=subprocess.check_output(['lscpu'],text=True),
            filesystem=subprocess.check_output(['findmnt','-T',str(out),'-n','-o','FSTYPE,TARGET'],text=True).strip(),
            cargo_jobs=2, test_threads=1, gpu_used=False, vram_bytes=None),
        results=records, **{flag:False for flag in FLAGS})
    def execute(name, command, timeout=2400):
        log=out/'logs'/(name+'.log'); usage=out/'logs'/(name+'.usage')
        started=time.monotonic_ns(); expired=False
        with log.open('w') as stream:
            process=subprocess.Popen(['/usr/bin/time','-f','%M %U %S','-o',str(usage),*command],
                cwd=ROOT,env=env,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
            try: code=process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                expired=True; os.killpg(process.pid,signal.SIGKILL); code=process.wait()
        row=dict(name=name,command=command,returncode=code,timed_out=expired,
                 elapsed_ns=time.monotonic_ns()-started,log=str(log.relative_to(out)),peak_rss_kib=None,vram_bytes=None)
        row['peak_rss_kib']=read_gnu_time_peak_rss(usage)
        records.append(row); print(json.dumps(row),flush=True)
        if code or expired: raise RuntimeError('QUALIFICATION_FAILED:'+name)
        if git('rev-parse','HEAD')!=commit or git('status','--porcelain'): raise ValueError('SOURCE_CHANGED')
    try:
        execute('evidence-source-negative-tests',[sys.executable,'scripts/ci/test_evidence_sources.py'])
        execute('evidence-source-preparation',[sys.executable,'scripts/ci/prepare_evidence_sources.py'])
        execute('public-readiness-evidence-negative-tests',[sys.executable,'scripts/ci/test_public_readiness_evidence.py'])
        execute('full-native-reference-regression',[sys.executable,'scripts/run_evaluation_qualification.py',
            '--native-node','--source',commit,'--out',str(out/'baseline'),'--target',env['CARGO_TARGET_DIR'],
            '--cargo-home',env['CARGO_HOME']],timeout=10800)
        for test in TESTS:
            execute(test,[sys.executable,'formal/pon-nakamoto-v1/'+test+'.py'])
        execute('transport-sustained-paid-unpaid',['cargo','test','--offline','--locked','--release',
            '--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node','--test','protected_ingress',
            'sustained_protected_socket_cost_campaign','--','--exact','--ignored','--nocapture','--test-threads=1'])
        execute('pipeline-build',['cargo','build','--offline','--locked','--release','--manifest-path','trillionnium/Cargo.toml',
                                '-p','trnm-pon-node','--examples','--bins'])
        binary=Path(env['CARGO_TARGET_DIR'])/'release/examples/continuous_pipeline'
        report['pipeline_binary_sha256']=sha(binary)
        for pattern,profile in [('hot','legacy'),('hot','protected'),('disjoint4','protected'),('growth','protected')]:
            name='pipeline-'+pattern+'-'+profile
            execute(name,[str(binary),str(out/name),str(args.blocks),str(args.batch),str(args.pace_ms),pattern,profile],
                    timeout=(args.blocks+8)*args.pace_ms//1000+300)
        inputs=ROOT/'evidence/pon-native-node-v1/model-current/model'
        # Owner bundle digest uses the ledger-domain framing, never the raw-file SHA.
        sys.path.insert(0,str(ROOT/'formal/pon-nakamoto-v1'))
        from contract_wire import H
        bundle=H('evaluation-bundle-v3',(inputs/'evaluation-bundle.json').read_bytes()).hex()
        execute('bounded-model-attribution',[sys.executable,'formal/pon-nakamoto-v1/experiments/model_attribution_campaign.py',
                    '--inputs',str(inputs),'--bundle-hash',bundle,'--out',str(out/'attribution')])
        report['all_commands_passed']=True
    except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as error:
        report['error']=str(error)
    finally:
        report['source_clean_after']=git('rev-parse','HEAD')==commit and not git('status','--porcelain')
        (out/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
        files={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p != out/'manifest.json'}
        (out/'manifest.json').write_text(json.dumps(dict(schema='trnm-public-readiness-evidence-v1',
            implementation_commit=commit,implementation_tree=tree,files=files,
            source_clean=report['source_clean_after'],all_commands_passed=report['all_commands_passed'],
            **{flag:False for flag in FLAGS}),indent=2)+'\n')
    if not report['all_commands_passed']: raise RuntimeError(report.get('error','INCOMPLETE'))
    print(json.dumps(dict(report=str(out/'qualification.json'),public_network_ready=False)),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',required=True); parser.add_argument('--cargo-home',required=True); parser.add_argument('--target',required=True)
    parser.add_argument('--blocks',type=int,default=20); parser.add_argument('--batch',type=int,default=32)
    parser.add_argument('--pace-ms',type=int,default=10000)
    args=parser.parse_args()
    if not 20<=args.blocks<=4096 or not 1<=args.batch<=256 or not 1000<=args.pace_ms<=60000:
        parser.error('live qualification requires20..4096 blocks,1..256 transactions and1000..60000ms pacing')
    run(args)
