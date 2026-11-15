#!/usr/bin/env python3
"""Required strict Clippy on the fixed candidate, with an owned process group."""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

root = Path('/workspace/scratch/822cc50e24f0/round2-chain-green')
target = Path('/workspace/scratch/822cc50e24f0/state-scheduling-restored/native-target-canonical')
out = Path('/workspace/scratch/822cc50e24f0/round2-evidence/strict-clippy')
monitor = Path('/workspace/scratch/822cc50e24f0/state-scheduling-restored/run-bounded.py')
compiler = Path('/root/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc')
expected = 'b5bb7bc8d7ffe79d46c6a58fd5189e2bb9e4550c'
tree = '8be28a72673ce318d60a464898ab610d9ba39216'
assert compiler.resolve(strict=True) == compiler
assert hashlib.sha256(compiler.read_bytes()).hexdigest() == 'bff349e72704ff70bc08a234a3847338e797065bbedde5e556808bc87b7bf7c6'
assert hashlib.sha256(monitor.read_bytes()).hexdigest() == 'ae20081596e452c1f0b8a5f7db17acc0fba650e840fed9a9914bdedd24cba52f'
definitions = [n for n in ast.parse(monitor.read_text()).body if isinstance(n, ast.FunctionDef)
               and n.name in {'available_memory_estimate', 'memory', 'oom_increased'}]
assert len(definitions) == 3
exec(compile(ast.Module(body=definitions, type_ignores=[]), str(monitor), 'exec'))
overrides = {'PATH':'/root/.cargo/bin:' + os.environ.get('PATH',''),
             'CARGO_HOME':'/root/.cargo', 'RUSTUP_HOME':'/root/.rustup',
             'RUSTUP_TOOLCHAIN':'1.95.0-x86_64-unknown-linux-gnu',
             'RUSTC':str(compiler), 'CARGO_TARGET_DIR':str(target),
             'CARGO_BUILD_JOBS':'1', 'CARGO_INCREMENTAL':'0', 'CARGO_NET_OFFLINE':'true',
             'PYTHONDONTWRITEBYTECODE':'1', 'GIT_OPTIONAL_LOCKS':'0'}
env = dict(os.environ, **overrides)
unset = ['RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS']
for key in unset:
    env.pop(key, None)
def git(*a):
    return subprocess.check_output(['git', *a], cwd=root, env=env, text=True).strip()
assert git('rev-parse','HEAD') == expected and git('rev-parse','HEAD^{tree}') == tree
assert not git('status','--porcelain=v1','--untracked-files=all')
out.mkdir(exist_ok=False)
preflight = subprocess.run(['bash','scripts/project-preflight.sh'], cwd=root, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
(out/'preflight.log').write_text(preflight.stdout)
command = ['/root/.cargo/bin/cargo','+1.95.0','clippy','--locked','--offline',
           '--manifest-path','trillionnium/Cargo.toml','--workspace','--all-targets',
           '--all-features','--','-D','warnings']
before = memory()
record = {'schema':'trnm-fixed-pair-strict-clippy-v1','chain_sha':expected,'chain_tree':tree,
          'runtime_sha':'d206c3c787f6b67c771b67a8e1d46c8261810042',
          'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'argv':command,'cwd':str(root),'environment_overrides':overrides,'environment_unset':unset,
          'scope':'Required original workspace/all-target/all-feature Clippy; no native tests and no performance acceptance',
          'timeout_seconds':1200,'available_memory_floor_bytes':512*1024*1024,
          'storage_floor_bytes':128*1024*1024,'memory_before':before,
          'memory_monitor_sha256':hashlib.sha256(monitor.read_bytes()).hexdigest(),
          'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'compiler_sha256':hashlib.sha256(compiler.read_bytes()).hexdigest(),
          'compiler_version':subprocess.check_output([str(compiler),'-vV'],text=True),
          'preflight_exit_code':preflight.returncode,'result':'PREFLIGHT','exit_code':None,
          'native_tests_executed':False,'production_activation':False}
def save():
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
if preflight.returncode or before['effective_available'] < 512*1024*1024 or shutil.disk_usage(target).free < 128*1024*1024:
    record['result']='PREFLIGHT_BLOCKED';save();print(json.dumps(record));raise SystemExit(2)
process = None
signals = []
def stop():
    if process is not None and process.poll() is None:
        os.killpg(process.pid,signal.SIGTERM)
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL);process.wait()
def interrupt(signum,frame):
    signals.append(signum);stop()
signal.signal(signal.SIGINT,interrupt)
signal.signal(signal.SIGTERM,interrupt)
start=time.monotonic()
record.update(result='RUNNING',min_available_memory_bytes=before['effective_available'])
save()
try:
    with (out/'cargo.log').open('wb') as log:
        process=subprocess.Popen(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        record['cargo_pid']=process.pid;save();next_report=0
        while process.poll() is None:
            elapsed=time.monotonic()-start;sample=memory();available=sample['effective_available']
            record['min_available_memory_bytes']=min(record['min_available_memory_bytes'],available)
            if oom_increased(before,sample): record['abort_reason']='OOM_OBSERVED'
            elif sample.get('estimate_error'):record['abort_reason']='MEMORY_MONITOR_ERROR'
            elif elapsed>=1200:record['abort_reason']='TIMEOUT'
            elif available<512*1024*1024:record['abort_reason']='ABORTED_RESOURCE'
            elif shutil.disk_usage(target).free<128*1024*1024:record['abort_reason']='ABORTED_STORAGE'
            if record.get('abort_reason'):stop();break
            if elapsed>=next_report:
                print(json.dumps({'stage':'strict-clippy','elapsed_seconds':round(elapsed),'available_estimate':available}),flush=True)
                next_report=elapsed+25
            time.sleep(.5)
        record['exit_code']=process.returncode
except BaseException as error:
    stop();record['runner_error']=str(error)
finally:
    record['wall_seconds']=round(time.monotonic()-start,6)
    record['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    record['memory_after']=memory()
    record['memory_events_delta']={k:record['memory_after'].get('event_counters',{}).get(k,0)-v for k,v in before.get('event_counters',{}).items()}
    record['head_after']=git('rev-parse','HEAD');record['tree_after']=git('rev-parse','HEAD^{tree}')
    record['status_after']=git('status','--porcelain=v1','--untracked-files=all')
    raw=(out/'cargo.log').read_bytes();record['log_sha256']=hashlib.sha256(raw).hexdigest();record['log_bytes']=len(raw)
    record['result']=record.get('abort_reason','PASS' if record['exit_code']==0 else 'FAIL')
    if 'runner_error' in record:record['result']='RUNNER_ERROR'
    if signals:record.update(result='INTERRUPTED',signals=signals)
    if oom_increased(before,record['memory_after']):record['result']='OOM_OBSERVED'
    if record['memory_after'].get('estimate_error') or any(v<0 for v in record['memory_events_delta'].values()):record['result']='MEMORY_MONITOR_ERROR'
    if record['head_after']!=expected or record['tree_after']!=tree or record['status_after']:record['result']='SOURCE_CHANGED'
    save();print(json.dumps({k:record[k] for k in ['result','exit_code','wall_seconds','min_available_memory_bytes','log_sha256']}),flush=True)
    print(raw.decode(errors='replace')[-6000:],flush=True)
raise SystemExit(0 if record['result']=='PASS' else 1)
