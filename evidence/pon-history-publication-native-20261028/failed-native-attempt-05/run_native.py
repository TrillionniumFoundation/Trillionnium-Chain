#!/usr/bin/env python3
"""Source-bound local native build/tests; deadlines never turn late exit into PASS."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE = '8d7741028eb650f0600e61fcab46ff3d14b50767'
TOOLCHAIN = Path('/workspace/scratch/301262829a43/pon-build-inputs/unpacked/toolchain/bin')
TARGET = Path('/tmp/pon-history-epoch-v1-20261028')
FREE_FLOOR = 256 * 1024 * 1024
LOG_LIMIT = 32 * 1024 * 1024

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')

def sources():
    rows = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT).decode().split('\0')
    return {row:sha(ROOT/row) for row in sorted(set(rows))
            if row and not row.startswith('evidence/') and (ROOT/row).is_file()}

def disk():
    v=os.statvfs('/tmp')
    return {'free_bytes':v.f_bfree*v.f_frsize,'available_bytes':v.f_bavail*v.f_frsize}

def environment():
    env=os.environ.copy()
    env.update(PATH=str(TOOLCHAIN)+os.pathsep+env.get('PATH',''),
        CARGO_HOME=str(ROOT.parent/'history-cargo-home'),
        CARGO_TARGET_DIR=str(TARGET),CARGO_BUILD_JOBS='1',CARGO_INCREMENTAL='0',
        CARGO_PROFILE_TEST_DEBUG='0',CARGO_NET_OFFLINE='true')
    return env

def bounded(command, out, budget, env):
    out.mkdir(exist_ok=False)
    started_unix,start=time.time(),time.monotonic()
    result={'command':command,'budget_seconds':budget,'started_unix':started_unix,
        'disk_before':disk(),'deadline_policy':'terminal-observation-must-not-exceed-budget',
        'free_floor_bytes':FREE_FLOOR,'log_limit_bytes':LOG_LIMIT,
        'native_returncode':None,'termination_reason':None,'uid':os.getuid(),
        'child_ownership':'direct subprocess with new session; only owned PID/process group signalled'}
    write(out/'started.json',result)
    if result['disk_before']['free_bytes']<FREE_FLOOR:
        result.update(outcome='RESOURCE_ABORT_BEFORE_START',passed=False)
        write(out/'process-receipt.json',result)
        return result
    logpath=out/'native.log'
    with logpath.open('wb',buffering=0) as log, (out/'samples.jsonl').open('w',buffering=1) as samples:
        child=subprocess.Popen(command,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,
            stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        result['owned_namespace_pid']=child.pid
        write(out/'started.json',result)
        stopped=None
        while True:
            pid,status,usage=os.wait4(child.pid,os.WNOHANG)
            now=time.monotonic()
            elapsed=now-start
            if pid:
                assert pid==child.pid
                child.returncode=os.waitstatus_to_exitcode(status)
                result.update(native_returncode=child.returncode,wait4_status=status,
                    terminal_observed_elapsed_seconds=elapsed,
                    reported_user_seconds=usage.ru_utime,reported_system_seconds=usage.ru_stime,
                    max_rss_kib=usage.ru_maxrss)
                if stopped is None and elapsed>budget:
                    result['termination_reason']='LATE_TERMINAL_OBSERVATION'
                break
            sample={'elapsed_seconds':elapsed,'disk':disk(),'log_bytes':logpath.stat().st_size}
            samples.write(json.dumps(sample,sort_keys=True)+'\n')
            reason=('TIMEOUT' if elapsed>=budget else
                    'RESOURCE_ABORT_DISK' if sample['disk']['free_bytes']<FREE_FLOOR else
                    'RESOURCE_ABORT_LOG' if sample['log_bytes']>LOG_LIMIT else None)
            if stopped is None and reason:
                result['termination_reason']=reason
                result['termination_elapsed_seconds']=elapsed
                try:os.killpg(child.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                stopped=now
            elif stopped is not None and now-stopped>=10:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
            time.sleep(0.1 if stopped else min(0.5,max(0.01,budget-elapsed)))
    result.update(finished_unix=time.time(),elapsed_seconds=time.monotonic()-start,
        disk_after=disk(),log_sha256=sha(logpath),samples_sha256=sha(out/'samples.jsonl'))
    result['outcome']=result['termination_reason'] or ('EXIT_ZERO' if result['native_returncode']==0 else 'EXIT_NONZERO')
    result['passed']=result['native_returncode']==0 and result['termination_reason'] is None
    write(out/'process-receipt.json',result)
    return result

def build():
    subprocess.run(['bash','scripts/project-preflight.sh'],cwd=ROOT,check=True)
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==BASE
    with (TARGET/'.history-publication-build.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        memory={}
        for name in ['memory.max','memory.current','memory.events']:
            p=Path('/sys/fs/cgroup')/name
            try:memory[name]=p.read_text()
            except OSError as exc:memory[name]={'error':str(exc)}
        write(HERE/'resource-before-build.json',{'disk':disk(),'cgroup':memory,
            'exclusive_build_owner_lock_acquired':True,'target_reused':str(TARGET),
            'profile_changes':{'CARGO_PROFILE_TEST_DEBUG':'0'},'jobs':1})
        before=sources();write(HERE/'source-before-build.json',before)
        command=[str(TOOLCHAIN/'cargo'),'test','--offline','--locked','--manifest-path','trillionnium/Cargo.toml',
                 '--config','profile.test.package.trnm-pon-node.opt-level=0','-p','trnm-pon-node','--lib','--no-run','--message-format=json-render-diagnostics']
        result=bounded(command,HERE/'build-05',1800,environment())
        after=sources();write(HERE/'source-after-build.json',after)
        binary=None
        for line in (HERE/'build-05/native.log').read_text().splitlines():
            try:row=json.loads(line)
            except json.JSONDecodeError:continue
            if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='trnm_pon_node' and row.get('profile',{}).get('test') and row.get('executable'):
                binary=Path(row['executable'])
        result.update(schema='history-publication-native-build-v1',base_commit=BASE,
            source_stable=before==after,binary=str(binary) if binary else None,
            binary_sha256=sha(binary) if binary else None,runner_sha256=sha(__file__))
        result['passed']=result['passed'] and before==after and binary is not None
        write(HERE/'build-receipt.json',result)
        print(json.dumps(result),flush=True)
        return 0 if result['passed'] else 1

def tests():
    build_result=json.loads((HERE/'build-receipt.json').read_text())
    assert build_result['passed']
    binary=Path(build_result['binary'])
    assert sha(binary)==build_result['binary_sha256']
    before=sources();assert before==json.loads((HERE/'source-after-build.json').read_text())
    listing=subprocess.check_output([str(binary),'--list'],cwd=ROOT,text=True,timeout=30)
    (HERE/'test-inventory.log').write_text(listing)
    names=[line.removesuffix(': test') for line in listing.splitlines() if line.endswith(': test')]
    selector='store::history_effect_v6::tests::'
    selected=[name for name in names if selector in name]
    assert len(selected)==16,selected
    out=HERE/'native-02'
    env=environment();env['TRNM_HISTORY_V6_ARTIFACT_DIR']=str(out/'artifacts')
    result=bounded([str(binary),selector,'--test-threads=1','--nocapture'],out,600,env)
    after=sources();write(HERE/'source-after-tests.json',after)
    raw=(out/'native.log').read_text()
    result.update(schema='history-publication-native-tests-v1',selected=selected,
        source_stable=before==after,binary_stable=sha(binary)==build_result['binary_sha256'],
        binary_sha256=build_result['binary_sha256'],runner_sha256=sha(__file__),
        summaries=re.findall(r'^test result: .+$',raw,re.M),whole_history_p0_closed=False,production_qualified=False)
    result['passed']=(result['passed'] and result['source_stable'] and result['binary_stable']
        and 'running 16 tests' in raw and 'test result: ok. 15 passed; 0 failed; 1 ignored;' in raw)
    write(HERE/'tests-receipt.json',result)
    print(json.dumps(result),flush=True)
    return 0 if result['passed'] else 1

if __name__=='__main__':
    raise SystemExit({'build':build,'tests':tests}[sys.argv[1]]())
