#!/usr/bin/env python3
"""Capture actual bounded native regression processes, without full-repository attestation."""
import argparse, hashlib, json, os, platform, resource, subprocess, time
from pathlib import Path

parser=argparse.ArgumentParser()
parser.add_argument('--label', required=True)
parser.add_argument('--cwd', required=True)
parser.add_argument('--out', required=True)
parser.add_argument('--timeout', type=int, default=600)
parser.add_argument('command', nargs=argparse.REMAINDER)
args=parser.parse_args()
command=args.command[1:] if args.command[:1]==['--'] else args.command
root=Path(args.cwd).resolve(); out=Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=True)

def git(*argv):
    return subprocess.check_output(['git','-C',str(root),*argv])

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1<<20),b''): h.update(chunk)
    return h.hexdigest()

def source_snapshot():
    patterns=['trillionnium','config','scripts/ci/ci_job.sh','scripts/ci/check_ci_contract.py','scripts/ci/test_ci_contract.py']
    paths=[p.decode() for p in git('ls-files','-z','--',*patterns).split(b'\0') if p]
    files=[]; absent=[]
    for rel in paths:
        p=root/rel
        if p.is_file(): files.append({'path':rel,'bytes':p.stat().st_size,'sha256':digest(p)})
        else: absent.append(rel)
    return {'schema':'pon-mining-time-source-binding-v1','scope':'tracked native workspace, config and three CI contract files',
            'source_commit':git('rev-parse','HEAD').decode().strip(),'source_tree':git('rev-parse','HEAD^{tree}').decode().strip(),
            'sparse_checkout':True,'full_source_inventory_claimed':False,
            'tracked_scope_diff':git('diff','HEAD','--',*patterns).decode(),
            'absent_in_scope':absent,'files':files}

def write(name,obj):
    (out/(args.label+'.'+name+'.json')).write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n')

before=source_snapshot(); write('source-before',before)
exe=Path(command[0])
exe_before={'path':str(exe),'bytes':exe.stat().st_size,'sha256':digest(exe)} if exe.is_absolute() and exe.is_file() else None
started=time.time_ns(); mono=time.monotonic_ns(); usage=resource.getrusage(resource.RUSAGE_CHILDREN)
with (out/(args.label+'.stdout.log')).open('wb') as stdout, (out/(args.label+'.stderr.log')).open('wb') as stderr:
    try:
        child=subprocess.run(command,cwd=root,stdout=stdout,stderr=stderr,timeout=args.timeout)
        exit_code=child.returncode; timed_out=False
    except subprocess.TimeoutExpired:
        exit_code=None; timed_out=True
elapsed=time.monotonic_ns()-mono; ended=time.time_ns(); after_usage=resource.getrusage(resource.RUSAGE_CHILDREN)
after=source_snapshot(); write('source-after',after)
exe_after={'path':str(exe),'bytes':exe.stat().st_size,'sha256':digest(exe)} if exe_before else None
allowed_env=('RUSTUP_HOME','CARGO_HOME','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','CARGO_INCREMENTAL','CARGO_PROFILE_TEST_DEBUG','RUSTFLAGS','RUSTC','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_ENCODED_RUSTFLAGS')
record={'schema':'pon-mining-time-process-v1','argv':command,'cwd':str(root),'started_unix_ns':started,'ended_unix_ns':ended,
 'elapsed_monotonic_ns':elapsed,'outer_timeout_seconds':args.timeout,'timed_out':timed_out,'exit_code':exit_code,
 'children_user_seconds':after_usage.ru_utime-usage.ru_utime,'children_system_seconds':after_usage.ru_stime-usage.ru_stime,
 'children_maxrss_kib':after_usage.ru_maxrss,'source_commit':before['source_commit'],'source_tree':before['source_tree'],
 'source_inputs_unchanged':before==after,'sparse_checkout':True,'full_source_inventory_claimed':False,
 'binary_before':exe_before,'binary_after':exe_after,'binary_unchanged':exe_before==exe_after,
 'environment':{k:os.environ.get(k) for k in allowed_env},
 'platform':platform.platform(),'machine':platform.machine(),'cpu_affinity':sorted(os.sched_getaffinity(0)),
 'nice':os.getpriority(os.PRIO_PROCESS,0),'exclusive_host':False,'production_qualified':False}
write('process',record); print(json.dumps({k:record[k] for k in ('schema','argv','exit_code','timed_out','elapsed_monotonic_ns','source_commit','source_inputs_unchanged','binary_unchanged')},sort_keys=True))
raise SystemExit(124 if timed_out else exit_code)
