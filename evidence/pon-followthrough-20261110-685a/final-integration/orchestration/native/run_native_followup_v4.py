#!/usr/bin/env python3
"""Retain the failed full suite and complete independent C2 observations."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

ROOT = Path('/home/qian-qi/chain-pon-followthrough-20261110-685a')
INPUTS = Path(str(ROOT) + '-inputs')
OLD = INPUTS / 'validation'
OUT = INPUTS / 'native-followup-04'
SOURCE = '8d8c0e64e7a301fc111a6720721a14816639e5aa'
TARGET = Path(str(ROOT) + '-target')
ENV = dict(os.environ, PATH='/home/qian-qi/.cargo/bin:' + os.environ.get('PATH', ''),
           CARGO_BUILD_JOBS='2', CARGO_TARGET_DIR=str(TARGET), CARGO_TERM_COLOR='never',
           PYTHONDONTWRITEBYTECODE='1')
RECORDS = []

def sha(raw): return hashlib.sha256(raw).hexdigest()

def emit(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    temporary.replace(path)

def git(*args):
    return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=ROOT, env=ENV)

def status(label, phase, code=None):
    emit(OUT / 'status.json', {'stage': label, 'phase': phase, 'exit_code': code,
         'source': SOURCE, 'recorded_unix_ns': time.time_ns(), 'original_full_node_suite_passed': False,
         'security_status': 'HOLD'})

def run(label, argv, required=False):
    start = time.time_ns(); status(label, 'running'); print('START', label, flush=True)
    stdout, stderr = OUT / (label + '.stdout.log'), OUT / (label + '.stderr.log')
    with stdout.open('xb') as out, stderr.open('xb') as err:
        result = subprocess.run(argv, cwd=ROOT, env=ENV, stdout=out, stderr=err)
    row = dict(label=label, argv=argv, cwd=str(ROOT), exit_code=result.returncode,
               start_unix_ns=start, end_unix_ns=time.time_ns())
    for key, path in [('stdout', stdout), ('stderr', stderr)]:
        raw = path.read_bytes(); row[key] = dict(file=path.name, bytes=len(raw), sha256=sha(raw))
    RECORDS.append(row); emit(OUT / 'commands.json', RECORDS)
    status(label, 'finished' if result.returncode == 0 else 'failed', result.returncode)
    print('END', label, result.returncode, flush=True)
    if required and result.returncode: raise RuntimeError('actual required command failed: ' + label)
    return result.returncode

def profile():
    fields = {}
    for name in ('cpu.max', 'memory.max', 'cpuset.cpus.effective'):
        path = Path('/sys/fs/cgroup') / name
        fields[name] = path.read_text().strip() if path.is_file() else None
    return {'observed_unix_ns': time.time_ns(), 'platform': platform.platform(), 'machine': platform.machine(),
            'logical_cpus': os.cpu_count(), 'affinity': sorted(os.sched_getaffinity(0)),
            'load_average': list(os.getloadavg()), 'cgroup_limits': fields,
            'cpu_model': next((x.split(':', 1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines()
                               if x.startswith('model name')), None),
            'scope': 'local wall-time observation; independently authenticated resource bound not claimed'}

assert not OUT.exists()
assert git('rev-parse', 'HEAD').decode().strip() == SOURCE and not git('status', '--porcelain')
assert all(not line or line.startswith(b'H ') for line in git('ls-files', '-v', '-z').split(b'\0'))
prior_raw = (OLD / 'commands.json').read_bytes(); prior = json.loads(prior_raw)
assert prior[-1]['label'] == 'node-library-v3' and prior[-1]['exit_code'] == 101
full = (OLD / 'node-library-v3.stdout.log').read_bytes()
assert sha(full) == '022eabf9dba4c26fda5ab75d9d9b53df76f209e19b2af9b3f4ce256ebf4f0b6b'
assert b'test result: FAILED. 1285 passed; 2 failed; 39 ignored;' in full
OUT.mkdir()
source = {'source': SOURCE, 'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
          'recorder_sha256': sha(Path(__file__).read_bytes()), 'prior_commands_sha256': sha(prior_raw),
          'prior_full_suite_sha256': sha(full), 'prior_full_suite': {'passed': 1285, 'failed': 2, 'ignored': 39, 'exit_code': 101},
          'original_full_node_suite_passed': False, 'all_prior_observations_retained': True,
          'source_mutations_performed': False, 'production_activation': False, 'security_status': 'HOLD',
          'explicit_environment': {key: ENV[key] for key in ('CARGO_BUILD_JOBS', 'CARGO_TARGET_DIR', 'CARGO_TERM_COLOR', 'PYTHONDONTWRITEBYTECODE')}}
emit(OUT / 'source.json', source)
try:
    run('preflight', ['bash', 'scripts/project-preflight.sh'], True)
    verify = ['python3', '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head', '--expected-head', SOURCE, '--output']
    run('source-before', verify + [str(OUT / 'source-before.json')], True)
    run('prior-source-identical', ['cmp', str(OLD / 'source-before-v3.json'), str(OUT / 'source-before.json')], True)
    cargo = ['cargo', 'test', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline']
    cases = [('isolated-large-parent', 'store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner'),
             ('isolated-inactive-page', 'store::native_authenticated_tests::native_inactive_page_parents_use_checked_material_without_early_activation')]
    for label, case in cases:
        run(label, cargo + ['-p', 'trnm-pon-node', '--lib', case, '--', '--exact', '--nocapture'])
    run('fresh-probe-tests', cargo + ['--release', '-p', 'trnm-crypto-primitives', '--example', 'pon_fresh_rejection_cost'])
    run('changed-owner-clippy', ['cargo', 'clippy', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline',
        '-p', 'trnm-pon-node', '-p', 'trnm-service-settlement', '-p', 'trnm-crypto-primitives', '--all-targets', '--', '-D', 'warnings'])
    run('format-check', ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check'])
    built = run('fresh-probe-build', ['cargo', 'build', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline',
        '--release', '-p', 'trnm-crypto-primitives', '--example', 'pon_fresh_rejection_cost'])
    binary_summary = None
    if built == 0:
        binary = TARGET / 'release/examples/pon_fresh_rejection_cost'
        binary_hash = sha(binary.read_bytes())
        emit(OUT / 'fresh-profile-before.json', profile())
        probe_exit = run('fresh-probe-native', [str(binary)])
        emit(OUT / 'fresh-profile-after.json', profile())
        assert sha(binary.read_bytes()) == binary_hash
        binary_summary = {'path': str(binary), 'sha256': binary_hash, 'exit_code': probe_exit}
        if probe_exit == 0:
            raw = OUT / 'fresh-probe-native.stdout.log'
            run('fresh-probe-reader', ['python3', '-B', 'scripts/pon_fresh_rejection_report.py', str(raw), '--raw-sha256', sha(raw.read_bytes())])
    run('fresh-reader-tests', ['python3', '-B', 'scripts/ci/test_fresh_rejection_report.py', '-v'])
    run('source-after', verify + [str(OUT / 'source-after.json')], True)
    run('source-identical', ['cmp', str(OUT / 'source-before.json'), str(OUT / 'source-after.json')], True)
    assert git('rev-parse', 'HEAD').decode().strip() == SOURCE and not git('status', '--porcelain')
    assert (OLD / 'commands.json').read_bytes() == prior_raw and (OLD / 'node-library-v3.stdout.log').read_bytes() == full
    summary = dict(source, schema='pon-native-failure-followup-v1', observation_complete=True,
        all_followup_checks_passed=all(row['exit_code'] == 0 for row in RECORDS),
        full_suite_repeated=False, commands=[{'label': row['label'], 'exit_code': row['exit_code']} for row in RECORDS],
        binary=binary_summary, open_consensus_qualified=False)
    emit(OUT / 'summary.json', summary); status('complete-observation', 'finished', 0)
    print(json.dumps(summary, sort_keys=True), flush=True)
except BaseException as error:
    emit(OUT / 'failure.json', {'observation_complete': False, 'reason': repr(error), 'source': source,
                             'recorded_unix_ns': time.time_ns(), 'security_status': 'HOLD'})
    status('followup', 'failed', 2); raise
