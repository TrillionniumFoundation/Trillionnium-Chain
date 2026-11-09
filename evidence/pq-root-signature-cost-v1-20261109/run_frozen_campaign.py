#!/usr/bin/env python3
"""Retain exact-source PQ component execution and its actual failures."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

ROOT = Path('/workspace/scratch/a6fe7c2e72c7/chain-pq')
WORK = ROOT.parent / 'pq-validation'
OUT = WORK / 'frozen-campaign-c9fb3fa6'
HEAD = 'c9fb3fa61e2aadbdeaf39e85a7e21604d72581b7'
sys.path.insert(0, str(ROOT / 'scripts/ci'))
from verify_ci_source import verify

OUT.mkdir(exist_ok=False)
environment = dict(os.environ)
environment['PATH'] = str(WORK / 'rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin') + ':' + environment['PATH']
environment.update(CARGO_HOME=str(WORK / 'cargo'), CARGO_TARGET_DIR='/tmp/trnm-pq-target-a6fe',
                   CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0', RUST_TEST_THREADS='1',
                   PYTHONDONTWRITEBYTECODE='1')
for line in (WORK / 'provider.env').read_text().splitlines():
    if line:
        key, value = line.split('=', 1)
        environment[key] = value
records = []
lock = threading.Lock()

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def run(name, argv, timeout=1800, cwd=ROOT, extra_environment=None):
    env = dict(environment)
    if extra_environment:
        env.update(extra_environment)
    start = time.monotonic()
    began = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    timed_out = False
    failure = None
    child_pid = None
    with (OUT / (name + '.stdout')).open('xb') as stdout, (OUT / (name + '.stderr')).open('xb') as stderr:
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
            child_pid = child.pid
            try:
                code = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                code = 124
        except OSError as error:
            failure = repr(error)
            stderr.write((failure + '\n').encode())
            code = 127
    row = {'name': name, 'argv': argv, 'cwd': str(cwd), 'source': HEAD,
           'started_utc': began, 'elapsed_seconds': time.monotonic() - start,
           'pid': child_pid, 'exit_code': code, 'timed_out': timed_out, 'launch_error': failure,
           'observed_executable_identity_authenticated': False}
    for stream in ('stdout', 'stderr'):
        path = OUT / (name + '.' + stream)
        data = path.read_bytes()
        row[stream] = {'path': path.name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    with lock:
        records.append(row)
        write_json(OUT / 'commands.json', records)
        print(json.dumps({'name': name, 'exit_code': code, 'seconds': round(row['elapsed_seconds'], 3)}), flush=True)
    return code

before = verify('head', HEAD, root=ROOT)
write_json(OUT / 'source-before.json', before)
write_json(OUT / 'environment.json', {
    'source': HEAD, 'source_tree': before.get('tested_tree'),
    'environment': {k: environment.get(k) for k in ('CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS',
        'CARGO_INCREMENTAL', 'RUST_TEST_THREADS', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS',
        'OPENSSL_DIR', 'OPENSSL_STATIC', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'TRNM_PQ_OPENSSL',
        'TRNM_PQ_OPENSSL_SHA256', 'TRNM_PQ_OPENSSL_VERSION')},
    'uname': list(os.uname()), 'cpu_count': os.cpu_count(),
    'initial_load_average': list(os.getloadavg()),
    'shared_executor_load_is_controlled': False,
    'root_native_tests_scope': 'research components; no production activation or whole protocol lane',
})
cargo = ['cargo', '--offline', '--locked', '--manifest-path', 'trillionnium/Cargo.toml']

def native_lane():
    entries = [
        ('rustc-version', ['rustc', '--version', '--verbose']),
        ('cargo-version', ['cargo', '--version']),
        ('cargo-graph', ['cargo', 'metadata', *cargo[1:], '--all-features', '--format-version=1']),
        ('cargo-tree', ['cargo', 'tree', *cargo[1:], '--workspace', '--all-features']),
        ('format', ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check']),
        ('default-crypto', ['cargo', 'test', *cargo[1:], '-p', 'trnm-crypto-primitives', '--lib', '--', '--test-threads=1']),
        ('default-release', ['cargo', 'test', *cargo[1:], '-p', 'trnm-release-bundle', '--lib', '--', '--test-threads=1']),
        ('native-v3', ['python3', 'scripts/ci/run_pq_root_native_v3.py', '--out', str(OUT / 'native-v3')]),
        ('native-v4', ['python3', 'scripts/ci/run_pq_root_continuation_v4.py', '--out', str(OUT / 'native-v4')]),
        ('strict-workspace-clippy', ['cargo', 'clippy', *cargo[1:], '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings']),
    ]
    for name, argv in entries:
        run(name, argv)

def control_lane():
    entries = [
        ('project-preflight', ['bash', 'scripts/project-preflight.sh', '--dev']),
        ('root-register-controls', ['python3', 'scripts/ci/test_pq_root_dependency_register.py']),
        ('root-register', ['python3', 'scripts/ci/pq_root_dependency_register.py']),
        ('native-v3-runner-controls', ['python3', 'scripts/ci/test_run_pq_root_native_v3.py']),
        ('native-v4-runner-controls', ['python3', 'scripts/ci/test_run_pq_root_continuation_v4.py']),
        ('corpus', ['python3', 'scripts/ci/check_pq_research_integration.py']),
        ('corpus-controls', ['python3', 'scripts/ci/test_pq_research_integration.py']),
        ('claim-guard', ['python3', 'scripts/ci/pq_chain_claim_guard.py']),
        ('claim-guard-controls', ['python3', 'scripts/ci/test_pq_chain_claim_guard.py']),
        ('source-integrity-controls', ['python3', 'scripts/ci/test_ci_source_integrity.py']),
        ('repository-and-links', ['python3', 'scripts/ci/check_repository.py']),
        ('ci-contract', ['python3', 'scripts/ci/check_ci_contract.py']),
        ('ci-contract-controls', ['python3', 'scripts/ci/test_ci_contract.py']),
        ('custody-controls', ['python3', 'scripts/ci/test_pq_root_custody_review_v1.py']),
        ('migration-controls', ['python3', 'scripts/ci/test_pq_root_migration_review_v1.py']),
        ('v2-native-signatures', ['python3', 'formal/pon-nakamoto-v1/test_pq_root_recovery_signatures_native_v2.py', '-v']),
        ('v2-native-readback', ['python3', 'formal/pon-nakamoto-v1/test_pq_root_effect_readback_native_v2.py', '-v']),
        ('v2-native-journal', ['python3', 'formal/pon-nakamoto-v1/test_pq_root_recovery_journal_native_v2.py', '-v']),
    ]
    for name, argv in entries:
        run(name, argv)

with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    futures = [pool.submit(native_lane), pool.submit(control_lane)]
    for future in futures:
        future.result()

write_json(OUT / 'load-before-cost-observation.json', {'load_average': list(os.getloadavg()), 'time_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})
run('cost-observation', ['cargo', 'run', *cargo[1:], '--release', '-p', 'trnm-crypto-primitives',
    '--features', 'pq-native-openssl', '--example', 'pq_root_v3_cost_observation', '--', '--rounds', '8'])
binary = Path(environment['CARGO_TARGET_DIR']) / 'release/examples/pq_root_v3_cost_observation'
if binary.is_file():
    raw = binary.read_bytes()
    write_json(OUT / 'cost-binary.json', {'path': str(binary), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'source': HEAD, 'identity_scope': 'local post-command executable bytes; not independent executor authentication'})
after = verify('head', HEAD, root=ROOT)
write_json(OUT / 'source-after.json', after)
write_json(OUT / 'summary.json', {
    'schema': 'trnm-pq-root-signature-cost-campaign-v1', 'source': HEAD,
    'complete_source_endpoints_match': before == after,
    'continuous_source_immutability_enforced': False,
    'independent_execution_authentication': False,
    'all_commands_exit_zero': all(row['exit_code'] == 0 for row in records),
    'completed_commands': len(records), 'commands': records,
    'full_protocol_lane_executed': False, 'all_workspace_tests_executed': False,
    'whole_chain_pq_qualified': False, 'composition_coverage_proved': False,
    'actual_lifetime_failure_bound': None, 'production_activation': False, 'status': 'HOLD',
})
raise SystemExit(0 if before == after and all(row['exit_code'] == 0 for row in records) else 1)
