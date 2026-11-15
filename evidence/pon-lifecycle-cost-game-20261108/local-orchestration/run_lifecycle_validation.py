#!/usr/bin/env python3
"""Local orchestration for one frozen commit; each original result is retained."""
from __future__ import annotations
import concurrent.futures
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

ROOT = Path('/workspace/scratch/68dd104c2e6a/chain-lifecycle')
OUT = Path(sys.argv[1]).resolve()
OUT.mkdir(parents=True, exist_ok=False)
HEAD = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
ENV = os.environ.copy()
ENV.update({
    'PATH': '/workspace/scratch/d95a703b8dd6/toolchain/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin:' + ENV['PATH'],
    'CARGO_HOME': '/workspace/scratch/d95a703b8dd6/toolchain/cargo',
    'CARGO_TARGET_DIR': '/workspace/scratch/68dd104c2e6a/cargo-target',
    'CARGO_INCREMENTAL': '0', 'CARGO_PROFILE_DEV_DEBUG': '0',
    'CARGO_PROFILE_TEST_DEBUG': '0', 'CARGO_BUILD_JOBS': '2',
    'RUST_TEST_THREADS': '1', 'PYTHONDONTWRITEBYTECODE': '1',
})
RESULTS = []
LOCK = threading.Lock()
CI_COPY_DONE = threading.Event()


def write_json(name, value):
    (OUT / name).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def run(name, command, cwd=ROOT):
    started = time.time()
    with (OUT / (name + '.log')).open('xb') as stream:
        result = subprocess.run(command, cwd=cwd, env=ENV,
                                stdout=stream, stderr=subprocess.STDOUT, check=False)
    row = {'name': name, 'command': command,
           'cwd_relative_to_source': str(Path(cwd).relative_to(ROOT)),
           'source_commit': HEAD, 'started_unix_seconds': started,
           'duration_seconds': time.time() - started, 'exit_code': result.returncode,
           'log': name + '.log'}
    with LOCK:
        RESULTS.append(row)
        write_json('commands-in-progress.json', RESULTS)
    print(json.dumps({k: row[k] for k in ('name', 'exit_code', 'duration_seconds')}), flush=True)
    return result.returncode


def source(label):
    return run(label, [sys.executable, 'scripts/ci/verify_ci_source.py',
                      '--kind', 'head', '--expected-head', HEAD,
                      '--output', str(OUT / (label + '.json'))])


def ci_controls():
    try:
        for name in ('test_ci_source_integrity', 'test_ci_execution', 'test_ci_contract'):
            run(name, [sys.executable, 'scripts/ci/' + name + '.py', '-v'])
    finally:
        CI_COPY_DONE.set()


def formal_controls():
    modules = (
        'test_lifecycle_cost_v1', 'test_cell_lottery_cost_audit_v1',
        'test_service_work_settlement_v1', 'test_reward_budget_oracle',
        'test_useful_cell_numeric_v1', 'test_grouped_cell_operator_v0',
        'test_useful_cell_relation_v1', 'test_useful_cell_execution_v2',
        'test_useful_cell_relation_v2', 'test_useful_cell_relation_v2_adversarial',
        'test_useful_cell_source_guard_v2', 'test_useful_cell_multimodal_execution_v3',
        'test_useful_cell_multimodal_relation_v3',
    )
    for module in modules:
        run(module, [sys.executable, 'formal/pon-nakamoto-v1/' + module + '.py', '-v'])


def static_and_native():
    run('preflight-audit', ['bash', 'scripts/project-preflight.sh', '--audit'])
    run('repository', [sys.executable, 'scripts/ci/check_repository.py'])
    run('ci-contract-static', [sys.executable, 'scripts/ci/check_ci_contract.py'])
    run('distributed-source-inventory', [sys.executable, 'scripts/refresh_distributed_source_inventory.py', '--check'])
    run('diff-whitespace', ['git', 'diff', '--check', HEAD + '^', HEAD])
    run('reproduction', [sys.executable, 'formal/pon-nakamoto-v1/experiments/lifecycle_cost_game_v1.py',
                         '--output', str(OUT / 'reproduction')])
    cargo_cwd = ROOT / 'trillionnium'
    run('cargo-metadata', ['cargo', 'metadata', '--locked', '--offline', '--format-version', '1'], cargo_cwd)
    run('cargo-format', ['cargo', 'fmt', '--all', '--', '--check'], cargo_cwd)
    CI_COPY_DONE.wait()
    run('cargo-clippy', ['cargo', 'clippy', '--locked', '--offline', '--workspace',
                         '--all-targets', '--all-features', '--', '-D', 'warnings'], cargo_cwd)
    run('crypto-native', ['cargo', 'test', '--locked', '--offline', '-p',
                          'trnm-crypto-primitives', '--lib'], cargo_cwd)
    run('cell-native', ['cargo', 'test', '--locked', '--offline', '-p',
                        'trnm-pon-node', '--test', 'cell_native_v1'], cargo_cwd)


runtime = {'schema': 'pon-lifecycle-local-runtime-v1', 'source_commit': HEAD,
           'python': sys.version, 'numpy': importlib.metadata.version('numpy'),
           'cryptography': importlib.metadata.version('cryptography'),
           'rustc': subprocess.check_output(['rustc', '-Vv'], env=ENV, text=True),
           'cargo': subprocess.check_output(['cargo', '-V'], env=ENV, text=True).strip(),
           'explicit_build_environment': {key: ENV[key] for key in
               ('CARGO_INCREMENTAL', 'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG',
                'CARGO_BUILD_JOBS', 'RUST_TEST_THREADS', 'PYTHONDONTWRITEBYTECODE')},
           'pinned_python_ci_runtime_reproduced': False,
           'full_github_ci_executed_locally': False,
           'production_activation': False}
write_json('runtime.json', runtime)
if source('source-before'):
    raise SystemExit(1)
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
    futures = [pool.submit(fn) for fn in (ci_controls, formal_controls, static_and_native)]
    for future in concurrent.futures.as_completed(futures):
        future.result()
source('source-after')
artifacts = []
for path in sorted(OUT.rglob('*')):
    if path.is_file() and path.name not in ('validation-manifest.json', 'commands-in-progress.json'):
        raw = path.read_bytes()
        artifacts.append({'path': str(path.relative_to(OUT)), 'bytes': len(raw),
                          'sha256': hashlib.sha256(raw).hexdigest()})
manifest = {'schema': 'pon-lifecycle-local-validation-v1', 'source_commit': HEAD,
            'status': 'PASS' if all(row['exit_code'] == 0 for row in RESULTS) else 'FAIL',
            'commands': RESULTS, 'artifacts': artifacts, 'qualification': 'HOLD_NO_GO',
            'actual_W1_all_algorithm_lower_bound': None,
            'quantum_lifecycle_certificate': None, 'native_chain_security_probability': None,
            'external_payment_executed': False, 'full_github_ci_executed_locally': False}
write_json('validation-manifest.json', manifest)
print(json.dumps({'status': manifest['status'], 'commands': len(RESULTS),
                  'source_commit': HEAD, 'output': str(OUT)}), flush=True)
raise SystemExit(0 if manifest['status'] == 'PASS' else 1)
