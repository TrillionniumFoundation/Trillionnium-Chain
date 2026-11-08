#!/usr/bin/env python3
"""New exact-source H execution; not recovery of unavailable cloud raw files."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import time

ROOT = Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2')
SOURCE = ROOT / 'chain-source-bounded'
EXPECTED = '690f710c1b6808787996e86aa4c36bd53e1f3939'
EXPECTED_SOURCE = 'f9b57e33935e7c767accd80b193b88bc51d42ff1e1e6d33d9da4d5f60725ee98'
COMPILER = Path('/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu')
OUT = ROOT / 'recovery-core-gates-690f-v1'
OUT.mkdir()

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        print(file=stream)

original = ROOT / 'run_remote_node_gate.py'
original_raw = original.read_bytes()
assert digest(original_raw) == '049c64cf32927bcd16a82059707a468c91d6fc9be7d7abc9047bb3efcd2d8123'
tree = ast.parse(original_raw)
functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in {'sha', 'git', 'source'}]
assert {node.name for node in functions} == {'sha', 'git', 'source'}
exec(compile(ast.Module(body=functions, type_ignores=[]), str(original), 'exec'), globals())
before, before_id = source()
assert before_id == EXPECTED_SOURCE
save(OUT / 'source.json', before)

env = dict(os.environ)
assert not [key for key, value in env.items() if value and (key.startswith('CARGO_PROFILE_') or key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'))]
provider_path = ROOT / 'build-receipts/pq-provider/provider.json'
provider_raw = provider_path.read_bytes()
provider = json.loads(provider_raw)
assert provider['result'] == 'PREPARED_AND_SMOKE_VERIFIED'
assert provider['version'] == '3.5.9' and type(provider['exit_code']) is int and provider['exit_code'] == 0
for artifact in provider['native_backend_inputs']:
    raw = Path(artifact['path']).read_bytes()
    assert len(raw) == artifact['bytes'] and digest(raw) == artifact['sha256']
allowed = {'OPENSSL_DIR', 'OPENSSL_STATIC', 'TRNM_PQ_OPENSSL', 'TRNM_PQ_OPENSSL_SHA256', 'TRNM_PQ_OPENSSL_VERSION', 'OPENSSL_CONF', 'OPENSSL_MODULES'}
for line in (ROOT / 'build-runtime/provider.env').read_text().splitlines():
    key, value = line.split('=', 1)
    assert key in allowed
    env[key] = value
env.update(RUSTC=str(COMPILER / 'bin/rustc'), PATH=str(COMPILER / 'bin') + os.pathsep + env.get('PATH', ''), LD_LIBRARY_PATH=str(COMPILER / 'lib'), CARGO_TARGET_DIR=str(ROOT / 'target'), CARGO_BUILD_JOBS='2', RUST_TEST_THREADS='1', CARGO_TERM_COLOR='never', OPENSSL_NO_VENDOR='1')
exported = allowed | {'RUSTC', 'LD_LIBRARY_PATH', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'RUST_TEST_THREADS', 'CARGO_TERM_COLOR', 'OPENSSL_NO_VENDOR'}
save(OUT / 'environment.json', {key: env[key] for key in sorted(exported)})
save(OUT / 'provenance.json', {'schema': 'pon-h-core-reexecution-provenance-v1', 'not_retrieved_cloud_raw': True, 'recorder_sha256': digest(Path(__file__).read_bytes()), 'source_function_recorder_sha256': digest(original_raw), 'provider_sha256': digest(provider_raw), 'source_commit': EXPECTED, 'source_tree': before['tree'], 'source_canonical_sha256': before_id})
with (OUT / 'preflight.log').open('xb') as stream:
    subprocess.run(['bash', 'scripts/project-preflight.sh', '--audit'], cwd=SOURCE, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
fuzz = [row.decode() for row in git('ls-files', '-z').split(b'\0') if row and row.decode().endswith('fuzz/Cargo.toml')]
assert len(fuzz) == 1, fuzz
cargo = str(COMPILER / 'bin/cargo')
commands = [
    ('core-suites', [cargo, 'test', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-service-settlement', '-p', 'trnm-protocol', '-p', 'trnm-mvcc-fee', '--all-targets', '--all-features', '--no-fail-fast', '--', '--test-threads=1']),
    ('workspace-clippy', [cargo, 'clippy', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings']),
    ('formatting', [cargo, 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check']),
    ('metadata-root', [cargo, 'metadata', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml', '--all-features', '--format-version', '1']),
    ('metadata-fuzz', [cargo, 'metadata', '--locked', '--offline', '--manifest-path', fuzz[0], '--all-features', '--format-version', '1']),
]
reports = []
for label, command in commands:
    directory = OUT / label
    directory.mkdir()
    actual_before, actual_before_id = source()
    assert actual_before_id == before_id
    start = time.time()
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    save(directory / 'started.json', {'command': command, 'started_unix_seconds': start, 'source_sha256': actual_before_id})
    print(json.dumps({'started': label, 'source_commit': EXPECTED, 'command': command}), flush=True)
    with (directory / 'stdout.log').open('xb') as stdout, (directory / 'stderr.log').open('xb') as stderr:
        result = subprocess.run(command, cwd=SOURCE, env=env, stdout=stdout, stderr=stderr, check=False)
    after_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    actual_after, actual_after_id = source()
    receipt = {'schema': 'pon-h-core-reexecution-v1', 'label': label, 'command': command, 'exit_code': result.returncode, 'source_commit': EXPECTED, 'source_tree': before['tree'], 'source_before_sha256': actual_before_id, 'source_after_sha256': actual_after_id, 'source_unchanged': actual_before_id == actual_after_id, 'started_unix_seconds': start, 'elapsed_seconds': time.time() - start, 'child_user_cpu_seconds': after_usage.ru_utime - usage.ru_utime, 'child_system_cpu_seconds': after_usage.ru_stime - usage.ru_stime, 'child_max_rss_kib': after_usage.ru_maxrss, 'logs': {}, 'independent_business_acceptance': False}
    for name in ('stdout.log', 'stderr.log'):
        raw = (directory / name).read_bytes()
        receipt['logs'][name] = {'bytes': len(raw), 'sha256': digest(raw)}
    if label.startswith('metadata-') and result.returncode == 0:
        metadata = json.loads((directory / 'stdout.log').read_text())
        receipt['cargo_graph'] = {'workspace_members': len(metadata['workspace_members']), 'packages': len(metadata['packages'])}
    save(directory / 'receipt.json', receipt)
    reports.append(receipt)
    print(json.dumps({key: receipt[key] for key in ('label', 'exit_code', 'elapsed_seconds', 'source_unchanged')}), flush=True)
save(OUT / 'summary.json', {'schema': 'pon-h-core-reexecution-summary-v1', 'source_commit': EXPECTED, 'gates': reports, 'all_selected_gates_passed': all(row['exit_code'] == 0 and row['source_unchanged'] for row in reports)})
raise SystemExit(0 if all(row['exit_code'] == 0 and row['source_unchanged'] for row in reports) else 1)
