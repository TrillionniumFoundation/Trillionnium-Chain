#!/usr/bin/env python3
"""Run this task's exact C1 checkout and retain every observed command outcome."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import subprocess
import time

HEAD = 'c2d67c5cf1ebb4caac525802362d5746b8fd957d'
BASE = '58f225e973054f69661bf06aeda936f9126ea8e1'
BRANCH = 'fix/chain-pon-learning-outcome-composition-20261111-7612'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
SOURCE = Path('/home/qian-qi/work/chain-pon-five-claims-20261111-d6cb')
ROOT = Path('/home/qian-qi/work/chain-pon-outcome-7612-publish')
OUT = Path('/home/qian-qi/work/chain-pon-outcome-7612-qualified-c1')
BUNDLE = Path('/home/qian-qi/chain-pon-outcome-c2d67c5c-7612.bundle')
TARGET = Path('/home/qian-qi/work/chain-pon-outcome-7612-qualified-target')
OUT.mkdir(mode=0o700)
env = os.environ.copy()
env['PATH'] = '/home/qian-qi/.cargo/bin:' + env.get('PATH', '')
env['RUSTUP_TOOLCHAIN'] = '1.95.0'
env['CARGO_TARGET_DIR'] = str(TARGET)
env['CARGO_BUILD_JOBS'] = '2'
env['CARGO_NET_OFFLINE'] = 'true'
env['PYTHONDONTWRITEBYTECODE'] = '1'
records = []

def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def save():
    (OUT/'commands.json').write_text(json.dumps({'schema': 'pon-learning-outcome-command-observation-v1',
        'source_head': HEAD, 'source_root': str(ROOT), 'scope': 'native-component-qualification',
        'production_activation': False, 'model_efficacy_certified': False,
        'commands': records}, indent=2) + '\n')

def run(label, command, cwd=ROOT, timeout=1800, required=False):
    started = stamp()
    print('BEGIN', label, started, flush=True)
    stdout_path = OUT/(label+'.stdout')
    stderr_path = OUT/(label+'.stderr')
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        try:
            p = subprocess.run(command, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                               timeout=timeout, check=False)
            code, timed_out = p.returncode, False
        except subprocess.TimeoutExpired:
            code, timed_out = None, True
    row = {'label': label, 'command': command, 'cwd': str(cwd), 'started_utc': started,
           'finished_utc': stamp(), 'exit_code': code, 'timed_out': timed_out,
           'stdout': stdout_path.name, 'stderr': stderr_path.name,
           'stdout_sha256': hashlib.sha256(stdout_path.read_bytes()).hexdigest(),
           'stderr_sha256': hashlib.sha256(stderr_path.read_bytes()).hexdigest()}
    records.append(row)
    save()
    print('END', label, code, 'timeout', timed_out, flush=True)
    if required and (code != 0 or timed_out):
        raise RuntimeError('required preparation failed: '+label)
    return row

def git(directory, *args):
    return subprocess.check_output(['git', *args], cwd=directory, text=True, env=env).strip()

assert git(SOURCE, 'rev-parse', 'HEAD') == BASE
assert hashlib.sha256(BUNDLE.read_bytes()).hexdigest() == '3da30ab82328666d7973fc7180093f43d841985e8c4c5915e4ba25a4bec68a11'
assert not ROOT.exists(), 'isolated destination already exists; inspect instead of replaying'
run('base-project-boundary', ['bash', 'scripts/project-preflight.sh'], cwd=SOURCE, required=True)
run('clone', ['git', 'clone', '--shared', '--no-checkout', '--local', '--template=', str(SOURCE), str(ROOT)], cwd=SOURCE.parent, required=True)
run('canonical-origin', ['git', 'remote', 'set-url', 'origin', ORIGIN], required=True)
run('bundle-verify', ['git', 'bundle', 'verify', str(BUNDLE)], required=True)
run('bundle-import', ['git', '-c', 'gc.auto=0', 'fetch', '--no-write-fetch-head', str(BUNDLE), 'HEAD'], required=True)
run('checkout', ['git', 'checkout', '-b', BRANCH, HEAD], required=True)
assert git(ROOT, 'rev-parse', 'HEAD') == HEAD
assert git(ROOT, 'status', '--porcelain') == ''
run('project-boundary-before', ['bash', 'scripts/project-preflight.sh'], required=True)
run('source-before', ['python3', '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head', '--expected-head', HEAD, '--output', str(OUT/'source-before.json')], required=True)

for name in ['rustc', 'rustdoc']:
    value = subprocess.check_output(['rustup', 'which', '--toolchain', '1.95.0', name], env=env, text=True).strip()
    env[name.upper()] = str(Path(value).resolve(strict=True))
environment = {name: env.get(name) for name in ['RUSTUP_TOOLCHAIN', 'RUSTC', 'RUSTDOC', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'CARGO_NET_OFFLINE', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CC', 'CFLAGS', 'RUSTC_WRAPPER']}
(OUT/'environment.json').write_text(json.dumps(environment, indent=2)+'\n')
run('toolchain', [env['RUSTC'], '-Vv'], required=True)
run('cargo-version', ['cargo', '-Vv'], required=True)
run('locked-metadata', ['cargo', 'metadata', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml', '--format-version', '1'])
run('format', ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--check'])
run('source-integrity-negatives', ['python3', '-B', 'scripts/ci/test_ci_source_integrity.py', '-v'])
run('project-boundary-negatives', ['python3', '-B', 'scripts/ci/test_project_boundary.py', '-v'])
run('repository-and-links', ['python3', '-B', 'scripts/ci/check_repository.py'])

prefix = ['cargo', 'test', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml']
run('adoption-library', prefix + ['-p', 'trnm-data-availability', '--lib', 'cell::adoption::', '--', '--nocapture', '--test-threads=1'], timeout=3600)
run('adoption-cli', prefix + ['-p', 'trnm-data-availability', '--test', 'cell_adoption_cli', '--', '--nocapture', '--test-threads=1'], timeout=3600)
run('outcome-role-separation', prefix + ['-p', 'trnm-pon-node', '--test', 'outcome_role_separation', '--', '--nocapture', '--test-threads=1'], timeout=3600)
clippy = ['cargo', 'clippy', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml']
run('adoption-clippy', clippy + ['-p', 'trnm-data-availability', '--lib', '--bin', 'trnm-cell-adoption', '--test', 'cell_adoption_cli', '--', '-D', 'warnings'], timeout=3600)
run('outcome-role-clippy', clippy + ['-p', 'trnm-pon-node', '--test', 'outcome_role_separation', '--', '-D', 'warnings'], timeout=3600)
run('source-after', ['python3', '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head', '--expected-head', HEAD, '--output', str(OUT/'source-after.json')])
print('QUALIFICATION_FINISHED', json.dumps({'head': HEAD, 'commands': len(records), 'failed': [r['label'] for r in records if r['exit_code'] != 0 or r['timed_out']]}), flush=True)
