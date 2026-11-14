#!/usr/bin/env python3
"""Retain each DA library test attempt and its exact local source inventory."""

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time


ROOT = Path('/workspace/scratch/dc0357cf2d6c/chain-capacity')
OUTPUT = Path('/workspace/scratch/dc0357cf2d6c/validation')
RUST_BIN = Path('/workspace/scratch/a6fe7c2e72c7/pq-validation/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin')
CARGO_HOME = '/workspace/scratch/a6fe7c2e72c7/pq-validation/cargo'
TARGET = '/workspace/scratch/dc0357cf2d6c/target'
PROVIDER_ENV = Path('/workspace/scratch/a6fe7c2e72c7/pq-validation/provider.env')
LIB_ROOTS = tuple(
    f'trillionnium/crates/{name}/src/'
    for name in ('trnm-data-availability', 'trnm-crypto-primitives', 'trnm-protocol')
)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture(args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def inventory():
    files = capture(['rg', '--files', 'trillionnium']).splitlines()
    return {
        name: digest(ROOT / name)
        for name in sorted(files)
        if name.endswith('.rs') or Path(name).name in ('Cargo.toml', 'Cargo.lock')
    }


def write_json(path, data):
    with path.open('x') as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write('\n')


attempt = sys.argv[1]
if not re.fullmatch(r'da-lib-attempt[0-9]+', attempt):
    raise SystemExit('expected da-lib-attemptNN')
base = OUTPUT / attempt
for suffix in ('-start.json', '.log', '-observation.json', '-sources-start.json', '-sources-end.json'):
    if Path(str(base) + suffix).exists():
        raise SystemExit(f'refusing to overwrite {base}{suffix}')

env = os.environ.copy()
provider = {}
for line in PROVIDER_ENV.read_text().splitlines():
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    if line.startswith('export '):
        line = line[7:]
    key, value = line.split('=', 1)
    values = shlex.split(value)
    provider[key] = values[0] if values else ''
env.update(provider)
env.update({
    'CARGO_HOME': CARGO_HOME,
    'CARGO_TARGET_DIR': TARGET,
    'CARGO_BUILD_JOBS': '2',
    'RUSTC': str(RUST_BIN / 'rustc'),
    'RUSTDOC': str(RUST_BIN / 'rustdoc'),
    'PATH': str(RUST_BIN) + os.pathsep + env.get('PATH', ''),
    'CARGO_TERM_COLOR': 'never',
})
test_filter = sys.argv[2] if len(sys.argv) > 2 else None
test_threads = 1 if test_filter else 2
command = [str(RUST_BIN / 'cargo'), 'test', '--locked', '--offline', '--jobs', '2',
           '-p', 'trnm-data-availability', '--lib']
if test_filter:
    command.append(test_filter)
command.extend(['--', f'--test-threads={test_threads}'])
if test_filter:
    command.append('--exact')

preflight = subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=ROOT,
                           text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
Path(str(base) + '-preflight.log').write_text(preflight.stdout)
if preflight.returncode:
    raise SystemExit(preflight.returncode)
sources = inventory()
source_file = Path(str(base) + '-sources-start.json')
write_json(source_file, sources)
started = utc()
start = {
    'started_at_utc': started,
    'command': command,
    'cwd': str(ROOT / 'trillionnium'),
    'head': capture(['git', 'rev-parse', 'HEAD']),
    'branch': capture(['git', 'branch', '--show-current']),
    'git_status': capture(['git', 'status', '--short']),
    'environment': {key: env[key] for key in
                    ['CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'RUSTC', 'RUSTDOC']},
    'provider_environment': provider,
    'provider_cli_sha256_actual': digest(Path(provider['TRNM_PQ_OPENSSL'])),
    'rustc_version': capture([str(RUST_BIN / 'rustc'), '--version']),
    'cargo_version': capture([str(RUST_BIN / 'cargo'), '--version']),
    'source_manifest': str(source_file),
    'source_manifest_sha256': digest(source_file),
    'source_files': len(sources),
    'lib_input_source_roots': LIB_ROOTS,
    'build_jobs': 2,
    'test_threads': test_threads,
    'test_filter': test_filter,
}
write_json(Path(str(base) + '-start.json'), start)
print(json.dumps({'attempt': attempt, 'state': 'started', 'source_files': len(sources),
                  'log': str(base) + '.log', 'source_manifest_sha256': digest(source_file)}), flush=True)
began = time.monotonic()
with Path(str(base) + '.log').open('x') as output:
    completed = subprocess.run(command, cwd=ROOT / 'trillionnium', env=env,
                               stdout=output, stderr=subprocess.STDOUT)
elapsed = time.monotonic() - began
after = inventory()
write_json(Path(str(base) + '-sources-end.json'), after)
changed = [name for name in sorted(set(sources) | set(after))
           if sources.get(name) != after.get(name)]
lib_changed = [name for name in changed if name.startswith(LIB_ROOTS)
               or Path(name).name in ('Cargo.toml', 'Cargo.lock')]
log = Path(str(base) + '.log').read_text()
summary = [line for line in log.splitlines() if line.startswith('test result:')]
observation = {
    'started_at_utc': started,
    'completed_at_utc': utc(),
    'elapsed_seconds': elapsed,
    'exit_code': completed.returncode,
    'command': command,
    'source_start_manifest_sha256': digest(source_file),
    'source_end_manifest_sha256': digest(Path(str(base) + '-sources-end.json')),
    'changed_workspace_source_files': changed,
    'changed_da_library_input_files': lib_changed,
    'da_library_inputs_unchanged': not lib_changed,
    'log_sha256': digest(Path(str(base) + '.log')),
    'test_result_lines': summary,
}
write_json(Path(str(base) + '-observation.json'), observation)
print(json.dumps({'attempt': attempt, 'state': 'completed', **observation}), flush=True)
raise SystemExit(completed.returncode)
