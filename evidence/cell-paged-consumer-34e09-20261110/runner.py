#!/usr/bin/env python3
"""Run retained gates on one explicitly pinned, clean ai395 candidate.

The source phase never invokes Cargo. The cargo phase requires a separately
coordinated idle target and refuses an already running task Cargo process.
Every attempt is append-only in a new directory outside the repository.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


REPOSITORY = Path('/home/qq/work/chain-cell-paged-consumer-34e09-20261109')
TARGET = Path('/home/qq/work/chain-cell-paged-consumer-34e09-20261109-target')
OUTPUT = Path('/home/qq/work/chain-cell-paged-consumer-34e09-20261109-validation')
RUST = Path('/home/qq/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin')
PROVIDER = Path('/home/qq/work/chain-cell-discovery-provider-f2568-20261108/runner/trnm-pq-provider-3.5.9.ReYCJ9gV/install')
PROVIDER_SHA256 = 'ed29dfe14c0686c876833e39fbeedb277846987f3728acc279c256b32259cf62'
DEFAULT_COMMIT = 'e58b9371677bc8eb1bcb42c090437fb4a766b526'
DEFAULT_TREE = 'c7a971a7ed682a2590a3fc3f88c3a4e4d05fa4de'


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        while block := source.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def capture(command, cwd=REPOSITORY, env=None):
    return subprocess.check_output(command, cwd=cwd, env=env, text=True).strip()


def write_json(path, value):
    with path.open('x') as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write('\n')


def identity(commit, tree):
    observed = {
        'commit': capture(['git', 'rev-parse', 'HEAD']),
        'tree': capture(['git', 'rev-parse', 'HEAD^{tree}']),
        'status': capture(['git', 'status', '--porcelain', '--untracked-files=all']),
    }
    if observed != {'commit': commit, 'tree': tree, 'status': ''}:
        raise RuntimeError('exact clean source identity mismatch: ' + json.dumps(observed))
    return observed


def sources():
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=REPOSITORY).split(b'\0')
    result = {}
    for raw in names:
        if not raw:
            continue
        name = os.fsdecode(raw)
        path = Path(name)
        if path.suffix in ('.rs', '.py', '.toml') or path.name == 'Cargo.lock':
            result[name] = sha256(REPOSITORY / name)
    return result


def active_task_compilers():
    result = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            command = (entry / 'cmdline').read_bytes().split(b'\0')
            if not command or Path(os.fsdecode(command[0])).name not in {
                'cargo', 'rustc', 'rustdoc', 'clippy-driver', 'cargo-clippy'
            }:
                continue
            cwd = os.readlink(entry / 'cwd')
            arguments = [os.fsdecode(arg) for arg in command if arg]
            if str(REPOSITORY) in cwd or any(str(TARGET) in arg for arg in arguments):
                result.append({'pid': int(entry.name), 'argv': arguments, 'cwd': cwd})
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return result


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--phase', choices=('source', 'cargo', 'clippy'), required=True)
parser.add_argument('--attempt', required=True)
parser.add_argument('--expected-commit', default=DEFAULT_COMMIT)
parser.add_argument('--expected-tree', default=DEFAULT_TREE)
parser.add_argument('--gate-timeout-seconds', type=int, default=7200)
args = parser.parse_args()
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', args.attempt):
    raise SystemExit('invalid attempt identity')
if not re.fullmatch(r'[0-9a-f]{40}', args.expected_commit) or not re.fullmatch(r'[0-9a-f]{40}', args.expected_tree):
    raise SystemExit('full explicit commit and tree required')
if not 1 <= args.gate_timeout_seconds <= 86400:
    raise SystemExit('invalid gate timeout')

temporary = OUTPUT / 'tmp'
temporary.mkdir(parents=True, exist_ok=True, mode=0o700)
env = os.environ.copy()
env.update({
    'TMPDIR': str(temporary),
    'CARGO_HOME': '/home/qq/.cargo',
    'CARGO_TARGET_DIR': str(TARGET),
    'CARGO_BUILD_JOBS': '2',
    'CARGO_INCREMENTAL': '0',
    'CARGO_TERM_COLOR': 'never',
    'RUSTC': str(RUST / 'rustc'),
    'RUSTDOC': str(RUST / 'rustdoc'),
    # Original repository build-requalification setup (75-86), not a gate override.
    'LD_LIBRARY_PATH': str(RUST.parent / 'lib'),
    'PATH': str(RUST) + os.pathsep + env.get('PATH', ''),
    'RUST_TEST_THREADS': '1',
    'PYTHONDONTWRITEBYTECODE': '1',
    'OPENSSL_DIR': str(PROVIDER),
    'OPENSSL_STATIC': '1',
    'OPENSSL_CONF': '/dev/null',
    'OPENSSL_MODULES': str(PROVIDER / 'lib/ossl-modules'),
    'TRNM_PQ_OPENSSL': str(PROVIDER / 'bin/openssl'),
    'TRNM_PQ_OPENSSL_SHA256': PROVIDER_SHA256,
    'TRNM_PQ_OPENSSL_VERSION': '3.5.9',
})
before_identity = identity(args.expected_commit, args.expected_tree)
provider_hash = sha256(PROVIDER / 'bin/openssl')
if provider_hash != PROVIDER_SHA256:
    raise SystemExit('independently pinned provider hash mismatch')

guard = None
if args.phase in ('cargo', 'clippy'):
    guard = (TARGET.parent / (TARGET.name + '.owner.lock')).open('a')
    fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
    active = active_task_compilers()
    if active:
        raise SystemExit('task target is still busy: ' + json.dumps(active))
    for binary in ('cargo', 'rustc', 'rustdoc', 'cargo-clippy', 'clippy-driver', 'rustfmt'):
        if not (RUST / binary).is_file():
            raise SystemExit('required toolchain component absent: ' + binary)

destination = OUTPUT / args.attempt
destination.mkdir(parents=True, exist_ok=False)
before = sources()
write_json(destination / 'sources-start.json', before)
started = utc()
write_json(destination / 'start.json', {
    'started_at_utc': started,
    'phase': args.phase,
    'identity': before_identity,
    'source_files': len(before),
    'source_manifest_sha256': sha256(destination / 'sources-start.json'),
    'script_sha256': sha256(Path(__file__)),
    'provider_cli_sha256': provider_hash,
    'environment': {key: env[key] for key in (
        'TMPDIR', 'CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL',
        'RUSTC', 'RUSTDOC', 'LD_LIBRARY_PATH', 'RUST_TEST_THREADS', 'OPENSSL_DIR', 'OPENSSL_STATIC',
        'OPENSSL_CONF', 'OPENSSL_MODULES', 'TRNM_PQ_OPENSSL',
        'TRNM_PQ_OPENSSL_SHA256', 'TRNM_PQ_OPENSSL_VERSION')},
})
print(json.dumps({'state': 'started', 'phase': args.phase, 'output': str(destination),
                  'commit': args.expected_commit, 'tree': args.expected_tree}), flush=True)

python = sys.executable
cargo = str(RUST / 'cargo')
feature = 'trnm-pon-node/pq-native-openssl'
gates = [('preflight', ['bash', 'scripts/project-preflight.sh'], REPOSITORY),
         ('exact-source', [python, 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                           '--expected-head', args.expected_commit], REPOSITORY)]
if args.phase == 'source':
    gates += [
        ('source-integrity-negatives', [python, 'scripts/ci/test_ci_source_integrity.py'], REPOSITORY),
        ('repository-and-links', [python, 'scripts/ci/check_repository.py'], REPOSITORY),
    ]
else:
    gates += [
        ('cargo-graph', [cargo, 'metadata', '--locked', '--offline', '--format-version', '1',
                         '--features', feature], REPOSITORY / 'trillionnium'),
        ('new-restore-cases', [cargo, 'test', '--locked', '--offline', '--jobs', '2', '-p', 'trnm-data-availability', 'paged_consumer_restore', '--', '--test-threads=1'], REPOSITORY / 'trillionnium'),
        ('source-integrity-negatives', [python, 'scripts/ci/test_ci_source_integrity.py'], REPOSITORY),
        ('repository-and-links', [python, 'scripts/ci/check_repository.py'], REPOSITORY),
        ('da-crate', [cargo, 'test', '--locked', '--offline', '--jobs', '2', '-p',
                    'trnm-data-availability', '--', '--test-threads=1'],
         REPOSITORY / 'trillionnium'),
        ('node-storage', [cargo, 'test', '--locked', '--offline', '--jobs', '2', '-p', 'trnm-pon-node', '--features', 'pq-native-openssl', '--lib', 'storage_service', '--', '--test-threads=1'], REPOSITORY / 'trillionnium'),
        ('strict-clippy', [cargo, 'clippy', '--locked', '--offline', '--jobs', '2',
                           '--all-targets', '-p', 'trnm-data-availability', '-p',
                           'trnm-pon-node', '--features', feature, '--', '-D', 'warnings'],
         REPOSITORY / 'trillionnium'),
        ('fmt', [cargo, 'fmt', '--all', '--', '--check'], REPOSITORY / 'trillionnium'),
    ]

gates.append(('exact-source-end', [python, 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                                  '--expected-head', args.expected_commit], REPOSITORY))
if args.phase == 'clippy':
    gates = [gate for gate in gates if gate[0] not in ('da-crate', 'fmt')]

results = []
for name, command, cwd in gates:
    identity(args.expected_commit, args.expected_tree)
    gate_started = utc()
    began = time.monotonic()
    write_json(destination / (name + '-start.json'), {
        'started_at_utc': gate_started, 'command': command, 'cwd': str(cwd),
        'commit': args.expected_commit, 'tree': args.expected_tree,
    })
    failure = None
    with (destination / (name + '.log')).open('x') as output:
        try:
            process = subprocess.run(command, cwd=cwd, env=env, stdout=output,
                                     stderr=subprocess.STDOUT,
                                     timeout=args.gate_timeout_seconds)
            exit_code = process.returncode
        except subprocess.TimeoutExpired:
            exit_code = 124
            failure = 'original gate deadline expired'
    result = {
        'name': name, 'command': command, 'started_at_utc': gate_started,
        'completed_at_utc': utc(), 'elapsed_seconds': time.monotonic() - began,
        'exit_code': exit_code, 'failure': failure,
        'log_sha256': sha256(destination / (name + '.log')),
    }
    write_json(destination / (name + '-observation.json'), result)
    print(json.dumps(result), flush=True)
    results.append(result)
    if exit_code:
        print((destination / (name + '.log')).read_text(errors='replace')[-22000:], flush=True)
        break

after_identity = identity(args.expected_commit, args.expected_tree)
after = sources()
write_json(destination / 'sources-end.json', after)
changed = [name for name in sorted(set(before) | set(after)) if before.get(name) != after.get(name)]
observation = {
    'started_at_utc': started, 'completed_at_utc': utc(),
    'phase': args.phase, 'identity': after_identity, 'gates': results,
    'changed_source_files': changed, 'sources_unchanged': not changed,
    'source_start_manifest_sha256': sha256(destination / 'sources-start.json'),
    'source_end_manifest_sha256': sha256(destination / 'sources-end.json'),
    'passed': not changed and len(results) == len(gates)
              and all(result['exit_code'] == 0 for result in results),
}
write_json(destination / 'observation.json', observation)
print(json.dumps({'state': 'completed', **observation}), flush=True)
raise SystemExit(0 if observation['passed'] else 1)
