#!/usr/bin/env python3
"""Retain actual read-only/static validation observations outside the repository."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/workspace/scratch/b6ec4f0afca8/chain-joint-daa')
OUT = Path('/workspace/scratch/b6ec4f0afca8/joint-validation')
EXPECTED = '73b5a70fc3f4ffa5a1a99da366591c243d384786'
TOOLCHAIN = Path('/home/agent/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin')
EXTRA = OUT / 'additional-static-gates'
EXTRA.mkdir(exist_ok=True)


def git(*args):
    return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=ROOT).decode().strip()


def snapshot():
    names = ['scripts/ci/test_ci_source_integrity.py', 'scripts/ci/verify_ci_source.py',
             'scripts/ci/ci_observation.py', 'scripts/ci/run_fuzz_smoke.py',
             'scripts/ci/run_supply_chain.py', 'scripts/ci/ci_job.sh',
             'rust-toolchain.toml', 'trillionnium/Cargo.toml', 'trillionnium/Cargo.lock']
    hashes = {}
    matched = True
    for name in names:
        raw = (ROOT / name).read_bytes()
        committed = subprocess.check_output(['git', '--no-replace-objects', 'show', 'HEAD:' + name], cwd=ROOT)
        hashes[name] = hashlib.sha256(raw).hexdigest()
        matched = matched and raw == committed
    return {'head': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'status': git('status', '--porcelain', '--untracked-files=all'),
            'listed_inputs_sha256': hashes, 'listed_input_bytes_match_head': matched,
            'complete_repository_raw_bytes_attested': False}


def record(label, command, *, env=None, timeout=1200):
    before = snapshot()
    require_source = before['head'] == EXPECTED and before['listed_input_bytes_match_head']
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    print(json.dumps({'label': label, 'state': 'starting', 'argv': command}), flush=True)
    stdout = EXTRA / (label + '.stdout.log')
    stderr = EXTRA / (label + '.stderr.log')
    timed_out = False
    with stdout.open('xb') as out, stderr.open('xb') as err:
        if not require_source:
            code = 125
            err.write(b'EXACT_HEAD_OR_LISTED_SOURCE_BINDING_REFUSED\n')
        else:
            try:
                code = subprocess.run(command, cwd=ROOT, stdout=out, stderr=err,
                                      env=env, timeout=timeout, check=False).returncode
            except subprocess.TimeoutExpired:
                code, timed_out = 124, True
    after = snapshot()
    same = before == after
    receipt = {'label': label, 'argv': command, 'cwd': str(ROOT), 'started_at_utc': started_at,
               'ended_at_utc': datetime.now(timezone.utc).isoformat(),
               'elapsed_seconds': time.monotonic() - started, 'expected_head': EXPECTED,
               'source_before': before, 'source_after': after, 'source_observation_unchanged': same,
               'process_exit_code': code, 'timed_out': timed_out,
               'passed': code == 0 and same and require_source,
               'stdout': stdout.name, 'stderr': stderr.name,
               'stdout_sha256': hashlib.sha256(stdout.read_bytes()).hexdigest(),
               'stderr_sha256': hashlib.sha256(stderr.read_bytes()).hexdigest(),
               'production_qualification': False, 'native_mining_or_attack_scenario_executed': False}
    if env is not None:
        receipt['task_environment'] = {name: env[name] for name in
            ['CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_NET_OFFLINE', 'CARGO_BUILD_JOBS',
             'RUSTC', 'RUSTDOC'] if name in env}
    with (EXTRA / (label + '.json')).open('x', encoding='utf-8') as out:
        json.dump(receipt, out, indent=2, sort_keys=True)
        out.write('\n')
    print(json.dumps({'label': label, 'exit_code': code, 'passed': receipt['passed'],
                      'elapsed_seconds': receipt['elapsed_seconds'], 'receipt': str(EXTRA / (label + '.json'))}), flush=True)
    return receipt


if sys.argv[1] == 'source':
    record('source-integrity-negatives', ['python3', '-B', 'scripts/ci/test_ci_source_integrity.py'])
elif sys.argv[1] == 'rust':
    for name, arguments in [('rustc', ['--version']), ('cargo', ['--version']),
                            ('rustfmt', ['--version']), ('clippy-driver', ['--version'])]:
        record('installed-' + name, [str(TOOLCHAIN / name), *arguments])
    private_home = OUT / 'rust-cargo-home'
    private_home.mkdir(exist_ok=False)
    record('copy-installed-registry', ['cp', '-a', '--reflink=auto', '/home/agent/.cargo/registry', str(private_home)])
    environment = os.environ.copy()
    environment.update(CARGO_HOME=str(private_home), CARGO_TARGET_DIR=str(OUT / 'rust-target'),
                       CARGO_NET_OFFLINE='true', CARGO_BUILD_JOBS='2',
                       RUSTC=str(TOOLCHAIN / 'rustc'), RUSTDOC=str(TOOLCHAIN / 'rustdoc'),
                       PATH=str(TOOLCHAIN) + ':/home/agent/.cargo/bin:' + os.environ.get('PATH', ''))
    cargo = str(TOOLCHAIN / 'cargo')
    record('cargo-metadata-offline', [cargo, 'metadata', '--locked', '--offline', '--manifest-path',
           'trillionnium/Cargo.toml', '--all-features', '--format-version', '1'], env=environment)
    record('cargo-fmt-check', [cargo, 'fmt', '--manifest-path', 'trillionnium/Cargo.toml',
           '--all', '--', '--check'], env=environment)
    record('cargo-clippy-offline', [cargo, 'clippy', '--locked', '--offline', '--manifest-path',
           'trillionnium/Cargo.toml', '--workspace', '--all-targets', '--all-features', '--',
           '-D', 'warnings'], env=environment)
else:
    raise SystemExit('expected source or rust')
