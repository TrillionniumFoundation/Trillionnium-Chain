"""Record actual local native gates; no acceptance verdict is synthesized."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path('/workspace/scratch/d991ec408034/sprint_cell_20261029')
OUT = Path('/workspace/scratch/d991ec408034/sprint_runtime_20261029')
TARGET = Path('/workspace/scratch/d991ec408034/sprint_build_20261029')
TOOLCHAIN = Path('/tmp/chain-pon-rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu')
CARGO = '/tmp/chain-pon-cargo/bin/cargo'

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()

def capture():
    result = []
    for dirname in ('trillionnium', 'config', 'tests'):
        for p in sorted((ROOT / dirname).rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts:
                result.append({'path': str(p.relative_to(ROOT)), 'bytes': p.stat().st_size, 'sha256': sha(p)})
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('name')
    parser.add_argument('--clean-path-packages', action='store_true')
    parser.add_argument('cargo_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    env = os.environ.copy()
    env.update(CARGO_HOME='/tmp/chain-pon-cargo', RUSTUP_HOME='/tmp/chain-pon-rustup',
               RUSTUP_TOOLCHAIN='1.95.0-x86_64-unknown-linux-gnu', RUSTC=str(TOOLCHAIN/'bin/rustc'),
               CARGO_TARGET_DIR=str(TARGET), CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0',
               CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
               PATH='/tmp/chain-pon-cargo/bin:'+env['PATH'])
    before = capture()
    prefix = OUT / args.name
    metadata = {'schema': 'local-native-gate-observation-v1',
                'local_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                'merge_heads': (ROOT/'.git/MERGE_HEAD').read_text().split() if (ROOT/'.git/MERGE_HEAD').exists() else [],
                'source_scope': 'all materialized files under trillionnium, config and tests',
                'lock_sha256': sha(ROOT/'trillionnium/Cargo.lock'),
                'compiler_sha256': sha(TOOLCHAIN/'bin/rustc'),
                'cargo_binary_sha256': sha(TOOLCHAIN/'bin/cargo'),
                'rustup_launcher_sha256': sha('/tmp/chain-pon-cargo/bin/rustup'),
                'compiler_version': subprocess.check_output([str(TOOLCHAIN/'bin/rustc'), '-Vv'], env=env, text=True),
                'environment_overrides': {k: env[k] for k in ('CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN', 'RUSTC',
                    'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL', 'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG')},
                'product_qualification': False}
    prefix.with_suffix('.source-before.json').write_text(json.dumps(before, indent=2)+'\n')
    subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=ROOT, check=True)
    if args.clean_path_packages:
        graph = json.loads(subprocess.check_output([CARGO, 'metadata', '--manifest-path', 'trillionnium/Cargo.toml',
            '--locked', '--offline', '--no-deps', '--format-version', '1'], cwd=ROOT, env=env, text=True))
        packages = sorted(p['name'] for p in graph['packages'] if p['source'] is None)
        command = [CARGO, 'clean', '--manifest-path', 'trillionnium/Cargo.toml']
        for name in packages + ['libsqlite3-sys']:
            command.extend(['-p', name])
        with prefix.with_suffix('.cache-clean.log').open('w') as log:
            subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        metadata['invalidated_local_packages'] = packages
        metadata['fresh_sqlite_dependency_build'] = True
    cargo_args = args.cargo_args[1:] if args.cargo_args[:1] == ['--'] else args.cargo_args
    command = [CARGO] + cargo_args
    metadata['command'] = command
    metadata['started_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    started = time.monotonic()
    with prefix.with_suffix('.log').open('w') as log:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    metadata['exit_code'] = result.returncode
    metadata['wall_seconds'] = time.monotonic()-started
    after = capture()
    prefix.with_suffix('.source-after.json').write_text(json.dumps(after, indent=2)+'\n')
    metadata['source_unchanged'] = before == after
    metadata['log_sha256'] = sha(prefix.with_suffix('.log'))
    metadata['source_before_sha256'] = sha(prefix.with_suffix('.source-before.json'))
    metadata['source_after_sha256'] = sha(prefix.with_suffix('.source-after.json'))
    prefix.with_suffix('.json').write_text(json.dumps(metadata, indent=2)+'\n')
    print(json.dumps({k: metadata[k] for k in ('exit_code', 'wall_seconds', 'source_unchanged', 'log_sha256')}), flush=True)
    return result.returncode if metadata['source_unchanged'] else 3

if __name__ == '__main__':
    raise SystemExit(main())
