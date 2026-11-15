#!/usr/bin/env python3
"""Snapshot exact W1 source and build two isolated selected-source diagnostics."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import tomllib

ROOT = Path('/workspace/scratch/6f6f9b342c90/Trillionnium-Chain')
OUT = Path(__file__).resolve().parent
TOOLCHAIN = Path('/tmp/trnm-original-budget-rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin')
CARGO_ROOT = Path('/tmp/trnm-original-budget-cargo')
EXPECTED_HEAD = '7c5caf5bce1396976808a0f504c4163fbc1aed44'
SOURCE_PREFIX = 'trillionnium/crates/trnm-crypto-primitives/src/'
SELECTED = [SOURCE_PREFIX + 'pon_work.rs', SOURCE_PREFIX + 'pon_work']

def digest(data):
    return hashlib.sha256(data).hexdigest()

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)

def package_id(package):
    return (package['name'], package['version'], package.get('source'), package.get('checksum'))

def environment():
    forbidden = sorted(k for k in os.environ if
        k in {'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
              'CARGO_INCREMENTAL', 'RUSTC', 'RUSTUP_TOOLCHAIN', 'CARGO_BUILD_RUSTFLAGS', 'CARGO_BUILD_TARGET'}
        or k.startswith('CARGO_PROFILE_') or (k.startswith('CARGO_TARGET_') and k.endswith('_RUSTFLAGS')))
    if forbidden:
        raise RuntimeError('compiler/profile overrides present: ' + ','.join(forbidden))
    env = dict(os.environ)
    env['PATH'] = str(TOOLCHAIN) + os.pathsep + env.get('PATH', '')
    env['CARGO_HOME'] = str(CARGO_ROOT)
    env['RUSTUP_HOME'] = '/tmp/trnm-original-budget-rustup'
    return env

def command(command, cwd, stem, env):
    started = time.time_ns()
    with (OUT / (stem + '.stdout')).open('wb') as stdout, (OUT / (stem + '.stderr')).open('wb') as stderr:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=stdout, stderr=stderr)
    receipt = {'command': command, 'cwd': str(cwd), 'exit_code': result.returncode,
               'started_unix_ns': started, 'finished_unix_ns': time.time_ns()}
    (OUT / (stem + '.receipt.json')).write_text(json.dumps(receipt, indent=2) + '\n')
    if result.returncode:
        raise RuntimeError(f'{stem} failed: exit {result.returncode}; preserved stdout/stderr')

def main():
    assert git('rev-parse', 'HEAD').decode().strip() == EXPECTED_HEAD
    env = environment()
    cargo = str(TOOLCHAIN / 'cargo')
    rustc = str(TOOLCHAIN / 'rustc')
    compiler = subprocess.check_output([rustc, '-vV'], env=env).decode()
    assert 'rustc 1.95.0 ' in compiler
    (OUT / 'rustc-vV.txt').write_text(compiler)
    (OUT / 'cargo-version.txt').write_bytes(subprocess.check_output([cargo, '-V'], env=env))
    tracked = git('ls-tree', '-r', '--name-only', 'HEAD', '--', *SELECTED).decode().splitlines()
    untracked = git('ls-files', '--others', '--exclude-standard', '--', *SELECTED).decode().splitlines()
    original_lock = (ROOT / 'trillionnium/Cargo.lock').read_bytes()
    (OUT / 'source-workspace-Cargo.lock').write_bytes(original_lock)
    original_packages = {package_id(p) for p in tomllib.loads(original_lock.decode())['package'] if p.get('source')}
    manifest = {'schema': 'pon-cache-diagnostic-build-v1', 'baseline_commit': EXPECTED_HEAD,
                'baseline_tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
                'workspace_lock_sha256': digest(original_lock), 'compiler': compiler,
                'compiler_elf_sha256': digest((TOOLCHAIN / 'rustc').read_bytes()),
                'cargo_elf_sha256': digest((TOOLCHAIN / 'cargo').read_bytes()),
                'compile_profile': 'unmodified Cargo default release', 'compiler_overrides': [],
                'same_harness_main_sha256': digest((OUT / 'main.rs').read_bytes()),
                'same_manifest_sha256': digest((OUT / 'Cargo.toml').read_bytes()),
                'qualification': {'selected_source_diagnostic_only': True, 'whole_workspace': False,
                                  'fixed_host': False, 'attacker_cost': False, 'service': False},
                'variants': {}}
    for variant in ['baseline', 'candidate']:
        harness = Path('/tmp/pon-cache-benchmark-' + variant)
        if harness.exists():
            raise RuntimeError(f'refusing to reuse an existing diagnostic checkout: {harness}')
        harness.mkdir()
        (harness / 'src').mkdir()
        for ancestor in [harness, *harness.parents, CARGO_ROOT]:
            directory = ancestor if ancestor == CARGO_ROOT else ancestor / '.cargo'
            for filename in ['config', 'config.toml']:
                if (directory / filename).exists():
                    raise RuntimeError(f'unqualified Cargo config: {directory / filename}')
        records = []
        for source in tracked + (untracked if variant == 'candidate' else []):
            data = git('show', 'HEAD:' + source) if variant == 'baseline' else (ROOT / source).read_bytes()
            destination = harness / 'src' / source.removeprefix(SOURCE_PREFIX)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            records.append({'repository_path': source, 'harness_path': str(destination.relative_to(harness)),
                            'bytes': len(data), 'sha256': digest(data),
                            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()})
        shutil.copyfile(OUT / 'main.rs', harness / 'src/main.rs')
        shutil.copyfile(OUT / 'Cargo.toml', harness / 'Cargo.toml')
        if variant == 'baseline':
            (harness / 'Cargo.lock').write_bytes(original_lock)
            metadata_flags = ['--offline']
        else:
            shutil.copyfile('/tmp/pon-cache-benchmark-baseline/Cargo.lock', harness / 'Cargo.lock')
            metadata_flags = ['--locked', '--offline']
        selected_env = dict(env)
        selected_env['CARGO_TARGET_DIR'] = str(harness / 'target')
        command([cargo, 'metadata', '--format-version', '1', *metadata_flags], harness,
                variant + '-metadata', selected_env)
        lock = (harness / 'Cargo.lock').read_bytes()
        packages = [package_id(p) for p in tomllib.loads(lock.decode())['package'] if p.get('source')]
        assert all(p in original_packages for p in packages), 'a resolved registry version/checksum differs from workspace lock'
        (OUT / (variant + '-Cargo.lock')).write_bytes(lock)
        command([cargo, 'build', '--release', '--locked', '--offline'], harness,
                variant + '-build', selected_env)
        elf = harness / 'target/release/pon-cache-benchmark'
        entries = {'harness': str(harness), 'target': str(harness / 'target'),
                   'elf': str(elf), 'elf_bytes': elf.stat().st_size,
                   'elf_sha256': digest(elf.read_bytes()), 'lock_sha256': digest(lock),
                   'registry_packages': packages, 'all_registry_pins_match_workspace': True,
                   'sources': records}
        manifest['variants'][variant] = entries
        (OUT / 'build-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        print(variant, 'built', entries['elf_sha256'], flush=True)
    assert manifest['variants']['baseline']['lock_sha256'] == manifest['variants']['candidate']['lock_sha256']
    print('complete identical-lock isolated builds', flush=True)

if __name__ == '__main__':
    main()
