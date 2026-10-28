#!/usr/bin/env python3
"""Attempt5: compile once with the authenticated official 1.91.1 compiler.

No receipt verification, guest execution or proving is invoked. This script
uses one caller-owned output directory and never retries a failed stage.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import tomllib

ROOT = Path('/workspace/scratch/56818e4fba76/chain-w1-next')
BASE = ROOT / 'formal/pon-nakamoto-v1/w1_batch'
HEAD = '401096e8f9eed84fcb4d78122a49fa5dd3aa88e9'
TREE = 'db0908a57db7675b22485c6ad712c8e19e4f38fa'
TARGET = Path('/tmp/trnm-w1-r2-target')
CACHE = Path('/tmp/pure-pon-cargo-20261027')
RISC0_HOME = Path('/tmp/w1-risc0-1911-resources-r8/home')
COMPILER = RISC0_HOME / 'toolchains/v1.91.1-rust-x86_64-unknown-linux-gnu'
ARCHIVE = Path('/tmp/w1-risc0-1911-resources-r8/rust-1.91.1.tar.gz')
ARCHIVE_HASH = 'e082a1dc44abdef1d95460295a70218eb294ab999b834570ec932d05641cce5d'
WRAPPER = Path('/tmp/w1-batch-attempt5-wrapper-r8/cargo')
WRAPPER_HASH = '6a65805d8f000fa04e5778ea4de16feb6224808915672033ad7f59a527ec20d2'
INSTALL = Path('/tmp/w1-risc0-1911-install-20261028-r8/acquisition-result.json')
INSTALL_HASH = '30beee21e1def3c0f7f24ba7db470e1c656ae68979395eff0456e958968a3335'
INSTALL_GUARD = Path('/tmp/w1-risc0-1911-install-20261028-r8/result.json')
INSTALL_GUARD_HASH = '4133aab9841a32198cba529bd96dde78496ec696e74ef5ca4fee8db1a11b591e'
INSTALLED_TREE = Path('/tmp/w1-risc0-1911-install-20261028-r8/installed-tree.json')
INSTALLED_TREE_HASH = 'c8a8f1170fa5d54f565e0dbeea0e33605664e5d2aaaf0851ad156dd225f877d9'
COMPILER_HASH = '207d5fd3164e7e45393e1bac2513f41760af3b48facbe879f52e9af31c696823'
SETTINGS_HASH = '339cfb8be3b1247b0997b442ded5605bb9daaa77a8a2feecf1bd7c66741301a6'
NATIVE_HASHES = {
    'cargo': '841072d1d92f9e841d9ba5b0814182a0adf064acf4527cd120967b7bc49dcb66',
    'rustc': 'bff349e72704ff70bc08a234a3847338e797065bbedde5e556808bc87b7bf7c6',
}
SDK_SOURCE = Path('/tmp/pure-pon-cargo-20261027/registry/src/index.crates.io-1949cf8c6b5b557f/risc0-build-3.0.6/src/lib.rs')
SDK_SOURCE_HASH = '30a523d2474299139a0616de729a0b034527bf018aaf3b490e72d900b79b88ea'
LOCKS = {
    BASE / 'Cargo.lock': '32953cbb86bb56186137507ee9e9bf59827bd8325c6e28c12b40d5c166fbfa4d',
    BASE / 'methods/guest/Cargo.lock': '018423c898d09d0be7a7fbe207e4a1672c5b6f36202dda765a81da852c044d18',
}


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def emit(out, value):
    row = {'unix_ns': time.time_ns(), **value}
    with (out / 'pipeline-events.jsonl').open('a') as file:
        file.write(json.dumps(row, sort_keys=True) + '\n')
        file.flush()
        os.fsync(file.fileno())
    print(json.dumps(row, sort_keys=True), flush=True)


def run(out, label, command, env):
    emit(out, {'stage': label, 'state': 'STARTED', 'command': command})
    started = time.monotonic()
    with (out / (label + '.stdout')).open('xb') as stdout, (out / (label + '.stderr')).open('xb') as stderr:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr)
    emit(out, {'stage': label, 'state': 'EXIT', 'returncode': result.returncode,
               'wall_seconds': time.monotonic() - started,
               'stdout_sha256': digest(out / (label + '.stdout')),
               'stderr_sha256': digest(out / (label + '.stderr'))})
    if result.returncode:
        raise RuntimeError(f'{label} failed: {result.returncode}; no retry')


def verify_installed_compiler():
    for path, expected in ((INSTALL, INSTALL_HASH), (INSTALL_GUARD, INSTALL_GUARD_HASH),
                           (INSTALLED_TREE, INSTALLED_TREE_HASH)):
        if digest(path) != expected:
            raise RuntimeError('authenticated installation receipt changed')
    installed = json.loads(INSTALL.read_text())
    guarded = json.loads(INSTALL_GUARD.read_text())
    if (installed['outcome'] != 'OFFICIAL_COMPILER_INSTALLED_METADATA_CHECKED_NO_BUILD'
            or installed['compiler_sha256'] != COMPILER_HASH
            or guarded['status'] != 'completed' or guarded['command_returncode'] != 0
            or guarded['errors'] or guarded['remaining_owned_processes']):
        raise RuntimeError('prior complete installation was not successful')
    if (RISC0_HOME.resolve(strict=True) != RISC0_HOME
            or COMPILER.is_symlink() or COMPILER.resolve(strict=True) != COMPILER
            or set(COMPILER.parent.iterdir()) != {COMPILER}):
        raise RuntimeError('isolated exact sole compiler selection is not satisfied')
    settings = RISC0_HOME / 'settings.toml'
    if settings.is_symlink() or digest(settings) != SETTINGS_HASH:
        raise RuntimeError('exact supported compiler settings changed')
    if tomllib.loads(settings.read_text()) != {'default_versions': {'rust': '1.91.1'}}:
        raise RuntimeError('requested official compiler default is not exact')
    inventory = json.loads(INSTALLED_TREE.read_text())['files']
    actual_paths = {str(path.relative_to(COMPILER)) for path in COMPILER.rglob('*')}
    if actual_paths != {row['path'] for row in inventory}:
        raise RuntimeError('complete compiler tree membership changed')
    for row in inventory:
        path = COMPILER / row['path']
        if 'symlink' in row:
            resolved = path.resolve(strict=True)
            if (not path.is_symlink() or os.readlink(path) != row['symlink']
                    or not (resolved == COMPILER or COMPILER in resolved.parents)):
                raise RuntimeError('installed compiler symlink changed or escaped')
        elif row.get('directory'):
            if not path.is_dir() or path.is_symlink():
                raise RuntimeError('installed compiler directory changed')
        elif (path.is_symlink() or not path.is_file() or path.stat().st_size != row['bytes']
                or digest(path) != row['sha256']):
            raise RuntimeError('authenticated compiler regular file changed')
    if digest(COMPILER / 'bin/rustc') != COMPILER_HASH:
        raise RuntimeError('official compiler binary changed')
    return installed


def main():
    out = Path(sys.argv[1])
    if not out.is_dir():
        raise RuntimeError('guard must create the new output directory first')
    for key in ('RISC0_SKIP_BUILD', 'RISC0_BUILD_DEBUG', 'RISC0_DEV_MODE', 'RISC0_PROVER',
                'BONSAI_API_URL', 'BONSAI_API_KEY', 'RISC0_RUST_SRC',
                'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTFLAGS',
                'CC_riscv32im_risc0_zkvm_elf', 'CFLAGS_riscv32im_risc0_zkvm_elf',
                'CARGO_ENCODED_RUSTFLAGS'):
        if key in os.environ:
            raise RuntimeError(f'unexpected inherited build/proof selector: {key}')
    env = dict(os.environ, CARGO_HOME=str(CACHE), RISC0_HOME=str(RISC0_HOME),
               CARGO_TARGET_DIR=str(TARGET), CARGO_BUILD_JOBS='1', CARGO_INCREMENTAL='0',
               RISC0_BUILD_LOCKED='1', CARGO_NET_OFFLINE='true', PYTHONDONTWRITEBYTECODE='1',
               PATH=str(WRAPPER.parent) + ':/tmp/pure-pon-toolchain-20261027/bin:' + os.environ['PATH'],
               TRNM_W1_CARGO_WRAPPER_LOG=str(out / 'cargo-wrapper.jsonl'),
               TRNM_W1_CARGO_WRAPPER_SHA256=WRAPPER_HASH)
    declaration = {
        'schema': 'TRNM-W1-BATCH-PHASE0-PIPELINE5', 'attempt': 5, 'source_commit': HEAD,
        'source_tree': TREE, 'pipeline_sha256': digest(Path(__file__)),
        'environment': {key: env[key] for key in ('CARGO_HOME', 'RISC0_HOME',
            'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL',
            'RISC0_BUILD_LOCKED', 'CARGO_NET_OFFLINE', 'PATH')},
        'guest_executed': False, 'receipt_verified': False, 'prover_executed': False,
        'wrapper_sha256': WRAPPER_HASH, 'sdk_source_sha256': SDK_SOURCE_HASH,
        'compiler_install_receipt_sha256': INSTALL_HASH,
        'compiler_install_guard_sha256': INSTALL_GUARD_HASH,
        'complete_installed_tree_receipt_sha256': INSTALLED_TREE_HASH,
        'guest_compiler_sha256': COMPILER_HASH, 'exact_settings_sha256': SETTINGS_HASH,
        'compiler_restored_again': False, 'network_download_permitted': False,
        'old_absolute_deadline_extended': False,
    }
    emit(out, declaration)
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], cwd=ROOT, text=True).splitlines()
    if actual != [HEAD, TREE]:
        raise RuntimeError('frozen source changed')
    run(out, 'source-before', ['python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head', '--expected-head', HEAD], env)
    run(out, 'preflight', ['bash', 'scripts/project-preflight.sh'], env)
    for path, expected in LOCKS.items():
        if digest(path) != expected:
            raise RuntimeError('independent lock changed')
    packages = tomllib.loads((BASE / 'Cargo.lock').read_text())['package']
    build = [item for item in packages if item['name'] == 'risc0-build' and item['version'] == '3.0.6']
    if len(build) != 1 or build[0].get('source') != 'registry+https://github.com/rust-lang/crates.io-index':
        raise RuntimeError('locked build dependency identity')
    crate = CACHE / 'registry/cache/index.crates.io-1949cf8c6b5b557f/risc0-build-3.0.6.crate'
    if not crate.is_file() or digest(crate) != build[0]['checksum']:
        raise RuntimeError('exact already-restored dependency archive unavailable; no download')
    emit(out, {'stage': 'dependency', 'state': 'ALREADY_PRESENT', 'sha256': digest(crate)})
    if digest(WRAPPER) != WRAPPER_HASH or digest(SDK_SOURCE) != SDK_SOURCE_HASH:
        raise RuntimeError('reviewed wrapper or unchanged SDK source changed')
    if (ARCHIVE.is_symlink() or not ARCHIVE.is_file()
            or ARCHIVE.stat().st_size != 515330687 or digest(ARCHIVE) != ARCHIVE_HASH):
        raise RuntimeError('exact authenticated new official compiler archive missing or changed')
    verify_installed_compiler()
    for name, expected in NATIVE_HASHES.items():
        if digest(Path('/tmp/pure-pon-toolchain-20261027/bin') / name) != expected:
            raise RuntimeError('fixed native toolchain identity changed')
    emit(out, {'stage': 'compiler-adoption', 'state': 'CHECKSUM_VERIFIED_NO_RESTORE',
               'archive_sha256': ARCHIVE_HASH, 'guest_rustc_sha256': COMPILER_HASH,
               'installation_receipt_sha256': INSTALL_HASH,
               'complete_installed_tree_sha256': INSTALLED_TREE_HASH,
               'exact_supported_settings_sha256': SETTINGS_HASH,
               'sole_expected_compiler_directory': str(COMPILER),
               'highest_installed_fallback_used': False})
    run(out, 'cargo-version', ['/tmp/pure-pon-toolchain-20261027/bin/cargo', '--version'], env)
    run(out, 'native-version', ['/tmp/pure-pon-toolchain-20261027/bin/rustc', '--version'], env)
    run(out, 'guest-version', [str(COMPILER / 'bin/rustc'), '--version'], env)
    run(out, 'build', ['/tmp/pure-pon-toolchain-20261027/bin/cargo', 'build', '--locked', '--offline',
                     '--release', '--manifest-path', 'formal/pon-nakamoto-v1/w1_batch/Cargo.toml',
                     '-p', 'trnm-w1-batch-host'], env)
    if digest(WRAPPER) != WRAPPER_HASH or digest(SDK_SOURCE) != SDK_SOURCE_HASH:
        raise RuntimeError('build changed wrapper or SDK source')
    wrapper_rows = [json.loads(line) for line in (out / 'cargo-wrapper.jsonl').read_text().splitlines()]
    if not wrapper_rows:
        raise RuntimeError('nested cargo invocation did not pass through reviewed wrapper')
    for row in wrapper_rows:
        if (row['source_sha256'] != WRAPPER_HASH or not row['home_preserved']
                or not row['sdk_rustc_preserved'] or not row['sdk_encoded_flags_preserved']
                or not row['argv_tail_unchanged']
                or row['sdk_rustc_path'] != str(COMPILER / 'bin/rustc')):
            raise RuntimeError('nested cargo wrapper invariants violated')
    verify_installed_compiler()
    for path, expected in LOCKS.items():
        if digest(path) != expected:
            raise RuntimeError('build changed an independent lock')
    run(out, 'source-after', ['python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head', '--expected-head', HEAD], env)
    generated = list((TARGET / 'release/build').glob('trnm-w1-batch-methods-*/out/methods.rs'))
    if len(generated) != 1:
        raise RuntimeError('ambiguous generated batch methods')
    methods = generated[0].read_text()
    match = re.search(r'TRNM_W1_BATCH_GUEST_ID\s*:\s*\[u32;\s*8\]\s*=\s*\[([^]]+)\]', methods)
    if not match:
        raise RuntimeError('generated image ID not found')
    image = [int(value) for value in re.findall(r'\d+', match.group(1))]
    if len(image) != 8:
        raise RuntimeError('image word count')
    elf_match = re.search(r'TRNM_W1_BATCH_GUEST_ELF.*?include_bytes!\("([^"]+)"\)', methods, re.S)
    if not elf_match:
        raise RuntimeError('real generated guest ELF path not found')
    guest = Path(elf_match.group(1))
    host = TARGET / 'release/trnm-w1-batch-host'
    (out / 'generated-methods.rs').write_bytes(generated[0].read_bytes())
    (out / 'batch-guest.bin').write_bytes(guest.read_bytes())
    result = {
        **declaration, 'outcome': 'SOURCE_COMPILED_NO_PROOF', 'image_id': image,
        'guest_path': str(guest), 'guest_sha256': digest(guest), 'guest_bytes': guest.stat().st_size,
        'host_path': str(host), 'host_sha256': digest(host), 'host_bytes': host.stat().st_size,
        'independent_locks_unchanged': True, 'compiled_source_unchanged': True,
        'complete_compiler_tree_unchanged': True,
        'sdk_guest_compilation_with_official_1911_completed': True,
        'guest_runtime_or_prover_compatibility_established': False,
        'benefit_gate': 'UNMEASURED', 'production_activation': False,
    }
    (out / 'build-result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    emit(out, result)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        if len(sys.argv) > 1 and Path(sys.argv[1]).is_dir():
            emit(Path(sys.argv[1]), {'stage': 'PIPELINE_FAILED', 'error': repr(error), 'retry': False})
        raise
