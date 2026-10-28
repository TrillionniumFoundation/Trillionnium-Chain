#!/usr/bin/env python3
"""Attempt3: adopt authenticated compiler and restore intended Cargo constraints.

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
HEAD = 'b3f3fa57a4ed928a1eae61a97aecc4a9d90df467'
TREE = 'ffe37b67fa03820053214879c619b730d518d6c7'
TARGET = Path('/tmp/trnm-w1-r2-target')
CACHE = Path('/tmp/pure-pon-cargo-20261027')
RISC0_HOME = Path('/tmp/pure-pon-risc0-home-20261027')
COMPILER = RISC0_HOME / 'toolchains/v1.88.0-rust-x86_64-unknown-linux-gnu'
ARCHIVE = Path('/tmp/trnm-risc0-rust-1.88.0.tar.gz')
ARCHIVE_HASH = '222651797ba58f0bafd959191a48d23b35b3266d9e082fc49fb4d84733064fce'
WRAPPER = Path('/tmp/w1-batch-attempt3-wrapper-r8/cargo')
WRAPPER_HASH = 'b0d6de899b65a084185b09d37edd2d42b5ecdc1366ae0b53e3867922406763df'
ADOPTION = Path('/tmp/w1-batch-attempt3-toolchain-adoption-20261028-r8.json')
ADOPTION_HASH = 'ac0380e20b04dae80ba784ea6e36ad70e8750ee8705569020ac7473f8d816778'
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


def main():
    out = Path(sys.argv[1])
    if not out.is_dir():
        raise RuntimeError('guard must create the new output directory first')
    for key in ('RISC0_SKIP_BUILD', 'RISC0_DEV_MODE', 'RISC0_PROVER',
                'BONSAI_API_URL', 'BONSAI_API_KEY', 'RISC0_RUST_SRC',
                'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTFLAGS',
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
        'schema': 'TRNM-W1-BATCH-PHASE0-PIPELINE3', 'attempt': 3, 'source_commit': HEAD,
        'source_tree': TREE, 'pipeline_sha256': digest(Path(__file__)),
        'environment': {key: env[key] for key in ('CARGO_HOME', 'RISC0_HOME',
            'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL',
            'RISC0_BUILD_LOCKED', 'CARGO_NET_OFFLINE', 'PATH')},
        'guest_executed': False, 'receipt_verified': False, 'prover_executed': False,
        'wrapper_sha256': WRAPPER_HASH, 'sdk_source_sha256': SDK_SOURCE_HASH,
        'toolchain_adoption_sha256': ADOPTION_HASH,
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
    if digest(ADOPTION) != ADOPTION_HASH:
        raise RuntimeError('compiler adoption record changed')
    adoption = json.loads(ADOPTION.read_text())
    previous = Path('/tmp/w1-batch-phase0-attempt2-20261028-r8/result.json')
    if digest(previous) != adoption['adopted_from_attempt2_result_sha256']:
        raise RuntimeError('previous terminal receipt changed')
    if (not COMPILER.is_dir() or ARCHIVE.stat().st_size != 490849318
            or digest(ARCHIVE) != ARCHIVE_HASH):
        raise RuntimeError('authenticated already-restored compiler archive missing or changed')
    if (digest(COMPILER / 'bin/rustc') != adoption['guest_rustc_sha256_from_original_archive']
            or adoption['guest_rustc_sha256_from_original_archive']
                != adoption['guest_rustc_sha256_on_disk']
            or adoption['restoration_repeated']):
        raise RuntimeError('restored guest compiler does not match original official archive member')
    for name in ('cargo', 'rustc'):
        if digest(Path('/tmp/pure-pon-toolchain-20261027/bin') / name) != adoption['native_' + name + '_sha256']:
            raise RuntimeError('fixed native toolchain identity changed')
    emit(out, {'stage': 'compiler-adoption', 'state': 'CHECKSUM_VERIFIED_NO_RESTORE',
               'archive_sha256': ARCHIVE_HASH,
               'guest_rustc_sha256': adoption['guest_rustc_sha256_on_disk'],
               'adoption_receipt_sha256': ADOPTION_HASH})
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
                or not row['argv_tail_unchanged']):
            raise RuntimeError('nested cargo wrapper invariants violated')
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
