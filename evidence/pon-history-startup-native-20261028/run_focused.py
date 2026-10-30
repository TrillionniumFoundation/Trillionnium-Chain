#!/usr/bin/env python3
"""Compile current source with pinned read-only third-party cache; not whole Cargo CI."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUSTC = Path('/workspace/scratch/301262829a43/pon-build-inputs/unpacked/toolchain/bin/rustc')
CACHE = Path('/tmp/pon-history-final-20261027/debug/deps')
OUTPUT = Path('/tmp/pon-history-epoch-v1-20261028/startup-candidate')
FLOOR = 256 * 1024 * 1024


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def bounded(command, out, env, seconds):
    start = time.monotonic()
    result = {'command': command, 'seconds': seconds, 'passed': False,
              'available_disk_floor_bytes': FLOOR, 'termination_reason': None,
              'scope': 'owned new-session child; keep leader until final group signal'}
    child = None
    out.mkdir()
    try:
        with (out / 'native.log').open('xb') as log:
            disk = os.statvfs(OUTPUT)
            if disk.f_bavail * disk.f_frsize < FLOOR:
                result['termination_reason'] = 'RESOURCE_ABORT_BEFORE_START'
                return result
            child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            stopped = None
            while True:
                terminal = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                elapsed = time.monotonic() - start
                if terminal:
                    if elapsed > seconds and result['termination_reason'] is None:
                        result['termination_reason'] = 'LATE_TERMINAL_OBSERVATION'
                    break
                disk = os.statvfs(OUTPUT)
                available = disk.f_bavail * disk.f_frsize
                reason = ('TIMEOUT' if elapsed >= seconds else
                          'RESOURCE_ABORT_DISK' if available < FLOOR else None)
                if stopped is None and reason:
                    result['termination_reason'] = reason
                    stopped = time.monotonic()
                    os.killpg(child.pid, signal.SIGTERM)
                if stopped is not None and time.monotonic() - stopped > 10:
                    os.killpg(child.pid, signal.SIGKILL)
                time.sleep(0.25)
    finally:
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            pid, status, usage = os.wait4(child.pid, 0)
            assert pid == child.pid
            child.returncode = os.waitstatus_to_exitcode(status)
            result.update(native_returncode=child.returncode, actual_wait4_status=status,
                          user_cpu_seconds=usage.ru_utime, system_cpu_seconds=usage.ru_stime,
                          max_rss_kib=usage.ru_maxrss)
            result['passed'] = child.returncode == 0 and result['termination_reason'] is None
        result['elapsed_seconds'] = time.monotonic() - start
        if (out / 'native.log').is_file():
            result['log_sha256'] = sha(out / 'native.log')
        write(out / 'terminal.json', result)
    return result


def main():
    out = HERE / sys.argv[1]
    out.mkdir()
    OUTPUT.mkdir(exist_ok=True)
    subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=ROOT, check=True)
    log = ROOT.parent / 'history-next/evidence/pon-history-publication-native-20261028/build-05/native.log'
    cache = {}
    for line in log.read_text().splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get('reason') == 'compiler-artifact':
            for name in row.get('filenames', []):
                p = Path(name)
                if p.suffix in ['.rlib', '.so'] and not p.name.startswith('libtrnm_'):
                    cache[row['target']['name']] = CACHE / p.name
    cache_pins = {str(p): sha(p) for p in cache.values()}
    source_paths = []
    for crate in ['trnm-protocol', 'trnm-crypto-primitives', 'trnm-verification-profiles', 'trnm-mvcc-fee']:
        source_paths.extend((ROOT / 'trillionnium/crates' / crate / 'src').rglob('*.rs'))
        source_paths.append(ROOT / 'trillionnium/crates' / crate / 'Cargo.toml')
    source_paths.extend([ROOT / 'trillionnium/Cargo.toml', ROOT / 'trillionnium/Cargo.lock',
        ROOT / 'trillionnium/crates/trnm-mvcc-fee/tests/checkpoint_tile_material_v1.rs'])
    before = {str(p.relative_to(ROOT)): sha(p) for p in source_paths}
    write(out / 'source-before.json', before)
    write(out / 'third-party-cache-pins.json', cache_pins)
    write(out / 'compiler.json', {'path': str(RUSTC), 'sha256': sha(RUSTC),
        'version': subprocess.check_output([str(RUSTC), '-vV'], text=True)})
    external = dict(cache)
    env = dict(os.environ, CARGO_PKG_VERSION='0.1.0', CARGO_PKG_NAME='trnm-mvcc-fee',
               CARGO_MANIFEST_DIR=str(ROOT / 'trillionnium/crates/trnm-mvcc-fee'))
    jobs = [
        ('trnm-protocol', 3, ['hex', 'serde', 'sha2', 'thiserror']),
        ('trnm-crypto-primitives', 3, ['anyhow', 'sha2', 'hex', 'ed25519_dalek', 'trnm_protocol']),
        ('trnm-verification-profiles', 0, ['sha2']),
        ('trnm-mvcc-fee', 1, ['trnm_verification_profiles', 'trnm_protocol', 'trnm_crypto_primitives',
                            'serde', 'serde_json', 'hex', 'borsh', 'rusqlite', 'sha2']),
    ]
    receipts = []
    for crate, opt, deps in jobs:
        name = crate.replace('-', '_')
        executable = OUTPUT / ('lib' + name + '-startup.rlib')
        command = [str(RUSTC), '--edition=2021', '--crate-name', name, '--crate-type=rlib',
                   str(ROOT / 'trillionnium/crates' / crate / 'src/lib.rs'),
                   '-C', 'metadata=history_startup_20261028', '-C', f'opt-level={opt}',
                   '-C', 'debug-assertions=yes', '-C', 'overflow-checks=yes', '-C', 'debuginfo=0',
                   '-C', 'codegen-units=16', '-L', 'dependency=' + str(CACHE),
                   '-L', 'dependency=' + str(OUTPUT), '-o', str(executable)]
        if crate == 'trnm-mvcc-fee':
            command += ['--cfg', 'feature="default"']
        for dep in deps:
            command += ['--extern', dep + '=' + str(external[dep])]
        receipt = bounded(command, out / crate, env, 600)
        receipts.append(receipt)
        if not receipt['passed']:
            break
        external[name] = executable
    if all(row['passed'] for row in receipts):
        binary = OUTPUT / ('material-tests-' + out.name)
        command = [str(RUSTC), '--edition=2021', '--test', '--crate-name', 'checkpoint_tile_material_v1',
                   str(ROOT / 'trillionnium/crates/trnm-mvcc-fee/tests/checkpoint_tile_material_v1.rs'),
                   '-C', 'opt-level=0', '-C', 'debug-assertions=yes', '-C', 'overflow-checks=yes',
                   '-C', 'debuginfo=0', '-L', 'dependency=' + str(CACHE),
                   '-L', 'dependency=' + str(OUTPUT), '-o', str(binary)]
        for dep in ['trnm_crypto_primitives', 'trnm_protocol', 'trnm_mvcc_fee', 'serde_json', 'sha2', 'hex']:
            command += ['--extern', dep + '=' + str(external[dep])]
        receipt = bounded(command, out / 'test-build', env, 300)
        receipts.append(receipt)
        if receipt['passed']:
            receipts.append(bounded([str(binary), '--test-threads=1', '--nocapture'], out / 'tests', env, 120))
    after = {str(p.relative_to(ROOT)): sha(p) for p in source_paths}
    cache_after = {str(p): sha(p) for p in cache.values()}
    write(out / 'source-after.json', after)
    write(out / 'result.json', {'scope': 'fresh current workspace libraries and actual focused native tests; '
          'read-only pinned third-party cache, not a whole Cargo CI qualification',
          'source_stable': before == after, 'third_party_cache_stable': cache_pins == cache_after,
          'passed': len(receipts) == 6 and all(row['passed'] for row in receipts) and before == after and cache_pins == cache_after,
          'receipts': receipts})
    print((out / 'result.json').read_text(), flush=True)


if __name__ == '__main__':
    main()
