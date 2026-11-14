#!/usr/bin/env python3
"""One newly owned ROG checkout: functional Rust gates, never security qualification."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import tomllib

EXPECTED = '4716bade250f327b012a098418f4eece6b73fcaa'
EXPECTED_TREE = 'bbc0278f87282d9bcf4e22b167040233516da310'
REMOTE_BRANCH = 'fix/chain-joint-production-tail-20261110-8e76'
LOCAL_BRANCH = 'test/chain-joint-tail-native-20261110-8e76'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
SEED = Path('/home/qian-qi/chain-hepta-review-340e')
BASE = Path('/home/qian-qi/chain-joint-tail-native-20261110-8e76')
SOURCE = BASE / 'source'
RECORDS = BASE / 'records'
CARGO_HOME = BASE / 'cargo-home'
TARGET = BASE / 'target'
ORIGINAL_REGISTRY = Path('/home/qian-qi/.cargo/registry')
REGISTRY_ID = 'index.crates.io-1949cf8c6b5b557f'
RUSTUP_BIN = Path('/home/qian-qi/.cargo/bin')
TOOLCHAIN = Path('/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu')
MIN_START_FREE = 6 * 1024**3
STOP_FREE = 1024**3
MAX_STAGE_SECONDS = 1200


def now():
    return datetime.now(timezone.utc).isoformat()


def digest_file(path):
    path = Path(path)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for body in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(body)
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest.hexdigest()}


def save(name, value):
    with (RECORDS / name).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def announce(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def disk(path):
    return dict(zip(('total', 'used', 'free'), shutil.disk_usage(path)))


def checked_copy(src, dst, expected_sha256=None):
    src, dst = Path(src), Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    observed = os.fstat(descriptor)
    assert stat.S_ISREG(observed.st_mode), 'input is not a regular file'
    digest = hashlib.sha256()
    try:
        with os.fdopen(descriptor, 'rb') as reader, dst.open('xb') as writer:
            for body in iter(lambda: reader.read(1024 * 1024), b''):
                digest.update(body)
                writer.write(body)
            writer.flush()
            os.fsync(writer.fileno())
            after = os.fstat(reader.fileno())
        fingerprint = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
        assert fingerprint(observed) == fingerprint(after), 'source file changed during copy'
        assert fingerprint(observed) == fingerprint(src.stat(follow_symlinks=False)), 'source path changed during copy'
        if expected_sha256 is not None:
            assert digest.hexdigest() == expected_sha256, 'archive differs from Cargo.lock'
        os.chmod(dst, 0o600)
        return {'source': str(src), 'destination': str(dst), 'bytes': observed.st_size,
                'sha256': digest.hexdigest(), 'lock_checksum_verified': expected_sha256 is not None}
    except BaseException:
        raise


def terminate_owned(process):
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def run(label, argv, *, cwd=SOURCE, timeout=MAX_STAGE_SECONDS, expected_exit=0):
    stdout, stderr = RECORDS / (label + '.stdout.log'), RECORDS / (label + '.stderr.log')
    row = {'schema': 'joint-tail-rog-command-v1', 'label': label, 'argv': [str(x) for x in argv],
           'cwd': str(cwd), 'source_commit': EXPECTED, 'source_tree': EXPECTED_TREE,
           'started_at_utc': now(), 'disk_before': disk(BASE), 'stdout': stdout.name,
           'stderr': stderr.name, 'expected_exit_code': expected_exit,
           'result': 'RUNNING', 'production_qualification': False}
    save(label + '.started.json', row)
    announce({'label': label, 'state': 'RUNNING'})
    started = time.monotonic()
    termination = None
    error = None
    code = None
    with stdout.open('xb') as out, stderr.open('xb') as err:
        try:
            process = subprocess.Popen([str(x) for x in argv], cwd=cwd, env=ENV,
                                       stdout=out, stderr=err, start_new_session=True)
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    termination = 'OPERATIONAL_STAGE_TIMEOUT'
                    terminate_owned(process)
                    break
                if disk(BASE)['free'] < STOP_FREE:
                    termination = 'OPERATIONAL_DISK_FLOOR'
                    terminate_owned(process)
                    break
                time.sleep(1)
            code = process.wait()
        except OSError as exc:
            error = {'type': type(exc).__name__, 'message': str(exc)}
            err.write((str(exc) + '\n').encode())
    row.update(ended_at_utc=now(), elapsed_seconds=time.monotonic() - started,
               exit_code=code, termination=termination, error=error,
               disk_after=disk(BASE), stdout_sha256=digest_file(stdout)['sha256'],
               stderr_sha256=digest_file(stderr)['sha256'],
               stdout_bytes=stdout.stat().st_size, stderr_bytes=stderr.stat().st_size,
               passed=code == expected_exit and termination is None and error is None,
               result='COMPLETE')
    save(label + '.json', row)
    COMMANDS.append(row)
    announce({key: row[key] for key in ('label', 'exit_code', 'passed', 'termination', 'elapsed_seconds')})
    return row


def require_pass(row):
    assert row['passed'], 'stage did not pass: ' + row['label']


def output_json(row):
    return json.loads((RECORDS / row['stdout']).read_text())


def prepare_registry():
    locked = tomllib.loads((SOURCE / 'trillionnium/Cargo.lock').read_text())
    archives = []
    indices = {}
    for item in locked['package']:
        if 'source' not in item:
            continue
        assert item['source'] == 'registry+https://github.com/rust-lang/crates.io-index', 'unreviewed dependency source'
        name, version = item['name'], item['version']
        assert re.fullmatch(r'[a-zA-Z0-9_-]+', name)
        assert re.fullmatch(r'[a-zA-Z0-9_.+-]+', version)
        expected = item['checksum']
        assert re.fullmatch(r'[0-9a-f]{64}', expected)
        filename = name + '-' + version + '.crate'
        archives.append(checked_copy(ORIGINAL_REGISTRY / 'cache' / REGISTRY_ID / filename,
                                     CARGO_HOME / 'registry/cache' / REGISTRY_ID / filename,
                                     expected))
        lower = name.lower()
        relative = (Path('1') / lower if len(lower) == 1 else
                    Path('2') / lower if len(lower) == 2 else
                    Path('3') / lower[0] / lower if len(lower) == 3 else
                    Path(lower[:2]) / lower[2:4] / lower)
        if lower not in indices:
            indices[lower] = checked_copy(ORIGINAL_REGISTRY / 'index' / REGISTRY_ID / '.cache' / relative,
                                         CARGO_HOME / 'registry/index' / REGISTRY_ID / '.cache' / relative)
    config = checked_copy(ORIGINAL_REGISTRY / 'index' / REGISTRY_ID / 'config.json',
                          CARGO_HOME / 'registry/index' / REGISTRY_ID / 'config.json')
    report = {'schema': 'joint-tail-owned-registry-v1', 'original_registry_modified': False,
              'private_credentials_copied': False, 'only_locked_archives_copied': True,
              'crate_archives': archives, 'index_files': list(indices.values()), 'index_config': config,
              'all_archive_checksums_match_lock': True, 'archive_count': len(archives),
              'whole_index_authenticity_proved': False, 'hermetic_compilation_proved': False}
    save('registry-copy.json', report)
    announce({'registry_archives': len(archives), 'checksums_verified': True})


def observe_build_outputs():
    files = []
    for pattern in ['debug/build/openssl-sys-*/output', 'debug/build/libsqlite3-sys-*/output',
                    'debug/build/trnm-sqlite-io-boundary-*/output']:
        for p in sorted(TARGET.glob(pattern)):
            copy = RECORDS / ('build-output-' + str(len(files)) + '.log')
            item = checked_copy(p, copy)
            files.append(item)
    save('build-output-observations.json', {
        'files': files, 'observed_build_outputs_only': True,
        'actual_dynamic_linkage_proved': False, 'whole_process_lifetime_identity_proved': False})
    binaries = []
    for p in sorted((TARGET / 'debug/deps').glob('trnm_pon_node-*')):
        if p.is_file() and os.access(p, os.X_OK) and not p.is_symlink():
            binaries.append(digest_file(p))
    save('test-binary-observations.json', {
        'files': binaries, 'file_hash_observation_only': True,
        'kernel_executable_object_observed': False, 'loaded_memory_identity_proved': False})


def package_records(summary):
    save('summary.json', summary)
    members = [p for p in sorted(RECORDS.iterdir()) if p.is_file()]
    index = {'schema': 'joint-tail-rog-raw-index-v1',
             'files': [{'path': p.name, **{k: v for k, v in digest_file(p).items() if k != 'path'}} for p in members],
             'source_and_target_trees_not_archived': True,
             'source_preserved_at': str(SOURCE), 'target_preserved_at': str(TARGET)}
    save('raw-records-index.json', index)
    members.append(RECORDS / 'raw-records-index.json')
    archive = BASE / 'raw-records.tar.gz'
    with archive.open('xb') as raw:
        with tarfile.open(fileobj=raw, mode='w:gz') as stream:
            for p in members:
                stream.add(p, arcname=p.name, recursive=False)
    save('archive.json', digest_file(archive))
    announce({'archive': digest_file(archive), 'summary': summary})


def main():
    global ENV
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    assert args.source_commit == EXPECTED, 'different source requires a separately reviewed request'
    assert SOURCE.parent == BASE and BASE.parent == Path('/home/qian-qi')
    assert SEED.is_dir(), 'observed seed checkout absent'
    assert not BASE.exists(), 'create-only task directory already exists; recover its original job'
    BASE.mkdir(mode=0o700)
    RECORDS.mkdir(mode=0o700)
    CARGO_HOME.mkdir(mode=0o700)
    TARGET.mkdir(mode=0o700)
    ENV = os.environ.copy()
    ENV.update(CARGO_HOME=str(CARGO_HOME), CARGO_TARGET_DIR=str(TARGET),
               CARGO_NET_OFFLINE='true', CARGO_BUILD_JOBS='2', RUSTUP_TOOLCHAIN='1.95.0',
               PYTHONDONTWRITEBYTECODE='1')
    observed_names = ['RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTFLAGS',
                      'CARGO_ENCODED_RUSTFLAGS', 'CARGO_INCREMENTAL', 'RUSTUP_HOME',
                      'OPENSSL_DIR', 'OPENSSL_LIB_DIR', 'OPENSSL_INCLUDE_DIR', 'OPENSSL_STATIC',
                      'OPENSSL_NO_VENDOR', 'PKG_CONFIG_PATH', 'LD_LIBRARY_PATH',
                      'RISC0_SKIP_BUILD', 'RISC0_USE_DOCKER']
    save('ownership.json', {'directory_created_from_absent': True, 'base': str(BASE),
                            'source_commit': EXPECTED, 'source_tree': EXPECTED_TREE,
                            'created_utc': now(), 'pid': os.getpid()})
    save('environment.json', {'overrides': {name: ENV[name] for name in
         ('CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_NET_OFFLINE', 'CARGO_BUILD_JOBS',
          'RUSTUP_TOOLCHAIN', 'PYTHONDONTWRITEBYTECODE')},
          'inherited_build_settings': {name: ENV.get(name) for name in observed_names},
          'python': sys.version, 'uname': list(os.uname()), 'logical_cpu_count': os.cpu_count(),
          'original_host_service_profile_exercised': False})
    checked_copy(Path(__file__).resolve(), RECORDS / 'runner.py')
    summary = {'schema': 'joint-tail-rog-validation-v1', 'source_commit': EXPECTED,
               'source_tree': EXPECTED_TREE, 'started_at_utc': now(), 'all_requested_gates_passed': False,
               'original_four_second_service_executed': False, 'wan_or_mining_experiment_executed': False,
               'production_activation': False, 'native_probability_qualified': False,
               'native_common_prefix_failure_bound': None, 'native_six_successor_risk_bound': None,
               'source_before_after_equal': False, 'error': None}
    try:
        assert disk(BASE)['free'] >= MIN_START_FREE, 'insufficient free space before setup'
        require_pass(run('clone', ['git', 'clone', '--shared', '--no-checkout', str(SEED), str(SOURCE)], cwd=BASE))
        require_pass(run('canonical-origin', ['git', 'remote', 'set-url', 'origin', ORIGIN]))
        require_pass(run('fetch-fixed-source', ['git', 'fetch', '--no-tags', '--depth=1', 'origin', EXPECTED]))
        require_pass(run('checkout-fixed-source', ['git', 'checkout', '-b', LOCAL_BRANCH, EXPECTED]))
        require_pass(run('preflight', ['bash', 'scripts/project-preflight.sh']))
        before = run('source-before', ['python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                                     '--expected-head', EXPECTED, '--output', str(RECORDS / 'source-before.report.json')])
        require_pass(before)
        identity = json.loads((RECORDS / 'source-before.report.json').read_text())
        assert identity['tested_tree'] == EXPECTED_TREE and identity['tracked_worktree_verified']
        prepare_registry()
        observed = []
        for tool in ['cargo', 'rustc', 'rustfmt', 'clippy-driver']:
            observed.append(digest_file(TOOLCHAIN / 'bin' / tool))
        save('toolchain-files.json', {'observed_concrete_files': observed, 'loaded_library_identity_proved': False})
        for label, argv in [
            ('cargo-version', [RUSTUP_BIN / 'cargo', '+1.95.0', '--version', '--verbose']),
            ('rustc-version', [RUSTUP_BIN / 'rustc', '+1.95.0', '--version', '--verbose']),
            ('openssl-cli', ['openssl', 'version', '-a']),
        ]:
            require_pass(run(label, argv))
        for label, arguments in [
            ('cargo-metadata', ['metadata', '--locked', '--offline', '--manifest-path',
                                'trillionnium/Cargo.toml', '--all-features', '--format-version', '1']),
            ('cargo-fmt', ['fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check']),
            ('cargo-clippy', ['clippy', '--locked', '--offline', '--manifest-path',
                              'trillionnium/Cargo.toml', '--workspace', '--all-targets', '--all-features',
                              '--', '-D', 'warnings']),
            ('native-consensus', ['test', '--locked', '--offline', '--manifest-path',
                                  'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--lib', 'consensus::tests']),
        ]:
            require_pass(run(label, [RUSTUP_BIN / 'cargo', '+1.95.0', *arguments]))
        native = (RECORDS / 'native-consensus.stdout.log').read_text()
        names = re.findall(r'^test (consensus::tests::[^ ]+) \.\.\. ok$', native, re.MULTILINE)
        assert len(names) == len(set(names)) == 10, 'actual passing consensus test roster differs'
        assert re.search(r'test result: ok\. 10 passed; 0 failed; 0 ignored;', native), 'test summary differs'
        save('native-consensus-roster.json', {'names': names, 'count': 10,
                                            'benign_arithmetic_and_time_controls_only': True})
        observe_build_outputs()
        after = run('source-after', ['python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                                    '--expected-head', EXPECTED, '--output', str(RECORDS / 'source-after.report.json')])
        require_pass(after)
        last = json.loads((RECORDS / 'source-after.report.json').read_text())
        assert identity == last, 'full source before/after identity changed'
        summary.update(all_requested_gates_passed=True, source_before_after_equal=True,
                       tracked_entries=last['tracked_entries'], tracked_bytes=last['tracked_bytes'],
                       native_test_count=10)
    except BaseException as exc:
        summary['error'] = {'type': type(exc).__name__, 'message': str(exc)}
        announce({'state': 'FAILED', 'error': summary['error']})
        if SOURCE.is_dir() and (SOURCE / 'scripts/ci/verify_ci_source.py').is_file():
            try:
                run('source-after-failure', ['python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                     '--expected-head', EXPECTED, '--output', str(RECORDS / 'source-after-failure.report.json')])
            except BaseException as tail:
                summary['failure_identity_error'] = str(tail)
    finally:
        summary.update(ended_at_utc=now(), disk_final=disk(BASE),
                       commands=[{key: row.get(key) for key in ('label', 'exit_code', 'passed', 'termination')}
                                 for row in COMMANDS])
        package_records(summary)
    return 0 if summary['all_requested_gates_passed'] else 2


COMMANDS = []
ENV = os.environ.copy()
if __name__ == '__main__':
    raise SystemExit(main())
