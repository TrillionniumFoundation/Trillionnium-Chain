#!/usr/bin/env python3
"""Run requested component suites and workspace checks on one exact candidate.

Reuse the repository's complete source verifier and native executable observer.
This driver does not qualify mining cost, learning, adoption or production.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import traceback

ROOT = Path('/home/qian-qi/work/chain-pon-five-claims-20261111-d6cb')
ARTIFACTS = Path('/home/qian-qi/work/pon-five-claims-component-artifacts-d6cb')
TARGET = Path('/home/qian-qi/work/chain-pon-five-claims-components-target-d6cb')
TOOLCHAIN = Path('/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu')


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--group', choices=('all', 'crypto', 'da', 'quality'), default='all')
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.source):
        raise ValueError('an exact candidate SHA is required')
    sys.path.insert(0, str(ROOT / 'scripts/ci'))
    from verify_ci_source import verify
    from pinned_native_process import descriptor_digest, fingerprint, observe_executable

    env = os.environ.copy()
    env.update(RUSTUP_TOOLCHAIN='1.95.0', RUSTC=str(TOOLCHAIN / 'bin/rustc'),
               CARGO_TARGET_DIR=str(TARGET), CARGO_BUILD_JOBS='2',
               RUST_TEST_THREADS='1', CARGO_TERM_COLOR='never')
    env['PATH'] = str(TOOLCHAIN / 'bin') + ':' + env.get('PATH', '')
    loader = env.get('LD_LIBRARY_PATH', '').split(':')
    if str(TOOLCHAIN / 'lib') not in loader:
        raise ValueError('start this unchanged driver with rustup run 1.95.0')
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
                 'RUSTC_WORKSPACE_WRAPPER'):
        if env.get(name):
            raise ValueError('unexpected compiler override: ' + name)
    if any(value for key, value in env.items() if key.startswith('CARGO_PROFILE_')):
        raise ValueError('unexpected Cargo profile override')
    output = ARTIFACTS / (args.source + '-' + args.group)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(__file__, output / 'driver.py')
    write(output / 'environment.json', {key: env.get(key) for key in (
        'RUSTC', 'RUSTUP_TOOLCHAIN', 'LD_LIBRARY_PATH', 'CARGO_BUILD_JOBS',
        'CARGO_INCREMENTAL', 'CARGO_TARGET_DIR', 'RUST_TEST_THREADS',
        'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'OPENSSL_DIR', 'OPENSSL_STATIC',
        'OPENSSL_CONF', 'OPENSSL_MODULES', 'TRNM_PQ_OPENSSL',
        'TRNM_PQ_OPENSSL_SHA256', 'TRNM_PQ_OPENSSL_VERSION')})
    input_paths = [TOOLCHAIN / 'bin' / name for name in
                   ('rustc', 'cargo', 'rustfmt', 'cargo-clippy', 'clippy-driver')]
    provider = Path(env['OPENSSL_DIR'])
    input_paths += [provider / part for part in
                    ('bin/openssl', 'lib/libcrypto.a', 'lib/libssl.a')]
    input_pins = {str(path): {'sha256': digest(path), 'bytes': path.stat().st_size}
                  for path in input_paths}
    if input_pins[str(provider / 'bin/openssl')]['sha256'] != env['TRNM_PQ_OPENSSL_SHA256']:
        raise ValueError('provider CLI does not match the explicit pin')
    write(output / 'toolchain-provider-before.json', input_pins)

    def command(folder, label, argv, cwd=ROOT, native=False):
        record = {'label': label, 'argv': argv, 'cwd': str(cwd),
                  'status': 'running', 'exit_code': None,
                  'started_unix_ns': time.time_ns(),
                  'performance_measurement': False}
        receipt = folder / (label + '.json')
        stdout = folder / (label + '.stdout.log')
        stderr = folder / (label + '.stderr.log')
        write(receipt, record)
        started = time.monotonic_ns()
        descriptor = None
        try:
            kwargs = {}
            if native:
                descriptor = os.open(argv[0], os.O_RDONLY | os.O_CLOEXEC |
                                     os.O_NOFOLLOW | os.O_NONBLOCK)
                expected, before = descriptor_digest(descriptor)
                if os.pread(descriptor, 4, 0) != b'\x7fELF':
                    raise ValueError('native subject is not ELF')
                record['dispatch_object'] = {
                    'sha256': expected, 'bytes': before.st_size,
                    'device': before.st_dev, 'inode': before.st_ino}
                kwargs.update(executable='/proc/self/fd/' + str(descriptor),
                              pass_fds=(descriptor,))
            with stdout.open('xb') as out, stderr.open('xb') as err:
                process = subprocess.Popen(argv, cwd=cwd, env=env,
                                           stdout=out, stderr=err, **kwargs)
                record['owned_pid'] = process.pid
                if native:
                    try:
                        record['native_observation'] = observe_executable(
                            process.pid, descriptor, expected)
                    except (OSError, ValueError) as error:
                        record['native_observation'] = {
                            'status': 'NOT_OBSERVED', 'error': str(error)}
                record['exit_code'] = process.wait()
                record['child_reaped'] = True
            if native:
                actual, after = descriptor_digest(descriptor)
                record['dispatch_object_after_sha256'] = actual
                record['dispatch_object_stable'] = (
                    actual == expected and fingerprint(before) == fingerprint(after))
                if not record['dispatch_object_stable']:
                    raise ValueError('dispatched executable changed')
            record['status'] = 'command_succeeded' if record['exit_code'] == 0 else 'command_failed'
        except BaseException:
            record['status'] = 'record_failed'
            record['error'] = traceback.format_exc()
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)
            for name, path in [('stdout', stdout), ('stderr', stderr)]:
                if path.exists():
                    record[name] = {'path': str(path), 'bytes': path.stat().st_size,
                                    'sha256': digest(path)}
            record['elapsed_ns'] = time.monotonic_ns() - started
            write(receipt, record)
            print(json.dumps({'label': label, 'exit_code': record['exit_code'],
                              'status': record['status'], 'receipt': str(receipt)}), flush=True)
        return record

    def required(folder, label, argv, cwd=ROOT):
        record = command(folder, label, argv, cwd)
        if record['exit_code']:
            raise RuntimeError(label + ' failed')
        return record

    def finish_source(folder, summary):
        try:
            summary['source_after'] = verify('head', args.source, root=ROOT)
            write(folder / 'source-after.json', summary['source_after'])
            if summary.get('source_before') != summary['source_after']:
                raise ValueError('source changed during validation')
            summary['source_stable'] = True
        except BaseException:
            summary['source_stable'] = False
            summary['source_error'] = traceback.format_exc()
            (folder / 'source-after-failure.txt').write_text(summary['source_error'])
            summary['tests_passed'] = False
            summary['checks_passed'] = False
            summary['status'] = 'source_verification_failed'

    required(output, 'rustc-version', [str(TOOLCHAIN / 'bin/rustc'), '--version', '--verbose'])
    required(output, 'cargo-version', [str(TOOLCHAIN / 'bin/cargo'), '--version', '--verbose'])
    required(output, 'provider-version', [env['TRNM_PQ_OPENSSL'], 'version', '-a'])

    groups = [('crypto', 'trnm-crypto-primitives', ['--lib'], 'pon_work'),
              ('da', 'trnm-data-availability', ['--all-targets', '--all-features'], None)]
    results = []
    for name, package, selection, test_filter in groups:
        if args.group not in ('all', name):
            continue
        folder = output / name
        folder.mkdir()
        summary = {'group': name, 'package': package, 'source': args.source,
                   'status': 'running', 'tests_passed': False,
                   'whole_chain_security_qualified': False, 'model_benefit_qualified': False,
                   'production_activation': False, 'native_suites': []}
        write(folder / 'summary.json', summary)
        guards = {}
        try:
            summary['source_before'] = verify('head', args.source, root=ROOT)
            write(folder / 'source-before.json', summary['source_before'])
            required(folder, 'preflight', ['bash', 'scripts/project-preflight.sh', '--audit'])
            manifest = ROOT / 'trillionnium/crates' / package / 'Cargo.toml'
            argv = [str(TOOLCHAIN / 'bin/cargo'), 'test', '--manifest-path',
                    str(ROOT / 'trillionnium/Cargo.toml'), '--release', '--locked',
                    '--offline', '-p', package] + selection + ['--no-run', '--message-format=json']
            required(folder, 'build', argv)
            artifacts = []
            for line in (folder / 'build.stdout.log').read_text().splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (item.get('reason') == 'compiler-artifact' and item.get('executable')
                        and Path(item.get('manifest_path', '')).resolve() == manifest.resolve()):
                    artifacts.append(item)
            if not artifacts:
                raise ValueError('Cargo emitted no executable provenance for the selected package')
            write(folder / 'compiler-artifacts.json', artifacts)
            retained = folder / 'binaries'
            retained.mkdir()
            for item in artifacts:
                binary = Path(item['executable'])
                if str(binary) in guards:
                    continue
                copy = retained / binary.name
                shutil.copy2(binary, copy)
                original_hash = digest(binary)
                if digest(copy) != original_hash:
                    raise ValueError('retained executable differs from compiler output')
                guards[str(binary)] = {'sha256': original_hash, 'bytes': binary.stat().st_size,
                                       'retained': str(copy)}
            write(folder / 'binary-guards-before.json', guards)
            tests = {item['executable']: item for item in artifacts if item['profile'].get('test')}
            if not tests:
                raise ValueError('no compiled native test executable')
            for index, (binary, item) in enumerate(sorted(tests.items())):
                label = f'{index:02d}-{item["target"]["name"]}'
                cwd = manifest.parent
                required(folder, label + '-list', [binary, '--list', '--format', 'terse'], cwd)
                listing = (folder / (label + '-list.stdout.log')).read_text()
                roster = [line[:-6] for line in listing.splitlines() if line.endswith(': test')]
                selected = [test for test in roster if test_filter is None or test_filter in test]
                if test_filter is not None and not selected:
                    raise ValueError('empty requested pon_work roster')
                write(folder / (label + '-roster.json'), {'all': roster, 'selected': selected,
                                                         'filter': test_filter})
                argv = [binary] + ([test_filter] if test_filter else []) + ['--nocapture', '--test-threads=1']
                native = command(folder, label + '-native', argv, cwd, native=True)
                raw = (folder / (label + '-native.stdout.log')).read_text()
                matches = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', raw)
                if not matches:
                    raise ValueError('missing top-level libtest summary')
                state, passed, failed, ignored, measured, filtered = matches[-1]
                counts = dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'),
                                  map(int, (passed, failed, ignored, measured, filtered))))
                suite = {'binary': binary, 'counts': counts, 'listed': len(roster),
                         'selected': len(selected), 'native_receipt': label + '-native.json',
                         'kernel_executable_observed': native.get('native_observation', {}).get('status') == 'OBSERVED'}
                summary['native_suites'].append(suite)
                if (native['exit_code'] != 0 or state != 'ok' or counts['failed'] != 0
                        or counts['measured'] != 0 or counts['passed'] + counts['ignored'] != len(selected)
                        or counts['filtered_out'] != len(roster) - len(selected)):
                    raise ValueError('native result does not match the complete selected roster')
            summary['tests_passed'] = True
            summary['status'] = 'component_tests_passed'
        except BaseException:
            summary['status'] = 'component_failed'
            summary['error'] = traceback.format_exc()
            (folder / 'failure.txt').write_text(summary['error'])
        finally:
            try:
                after_guards = {}
                for binary, guard in guards.items():
                    after_guards[binary] = {'sha256': digest(binary),
                        'retained_sha256': digest(guard['retained']),
                        'expected_sha256': guard['sha256']}
                    if any(after_guards[binary][key] != guard['sha256']
                           for key in ('sha256', 'retained_sha256')):
                        raise ValueError('compiled or retained executable changed')
                write(folder / 'binary-guards-after.json', after_guards)
            except BaseException:
                summary['tests_passed'] = False
                summary['status'] = 'binary_verification_failed'
                summary['binary_error'] = traceback.format_exc()
            finish_source(folder, summary)
            write(folder / 'summary.json', summary)
            results.append(summary)
            write(output / 'summary.json', results)
            print(json.dumps({'group': name, 'status': summary['status'], 'summary': str(folder / 'summary.json')}), flush=True)
    if args.group in ('all', 'quality'):
        cargo = str(TOOLCHAIN / 'bin/cargo')
        workspace = str(ROOT / 'trillionnium/Cargo.toml')
        gates = [
            ('fmt', [cargo, 'fmt', '--manifest-path', workspace, '--all', '--', '--check']),
            ('workspace-metadata', [cargo, 'metadata', '--manifest-path', workspace,
                '--locked', '--offline', '--format-version=1']),
            ('fuzz-metadata', [cargo, 'metadata', '--manifest-path',
                str(ROOT / 'tests/fuzz/Cargo.toml'), '--locked', '--offline',
                '--format-version=1']),
            ('clippy', [cargo, 'clippy', '--manifest-path', workspace,
                '--workspace', '--all-targets', '--all-features', '--locked',
                '--offline', '--', '-D', 'warnings']),
        ]
        for name, argv in gates:
            folder = output / name
            folder.mkdir()
            summary = {'group': name, 'source': args.source, 'status': 'running',
                       'checks_passed': False, 'production_activation': False}
            try:
                summary['source_before'] = verify('head', args.source, root=ROOT)
                write(folder / 'source-before.json', summary['source_before'])
                required(folder, name, argv)
                summary['checks_passed'] = True
                summary['status'] = 'check_passed'
            except BaseException:
                summary['status'] = 'check_failed'
                summary['error'] = traceback.format_exc()
                (folder / 'failure.txt').write_text(summary['error'])
            finally:
                finish_source(folder, summary)
                write(folder / 'summary.json', summary)
                results.append(summary)
                write(output / 'summary.json', results)
                print(json.dumps({'group': name, 'status': summary['status'],
                                  'summary': str(folder / 'summary.json')}), flush=True)
    input_pins_after = {str(path): {'sha256': digest(path), 'bytes': path.stat().st_size}
                        for path in input_paths}
    write(output / 'toolchain-provider-after.json', input_pins_after)
    if input_pins_after != input_pins:
        raise ValueError('compiler or provider input changed during validation')
    return 0 if results and all(item.get('tests_passed', item.get('checks_passed', False))
                                for item in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
