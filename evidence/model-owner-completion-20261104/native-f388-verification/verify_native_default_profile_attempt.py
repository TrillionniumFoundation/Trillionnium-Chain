#!/usr/bin/env python3
"""Exact-source M06 revalidation; scratch-only controller, no source mutation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

REPO = Path('/workspace/scratch/f4976366a32a/chain')
OUT_ROOT = REPO.parent
PROVIDER = Path('/workspace/scratch/e537ad232c79/native-runtime-acceptance/provider.env')
EXPECTED_STATIC = {
    'libcrypto.a': 'fda16ed5c2188f643f8edc1574966efa56f1685a640705eba602c2242c02ce08',
    'libssl.a': 'e15be5fe884475c5efdd00ad40173d9abe71a2127f476145bed6ef2d86dfd5c9',
}


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def git(*args):
    return subprocess.check_output(['git', '-C', str(REPO), *args], text=True).strip()


def exact_source(expected):
    actual = git('rev-parse', 'HEAD')
    if actual != expected or git('status', '--porcelain', '--untracked-files=all'):
        raise RuntimeError('native verification requires unchanged, clean exact source ' + expected)
    return dict(commit=actual, tree=git('rev-parse', 'HEAD^{tree}'),
                native_tree=git('rev-parse', 'HEAD:trillionnium'),
                crypto_tree=git('rev-parse', 'HEAD:trillionnium/crates/trnm-crypto-primitives'),
                m06_tree=git('rev-parse', 'HEAD:trillionnium/crates/trnm-mvcc-fee'),
                formal_tree=git('rev-parse', 'HEAD:formal/pon-nakamoto-v1'),
                cargo_lock_sha256=sha(REPO / 'trillionnium/Cargo.lock'))


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.partial')
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    temporary.replace(path)


def memory():
    root = Path('/sys/fs/cgroup')
    result = {}
    for name in ('memory.max', 'memory.current', 'memory.peak'):
        try:
            result[name] = (root / name).read_text().strip()
        except OSError:
            result[name] = None
    try:
        values = dict(line.split() for line in (root / 'memory.stat').read_text().splitlines())
        result.update({name: int(values[name]) for name in ('anon', 'file')})
    except (OSError, KeyError, ValueError):
        pass
    return result


def provider_snapshot():
    provider = Path(os.environ['TRNM_PQ_OPENSSL'])
    directory = Path(os.environ['OPENSSL_DIR'])
    if os.environ.get('OPENSSL_STATIC') != '1':
        raise ValueError('original static OpenSSL profile required')
    executable_sha = sha(provider)
    if executable_sha != os.environ['TRNM_PQ_OPENSSL_SHA256']:
        raise ValueError('original provider executable bytes differ from pin')
    libraries = {name: sha(directory / 'lib' / name) for name in EXPECTED_STATIC}
    if libraries != EXPECTED_STATIC:
        raise ValueError('static OpenSSL inputs differ from original prepared provider')
    return dict(provider_env_sha256=sha(PROVIDER), executable_path=str(provider),
                executable_sha256=executable_sha, openssl_dir=str(directory),
                openssl_static=True, static_libraries=libraries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.source):
        raise ValueError('exact commit required')
    before = exact_source(args.source)
    subprocess.run(['git', '-C', str(REPO), 'merge-base', '--is-ancestor',
        '38543c96cabb0d63a4a99d149a30a270d0c2c107', args.source], check=True)
    out = OUT_ROOT / ('native-frozen-' + args.source[:12])
    out.mkdir(mode=0o700, exist_ok=False)
    original_provider = provider_snapshot()
    provider_sha = original_provider['executable_sha256']
    rust = subprocess.check_output(['rustc', '--version', '--verbose'], text=True)
    cargo = subprocess.check_output(['cargo', '--version'], text=True).strip()
    if not rust.startswith('rustc 1.95.0 ') or not cargo.startswith('cargo 1.95.0 '):
        raise ValueError('original Rust 1.95 toolchain required')
    result = dict(schema='model-owner-native-exact-source-revalidation-v1',
        source_before=before, requested_remote_input='38543c96cabb0d63a4a99d149a30a270d0c2c107',
        controller_sha256=sha(__file__), provider_before=original_provider,
        provider_env_sha256=sha(PROVIDER), provider_sha256=provider_sha,
        provider_version=os.environ.get('TRNM_PQ_OPENSSL_VERSION'), rustc=rust, cargo=cargo,
        cargo_home=os.environ.get('CARGO_HOME'), target_dir=os.environ.get('CARGO_TARGET_DIR'),
        build_jobs=os.environ.get('CARGO_BUILD_JOBS'), initial_memory=memory(),
        started_utc_ns=time.time_ns(), commands=[], qualification=False,
        prior_229_pass_record='retained historical observation; not substituted for this source')
    save(out / 'verification.json', result)
    commands = [
        ('preflight', ['bash', 'scripts/project-preflight.sh']),
        ('cargo-metadata', ['cargo', 'metadata', '--locked', '--manifest-path',
                           'trillionnium/Cargo.toml', '--format-version', '1']),
        ('cargo-fmt', ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check']),
        ('m06-tests', ['cargo', 'test', '--locked', '--manifest-path', 'trillionnium/Cargo.toml',
                       '-p', 'trnm-mvcc-fee', '--all-targets', '--all-features']),
        ('m06-clippy', ['cargo', 'clippy', '--locked', '--manifest-path', 'trillionnium/Cargo.toml',
                        '-p', 'trnm-mvcc-fee', '--all-targets', '--all-features', '--', '-D', 'warnings']),
    ]
    for name, command in commands:
        exact_source(args.source)
        if provider_snapshot() != original_provider:
            raise RuntimeError('provider changed before ' + name)
        start = time.monotonic()
        print(json.dumps(dict(stage=name, state='started', source=args.source)), flush=True)
        path = out / (name + '.log')
        stderr_path = out / (name + '.stderr.log')
        with path.open('xb') as output, stderr_path.open('xb') as errors:
            completed = subprocess.run(command, cwd=REPO, stdout=output,
                                      stderr=errors if name == 'cargo-metadata' else subprocess.STDOUT)
        row = dict(name=name, command=command, exit_code=completed.returncode,
                   seconds=time.monotonic() - start, log_sha256=sha(path), stderr_sha256=sha(stderr_path),
                   provider_sha256=provider_sha, memory=memory())
        result['commands'].append(row)
        try:
            result['source_after_last_command'] = exact_source(args.source)
            row['provider_after'] = provider_snapshot()
            if row['provider_after'] != original_provider:
                raise RuntimeError('provider changed during ' + name)
        except BaseException as error:
            result.update(status='SOURCE_CHANGED', error_type=type(error).__name__, error=str(error))
            save(out / 'verification.json', result)
            raise
        if name == 'cargo-metadata' and completed.returncode == 0:
            metadata = json.loads(path.read_text())
            result['workspace_members'] = len(metadata['workspace_members'])
            result['resolved_packages'] = len(metadata['packages'])
        if name == 'm06-tests':
            pattern = r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;'
            rows = [tuple(map(int, match)) for match in re.findall(pattern, path.read_text())]
            result['native_test_summary_count'] = len(rows)
            result['native_test_totals'] = dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'),
                                                   [sum(row[i] for row in rows) for i in range(5)]))
            totals = result['native_test_totals']
            # These are the actual retained M06 targets on this merge. Crypto
            # dependencies changed; the M06 test inventory did not. The previous
            # run is not substituted for any missing transcript in this run.
            expected = dict(passed=229, failed=0, ignored=7, measured=0, filtered_out=0)
            result['expected_retained_test_inventory'] = dict(summaries=25, totals=expected)
            result['test_transcript_complete'] = len(rows) == 25 and totals == expected
            if not result['test_transcript_complete']:
                result.update(status='FAILED_TEST_TRANSCRIPT', finished_utc_ns=time.time_ns())
                save(out / 'verification.json', result)
                raise RuntimeError('actual M06 transcript does not cover the complete retained inventory')
        save(out / 'verification.json', result)
        print(json.dumps(dict(stage=name, state='returned', exit_code=completed.returncode,
                              seconds=row['seconds'])), flush=True)
        if completed.returncode != 0:
            result.update(status='FAILED', finished_utc_ns=time.time_ns())
            save(out / 'verification.json', result)
            raise SystemExit(completed.returncode)
    result.update(status='PASS', source_after=exact_source(args.source),
                  provider_after=provider_snapshot(), finished_utc_ns=time.time_ns())
    result['source_unchanged'] = result['source_before'] == result['source_after']
    result['provider_observations_unchanged'] = result['provider_before'] == result['provider_after']
    save(out / 'verification.json', result)
    print(json.dumps(dict(status='PASS', report=str(out / 'verification.json'),
        tests=result.get('native_test_totals'), source=args.source)), flush=True)


if __name__ == '__main__':
    main()
