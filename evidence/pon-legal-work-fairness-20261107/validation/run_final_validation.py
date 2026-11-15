#!/usr/bin/env python3
"""Retain original commands and strict exact-source receipts for this campaign."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--runner', required=True, type=Path)
    args = parser.parse_args()
    repo, out = args.repo.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(repo / 'scripts/ci'))
    from verify_ci_source import verify
    before = verify('head', args.source_sha, root=repo)
    save(out / 'source-before.json', before)
    env = dict(os.environ, TRNM_GROUPED_NATIVE=str(args.runner.resolve()),
               RUST_TEST_THREADS='1', PYTHONDONTWRITEBYTECODE='1')
    py = sys.executable
    cargo = ['cargo']
    manifest = ['--manifest-path', 'trillionnium/Cargo.toml']
    commands = [
        ('preflight', ['bash', 'scripts/project-preflight.sh']),
        ('cargo-version', ['cargo', '--version']), ('rustc-version', ['rustc', '--version']),
        ('openssl-version', [env['TRNM_PQ_OPENSSL'], 'version']),
        ('locked-workspace-graph', cargo + ['metadata', '--offline', '--locked', *manifest,
                                         '--all-features', '--format-version', '1']),
        ('locked-fuzz-graph', cargo + ['metadata', '--offline', '--locked', '--manifest-path',
                                    'tests/fuzz/Cargo.toml', '--all-features', '--format-version', '1']),
        ('format', cargo + ['fmt', *manifest, '--all', '--', '--check']),
        ('native-build', cargo + ['build', '--offline', '--locked', '--release', *manifest,
                                 '-p', 'trnm-crypto-primitives', '--example', 'pon_routed_int257_grouped']),
        ('grouped-python-and-native', [py, '-B', '-m', 'unittest', 'discover', '-s',
                                      'formal/pon-nakamoto-v1', '-p', 'test_grouped*.py', '-v']),
        ('conditional-query-bound', [py, '-B', '-m', 'unittest', 'discover', '-s',
                                    'formal/pon-nakamoto-v1', '-p', 'test_work_query_bound.py', '-v']),
        ('native-crypto-all-targets', cargo + ['test', '--offline', '--locked', *manifest,
                                             '-p', 'trnm-crypto-primitives', '--all-targets', '--all-features']),
        ('native-header-binding', cargo + ['test', '--offline', '--locked', *manifest,
                                          '-p', 'trnm-pon-node', '--all-features', '--test', 'work_header_binding']),
        ('source-integrity-controls', [py, '-B', 'scripts/ci/test_ci_source_integrity.py']),
        ('ci-contract-controls', [py, '-B', 'scripts/ci/test_ci_contract.py']),
        ('source-inventory', [py, '-B', 'scripts/refresh_distributed_source_inventory.py', '--check']),
        ('repository-and-links', [py, '-B', 'scripts/ci/check_repository.py']),
        ('strict-workspace-clippy', cargo + ['clippy', '--offline', '--locked', *manifest,
                                           '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings']),
        ('whitespace', ['git', 'diff', '--check']),
    ]
    save(out / 'plan.json', {'source': before, 'commands': commands,
        'source_validation_is_not_qualification': True,
        'timeout_seconds_per_command': 1800, 'production_activation': False})
    records = []
    for label, command in commands:
        log = out / (label + '.log')
        start = time.monotonic()
        record = {'label': label, 'command': command,
                  'started_utc': datetime.now(timezone.utc).isoformat()}
        with log.open('xb') as stream:
            try:
                result = subprocess.run(command, cwd=repo, env=env, stdout=stream,
                                        stderr=subprocess.STDOUT, timeout=1800)
                record.update(exit_code=result.returncode, timed_out=False)
            except subprocess.TimeoutExpired:
                record.update(exit_code=None, timed_out=True)
        record.update(elapsed_seconds=time.monotonic()-start, log=log.name,
                      log_bytes=log.stat().st_size, log_sha256=hashlib.sha256(log.read_bytes()).hexdigest())
        records.append(record)
        save(out / 'commands.json', records)
        print(json.dumps(record), flush=True)
    after = verify('head', args.source_sha, root=repo)
    save(out / 'source-after.json', after)
    if before != after:
        raise ValueError('EXACT_SOURCE_CHANGED')
    save(out / 'environment.json', {key: env.get(key) for key in (
        'OPENSSL_DIR','OPENSSL_STATIC','OPENSSL_CONF','OPENSSL_MODULES','TRNM_PQ_OPENSSL',
        'TRNM_PQ_OPENSSL_SHA256','TRNM_PQ_OPENSSL_VERSION','CARGO_TARGET_DIR',
        'CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG','CARGO_INCREMENTAL','CARGO_BUILD_JOBS',
        'TRNM_GROUPED_NATIVE','RUST_TEST_THREADS','PYTHONDONTWRITEBYTECODE')})
    passed = all(row['exit_code'] == 0 for row in records)
    summary = {'schema': 'pon-grouped-fairness-local-validation-v0', 'source': before,
        'status': 'PASS' if passed else 'FAIL', 'commands': len(records),
        'native_runner_sha256': hashlib.sha256(args.runner.read_bytes()).hexdigest(),
        'original_service_campaign_executed': False, 'full_workspace_unit_tests_executed': False,
        'minimum_legal_cost_proved': False, 'pow_qualified': False, 'production_activation': False}
    save(out / 'summary.json', summary)
    print(json.dumps(summary), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
