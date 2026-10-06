#!/usr/bin/env python3
"""Build and execute the named from-zero controls on the current checked source.

Used by the existing protocol-contract jobs, not a new lane. Every native test
runs in its own process. A format failure is retained independently of native
outcomes; neither existing binary replays nor zero matching tests can pass.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from replay_pinned_native import digest, json_load, require, run_child

TESTS = (
    'caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct',
    'from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection',
    'from_zero_service_shares_cpu_with_honest_work_and_reopened_owner',
)
ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path('trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs')


def identity(output: Path) -> dict:
    command = [sys.executable, 'scripts/ci/verify_ci_source.py']
    if os.environ.get('TRNM_EXPECTED_CANDIDATE_SHA'):
        command += ['--kind', 'prospective-merge', '--expected-head',
                    os.environ['TRNM_EXPECTED_CANDIDATE_SHA'], '--expected-base',
                    os.environ['TRNM_EXPECTED_BASE_SHA'], '--expected-merge',
                    os.environ['TRNM_EXPECTED_SOURCE_SHA']]
    else:
        command += ['--kind', 'head', '--expected-head',
                    os.environ['TRNM_EXPECTED_SOURCE_SHA']]
    subprocess.run(command + ['--output', str(output)], check=True, timeout=120)
    return json_load(output.read_bytes())


def executable_from_messages(raw: bytes) -> Path:
    matches = []
    for line in raw.splitlines():
        message = json_load(line)
        if (message.get('reason') == 'compiler-artifact'
                and message.get('target', {}).get('name') == 'public_v3_from_zero'
                and message.get('target', {}).get('kind') == ['test']
                and message.get('profile', {}).get('test') is True
                and message.get('executable')):
            matches.append(Path(message['executable']))
    require(len(matches) == 1, 'EXPECTED_ONE_TEST_BINARY')
    return matches[0].resolve(strict=True)


def main() -> None:
    os.chdir(ROOT)
    root = Path(os.environ.get('TRNM_CI_RECEIPT_DIR', '/tmp/trnm-ci')).resolve()
    root.mkdir(parents=True, exist_ok=True)
    out = root / 'from-zero-native'
    out.mkdir()  # Old results must never be overwritten or silently reused.
    receipt = {'schema': 'trnm-from-zero-native-conformance-v1', 'tests': [],
               'completed': False, 'production_activation': False,
               'public_network_ready': False, 'full_workspace_accepted': False,
               'run_id': os.environ.get('GITHUB_RUN_ID'),
               'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT')}
    try:
        receipt['source_before'] = identity(out / 'source-before.json')
        raw = SOURCE.read_bytes()
        receipt['test_source_sha256'] = digest(raw)
        formatted = subprocess.run(
            ['rustup', 'run', '1.95.0', 'rustfmt', '--edition', '2021', '--emit', 'stdout'],
            input=raw, capture_output=True, timeout=60, check=False)
        (out / 'formatted.rs').write_bytes(formatted.stdout)
        (out / 'rustfmt.stderr').write_bytes(formatted.stderr)
        receipt['format_exit_code'] = formatted.returncode
        receipt['format_equal'] = formatted.returncode == 0 and formatted.stdout == raw
        build = run_child([
            'cargo', 'test', '--locked', '--release', '--manifest-path',
            'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--test',
            'public_v3_from_zero', '--no-run', '--message-format=json'],
            out / 'build', timeout=900)
        receipt['build'] = build
        require(build['exit_code'] == 0 and not build['timed_out'], 'BUILD_FAILED')
        binary = executable_from_messages((out / 'build/stdout').read_bytes())
        sha = digest(binary.read_bytes())
        shutil.copyfile(binary, out / 'public_v3_from_zero')
        (out / 'public_v3_from_zero').chmod(0o700)
        receipt['binary_sha256'] = sha
        listing = run_child([str(binary), '--list'], out / 'inventory')
        require(listing['exit_code'] == 0 and not listing['timed_out'], 'LIST_FAILED')
        names = [line[:-6] for line in (out / 'inventory/stdout').read_text().splitlines()
                 if line.endswith(': test')]
        require(sorted(names) == sorted(TESTS), 'TEST_INVENTORY_MISMATCH')
        receipt['test_inventory'] = names
        os.environ['TRNM_PUBLIC_V3_FROM_ZERO_DIR'] = str(out / 'service')
        success = True
        for index, name in enumerate(TESTS):
            folder = out / f'test-{index}'
            result = run_child([str(binary), name, '--exact', '--nocapture',
                                '--test-threads=1'], folder, timeout=120)
            check = run_child([sys.executable, 'scripts/ci/check_required_native_test.py',
                               str(folder / 'stdout'), '--test', name], folder / 'execution-check')
            accepted = (result['exit_code'] == 0 and not result['timed_out']
                        and check['exit_code'] == 0 and not check['timed_out'])
            success &= accepted
            receipt['tests'].append({'name': name, 'process': result,
                                     'execution_check': check, 'accepted': accepted})
            print(json.dumps({'test': name, 'accepted': accepted}), flush=True)
        receipt['native_tests_passed'] = success
        require(digest(binary.read_bytes()) == sha, 'BINARY_CHANGED')
        require(SOURCE.read_bytes() == raw, 'TEST_SOURCE_CHANGED')
        receipt['source_after'] = identity(out / 'source-after.json')
        require(receipt['source_before'] == receipt['source_after'], 'SOURCE_CHANGED')
        require(success, 'NATIVE_TEST_FAILED')
        require(receipt['format_equal'], 'RUSTFMT_DIFFERENCE')
        receipt['completed'] = True
    except Exception as error:
        receipt['error'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
