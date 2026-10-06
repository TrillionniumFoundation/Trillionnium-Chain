#!/usr/bin/env python3
"""Build and execute exact from-zero tests inside the existing protocol lane.

Keep failed builds, named nonzero test executions, full reports and the actual
binary. No old artifact can satisfy this source build, and no extra CI lane is
introduced. Process CPU encloses the entire test, not a per-actor cost allocation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from check_required_native_test import validate
from replay_pinned_native import digest, json_load, require, run_child

ROOT = Path(__file__).resolve().parents[2]
TARGET = 'public_v3_from_zero'
SOURCE = 'trillionnium/crates/trnm-pon-node/tests/' + TARGET + '.rs'
TESTS = (
    'caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct',
    'from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection',
    'from_zero_service_shares_cpu_with_honest_work_and_reopened_owner',
)


def source_identity() -> dict:
    def git(*args: str) -> str:
        return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True).strip()
    require(not git('status', '--porcelain'), 'CLEAN_COMMITTED_SOURCE_REQUIRED')
    return {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'test_sha256': digest((ROOT / SOURCE).read_bytes())}


def select_binary(lines: list[str]) -> Path:
    paths = []
    for line in lines:
        if not line.startswith('{'):
            continue
        row = json_load(line)
        if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == TARGET:
            if row.get('profile', {}).get('test') is True and row.get('executable'):
                paths.append(Path(row['executable']).resolve())
    require(len(paths) == 1, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED')
    return paths[0]


def run(out: Path) -> dict:
    out = out.resolve()
    require(not out.is_relative_to(ROOT), 'OUTPUT_MUST_BE_OUTSIDE_CHECKOUT')
    identity = source_identity()
    out.mkdir(parents=True, exist_ok=False)
    result = {'schema': 'trnm-from-zero-native-execution-v1', 'source_before': identity,
              'source_after': None, 'source_recompiled': False, 'all_named_tests_passed': False,
              'format_passed': False, 'runs': [], 'failures': [],
              'independent_wan_accepted': False, 'work_hardness_accepted': False,
              'production_activation': False}
    previous_output = os.environ.get('TRNM_PUBLIC_V3_FROM_ZERO_DIR')
    try:
        os.chdir(ROOT)
        os.environ['TRNM_PUBLIC_V3_FROM_ZERO_DIR'] = str(out / 'native')
        result['rustc'] = subprocess.check_output(['rustc', '-Vv'], text=True)
        result['cargo'] = subprocess.check_output(['cargo', '-V'], text=True).strip()
        result['build_env'] = {key: os.environ.get(key) for key in (
            'CARGO_BUILD_JOBS', 'CARGO_TARGET_DIR', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS')}
        # A copy gives a reproducible formatting repair without changing checkout.
        shutil.copyfile(ROOT / SOURCE, out / 'formatted.rs')
        result['format_copy'] = run_child(
            ['rustfmt', '--edition', '2021', str(out / 'formatted.rs')], out / 'format-copy', 60)
        result['format'] = run_child(
            ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check'],
            out / 'format-check', 60)
        result['format_passed'] = result['format']['exit_code'] == 0 and not result['format']['timed_out']
        command = ['cargo', 'test', '--locked', '--release', '--manifest-path',
                   'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--test', TARGET,
                   '--no-run', '--message-format=json']
        result['build'] = run_child(command, out / 'build', 900)
        require(result['build']['exit_code'] == 0 and not result['build']['timed_out'], 'NATIVE_BUILD_FAILED')
        binary = select_binary((out / 'build/stdout').read_text().splitlines())
        require(binary.is_file() and not binary.is_symlink(), 'REGULAR_BINARY_REQUIRED')
        result['source_recompiled'] = True
        result['binary_sha256_before'] = digest(binary.read_bytes())
        shutil.copy2(binary, out / TARGET)
        for name in TESTS:
            folder = out / name
            observed = run_child([str(binary), name, '--exact', '--nocapture', '--test-threads=1'], folder, 90)
            row = {'name': name, 'process': observed, 'passed': False}
            result['runs'].append(row)
            try:
                require(observed['exit_code'] == 0 and not observed['timed_out'], 'NATIVE_TEST_FAILED')
                row['named_execution'] = validate((folder / 'stdout').read_text().splitlines(), name)
                row['passed'] = True
            except (ValueError, OSError, UnicodeError) as error:
                row['failure'] = str(error)
                result['failures'].append(name + ': ' + str(error))
            print(json.dumps(row, sort_keys=True), flush=True)
        result['binary_sha256_after'] = digest(binary.read_bytes())
        require(result['binary_sha256_before'] == result['binary_sha256_after']
                == digest((out / TARGET).read_bytes()), 'NATIVE_BINARY_CHANGED')
        result['all_named_tests_passed'] = len(result['runs']) == len(TESTS) and all(r['passed'] for r in result['runs'])
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result['failures'].append(str(error))
    finally:
        if previous_output is None:
            os.environ.pop('TRNM_PUBLIC_V3_FROM_ZERO_DIR', None)
        else:
            os.environ['TRNM_PUBLIC_V3_FROM_ZERO_DIR'] = previous_output
        try:
            result['source_after'] = source_identity()
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            result['failures'].append(str(error))
        result['passed'] = (result['source_before'] == result['source_after']
                            and result['source_recompiled'] and result['format_passed']
                            and result['all_named_tests_passed'] and not result['failures'])
        result['files'] = {p.relative_to(out).as_posix(): digest(p.read_bytes())
                           for p in sorted(out.rglob('*')) if p.is_file()}
        (out / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    receipt = run(parser.parse_args().out)
    print(json.dumps({'passed': receipt['passed'], 'failures': receipt['failures']}))
    raise SystemExit(0 if receipt['passed'] else 1)
