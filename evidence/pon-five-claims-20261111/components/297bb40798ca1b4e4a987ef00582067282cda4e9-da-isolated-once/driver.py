#!/usr/bin/env python3
"""One unchanged-test diagnostic; it cannot replace the complete DA suite."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import traceback

ROOT = Path('/home/qian-qi/work/chain-pon-five-claims-20261111-d6cb')
BASE = ROOT.parent / 'pon-five-claims-component-artifacts-d6cb'
SOURCE = '297bb40798ca1b4e4a987ef00582067282cda4e9'
ORIGINAL = BASE / (SOURCE + '-all')
OUTPUT = BASE / (SOURCE + '-da-isolated-once')
BINARY = ORIGINAL / 'da/binaries/trnm_data_availability-64b25e344716c90a'
EXPECTED = 'ac7491d9888890f10e60e31336b7c2cb5c74f3df89264dbd8ab8272037537c9f'
SELECTOR = 'cell::version_retention::tests::shard_plan::capacity::retained_shard_plan_initial_128_profile_accepts_complete_65_and_128_chunk_catalogs'


def save(path, data):
    path.write_text(json.dumps(data, sort_keys=True, indent=2) + '\n')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    # The full original run, including Clippy and its final input check, must end.
    if not (ORIGINAL / 'toolchain-provider-after.json').is_file():
        raise ValueError('original component/quality run is not complete')
    env = json.loads((ORIGINAL / 'environment.json').read_text())
    if os.environ.get('LD_LIBRARY_PATH') != env['LD_LIBRARY_PATH']:
        raise ValueError('use the same natural rustup loader environment')
    for key, value in env.items():
        if key == 'LD_LIBRARY_PATH':
            continue
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    toolchain = Path(env['RUSTC']).parent
    os.environ['PATH'] = str(toolchain) + ':' + os.environ.get('PATH', '')
    sys.path.insert(0, str(ROOT / 'scripts/ci'))
    from verify_ci_source import verify
    from pinned_native_process import run_pinned
    OUTPUT.mkdir(parents=True, exist_ok=False)
    shutil.copy2(__file__, OUTPUT / 'driver.py')
    save(OUTPUT / 'environment.json', {key: os.environ.get(key) for key in env})
    argv = [str(BINARY), '--exact', SELECTOR, '--nocapture', '--test-threads=1']
    cwd = ROOT / 'trillionnium/crates/trnm-data-availability'
    report = {'source': SOURCE, 'argv': argv, 'cwd': str(cwd),
              'status': 'running', 'exit_code': None,
              'scope': 'one isolated diagnostic; full-suite failure remains',
              'whole_suite_passed': False, 'deadline_changed': False,
              'assertions_changed': False, 'performance_measurement': False}
    save(OUTPUT / 'receipt.json', report)
    started = time.monotonic_ns()
    try:
        report['source_before'] = verify('head', SOURCE, root=ROOT)
        report['binary_before'] = {'path': str(BINARY), 'sha256': digest(BINARY),
                                   'bytes': BINARY.stat().st_size}
        if report['binary_before']['sha256'] != EXPECTED:
            raise ValueError('retained original ELF differs from its full-suite pin')
        log = OUTPUT / 'native-combined.log'
        with log.open('xb') as stream:
            report['exit_code'], report['native_execution'] = run_pinned(argv, cwd, stream, EXPECTED)
        report['combined_stdout_stderr'] = {'path': str(log), 'bytes': log.stat().st_size,
                                           'sha256': digest(log)}
        matches = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', log.read_text())
        if not matches:
            raise ValueError('missing isolated native roster result')
        state, passed, failed, ignored, measured, filtered = matches[-1]
        report['counts'] = dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'),
                                    map(int, (passed, failed, ignored, measured, filtered))))
        if int(passed) + int(failed) != 1 or (ignored, measured, filtered) != ('0', '0', '740'):
            raise ValueError('isolated result does not match the single original selector')
        report['status'] = 'diagnostic_passed' if report['exit_code'] == 0 else 'diagnostic_failed'
        if report['native_execution']['status'] != 'PINNED_AND_OBSERVED':
            report['status'] = 'native_not_fully_observed'
    except BaseException:
        report['status'] = 'record_failed'
        report['error'] = traceback.format_exc()
    finally:
        try:
            report['source_after'] = verify('head', SOURCE, root=ROOT)
            report['binary_after'] = {'path': str(BINARY), 'sha256': digest(BINARY),
                                      'bytes': BINARY.stat().st_size}
            report['source_stable'] = report['source_before'] == report['source_after']
            report['binary_stable'] = report['binary_before'] == report['binary_after']
            if not report['source_stable'] or not report['binary_stable']:
                raise ValueError('source or retained binary changed')
        except BaseException:
            report['status'] = 'guard_failed'
            report['guard_error'] = traceback.format_exc()
        report['elapsed_ns'] = time.monotonic_ns() - started
        save(OUTPUT / 'receipt.json', report)
        print(json.dumps(report), flush=True)
    return 0 if report['status'] == 'diagnostic_passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
