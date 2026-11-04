#!/usr/bin/env python3
"""Cargo runner for the original complete architecture and sync observations.

Only the two explicitly admitted original targets enter the protected Host parent.
Every other Cargo executable keeps its exact argv, environment and working
directory. No test is skipped, renamed, ignored or replaced with a receipt.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TARGET = re.compile(r'architecture_delivery_compare-[0-9a-f]{16}')
TESTS = (
    'reference_dag_rejects_withheld_body_equivocation_and_changed_signed_history',
    'signed_dag_delivery_comparison_uses_same_native_business_and_confirmation_contract',
)
MODES = ('serial-signed-batches', 'concurrent-proposer-batches', 'signed-reference-dag')
SCENARIOS = ('disjoint-recipients', 'hot-recipient')


def require(value, message):
    if not value:
        raise ValueError(message)


def selected(command):
    require(bool(command), 'ARCHITECTURE_CARGO_EXECUTABLE_REQUIRED')
    name = Path(command[0]).name
    if not name.startswith('architecture_delivery_compare-'):
        return False
    require(TARGET.fullmatch(name) is not None and len(command) == 1,
            'ARCHITECTURE_ORIGINAL_UNFILTERED_TARGET_REQUIRED')
    return True


def validate_observation(stdout, report):
    """Validate execution completeness; the Rust test retains semantic authority."""
    names = re.findall(r'^test (\S+) \.\.\. ok$', stdout, re.M)
    require(sorted(names) == sorted(TESTS), 'ARCHITECTURE_EXACT_TWO_TESTS')
    summaries = re.findall(
        r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
        r'(\d+) measured; (\d+) filtered out; finished in [0-9.]+s$', stdout, re.M)
    require(summaries == [('ok', '2', '0', '0', '0', '0')],
            'ARCHITECTURE_COMPLETE_UNFILTERED_SUMMARY')
    require(report.get('schema') == 'native-signed-dag-delivery-comparison-v1'
            and report.get('same_signed_packets_across_modes_and_repetitions') is True
            and report.get('balanced_cyclic_mode_order') is True
            and report.get('samples_per_workload_and_mode') == 3,
            'ARCHITECTURE_ORIGINAL_REPORT')
    samples = report.get('samples')
    require(type(samples) is list and len(samples) == 18, 'ARCHITECTURE_ALL_EIGHTEEN_SAMPLES')
    actual = []
    for row in samples:
        require(type(row) is dict and row.get('scenario') in SCENARIOS
                and type(row.get('sample')) is int and row['sample'] in range(3)
                and type(row.get('position')) is int and row['position'] in range(3),
                'ARCHITECTURE_ORIGINAL_SAMPLE_IDENTITY')
        require(row.get('mode') == MODES[(row['sample'] + row['position']) % 3]
                and row.get('cold_reopen_equal') is True and row.get('errors') == []
                and type(row.get('finite_business_target_met')) is bool,
                'ARCHITECTURE_RETAINED_NATIVE_INVARIANTS')
        actual.append((row['scenario'], row['sample'], row['position']))
    expected = [(scenario, sample, position) for scenario in SCENARIOS
                for sample in range(3) for position in range(3)]
    require(sorted(actual) == sorted(expected), 'ARCHITECTURE_DISTINCT_ORIGINAL_SAMPLES')
    business = all(row['finite_business_target_met'] for row in samples)
    require(report.get('all_finite_business_targets_met') is business,
            'ARCHITECTURE_BUSINESS_OUTCOME_CONSISTENCY')
    return {'named_tests': list(TESTS), 'passed': 2, 'failed': 0, 'ignored': 0,
            'filtered_out': 0, 'samples': 18, 'all_finite_business_targets_met': business,
            'business_outcome_is_not_inferred_from_exit_code': True}


def run_selected(command):
    # -I deliberately excludes caller PYTHONPATH and the script directory.
    os.environ['GIT_NO_LAZY_FETCH'] = '1'
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from from_zero_native_host import ARCHITECTURE_TIMEOUT_SECONDS, run_host_child, sha
    from history_fixed_parent_v2 import owner
    from verify_ci_source import verify

    original_cwd = Path.cwd()
    out_root = os.environ.get('TRNM_CI_RECEIPT_DIR')
    require(out_root is not None, 'ARCHITECTURE_RECEIPT_DIRECTORY_REQUIRED')
    out = Path(out_root) / 'architecture-native-host'
    require(out.is_absolute() and not out.resolve().is_relative_to(ROOT),
            'ARCHITECTURE_RECEIPT_OUTSIDE_SOURCE')
    out.mkdir(parents=True, exist_ok=False)
    run_owner = os.environ.get('TRNM_FROM_ZERO_HOST_OWNER')
    if run_owner is None:
        run_owner = os.environ.get('GITHUB_RUN_ID', '') + '.' + os.environ.get('GITHUB_RUN_ATTEMPT', '')
    owner(run_owner)
    require(os.environ.get('RUST_TEST_THREADS') == '1', 'ARCHITECTURE_ORIGINAL_SERIAL_HARNESS')
    binary = Path(command[0])
    require(binary.is_absolute() and not binary.is_symlink()
            and binary.resolve(strict=True) == binary, 'ARCHITECTURE_ORIGINAL_BINARY')

    def identity():
        source = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
        expected = os.environ.get('TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT')
        require(source == expected, 'ARCHITECTURE_COMPILE_AND_RUN_SOURCE')
        return verify('head', source, root=ROOT)

    record = {'schema': 'native-architecture-host-process-v1', 'original_cargo_command': command,
              'original_cargo_cwd': str(original_cwd), 'native_cwd': str(ROOT),
              'original_test_execution_mapping': {name: 'native/stdout' for name in TESTS},
              'target_selection_changed': False, 'source_before': None, 'source_after': None,
              'source_unchanged': False, 'binary_unchanged': False, 'actual_process': None,
              'observation': None, 'complete': False, 'production_qualification': False,
              'errors': []}

    def save():
        (out / 'summary.json').write_text(json.dumps(record, indent=2) + '\n')

    def parent(action):
        args = ['/usr/bin/sudo', '-n', '--', '/usr/bin/python3', '-I', '-B',
                str(ROOT / 'scripts/ci/history_fixed_parent_v2.py'), action, '--owner', run_owner]
        if action == 'provision':
            args += ['--source', str(ROOT / 'config/systemd/trnmponpublic.slice')]
        observed = subprocess.run(args, cwd=ROOT, capture_output=True, timeout=20, check=False)
        for stream in ('stdout', 'stderr'):
            (out / f'parent-{action}.{stream}').write_bytes(getattr(observed, stream))
        record['parent_' + action] = {'command': args, 'returncode': observed.returncode}
        require(observed.returncode == 0, 'ARCHITECTURE_PARENT_' + action.upper())

    provisioned = False
    save()
    try:
        record['source_before'] = identity()
        record['binary_sha256'] = sha(binary.read_bytes())
        record['test_source_sha256'] = sha((ROOT / 'trillionnium/crates/trnm-pon-node/tests/architecture_delivery_compare.rs').read_bytes())
        os.chdir(ROOT)  # The existing root helper binds both actor CWDs to this exact source.
        os.environ['TRNM_ARCHITECTURE_COMPARE_DIR'] = str(out / 'native-report')
        parent('provision')
        provisioned = True
        save()
        print(json.dumps({'event': 'original architecture target enters fixed Host parent',
                          'source': record['source_before']['tested_commit'],
                          'tests': list(TESTS), 'receipt': str(out)}), flush=True)
        result = run_host_child(command, out / 'native', ARCHITECTURE_TIMEOUT_SECONDS,
                                run_owner=run_owner,
                                source=record['source_before']['tested_commit'],
                                binary_sha256=record['binary_sha256'])
        record['actual_process'] = result
        stdout = (out / 'native/stdout').read_bytes()
        stderr = (out / 'native/stderr').read_bytes()
        sys.stdout.buffer.write(stdout)
        sys.stderr.buffer.write(stderr)
        sys.stdout.buffer.flush()
        sys.stderr.buffer.flush()
        report_bytes = (out / 'native-report/report.json').read_bytes()
        record['report_sha256'] = sha(report_bytes)
        record['observation'] = validate_observation(stdout.decode('utf-8'), json.loads(report_bytes))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        record['errors'].append(str(error))
    finally:
        if provisioned:
            try:
                parent('cleanup')
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                record['errors'].append(str(error))
        try:
            record['source_after'] = identity()
            record['source_unchanged'] = record['source_before'] == record['source_after']
            record['binary_unchanged'] = record.get('binary_sha256') == sha(binary.read_bytes())
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            record['errors'].append(str(error))
        result = record['actual_process']
        record['complete'] = (not record['errors'] and record['source_unchanged']
                              and record['binary_unchanged'] and record['observation'] is not None
                              and result is not None and result['host_scope']['complete']
                              and result['host_scope']['closure'].get('closed') is True
                              and result['host_scope']['closure'].get('forced_cleanup') is False)
        save()
    if record['complete']:
        return 0
    code = (record['actual_process'] or {}).get('exit_code')
    return code if type(code) is int and 0 < code < 256 else 1


def main():
    command = sys.argv[1:]
    if selected(command):
        return run_selected(command)
    # Keep the second original integration target separately selected and
    # validated. No other Cargo executable acquires a privileged Host profile.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import evaluation_host_runner
    if evaluation_host_runner.selected(command):
        return evaluation_host_runner.run_selected(command)
    os.execv(command[0], command)
    raise AssertionError('exec returned')


if __name__ == '__main__':
    raise SystemExit(main())
