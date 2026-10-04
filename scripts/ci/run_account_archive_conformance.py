#!/usr/bin/env python3
"""Retain real archive vectors and a separate read-only arithmetic/database check."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from ci_observation import ROOT, digest, finish, receipt_root, source
from check_cross_arch_cost import read_json, require
from run_cross_arch_cost import capture

INPUTS = [
    'rust-toolchain.toml', 'trillionnium/Cargo.toml', 'trillionnium/Cargo.lock',
    'trillionnium/crates/trnm-pon-node/Cargo.toml',
    'trillionnium/crates/trnm-pon-node/src/account_archive_prototype.rs',
    'trillionnium/crates/trnm-pon-node/examples/account_archive_vectors.rs',
    'trillionnium/crates/trnm-pon-node/examples/support/account_archive_artifact.rs',
    'formal/pon-nakamoto-v1/account_archive_oracle.py',
    'formal/pon-nakamoto-v1/test_account_archive_oracle.py',
    'scripts/ci/run_account_archive_conformance.py',
    'scripts/ci/ci_observation.py', 'scripts/ci/run_cross_arch_cost.py',
]
ORACLE_SCOPE = {'independent_root_and_proof_arithmetic': True,
                'native_recovery_reexecuted': False, 'source_transition_authorized': False,
                'production_activation': False, 'large_account_space_verified': False}
NATIVE_SCOPE = {'archive_used_for_native_execution': False, 'protocol_capacity_changed': False,
                'public_data_availability_accepted': False, 'production_accepted': False}


def validate_reports(native: dict, oracle: dict, native_digest: str, database_digest: str) -> dict:
    """Require the small, complete native set plus the independent check's identity."""
    require(type(native) is dict and native.get('schema') == 'pon-account-archive-native-observation-v1',
            'archive native observation schema')
    require(native.get('reopened') is True and all(native.get(flag) is False for flag in
            ['archive_used_for_native_execution', 'protocol_capacity_changed', 'public_data_availability_accepted']),
            'shadow archive must keep its native reopening and non-consensus scope')
    require(type(native.get('snapshots')) is list and len(native['snapshots']) == 6 and
            type(native.get('operations')) is list and len(native['operations']) == 17,
            'complete bounded archive fixture cannot be replaced by a partial or large-space observation')
    require(type(oracle) is dict and oracle.get('schema') == 'pon-account-archive-oracle-observation-v1' and
            oracle.get('result') == 'PASS' and 'error' not in oracle,
            'independent archive checker must actually complete without a hidden failure')
    require(oracle.get('native_json_sha256') == native_digest and
            oracle.get('database_sha256') == database_digest,
            'independent check must bind the same original native JSON and closed database')
    require(oracle.get('scope') == ORACLE_SCOPE and
            all(type(value) is bool for value in oracle['scope'].values()),
            'small archive arithmetic/database evidence cannot promote large-space or production acceptance')
    require(oracle.get('native_scope') == NATIVE_SCOPE and
            all(type(value) is bool for value in oracle['native_scope'].values()),
            'native shadow archive observations cannot promote execution, capacity or data availability')
    for name, expected in [('snapshots_checked', 6), ('witness_checks', 13), ('operation_observations_checked', 17)]:
        require(type(oracle.get(name)) is int and oracle[name] == expected,
                'complete independent archive comparison count: ' + name)
    for name, expected in [('witness_observations', 13), ('operation_observations', 17)]:
        require(type(oracle.get(name)) is list and len(oracle[name]) == expected and
                all(type(row) is dict for row in oracle[name]),
                'all detailed independent archive comparison records must remain retained: ' + name)
    require(type(oracle.get('database')) is dict and oracle['database'].get('all_node_records_checked') is True,
            'the independent oracle must inspect actual persisted node records')
    return {'snapshots_checked': 6, 'witness_checks': 13, 'operation_observations_checked': 17,
            'scope': dict(ORACLE_SCOPE)}


def main() -> int:
    output = receipt_root('account-archive')
    report = {'schema': 'trnm-account-archive-conformance-execution-v1', 'result': 'FAIL',
              'observations': [], 'source_before': None,
              'archive_used_for_native_execution': False, 'protocol_capacity_changed': False,
              'public_data_availability_accepted': False, 'large_account_space_verified': False,
              'production_activation': False}

    def checked(command, stem, timeout):
        observed = capture(command, output, stem, timeout=timeout)
        report['observations'].append(observed)
        if observed['exit_code'] != 0 or observed['timed_out'] or 'launch_error' in observed:
            raise RuntimeError(stem + ' failed; original output and status remain retained')

    try:
        report['source_before'] = source()
        expected = os.environ.get('TRNM_EXPECTED_SOURCE_SHA', '')
        require(re.fullmatch('[0-9a-f]{40}', expected) is not None and
                report['source_before']['commit'] == expected and
                report['source_before']['source_state'] == 'committed-clean',
                'archive CI vectors require the exact expected committed source')
        report['input_sha256_before'] = {name: digest(ROOT / name) for name in INPUTS}
        binary = (Path(os.environ['CARGO_TARGET_DIR']) / 'release/examples/account_archive_vectors').resolve(strict=True)
        require(binary.is_file() and os.access(binary, os.X_OK), 'the actual release archive example must be built first')
        report['binary_sha256_before'] = digest(binary)
        shutil.copyfile(binary, output / 'account_archive_vectors')
        native_output = output / 'native'
        checked([str(binary), str(native_output)], 'native', 300)
        native_path, database = native_output / 'observation.json', native_output / 'archive.sqlite'
        native = read_json(native_path)
        require(native.get('database') == str(database), 'native archive database path must bind this fresh run')
        require((output / 'native.stdout').read_bytes() == native_path.read_bytes() + b'\n',
                'native stdout must retain the exact observation JSON written by this execution')
        frozen = {str(path.relative_to(native_output)): digest(path) for path in sorted(native_output.rglob('*'))
                  if path.is_file()}
        report['native_files_sha256_before_oracle'] = frozen
        checked([sys.executable, 'formal/pon-nakamoto-v1/account_archive_oracle.py',
                 '--native-json', str(native_path), '--database', str(database)], 'oracle', 300)
        oracle = read_json(output / 'oracle.stdout')
        report['independent_validation'] = validate_reports(native, oracle, digest(native_path), digest(database))
        after = {str(path.relative_to(native_output)): digest(path) for path in sorted(native_output.rglob('*'))
                 if path.is_file()}
        report['native_files_sha256_after_oracle'] = after
        require(after == frozen, 'the independent checker must leave every native output unchanged')
        report['binary_sha256_after'] = digest(binary)
        require(report['binary_sha256_before'] == report['binary_sha256_after'],
                'measured native archive executable changed during conformance')
        report['result'] = 'PASS'
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        try:
            report['source_after'] = source()
            report['input_sha256_after'] = {name: digest(ROOT / name) for name in INPUTS}
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            report['source_after'] = {'error': str(error)}
        report['source_changed'] = (report['source_before'] != report['source_after'] or
            report.get('input_sha256_before') != report.get('input_sha256_after'))
        if report['source_changed']:
            report['result'] = 'FAIL'
        finish(output, report, INPUTS)
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
