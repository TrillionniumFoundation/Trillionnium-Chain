#!/usr/bin/env python3
"""Retain actual signed account execution and an independent JSON transition check.

The immutable SQLite export is checked as a delivery artifact.  The separate
application oracle reads only the observation JSON and does not independently
reexecute native consensus, storage recovery or database operations.
"""
from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

from ci_observation import ROOT, digest, receipt_root, source
from check_cross_arch_cost import require
from run_cross_arch_cost import capture
from run_account_archive_conformance import EXPORT_FILES, validate_export_retention


MAX_JSON_BYTES = 32 * 1024 * 1024


def read_json(path: Path):
    """Read this fixture's bounded UTF-8 JSON without relaxing the cost reader."""
    if path.is_symlink() or not path.is_file():
        raise ValueError('account execution JSON: require a regular non-symlink file')
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError('account execution JSON: exceeds the 32 MiB byte limit')
    with path.open('rb') as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError('account execution JSON: exceeds the 32 MiB byte limit')

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('account execution JSON: duplicate object key: ' + key)
            value[key] = item
        return value

    def nonfinite(value):
        raise ValueError('account execution JSON: nonfinite constant: ' + value)

    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=nonfinite)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('account execution JSON: invalid UTF-8 or JSON syntax') from error


INPUTS = sorted(set([
    'rust-toolchain.toml', 'trillionnium/Cargo.toml', 'trillionnium/Cargo.lock',
    'formal/pon-nakamoto-v1/requirements.txt',
    'formal/pon-nakamoto-v1/account_execution_oracle.py',
    'formal/pon-nakamoto-v1/test_account_execution_oracle.py',
    'formal/pon-nakamoto-v1/account_archive_oracle.py',
    'formal/pon-nakamoto-v1/strict_signature.py',
    'scripts/ci/run_account_execution_conformance.py',
    'scripts/ci/test_run_account_execution_conformance.py',
    'scripts/ci/run_account_archive_conformance.py',
    'scripts/ci/ci_observation.py', 'scripts/ci/verify_ci_source.py',
    'scripts/ci/run_cross_arch_cost.py', 'scripts/ci/check_cross_arch_cost.py',
    'scripts/ci/ci_job.sh', '.github/workflows/trnm-required-baseline.yml',
] + [str(path.relative_to(ROOT)) for pattern in
     ['trillionnium/crates/**/*.rs', 'trillionnium/crates/*/Cargo.toml', 'config/pon/*.json']
     for path in ROOT.glob(pattern)]))

NATIVE_SCOPE = {
    'complete_state_retained': True,
    'research_account_access_execution': True,
    'serial_execution_only': True,
    'production_backend_changed': False,
    'protocol_capacity_changed': False,
    'public_data_availability_accepted': False,
    'production_activation': False,
}
ORACLE_SCOPE = {
    'independent_genesis_derivation': True,
    'independent_signed_application_transitions': True,
    'complete_state_and_account_roots': True,
    'account_access_witnesses_checked': True,
    'native_consensus_admission_reexecuted': False,
    'work_relation_reverified': False,
    'fork_choice_reverified': False,
    'production_activation': False,
    'protocol_capacity_changed': False,
    'public_data_availability_accepted': False,
}
BLOCK_LABELS = ([f'main-{height:02}' for height in range(1, 22)] +
                [f'fork-{height:02}' for height in range(3, 23)] + ['restored-22', 'restored-23'])
REOPEN_LABELS = ['main-21', 'fork-22', 'restored-23']
NEGATIVE_LABELS = [
    'missing-sender', 'missing-new-recipient', 'missing-intrablock-owner',
    'missing-future-reward-recipient', 'missing-quota-provider', 'missing-expiry-recipient',
    'missing-matured-reward-recipient', 'unused-witness', 'duplicate-witness',
    'forged-account-value', 'forged-account-absence', 'witness-from-old-branch',
    'forged-witness-root', 'malformed-witness', 'witness-budget', 'wrong-parent',
    'wrong-height', 'wrong-context', 'wrong-source-state-root',
    'wrong-nonaccount-source-state-root', 'missing-checkpoint', 'main-signature',
    'recredited-nonce-replay', 'fee-limit', 'insufficient-funds', 'consumer-signature',
    'resource-id', 'canonical-nonce-before-later-signature', 'cancel-before-output',
]


def directory_sha256(directory: Path, *, exact: set[str] | None = None) -> dict[str, str]:
    """Hash regular retained files; refuse symlinks and unexpected export entries."""
    require(directory.is_dir() and not directory.is_symlink(), 'retained output must be an actual directory')
    files = {}
    for path in sorted(directory.rglob('*')):
        relative = str(path.relative_to(directory))
        mode = path.lstat().st_mode
        require(not stat.S_ISLNK(mode), 'retained output may not follow a symlink: ' + relative)
        if stat.S_ISDIR(mode):
            require(exact is None, 'standalone export may not contain an extra directory: ' + relative)
            continue
        require(stat.S_ISREG(mode), 'retained output must be a regular file: ' + relative)
        require(exact is None or relative in exact, 'unexpected standalone export file: ' + relative)
        files[relative] = digest(path)
    require(exact is None or set(files) == exact, 'complete standalone export file inventory required')
    return files


def file_observation(value: dict, label: str) -> None:
    require(type(value) is dict and set(value) == {'exists', 'bytes', 'error'},
            'complete native file observation: ' + label)
    if value['error'] is not None:
        require(type(value['error']) is str and bool(value['error']) and
                value['exists'] is None and value['bytes'] is None,
                'a failed file observation cannot claim a successful stat: ' + label)
    else:
        require(type(value['exists']) is bool, 'boolean observed file existence: ' + label)
        require((type(value['bytes']) is int and value['bytes'] >= 0) if value['exists'] else
                value['bytes'] is None, 'observed file length or absence: ' + label)


def successful_step(value: dict, label: str) -> None:
    require(type(value) is dict and value == {'result': 'OK', 'error': None},
            'native snapshot operation must succeed without hidden failure: ' + label)


def validate_snapshot_finalization(value: dict, database: Path,
                                   expected_working: str, expected_export: str) -> dict:
    """Check actual bytes/receipt only; no SQLite connection or native I/O replay."""
    require(type(value) is dict and set(value) == {
        'schema', 'result', 'sqlite_version', 'method', 'source_database',
        'export_database', 'source', 'export'}, 'exact standalone snapshot receipt fields')
    require(value['schema'] == 'pon-account-archive-snapshot-finalization-v1' and
            value['result'] == 'PASS' and value['method'] == 'VACUUM main INTO ?1',
            'the existing native standalone snapshot relation must succeed')
    require(value['source_database'] == expected_working and value['export_database'] == expected_export,
            'snapshot source and export must bind this fresh native command')
    require(type(value['sqlite_version']) is str and bool(value['sqlite_version']), 'observed SQLite version')
    observed_source, exported = value['source'], value['export']
    require(type(observed_source) is dict and type(exported) is dict, 'complete source/export observations')
    require(observed_source['connection_path'] == expected_working and observed_source['path_matches'] is True and
            observed_source['query_errors'] == [] and observed_source['autocommit_before_checkpoint'] is True and
            observed_source['checkpoint_error'] is None, 'actual source path, queries and autocommit must agree')
    require(type(observed_source['synchronous']) is int, 'actual source synchronous value')
    checkpoint = observed_source['checkpoint']
    require(type(checkpoint) is dict and set(checkpoint) == {'busy', 'log_frames', 'checkpointed_frames'} and
            all(type(number) is int and number == 0 for number in checkpoint.values()),
            'all actual checkpoint columns must equal integer zero')
    successful_step(observed_source['close'], 'source control connection close')
    for name in ['wal_before_checkpoint', 'wal_after_checkpoint', 'wal_after_close']:
        file_observation(observed_source[name], 'source ' + name)
    missing = {'exists': False, 'bytes': None, 'error': None}
    file_observation(exported['destination_before'], 'export destination before snapshot')
    require(exported['destination_before'] == missing, 'export destination must be fresh')
    for name in ['vacuum_into', 'open', 'close']:
        successful_step(exported[name], 'export ' + name)
    require(exported['journal_mode'] == 'delete' and exported['query_errors'] == [] and
            exported['header_error'] is None, 'successful standalone DELETE-mode export inspection')
    for section in [observed_source, exported]:
        for name in ['page_count', 'page_size']:
            require(type(section[name]) is int and section[name] > 0, 'actual positive snapshot geometry')
    require(database.is_file() and not database.is_symlink(), 'retained standalone database must be regular')
    size = database.stat().st_size
    file_observation(exported['file_after_close'], 'export after close')
    require(exported['file_after_close'] == {'exists': True, 'bytes': size, 'error': None} and
            size == exported['page_count'] * exported['page_size'], 'actual snapshot file length/geometry')
    with database.open('rb') as stream:
        header = stream.read(100)
    require(len(header) == 100 and header[:16] == b'SQLite format 3\0' and header[18:20] == b'\x01\x01' and
            exported['header_prefix_hex'] == header[:20].hex(), 'actual SQLite header must use versions 1/1')
    encoded_page_size = int.from_bytes(header[16:18], 'big')
    require(exported['page_size'] == (65536 if encoded_page_size == 1 else encoded_page_size),
            'retained SQLite header page size must agree')
    for name, suffix in [('wal_after_close', '-wal'), ('shm_after_close', '-shm'),
                         ('journal_after_close', '-journal')]:
        file_observation(exported[name], 'export ' + name)
        require(exported[name] == missing and not os.path.lexists(str(database) + suffix),
                'standalone export must have no physical late sidecar: ' + suffix)
    return {'schema': value['schema'], 'method': value['method'], 'export_file_bytes': size,
            'export_page_count': exported['page_count'], 'export_page_size': exported['page_size'],
            'export_header_prefix_hex': header[:20].hex(), 'checkpoint': checkpoint,
            'sqlite_rows_independently_checked': False, 'native_snapshot_reexecuted': False,
            'working_files_immutability_claimed': False}


def validate_reports(native: dict, oracle: dict, native_digest: str) -> dict:
    """Bind the independent complete JSON check to this exact signed native set."""
    require(type(native) is dict and native.get('schema') == 'pon-account-execution-native-observation-v1' and
            'error' not in native, 'complete actual account execution observation without hidden failure')
    require(native.get('scope') == NATIVE_SCOPE and all(type(v) is bool for v in native['scope'].values()),
            'research execution must retain complete State and its exact native scope')
    require(type(native.get('blocks')) is list and len(native['blocks']) == 43 and
            all(type(row) is dict for row in native['blocks']), 'all 43 actual signed/admitted block observations')
    require([row.get('label') for row in native['blocks']] == BLOCK_LABELS,
            'the exact main, fork and restored branch observation sequence is required')
    require(type(native.get('reopens')) is list and len(native['reopens']) == 3 and
            all(type(row) is dict for row in native['reopens']) and
            [row.get('label') for row in native['reopens']] == REOPEN_LABELS, 'all three native reopen observations')
    for name, expected in [('accepted_native_packets', 43), ('accepted_signed_transactions', 20),
                           ('native_reorganizations', 2), ('cold_reopens', 3)]:
        require(type(native.get(name)) is int and native[name] == expected,
                'actual native signed fixture count: ' + name)
    negatives = native.get('negative_cases')
    require(type(negatives) is list and len(negatives) == len(NEGATIVE_LABELS) and
            all(type(row) is dict for row in negatives) and
            [row.get('label') for row in negatives] == NEGATIVE_LABELS,
            'the complete 29-case native negative sequence is required')
    require(type(oracle) is dict and oracle.get('schema') == 'pon-account-execution-oracle-observation-v1' and
            oracle.get('result') == 'PASS' and 'error' not in oracle and
            oracle.get('native_json_sha256') == native_digest, 'actual oracle success must bind this exact native JSON')
    require(oracle.get('scope') == ORACLE_SCOPE and all(type(v) is bool for v in oracle['scope'].values()),
            'independent signed transitions cannot promote consensus, recovery or production acceptance')
    require(oracle.get('native_scope') == NATIVE_SCOPE and all(type(v) is bool for v in oracle['native_scope'].values()),
            'independent report must retain the exact native research scope')
    require(oracle.get('genesis_checked') is True, 'independent complete genesis derivation required')
    counts = {'blocks_checked': 43, 'transaction_envelopes_checked': 20,
              'reorganizations_checked': 2, 'reopen_observations_checked': 3,
              'negative_observations_checked': 29}
    for name, expected in counts.items():
        require(type(oracle.get(name)) is int and oracle[name] == expected,
                'complete independent signed fixture count: ' + name)
    for name, expected in [('block_observations', 43), ('reopen_observations', 3),
                           ('negative_observations', len(negatives))]:
        require(type(oracle.get(name)) is list and len(oracle[name]) == expected and
                all(type(row) is dict for row in oracle[name]), 'complete independent detailed observations: ' + name)
    require([row.get('label') for row in oracle['negative_observations']] == NEGATIVE_LABELS,
            'all independent negative results must bind the actual ordered cases')
    require(oracle.get('complete_archive_rows_from_observation_checked') is True and
            oracle.get('sqlite_database_opened') is False,
            'independent reported-row reconstruction must remain distinct from SQLite inspection')
    return {**counts, 'genesis_checked': True,
            'scope': dict(ORACLE_SCOPE), 'native_scope': dict(NATIVE_SCOPE),
            'complete_archive_rows_from_observation_checked': True, 'sqlite_rows_independently_checked': False}


def finish_execution_receipt(output: Path, report: dict) -> None:
    """Success is assigned after final source, executable and complete export checks."""
    report['result'] = 'FAIL'
    try:
        report['source_after'] = source()
        report['source'] = report['source_after']
        report['input_sha256_after'] = {name: digest(ROOT / name) for name in INPUTS}
        report['input_sha256'] = report['input_sha256_after']
        report['source_changed'] = (report.get('source_before') != report['source_after'] or
                                   report.get('input_sha256_before') != report['input_sha256_after'])
        if 'binary_path' in report:
            report['binary_sha256_at_finish'] = digest(Path(report['binary_path']))
        report['artifact_sha256'] = directory_sha256(output)
        report['native_files_sha256_at_finish'] = {
            name.removeprefix('native/'): value for name, value in report['artifact_sha256'].items()
            if name.startswith('native/')}
        report['working_files_sha256_at_finish'] = {
            name.removeprefix('native-working/'): value for name, value in report['artifact_sha256'].items()
            if name.startswith('native-working/')}
        working = [report.get('working_files_sha256_before_oracle'),
                   report.get('working_files_sha256_after_oracle'), report['working_files_sha256_at_finish']]
        report['working_files_changed_during_observation'] = (
            not all(value == working[0] for value in working)
            if all(type(value) is dict for value in working) else None)
        if report.get('checks_completed_before_retention') is True and 'error' not in report:
            require(report['source_changed'] is False, 'account execution source changed during conformance')
            actual_export = directory_sha256(output / 'native', exact=EXPORT_FILES)
            exported, _ = validate_export_retention(report['native_files_sha256_before_oracle'], report['artifact_sha256'])
            require(actual_export == exported == report['native_files_sha256_after_oracle'],
                    'complete execution export changed before final retention')
            require(report['binary_sha256_at_finish'] == report['binary_sha256_before'] ==
                    report['binary_sha256_after'] == digest(output / 'account_execution_vectors'),
                    'same actual execution binary must remain retained at final completion')
            report['result'] = 'PASS'
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        report['final_retention_error'] = str(error)
        print(str(error), file=sys.stderr)
    with (output / 'manifest.json').open('x') as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'result': report['result'], 'receipt': str(output)}, sort_keys=True))


def main() -> int:
    output = receipt_root('account-execution').resolve(strict=True)
    report = {'schema': 'trnm-account-execution-conformance-execution-v1', 'result': 'FAIL',
              'observations': [], 'source_before': None, 'native_scope': dict(NATIVE_SCOPE),
              'oracle_scope': dict(ORACLE_SCOPE), 'working_files_immutability_claimed': False,
              'oracle_reads_sqlite': False, 'sqlite_rows_independently_checked': False,
              'production_activation': False}

    def checked(command: list[str], stem: str, timeout: int) -> None:
        observed = capture(command, output, stem, timeout=timeout)
        report['observations'].append(observed)
        if (type(observed['exit_code']) is not int or observed['exit_code'] != 0 or
                observed['timed_out'] is not False or 'launch_error' in observed):
            raise RuntimeError(stem + ' failed; original output/status remain retained')

    try:
        report['source_before'] = source()
        expected = os.environ.get('TRNM_EXPECTED_SOURCE_SHA', '')
        require(re.fullmatch('[0-9a-f]{40}', expected) is not None and
                report['source_before']['commit'] == expected and
                report['source_before']['source_state'] == 'committed-clean',
                'account execution vectors require the exact expected committed source')
        report['input_sha256_before'] = {name: digest(ROOT / name) for name in INPUTS}
        report['python_environment'] = {'executable': sys.executable, 'version': sys.version,
            'cryptography': importlib.metadata.version('cryptography')}
        target = Path(os.environ['CARGO_TARGET_DIR'])
        require(target.is_absolute(), 'the actual isolated Cargo target directory must be explicit')
        binary = (target / 'release/examples/account_execution_vectors').resolve(strict=True)
        require(binary.is_file() and os.access(binary, os.X_OK), 'actual release account execution example must be built first')
        report['binary_path'] = str(binary)
        report['binary_sha256_before'] = digest(binary)
        shutil.copyfile(binary, output / 'account_execution_vectors')
        native_output, working_output = output / 'native', output / 'native-working'
        checked([str(binary), str(native_output)], 'native', 300)
        native_path, database = native_output / 'observation.json', native_output / 'archive.sqlite'
        native = read_json(native_path)
        require(native.get('database') == str(database) and
                native.get('working_database') == str(working_output / 'archive.sqlite'),
                'actual execution observation must bind its fresh export and working database')
        require((output / 'native.stdout').read_bytes() == native_path.read_bytes() + b'\n',
                'native stdout must equal the complete observation JSON written by this execution')
        frozen = directory_sha256(native_output, exact=EXPORT_FILES)
        finalization = read_json(native_output / 'finalization.json')
        require(finalization == native.get('finalization'), 'complete native/snapshot finalization identity')
        report['snapshot_delivery'] = validate_snapshot_finalization(finalization, database,
            str(working_output / 'archive.sqlite'), str(database))
        report['working_directory'] = str(working_output)
        report['working_files_sha256_before_oracle'] = directory_sha256(working_output)
        require('archive.sqlite' in report['working_files_sha256_before_oracle'] and
                any(name.startswith('native-node/') for name in report['working_files_sha256_before_oracle']),
                'retain the actual source archive and native Node working files')
        report['native_files_sha256_before_oracle'] = frozen
        checked([sys.executable, 'formal/pon-nakamoto-v1/account_execution_oracle.py',
                 '--native-json', str(native_path)], 'oracle', 300)
        oracle = read_json(output / 'oracle.stdout')
        report['independent_validation'] = validate_reports(native, oracle, digest(native_path))
        report['native_files_sha256_after_oracle'] = directory_sha256(native_output, exact=EXPORT_FILES)
        report['working_files_sha256_after_oracle'] = directory_sha256(working_output)
        require(report['native_files_sha256_after_oracle'] == frozen,
                'independent JSON checker must leave all original export files unchanged')
        report['binary_sha256_after'] = digest(binary)
        require(report['binary_sha256_after'] == report['binary_sha256_before'],
                'actual execution binary changed during conformance')
        report['checks_completed_before_retention'] = True
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        finish_execution_receipt(output, report)
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
