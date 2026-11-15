#!/usr/bin/env python3
"""Finite receipt/file controls; synthetic bytes are never native execution evidence."""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_account_execution_conformance as execution


def reports():
    native = {'schema': 'pon-account-execution-native-observation-v1', 'scope': dict(execution.NATIVE_SCOPE),
              'blocks': [{'label': label} for label in execution.BLOCK_LABELS],
              'reopens': [{'label': label} for label in execution.REOPEN_LABELS],
              'negative_cases': [{'label': label} for label in execution.NEGATIVE_LABELS],
              'accepted_native_packets': 43, 'accepted_signed_transactions': 20,
              'native_reorganizations': 2, 'cold_reopens': 3}
    oracle = {'schema': 'pon-account-execution-oracle-observation-v1', 'result': 'PASS',
              'native_json_sha256': '1' * 64, 'genesis_checked': True,
              'scope': dict(execution.ORACLE_SCOPE), 'native_scope': dict(execution.NATIVE_SCOPE),
              'blocks_checked': 43, 'transaction_envelopes_checked': 20,
              'reorganizations_checked': 2, 'reopen_observations_checked': 3,
              'negative_observations_checked': 29, 'complete_archive_rows_from_observation_checked': True,
              'sqlite_database_opened': False,
              'block_observations': [{} for _ in range(43)], 'reopen_observations': [{} for _ in range(3)],
              'negative_observations': [{'label': label} for label in execution.NEGATIVE_LABELS]}
    return native, oracle


def state_witness_reports():
    native, _ = reports()
    native['context'] = {'synthetic': 'context-identity-only'}
    for index, block in enumerate(native['blocks']):
        block['id'] = [index] * 32
    companion = {'schema': 'pon-state-witness-native-observation-v1', 'result': 'PASS',
        'source_native_schema': 'pon-account-execution-native-observation-v1',
        'native_json_sha256': '1' * 64, 'context': native['context'],
        'blocks': copy.deepcopy(native['blocks']),
        'negative_cases': [{'label': label} for label in execution.STATE_WITNESS_NEGATIVE_LABELS],
        'scope': dict(execution.STATE_WITNESS_NATIVE_SCOPE)}
    oracle = {'schema': 'pon-state-witness-oracle-observation-v1', 'result': 'PASS',
        'native_schema': companion['schema'], 'native_json_sha256': '1' * 64,
        'state_witness_json_sha256': '2' * 64, 'genesis_checked': True,
        'blocks_checked': 43, 'state_transitions_checked': 86,
        'signed_transaction_envelopes_checked': 20, 'source_application_negative_observations_checked': 29,
        'complete_non_account_partitions_checked': 43, 'negative_observations_checked': 22,
        'block_observations': [{'label': block['label'], 'id': bytes(block['id']).hex()}
                                for block in native['blocks']],
        'negative_observations': [{'label': label} for label in execution.STATE_WITNESS_NEGATIVE_LABELS],
        'native_scope': dict(execution.STATE_WITNESS_NATIVE_SCOPE),
        'scope': dict(execution.STATE_WITNESS_ORACLE_SCOPE)}
    return native, companion, oracle


def snapshot(database: Path):
    # This is an intentionally synthetic header fixture, not a SQLite database
    # correctness test. The delivery checker reads raw bytes and never opens SQL.
    header = bytearray(4096)
    header[:16] = b'SQLite format 3\0'
    header[16:18] = (4096).to_bytes(2, 'big')
    header[18:20] = b'\x01\x01'
    database.write_bytes(header)
    missing = {'exists': False, 'bytes': None, 'error': None}
    ok = {'result': 'OK', 'error': None}
    return {
        'schema': 'pon-account-archive-snapshot-finalization-v1', 'result': 'PASS',
        'sqlite_version': 'synthetic-fixture', 'method': 'VACUUM main INTO ?1',
        'source_database': '/synthetic/native-working/archive.sqlite', 'export_database': str(database),
        'source': {'connection_path': '/synthetic/native-working/archive.sqlite', 'path_matches': True,
                   'synchronous': 2, 'page_count': 1, 'page_size': 4096, 'query_errors': [],
                   'autocommit_before_checkpoint': True,
                   'checkpoint': {'busy': 0, 'log_frames': 0, 'checkpointed_frames': 0},
                   'checkpoint_error': None, 'close': dict(ok),
                   'wal_before_checkpoint': dict(missing), 'wal_after_checkpoint': dict(missing),
                   'wal_after_close': dict(missing)},
        'export': {'destination_before': dict(missing), 'vacuum_into': dict(ok), 'open': dict(ok),
                   'journal_mode': 'delete', 'page_count': 1, 'page_size': 4096, 'query_errors': [],
                   'close': dict(ok), 'header_prefix_hex': bytes(header[:20]).hex(), 'header_error': None,
                   'file_after_close': {'exists': True, 'bytes': 4096, 'error': None},
                   'wal_after_close': dict(missing), 'shm_after_close': dict(missing),
                   'journal_after_close': dict(missing)},
    }


class AccountExecutionReceiptTests(unittest.TestCase):
    def test_companion_receipt_binds_both_files_all_blocks_and_distinct_json_scope(self):
        native, companion, oracle = state_witness_reports()
        checked = execution.validate_state_witness_reports(native, companion, oracle, '1' * 64, '2' * 64)
        self.assertEqual(checked['blocks_checked'], 43)
        self.assertEqual(checked['state_transitions_checked'], 86)
        self.assertEqual(checked['negative_observations_checked'], 22)
        self.assertFalse(checked['scope']['sqlite_database_opened'])
        self.assertFalse(checked['scope']['partial_state_backend_accepted'])

    def test_companion_counts_source_identity_order_and_hidden_failures_are_rejected(self):
        native, companion, oracle = state_witness_reports()
        changes = [lambda value: value.update(native_json_sha256='3' * 64),
                   lambda value: value.update(error=None),
                   lambda value: value['blocks'].reverse(),
                   lambda value: value['blocks'][0].update(id=[255] * 32),
                   lambda value: value['negative_cases'].pop(),
                   lambda value: value.update(context={})]
        for change in changes:
            altered = copy.deepcopy(companion)
            change(altered)
            with self.subTest(change=change), self.assertRaises(ValueError):
                execution.validate_state_witness_reports(native, altered, oracle, '1' * 64, '2' * 64)
        for fields in [{'state_witness_json_sha256': '3' * 64}, {'native_json_sha256': '3' * 64},
                       {'blocks_checked': True}, {'state_transitions_checked': 85},
                       {'complete_non_account_partitions_checked': 42}, {'negative_observations_checked': 21},
                       {'signed_transaction_envelopes_checked': 19}, {'source_application_negative_observations_checked': 28},
                       {'genesis_checked': 1}, {'negative_observations': []}, {'error': None}, {'result': 'FAIL'}]:
            altered = copy.deepcopy(oracle)
            altered.update(fields)
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                execution.validate_state_witness_reports(native, companion, altered, '1' * 64, '2' * 64)

    def test_companion_receipt_rejects_scope_promotions_and_boolean_integer_aliases(self):
        native, companion, oracle = state_witness_reports()
        for section in ('scope', 'native_scope'):
            for key, value in oracle[section].items():
                for replacement in (not value, int(value)):
                    altered = copy.deepcopy(oracle)
                    altered[section][key] = replacement
                    with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                        execution.validate_state_witness_reports(native, companion, altered, '1' * 64, '2' * 64)
        altered = copy.deepcopy(companion)
        altered['scope']['complete_state_required'] = 1
        with self.assertRaises(ValueError):
            execution.validate_state_witness_reports(native, altered, oracle, '1' * 64, '2' * 64)

    def test_execution_json_reader_has_its_own_actual_32_mib_boundary(self):
        self.assertEqual(execution.MAX_JSON_BYTES, 32 * 1024 * 1024)
        with tempfile.TemporaryDirectory(prefix='trnm-execution-json-boundary-') as directory:
            path = Path(directory) / 'synthetic.json'
            for size in [16 * 1024 * 1024 + 1, execution.MAX_JSON_BYTES]:
                with self.subTest(bytes=size):
                    path.write_bytes(b'{}' + b' ' * (size - 2))
                    self.assertEqual(path.stat().st_size, size)
                    self.assertEqual(execution.read_json(path), {})
            with path.open('ab') as stream:
                stream.write(b' ')
            self.assertEqual(path.stat().st_size, execution.MAX_JSON_BYTES + 1)
            with self.assertRaisesRegex(ValueError, 'account execution JSON: exceeds the 32 MiB byte limit'):
                execution.read_json(path)

    def test_execution_json_reader_rejects_nonregular_ambiguous_and_nonfinite_inputs(self):
        with tempfile.TemporaryDirectory(prefix='trnm-execution-json-refusal-') as directory:
            root = Path(directory)
            path = root / 'synthetic.json'
            for raw in [b'{"same":1,"same":2}', b'{"nested":{"same":1,"same":2}}',
                        b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}',
                        b'{} {}', b'\xff']:
                with self.subTest(raw=raw):
                    path.write_bytes(raw)
                    with self.assertRaisesRegex(ValueError, 'account execution JSON:'):
                        execution.read_json(path)
            path.write_bytes(b'{"finite":1}')
            for name, target in [('link', path), ('dangling', root / 'missing-target')]:
                link = root / name
                link.symlink_to(target)
                with self.subTest(path=name), self.assertRaisesRegex(ValueError, 'regular non-symlink file'):
                    execution.read_json(link)
            for invalid in [root, root / 'missing-file']:
                with self.subTest(path=invalid), self.assertRaisesRegex(ValueError, 'regular non-symlink file'):
                    execution.read_json(invalid)
            self.assertEqual(execution.read_json(path), {'finite': 1})

    def test_complete_fixture_identity_and_separate_json_scope(self):
        native, oracle = reports()
        checked = execution.validate_reports(native, oracle, '1' * 64)
        self.assertEqual(checked['blocks_checked'], 43)
        self.assertEqual(checked['transaction_envelopes_checked'], 20)
        self.assertFalse(checked['sqlite_rows_independently_checked'])
        self.assertFalse(checked['scope']['native_consensus_admission_reexecuted'])

    def test_native_partial_order_or_hidden_failure_cannot_be_promoted(self):
        native, oracle = reports()
        mutations = [lambda value: value['blocks'].pop(),
                     lambda value: value['blocks'].reverse(),
                     lambda value: value['reopens'].pop(),
                     lambda value: value['negative_cases'].reverse(),
                     lambda value: value.update(negative_cases=[]),
                     lambda value: value.update(cold_reopens=True),
                     lambda value: value.update(accepted_signed_transactions=19),
                     lambda value: value.update(accepted_native_packets=42),
                     lambda value: value.update(native_reorganizations=False),
                     lambda value: value.update(error=None),
                     lambda value: value.update(schema='pon-account-archive-native-observation-v1')]
        for change in mutations:
            altered = copy.deepcopy(native)
            change(altered)
            with self.subTest(change=change), self.assertRaises(ValueError):
                execution.validate_reports(altered, oracle, '1' * 64)

    def test_oracle_identity_counts_and_all_detailed_results_are_required(self):
        native, oracle = reports()
        for values in [{'result': 'FAIL'}, {'error': None}, {'native_json_sha256': '2' * 64},
                       {'genesis_checked': 1}, {'blocks_checked': True}, {'blocks_checked': 42},
                       {'transaction_envelopes_checked': 19}, {'reorganizations_checked': 1},
                       {'negative_observations_checked': 28}, {'sqlite_database_opened': True},
                       {'complete_archive_rows_from_observation_checked': 1},
                       {'reopen_observations_checked': 2}, {'block_observations': [{}] * 42},
                       {'reopen_observations': [{}] * 2}, {'negative_observations': []},
                       {'schema': 'pon-account-archive-oracle-observation-v1'}]:
            altered = copy.deepcopy(oracle)
            altered.update(values)
            with self.subTest(values=values), self.assertRaises(ValueError):
                execution.validate_reports(native, altered, '1' * 64)

    def test_scopes_reject_promotion_and_integer_boolean_aliases(self):
        native, oracle = reports()
        for section in ['scope', 'native_scope']:
            for key, value in oracle[section].items():
                for replacement in [not value, int(value)]:
                    altered = copy.deepcopy(oracle)
                    altered[section][key] = replacement
                    with self.subTest(section=section, key=key, value=replacement), self.assertRaises(ValueError):
                        execution.validate_reports(native, altered, '1' * 64)
        for key, value in native['scope'].items():
            altered = copy.deepcopy(native)
            altered['scope'][key] = int(value)
            with self.subTest(native_key=key), self.assertRaises(ValueError):
                execution.validate_reports(altered, oracle, '1' * 64)

    def test_export_inventory_rejects_extra_directories_and_symlinks(self):
        with tempfile.TemporaryDirectory(prefix='trnm-execution-export-controls-') as directory:
            root = Path(directory)
            for name in execution.EXPORT_FILES:
                (root / name).write_bytes(b'synthetic-file-map-only')
            self.assertEqual(set(execution.directory_sha256(root, exact=execution.EXPORT_FILES)), execution.EXPORT_FILES)
            (root / 'extra').mkdir()
            with self.assertRaises(ValueError):
                execution.directory_sha256(root, exact=execution.EXPORT_FILES)
            (root / 'extra').rmdir()
            (root / 'archive.sqlite-wal').symlink_to(root / 'missing-target')
            with self.assertRaises(ValueError):
                execution.directory_sha256(root, exact=execution.EXPORT_FILES)
            with self.assertRaises(ValueError):
                execution.directory_sha256(root)

    def test_snapshot_delivery_checks_actual_header_without_claiming_sql_rows(self):
        with tempfile.TemporaryDirectory(prefix='trnm-snapshot-header-controls-') as directory:
            database = Path(directory) / 'archive.sqlite'
            value = snapshot(database)
            result = execution.validate_snapshot_finalization(value, database,
                '/synthetic/native-working/archive.sqlite', str(database))
            self.assertEqual(result['export_file_bytes'], 4096)
            self.assertFalse(result['sqlite_rows_independently_checked'])
            self.assertFalse(result['native_snapshot_reexecuted'])

    def test_snapshot_busy_checkpoint_close_and_geometry_failures_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix='trnm-snapshot-refusal-controls-') as directory:
            database = Path(directory) / 'archive.sqlite'
            value = snapshot(database)
            mutations = [lambda row: row['source']['checkpoint'].update(busy=1),
                         lambda row: row['source']['checkpoint'].update(log_frames=1),
                         lambda row: row['source']['checkpoint'].update(checkpointed_frames=False),
                         lambda row: row['source'].update(close={'result': 'NOT_ATTEMPTED', 'error': None}),
                         lambda row: row['source'].update(path_matches=1),
                         lambda row: row['source'].update(checkpoint_error='BUSY'),
                         lambda row: row['export'].update(vacuum_into={'result': 'ERROR', 'error': 'failure'}),
                         lambda row: row['export'].update(close={'result': 'NOT_ATTEMPTED', 'error': None}),
                         lambda row: row['export'].update(page_count=True),
                         lambda row: row['export'].update(page_size=8192),
                         lambda row: row['export'].update(journal_mode='wal'),
                         lambda row: row.update(error=None)]
            for change in mutations:
                altered = copy.deepcopy(value)
                change(altered)
                with self.subTest(change=change), self.assertRaises(ValueError):
                    execution.validate_snapshot_finalization(altered, database,
                        '/synthetic/native-working/archive.sqlite', str(database))

    def test_snapshot_rejects_even_empty_physical_sidecars_and_wrong_headers(self):
        with tempfile.TemporaryDirectory(prefix='trnm-snapshot-sidecar-controls-') as directory:
            database = Path(directory) / 'archive.sqlite'
            value = snapshot(database)
            for suffix in ['-wal', '-shm', '-journal']:
                sidecar = Path(str(database) + suffix)
                sidecar.write_bytes(b'')
                with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                    execution.validate_snapshot_finalization(value, database,
                        '/synthetic/native-working/archive.sqlite', str(database))
                sidecar.unlink()
            changed = bytearray(database.read_bytes())
            changed[18:20] = b'\x02\x02'
            database.write_bytes(changed)
            with self.assertRaises(ValueError):
                execution.validate_snapshot_finalization(value, database,
                    '/synthetic/native-working/archive.sqlite', str(database))

    def finish_fixture(self, root):
        output = root / 'output'
        output.mkdir()
        (root / 'pin.txt').write_bytes(b'synthetic-source-pin')
        original = root / 'original-binary'
        original.write_bytes(b'synthetic-binary-identity-only')
        (output / 'account_execution_vectors').write_bytes(original.read_bytes())
        native = output / 'native'
        native.mkdir()
        for name in execution.EXPORT_FILES:
            (native / name).write_bytes(b'synthetic-final-retention-only')
        companion = output / 'state-witness'
        companion.mkdir()
        (companion / 'observation.json').write_bytes(b'synthetic-companion-retention-only')
        companion_hashes = execution.directory_sha256(companion, exact=execution.STATE_WITNESS_EXPORT_FILES)
        working = output / 'native-working'
        working.mkdir()
        (working / 'archive.sqlite').write_bytes(b'synthetic-working-original')
        source = {'source_state': 'synthetic-receipt-control-only'}
        exported = execution.directory_sha256(native, exact=execution.EXPORT_FILES)
        report = {'result': 'FAIL', 'source_before': source,
                  'input_sha256_before': {'pin.txt': execution.digest(root / 'pin.txt')},
                  'binary_path': str(original), 'binary_sha256_before': execution.digest(original),
                  'binary_sha256_after': execution.digest(original),
                  'native_files_sha256_before_oracle': exported,
                  'native_files_sha256_after_oracle': dict(exported),
                  'state_witness_files_sha256_before_oracle': companion_hashes,
                  'state_witness_files_sha256_after_oracle': dict(companion_hashes),
                  'working_files_sha256_before_oracle': execution.directory_sha256(working),
                  'working_files_sha256_after_oracle': execution.directory_sha256(working),
                  'checks_completed_before_retention': True}
        return output, report, source

    def finish(self, root, output, report, source):
        with patch.object(execution, 'ROOT', root), patch.object(execution, 'INPUTS', ['pin.txt']), \
                patch.object(execution, 'source', return_value=source), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            execution.finish_execution_receipt(output, report)
        return json.loads((output / 'manifest.json').read_text())

    def test_final_retention_does_not_claim_working_file_immutability(self):
        with tempfile.TemporaryDirectory(prefix='trnm-execution-finish-controls-') as directory:
            root = Path(directory)
            output, report, source = self.finish_fixture(root)
            (output / 'native-working/archive.sqlite').write_bytes(b'changed-working-observation')
            retained = self.finish(root, output, report, source)
            self.assertEqual(retained['result'], 'PASS')
            self.assertTrue(retained['working_files_changed_during_observation'])
            self.assertEqual(retained['native_files_sha256_at_finish'], report['native_files_sha256_before_oracle'])

    def test_late_export_or_binary_changes_cannot_keep_a_successful_result(self):
        for kind in ['extra-directory', 'late-sidecar', 'changed-export', 'binary', 'copied-binary', 'source',
                     'changed-companion', 'missing-companion', 'extra-companion']:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='trnm-execution-late-controls-') as directory:
                root = Path(directory)
                output, report, source = self.finish_fixture(root)
                if kind == 'extra-directory':
                    (output / 'native/extra').mkdir()
                elif kind == 'late-sidecar':
                    (output / 'native/archive.sqlite-wal').write_bytes(b'')
                elif kind == 'changed-export':
                    (output / 'native/observation.json').write_bytes(b'changed')
                elif kind == 'binary':
                    Path(report['binary_path']).write_bytes(b'changed-binary')
                elif kind == 'copied-binary':
                    (output / 'account_execution_vectors').write_bytes(b'changed-copy')
                elif kind == 'changed-companion':
                    (output / 'state-witness/observation.json').write_bytes(b'changed-companion')
                elif kind == 'missing-companion':
                    (output / 'state-witness/observation.json').unlink()
                elif kind == 'extra-companion':
                    (output / 'state-witness/extra').write_bytes(b'new')
                else:
                    (root / 'pin.txt').write_bytes(b'changed-source')
                retained = self.finish(root, output, report, source)
                self.assertEqual(retained['result'], 'FAIL')
                self.assertIn('final_retention_error', retained)

    def test_partial_or_hidden_failed_execution_never_completes_during_retention(self):
        for values in [{'error': None}, {'checks_completed_before_retention': False},
                       {'checks_completed_before_retention': 1}]:
            with self.subTest(values=values), tempfile.TemporaryDirectory(prefix='trnm-execution-incomplete-controls-') as directory:
                root = Path(directory)
                output, report, source = self.finish_fixture(root)
                report.update(values)
                self.assertEqual(self.finish(root, output, report, source)['result'], 'FAIL')


if __name__ == '__main__':
    unittest.main(verbosity=2)
