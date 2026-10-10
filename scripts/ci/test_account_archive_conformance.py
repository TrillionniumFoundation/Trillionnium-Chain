#!/usr/bin/env python3
"""Synthetic archive receipt contracts, never native execution evidence."""
import copy
import unittest

from run_account_archive_conformance import (EXPORT_FILES, NATIVE_SCOPE, ORACLE_SCOPE,
                                            validate_export_retention, validate_reports)


def parser_fixture():
    return (
        {'schema': 'pon-account-archive-native-observation-v1', 'reopened': True,
         'archive_used_for_native_execution': False, 'protocol_capacity_changed': False,
         'public_data_availability_accepted': False, 'snapshots': [{} for _ in range(6)],
         'operations': [{} for _ in range(17)]},
        {'schema': 'pon-account-archive-oracle-observation-v1', 'result': 'PASS',
         'native_json_sha256': '1' * 64, 'database_sha256': '2' * 64,
         'scope': dict(ORACLE_SCOPE), 'native_scope': dict(NATIVE_SCOPE),
         'snapshots_checked': 6, 'witness_checks': 13, 'witness_observations': [{} for _ in range(13)],
         'operation_observations_checked': 17, 'operation_observations': [{} for _ in range(17)],
         'database': {'all_node_records_checked': True}},
    )


class ArchiveReceiptContractTests(unittest.TestCase):
    def test_complete_identity_and_bounded_scope_are_required(self):
        native, oracle = parser_fixture()
        checked = validate_reports(native, oracle, '1' * 64, '2' * 64)
        self.assertEqual(checked['witness_checks'], 13)
        self.assertFalse(checked['scope']['large_account_space_verified'])
        self.assertFalse(checked['scope']['source_transition_authorized'])

    def test_partial_native_sets_or_missing_actual_reopen_cannot_be_success(self):
        native, oracle = parser_fixture()
        for change in [lambda data: data['snapshots'].pop(), lambda data: data['operations'].pop(),
                       lambda data: data.update(reopened=False), lambda data: data.update(reopened=1),
                       lambda data: data.update(protocol_capacity_changed=True),
                       lambda data: data.update(schema='pon-account-archive-large-observation-v1')]:
            changed = copy.deepcopy(native)
            change(changed)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_reports(changed, oracle, '1' * 64, '2' * 64)

    def test_oracle_failure_or_other_json_database_cannot_complete_native_run(self):
        native, oracle = parser_fixture()
        for fields in [{'result': 'FAIL'}, {'error': None}, {'native_json_sha256': '3' * 64},
                       {'database_sha256': '3' * 64}, {'snapshots_checked': True},
                       {'witness_checks': 12}, {'witness_checks': [{} for _ in range(13)]},
                       {'operation_observations_checked': 16},
                       {'witness_observations': [{} for _ in range(12)]},
                       {'operation_observations': [{} for _ in range(16)]},
                       {'database': {'all_node_records_checked': False}}]:
            changed = copy.deepcopy(oracle)
            changed.update(fields)
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                validate_reports(native, changed, '1' * 64, '2' * 64)

    def test_small_fixture_cannot_be_promoted_or_use_boolean_aliases(self):
        native, oracle = parser_fixture()
        for key, value in [('large_account_space_verified', True), ('production_activation', True),
                           ('source_transition_authorized', True), ('native_recovery_reexecuted', True),
                           ('independent_root_and_proof_arithmetic', 1), ('production_activation', 0)]:
            changed = copy.deepcopy(oracle)
            changed['scope'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate_reports(native, changed, '1' * 64, '2' * 64)

    def test_native_scope_cannot_disguise_capacity_or_availability_acceptance(self):
        native, oracle = parser_fixture()
        for key in NATIVE_SCOPE:
            for value in [True, 0]:
                changed = copy.deepcopy(oracle)
                changed['native_scope'][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    validate_reports(native, changed, '1' * 64, '2' * 64)

    def test_final_export_rejects_late_sidecars_missing_bytes_or_changed_hashes(self):
        initial = {name: str(index) * 64 for index, name in enumerate(sorted(EXPORT_FILES), 1)}
        artifacts = {'native/' + name: value for name, value in initial.items()}
        self.assertEqual(validate_export_retention(initial, artifacts), (initial, {}))
        changes = [lambda value: value.update({'native/archive.sqlite-wal': '9' * 64}),
                   lambda value: value.pop('native/finalization.json'),
                   lambda value: value.update({'native/archive.sqlite': '9' * 64})]
        for change in changes:
            altered = dict(artifacts)
            change(altered)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_export_retention(initial, altered)

    def test_working_database_changes_are_retained_separately_from_export_identity(self):
        initial = {name: '1' * 64 for name in EXPORT_FILES}
        artifacts = {'native/' + name: value for name, value in initial.items()}
        for working in [{'archive.sqlite': '2' * 64},
                        {'archive.sqlite': '3' * 64, 'archive.sqlite-wal': '4' * 64}]:
            combined = {**artifacts, **{'native-working/' + name: value for name, value in working.items()}}
            exported, observed_working = validate_export_retention(initial, combined)
            self.assertEqual(exported, initial)
            self.assertEqual(observed_working, working)

    def test_initial_export_cannot_define_a_sidecar_as_an_accepted_input(self):
        initial = {name: '1' * 64 for name in [*EXPORT_FILES, 'archive.sqlite-wal']}
        with self.assertRaises(ValueError):
            validate_export_retention(initial, {'native/' + name: value for name, value in initial.items()})


if __name__ == '__main__':
    unittest.main(verbosity=2)
