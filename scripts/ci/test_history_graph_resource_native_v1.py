#!/usr/bin/env python3
"""Finite reader and real local directory-race controls; never native efficacy."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

import history_graph_resource_guardian_v1 as guardian
import read_history_graph_resource_native_v1 as reader
from read_native_history_verifier import GRAPH_COUNTERS

BINARY = 'ab' * 32
BOOT = '12345678-1234-1234-1234-123456789abc'


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + '\n')


def graph(imports=0, failed=0, closed=0):
    counters = dict.fromkeys(GRAPH_COUNTERS, 0)
    counters.update(imports=imports, imports_failed=failed, imports_closed=closed,
                    native_cpu_checkpoints=11, graph_entries=1, graph_exits=1,
                    graph_aborts=1 if failed else 0, graph_node_checkpoints=9,
                    graph_completed_node_bodies=8, graph_full_resource_checks=4,
                    graph_max_node_window=8, before_commit_checks=1,
                    kernel_checks=4, kernel_cpu_known_calls=4, kernel_cpu_ns=100,
                    kernel_wall_ns=200, kernel_failed_checks=1)
    return {'schema': 'ordinary-history-graph-resource-observation-v1', 'profile': reader.PROFILE,
            'maximum_node_bodies_between_full_checks': 8, 'counters': counters,
            'strict_path_is_separate': True, 'observation_is_authority': False,
            'wall_clock_revocation_bound_claimed': False, 'live_known_close_pending': False,
            'cold_epoch_recovery_granted': False}


def receipt():
    return {'schema': 'service-owner-scoped-thread-cpu-settlement-v1', 'owner_cpu_ns': 12,
            'scoped_worker_cpu_ns': 3, 'total_cpu_ns': 15, 'live_paid_cpu_ns': 10,
            'residual_cpu_ns': 5, 'spawned_workers': 1, 'started_workers': 1,
            'finished_workers': 1, 'known_workers': 1, 'live_refused': False,
            'accounting_unavailable': False}


def cpu():
    return {'schema': 'public-v3-local-stored-cpu-budget-v1', 'stored_credit_ns': 199999985,
            'in_flight': 0, 'accounting_unavailable': False, 'burst_ns': 2000000000,
            'refill_ns_per_second': 250000000, 'start_reserve_ns': 100000000, 'worker_limit': 2}


def flow():
    return {'schema': 'public-v3-local-actual-cpu-flow-v1', 'initial_credit_ns': 200000000,
            'credited_refill_ns': 0, 'discarded_refill_ns': 0, 'booked_reservation_ns': 0,
            'live_debited_cpu_ns': 10, 'settlement_residual_cpu_ns': 5,
            'settled_full_cpu_ns': 15, 'unsettled_known_live_cpu_ns': 0,
            'paid_cpu_debit_ns': 15, 'settlement_discard_ns': 0,
            'remaining_paid_credit_ns': 199999985, 'balance_identity_verified': True,
            'stored_credit_ns': 199999985, 'live_owners': 0}


def markers():
    value = {'schema': 'ordinary-history-graph-resource-binding-v1', 'profile': reader.PROFILE,
             'maximum_node_bodies_between_full_checks': 8, 'policy_digest': reader.policy_digest(),
             'epoch_nonce': 'ac' * 32, 'cpu_epoch_key': 'ordinary-public-v3-epoch-v1',
             'cpu_epoch_value': b'active-v1'.hex(), 'new_cpu_credit_granted': False,
             'signed_v6_authority': False}
    return [['ordinary-history-graph-resource-policy-v1', json.dumps(value).encode().hex().upper()],
            ['ordinary-public-v3-epoch-v1', b'active-v1'.hex().upper()]]


def fixture(directory, spec):
    """Construct shape-only receipts; the test itself never grants runtime PASS."""
    directory.mkdir(mode=0o700)
    unit = 'trnm-graph-123-1-' + spec['case'] + '.service'
    group = '/trnmponpublic.slice/' + unit
    outer = '/system.slice/owned-outer.service'
    identity = {'pid': 100, 'tid': 101, 'uid': 1001, 'gid': 1001, 'thread_cgroup': '0::' + group}
    parent = {'path': reader.PARENT, 'device': 20, 'inode': 30, 'boot_id': BOOT, 'uid': 0, 'mode': 0o40755,
              'limits': dict(reader.LIMITS), 'cpu_file_mode': 0o644, 'pids_current': 0,
              'cpu_stat': 'usage_usec 100\nnr_periods 1\nnr_throttled 0\nthrottled_usec 0\n'}
    kernel_parent = {'schema': 'fixed-kernel-parent-identity-observation-v1',
                     'path': reader.PARENT, 'device': 20, 'inode': 30, 'boot_id': BOOT,
                     'cpu_quota_us': 25_000, 'cpu_period_us': 100_000, 'cpu_burst_us': 0,
                     'memory_bytes': 2_147_483_648, 'swap_bytes': 0, 'tasks': 256,
                     'observation_is_authority': False}
    documents = {
        'job.json': {**spec, 'schema': 'history-graph-resource-physical-job-v1', 'parent': reader.PARENT,
                     'profile': reader.PROFILE, 'binary_sha256': BINARY},
        'ready.json': {'case': spec['case'], 'identity': identity, 'binary_sha256': BINARY, 'parent': kernel_parent},
        'guardian.json': {'schema': 'history-graph-resource-physical-guardian-v1', 'case': spec['case'],
                          'action': spec['action'], 'profile': reader.PROFILE, 'binary_sha256': BINARY,
                          'passed': True, 'native_exit_code': 0, 'root_lease_verified': True,
                          'actual_child_unprivileged': True, 'pidfd_pinned': True,
                          'production_qualified': False, 'whole_history_p0_closed': False,
                          'case_budget_seconds': 60, 'elapsed_seconds': 1.5, 'native_cgroup': group,
                          'outer_cgroup': outer, 'unit': unit, 'original_identity': identity,
                          'actual_systemd_main_pid': 100, 'original_parent': copy.deepcopy(parent),
                          'final_parent': copy.deepcopy(parent), 'cleanup_parent': copy.deepcopy(parent)},
    }
    native = {'schema': 'history-graph-resource-physical-native-result-v1', 'case': spec['case'],
              'identity_after_refusal': copy.deepcopy(identity), 'triggered': spec['action'] != 'none'}
    trigger = spec['trigger']
    if spec['action'] == 'none':
        native.update(same_legal_packet_and_active_state=True, clean_both_epochs=True,
                      cold_reopen_both_equal=True, graph_resource=graph(1, 0, 1))
        native['graph_resource']['counters']['kernel_failed_checks'] = 0
    else:
        migrated = spec['action'] == 'migrate-process'
        if migrated:native['identity_after_refusal']['thread_cgroup'] = '0::' + outer
        error = ('PUBLIC_HOST_KERNEL_CONTEXT' if migrated else 'PUBLIC_HOST_KERNEL_UNAVAILABLE'
                 if spec['action'] == 'unreadable-cpu' else 'PUBLIC_HOST_KERNEL_LIMITS'
                 if spec['action'] in ('burst', 'swap') else 'PUBLIC_HOST_KERNEL_LIMITS_CHANGED')
        native.update(error=error, protocol_invalid=False, cpu_receipt=receipt(),
                      original_cpu=cpu(), original_cpu_flow=flow())
        point = {}
        if trigger in ('after-node', 'strict-after-node0', 'enter', 'final-relation', 'exit'):
            completed = 8 if trigger == 'after-node' else 1 if trigger == 'strict-after-node0' else 0 if trigger == 'enter' else 63
            native.update(completed_node_bodies=completed, fixture_account_count=32,
                          graph_resource=graph(), actual_graph_events=[], decode_before=[0, 0], decode_after=[0, 0])
            if trigger == 'after-node':point = {'after_typed_checkpoint_before_body': spec['offset']}
            if trigger == 'strict-after-node0':point = {'strict_original_callback': True, 'after_full_check_before_body': 0}
            if trigger != 'strict-after-node0':
                nodes = 9 if trigger == 'after-node' else 0 if trigger == 'enter' else 63
                events = ['Enter'] + [f'BeforeNode {{ ordinal: {i} }}' for i in range(nodes)]
                if trigger in ('final-relation', 'exit'):events.append('BeforeFinalRelation { completed: 63 }')
                success = 'true' if trigger == 'exit' else 'false'
                events.append(f'Exit {{ completed: {completed}, succeeded: {success} }}')
                native['actual_graph_events'] = events
            if trigger in ('enter', 'final-relation', 'exit'):
                value = 'Enter' if trigger == 'enter' else 'BeforeFinalRelation { completed: 63 }' if trigger == 'final-relation' else 'Exit { completed: 63, succeeded: true }'
                point = {'before_typed_full_boundary': value}
        elif trigger in ('admission-commit', 'activation-commit'):
            point = {'before_actual_native_commit': True, 'activation': trigger == 'activation-commit'}
            native.update(original_native_state_unchanged=True, original_markers_preserved=True,
                          known_abort_closed_after_actual_restore=True, next_original_strict_epoch_completed=True,
                          markers=markers(), graph_resource=graph())
        elif trigger == 'settlement':
            point = {'inside_epoch_close_transaction_before_commit': True}
            native.update(original_markers_preserved=True, cold_restart_did_not_clear_unsettled_markers=True,
                          markers=markers())
        else:
            point = {'before_actual_public_import_commit': True}
            native.pop('cpu_receipt')
            native.update(cpu_receipts=[receipt(), receipt()], markers=markers(),
                          premature_resume_error=error, cold_epoch_recovery_claimed=False,
                          final_height=2, actual_strict_tip='01' * 32, actual_next_tip='02' * 32,
                          credit_before_resume=cpu(), credit_after_resume=cpu(),
                          flow_before_resume=flow(), flow_after_resume=flow(),
                          graph_resource=graph(1, 1, 0), graph_resource_after_resume=graph(1, 1, 1),
                          final_graph_resource=graph(2, 1, 2))
            native['graph_resource']['live_known_close_pending'] = True
            for field in ('actual_public_entry_returned_error_before_restore', 'original_native_state_unchanged',
                          'actual_premature_public_resume_refused_without_poison', 'original_markers_preserved',
                          'same_live_domain_preserved', 'known_abort_closed_after_actual_restore',
                          'repeated_resume_refused', 'next_original_strict_import_completed',
                          'next_explicit_v1_import_completed', 'clean_cold_readback_after_real_next_imports'):
                native[field] = True
        documents['mutation-request.json'] = {'schema': 'history-graph-resource-physical-request-v1',
            'case': spec['case'], 'action': spec['action'], 'identity': identity, 'point': point,
            'binary_sha256': BINARY}
        before = copy.deepcopy(parent);before['pids_current'] = 2
        after = copy.deepcopy(before)
        if spec['action'] in guardian.MUTATIONS:
            name, value = guardian.MUTATIONS[spec['action']];after['limits'][name] = value
        if spec['action'] == 'unreadable-cpu':after['cpu_file_mode'] = 0
        documents['mutation-applied.json'] = {'case': spec['case'], 'action': spec['action'],
            'identity': identity, 'actual_mutation_applied': True, 'pidfd_pinned': True,
            'before': before, 'after': after, 'membership_before': group,
            'membership_after': outer if migrated else group, 'process_wide_migration': migrated}
        documents['mutation-restored.json'] = {'case': spec['case'], 'actual_restored': True,
            'pidfd_pinned': True, 'parent': before, 'membership': group}
        documents['guardian.json']['mutation'] = documents['mutation-applied.json']
        documents['guardian.json']['restoration'] = documents['mutation-restored.json']
        documents['native-result-before-restore.json'] = {
            key: copy.deepcopy(native[key]) for key in ('schema', 'case', 'error', 'protocol_invalid',
                                                       'triggered', 'original_cpu', 'original_cpu_flow')}
    documents['complete.json'] = {'schema': 'history-graph-resource-physical-completion-v1',
        'case': spec['case'], 'passed': True, 'binary_sha256': BINARY,
        'parent_restored_and_rechecked': True, 'final_identity': identity, 'result': native}
    for name, value in documents.items():write(directory / name, value)
    (directory / 'native.log').write_text('running 1 test\n' + 'test ' + reader.HELPER + ' ... ok\n'
        'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 797 filtered out; finished in 0.01s\n')
    return documents


class PhysicalReader(unittest.TestCase):
    def test_actual_native_identity_shape_requires_exact_limits_and_no_invented_sample_fields(self):
        # Exact ready.parent shape retained from source1252076's cpu-window-0
        # job123174765428. This reader regression never reclassifies that failed
        # whole lane, whose guardian did not retain uid/mode and must run again.
        actual = {"boot_id": "b21288b9-f29d-43ee-8296-36b8fc329c27",
                  "cpu_burst_us": 0, "cpu_period_us": 100000, "cpu_quota_us": 25000,
                  "device": 31, "inode": 6818, "memory_bytes": 2147483648,
                  "observation_is_authority": False, "path": reader.PARENT,
                  "schema": "fixed-kernel-parent-identity-observation-v1",
                  "swap_bytes": 0, "tasks": 256}
        self.assertEqual(reader.native_parent_identity(actual),
                         (reader.PARENT, 31, 6818, actual['boot_id']))
        for key in actual:
            changed = dict(actual);del changed[key]
            with self.subTest(missing=key), self.assertRaises((ValueError, KeyError, TypeError)):
                reader.native_parent_identity(changed)
        for key, value in [('cpu_quota_us', 20000), ('cpu_period_us', 200000),
                           ('cpu_burst_us', 1), ('memory_bytes', 2147483649), ('swap_bytes', 1),
                           ('tasks', 257), ('observation_is_authority', True), ('device', True),
                           ('uid', 0), ('cpu.stat', {})]:
            with self.subTest(replacement=key), self.assertRaises((ValueError, KeyError, TypeError)):
                reader.native_parent_identity({**actual, key: value})

    def test_missing_guardian_ownership_and_changed_native_identity_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as tmp:
            for number, (filename, parent_key, field, replacement) in enumerate([
                ('guardian.json', 'original_parent', 'uid', None),
                ('guardian.json', 'final_parent', 'mode', None),
                ('guardian.json', 'cleanup_parent', 'uid', True),
                ('ready.json', 'parent', 'inode', 31),
                ('ready.json', 'parent', 'cpu_quota_us', 20000),
                ('guardian.json', 'original_parent', 'mode', 0o40757),
            ]):
                directory = Path(tmp) / str(number);documents = fixture(directory, reader.CASES[0])
                if replacement is None:del documents[filename][parent_key][field]
                else:documents[filename][parent_key][field] = replacement
                write(directory / filename, documents[filename])
                with self.subTest(filename=filename, field=field), self.assertRaises((ValueError, KeyError, TypeError)):
                    reader.validate_case(directory, reader.CASES[0], BINARY)

    def test_all_twenty_three_explicit_schema_cases(self):
        self.assertEqual(len(reader.CASES), 23)
        self.assertEqual(len(set(row['case'] for row in reader.CASES)), 23)
        expected_errors = {'cpu': 'PUBLIC_HOST_KERNEL_LIMITS_CHANGED',
                           'memory': 'PUBLIC_HOST_KERNEL_LIMITS_CHANGED',
                           'pids': 'PUBLIC_HOST_KERNEL_LIMITS_CHANGED',
                           'burst': 'PUBLIC_HOST_KERNEL_LIMITS', 'swap': 'PUBLIC_HOST_KERNEL_LIMITS',
                           'unreadable-cpu': 'PUBLIC_HOST_KERNEL_UNAVAILABLE',
                           'migrate-process': 'PUBLIC_HOST_KERNEL_CONTEXT'}
        with tempfile.TemporaryDirectory() as tmp:
            for spec in reader.CASES:
                with self.subTest(case=spec['case']):
                    directory = Path(tmp) / spec['case'];documents = fixture(directory, spec)
                    self.assertTrue(reader.validate_case(directory, spec, BINARY)['passed'])
                    if spec['action'] == 'none':
                        continue
                    expected = expected_errors[spec['action']]
                    self.assertEqual(documents['complete.json']['result']['error'], expected)
                    # Update both retained observations coherently. A reader
                    # must still refuse a wrong runtime category, even when
                    # the pre-restoration and completed reports agree.
                    for substituted in sorted(set(expected_errors.values()) - {expected}):
                        documents['complete.json']['result']['error'] = substituted
                        documents['native-result-before-restore.json']['error'] = substituted
                        for name in ('complete.json', 'native-result-before-restore.json'):
                            write(directory / name, documents[name])
                        with self.subTest(substituted=substituted), self.assertRaises(ValueError):
                            reader.validate_case(directory, spec, BINARY)

    def test_semantic_substitutions_after_reencoding_are_rejected(self):
        changes = [
            ('guardian.json', ('root_lease_verified',), False), ('guardian.json', ('pidfd_pinned',), False),
            ('guardian.json', ('native_exit_code',), 1), ('guardian.json', ('elapsed_seconds',), 60.1),
            ('guardian.json', ('case_budget_seconds',), 61), ('guardian.json', ('production_qualified',), True),
            ('guardian.json', ('original_identity', 'uid'), 0), ('guardian.json', ('actual_systemd_main_pid',), 999),
            ('guardian.json', ('final_parent', 'pids_current'), 1), ('guardian.json', ('cleanup_parent', 'inode'), 99),
            ('guardian.json', ('original_parent', 'uid'), 1001),
            ('guardian.json', ('final_parent', 'mode'), 0o40777),
            ('guardian.json', ('cleanup_parent', 'mode'), 0o100644),
            ('ready.json', ('binary_sha256',), 'cd' * 32), ('ready.json', ('parent', 'memory_bytes'), 2_147_483_649),
            ('ready.json', ('parent', 'cpu_quota_us'), 25_001),
            ('ready.json', ('parent', 'cpu_burst_us'), True),
            ('ready.json', ('parent', 'observation_is_authority'), True),
            ('complete.json', ('parent_restored_and_rechecked',), False),
            ('complete.json', ('result', 'protocol_invalid'), True),
            ('complete.json', ('result', 'completed_node_bodies'), 9),
            ('complete.json', ('result', 'actual_graph_events'), []),
            ('complete.json', ('result', 'graph_resource', 'maximum_node_bodies_between_full_checks'), 9),
            ('complete.json', ('result', 'graph_resource', 'counters', 'kernel_cpu_unknown_calls'), 1),
            ('complete.json', ('result', 'graph_resource', 'counters', 'kernel_failed_checks'), 0),
            ('complete.json', ('result', 'cpu_receipt', 'total_cpu_ns'), 16),
            ('complete.json', ('result', 'cpu_receipt', 'finished_workers'), 0),
            ('complete.json', ('result', 'original_cpu', 'in_flight'), 1),
            ('complete.json', ('result', 'original_cpu', 'refill_ns_per_second'), 500000000),
            ('complete.json', ('result', 'original_cpu_flow', 'paid_cpu_debit_ns'), 0),
            ('mutation-applied.json', ('actual_mutation_applied',), False),
            ('mutation-restored.json', ('actual_restored',), False),
            ('mutation-request.json', ('point', 'after_typed_checkpoint_before_body'), 7),
            ('job.json', ('profile',), 'silent-fallback'),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for number, (name, keys, value) in enumerate(changes):
                with self.subTest(change=(name, keys)):
                    directory = Path(tmp) / str(number);documents = fixture(directory, reader.CASES[0])
                    row = documents[name]
                    for key in keys[:-1]:row = row[key]
                    row[keys[-1]] = value
                    write(directory / name, documents[name])
                    with self.assertRaises((ValueError, KeyError, TypeError)):
                        reader.validate_case(directory, reader.CASES[0], BINARY)

    def test_roster_and_native_terminal_cannot_be_omitted_or_forged(self):
        text = '\n'.join('test ' + name + ' ... ok' for name in reader.PURE_ROSTER)
        text += '\ntest ' + reader.HELPER + ' ... ignored, actual parent required\n'
        text += 'test result: ok. 17 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.68s\n'
        reader.test_terminal(text, reader.PURE_ROSTER, [reader.HELPER])
        for altered in (text.replace(reader.PURE_ROSTER[0], 'substituted'), text.replace('17 passed', '16 passed'),
                        text + text, text.replace(' ... ok', ' ... FAILED', 1)):
            with self.assertRaises(ValueError):reader.test_terminal(altered, reader.PURE_ROSTER, [reader.HELPER])

    def test_real_directory_replacement_does_not_redirect_privileged_io(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);case = root / 'case';case.mkdir(mode=0o700)
            foreign = root / 'foreign';foreign.mkdir(mode=0o700)
            write(case / 'request.json', {'original': True});write(foreign / 'request.json', {'foreign': True})
            with guardian.PinnedCase(case, os.getuid()) as pin:
                moved = root / 'moved';case.rename(moved);case.symlink_to(foreign, target_is_directory=True)
                self.assertEqual(pin.read('request.json'), {'original': True})
                pin.put('guardian.json', {'original': True}, os.getuid(), os.getgid())
                with pin.log(os.getgid()) as log:log.write(b'original bytes')
                self.assertFalse((foreign / 'guardian.json').exists())
                self.assertFalse((foreign / 'native.log').exists())
                self.assertEqual(json.loads((moved / 'guardian.json').read_text()), {'original': True})

    def test_real_ancestor_symlink_and_existing_receipts_are_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);case = root / 'case';case.mkdir(mode=0o700)
            link = root / 'link';link.symlink_to(case, target_is_directory=True)
            with self.assertRaises(OSError):guardian.PinnedCase(link, os.getuid())
            with guardian.PinnedCase(case, os.getuid()) as pin:
                write(case / 'guardian.json', {'existing': True})
                with self.assertRaises(FileExistsError):pin.put('guardian.json', {'replace': True}, os.getuid(), os.getgid())
                self.assertEqual(json.loads((case / 'guardian.json').read_text()), {'existing': True})
                (case / 'request.json').symlink_to(case / 'guardian.json')
                with self.assertRaises(OSError):pin.read('request.json')

    def test_real_handshake_refuses_nonregular_ambiguous_and_nonfinite_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = Path(tmp) / 'case';case.mkdir(mode=0o700)
            with guardian.PinnedCase(case, os.getuid()) as pin:
                for text in ('{"a":1,"a":2}', '{"a":NaN}', 'x' * 65537):
                    (case / 'request.json').write_text(text)
                    with self.assertRaises(ValueError):pin.read('request.json')
                (case / 'request.json').unlink();os.mkfifo(case / 'request.json')
                with self.assertRaises(ValueError):pin.read('request.json')


if __name__ == '__main__':
    unittest.main(verbosity=2)
