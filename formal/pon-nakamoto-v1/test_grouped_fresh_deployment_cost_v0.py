"""Accounting counterexamples; synthetic rows are not measured resource evidence."""
from __future__ import annotations

import copy
import json
import socket
import struct
import tempfile
import unittest
import os
import subprocess
import sys
from pathlib import Path

from grouped_fresh_deployment_cost_v0 import (
    CASES, LOCAL_CAP, demand_bridge_audit, topology_accounting,
)
from contract_wire import canonical
from experiments.grouped_fresh_fanout_v0 import (
    campaign_plan, close_native_with_cleanup, process_identity, read_json, receive_into, save_json,
)


def synthetic_worker(index=0):
    records = []
    for ordinal, case in enumerate(CASES):
        row = {'case': case, 'ordinal': ordinal, 'status': 'observed',
               'received_frame_bytes': 21 if case == 'truncated_cancel' else 100,
               'ack_kernel_accepted_bytes': 30, 'complete_verifier_called': case != 'truncated_cancel',
               'client': {'status': 'response_observed', 'received_bytes': 30}}
        if case in ('valid', 'carrier_replay', 'discarded_response', 'forged_endpoint'):
            value = {'status': 'verified', 'work_id': 'second' if case == 'discarded_response' else 'first',
                     'stages': {'independent_full_cell': {'wall_ns': 1}}, 'reference_macs': 37008}
            if case == 'forged_endpoint':
                value.update(status='rejected', error='NATIVE_Seal(Endpoint)')
            row['verification'] = value
        if case == 'truncated_cancel':
            row['transport_error'] = 'TCP_TRUNCATED_FRAME'
        if case == 'discarded_response':
            row['client'] = {'status': 'response_intentionally_discarded', 'received_bytes': 0}
        if case == 'after_local_cap':
            row['verification'] = {'status': 'rejected', 'error': 'NATIVE_VerificationBudget', 'stages': {}}
        records.append(row)
    return {'receiver_id': f'receiver-{index}',
            'wait4': {'user_seconds': 2.0, 'system_seconds': 1.0, 'exit_code': 0},
            'worker_report': {
                'status': 'PASS', 'source_bytes_stable': True, 'runner_bytes_stable': True,
                'chainwork_awarded': 0, 'external_demand_authenticated': False,
                'material_content_id': 'same-material', 'transport_records': records,
                'native_exit': {'exit_code': 0, 'native_child_user_seconds': .25, 'native_child_system_seconds': .25},
                'final_ledger': {'verification_budget': {'fixed_limit': LOCAL_CAP, 'reserved': LOCAL_CAP, 'remaining': 0}},
            }}


class FanoutAccountingTests(unittest.TestCase):
    def test_plan_preserves_denominators_and_no_stop_on_hit(self):
        plan = campaign_plan()
        self.assertEqual(plan['topology_sizes'], [1, 2, 4])
        self.assertEqual(plan['expected_receivers'], 7)
        self.assertEqual(plan['expected_transport_attempts'], 42)
        self.assertTrue(plan['no_stop_on_hit'])
        self.assertEqual(plan['receiver_cases'], list(CASES))

    def test_receiver_multiplicity_does_not_create_new_tickets_or_demand(self):
        observed = topology_accounting(4, [synthetic_worker(i) for i in range(4)])
        self.assertEqual(observed['status'], 'PASS')
        self.assertEqual(observed['observed_local_reservations'], 1024)
        self.assertEqual(observed['verified_receptions'], 12)
        self.assertEqual(observed['distinct_verified_work_ids'], 2)
        self.assertEqual(observed['distinct_material_content_ids'], 1)
        self.assertEqual(observed['independent_full_cell_calls'], 16)
        self.assertEqual(observed['independent_full_cell_macs'], 16 * 37008)
        self.assertEqual(observed['actual_consumer_uses_observed'], 0)
        self.assertFalse(observed['external_demand_authenticated'])
        self.assertFalse(observed['global_verification_cap_enforced'])

    def test_wait4_and_native_subset_are_not_added_twice(self):
        observed = topology_accounting(2, [synthetic_worker(i) for i in range(2)])
        self.assertEqual(observed['receiver_wait4_cpu_seconds'], 6.0)
        self.assertEqual(observed['native_cpu_seconds_subset'], 1.0)
        self.assertTrue(observed['native_cpu_is_subset_not_additional'])

    def test_lost_worker_stays_in_denominator_with_unknown_cpu(self):
        missing = {'receiver_id': 'receiver-1', 'worker_report': None}
        observed = topology_accounting(2, [synthetic_worker(), missing])
        self.assertEqual(observed['status'], 'FAIL')
        self.assertEqual(observed['planned_transport_attempts'], 12)
        self.assertEqual(observed['completed_transport_attempts'], 6)
        self.assertIsNone(observed['receiver_wait4_cpu_seconds'])
        self.assertEqual(observed['observed_wait4_cpu_seconds_partial'], 3.0)

    def test_omitting_failed_receiver_refuses_denominator(self):
        observed = topology_accounting(2, [synthetic_worker()])
        self.assertIn('RECEIVER_DENOMINATOR', observed['issues'])
        self.assertEqual(observed['planned_transport_attempts'], 12)

    def test_repeating_one_journal_identity_cannot_masquerade_as_two_receivers(self):
        observed = topology_accounting(2, [synthetic_worker(), synthetic_worker()])
        self.assertEqual(observed['status'], 'FAIL')
        self.assertTrue(any('DUPLICATE_OR_MISSING_ID' in v for v in observed['issues']))

    def test_cap_failure_after_full_cell_is_detected(self):
        value = synthetic_worker()
        row = value['worker_report']['transport_records'][-1]
        row['verification'].update(stages={'independent_full_cell': {}}, reference_macs=37008)
        observed = topology_accounting(1, [value])
        self.assertTrue(any('CAP_REJECTED_AFTER_CELL' in v for v in observed['issues']))

    def test_forged_endpoint_cannot_be_relabelled_success(self):
        value = synthetic_worker()
        value['worker_report']['transport_records'][2]['verification']['status'] = 'verified'
        observed = topology_accounting(1, [value])
        self.assertTrue(any('FORGED_ENDPOINT' in v for v in observed['issues']))

    def test_discarded_ack_kernel_send_is_not_peer_consumption(self):
        value = synthetic_worker()
        observed = topology_accounting(1, [value])
        self.assertEqual(observed['tcp_ack_kernel_accepted_bytes_not_proof_of_peer_read'], 180)
        self.assertEqual(observed['tcp_application_received_by_clients_bytes'], 150)
        value['worker_report']['transport_records'][4]['client']['received_bytes'] = 30
        changed = topology_accounting(1, [value])
        self.assertTrue(any('DISCARD_CONTROL' in v for v in changed['issues']))

    def test_source_change_and_demand_promotion_refuse(self):
        value = synthetic_worker()
        value['worker_report'].update(source_bytes_stable=False, external_demand_authenticated=True)
        observed = topology_accounting(1, [value])
        self.assertTrue(any('SOURCE_OR_RUNNER_CHANGED' in v for v in observed['issues']))
        self.assertTrue(any('QUALIFICATION_OVERCLAIM' in v for v in observed['issues']))

    def test_missing_native_exit_never_becomes_zero_cpu(self):
        value = synthetic_worker()
        value['worker_report']['native_exit'] = None
        observed = topology_accounting(1, [value])
        self.assertIsNone(observed['receiver_wait4_cpu_seconds'])
        self.assertTrue(any('NATIVE_CPU_OR_EXIT_UNKNOWN' in v for v in observed['issues']))

    def test_unstarted_cancellation_is_not_a_pass(self):
        value = synthetic_worker()
        value['worker_report']['transport_records'][3] = {'case': 'truncated_cancel', 'status': 'not_started'}
        observed = topology_accounting(1, [value])
        self.assertEqual(observed['completed_transport_attempts'], 5)
        self.assertEqual(observed['status'], 'FAIL')

    def test_empty_source_catalog_never_authenticates_demand_or_payment(self):
        with tempfile.TemporaryDirectory() as directory:
            observed = demand_bridge_audit(Path(directory))
        self.assertTrue(all(v['source_status'] == 'unavailable' for v in observed['components']))
        self.assertFalse(observed['external_demand_authenticated'])
        self.assertFalse(observed['native_payment_for_grouped_output_observed'])
        self.assertEqual(observed['actual_consumer_uses_observed'], 0)

    def test_transport_cancellation_preserves_exact_partial_frame(self):
        left, right = socket.socketpair()
        try:
            frame = struct.pack('!I', 1000) + b'x' * 17
            left.sendall(frame)
            left.shutdown(socket.SHUT_WR)
            captured = bytearray()
            prefix = receive_into(right, 4, captured)
            self.assertEqual(struct.unpack('!I', prefix)[0], 1000)
            with self.assertRaisesRegex(ValueError, 'TCP_TRUNCATED_FRAME'):
                receive_into(right, 1000, captured)
            self.assertEqual(bytes(captured), frame)
        finally:
            left.close()
            right.close()

    def test_cpu_observations_allow_finite_seconds_without_changing_protocol_encoding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cpu.json'
            save_json(path, {'cpu_seconds': 0.375407})
            self.assertEqual(read_json(path), {'cpu_seconds': 0.375407})
            with self.assertRaises(ValueError):
                save_json(Path(directory) / 'invalid.json', {'cpu_seconds': float('nan')})
            self.assertFalse((Path(directory) / 'invalid.json').exists())
        with self.assertRaises(ValueError):
            canonical({'cpu_seconds': 0.375407})

    @unittest.skipUnless(Path('/proc/self/stat').is_file(), 'Linux procfs required by this campaign')
    def test_process_identity_resolves_the_observed_pid_namespace(self):
        value = process_identity(os.getpid())
        self.assertEqual(value['pid'], os.getpid())
        self.assertEqual(value['parent_pid'], os.getppid())
        self.assertGreater(value['start_ticks'], 0)
        self.assertGreater(value['procfs_pid'], 0)

    @unittest.skipUnless(Path('/proc/self/stat').is_file(), 'Linux procfs required by this campaign')
    def test_child_identity_resolves_without_assuming_procfs_mount_namespace(self):
        child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.read(1)'], stdin=subprocess.PIPE)
        try:
            value = process_identity(child.pid)
            self.assertEqual(value['pid'], child.pid)
            self.assertEqual(value['parent_pid'], os.getpid())
        finally:
            child.communicate(b'x', timeout=5)

    def test_native_log_failure_still_terminates_and_reaps_owned_child(self):
        child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.read()'],
                                 stdin=subprocess.PIPE, start_new_session=True)
        class FailedLogSession:
            def __init__(self, process):
                self.child = process
            def close(self):
                raise OSError('controlled log write failure')
        try:
            with self.assertRaisesRegex(OSError, 'controlled log write failure'):
                close_native_with_cleanup(FailedLogSession(child))
            self.assertIsNotNone(child.returncode)
        finally:
            child.stdin.close()


class FanoutEvidenceIntegrityTests(unittest.TestCase):
    """Mutated reports cannot erase paid work or turn unknown observations into zero."""

    def refused(self, workers, planned=1):
        observed = topology_accounting(planned, workers)
        self.assertEqual(observed['status'], 'FAIL')
        self.assertTrue(observed['issues'])
        self.assertEqual(observed['planned_transport_attempts'], planned * len(CASES))
        self.assertEqual(observed['chainwork_awarded'], 0)
        self.assertFalse(observed['external_demand_authenticated'])
        self.assertFalse(observed['global_verification_cap_enforced'])
        self.assertFalse(observed['production_activation'])
        # Overflow/NaN may not escape through either full or partial aggregates.
        json.dumps(observed, allow_nan=False)
        return observed

    @staticmethod
    def set_path(value, path, replacement):
        for key in path[:-1]:
            value = value[key]
        value[path[-1]] = replacement

    def test_legacy_valid_fixture_preserves_schema_and_totals(self):
        observed = topology_accounting(1, [synthetic_worker()])
        self.assertEqual(observed['status'], 'PASS')
        self.assertEqual(observed['schema'], 'pon-grouped-fresh-deployment-cost-v0')
        self.assertEqual(observed['distinct_verified_work_ids'], 2)
        self.assertEqual(observed['independent_full_cell_calls'], 4)
        self.assertEqual(observed['independent_full_cell_macs'], 4 * 37008)
        self.assertEqual(observed['receiver_wait4_cpu_seconds'], 3.0)
        self.assertEqual(observed['native_cpu_seconds_subset'], 0.5)
        self.assertEqual(observed['tcp_application_received_by_receivers_bytes'], 521)
        self.assertEqual(observed['tcp_application_received_by_clients_bytes'], 150)
        self.assertEqual(observed['tcp_ack_kernel_accepted_bytes_not_proof_of_peer_read'], 180)
        json.dumps(observed, allow_nan=False)

    def test_verified_receipts_require_observed_work_identities(self):
        for replacement in (None, '', ' ', [], {}, False, 0):
            with self.subTest(identity=replacement):
                value = synthetic_worker()
                for row in value['worker_report']['transport_records']:
                    if row['case'] in ('valid', 'carrier_replay', 'discarded_response'):
                        row['verification']['work_id'] = replacement
                observed = self.refused([value])
                self.assertEqual(observed['verified_receptions'], 3)
                self.assertIsNone(observed['distinct_verified_work_ids'])
                self.assertEqual(observed['observed_distinct_verified_work_ids_partial'], 0)
                self.assertEqual(observed['receiver_wait4_cpu_seconds'], 3.0)
                self.assertTrue(any('WORK_ID_UNKNOWN' in issue for issue in observed['issues']))

    def test_one_missing_identity_retains_other_distinct_work(self):
        value = synthetic_worker()
        del value['worker_report']['transport_records'][4]['verification']['work_id']
        observed = self.refused([value])
        self.assertIsNone(observed['distinct_verified_work_ids'])
        self.assertEqual(observed['observed_distinct_verified_work_ids_partial'], 1)
        self.assertEqual(observed['completed_transport_attempts'], 6)

    def test_material_identity_is_not_a_missing_or_unhashable_label(self):
        for replacement in (None, '', [], {}, False):
            with self.subTest(identity=replacement):
                value = synthetic_worker()
                value['worker_report']['material_content_id'] = replacement
                observed = self.refused([value])
                self.assertIsNone(observed['distinct_material_content_ids'])
                self.assertEqual(observed['observed_distinct_material_content_ids_partial'], 0)

    def test_missing_transport_counters_never_become_zero_totals(self):
        value = synthetic_worker()
        for row in value['worker_report']['transport_records']:
            del row['received_frame_bytes']
            del row['ack_kernel_accepted_bytes']
            if row['case'] != 'discarded_response':
                del row['client']['received_bytes']
        observed = self.refused([value])
        self.assertIsNone(observed['tcp_application_received_by_receivers_bytes'])
        self.assertIsNone(observed['tcp_application_received_by_clients_bytes'])
        self.assertIsNone(observed['tcp_ack_kernel_accepted_bytes_not_proof_of_peer_read'])
        self.assertEqual(observed['observed_transport_bytes_partial'],
                         {'receiver': 0, 'client': 0, 'ack_kernel': 0})
        self.assertEqual(observed['transport_byte_observation_counts'],
                         {'receiver': 0, 'client': 1, 'ack_kernel': 0})

    def test_bad_transport_counters_preserve_other_observed_costs(self):
        fields = (
            (('received_frame_bytes',), 'receiver',
             'tcp_application_received_by_receivers_bytes', 421),
            (('ack_kernel_accepted_bytes',), 'ack_kernel',
             'tcp_ack_kernel_accepted_bytes_not_proof_of_peer_read', 150),
            (('client', 'received_bytes'), 'client',
             'tcp_application_received_by_clients_bytes', 120),
        )
        for path, kind, total, partial in fields:
            for replacement in (-1, True, False, 1.0, '1', None, [], 1 << 64):
                with self.subTest(field=path, value=replacement):
                    value = synthetic_worker()
                    self.set_path(value['worker_report']['transport_records'][0], path, replacement)
                    observed = self.refused([value])
                    self.assertIsNone(observed[total])
                    self.assertEqual(observed['observed_transport_bytes_partial'][kind], partial)
                    self.assertEqual(observed['transport_byte_observation_counts'][kind], 5)
                    self.assertEqual(observed['completed_transport_attempts'], 6)

    def test_finite_cpu_fields_cannot_overflow_per_receiver_sum(self):
        value = synthetic_worker()
        value['wait4'].update(user_seconds=1e308, system_seconds=1e308)
        observed = self.refused([value])
        self.assertIsNone(observed['receiver_wait4_cpu_seconds'])
        self.assertIsNone(observed['observed_wait4_cpu_seconds_partial'])
        self.assertIn('CPU_SUM_RANGE', observed['issues'])

    def test_finite_receiver_sums_cannot_overflow_topology_sum(self):
        workers = [synthetic_worker(i) for i in range(2)]
        for value in workers:
            value['wait4'].update(user_seconds=1e308, system_seconds=0.0)
        observed = self.refused(workers, 2)
        self.assertEqual(observed['known_wait4_receivers'], 2)
        self.assertIsNone(observed['receiver_wait4_cpu_seconds'])
        self.assertIsNone(observed['observed_wait4_cpu_seconds_partial'])

    def test_native_cpu_overflow_is_not_serialized_as_infinity(self):
        value = synthetic_worker()
        value['worker_report']['native_exit'].update(
            native_child_user_seconds=1e308, native_child_system_seconds=1e308)
        observed = self.refused([value])
        self.assertIsNone(observed['native_cpu_seconds_subset'])
        self.assertIsNone(observed['observed_native_cpu_seconds_partial'])
        self.assertIn('NATIVE_CPU_SUM_RANGE', observed['issues'])

    def test_unknown_cpu_components_keep_known_parts_and_null_total(self):
        paths = (
            (('wait4', 'user_seconds'), 'receiver_wait4_cpu_seconds',
             'observed_wait4_cpu_seconds_partial', 1.0),
            (('worker_report', 'native_exit', 'native_child_user_seconds'),
             'native_cpu_seconds_subset', 'observed_native_cpu_seconds_partial', 0.25),
        )
        for path, total, partial, expected in paths:
            for replacement in (None, True, False, -1, float('nan'), float('inf'), '1', 10 ** 1000):
                with self.subTest(field=path, value_type=type(replacement).__name__):
                    value = synthetic_worker()
                    self.set_path(value, path, replacement)
                    observed = self.refused([value])
                    self.assertIsNone(observed[total])
                    self.assertEqual(observed[partial], expected)

    def test_native_subset_cannot_exceed_wait4_envelope(self):
        value = synthetic_worker()
        value['worker_report']['native_exit'].update(
            native_child_user_seconds=100.0, native_child_system_seconds=100.0)
        observed = self.refused([value])
        self.assertIsNone(observed['receiver_wait4_cpu_seconds'])
        self.assertIsNone(observed['native_cpu_seconds_subset'])
        self.assertEqual(observed['observed_wait4_cpu_seconds_partial'], 3.0)
        self.assertEqual(observed['observed_native_cpu_seconds_partial'], 200.0)
        self.assertTrue(any('NATIVE_CPU_EXCEEDS_RECEIVER' in issue for issue in observed['issues']))

    def test_native_subset_allows_only_absolute_microsecond_rounding(self):
        value = synthetic_worker()
        value['worker_report']['native_exit'].update(
            native_child_user_seconds=2.7500005, native_child_system_seconds=0.25)
        self.assertEqual(topology_accounting(1, [value])['status'], 'PASS')
        value['worker_report']['native_exit']['native_child_user_seconds'] = 2.7501
        self.refused([value])

    def test_only_observed_transport_attempts_count_as_completed(self):
        for replacement in ('unknown', 'failed', 'not_started', 'started', None, True, [], {}):
            with self.subTest(status=replacement):
                value = synthetic_worker()
                value['worker_report']['transport_records'][0]['status'] = replacement
                observed = self.refused([value])
                self.assertEqual(observed['completed_transport_attempts'], 5)
                self.assertIsNone(observed['tcp_application_received_by_receivers_bytes'])
                self.assertEqual(observed['observed_transport_bytes_partial']['receiver'], 521)

    def test_malformed_nested_containers_fail_without_losing_other_slots(self):
        paths = (
            ('wait4',), ('worker_report',),
            ('worker_report', 'transport_records'), ('worker_report', 'transport_records', 0),
            ('worker_report', 'transport_records', 0, 'verification'),
            ('worker_report', 'transport_records', 0, 'verification', 'stages'),
            ('worker_report', 'transport_records', 0, 'verification', 'stages', 'independent_full_cell'),
            ('worker_report', 'transport_records', 0, 'client'),
            ('worker_report', 'final_ledger'), ('worker_report', 'final_ledger', 'verification_budget'),
            ('worker_report', 'native_exit'), ('receiver_id',),
        )
        for path in paths:
            for replacement in (None, False, 0, '', [], ['unexpected']):
                with self.subTest(path=path, value=replacement):
                    value = synthetic_worker()
                    self.set_path(value, path, replacement)
                    observed = self.refused([value, synthetic_worker(1)], 2)
                    self.assertGreaterEqual(observed['completed_transport_attempts'], 6)
                    self.assertGreaterEqual(observed['observed_wait4_cpu_seconds_partial'], 3.0)

    def test_missing_records_do_not_erase_cpu_or_reservations(self):
        value = synthetic_worker()
        value['worker_report']['transport_records'] = None
        observed = self.refused([value])
        self.assertEqual(observed['completed_transport_attempts'], 0)
        self.assertEqual(observed['receiver_wait4_cpu_seconds'], 3.0)
        self.assertEqual(observed['native_cpu_seconds_subset'], 0.5)
        self.assertEqual(observed['observed_local_reservations'], LOCAL_CAP)
        self.assertIsNone(observed['independent_full_cell_calls'])
        self.assertIsNone(observed['tcp_application_received_by_receivers_bytes'])

    def test_missing_worker_keeps_unknown_totals_and_known_partial_costs(self):
        observed = self.refused([synthetic_worker(), None], 2)
        self.assertEqual(observed['completed_transport_attempts'], 6)
        self.assertEqual(observed['observed_wait4_cpu_seconds_partial'], 3.0)
        self.assertEqual(observed['observed_native_cpu_seconds_partial'], 0.5)
        self.assertEqual(observed['observed_transport_bytes_partial']['receiver'], 521)
        for field in ('receiver_wait4_cpu_seconds', 'native_cpu_seconds_subset',
                      'observed_local_reservations', 'distinct_verified_work_ids',
                      'tcp_application_received_by_receivers_bytes'):
            self.assertIsNone(observed[field], field)

    def test_boolean_and_float_aliases_cannot_satisfy_receipts_or_counters(self):
        edits = (
            (('wait4', 'exit_code'), False),
            (('worker_report', 'native_exit', 'exit_code'), False),
            (('worker_report', 'chainwork_awarded'), False),
            (('worker_report', 'external_demand_authenticated'), 0),
            (('worker_report', 'production_activation'), 0),
            (('worker_report', 'source_bytes_stable'), 1),
            (('worker_report', 'runner_bytes_stable'), 'true'),
            (('worker_report', 'transport_records', 0, 'ordinal'), False),
            (('worker_report', 'transport_records', 0, 'complete_verifier_called'), 1),
            (('worker_report', 'transport_records', 3, 'complete_verifier_called'), 0),
            (('worker_report', 'transport_records', 4, 'client', 'received_bytes'), False),
            (('worker_report', 'transport_records', 0, 'verification', 'reference_macs'), 37008.0),
            (('worker_report', 'transport_records', 0, 'verification', 'chainwork_awarded'), False),
            (('worker_report', 'transport_records', 0, 'verification', 'production_activation'), 0),
            (('worker_report', 'final_ledger', 'verification_budget', 'fixed_limit'), 256.0),
            (('worker_report', 'final_ledger', 'verification_budget', 'reserved'), 256.0),
            (('worker_report', 'final_ledger', 'verification_budget', 'remaining'), False),
            (('worker_report', 'final_ledger', 'verification_budget', 'spent'), False),
        )
        for path, replacement in edits:
            with self.subTest(path=path, value=replacement):
                value = synthetic_worker()
                self.set_path(value, path, replacement)
                self.refused([value])

    def test_nested_verification_cannot_promote_fixture_qualification(self):
        for field, claimed in (('chainwork_awarded', 1), ('production_activation', True),
                               ('external_demand_authenticated', True)):
            with self.subTest(field=field):
                value = synthetic_worker()
                value['worker_report']['transport_records'][0]['verification'][field] = claimed
                observed = self.refused([value])
                self.assertTrue(any('QUALIFICATION_OVERCLAIM' in issue for issue in observed['issues']))

    def test_missing_mac_cost_is_not_zero_or_a_successful_verification(self):
        for replacement in (None, False, -1, '37008', 37008.0, [], 1 << 64):
            with self.subTest(value=replacement):
                value = synthetic_worker()
                value['worker_report']['transport_records'][0]['verification']['reference_macs'] = replacement
                observed = self.refused([value])
                self.assertIsNone(observed['independent_full_cell_macs'])
                self.assertEqual(observed['observed_independent_full_cell_macs_partial'], 3 * 37008)

    def test_missing_cell_stage_does_not_create_a_zero_cost_verified_receipt(self):
        value = synthetic_worker()
        del value['worker_report']['transport_records'][0]['verification']['stages']['independent_full_cell']
        observed = self.refused([value])
        self.assertIsNone(observed['independent_full_cell_calls'])
        self.assertEqual(observed['observed_independent_full_cell_calls_partial'], 3)
        self.assertEqual(observed['observed_independent_full_cell_macs_partial'], 3 * 37008)

    def test_received_client_bytes_cannot_exceed_kernel_accepted_ack(self):
        value = synthetic_worker()
        value['worker_report']['transport_records'][0]['client']['received_bytes'] = 31
        observed = self.refused([value])
        self.assertIsNone(observed['tcp_application_received_by_clients_bytes'])
        self.assertIsNone(observed['tcp_ack_kernel_accepted_bytes_not_proof_of_peer_read'])
        self.assertEqual(observed['observed_transport_bytes_partial']['client'], 151)
        self.assertEqual(observed['observed_transport_bytes_partial']['ack_kernel'], 180)

    def test_failed_client_retains_its_measured_bytes_without_acceptance(self):
        value = synthetic_worker()
        value['worker_report']['transport_records'][0]['client']['status'] = 'failed'
        observed = self.refused([value])
        self.assertEqual(observed['tcp_application_received_by_clients_bytes'], 150)
        self.assertEqual(observed['tcp_ack_kernel_accepted_bytes_not_proof_of_peer_read'], 180)

    def test_reanalysis_never_rewrites_supplied_evidence(self):
        value = synthetic_worker()
        value['worker_report']['transport_records'][0]['verification']['work_id'] = None
        before = copy.deepcopy(value)
        first = self.refused([value])
        self.assertEqual(value, before)
        self.assertEqual(self.refused([value]), first)


if __name__ == '__main__':
    unittest.main()
