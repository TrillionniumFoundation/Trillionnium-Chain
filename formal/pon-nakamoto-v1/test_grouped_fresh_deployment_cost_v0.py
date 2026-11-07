"""Accounting counterexamples; synthetic rows are not measured resource evidence."""
from __future__ import annotations

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


if __name__ == '__main__':
    unittest.main()
