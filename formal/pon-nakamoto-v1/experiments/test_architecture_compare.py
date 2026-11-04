"""Synthetic reader negative controls; these values are not native measurements."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

import architecture_compare as comparison
from contract_wire import H, SCHEMA, header_encode, sequence_root, tx_unsigned


CONTEXT = dict(network='11' * 32, parameters='22' * 32, genesis='33' * 32)


def simulated_workload(scenario):
    """Wire-shaped identity fixtures, with NO valid signature or W1 claim."""
    transactions = [tx_unsigned(bytes.fromhex(CONTEXT['network']),
                                H('synthetic-architecture-sender', scenario.encode(), bytes([index])),
                                1, 1000, 1_000_000, 1,
                                dict(recipient=bytes(32), amount=1)) + bytes(64)
                    for index in range(32)]
    cells = [dict(round=index // 4, proposer=index % 4,
                  transactions=[raw.hex() for raw in transactions[index * 4:index * 4 + 4]])
             for index in range(8)]
    parent, packets = bytes.fromhex(CONTEXT['genesis']), []
    for index in range(7):
        body = transactions if index == 0 else []
        fields = {row['name']: bytes(32) if row['type'] == 'hash32' else 0
                  for row in SCHEMA['header']}
        fields.update(network=bytes.fromhex(CONTEXT['network']),
                      parameters=bytes.fromhex(CONTEXT['parameters']), parent=parent,
                      height=index + 1, timestamp=index + 1, target=bytes([255]) * 32,
                      transactions=sequence_root('transactions', body))
        trace = H('synthetic-architecture-trace', scenario.encode(), bytes([index]))
        proof = b'PNW1' + bytes(49188 - 36) + trace
        fields['work_task'] = H('task', proof[4:16388], proof[16388:32772])
        header = header_encode(fields)
        packets.append((header + len(body).to_bytes(2, 'little')
                        + b''.join(len(raw).to_bytes(2, 'little') + raw for raw in body)
                        + proof).hex())
        parent = H('block', header, trace)
    return dict(scenario=scenario, cells=cells, signed_packets=packets,
                work_attempts_including_target_misses=7)


def simulated_report():
    """Bounded metadata fixture only, deliberately no throughput/security claim."""
    workloads = [simulated_workload(scenario)
                 for scenario in ('disjoint-recipients', 'hot-recipient')]
    samples = []
    for workload in workloads:
        expected = comparison.workload_identity(workload, CONTEXT)
        for sample in range(3):
            for position in range(3):
                request = dict(ok=True, error=None, reply=dict(ok=True), wall_ns=1)
                samples.append(dict(scenario=workload['scenario'], sample=sample, position=position,
                    mode=comparison.MODES[(sample+position) % 3], finite_business_target_met=True,
                    native_state_equal=True, cold_reopen_equal=True,
                    dag_consensus_implemented=False, committee_bft_implemented=False, ghast_implemented=False,
                    quorum_data_availability_qualified=False, wan_tested=False, independent_operators=False,
                    work_profile_qualified=False, production_activation=False,
                    consensus_profile='unchanged-pon-nakamoto-v1', errors=[],
                    signed_transaction_count=32, confirmed_transactions=32, full_business_latency_ns=10,
                    whole_trial_wall_ns_including_cold_reopen=12, whole_trial_process_cpu_ns=1,
                    cold_proof_acquisition_wall_ns=1, cold_proof_acquisition_process_cpu_ns=1,
                    work_attempts_including_target_misses=7,
                    dissemination=dict(signed_cells=8, durable_copy_count=1,
                        quorum_availability_certified=False, physical_network_bytes=None,
                        application_frame_bytes=1, wall_ns=1),
                    pool_calls=[copy.deepcopy(request) for _ in range(8)],
                    block_submissions=[copy.deepcopy(request) for _ in range(7)],
                    history_calls=[copy.deepcopy(request)],
                    independent_confirmations=[dict(**CONTEXT, transaction=transaction,
                        included_block=expected['included'], observed_tip=expected['tip'],
                        policy='installed-depth-and-required-work', active_generation=7, observed_now=100,
                        required_work_delta=expected['required_work'], work_delta=expected['observed_work'],
                        confirmed=True, depth=6, included_height=1,
                        observed_height=7, finalized=False, execution_authority=False, reorged=False)
                        for transaction in expected['transactions']],
                    service=dict(work_started=7, work_finished=7, work_failed=0,
                        mutation_cpu_clock_failures=0, mutation_cpu_charged_ns=2,
                        mutation_full_work_cpu_ns=1, mutation_dispatch_excluding_work_cpu_ns=1)))
    return dict(**CONTEXT, schema='native-signed-dag-delivery-comparison-v1', simulated_control=True,
        same_signed_packets_across_modes_and_repetitions=True, balanced_cyclic_mode_order=True,
        all_finite_business_targets_met=True, samples_per_workload_and_mode=3,
        architecture_winner_declared=False, protocol_switch_qualified=False,
        independent_accepted=False, wan_tested=False, production_activation=False,
        workloads=workloads, samples=samples)


class ReaderTests(unittest.TestCase):
    def validate(self, edit=None):
        value = simulated_report()
        if edit is not None: edit(value)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'report.json'
            path.write_text(json.dumps(value))
            return comparison.validate_report(path)

    def test_synthetic_consistency_only(self):
        result = self.validate()
        self.assertTrue(result['finite_target_met'])
        self.assertTrue(all(row['saturated_confirmed_tps'] is None for row in result['summary']))
        self.assertIs(result['workload_and_confirmation_identities_bound'], True)
        self.assertIs(result['pq_workload_measured'], False)
        self.assertIs(result['source_identity_qualified'], False)

    def test_shared_public_fixture_launcher_stays_standard_library_only(self):
        process = subprocess.run([sys.executable, '-S', 'scripts/ci/run_public_fixture_native.py', '--help'],
                                 cwd=comparison.ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_duplicate_foreign_or_reordered_confirmations_cannot_count_as_32(self):
        for mutation in ('duplicate', 'foreign-scenario', 'reordered'):
            def edit(value):
                rows = value['samples'][0]['independent_confirmations']
                if mutation == 'duplicate': rows[:] = [copy.deepcopy(rows[0]) for _ in range(32)]
                elif mutation == 'foreign-scenario':
                    rows[:] = copy.deepcopy(value['samples'][9]['independent_confirmations'])
                else: rows[0], rows[1] = rows[1], rows[0]
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'ARCHITECTURE_TRANSACTION_IDENTITIES'):
                self.validate(edit)

    def test_current_confirmation_context_and_batch_view_are_bound(self):
        for field in ('network', 'parameters', 'genesis', 'included_block', 'observed_tip'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'ARCHITECTURE_CONFIRMATION_CONTEXT'):
                self.validate(lambda value: value['samples'][0]['independent_confirmations'][0].update({field: 'ff' * 32}))
        for field in ('active_generation', 'observed_now'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'ARCHITECTURE_CONFIRMATION_VIEW'):
                self.validate(lambda value: value['samples'][0]['independent_confirmations'][0].update({field: 999}))

    def test_depth_alone_cannot_substitute_for_required_work(self):
        for field, replacement in (('policy', 'depth-only'), ('required_work_delta', '00' * 64),
                                   ('work_delta', '00' * 64)):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'ARCHITECTURE_CONFIRMATION_WORK'):
                self.validate(lambda value: value['samples'][0]['independent_confirmations'][0].update({field: replacement}))

    def test_cells_packets_and_attempt_denominators_are_not_unchecked_labels(self):
        edits = (
            ('ARCHITECTURE_PACKET_TRANSACTIONS', lambda value: value['workloads'][0]['cells'][0]['transactions'].__setitem__(0, '00' * 159)),
            ('ARCHITECTURE_PACKET_CONTEXT', lambda value: value['workloads'][0]['signed_packets'].__setitem__(1, value['workloads'][0]['signed_packets'][0])),
            ('ARCHITECTURE_WORKLOAD_ATTEMPTS', lambda value: value['workloads'][0].update(work_attempts_including_target_misses=8)),
            ('ARCHITECTURE_WORKLOAD_BYTES', lambda value: value['workloads'][0]['cells'].pop()),
        )
        for error, edit in edits:
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                self.validate(edit)

    def test_unqualified_cross_protocol_winner_cannot_be_promoted(self):
        for field in ('architecture_winner_declared', 'protocol_switch_qualified', 'production_activation'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'ARCHITECTURE_SCOPE_PROMOTION'):
                self.validate(lambda value: value.update({field: True}))

    def test_partial_business_cannot_pass_cargo_success(self):
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_FINITE_TARGET'):
            self.validate(lambda value: value['samples'][0].update(finite_business_target_met=False))

    def test_missing_failed_or_late_native_steps_remain_failures(self):
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_NATIVE_CALLS'):
            self.validate(lambda value: value['samples'][0]['block_submissions'].pop())
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_NATIVE_ERRORS'):
            self.validate(lambda value: value['samples'][0]['pool_calls'][0].update(ok=False, error='deadline'))

    def test_wrong_order_or_duplicate_arm_is_not_balanced_comparison(self):
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_BALANCED_ORDER'):
            self.validate(lambda value: value['samples'][0].update(mode=comparison.MODES[1]))
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_DUPLICATE_SAMPLE'):
            self.validate(lambda value: value['samples'].__setitem__(1, copy.deepcopy(value['samples'][0])))

    def test_cached_proof_acquisition_or_lost_target_misses_refused(self):
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_FULL_COST'):
            self.validate(lambda value: value['samples'][0].update(cold_proof_acquisition_process_cpu_ns=0))
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_SAME_WORK'):
            self.validate(lambda value: value['samples'][0].update(work_attempts_including_target_misses=8))

    def test_ack_is_not_availability_quorum_or_confirmation(self):
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_AVAILABILITY_SCOPE'):
            self.validate(lambda value: value['samples'][0]['dissemination'].update(quorum_availability_certified=True))
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_CONFIRMATION'):
            self.validate(lambda value: value['samples'][0]['independent_confirmations'][0].update(finalized=True))
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_CONFIRMATION'):
            self.validate(lambda value: value['samples'][0]['independent_confirmations'][0].update(depth=5))

    def test_unknown_clock_and_double_cpu_debit_cannot_be_zero_cost(self):
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_NUMBER'):
            self.validate(lambda value: value['samples'][0].update(whole_trial_process_cpu_ns=None))
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_CPU_SUM'):
            self.validate(lambda value: value['samples'][0]['service'].update(mutation_cpu_charged_ns=3))
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_WORK_CLOSURE'):
            self.validate(lambda value: value['samples'][0]['service'].update(work_finished=6))

    def test_bounded_reader_rejects_symlink_or_oversized_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'report.json'
            path.write_text('{}')
            link = Path(temporary)/'link.json'; link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_REPORT_REQUIRED'):
                comparison.validate_report(link)
            path.write_bytes(b'x'*(comparison.REPORT_LIMIT+1))
            with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_REPORT_LIMIT'):
                comparison.validate_report(path)


if __name__ == '__main__': unittest.main()
