"""Synthetic reader negative controls; these values are not native measurements."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import architecture_compare as comparison


def simulated_report():
    """Bounded metadata fixture only, deliberately no throughput/security claim."""
    workloads = [{'scenario': scenario, 'work_attempts_including_target_misses': 7}
                 for scenario in ('disjoint-recipients', 'hot-recipient')]
    samples = []
    for workload in workloads:
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
                    independent_confirmations=[dict(confirmed=True, depth=6, included_height=1,
                        observed_height=7, finalized=False, execution_authority=False, reorged=False)
                        for _ in range(32)],
                    service=dict(work_started=7, work_finished=7, work_failed=0,
                        mutation_cpu_clock_failures=0, mutation_cpu_charged_ns=2,
                        mutation_full_work_cpu_ns=1, mutation_dispatch_excluding_work_cpu_ns=1)))
    return dict(schema='native-signed-dag-delivery-comparison-v1', simulated_control=True,
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
