#!/usr/bin/env python3
"""Adversarial reader controls; every positive fixture is explicitly synthetic.

These tests execute no native work, signatures, Host or cgroup. The separate
historical readback uses unchanged retained native report bytes and their pins.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import throughput_cost_coverage as reader
from test_pon_public_v3_phase_read import attribution_phase, lifecycle_record, observed_history_call

HEAD, TREE = 'a' * 40, 'b' * 40


def source():
    return dict(schema='trnm-ci-source-v1', kind='head', candidate=HEAD, tested_commit=HEAD,
                tested_tree=TREE, base=None, prospective_merge=None, tracked_entries=1,
                tracked_bytes=1, tracked_worktree_verified=True,
                tests_executed_by_identity_check=False)


def host_context():
    before = dict(cpu_usage_usec=100, cpu_nr_periods=10, cpu_nr_throttled=2,
                  cpu_throttled_usec=30, memory_current_bytes=64, pids_current=2)
    after = dict(before, cpu_usage_usec=150, cpu_nr_periods=15,
                 cpu_throttled_usec=32, memory_current_bytes=32, pids_current=1)
    return dict(schema='fixed-public-phase-external-actors-v1', phase_pid=1,
        phase_cgroup='/trnmponpublic.slice/synthetic.service',
        controller_cgroup='/system.slice/synthetic-controller.service',
        host_before=before, host_after=after, same_original_receiver_and_verifier_owners=True,
        attackers_launched_by_external_controller=True, runtime_business_deadline_changed=False,
        scalar_policy_changed=False, independent_administration=False, wan_qualified=False)


def report():
    """Producer-shaped observations; the numbers are not measured CPU or bytes."""
    rows = []
    for index, mode in enumerate(reader.phases.MODES):
        record = lifecycle_record(accepted=0, connection=200, task=190)
        record.update(connection_id=1, application_bytes_read=300, application_bytes_written=400,
                      physical_network_bytes=None)
        by_name = {span['phase']: span for span in record['submit_phases']}
        for name, start, end, cpu in [('admission', 20, 80, 50), ('execution', 30, 70, 20),
                                      ('root_commitment', 40, 50, 4)]:
            by_name[name].update(started=True, completed=True, accepted=True,
                                 started_ns=start, ended_ns=end, wall_ns=end-start, thread_cpu_ns=cpu)
        phase = attribution_phase([], [observed_history_call()], [], [record])
        phase.update(mode=mode, whole_parent_phase_cpu_ns=500,
            whole_parent_phase_wall_ns=1000, receiver_and_verifier_setup_cpu_ns=10,
            receiver_and_verifier_setup_wall_ns=20, phase_process_context=host_context(),
            service_outcome={'Ok': dict(pq_authentication_attempts=0, pq_authentication_bytes=0,
                pq_authentication_thread_cpu_ns=0, pq_authentication_unavailable=False,
                mutation_cpu_charged_ns=100, mutation_full_work_cpu_ns=30,
                mutation_dispatch_excluding_work_cpu_ns=70,
                mutation_body_decode_cpu_ns=10, mutation_response_cpu_ns=2)})
        phase['receiver_observation'].update(schema='public-v3-local-request-resource-observation-v4',
            capacity=16384, accepted_connections_seen=1, records_not_retained=0,
            measurement_failures=0, counter_overflow=False, observation_has_consensus_authority=False,
            stream_bytes_are_physical_network_bytes=False, cpu_wait_is_outside_dispatch=True,
            phase_parent_links_are_inclusive=True, monotonic_epoch_is_observer_local=True,
            cpu_includes_reactor_authentication_or_response_signing=True,
            cpu_includes_reactor_authentication=False,
            dispatch_cpu_includes_paid_body_decode=True, dispatch_cpu_includes_response_signing=True)
        rows.append(phase)
    return dict(schema='native-public-v3-separate-process-campaign-v2',
        state_backend='authenticated-v1', finite_experiment_criteria_met=False,
        economics_complete=False, best_observed_cold_legal_method=None,
        preparation=dict(cpu_ns=None, wall_ns=None), phases=rows)


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()


class CoverageControls(unittest.TestCase):
    def analyze(self, value=None):
        value = report() if value is None else value
        return reader.analyze(value, hashlib.sha256(encoded(value)).hexdigest())

    def file_inputs(self, value=None):
        temporary = tempfile.TemporaryDirectory(prefix='trnm-cost-reader-control-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        raw = encoded(report() if value is None else value)
        (root / 'report.json').write_bytes(raw)
        for name in ('before.json', 'after.json'):
            (root / name).write_bytes(encoded(source()))
        return root, hashlib.sha256(raw).hexdigest()

    def read(self, root, pin, **kwargs):
        return reader.read_coverage(root/'report.json', root/'before.json', root/'after.json',
            expected_report_sha256=pin, head=HEAD, tree=TREE, **kwargs)

    def test_failed_campaign_and_all_planned_denominators_are_preserved(self):
        result = self.analyze()
        self.assertFalse(result['original_finite_experiment_criteria_met'])
        self.assertEqual([p['mode'] for p in result['phases']], list(reader.phases.MODES))
        for phase in result['phases']:
            self.assertFalse(phase['original_outcome']['native_phase_criteria_met'])
            self.assertEqual(phase['original_outcome']['scheduled_confirmation_rounds'], 3)
            self.assertEqual(phase['original_outcome']['unobserved_scheduled_rounds'], 3)
            self.assertEqual(phase['history']['records'][0]['error'], 'PUBLIC_REQUEST_DEADLINE')
            self.assertFalse(phase['history']['records'][0]['succeeded'])
        self.assertFalse(result['scope']['production_qualification'])
        self.assertIsNone(result['scope']['business_tps_capacity'])

    def test_nested_request_settlement_host_and_process_cpu_are_never_added(self):
        phase = self.analyze()['phases'][0]
        self.assertEqual(phase['phase_process_cpu_ns'], 500)
        self.assertEqual(phase['receiver']['dispatch_thread_cpu_ns']['sum_known'], 100)
        self.assertEqual(phase['receiver']['settlement']['total_cpu_ns']['sum_known'], 170)
        costs = {v['phase']: v for v in phase['receiver']['phases']}
        self.assertEqual(costs['admission']['thread_cpu_ns']['sum_known'], 50)
        self.assertEqual(costs['execution']['parent_phase'], 'admission')
        self.assertEqual(costs['root_commitment']['parent_phase'], 'execution')
        self.assertIsNone(phase['complete_pipeline_cpu_ns'])
        self.assertIsNone(phase['cold_recovery_cpu_ns'])
        self.assertFalse(self.analyze()['scope']['overlapping_cpu_domains_are_added'])

    def test_missing_clock_and_unentered_span_are_not_zero_cost_samples(self):
        value = report()
        record = value['phases'][0]['receiver_observation']['records'][0]
        record['dispatch_thread_cpu_ns'] = None
        result = self.analyze(value)['phases'][0]['receiver']
        self.assertIsNone(result['dispatch_thread_cpu_ns']['sum_known'])
        self.assertIsNone(result['dispatch_thread_cpu_ns']['sum_all_observed'])
        self.assertEqual(result['dispatch_thread_cpu_ns']['unknown_slots'], 1)
        unentered = next(v for v in result['phases'] if v['phase'] == 'history_epoch_open')
        self.assertEqual(unentered['unentered'], 1)
        self.assertEqual(unentered['thread_cpu_ns']['observed_slots'], 0)
        self.assertIsNone(unentered['thread_cpu_ns']['sum_known'])

    def test_unfinished_and_unretained_work_remain_explicit(self):
        value = report()
        observer = value['phases'][0]['receiver_observation']
        observer.update(accepted_connections_seen=3, records_not_retained=2)
        span = next(v for v in observer['records'][0]['submit_phases'] if v['phase'] == 'admission')
        span.update(completed=False, accepted=None)
        result = self.analyze(value)['phases'][0]['receiver']
        self.assertEqual(result['unobserved_records'], 2)
        measured = next(v for v in result['phases'] if v['phase'] == 'admission')
        self.assertEqual(measured['unfinished'], 1)
        self.assertEqual(measured['thread_cpu_ns']['sum_known'], 50)
        self.assertFalse(result['all_request_costs_covered'])

    def test_same_connection_number_across_epochs_is_separate_but_local_duplicates_refuse(self):
        result = self.analyze()
        epochs = [p['receiver']['epoch'] for p in result['phases']]
        self.assertEqual(len(set(epochs)), 3)
        value = report()
        observer = value['phases'][0]['receiver_observation']
        observer['records'].append(copy.deepcopy(observer['records'][0]))
        observer['accepted_connections_seen'] = 2
        with self.assertRaisesRegex(ValueError, 'duplicate receiver identity'):
            self.analyze(value)

    def test_receiver_epoch_and_inclusive_parent_claims_cannot_be_mixed(self):
        for mutation in ('foreign_start', 'foreign_end', 'global_epoch', 'wrong_parent'):
            value = report()
            observer = value['phases'][0]['receiver_observation']
            row = observer['records'][0]
            span = next(v for v in row['submit_phases'] if v['phase'] == 'admission')
            if mutation == 'foreign_start':
                row['lifecycle']['accepted_ns'] = 25
            elif mutation == 'foreign_end':
                span.update(ended_ns=250, wall_ns=230)
            elif mutation == 'global_epoch':
                observer['monotonic_epoch_is_observer_local'] = False
            else:
                next(v for v in row['submit_phases'] if v['phase'] == 'root_commitment')['parent_phase'] = 'admission'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.analyze(value)

    def test_history_epoch_stays_separate_and_wrong_host_scope_refuses(self):
        result = self.analyze()['phases'][0]
        native = result['history']['records'][0]
        self.assertNotEqual(native['epoch'], result['receiver']['epoch'])
        self.assertEqual(native['native_snapshot']['phases'][16]['phase'], 'history_import')
        self.assertIsNone(result['history']['cold_recovery_cpu_ns'])
        value = report()
        value['phases'][0]['history'][0]['client_import']['native_import_observation']['host_cpu_is_full_worker_cpu'] = True
        with self.assertRaisesRegex(ValueError, 'IMPORT_OBSERVATION_SCOPE'):
            self.analyze(value)

    def test_stream_byte_counts_cannot_be_promoted_to_physical_network_cost(self):
        result = self.analyze()['phases'][0]['receiver']
        self.assertEqual(result['application_bytes_read']['sum_known'], 300)
        self.assertIsNone(result['physical_network_bytes'])
        for mutation in ('stream_flag', 'physical_count'):
            value = report()
            observer = value['phases'][0]['receiver_observation']
            if mutation == 'stream_flag':
                observer['stream_bytes_are_physical_network_bytes'] = True
            else:
                observer['records'][0]['physical_network_bytes'] = 700
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.analyze(value)

    def test_zero_pq_attempts_remain_zero_and_absent_metrics_remain_unknown(self):
        pq = self.analyze()['phases'][0]['listener']['pq_authentication']
        self.assertEqual(pq['pq_authentication_attempts'], 0)
        self.assertEqual(pq['pq_authentication_thread_cpu_ns'], 0)
        self.assertEqual(pq['missing_fields'], [])
        value = report()
        value['phases'][0]['service_outcome']['Ok'].pop('pq_authentication_thread_cpu_ns')
        pq = self.analyze(value)['phases'][0]['listener']['pq_authentication']
        self.assertIsNone(pq['pq_authentication_thread_cpu_ns'])
        self.assertEqual(pq['missing_fields'], ['pq_authentication_thread_cpu_ns'])

    def test_inconsistent_mutation_settlement_and_numeric_boolean_clocks_refuse(self):
        for field, observed in [('mutation_cpu_charged_ns', 200),
                                ('pq_authentication_thread_cpu_ns', True),
                                ('pq_authentication_unavailable', 0)]:
            value = report()
            value['phases'][0]['service_outcome']['Ok'][field] = observed
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.analyze(value)

    def test_host_delta_is_local_memory_points_are_not_delta_or_peak(self):
        result = self.analyze()['phases'][0]['fixed_parent']
        self.assertEqual(result['counter_deltas']['cpu_usage_usec'], 50)
        self.assertNotIn('memory_current_bytes', result['counter_deltas'])
        self.assertNotIn('pids_current', result['counter_deltas'])
        self.assertEqual(result['context']['host_after']['memory_current_bytes'], 32)
        self.assertIsNone(result['serialized_boot_identity'])
        for mutation in ('cpu_rewind', 'merged_owner', 'foreign_profile', 'parent_path', 'empty_path'):
            value = report()
            context = value['phases'][0]['phase_process_context']
            if mutation == 'cpu_rewind':
                context['host_after']['cpu_usage_usec'] = 99
            elif mutation == 'merged_owner':
                context['controller_cgroup'] = context['phase_cgroup']
            elif mutation == 'foreign_profile':
                context['schema'] = 'other-resource-profile'
            elif mutation == 'parent_path':
                context['controller_cgroup'] = '/system.slice/../trnmponpublic.slice/hidden'
            else:
                context['phase_cgroup'] = '/trnmponpublic.slice//child'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.analyze(value)

    def test_incomplete_phase_does_not_delete_original_failure_denominator(self):
        value = report()
        value['phases'][1] = dict(mode='from-zero', state_backend='authenticated-v1',
                                 finite_phase_criteria_met=False, startup_or_campaign_error='FAILED_START')
        phase = self.analyze(value)['phases'][1]
        self.assertEqual(phase['original_outcome']['startup_or_campaign_error'], 'FAILED_START')
        self.assertEqual(phase['original_outcome']['unobserved_scheduled_rounds'], 3)
        self.assertIsNone(phase['receiver'])
        self.assertIsNone(phase['phase_process_cpu_ns'])

    def test_sources_reports_and_prospective_merge_identity_are_exact(self):
        root, pin = self.file_inputs()
        result = self.read(root, pin)
        self.assertEqual(result['source']['tested_commit'], HEAD)
        self.assertEqual(result['input']['report_sha256'], pin)
        wrong = source()
        wrong['tested_tree'] = 'c' * 40
        (root/'after.json').write_bytes(encoded(wrong))
        with self.assertRaisesRegex(ValueError, 'unchanged complete source'):
            self.read(root, pin)
        (root/'before.json').write_bytes(encoded(wrong))
        with self.assertRaisesRegex(ValueError, 'pinned source'):
            self.read(root, pin)
        base, merge = 'd' * 40, 'e' * 40
        prospective = dict(source(), kind='prospective-merge', base=base,
                           prospective_merge=merge, tested_commit=merge)
        for name in ('before.json', 'after.json'):
            (root/name).write_bytes(encoded(prospective))
        result = self.read(root, pin, kind='prospective-merge', base=base, merge=merge)
        self.assertEqual(result['source']['tested_commit'], merge)
        with self.assertRaisesRegex(ValueError, 'pinned source'):
            self.read(root, pin, kind='prospective-merge', base=base, merge='f' * 40)

    def test_changed_report_and_symlinked_input_cannot_reuse_source_receipts(self):
        root, pin = self.file_inputs()
        with self.assertRaisesRegex(ValueError, 'report SHA256 mismatch'):
            self.read(root, '0' * 64)
        original = (root/'report.json').read_bytes()
        (root/'report.json').write_bytes(original+b' ')
        with self.assertRaisesRegex(ValueError, 'report SHA256 mismatch'):
            self.read(root, pin)
        (root/'report.json').unlink()
        (root/'other.json').write_bytes(original)
        (root/'report.json').symlink_to(root/'other.json')
        with self.assertRaises((ValueError, OSError)):
            self.read(root, pin)

    def test_duplicate_keys_nonfinite_numbers_and_truncated_json_refuse(self):
        for raw in (b'{"schema":1,"schema":2}', b'{"x":NaN}', b'{"schema":'):
            root, _ = self.file_inputs()
            (root/'report.json').write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.read(root, hashlib.sha256(raw).hexdigest())

    def test_unknown_or_mixed_report_profiles_and_phase_order_refuse(self):
        for mutation in ('schema', 'backend', 'unknown_backend', 'phase_order'):
            value = report()
            if mutation == 'schema':
                value['schema'] = 'unrecognized'
            elif mutation == 'backend':
                value['phases'][1]['state_backend'] = 'other'
            elif mutation == 'unknown_backend':
                value['state_backend'] = 'other'
                for phase in value['phases']:
                    phase['state_backend'] = 'other'
            else:
                value['phases'][1], value['phases'][2] = value['phases'][2], value['phases'][1]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.analyze(value)

    def test_bad_collection_shapes_and_oversized_epochs_refuse_before_analysis(self):
        for mutation in ('missing_preparation', 'invalid_phase', 'invalid_record',
                         'receiver_capacity', 'history_capacity', 'invalid_import'):
            value = report()
            phase = value['phases'][0]
            if mutation == 'missing_preparation':
                value['preparation'] = None
            elif mutation == 'invalid_phase':
                value['phases'][0] = None
            elif mutation == 'invalid_record':
                phase['receiver_observation']['records'] = [None]
            elif mutation == 'receiver_capacity':
                phase['receiver_observation']['records'] *= reader.MAX_RECORDS + 1
            elif mutation == 'history_capacity':
                phase['history'] *= 65
            else:
                phase['history'][0]['client_import'] = 'unexpected'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                reader.analyze(value, '1' * 64)

    def test_legacy_import_costs_keep_calling_thread_scope(self):
        value = report()
        imported = value['phases'][0]['history'][0]['client_import']
        imported.pop('native_import_observation')
        result = self.analyze(value)['phases'][0]['history']
        self.assertEqual(result['imports_without_native_snapshot'], 1)
        self.assertIsNone(result['host_checks'][0]['thread_cpu_ns']['sum_known'])
        imported['scope'] = 'entire process including all workers'
        with self.assertRaisesRegex(ValueError, 'calling-thread CPU scope'):
            self.analyze(value)


if __name__ == '__main__':
    unittest.main()
